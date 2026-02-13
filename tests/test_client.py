import hashlib
import time

from unittest.mock import MagicMock
from unittest.mock import patch

from django.core.cache import cache
from django.test import RequestFactory
from django.test import TestCase
from django.test import TransactionTestCase

from auth0_oauth_client.client import DjangoAuthClient
from auth0_oauth_client.errors import AccessTokenErrorCode
from auth0_oauth_client.errors import AccessTokenOauthClientError
from auth0_oauth_client.errors import ApiOauthClientError
from auth0_oauth_client.errors import MissingRequiredArgumentOauthClientError
from auth0_oauth_client.errors import MissingTransactionOauthClientError
from auth0_oauth_client.models import AccountLinking
from auth0_oauth_client.models import AccountToken
from auth0_oauth_client.models import ConnectedAccount


class MockSession(dict):
    """Dict subclass that supports the `modified` attribute like Django sessions."""

    modified = False


def _make_request_with_session():
    """Create a request object with a dict-like session for testing."""
    factory = RequestFactory()
    request = factory.get("/")
    request.session = MockSession()
    return request


def _make_session_data(user_id="auth0|user123", email="user@example.com", refresh_token="rt_123"):
    return {
        "userinfo": {"sub": user_id, "email": email},
        "refresh_token": refresh_token,
    }


class DjangoAuthClientInitTest(TestCase):
    def test_reads_configuration_from_settings(self):
        client = DjangoAuthClient()
        self.assertEqual(client.auth0_domain, "test.auth0.com")
        self.assertEqual(client.auth0_management_api_domain, "test.auth0.com")
        self.assertEqual(client.client_id, "test-client-id")
        self.assertEqual(client.client_secret, "test-client-secret")
        self.assertEqual(client.audience, "https://api.test.com/")
        self.assertFalse(client.pushed_authorization_requests)
        self.assertEqual(client.my_account_audience, "https://test.auth0.com/me/")
        self.assertEqual(client.connections_for_account_linking, ["google-oauth2", "facebook"])

    def test_authorization_params_loaded(self):
        client = DjangoAuthClient()
        self.assertEqual(client.authorization_params["scope"], "openid profile email offline_access")
        self.assertEqual(client.authorization_params["prompt"], "consent")


class GetIdpUsernameTest(TestCase):
    def test_returns_sub_when_session_exists(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = _make_session_data(user_id="auth0|abc")
        result = client.get_idp_username(request)
        self.assertEqual(result, "auth0|abc")

    def test_returns_none_when_no_session(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        result = client.get_idp_username(request)
        self.assertIsNone(result)


class StartLoginTest(TestCase):
    @patch("auth0_oauth_client.client.build_authorization_url")
    @patch("auth0_oauth_client.client.generate_state", return_value="mock-state")
    @patch("auth0_oauth_client.client.generate_pkce_pair", return_value=("mock-verifier", "mock-challenge"))
    def test_stores_transaction_and_returns_url(self, mock_pkce, mock_state, mock_build_url):
        mock_build_url.return_value = "https://test.auth0.com/authorize?state=mock-state"
        client = DjangoAuthClient()
        request = _make_request_with_session()
        url = client.start_login(request, "https://app.test.com/callback")
        self.assertEqual(url, "https://test.auth0.com/authorize?state=mock-state")
        tx = request.session[DjangoAuthClient.SESSION_KEY_TX]
        self.assertEqual(tx["state"], "mock-state")
        self.assertEqual(tx["code_verifier"], "mock-verifier")
        self.assertEqual(tx["redirect_uri"], "https://app.test.com/callback")

    @patch("auth0_oauth_client.client.build_authorization_url")
    @patch("auth0_oauth_client.client.generate_state", return_value="s")
    @patch("auth0_oauth_client.client.generate_pkce_pair", return_value=("v", "c"))
    def test_passes_authorization_params(self, mock_pkce, mock_state, mock_build_url):
        mock_build_url.return_value = "url"
        client = DjangoAuthClient()
        request = _make_request_with_session()
        client.start_login(request, "https://app.test.com/callback", authorization_params={"connection": "google"})
        mock_build_url.assert_called_once_with(
            "https://app.test.com/callback", "s", "c", extra_params={"connection": "google"}
        )


class CompleteLoginTest(TransactionTestCase):
    @patch("auth0_oauth_client.client.exchange_code_for_tokens")
    def test_completes_login_successfully(self, mock_exchange):
        mock_exchange.return_value = {
            "access_token": "at_123",
            "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdXRoMHx1c2VyMTIzIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIn0.fake",  # noqa: E501
            "refresh_token": "rt_123",
            "token_type": "Bearer",
            "expires_in": 86400,
            "scope": "openid profile email",
        }

        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_TX] = {
            "state": "test-state",
            "code_verifier": "test-verifier",
            "redirect_uri": "https://app.test.com/callback",
        }

        callback_url = "https://app.test.com/callback?code=auth_code_123&state=test-state"
        result = client.complete_login(request, callback_url)

        self.assertIn("access_token", result)
        self.assertIn("expires_at", result)
        session_data = request.session[DjangoAuthClient.SESSION_KEY_STATE]
        self.assertIn("userinfo", session_data)
        self.assertIn("refresh_token", session_data)
        self.assertTrue(AccountToken.objects.filter(user_id=session_data["userinfo"]["sub"]).exists())

    def test_raises_error_when_code_missing(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        callback_url = "https://app.test.com/callback?state=test-state"
        with self.assertRaises(MissingRequiredArgumentOauthClientError):
            client.complete_login(request, callback_url)

    def test_raises_error_when_state_missing(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        callback_url = "https://app.test.com/callback?code=auth_code_123"
        with self.assertRaises(MissingRequiredArgumentOauthClientError):
            client.complete_login(request, callback_url)

    def test_raises_error_on_state_mismatch(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_TX] = {
            "state": "original-state",
            "code_verifier": "verifier",
            "redirect_uri": "https://app.test.com/callback",
        }
        callback_url = "https://app.test.com/callback?code=auth_code_123&state=wrong-state"
        with self.assertRaises(ApiOauthClientError) as ctx:
            client.complete_login(request, callback_url)
        self.assertEqual(ctx.exception.code, "state_mismatch")

    def test_raises_error_when_no_transaction(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        callback_url = "https://app.test.com/callback?code=auth_code_123&state=test-state"
        with self.assertRaises(MissingTransactionOauthClientError):
            client.complete_login(request, callback_url)


class LogoutTest(TestCase):
    @patch("auth0_oauth_client.client.build_logout_url", return_value="https://test.auth0.com/v2/logout?returnTo=home")
    def test_clears_session_and_returns_url(self, mock_logout_url):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = _make_session_data()
        url = client.logout(request, return_to="https://app.test.com/")
        self.assertNotIn(DjangoAuthClient.SESSION_KEY_STATE, request.session)
        self.assertEqual(url, "https://test.auth0.com/v2/logout?returnTo=home")

    @patch("auth0_oauth_client.client.build_logout_url", return_value="https://test.auth0.com/v2/logout")
    def test_logout_without_existing_session(self, mock_logout_url):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        url = client.logout(request)
        self.assertNotIn(DjangoAuthClient.SESSION_KEY_STATE, request.session)
        self.assertIsNotNone(url)


class StartConnectAccountTest(TestCase):
    @patch("auth0_oauth_client.client.myaccount_connect_account")
    @patch.object(DjangoAuthClient, "_get_access_token", return_value="at_myaccount")
    @patch("auth0_oauth_client.client.generate_state", return_value="mock-state")
    @patch("auth0_oauth_client.client.generate_pkce_pair", return_value=("mock-verifier", "mock-challenge"))
    def test_returns_connect_uri_with_ticket(self, mock_pkce, mock_state, mock_get_at, mock_connect):
        mock_connect.return_value = {
            "auth_session": "session_123",
            "connect_uri": "https://test.auth0.com/connect",
            "connect_params": {"ticket": "ticket_abc"},
            "expires_in": 300,
        }
        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = _make_session_data()

        url = client.start_connect_account(request, "google-oauth2", "https://app.test.com/callback")
        self.assertIn("ticket=ticket_abc", url)
        tx = request.session[DjangoAuthClient.SESSION_KEY_TX]
        self.assertEqual(tx["state"], "mock-state")
        self.assertTrue(tx["is_connect"])
        self.assertEqual(tx["auth_session"], "session_123")

    def test_raises_error_when_redirect_uri_missing(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        with self.assertRaises(MissingRequiredArgumentOauthClientError):
            client.start_connect_account(request, "google-oauth2", redirect_uri="")

    @patch("auth0_oauth_client.client.myaccount_connect_account")
    @patch.object(DjangoAuthClient, "_get_access_token", return_value="at_myaccount")
    @patch("auth0_oauth_client.client.generate_state", return_value="mock-state")
    @patch("auth0_oauth_client.client.generate_pkce_pair", return_value=("mock-verifier", "mock-challenge"))
    def test_returns_connect_uri_without_ticket(self, mock_pkce, mock_state, mock_get_at, mock_connect):
        mock_connect.return_value = {
            "auth_session": "session_123",
            "connect_uri": "https://test.auth0.com/connect/direct",
            "connect_params": {},
            "expires_in": 300,
        }
        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = _make_session_data()

        url = client.start_connect_account(request, "google-oauth2", "https://app.test.com/callback")
        self.assertEqual(url, "https://test.auth0.com/connect/direct")

    @patch("auth0_oauth_client.client.myaccount_connect_account")
    @patch.object(DjangoAuthClient, "_get_access_token", return_value="at_myaccount")
    @patch("auth0_oauth_client.client.generate_state", return_value="mock-state")
    @patch("auth0_oauth_client.client.generate_pkce_pair", return_value=("mock-verifier", "mock-challenge"))
    def test_merges_custom_scopes_and_passed_scopes(self, mock_pkce, mock_state, mock_get_at, mock_connect):
        mock_connect.return_value = {
            "connect_uri": "https://test.auth0.com/connect",
            "connect_params": {},
            "expires_in": 300,
        }
        client = DjangoAuthClient()
        client.custom_scopes = {"google-oauth2": ["email", "calendar"]}
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = _make_session_data()

        client.start_connect_account(
            request,
            "google-oauth2",
            "https://app.test.com/callback",
            scopes=["drive", "email"],
        )
        call_args = mock_connect.call_args
        request_data = call_args[0][1]
        self.assertIn("email", request_data["scopes"])
        self.assertIn("calendar", request_data["scopes"])
        self.assertIn("drive", request_data["scopes"])

    @patch("auth0_oauth_client.client.myaccount_connect_account")
    @patch.object(DjangoAuthClient, "_get_access_token", return_value="at_myaccount")
    @patch("auth0_oauth_client.client.generate_state", return_value="mock-state")
    @patch("auth0_oauth_client.client.generate_pkce_pair", return_value=("mock-verifier", "mock-challenge"))
    def test_passes_authorization_params(self, mock_pkce, mock_state, mock_get_at, mock_connect):
        mock_connect.return_value = {
            "connect_uri": "https://test.auth0.com/connect",
            "connect_params": {},
            "expires_in": 300,
        }
        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = _make_session_data()

        client.start_connect_account(
            request,
            "google-oauth2",
            "https://app.test.com/callback",
            authorization_params={"prompt": "login"},
        )
        call_args = mock_connect.call_args
        request_data = call_args[0][1]
        self.assertEqual(request_data["authorization_params"], {"prompt": "login"})


class CompleteConnectAccountTest(TransactionTestCase):
    @patch("auth0_oauth_client.client.myaccount_complete_connect_account")
    @patch.object(DjangoAuthClient, "_get_access_token", return_value="at_myaccount")
    def test_completes_connect_account_successfully(self, mock_get_at, mock_complete):
        mock_complete.return_value = {"id": "ca_123", "connection": "google-oauth2"}

        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = _make_session_data(user_id="auth0|owner1")
        request.session[DjangoAuthClient.SESSION_KEY_TX] = {
            "state": "test-state",
            "code_verifier": "verifier",
            "redirect_uri": "https://app.test.com/callback",
            "is_connect": True,
            "auth_session": "session_123",
        }

        callback_url = "https://app.test.com/callback?connect_code=cc_123&state=test-state"
        result = client.complete_connect_account(request, callback_url)

        self.assertEqual(result["id"], "ca_123")
        self.assertTrue(ConnectedAccount.objects.filter(connected_account_id="ca_123").exists())

    def test_raises_error_when_connect_code_missing(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        callback_url = "https://app.test.com/callback?state=test-state"
        with self.assertRaises(MissingRequiredArgumentOauthClientError):
            client.complete_connect_account(request, callback_url)

    def test_raises_error_on_state_mismatch(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_TX] = {
            "state": "original-state",
            "code_verifier": "verifier",
            "redirect_uri": "https://app.test.com/callback",
        }
        callback_url = "https://app.test.com/callback?connect_code=cc_123&state=wrong-state"
        with self.assertRaises(ApiOauthClientError):
            client.complete_connect_account(request, callback_url)

    @patch("auth0_oauth_client.client.myaccount_complete_connect_account")
    @patch.object(DjangoAuthClient, "_get_access_token", return_value="at_myaccount")
    def test_marks_connected_account_as_linked_when_account_linking_exists(self, mock_get_at, mock_complete):
        mock_complete.return_value = {"id": "ca_123", "connection": "google-oauth2"}

        user_id = "auth0|owner1"
        AccountLinking.objects.create(
            primary_user_id=user_id,
            secondary_provider="google-oauth2",
            secondary_user_id="google-oauth2|linked1",
        )

        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = _make_session_data(user_id=user_id)
        request.session[DjangoAuthClient.SESSION_KEY_TX] = {
            "state": "test-state",
            "code_verifier": "verifier",
            "redirect_uri": "https://app.test.com/callback",
            "auth_session": "session_123",
        }

        callback_url = "https://app.test.com/callback?connect_code=cc_123&state=test-state"
        client.complete_connect_account(request, callback_url)

        ca = ConnectedAccount.objects.get(connected_account_id="ca_123")
        self.assertTrue(ca.is_account_linked)


class ListConnectedAccountsTest(TestCase):
    @patch("auth0_oauth_client.client.myaccount_list_connected_accounts")
    @patch.object(DjangoAuthClient, "_get_access_token", return_value="at_myaccount")
    def test_returns_accounts(self, mock_get_at, mock_list):
        mock_list.return_value = [{"id": "ca_1", "connection": "google-oauth2"}]
        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = _make_session_data()

        result = client.list_connected_accounts(request)
        self.assertEqual(len(result), 1)


class DeleteConnectedAccountTest(TransactionTestCase):
    @patch("auth0_oauth_client.client.myaccount_delete_connected_account")
    @patch.object(DjangoAuthClient, "_get_access_token", return_value="at_myaccount")
    def test_deletes_connected_account(self, mock_get_at, mock_delete):
        ConnectedAccount.objects.create(
            connected_account_id="ca_123",
            email="user@example.com",
            provider="google-oauth2",
            user_id_owner="auth0|user1",
        )
        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = _make_session_data()

        client.delete_connected_account(request, "ca_123")
        self.assertFalse(ConnectedAccount.objects.filter(connected_account_id="ca_123").exists())

    def test_raises_error_when_id_empty(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        with self.assertRaises(MissingRequiredArgumentOauthClientError):
            client.delete_connected_account(request, "")


class ListConnectedAccountConnectionsTest(TestCase):
    @patch("auth0_oauth_client.client.myaccount_list_connections")
    @patch.object(DjangoAuthClient, "_get_access_token", return_value="at_myaccount")
    def test_returns_connections(self, mock_get_at, mock_list):
        mock_list.return_value = [{"name": "google-oauth2", "strategy": "google", "scopes": []}]
        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = _make_session_data()

        result = client.list_connected_account_connections(request)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "google-oauth2")


class CompleteAccountLinkingTest(TransactionTestCase):
    def test_returns_none_when_no_pending_linking(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        result = client.complete_account_linking(request)
        self.assertIsNone(result)

    def test_returns_failure_when_different_account(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = _make_session_data(user_id="auth0|current")
        request.session[DjangoAuthClient.SESSION_KEY_ACCOUNT_LINKING_TX] = {
            "primary_user_id": "auth0|different",
            "secondary_provider": "google-oauth2",
            "secondary_user_id": "google-oauth2|secondary",
        }
        result = client.complete_account_linking(request)
        self.assertFalse(result["success"])
        self.assertTrue(result["used_different_account"])

    @patch.object(DjangoAuthClient, "_merge_and_link_accounts", return_value=[])
    def test_completes_account_linking_successfully(self, mock_merge):
        user_id = "auth0|primary"
        AccountToken.objects.create(user_id=user_id, refresh_token="rt_primary")

        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = _make_session_data(user_id=user_id)
        request.session[DjangoAuthClient.SESSION_KEY_ACCOUNT_LINKING_TX] = {
            "primary_user_id": user_id,
            "secondary_provider": "google-oauth2",
            "secondary_user_id": "google-oauth2|secondary",
        }
        result = client.complete_account_linking(request)
        self.assertTrue(result["success"])
        self.assertTrue(AccountLinking.objects.filter(primary_user_id=user_id).exists())
        mock_merge.assert_called_once_with(user_id, "google-oauth2", "google-oauth2|secondary")

    @patch.object(DjangoAuthClient, "_merge_and_link_accounts", return_value=[])
    def test_updates_connected_account_linked_status(self, mock_merge):
        user_id = "auth0|primary"
        secondary_user_id = "google-oauth2|secondary"
        AccountToken.objects.create(user_id=user_id, refresh_token="rt_primary")
        ConnectedAccount.objects.create(
            connected_account_id="ca_1",
            email="user@example.com",
            provider="google-oauth2",
            user_id_owner=user_id,
            is_account_linked=False,
        )

        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = _make_session_data(user_id=user_id)
        request.session[DjangoAuthClient.SESSION_KEY_ACCOUNT_LINKING_TX] = {
            "primary_user_id": user_id,
            "secondary_provider": "google-oauth2",
            "secondary_user_id": secondary_user_id,
        }
        client.complete_account_linking(request)
        ca = ConnectedAccount.objects.get(connected_account_id="ca_1")
        self.assertTrue(ca.is_account_linked)


class VerifyAccountLinkingTest(TransactionTestCase):
    def _setup_client_and_request(self, user_id="auth0|user1"):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = _make_session_data(user_id=user_id)
        return client, request

    @patch.object(DjangoAuthClient, "get_user_info")
    def test_linked_via_connected_account_entry(self, mock_get_user_info):
        user_id = "auth0|user1"
        primary_user_id = "auth0|primary"
        mock_get_user_info.return_value = {
            "email": "user@example.com",
            "identities": [{"provider": "google-oauth2", "connection": "google-oauth2"}],
        }

        ConnectedAccount.objects.create(
            connected_account_id="ca_1",
            email="user@example.com",
            provider="google-oauth2",
            user_id_owner=primary_user_id,
            is_account_linked=False,
        )
        AccountToken.objects.create(user_id=primary_user_id, refresh_token="rt_primary")

        client, request = self._setup_client_and_request(user_id=user_id)

        with patch.object(client, "_merge_and_link_accounts", return_value=[]):
            result = client.verify_account_linking(request)

        self.assertFalse(result["is_pending_account_linking"])
        self.assertTrue(result["is_account_linked"])
        ca = ConnectedAccount.objects.get(connected_account_id="ca_1")
        self.assertTrue(ca.is_account_linked)
        session_data = request.session[DjangoAuthClient.SESSION_KEY_STATE]
        self.assertEqual(session_data["userinfo"]["sub"], primary_user_id)

    @patch.object(DjangoAuthClient, "_search_users_excluding_connection")
    @patch.object(DjangoAuthClient, "get_user_info")
    def test_auto_links_social_provider(self, mock_get_user_info, mock_search):
        user_id = "google-oauth2|newuser"
        existing_user_id = "auth0|existing"
        mock_get_user_info.return_value = {
            "email": "user@example.com",
            "identities": [{"provider": "google-oauth2", "connection": "google-oauth2"}],
        }
        mock_search.return_value = [
            {
                "user_id": existing_user_id,
                "identities": [{"provider": "auth0", "connection": "Username-Password-Authentication"}],
            }
        ]
        AccountToken.objects.create(user_id=existing_user_id, refresh_token="rt_existing")

        client, request = self._setup_client_and_request(user_id=user_id)

        with patch.object(client, "_merge_and_link_accounts", return_value=[]):
            result = client.verify_account_linking(request)

        self.assertFalse(result["is_pending_account_linking"])
        self.assertTrue(result["is_account_linked"])

    @patch.object(DjangoAuthClient, "_search_users_excluding_connection")
    @patch.object(DjangoAuthClient, "get_user_info")
    def test_pending_linking_for_non_social_provider(self, mock_get_user_info, mock_search):
        user_id = "auth0|newuser"
        existing_user_id = "google-oauth2|existing"
        mock_get_user_info.return_value = {
            "email": "user@example.com",
            "identities": [{"provider": "auth0", "connection": "Username-Password-Authentication"}],
        }
        mock_search.return_value = [
            {
                "user_id": existing_user_id,
                "identities": [{"provider": "google-oauth2", "connection": "google-oauth2"}],
            }
        ]

        client, request = self._setup_client_and_request(user_id=user_id)
        result = client.verify_account_linking(request)

        self.assertTrue(result["is_pending_account_linking"])
        self.assertFalse(result["is_account_linked"])
        pending = request.session[DjangoAuthClient.SESSION_KEY_ACCOUNT_LINKING_TX]
        self.assertEqual(pending["primary_user_id"], existing_user_id)
        self.assertEqual(pending["secondary_user_id"], user_id)

    @patch.object(DjangoAuthClient, "_search_users_excluding_connection")
    @patch.object(DjangoAuthClient, "get_user_info")
    def test_no_linking_when_no_existing_accounts(self, mock_get_user_info, mock_search):
        mock_get_user_info.return_value = {
            "email": "user@example.com",
            "identities": [{"provider": "auth0", "connection": "Username-Password-Authentication"}],
        }
        mock_search.return_value = []

        client, request = self._setup_client_and_request()
        result = client.verify_account_linking(request)

        self.assertFalse(result["is_pending_account_linking"])
        self.assertFalse(result["is_account_linked"])

    @patch.object(DjangoAuthClient, "get_user_info")
    def test_no_linking_when_all_identities_present(self, mock_get_user_info):
        mock_get_user_info.return_value = {
            "email": "user@example.com",
            "identities": [
                {"provider": "auth0", "connection": "auth0"},
                {"provider": "google-oauth2", "connection": "google-oauth2"},
            ],
        }
        client, request = self._setup_client_and_request()
        result = client.verify_account_linking(request)
        self.assertFalse(result["is_pending_account_linking"])
        self.assertFalse(result["is_account_linked"])


class PendingAccountLinkingTest(TestCase):
    def test_returns_payload_when_exists(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        payload = {"primary_user_id": "auth0|p", "secondary_user_id": "g|s"}
        request.session[DjangoAuthClient.SESSION_KEY_ACCOUNT_LINKING_TX] = payload
        self.assertEqual(client.pending_account_linking(request), payload)

    def test_returns_none_when_not_exists(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        self.assertIsNone(client.pending_account_linking(request))


class CancelAccountLinkingTest(TestCase):
    def test_removes_pending_linking(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_ACCOUNT_LINKING_TX] = {"data": "value"}
        client.cancel_account_linking(request)
        self.assertNotIn(DjangoAuthClient.SESSION_KEY_ACCOUNT_LINKING_TX, request.session)

    def test_no_error_when_no_pending_linking(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        client.cancel_account_linking(request)


class GetRefreshTokenTest(TestCase):
    def test_returns_refresh_token(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = _make_session_data(refresh_token="rt_test")
        self.assertEqual(client.get_refresh_token(request), "rt_test")

    def test_returns_none_when_no_session(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        self.assertIsNone(client.get_refresh_token(request))


class GetAccessTokenTest(TestCase):
    def setUp(self):
        cache.clear()

    def _compute_hash_key(self, audience, scope):
        """Compute the same hashed key that _get_access_token uses internally."""
        client = DjangoAuthClient()
        merged_scope = client._merge_scope_with_defaults(scope, audience)
        return hashlib.sha256(f"{audience}{merged_scope}".encode()).hexdigest()

    def test_returns_cached_access_token_when_valid(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        hashed_key = self._compute_hash_key(client.audience, None)
        session_data = _make_session_data()
        session_data[hashed_key] = {
            "access_token": "cached_at",
            "expires_at": int(time.time()) + 3600,
        }
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = session_data

        result = client._get_access_token(request)
        self.assertEqual(result, "cached_at")

    @patch("auth0_oauth_client.client.refresh_access_token")
    def test_refreshes_expired_token(self, mock_refresh):
        mock_refresh.return_value = {
            "access_token": "new_at",
            "scope": "openid profile email offline_access",
            "expires_in": 86400,
        }
        client = DjangoAuthClient()
        request = _make_request_with_session()
        session_data = _make_session_data()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = session_data

        result = client._get_access_token(request)
        self.assertEqual(result, "new_at")

    @patch("auth0_oauth_client.client.refresh_access_token")
    def test_updates_refresh_token_when_rotated(self, mock_refresh):
        mock_refresh.return_value = {
            "access_token": "new_at",
            "scope": "openid",
            "expires_in": 3600,
            "refresh_token": "new_rt",
        }
        client = DjangoAuthClient()
        request = _make_request_with_session()
        session_data = _make_session_data(refresh_token="old_rt")
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = session_data

        client._get_access_token(request)
        updated_session = request.session[DjangoAuthClient.SESSION_KEY_STATE]
        self.assertEqual(updated_session["refresh_token"], "new_rt")

    def test_raises_error_when_no_session(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        with self.assertRaises(AccessTokenOauthClientError) as ctx:
            client._get_access_token(request)
        self.assertEqual(ctx.exception.code, AccessTokenErrorCode.MISSING_SESSION)

    @patch("auth0_oauth_client.client.refresh_access_token", side_effect=Exception("Network error"))
    def test_raises_access_token_error_on_refresh_failure(self, mock_refresh):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        session_data = _make_session_data()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = session_data

        with self.assertRaises(AccessTokenOauthClientError) as ctx:
            client._get_access_token(request)
        self.assertEqual(ctx.exception.code, AccessTokenErrorCode.REFRESH_TOKEN_ERROR)

    @patch("auth0_oauth_client.client.refresh_access_token")
    def test_reraises_access_token_error(self, mock_refresh):
        mock_refresh.side_effect = AccessTokenOauthClientError(
            AccessTokenErrorCode.MISSING_REFRESH_TOKEN, "Missing refresh token"
        )
        client = DjangoAuthClient()
        request = _make_request_with_session()
        session_data = _make_session_data()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = session_data

        with self.assertRaises(AccessTokenOauthClientError) as ctx:
            client._get_access_token(request)
        self.assertEqual(ctx.exception.code, AccessTokenErrorCode.MISSING_REFRESH_TOKEN)

    @patch("auth0_oauth_client.client.refresh_access_token")
    def test_uses_custom_audience_and_scope(self, mock_refresh):
        mock_refresh.return_value = {
            "access_token": "custom_at",
            "scope": "custom_scope",
            "expires_in": 3600,
        }
        client = DjangoAuthClient()
        request = _make_request_with_session()
        session_data = _make_session_data()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = session_data

        result = client._get_access_token(request, audience="https://custom.api/", scope="custom_scope")
        self.assertEqual(result, "custom_at")
        mock_refresh.assert_called_once_with("rt_123", audience="https://custom.api/", scope="custom_scope")


class GetAuth0TokenThroughM2MTest(TestCase):
    def setUp(self):
        cache.clear()

    @patch("auth0_oauth_client.client.GetToken")
    def test_fetches_and_caches_m2m_token(self, mock_get_token_cls):
        mock_instance = MagicMock()
        mock_instance.client_credentials.return_value = {
            "access_token": "m2m_at",
            "expires_in": 86400,
        }
        mock_get_token_cls.return_value = mock_instance

        client = DjangoAuthClient()
        result = client._get_auth0_token_through_m2m()
        self.assertEqual(result["access_token"], "m2m_at")
        cached = cache.get("_auth0_oauth_client_m2m_token")
        self.assertIsNotNone(cached)

    def test_returns_cached_m2m_token(self):
        cached_token = {"access_token": "cached_m2m"}
        cache.set("_auth0_oauth_client_m2m_token", cached_token)
        client = DjangoAuthClient()
        result = client._get_auth0_token_through_m2m()
        self.assertEqual(result, cached_token)


class MergeScopeWithDefaultsTest(TestCase):
    def test_merges_request_scope_with_defaults(self):
        client = DjangoAuthClient()
        result = client._merge_scope_with_defaults("custom_scope")
        self.assertIn("custom_scope", result)

    def test_returns_none_when_no_scopes(self):
        client = DjangoAuthClient()
        client.authorization_params = {}
        result = client._merge_scope_with_defaults(None)
        self.assertIsNone(result)

    def test_uses_audience_specific_scope(self):
        client = DjangoAuthClient()
        client.authorization_params = {"scope": {"https://api.test.com/": "read:data write:data"}}
        result = client._merge_scope_with_defaults(None, audience="https://api.test.com/")
        self.assertIn("read:data", result)
        self.assertIn("write:data", result)

    def test_deduplicates_scopes(self):
        client = DjangoAuthClient()
        client.authorization_params = {"scope": "openid profile"}
        result = client._merge_scope_with_defaults("openid custom")
        scopes = result.split()
        self.assertEqual(len(scopes), len(set(scopes)))


class MergeUserMetadataTest(TestCase):
    def test_primary_values_take_precedence(self):
        client = DjangoAuthClient()
        result = client._merge_user_metadata({"key": "primary"}, {"key": "secondary"})
        self.assertEqual(result["key"], "primary")

    def test_secondary_fills_missing_keys(self):
        client = DjangoAuthClient()
        result = client._merge_user_metadata({}, {"key": "secondary"})
        self.assertEqual(result["key"], "secondary")

    def test_primary_fills_missing_keys(self):
        client = DjangoAuthClient()
        result = client._merge_user_metadata({"key": "primary"}, {})
        self.assertEqual(result["key"], "primary")

    def test_lists_are_concatenated(self):
        client = DjangoAuthClient()
        result = client._merge_user_metadata({"tags": ["a"]}, {"tags": ["b"]})
        self.assertEqual(result["tags"], ["b", "a"])

    def test_nested_dicts_are_merged_recursively(self):
        client = DjangoAuthClient()
        primary = {"prefs": {"theme": "dark", "lang": "en"}}
        secondary = {"prefs": {"theme": "light", "font": "mono"}}
        result = client._merge_user_metadata(primary, secondary)
        self.assertEqual(result["prefs"]["theme"], "dark")
        self.assertEqual(result["prefs"]["lang"], "en")
        self.assertEqual(result["prefs"]["font"], "mono")

    def test_empty_dicts(self):
        client = DjangoAuthClient()
        result = client._merge_user_metadata({}, {})
        self.assertEqual(result, {})


class IsSocialProviderTest(TestCase):
    def test_google_is_social(self):
        client = DjangoAuthClient()
        self.assertTrue(client._is_social_provider("google-oauth2"))

    def test_facebook_is_social(self):
        client = DjangoAuthClient()
        self.assertTrue(client._is_social_provider("facebook"))

    def test_apple_is_social(self):
        client = DjangoAuthClient()
        self.assertTrue(client._is_social_provider("apple"))

    def test_auth0_is_not_social(self):
        client = DjangoAuthClient()
        self.assertFalse(client._is_social_provider("auth0"))


class StoreAndPopTransactionTest(TestCase):
    def test_stores_and_pops_transaction(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        client._store_transaction(request, "state1", "verifier1", "https://callback.com")
        tx = client._pop_transaction(request)
        self.assertEqual(tx["state"], "state1")
        self.assertEqual(tx["code_verifier"], "verifier1")
        self.assertEqual(tx["redirect_uri"], "https://callback.com")
        self.assertFalse(tx["is_connect"])
        self.assertNotIn(DjangoAuthClient.SESSION_KEY_TX, request.session)

    def test_stores_with_connect_and_auth_session(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        client._store_transaction(
            request,
            "state1",
            "verifier1",
            "https://callback.com",
            is_connect=True,
            auth_session="session_abc",
        )
        tx = client._pop_transaction(request)
        self.assertTrue(tx["is_connect"])
        self.assertEqual(tx["auth_session"], "session_abc")

    def test_pop_raises_when_no_transaction(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        with self.assertRaises(MissingTransactionOauthClientError):
            client._pop_transaction(request)


class SessionManagementTest(TestCase):
    def test_store_and_get_session(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        session_data = _make_session_data()
        client._store_session(request, session_data)
        result = client._get_session(request)
        self.assertEqual(result, session_data)

    def test_get_session_returns_none_when_empty(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        result = client._get_session(request)
        self.assertIsNone(result)


class GetUserInfoTest(TestCase):
    @patch.object(DjangoAuthClient, "_get_auth0_token_through_m2m")
    @patch("auth0_oauth_client.client.Auth0")
    def test_fetches_user_info(self, mock_auth0_cls, mock_m2m):
        mock_m2m.return_value = {"access_token": "m2m_at"}
        mock_auth0_instance = MagicMock()
        mock_auth0_instance.users.get.return_value = {
            "user_id": "auth0|user1",
            "email": "user@example.com",
        }
        mock_auth0_cls.return_value = mock_auth0_instance

        client = DjangoAuthClient()
        result = client.get_user_info("auth0|user1")
        self.assertEqual(result["user_id"], "auth0|user1")


class SearchUsersExcludingConnectionTest(TestCase):
    @patch.object(DjangoAuthClient, "_get_auth0_token_through_m2m")
    @patch("auth0_oauth_client.client.Auth0")
    def test_searches_users(self, mock_auth0_cls, mock_m2m):
        mock_m2m.return_value = {"access_token": "m2m_at"}
        mock_auth0_instance = MagicMock()
        mock_auth0_instance.users.list.return_value = {
            "users": [
                {
                    "user_id": "auth0|found",
                    "identities": [{"provider": "auth0", "connection": "Username-Password-Authentication"}],
                }
            ]
        }
        mock_auth0_cls.return_value = mock_auth0_instance

        client = DjangoAuthClient()
        result = client._search_users_excluding_connection("user@example.com", "google-oauth2")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["user_id"], "auth0|found")


class UpdateUserTest(TestCase):
    @patch.object(DjangoAuthClient, "_get_auth0_token_through_m2m")
    @patch("auth0_oauth_client.client.Auth0")
    def test_updates_user(self, mock_auth0_cls, mock_m2m):
        mock_m2m.return_value = {"access_token": "m2m_at"}
        mock_auth0_instance = MagicMock()
        mock_auth0_instance.users.update.return_value = {"user_id": "auth0|user1"}
        mock_auth0_cls.return_value = mock_auth0_instance

        client = DjangoAuthClient()
        result = client._update_user("auth0|user1", {"user_metadata": {"key": "value"}})
        self.assertEqual(result["user_id"], "auth0|user1")


class LinkUserAccountsTest(TestCase):
    @patch.object(DjangoAuthClient, "_get_auth0_token_through_m2m")
    @patch("auth0_oauth_client.client.Auth0")
    def test_links_user_accounts(self, mock_auth0_cls, mock_m2m):
        mock_m2m.return_value = {"access_token": "m2m_at"}
        mock_auth0_instance = MagicMock()
        mock_auth0_instance.users.link_user_account.return_value = [{"provider": "google-oauth2"}]
        mock_auth0_cls.return_value = mock_auth0_instance

        client = DjangoAuthClient()
        result = client._link_user_accounts("auth0|primary", "google-oauth2", "google-oauth2|secondary")
        self.assertEqual(len(result), 1)


class MergeAndLinkAccountsTest(TestCase):
    @patch.object(DjangoAuthClient, "_link_user_accounts", return_value=[{"provider": "google-oauth2"}])
    @patch.object(DjangoAuthClient, "_update_user")
    @patch.object(DjangoAuthClient, "get_user_info")
    def test_merges_metadata_and_links(self, mock_get_user_info, mock_update, mock_link):
        mock_get_user_info.side_effect = [
            {"user_metadata": {"key1": "val1"}, "app_metadata": {"a1": "v1"}},
            {"user_metadata": {"key2": "val2"}, "app_metadata": {"a2": "v2"}},
        ]
        client = DjangoAuthClient()
        result = client._merge_and_link_accounts("auth0|primary", "google-oauth2", "google-oauth2|secondary")
        mock_update.assert_called_once()
        update_body = mock_update.call_args[0][1]
        self.assertIn("key1", update_body["user_metadata"])
        self.assertIn("key2", update_body["user_metadata"])
        self.assertEqual(len(result), 1)

    @patch.object(DjangoAuthClient, "_link_user_accounts", return_value=[])
    @patch.object(DjangoAuthClient, "_update_user")
    @patch.object(DjangoAuthClient, "get_user_info")
    def test_skips_update_when_no_metadata(self, mock_get_user_info, mock_update, mock_link):
        mock_get_user_info.side_effect = [
            {},
            {},
        ]
        client = DjangoAuthClient()
        client._merge_and_link_accounts("auth0|primary", "google-oauth2", "google-oauth2|secondary")
        mock_update.assert_not_called()
