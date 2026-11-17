import hashlib
import time

from datetime import UTC
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock
from unittest.mock import patch

import jwt
import requests

from auth0.exceptions import Auth0Error
from auth0.exceptions import RateLimitError
from django.core.cache import cache
from django.test import RequestFactory
from django.test import TestCase
from django.test import TransactionTestCase

from auth0_oauth_client.client import DjangoAuthClient
from auth0_oauth_client.errors import AccessTokenErrorCode
from auth0_oauth_client.errors import AccessTokenOauthClientError
from auth0_oauth_client.errors import ApiOauthClientError
from auth0_oauth_client.errors import Auth0PingError
from auth0_oauth_client.errors import FederatedConnectionRefreshTokenNotFound
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

    @patch("auth0_oauth_client.client.myaccount_complete_connect_account")
    @patch.object(DjangoAuthClient, "_get_access_token", return_value="at_myaccount")
    def test_reconnect_with_new_connected_account_id_updates_existing_row(self, mock_get_at, mock_complete):
        # Regression: on RECONNECT of an already-linked account, Auth0 returns a NEW connected_account_id
        # for the SAME (user_id_owner, provider). The upsert previously keyed on connected_account_id, so
        # it missed the existing row, fell through to an INSERT, and violated the `unique_connected_account`
        # (user_id_owner, provider) constraint -> IntegrityError (HTTP 500 in the /callback/ view). The
        # upsert must instead key on (user_id_owner, provider) and update the existing row's id in place.
        user_id = "auth0|owner1"
        ConnectedAccount.objects.create(
            connected_account_id="ca_OLD",
            user_id_owner=user_id,
            provider="google-oauth2",
            email="owner1@example.com",
            is_account_linked=False,
        )
        mock_complete.return_value = {"id": "ca_NEW", "connection": "google-oauth2"}

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
        # Must NOT raise IntegrityError.
        client.complete_connect_account(request, callback_url)

        # Exactly one row for (user, provider), updated in place to the new connected_account_id.
        rows = ConnectedAccount.objects.filter(user_id_owner=user_id, provider="google-oauth2")
        self.assertEqual(rows.count(), 1)
        self.assertEqual(rows.first().connected_account_id, "ca_NEW")
        self.assertFalse(ConnectedAccount.objects.filter(connected_account_id="ca_OLD").exists())


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


LINKING_EMAIL = "victim.linking@example.com"
PASSWORD_CONNECTION = "Username-Password-Authentication"
# Marks a field that the Auth0 record must not carry at all (as opposed to carrying `None`).
_MISSING = object()


def _identity(provider):
    connection = PASSWORD_CONNECTION if provider == "auth0" else provider
    return {"provider": provider, "connection": connection}


def _with_fields(record, **fields):
    for key, value in fields.items():
        if value is not _MISSING:
            record[key] = value
    return record


def _current_record(provider="google-oauth2", email_verified=True, created_at=_MISSING):
    """The current account as `get_user_by_id` returns it."""
    record = {"email": LINKING_EMAIL, "identities": [_identity(provider)]}
    return _with_fields(record, email_verified=email_verified, created_at=created_at)


def _candidate_record(user_id, provider, email_verified=True, created_at=_MISSING, email=LINKING_EMAIL):
    """A search result as `_search_users_excluding_connection` returns it."""
    record = {"user_id": user_id, "identities": [_identity(provider)]}
    return _with_fields(record, email=email, email_verified=email_verified, created_at=created_at)


def _owner_record(provider, email=LINKING_EMAIL, email_verified=True, created_at=_MISSING):
    """A ConnectedAccount owner as the fresh Management API read returns it."""
    record = {"identities": [_identity(provider)]}
    return _with_fields(record, email=email, email_verified=email_verified, created_at=created_at)


class VerifyAccountLinkingTest(TransactionTestCase):
    GOOGLE_USER_ID = "google-oauth2|newuser"
    PASSWORD_USER_ID = "auth0|existing"
    FACEBOOK_USER_ID = "facebook|existing"
    AUTO_LINK_MESSAGE = "Account linked automatically branch=%s primary_user_id=%s secondary_user_id=%s"
    WITHHELD_MESSAGE = (
        "Automatic account linking withheld branch=%s current_user_id=%s candidate_user_id=%s "
        "candidate_provider=%s current_email_verified=%s candidate_email_verified=%s"
    )
    SKIPPED_MESSAGE = (
        "Account linking skipped, candidate is newer branch=search current_user_id=%s candidate_user_id=%s"
    )
    MULTIPLE_CANDIDATES_MESSAGE = "Multiple account linking candidates count=%s current_user_id=%s"
    OWNER_READ_FAILED_MESSAGE = (
        "Account linking owner read failed branch=connected_account candidate_user_id=%s status_code=%s"
    )
    CANDIDATE_IGNORED_MESSAGE = (
        "Account linking candidate ignored, e-mail mismatch branch=search current_user_id=%s candidate_user_id=%s"
    )
    NOT_LINKED = {"is_pending_account_linking": False, "is_account_linked": False}
    PENDING = {"is_pending_account_linking": True, "is_account_linked": False}
    LINKED = {"is_pending_account_linking": False, "is_account_linked": True}

    def setUp(self):
        cache.clear()

    def _setup_client_and_request(self, user_id="auth0|user1"):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = _make_session_data(user_id=user_id, email=LINKING_EMAIL)
        return client, request

    def _verify(self, current, candidates=(), user_id=GOOGLE_USER_ID, owner=None, owner_error=None):
        """Run `verify_account_linking` with every Auth0 boundary replaced, and return what it touched."""
        client, request = self._setup_client_and_request(user_id=user_id)
        with (
            patch.object(DjangoAuthClient, "get_user_by_id", return_value=current),
            patch.object(
                DjangoAuthClient, "_search_users_excluding_connection", return_value=list(candidates)
            ) as mock_search,
            patch.object(
                DjangoAuthClient, "_get_user_by_id_uncached", return_value=owner, side_effect=owner_error
            ) as mock_owner_read,
            # The only way into `_link_user_accounts` (the Auth0 link call), so it is the link boundary here.
            patch.object(DjangoAuthClient, "_merge_and_link_accounts", return_value=[]) as mock_merge,
        ):
            result = client.verify_account_linking(request)
        return SimpleNamespace(
            result=result,
            session=request.session,
            search=mock_search,
            owner_read=mock_owner_read,
            merge=mock_merge,
        )

    def _assert_not_linked(self, outcome, current_user_id):
        outcome.merge.assert_not_called()
        session_data = outcome.session[DjangoAuthClient.SESSION_KEY_STATE]
        self.assertEqual(session_data["userinfo"]["sub"], current_user_id)
        self.assertEqual(session_data["refresh_token"], "rt_123")
        self.assertFalse(AccountLinking.objects.exists())

    def _assert_manual_path(
        self,
        outcome,
        primary_user_id,
        primary_provider,
        friendly_name,
        secondary_user_id=GOOGLE_USER_ID,
        secondary_provider="google-oauth2",
    ):
        self.assertEqual(outcome.result, self.PENDING)
        self.assertEqual(
            outcome.session[DjangoAuthClient.SESSION_KEY_ACCOUNT_LINKING_TX],
            {
                "primary_user_id": primary_user_id,
                "primary_provider": primary_provider,
                "primary_provider_friendly_name": friendly_name,
                "primary_connection_name": _identity(primary_provider)["connection"],
                "secondary_user_id": secondary_user_id,
                "secondary_provider": secondary_provider,
                "secondary_connection_name": _identity(secondary_provider)["connection"],
            },
        )
        self._assert_not_linked(outcome, secondary_user_id)

    def _assert_logged(self, logs, expected):
        self.assertEqual([(record.levelname, record.msg, record.args) for record in logs.records], expected)
        for record in logs.records:
            self.assertNotIn(LINKING_EMAIL.casefold(), record.getMessage().casefold())
            self.assertNotIn(LINKING_EMAIL.casefold(), repr(record.args).casefold())
            # The raw Auth0 link response (identities with profileData) must never reach a log line.
            self.assertNotIn("Merged and linked accounts", record.getMessage())

    def _create_connected_account(self, owner_user_id, provider="google-oauth2"):
        return ConnectedAccount.objects.create(
            connected_account_id=f"ca_{owner_user_id}",
            email=LINKING_EMAIL,
            provider=provider,
            user_id_owner=owner_user_id,
            is_account_linked=False,
        )

    # region ConnectedAccount branch

    @patch.object(DjangoAuthClient, "_get_user_by_id_uncached")
    @patch.object(DjangoAuthClient, "get_user_by_id")
    def test_linked_via_connected_account_entry(self, mock_get_user_by_id, mock_get_owner):
        user_id = "google-oauth2|user1"
        primary_user_id = "facebook|primary"
        mock_get_user_by_id.return_value = {
            "email": "user@example.com",
            "email_verified": True,
            "identities": [{"provider": "google-oauth2", "connection": "google-oauth2"}],
        }
        mock_get_owner.return_value = {
            "email": "user@example.com",
            "email_verified": True,
            "identities": [{"provider": "facebook", "connection": "facebook"}],
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
        mock_get_owner.assert_called_once_with(primary_user_id)

    @patch.object(DjangoAuthClient, "_search_users_excluding_connection")
    @patch.object(DjangoAuthClient, "get_user_by_id")
    def test_skips_self_link_when_connected_account_points_to_same_user(self, mock_get_user_by_id, mock_search):
        user_id = "google-oauth2|111"
        mock_get_user_by_id.return_value = {
            "email": "user@example.com",
            "identities": [{"provider": "google-oauth2", "connection": "google-oauth2"}],
        }
        mock_search.return_value = []

        ConnectedAccount.objects.create(
            connected_account_id="ca_self",
            email="user@example.com",
            provider="google-oauth2",
            user_id_owner=user_id,
            is_account_linked=False,
        )

        client, request = self._setup_client_and_request(user_id=user_id)
        result = client.verify_account_linking(request)

        self.assertFalse(result["is_pending_account_linking"])
        self.assertFalse(result["is_account_linked"])
        ca = ConnectedAccount.objects.get(connected_account_id="ca_self")
        self.assertFalse(ca.is_account_linked)

    def test_connected_account_links_verified_social_owner_with_email_in_other_case(self):
        owner_user_id = "facebook|owner"
        row = self._create_connected_account(owner_user_id)
        AccountToken.objects.create(user_id=owner_user_id, refresh_token="rt_owner")
        owner = _owner_record("facebook", email=LINKING_EMAIL.upper())

        with self.assertLogs("auth0_oauth_client", "DEBUG") as logs:
            outcome = self._verify(_current_record(), owner=owner)

        self.assertEqual(outcome.result, self.LINKED)
        outcome.owner_read.assert_called_once_with(owner_user_id)
        outcome.merge.assert_called_once_with(owner_user_id, "google-oauth2", self.GOOGLE_USER_ID)
        outcome.search.assert_not_called()
        row.refresh_from_db()
        self.assertTrue(row.is_account_linked)
        session_data = outcome.session[DjangoAuthClient.SESSION_KEY_STATE]
        self.assertEqual(session_data["userinfo"]["sub"], owner_user_id)
        self.assertEqual(session_data["refresh_token"], "rt_owner")
        self.assertTrue(
            AccountLinking.objects.filter(
                primary_user_id=owner_user_id,
                secondary_provider="google-oauth2",
                secondary_user_id=self.GOOGLE_USER_ID,
            ).exists()
        )
        self._assert_logged(
            logs, [("INFO", self.AUTO_LINK_MESSAGE, ("connected_account", owner_user_id, self.GOOGLE_USER_ID))]
        )

    def test_connected_account_newer_owner_is_never_linked(self):
        # The owner stays primary, so a verified social owner created after the current account is not linked.
        owner_user_id = "facebook|owner"
        row = self._create_connected_account(owner_user_id)
        current = _current_record(created_at="2026-01-01T00:00:00Z")
        owner = _owner_record("facebook", created_at="2026-02-01T00:00:00Z")

        with self.assertLogs("auth0_oauth_client", "DEBUG") as logs:
            outcome = self._verify(current, owner=owner)

        self.assertEqual(outcome.result, self.NOT_LINKED)
        self._assert_not_linked(outcome, self.GOOGLE_USER_ID)
        outcome.search.assert_called_once_with(LINKING_EMAIL, "google-oauth2")
        row.refresh_from_db()
        self.assertFalse(row.is_account_linked)
        self._assert_logged(
            logs,
            [
                (
                    "INFO",
                    self.WITHHELD_MESSAGE,
                    ("connected_account", self.GOOGLE_USER_ID, owner_user_id, "facebook", True, True),
                )
            ],
        )

    def test_connected_account_owner_with_password_identity_is_never_linked(self):
        owner_user_id = "auth0|owner"
        row = self._create_connected_account(owner_user_id)
        for owner_verified in (True, False):
            with self.subTest(owner_email_verified=owner_verified):
                owner = _owner_record("auth0", email_verified=owner_verified)
                password_candidate = _candidate_record(owner_user_id, "auth0", email_verified=owner_verified)

                with self.assertLogs("auth0_oauth_client", "DEBUG") as logs:
                    outcome = self._verify(_current_record(), [password_candidate], owner=owner)

                self._assert_manual_path(outcome, owner_user_id, "auth0", "e-mail e senha")
                outcome.owner_read.assert_called_once_with(owner_user_id)
                outcome.search.assert_called_once_with(LINKING_EMAIL, "google-oauth2")
                row.refresh_from_db()
                self.assertFalse(row.is_account_linked)
                self._assert_logged(
                    logs,
                    [
                        (
                            "INFO",
                            self.WITHHELD_MESSAGE,
                            ("connected_account", self.GOOGLE_USER_ID, owner_user_id, "auth0", True, owner_verified),
                        ),
                        (
                            "INFO",
                            self.WITHHELD_MESSAGE,
                            ("search", self.GOOGLE_USER_ID, owner_user_id, "auth0", True, owner_verified),
                        ),
                    ],
                )

    def test_connected_account_social_owner_with_another_email_falls_through_to_search(self):
        owner_user_id = "facebook|owner"
        row = self._create_connected_account(owner_user_id)
        owner = _owner_record("facebook", email="someone.else@example.com")

        outcome = self._verify(_current_record(), owner=owner)

        self.assertEqual(outcome.result, self.NOT_LINKED)
        self._assert_not_linked(outcome, self.GOOGLE_USER_ID)
        outcome.search.assert_called_once_with(LINKING_EMAIL, "google-oauth2")
        row.refresh_from_db()
        self.assertFalse(row.is_account_linked)

    def test_connected_account_with_unverified_current_account_falls_through_to_search(self):
        owner_user_id = "facebook|owner"
        row = self._create_connected_account(owner_user_id)

        with self.assertLogs("auth0_oauth_client", "DEBUG") as logs:
            outcome = self._verify(_current_record(email_verified=False), owner=_owner_record("facebook"))

        self.assertEqual(outcome.result, self.NOT_LINKED)
        self._assert_not_linked(outcome, self.GOOGLE_USER_ID)
        # An unverified login can never be linked automatically, so the owner is not even read.
        outcome.owner_read.assert_not_called()
        outcome.search.assert_called_once_with(LINKING_EMAIL, "google-oauth2")
        row.refresh_from_db()
        self.assertFalse(row.is_account_linked)
        self._assert_logged(
            logs,
            [
                (
                    "INFO",
                    self.WITHHELD_MESSAGE,
                    ("connected_account", self.GOOGLE_USER_ID, owner_user_id, None, False, None),
                )
            ],
        )

    def test_connected_account_owner_read_failure_falls_through_to_search(self):
        owner_user_id = "facebook|owner"
        row = self._create_connected_account(owner_user_id)
        errors = {
            "rate limited": RateLimitError(error_code="too_many_requests", message="Too Many Requests", reset_at=0),
            "server error": Auth0Error(status_code=503, error_code="temporarily_unavailable", message="Unavailable"),
        }
        for label, error in errors.items():
            with self.subTest(label):
                with self.assertLogs("auth0_oauth_client", "DEBUG") as logs:
                    outcome = self._verify(_current_record(), owner_error=error)

                self.assertEqual(outcome.result, self.NOT_LINKED)
                self._assert_not_linked(outcome, self.GOOGLE_USER_ID)
                outcome.owner_read.assert_called_once_with(owner_user_id)
                outcome.search.assert_called_once_with(LINKING_EMAIL, "google-oauth2")
                row.refresh_from_db()
                self.assertFalse(row.is_account_linked)
                self._assert_logged(
                    logs,
                    [
                        ("WARNING", self.OWNER_READ_FAILED_MESSAGE, (owner_user_id, error.status_code)),
                        (
                            "INFO",
                            self.WITHHELD_MESSAGE,
                            ("connected_account", self.GOOGLE_USER_ID, owner_user_id, None, True, None),
                        ),
                    ],
                )

    @patch.object(DjangoAuthClient, "_get_auth0_token_through_m2m", return_value={"access_token": "m2m_at"})
    @patch("auth0_oauth_client.client.Auth0")
    def test_connected_account_owner_deleted_in_auth0_falls_through_to_search(self, mock_auth0_cls, mock_m2m):
        # A row whose owner no longer exists: the Management API answers 404, which auth0-python raises as
        # Auth0Error. The login goes on through the search branch instead of failing.
        owner_user_id = "auth0|deleted-owner"
        row = self._create_connected_account(owner_user_id)
        mock_auth0_cls.return_value.users.get.side_effect = Auth0Error(
            status_code=404, error_code="inexistent_user", message="The user does not exist."
        )
        cache.set(f"_auth0_oauth_client_user_{self.GOOGLE_USER_ID}", _current_record())
        client, request = self._setup_client_and_request(user_id=self.GOOGLE_USER_ID)

        with (
            patch.object(DjangoAuthClient, "_search_users_excluding_connection", return_value=[]) as mock_search,
            patch.object(DjangoAuthClient, "_merge_and_link_accounts", return_value=[]) as mock_merge,
        ):
            result = client.verify_account_linking(request)

        self.assertEqual(result, self.NOT_LINKED)
        mock_auth0_cls.return_value.users.get.assert_called_once_with(id=owner_user_id)
        mock_search.assert_called_once_with(LINKING_EMAIL, "google-oauth2")
        mock_merge.assert_not_called()
        row.refresh_from_db()
        self.assertFalse(row.is_account_linked)

    def test_connected_account_owner_without_usable_fields_falls_through_to_search(self):
        owner_user_id = "facebook|owner"
        row = self._create_connected_account(owner_user_id)
        owners = {
            "email missing": _owner_record("facebook", email=_MISSING),
            "email null": _owner_record("facebook", email=None),
            "email_verified false": _owner_record("facebook", email_verified=False),
            "email_verified null": _owner_record("facebook", email_verified=None),
            "email_verified missing": _owner_record("facebook", email_verified=_MISSING),
            "email_verified as string": _owner_record("facebook", email_verified="true"),
            "identities empty": {"email": LINKING_EMAIL, "email_verified": True, "identities": []},
            "identities missing": {"email": LINKING_EMAIL, "email_verified": True},
        }
        for label, owner in owners.items():
            with self.subTest(owner=label):
                outcome = self._verify(_current_record(), owner=owner)

                self.assertEqual(outcome.result, self.NOT_LINKED)
                self._assert_not_linked(outcome, self.GOOGLE_USER_ID)
                outcome.search.assert_called_once_with(LINKING_EMAIL, "google-oauth2")
                row.refresh_from_db()
                self.assertFalse(row.is_account_linked)

    def test_connected_account_never_links_a_password_login(self):
        # The row's provider follows the current login's provider, so a password login can only match a row
        # whose provider is `auth0`. Even with a verified social owner, two social accounts are required.
        current_user_id = "auth0|current"
        row = self._create_connected_account("facebook|owner", provider="auth0")

        outcome = self._verify(_current_record("auth0"), user_id=current_user_id, owner=_owner_record("facebook"))

        self.assertEqual(outcome.result, self.NOT_LINKED)
        self._assert_not_linked(outcome, current_user_id)
        outcome.owner_read.assert_not_called()
        outcome.search.assert_called_once_with(LINKING_EMAIL, PASSWORD_CONNECTION)
        row.refresh_from_db()
        self.assertFalse(row.is_account_linked)

    @patch.object(DjangoAuthClient, "_get_auth0_token_through_m2m", return_value={"access_token": "m2m_at"})
    @patch("auth0_oauth_client.client.Auth0")
    def test_connected_account_owner_read_bypasses_the_user_cache(self, mock_auth0_cls, mock_m2m):
        # The cached owner claims a verified social account; the fresh Management API read disagrees.
        mock_users = mock_auth0_cls.return_value.users
        fresh_reads = {
            "password": ("auth0|owner", "auth0", True, "e-mail e senha"),
            "unverified social": ("facebook|owner", "facebook", False, "Facebook"),
        }
        for fresh_label, (owner_user_id, fresh_provider, fresh_verified, friendly_name) in fresh_reads.items():
            owner_cache_key = f"_auth0_oauth_client_user_{owner_user_id}"
            row = self._create_connected_account(owner_user_id)
            stale_cached_owner = _owner_record("facebook", email_verified=True)
            mock_users.get.return_value = _owner_record(fresh_provider, email_verified=fresh_verified)
            # The search returns the same owner, as it would, with the same fresh values.
            candidate = _candidate_record(owner_user_id, fresh_provider, email_verified=fresh_verified)

            for seed_owner_cache in (True, False):
                with self.subTest(fresh_read=fresh_label, seed_owner_cache=seed_owner_cache):
                    cache.clear()
                    mock_users.reset_mock()
                    cache.set(f"_auth0_oauth_client_user_{self.GOOGLE_USER_ID}", _current_record())
                    if seed_owner_cache:
                        cache.set(owner_cache_key, stale_cached_owner)
                    client, request = self._setup_client_and_request(user_id=self.GOOGLE_USER_ID)

                    with (
                        patch.object(
                            DjangoAuthClient, "_search_users_excluding_connection", return_value=[candidate]
                        ) as mock_search,
                        # A spy that runs the real method, so a wrong link would reach the faked Auth0 client.
                        patch.object(
                            DjangoAuthClient,
                            "_merge_and_link_accounts",
                            autospec=True,
                            side_effect=DjangoAuthClient._merge_and_link_accounts,
                        ) as mock_merge,
                    ):
                        result = client.verify_account_linking(request)

                    outcome = SimpleNamespace(
                        result=result, session=request.session, search=mock_search, merge=mock_merge
                    )
                    self._assert_manual_path(outcome, owner_user_id, fresh_provider, friendly_name)
                    mock_users.link_user_account.assert_not_called()
                    mock_users.update.assert_not_called()
                    mock_auth0_cls.assert_called_with("test.auth0.com", "m2m_at")
                    mock_users.get.assert_called_once_with(id=owner_user_id)
                    if seed_owner_cache:
                        self.assertEqual(cache.get(owner_cache_key), stale_cached_owner)
                    else:
                        self.assertIsNone(cache.get(owner_cache_key))
                    row.refresh_from_db()
                    self.assertFalse(row.is_account_linked)
            row.delete()

    # endregion

    # region Search branch, social login

    def test_social_login_into_password_account_takes_manual_path(self):
        candidate = _candidate_record(self.PASSWORD_USER_ID, "auth0", email_verified=True)
        AccountToken.objects.create(user_id=self.PASSWORD_USER_ID, refresh_token="rt_existing")

        with self.assertLogs("auth0_oauth_client", "DEBUG") as logs:
            outcome = self._verify(_current_record(), [candidate])

        self._assert_manual_path(outcome, self.PASSWORD_USER_ID, "auth0", "e-mail e senha")
        outcome.search.assert_called_once_with(LINKING_EMAIL, "google-oauth2")
        self._assert_logged(
            logs,
            [
                (
                    "INFO",
                    self.WITHHELD_MESSAGE,
                    ("search", self.GOOGLE_USER_ID, self.PASSWORD_USER_ID, "auth0", True, True),
                )
            ],
        )

    def test_social_login_into_unverified_password_account_takes_manual_path(self):
        candidate = _candidate_record(self.PASSWORD_USER_ID, "auth0", email_verified=False)
        AccountToken.objects.create(user_id=self.PASSWORD_USER_ID, refresh_token="rt_existing")

        outcome = self._verify(_current_record(), [candidate])

        self._assert_manual_path(outcome, self.PASSWORD_USER_ID, "auth0", "e-mail e senha")

    def test_unverified_social_login_into_password_account_takes_manual_path(self):
        for candidate_verified in (True, False):
            with self.subTest(candidate_email_verified=candidate_verified):
                candidate = _candidate_record(self.PASSWORD_USER_ID, "auth0", email_verified=candidate_verified)

                with self.assertLogs("auth0_oauth_client", "DEBUG") as logs:
                    outcome = self._verify(_current_record(email_verified=False), [candidate])

                self._assert_manual_path(outcome, self.PASSWORD_USER_ID, "auth0", "e-mail e senha")
                self._assert_logged(
                    logs,
                    [
                        (
                            "INFO",
                            self.WITHHELD_MESSAGE,
                            ("search", self.GOOGLE_USER_ID, self.PASSWORD_USER_ID, "auth0", False, candidate_verified),
                        )
                    ],
                )

    def test_auto_links_two_verified_social_accounts(self):
        candidate = _candidate_record(self.FACEBOOK_USER_ID, "facebook")
        AccountToken.objects.create(user_id=self.FACEBOOK_USER_ID, refresh_token="rt_facebook")
        # The current user's own Token Vault row is marked linked too, as `complete_account_linking` does.
        own_row = self._create_connected_account(self.GOOGLE_USER_ID)

        with self.assertLogs("auth0_oauth_client", "DEBUG") as logs:
            outcome = self._verify(_current_record(), [candidate])

        self.assertEqual(outcome.result, self.LINKED)
        outcome.merge.assert_called_once_with(self.FACEBOOK_USER_ID, "google-oauth2", self.GOOGLE_USER_ID)
        outcome.owner_read.assert_not_called()
        session_data = outcome.session[DjangoAuthClient.SESSION_KEY_STATE]
        self.assertEqual(session_data["userinfo"]["sub"], self.FACEBOOK_USER_ID)
        self.assertEqual(session_data["refresh_token"], "rt_facebook")
        self.assertNotIn(DjangoAuthClient.SESSION_KEY_ACCOUNT_LINKING_TX, outcome.session)
        self.assertTrue(
            AccountLinking.objects.filter(
                primary_user_id=self.FACEBOOK_USER_ID,
                secondary_provider="google-oauth2",
                secondary_user_id=self.GOOGLE_USER_ID,
            ).exists()
        )
        own_row.refresh_from_db()
        self.assertTrue(own_row.is_account_linked)
        self._assert_logged(
            logs, [("INFO", self.AUTO_LINK_MESSAGE, ("search", self.FACEBOOK_USER_ID, self.GOOGLE_USER_ID))]
        )

    def test_unverified_or_malformed_email_verified_takes_manual_path(self):
        values = {"false": False, "missing": _MISSING, "null": None, "string true": "true", "integer one": 1}
        for side in ("candidate", "current"):
            for label, value in values.items():
                with self.subTest(side=side, email_verified=label):
                    current = _current_record(email_verified=value if side == "current" else True)
                    candidate = _candidate_record(
                        self.FACEBOOK_USER_ID, "facebook", email_verified=value if side == "candidate" else True
                    )

                    outcome = self._verify(current, [candidate])

                    self._assert_manual_path(outcome, self.FACEBOOK_USER_ID, "facebook", "Facebook")

    def test_candidate_provider_without_friendly_name_uses_the_raw_provider(self):
        # A passwordless `email` connection has no friendly name; the pending path must not raise.
        candidate = _candidate_record("email|existing", "email")

        outcome = self._verify(_current_record(), [candidate])

        self._assert_manual_path(outcome, "email|existing", "email", "email")

    def test_search_candidate_with_another_email_is_ignored(self):
        candidate_user_id = self.FACEBOOK_USER_ID
        emails = {
            "another e-mail": "someone.else@example.com",
            "missing": _MISSING,
            "null": None,
            "not a string": ["victim.linking@example.com"],
        }
        for label, email in emails.items():
            with self.subTest(candidate_email=label):
                candidate = _candidate_record(candidate_user_id, "facebook", email=email)

                with self.assertLogs("auth0_oauth_client", "DEBUG") as logs:
                    outcome = self._verify(_current_record(), [candidate])

                self.assertEqual(outcome.result, self.NOT_LINKED)
                self.assertNotIn(DjangoAuthClient.SESSION_KEY_ACCOUNT_LINKING_TX, outcome.session)
                self._assert_not_linked(outcome, self.GOOGLE_USER_ID)
                self._assert_logged(
                    logs, [("WARNING", self.CANDIDATE_IGNORED_MESSAGE, (self.GOOGLE_USER_ID, candidate_user_id))]
                )
                self.assertNotIn("someone.else", repr([record.args for record in logs.records]))

    def test_search_candidate_email_matches_ignoring_case(self):
        candidate = _candidate_record(self.PASSWORD_USER_ID, "auth0", email=LINKING_EMAIL.upper())

        outcome = self._verify(_current_record(), [candidate])

        self._assert_manual_path(outcome, self.PASSWORD_USER_ID, "auth0", "e-mail e senha")

    def test_ignored_candidate_does_not_count_as_a_match(self):
        # Only the matching candidate is considered, so it is the single candidate and the rules apply to it.
        candidates = [
            _candidate_record("facebook|other-email", "facebook", email="someone.else@example.com"),
            _candidate_record(self.FACEBOOK_USER_ID, "facebook"),
        ]
        AccountToken.objects.create(user_id=self.FACEBOOK_USER_ID, refresh_token="rt_facebook")

        with self.assertLogs("auth0_oauth_client", "DEBUG") as logs:
            outcome = self._verify(_current_record(), candidates)

        self.assertEqual(outcome.result, self.LINKED)
        outcome.merge.assert_called_once_with(self.FACEBOOK_USER_ID, "google-oauth2", self.GOOGLE_USER_ID)
        self._assert_logged(
            logs,
            [
                ("WARNING", self.CANDIDATE_IGNORED_MESSAGE, (self.GOOGLE_USER_ID, "facebook|other-email")),
                ("INFO", self.AUTO_LINK_MESSAGE, ("search", self.FACEBOOK_USER_ID, self.GOOGLE_USER_ID)),
            ],
        )

    def test_multiple_candidates_never_link_automatically(self):
        candidates = [
            _candidate_record("facebook|first", "facebook"),
            _candidate_record("facebook|second", "facebook"),
        ]

        with self.assertLogs("auth0_oauth_client", "WARNING") as logs:
            outcome = self._verify(_current_record(), candidates)

        self._assert_manual_path(outcome, "facebook|first", "facebook", "Facebook")
        self._assert_logged(logs, [("WARNING", self.MULTIPLE_CANDIDATES_MESSAGE, (2, self.GOOGLE_USER_ID))])

    # endregion

    # region Search branch, password login

    @patch.object(DjangoAuthClient, "_search_users_excluding_connection")
    @patch.object(DjangoAuthClient, "get_user_by_id")
    def test_pending_linking_for_non_social_provider(self, mock_get_user_by_id, mock_search):
        user_id = "auth0|newuser"
        existing_user_id = "google-oauth2|existing"
        mock_get_user_by_id.return_value = {
            "email": "user@example.com",
            "identities": [{"provider": "auth0", "connection": "Username-Password-Authentication"}],
        }
        mock_search.return_value = [
            {
                "user_id": existing_user_id,
                "email": "user@example.com",
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

    def test_password_login_with_older_social_candidate_takes_manual_path(self):
        current_user_id = "auth0|current"
        current = _current_record("auth0", created_at="2026-01-01T00:00:00.000Z")
        candidate = _candidate_record("google-oauth2|existing", "google-oauth2", created_at="2025-12-31T23:59:59.999Z")

        with self.assertNoLogs("auth0_oauth_client", "INFO"):
            outcome = self._verify(current, [candidate], user_id=current_user_id)

        self._assert_manual_path(
            outcome,
            "google-oauth2|existing",
            "google-oauth2",
            "Google",
            secondary_user_id=current_user_id,
            secondary_provider="auth0",
        )

    def test_password_login_with_newer_social_candidate_skips_linking(self):
        current_user_id = "auth0|current"
        candidate_user_id = "google-oauth2|newer"
        current = _current_record("auth0", created_at="2026-06-01T12:00:00.000Z")
        candidate = _candidate_record(candidate_user_id, "google-oauth2", created_at="2026-11-17T09:30:00.000Z")

        with self.assertLogs("auth0_oauth_client", "DEBUG") as logs:
            outcome = self._verify(current, [candidate], user_id=current_user_id)

        self.assertEqual(outcome.result, self.NOT_LINKED)
        self.assertNotIn(DjangoAuthClient.SESSION_KEY_ACCOUNT_LINKING_TX, outcome.session)
        self._assert_not_linked(outcome, current_user_id)
        self._assert_logged(logs, [("INFO", self.SKIPPED_MESSAGE, (current_user_id, candidate_user_id))])

    def test_created_at_is_compared_as_an_instant_not_as_text(self):
        # 2025-12-31T22:00:00-03:00 (America/Sao_Paulo) is 2026-01-01T01:00:00Z: later than 00:30Z, although
        # it sorts first as text.
        current_user_id = "auth0|current"
        candidate_user_id = "google-oauth2|existing"
        cases = {
            "candidate newer across the year boundary": ("2026-01-01T00:30:00+00:00", "2025-12-31T22:00:00-03:00"),
            "candidate older across the year boundary": ("2025-12-31T22:00:00-03:00", "2026-01-01T00:30:00Z"),
        }
        for label, (current_created_at, candidate_created_at) in cases.items():
            with self.subTest(label):
                current = _current_record("auth0", created_at=current_created_at)
                candidate = _candidate_record(candidate_user_id, "google-oauth2", created_at=candidate_created_at)

                outcome = self._verify(current, [candidate], user_id=current_user_id)

                if label.startswith("candidate newer"):
                    self.assertEqual(outcome.result, self.NOT_LINKED)
                    self.assertNotIn(DjangoAuthClient.SESSION_KEY_ACCOUNT_LINKING_TX, outcome.session)
                    self._assert_not_linked(outcome, current_user_id)
                else:
                    self._assert_manual_path(
                        outcome,
                        candidate_user_id,
                        "google-oauth2",
                        "Google",
                        secondary_user_id=current_user_id,
                        secondary_provider="auth0",
                    )

    def test_equal_missing_or_unusable_created_at_keeps_manual_path(self):
        current_user_id = "auth0|current"
        candidate_user_id = "google-oauth2|existing"
        cases = {
            "equal": ("2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z"),
            "equal instant in another offset": ("2026-01-01T00:00:00Z", "2025-12-31T21:00:00-03:00"),
            "missing on current": (_MISSING, "2026-02-01T00:00:00Z"),
            "missing on candidate": ("2026-01-01T00:00:00Z", _MISSING),
            "null on candidate": ("2026-01-01T00:00:00Z", None),
            "unparseable on current": ("yesterday", "2026-02-01T00:00:00Z"),
            "unparseable on candidate": ("2026-01-01T00:00:00Z", "yesterday"),
            "naive on current": ("2026-01-01T00:00:00", "2026-02-01T00:00:00Z"),
            "naive on candidate": ("2026-01-01T00:00:00Z", "2026-02-01T00:00:00"),
            "not a string on candidate": ("2026-01-01T00:00:00Z", 1769904000),
        }
        for label, (current_created_at, candidate_created_at) in cases.items():
            with self.subTest(label):
                current = _current_record("auth0", created_at=current_created_at)
                candidate = _candidate_record(candidate_user_id, "google-oauth2", created_at=candidate_created_at)

                outcome = self._verify(current, [candidate], user_id=current_user_id)

                self._assert_manual_path(
                    outcome,
                    candidate_user_id,
                    "google-oauth2",
                    "Google",
                    secondary_user_id=current_user_id,
                    secondary_provider="auth0",
                )

    def _password_candidate_in_another_database(self, user_id, created_at):
        # The search excludes the current connection, so a password candidate on a password login can only come
        # from another database connection.
        return {
            "user_id": user_id,
            "identities": [{"provider": "auth0", "connection": "Another-Database"}],
            "email": LINKING_EMAIL,
            "email_verified": True,
            "created_at": created_at,
        }

    def test_password_login_with_newer_password_candidate_skips_linking(self):
        # The newer-account rule holds whatever the candidate's provider is.
        current_user_id = "auth0|current"
        candidate_user_id = "auth0|other-database"
        current = _current_record("auth0", created_at="2026-01-01T00:00:00Z")
        candidate = self._password_candidate_in_another_database(candidate_user_id, "2026-02-01T00:00:00Z")

        with self.assertLogs("auth0_oauth_client", "DEBUG") as logs:
            outcome = self._verify(current, [candidate], user_id=current_user_id)

        self.assertEqual(outcome.result, self.NOT_LINKED)
        self.assertNotIn(DjangoAuthClient.SESSION_KEY_ACCOUNT_LINKING_TX, outcome.session)
        self._assert_not_linked(outcome, current_user_id)
        self._assert_logged(logs, [("INFO", self.SKIPPED_MESSAGE, (current_user_id, candidate_user_id))])

    def test_password_login_with_older_password_candidate_takes_manual_path(self):
        current_user_id = "auth0|current"
        candidate_user_id = "auth0|other-database"
        current = _current_record("auth0", created_at="2026-02-01T00:00:00Z")
        candidate = self._password_candidate_in_another_database(candidate_user_id, "2026-01-01T00:00:00Z")

        outcome = self._verify(current, [candidate], user_id=current_user_id)

        self.assertEqual(outcome.result, self.PENDING)
        pending = outcome.session[DjangoAuthClient.SESSION_KEY_ACCOUNT_LINKING_TX]
        self.assertEqual(pending["primary_user_id"], candidate_user_id)
        self.assertEqual(pending["primary_connection_name"], "Another-Database")
        self.assertEqual(pending["primary_provider_friendly_name"], "e-mail e senha")
        self._assert_not_linked(outcome, current_user_id)

    def test_social_login_with_newer_password_candidate_skips_linking(self):
        # An older Google account and a password account registered later with the same e-mail (possibly by
        # someone else): confirming would move the Google identity, and her data, into the newer account.
        current = _current_record(created_at="2026-01-01T00:00:00.000Z")
        candidate = _candidate_record(self.PASSWORD_USER_ID, "auth0", created_at="2026-03-01T00:00:00.000Z")

        with self.assertLogs("auth0_oauth_client", "DEBUG") as logs:
            outcome = self._verify(current, [candidate])

        self.assertEqual(outcome.result, self.NOT_LINKED)
        self.assertNotIn(DjangoAuthClient.SESSION_KEY_ACCOUNT_LINKING_TX, outcome.session)
        self._assert_not_linked(outcome, self.GOOGLE_USER_ID)
        self._assert_logged(logs, [("INFO", self.SKIPPED_MESSAGE, (self.GOOGLE_USER_ID, self.PASSWORD_USER_ID))])

    def test_social_login_with_newer_verified_social_candidate_skips_linking(self):
        current = _current_record(created_at="2026-01-01T00:00:00.000Z")
        candidate = _candidate_record(self.FACEBOOK_USER_ID, "facebook", created_at="2026-01-01T00:00:00.001Z")
        AccountToken.objects.create(user_id=self.FACEBOOK_USER_ID, refresh_token="rt_facebook")

        with self.assertLogs("auth0_oauth_client", "DEBUG") as logs:
            outcome = self._verify(current, [candidate])

        self.assertEqual(outcome.result, self.NOT_LINKED)
        self.assertNotIn(DjangoAuthClient.SESSION_KEY_ACCOUNT_LINKING_TX, outcome.session)
        self._assert_not_linked(outcome, self.GOOGLE_USER_ID)
        self._assert_logged(logs, [("INFO", self.SKIPPED_MESSAGE, (self.GOOGLE_USER_ID, self.FACEBOOK_USER_ID))])

    def test_social_login_with_older_password_candidate_takes_manual_path(self):
        current = _current_record(created_at="2026-11-17T09:30:00.000Z")
        candidate = _candidate_record(self.PASSWORD_USER_ID, "auth0", created_at="2026-06-01T12:00:00.000Z")

        outcome = self._verify(current, [candidate])

        self._assert_manual_path(outcome, self.PASSWORD_USER_ID, "auth0", "e-mail e senha")

    def test_social_login_with_older_or_same_age_verified_social_candidate_links_automatically(self):
        cases = {
            "older": ("2026-11-17T09:30:00.000Z", "2026-06-01T12:00:00.000Z"),
            "same instant": ("2026-01-01T00:00:00Z", "2025-12-31T21:00:00-03:00"),
        }
        AccountToken.objects.create(user_id=self.FACEBOOK_USER_ID, refresh_token="rt_facebook")
        for label, (current_created_at, candidate_created_at) in cases.items():
            with self.subTest(label):
                AccountLinking.objects.all().delete()
                current = _current_record(created_at=current_created_at)
                candidate = _candidate_record(self.FACEBOOK_USER_ID, "facebook", created_at=candidate_created_at)

                outcome = self._verify(current, [candidate])

                self.assertEqual(outcome.result, self.LINKED)
                outcome.merge.assert_called_once_with(self.FACEBOOK_USER_ID, "google-oauth2", self.GOOGLE_USER_ID)

    def test_multiple_candidates_on_password_login_apply_the_newer_rule_to_the_first(self):
        current_user_id = "auth0|current"
        current = _current_record("auth0", created_at="2026-01-01T00:00:00Z")
        candidates = [
            _candidate_record("google-oauth2|newer", "google-oauth2", created_at="2026-02-01T00:00:00Z"),
            _candidate_record("facebook|older", "facebook", created_at="2025-01-01T00:00:00Z"),
        ]

        with self.assertLogs("auth0_oauth_client", "DEBUG") as logs:
            outcome = self._verify(current, candidates, user_id=current_user_id)

        self.assertEqual(outcome.result, self.NOT_LINKED)
        self.assertNotIn(DjangoAuthClient.SESSION_KEY_ACCOUNT_LINKING_TX, outcome.session)
        self._assert_not_linked(outcome, current_user_id)
        self._assert_logged(
            logs,
            [
                ("WARNING", self.MULTIPLE_CANDIDATES_MESSAGE, (2, current_user_id)),
                ("INFO", self.SKIPPED_MESSAGE, (current_user_id, "google-oauth2|newer")),
            ],
        )

    # endregion

    @patch.object(DjangoAuthClient, "_search_users_excluding_connection")
    @patch.object(DjangoAuthClient, "get_user_by_id")
    def test_no_linking_when_no_existing_accounts(self, mock_get_user_by_id, mock_search):
        mock_get_user_by_id.return_value = {
            "email": "user@example.com",
            "identities": [{"provider": "auth0", "connection": "Username-Password-Authentication"}],
        }
        mock_search.return_value = []

        client, request = self._setup_client_and_request()
        result = client.verify_account_linking(request)

        self.assertFalse(result["is_pending_account_linking"])
        self.assertFalse(result["is_account_linked"])

    @patch.object(DjangoAuthClient, "get_user_by_id")
    def test_no_linking_when_all_identities_present(self, mock_get_user_by_id):
        mock_get_user_by_id.return_value = {
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

    def test_returns_not_linked_without_a_session(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()

        self.assertEqual(client.verify_account_linking(request), self.NOT_LINKED)


class AccountLinkingHelpersTest(TestCase):
    def test_is_verified_only_for_boolean_true(self):
        client = DjangoAuthClient()
        self.assertTrue(client._is_verified({"email_verified": True}))
        for value in (False, None, "true", 1, {}):
            with self.subTest(email_verified=value):
                self.assertFalse(client._is_verified({"email_verified": value}))
        self.assertFalse(client._is_verified({}))

    def test_primary_provider_reads_the_first_identity(self):
        client = DjangoAuthClient()
        record = {"identities": [{"provider": "auth0"}, {"provider": "google-oauth2"}]}
        self.assertEqual(client._primary_provider(record), "auth0")

    def test_primary_provider_is_none_for_unusable_identities(self):
        client = DjangoAuthClient()
        records = {
            "missing": {},
            "null": {"identities": None},
            "empty": {"identities": []},
            "not a list": {"identities": "auth0"},
            "first not a dict": {"identities": ["auth0"]},
            "provider missing": {"identities": [{"connection": "google-oauth2"}]},
            "provider not a string": {"identities": [{"provider": 1}]},
        }
        for label, record in records.items():
            with self.subTest(label):
                self.assertIsNone(client._primary_provider(record))

    def test_is_social_account(self):
        client = DjangoAuthClient()
        self.assertTrue(client._is_social_account({"identities": [{"provider": "facebook"}]}))
        self.assertFalse(client._is_social_account({"identities": [{"provider": "auth0"}]}))
        self.assertFalse(client._is_social_account({"identities": []}))

    def test_parse_created_at_returns_an_aware_datetime(self):
        client = DjangoAuthClient()
        expected = datetime(2026, 1, 1, tzinfo=UTC)
        for value in ("2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00Z", "2025-12-31T21:00:00-03:00"):
            with self.subTest(value):
                self.assertEqual(client._parse_created_at(value), expected)

    def test_parse_created_at_is_none_for_unusable_values(self):
        client = DjangoAuthClient()
        for value in ("2026-01-01T00:00:00", "yesterday", "", 1767225600, None):
            with self.subTest(value=value):
                self.assertIsNone(client._parse_created_at(value))

    def test_is_created_after_only_when_strictly_later_and_both_known(self):
        client = DjangoAuthClient()
        cases = {
            "later": ("2026-01-01T00:00:00.001Z", "2026-01-01T00:00:00Z", True),
            "earlier": ("2025-12-31T23:59:59Z", "2026-01-01T00:00:00Z", False),
            "same instant in another offset": ("2025-12-31T21:00:00-03:00", "2026-01-01T00:00:00Z", False),
            "record unknown": (None, "2026-01-01T00:00:00Z", False),
            "reference unknown": ("2026-01-01T00:00:00Z", "yesterday", False),
        }
        for label, (record_created_at, reference_created_at, expected) in cases.items():
            with self.subTest(label):
                self.assertIs(
                    client._is_created_after({"created_at": record_created_at}, {"created_at": reference_created_at}),
                    expected,
                )


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
        self.assertIsInstance(ctx.exception.__cause__, Exception)
        self.assertEqual(str(ctx.exception.__cause__), "Network error")

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


class GetUserByIdTest(TestCase):
    def setUp(self):
        cache.clear()

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
        result = client.get_user_by_id("auth0|user1")
        self.assertEqual(result["user_id"], "auth0|user1")

    @patch.object(DjangoAuthClient, "_get_auth0_token_through_m2m")
    @patch("auth0_oauth_client.client.Auth0")
    def test_returns_cached_result_on_second_call(self, mock_auth0_cls, mock_m2m):
        mock_m2m.return_value = {"access_token": "m2m_at"}
        mock_auth0_instance = MagicMock()
        mock_auth0_instance.users.get.return_value = {
            "user_id": "auth0|user1",
            "email": "user@example.com",
        }
        mock_auth0_cls.return_value = mock_auth0_instance

        client = DjangoAuthClient()
        client.get_user_by_id("auth0|user1")
        client.get_user_by_id("auth0|user1")

        mock_auth0_instance.users.get.assert_called_once()

    @patch.object(DjangoAuthClient, "_get_auth0_token_through_m2m")
    @patch("auth0_oauth_client.client.Auth0")
    def test_cache_is_invalidated_after_update_user(self, mock_auth0_cls, mock_m2m):
        mock_m2m.return_value = {"access_token": "m2m_at"}
        mock_auth0_instance = MagicMock()
        mock_auth0_instance.users.get.side_effect = [
            {"user_id": "auth0|user1", "email": "old@example.com"},
            {"user_id": "auth0|user1", "email": "new@example.com"},
        ]
        mock_auth0_instance.users.update.return_value = {"user_id": "auth0|user1"}
        mock_auth0_cls.return_value = mock_auth0_instance

        client = DjangoAuthClient()
        first = client.get_user_by_id("auth0|user1")
        self.assertEqual(first["email"], "old@example.com")

        client._update_user("auth0|user1", {"email": "new@example.com"})

        second = client.get_user_by_id("auth0|user1")
        self.assertEqual(second["email"], "new@example.com")
        self.assertEqual(mock_auth0_instance.users.get.call_count, 2)


class GetUserByIdUncachedTest(TestCase):
    CACHE_KEY = "_auth0_oauth_client_user_auth0|user1"

    def setUp(self):
        cache.clear()

    @patch.object(DjangoAuthClient, "_get_auth0_token_through_m2m", return_value={"access_token": "m2m_at"})
    @patch("auth0_oauth_client.client.Auth0")
    def test_reads_from_management_api_without_writing_the_cache(self, mock_auth0_cls, mock_m2m):
        mock_auth0_cls.return_value.users.get.return_value = {"user_id": "auth0|user1", "email_verified": True}

        client = DjangoAuthClient()
        result = client._get_user_by_id_uncached("auth0|user1")

        self.assertEqual(result, {"user_id": "auth0|user1", "email_verified": True})
        mock_auth0_cls.assert_called_once_with("test.auth0.com", "m2m_at")
        mock_auth0_cls.return_value.users.get.assert_called_once_with(id="auth0|user1")
        self.assertIsNone(cache.get(self.CACHE_KEY))

    @patch.object(DjangoAuthClient, "_get_auth0_token_through_m2m", return_value={"access_token": "m2m_at"})
    @patch("auth0_oauth_client.client.Auth0")
    def test_ignores_and_keeps_a_cached_record(self, mock_auth0_cls, mock_m2m):
        cached = {"user_id": "auth0|user1", "email_verified": True}
        cache.set(self.CACHE_KEY, cached)
        mock_auth0_cls.return_value.users.get.return_value = {"user_id": "auth0|user1", "email_verified": False}

        client = DjangoAuthClient()
        result = client._get_user_by_id_uncached("auth0|user1")

        self.assertEqual(result, {"user_id": "auth0|user1", "email_verified": False})
        self.assertEqual(cache.get(self.CACHE_KEY), cached)


class GetUserInfoTest(TestCase):
    def test_returns_userinfo_from_session(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()
        userinfo = {"sub": "auth0|user1", "email": "user@example.com", "name": "Test"}
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = {
            "userinfo": userinfo,
            "refresh_token": "rt_123",
        }

        result = client.get_user_info(request)
        self.assertEqual(result, userinfo)

    def test_returns_none_when_no_session(self):
        client = DjangoAuthClient()
        request = _make_request_with_session()

        result = client.get_user_info(request)
        self.assertIsNone(result)


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
        mock_auth0_cls.assert_called_once_with("test.auth0.com", "m2m_at")
        mock_auth0_instance.users.list.assert_called_once_with(
            q='email:"user@example.com" AND NOT identities.connection:"google-oauth2"',
            fields=[
                "user_id",
                "identities.provider",
                "identities.connection",
                "email",
                "email_verified",
                "created_at",
            ],
        )


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
    @patch.object(DjangoAuthClient, "get_user_by_id")
    def test_merges_metadata_and_links(self, mock_get_user_by_id, mock_update, mock_link):
        mock_get_user_by_id.side_effect = [
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
    @patch.object(DjangoAuthClient, "get_user_by_id")
    def test_skips_update_when_no_metadata(self, mock_get_user_by_id, mock_update, mock_link):
        mock_get_user_by_id.side_effect = [
            {},
            {},
        ]
        client = DjangoAuthClient()
        client._merge_and_link_accounts("auth0|primary", "google-oauth2", "google-oauth2|secondary")
        mock_update.assert_not_called()


def _make_m2m_jwt(
    iss="https://test.auth0.com/",
    aud="https://test.auth0.com/api/v2/",
    scope="",
):
    """Build a fake M2M access token. Signature is irrelevant — ping() decodes without verification."""
    return jwt.encode({"iss": iss, "aud": aud, "scope": scope}, key="secret", algorithm="HS256")


def _make_token_response(jwt_token, expires_in=86400):
    response = MagicMock()
    response.ok = True
    response.status_code = 200
    response.json.return_value = {"access_token": jwt_token, "expires_in": expires_in}
    return response


def _make_error_response(status_code, body=None):
    response = MagicMock()
    response.ok = False
    response.status_code = status_code
    if body is None:
        response.json.side_effect = requests.JSONDecodeError("no body", "", 0)
        response.text = ""
    else:
        response.json.return_value = body
        response.text = str(body)
    return response


class PingTest(TestCase):
    M2M_CACHE_KEY = "_auth0_oauth_client_m2m_token"

    def setUp(self):
        cache.clear()

    @patch("auth0_oauth_client.client.requests.post")
    def test_happy_path_returns_ok_with_expected_keys(self, mock_post):
        token = _make_m2m_jwt(scope="read:users update:users")
        mock_post.return_value = _make_token_response(token, expires_in=86400)

        client = DjangoAuthClient()
        result = client.ping(required_scopes=["read:users", "update:users"])

        self.assertTrue(result["ok"])
        self.assertEqual(result["expires_in"], 86400)
        self.assertEqual(sorted(result["granted_scopes"]), ["read:users", "update:users"])
        self.assertIsInstance(result["latency_ms"], int)
        self.assertGreaterEqual(result["latency_ms"], 0)

    @patch("auth0_oauth_client.client.requests.post")
    def test_posts_client_credentials_to_correct_url(self, mock_post):
        mock_post.return_value = _make_token_response(_make_m2m_jwt())

        client = DjangoAuthClient()
        client.ping()

        call_kwargs = mock_post.call_args.kwargs
        self.assertEqual(mock_post.call_args.args[0], "https://test.auth0.com/oauth/token")
        self.assertEqual(call_kwargs["json"]["grant_type"], "client_credentials")
        self.assertEqual(call_kwargs["json"]["client_id"], "test-client-id")
        self.assertEqual(call_kwargs["json"]["client_secret"], "test-client-secret")
        self.assertEqual(call_kwargs["json"]["audience"], "https://test.auth0.com/api/v2/")

    @patch("auth0_oauth_client.client.requests.post")
    def test_raises_m2m_token_on_401(self, mock_post):
        mock_post.return_value = _make_error_response(
            401, {"error": "access_denied", "error_description": "Unauthorized"}
        )

        client = DjangoAuthClient()
        with self.assertRaises(Auth0PingError) as ctx:
            client.ping()
        self.assertEqual(ctx.exception.stage, "m2m_token")
        self.assertEqual(ctx.exception.status_code, 401)

    @patch("auth0_oauth_client.client.requests.post")
    def test_raises_m2m_token_on_403(self, mock_post):
        mock_post.return_value = _make_error_response(403, {"error": "access_denied"})

        client = DjangoAuthClient()
        with self.assertRaises(Auth0PingError) as ctx:
            client.ping()
        self.assertEqual(ctx.exception.stage, "m2m_token")
        self.assertEqual(ctx.exception.status_code, 403)

    @patch("auth0_oauth_client.client.requests.post")
    def test_raises_m2m_token_on_timeout_without_status_code(self, mock_post):
        mock_post.side_effect = requests.Timeout("timed out")

        client = DjangoAuthClient()
        with self.assertRaises(Auth0PingError) as ctx:
            client.ping(timeout=2.5)
        self.assertEqual(ctx.exception.stage, "m2m_token")
        self.assertIsNone(ctx.exception.status_code)
        self.assertIn("2.5", str(ctx.exception))

    @patch("auth0_oauth_client.client.requests.post")
    def test_raises_m2m_token_on_network_error(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("dns failure")

        client = DjangoAuthClient()
        with self.assertRaises(Auth0PingError) as ctx:
            client.ping()
        self.assertEqual(ctx.exception.stage, "m2m_token")
        self.assertIsNone(ctx.exception.status_code)

    @patch("auth0_oauth_client.client.requests.post")
    def test_raises_m2m_token_when_response_lacks_access_token(self, mock_post):
        response = MagicMock()
        response.ok = True
        response.status_code = 200
        response.json.return_value = {"expires_in": 86400}
        mock_post.return_value = response

        client = DjangoAuthClient()
        with self.assertRaises(Auth0PingError) as ctx:
            client.ping()
        self.assertEqual(ctx.exception.stage, "m2m_token")

    @patch("auth0_oauth_client.client.requests.post")
    def test_raises_token_claims_on_iss_mismatch(self, mock_post):
        token = _make_m2m_jwt(iss="https://other.auth0.com/")
        mock_post.return_value = _make_token_response(token)

        client = DjangoAuthClient()
        with self.assertRaises(Auth0PingError) as ctx:
            client.ping()
        self.assertEqual(ctx.exception.stage, "token_claims")
        self.assertIn("iss", str(ctx.exception))

    @patch("auth0_oauth_client.client.requests.post")
    def test_raises_token_claims_on_aud_mismatch(self, mock_post):
        token = _make_m2m_jwt(aud="https://other.auth0.com/api/v2/")
        mock_post.return_value = _make_token_response(token)

        client = DjangoAuthClient()
        with self.assertRaises(Auth0PingError) as ctx:
            client.ping()
        self.assertEqual(ctx.exception.stage, "token_claims")
        self.assertIn("aud", str(ctx.exception))

    @patch("auth0_oauth_client.client.requests.post")
    def test_aud_accepts_list_containing_expected_audience(self, mock_post):
        token = _make_m2m_jwt(aud=["https://test.auth0.com/api/v2/", "https://test.auth0.com/userinfo"])
        mock_post.return_value = _make_token_response(token)

        client = DjangoAuthClient()
        result = client.ping()
        self.assertTrue(result["ok"])

    @patch("auth0_oauth_client.client.requests.post")
    def test_raises_scope_grant_with_exact_missing_scopes(self, mock_post):
        token = _make_m2m_jwt(scope="read:users")
        mock_post.return_value = _make_token_response(token)

        client = DjangoAuthClient()
        with self.assertRaises(Auth0PingError) as ctx:
            client.ping(required_scopes={"read:users", "update:users", "read:user_idp_tokens"})
        self.assertEqual(ctx.exception.stage, "scope_grant")
        self.assertEqual(
            ctx.exception.missing_scopes,
            frozenset({"update:users", "read:user_idp_tokens"}),
        )

    @patch("auth0_oauth_client.client.requests.post")
    def test_empty_required_scopes_skips_scope_check(self, mock_post):
        token = _make_m2m_jwt(scope="")
        mock_post.return_value = _make_token_response(token)

        client = DjangoAuthClient()
        result = client.ping()
        self.assertTrue(result["ok"])
        self.assertEqual(result["granted_scopes"], [])

    @patch("auth0_oauth_client.client.requests.post")
    def test_does_not_consult_existing_m2m_cache(self, mock_post):
        cache.set(self.M2M_CACHE_KEY, {"access_token": "stale_cached_token", "expires_in": 60})
        token = _make_m2m_jwt()
        mock_post.return_value = _make_token_response(token)

        client = DjangoAuthClient()
        client.ping()

        mock_post.assert_called_once()
        cached = cache.get(self.M2M_CACHE_KEY)
        self.assertEqual(cached["access_token"], "stale_cached_token")

    @patch("auth0_oauth_client.client.requests.post")
    def test_does_not_populate_m2m_cache(self, mock_post):
        token = _make_m2m_jwt()
        mock_post.return_value = _make_token_response(token)

        client = DjangoAuthClient()
        client.ping()

        self.assertIsNone(cache.get(self.M2M_CACHE_KEY))

    @patch("auth0_oauth_client.client.requests.post")
    def test_timeout_is_passed_to_http_layer(self, mock_post):
        token = _make_m2m_jwt()
        mock_post.return_value = _make_token_response(token)

        client = DjangoAuthClient()
        client.ping(timeout=1.5)

        self.assertEqual(mock_post.call_args.kwargs["timeout"], 1.5)

    @patch("auth0_oauth_client.client.requests.post")
    def test_raises_m2m_token_when_error_response_body_is_not_json(self, mock_post):
        response = _make_error_response(502, body=None)
        response.text = "<html>Bad Gateway</html>"
        mock_post.return_value = response

        client = DjangoAuthClient()
        with self.assertRaises(Auth0PingError) as ctx:
            client.ping()
        self.assertEqual(ctx.exception.stage, "m2m_token")
        self.assertEqual(ctx.exception.status_code, 502)

    @patch("auth0_oauth_client.client.requests.post")
    def test_raises_m2m_token_when_success_response_body_is_not_json(self, mock_post):
        response = MagicMock()
        response.ok = True
        response.status_code = 200
        response.json.side_effect = requests.JSONDecodeError("not json", "", 0)
        mock_post.return_value = response

        client = DjangoAuthClient()
        with self.assertRaises(Auth0PingError) as ctx:
            client.ping()
        self.assertEqual(ctx.exception.stage, "m2m_token")

    @patch("auth0_oauth_client.client.requests.post")
    def test_raises_token_claims_when_access_token_is_not_a_jwt(self, mock_post):
        response = MagicMock()
        response.ok = True
        response.status_code = 200
        response.json.return_value = {"access_token": "not-a-jwt", "expires_in": 86400}
        mock_post.return_value = response

        client = DjangoAuthClient()
        with self.assertRaises(Auth0PingError) as ctx:
            client.ping()
        self.assertEqual(ctx.exception.stage, "token_claims")


class GetAccessTokenForConnectionTest(TestCase):
    @patch("auth0_oauth_client.client.GetToken")
    def test_exchanges_the_session_refresh_token(self, mock_get_token_cls):
        # Regression: the method called itself with the refresh token in place of the request.
        mock_exchange = mock_get_token_cls.return_value.access_token_for_connection
        mock_exchange.return_value = {"access_token": "fed_at", "expires_in": 3600, "scope": "calendar"}
        client = DjangoAuthClient()
        request = _make_request_with_session()
        request.session[DjangoAuthClient.SESSION_KEY_STATE] = _make_session_data(refresh_token="rt_session")

        result = client.get_access_token_for_connection(request, "google-oauth2")

        self.assertEqual(result["access_token"], "fed_at")
        mock_get_token_cls.assert_called_once_with("test.auth0.com", "test-client-id", "test-client-secret")
        mock_exchange.assert_called_once()
        self.assertEqual(mock_exchange.call_args.kwargs["subject_token"], "rt_session")
        self.assertEqual(mock_exchange.call_args.kwargs["connection"], "google-oauth2")


class GetAccessTokenForConnectionUsingUserRefreshTokenTest(TestCase):
    @patch("auth0_oauth_client.client.GetToken")
    def test_returns_result_on_success(self, mock_get_token_cls):
        mock_instance = MagicMock()
        mock_instance.access_token_for_connection.return_value = {
            "access_token": "fed_at",
            "scope": "https://www.googleapis.com/auth/calendar",
        }
        mock_get_token_cls.return_value = mock_instance

        client = DjangoAuthClient()
        result = client.get_access_token_for_connection_using_user_refresh_token("rt_123", "google-oauth2")
        self.assertEqual(result["access_token"], "fed_at")

    @patch("auth0_oauth_client.client.GetToken")
    def test_raises_typed_exception_on_federated_not_found_401(self, mock_get_token_cls):
        mock_instance = MagicMock()
        mock_instance.access_token_for_connection.side_effect = Auth0Error(
            status_code=401,
            error_code="federated_connection_refresh_token_not_found",
            message="Federated connection Refresh Token not found.",
        )
        mock_get_token_cls.return_value = mock_instance

        client = DjangoAuthClient()
        with self.assertRaises(FederatedConnectionRefreshTokenNotFound) as ctx:
            client.get_access_token_for_connection_using_user_refresh_token("rt_123", "google-oauth2")
        self.assertEqual(ctx.exception.error, "federated_connection_refresh_token_not_found")
        self.assertEqual(ctx.exception.code, "federated_connection_refresh_token_not_found")
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertIsNotNone(ctx.exception.cause)

    @patch("auth0_oauth_client.client.GetToken")
    def test_reraises_other_auth0_errors(self, mock_get_token_cls):
        mock_instance = MagicMock()
        mock_instance.access_token_for_connection.side_effect = Auth0Error(
            status_code=500,
            error_code="server_error",
            message="boom",
        )
        mock_get_token_cls.return_value = mock_instance

        client = DjangoAuthClient()
        with self.assertRaises(Auth0Error):
            client.get_access_token_for_connection_using_user_refresh_token("rt_123", "google-oauth2")

    @patch("auth0_oauth_client.client.GetToken")
    def test_does_not_wrap_non_federated_401(self, mock_get_token_cls):
        mock_instance = MagicMock()
        mock_instance.access_token_for_connection.side_effect = Auth0Error(
            status_code=401,
            error_code="invalid_grant",
            message="unrelated 401",
        )
        mock_get_token_cls.return_value = mock_instance

        client = DjangoAuthClient()
        with self.assertRaises(Auth0Error):
            client.get_access_token_for_connection_using_user_refresh_token("rt_123", "google-oauth2")


class ListFederatedConnectionsTokensetsTest(TestCase):
    def setUp(self):
        cache.clear()

    @patch.object(DjangoAuthClient, "_get_auth0_token_through_m2m")
    @patch("auth0_oauth_client.client.requests.get")
    def test_returns_tokensets(self, mock_get, mock_m2m):
        mock_m2m.return_value = {"access_token": "m2m_at"}
        response = MagicMock()
        response.json.return_value = [{"connection": "google-oauth2", "scopes": ["..."]}]
        response.raise_for_status.return_value = None
        mock_get.return_value = response

        client = DjangoAuthClient()
        result = client.list_federated_connections_tokensets("google-oauth2|123")

        self.assertEqual(result[0]["connection"], "google-oauth2")
        args, kwargs = mock_get.call_args
        self.assertIn("/api/v2/users/", args[0])
        # The user_id is URL-encoded into the path.
        self.assertIn("google-oauth2%7C123", args[0])
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer m2m_at")

    @patch.object(DjangoAuthClient, "_get_auth0_token_through_m2m")
    @patch("auth0_oauth_client.client.requests.get")
    def test_raises_on_http_error(self, mock_get, mock_m2m):
        mock_m2m.return_value = {"access_token": "m2m_at"}
        response = MagicMock()
        response.status_code = 500
        response.raise_for_status.side_effect = requests.HTTPError("500")
        mock_get.return_value = response

        client = DjangoAuthClient()
        with self.assertRaises(requests.HTTPError):
            client.list_federated_connections_tokensets("google-oauth2|123")

    @patch.object(DjangoAuthClient, "_get_auth0_token_through_m2m")
    @patch("auth0_oauth_client.client.requests.get")
    def test_returns_empty_list_on_200_empty_vault(self, mock_get, mock_m2m):
        # Per the Auth0 docs, an EMPTY vault is HTTP 200 with `[]` (not a 404). It must be returned
        # as-is so the caller recognises a confirmed-empty vault.
        mock_m2m.return_value = {"access_token": "m2m_at"}
        response = MagicMock()
        response.status_code = 200
        response.raise_for_status.return_value = None
        response.json.return_value = []
        mock_get.return_value = response

        client = DjangoAuthClient()
        result = client.list_federated_connections_tokensets("google-oauth2|123")

        self.assertEqual(result, [])

    @patch.object(DjangoAuthClient, "_get_auth0_token_through_m2m")
    @patch("auth0_oauth_client.client.requests.get")
    def test_raises_on_404_user_not_found(self, mock_get, mock_m2m):
        # Per the Auth0 docs, a 404 means the *user does not exist* — a genuine error, NOT an empty
        # vault. It must raise (not map to []) so the caller treats it as a transient skip rather than
        # wrongly flipping the psychologist to NEEDS_RECONNECT.
        mock_m2m.return_value = {"access_token": "m2m_at"}
        response = MagicMock()
        response.status_code = 404
        response.raise_for_status.side_effect = requests.HTTPError("404")
        mock_get.return_value = response

        client = DjangoAuthClient()
        with self.assertRaises(requests.HTTPError):
            client.list_federated_connections_tokensets("google-oauth2|123")
