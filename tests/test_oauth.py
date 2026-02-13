import base64
import hashlib

from unittest.mock import MagicMock
from urllib.parse import parse_qs
from urllib.parse import urlparse

import requests_mock

from django.core.cache import cache
from django.test import TestCase

from auth0_oauth_client.errors import ApiOauthClientError
from auth0_oauth_client.errors import MyAccountApiOauthClientError
from auth0_oauth_client.oauth import _bearer_headers
from auth0_oauth_client.oauth import _handle_myaccount_error
from auth0_oauth_client.oauth import _myaccount_base_url
from auth0_oauth_client.oauth import build_authorization_url
from auth0_oauth_client.oauth import build_logout_url
from auth0_oauth_client.oauth import exchange_code_for_tokens
from auth0_oauth_client.oauth import exchange_connect_code
from auth0_oauth_client.oauth import fetch_oidc_metadata
from auth0_oauth_client.oauth import generate_pkce_pair
from auth0_oauth_client.oauth import generate_state
from auth0_oauth_client.oauth import myaccount_complete_connect_account
from auth0_oauth_client.oauth import myaccount_connect_account
from auth0_oauth_client.oauth import myaccount_delete_connected_account
from auth0_oauth_client.oauth import myaccount_list_connected_accounts
from auth0_oauth_client.oauth import myaccount_list_connections
from auth0_oauth_client.oauth import refresh_access_token


class GeneratePkcePairTest(TestCase):
    def test_returns_tuple_of_two_strings(self):
        verifier, challenge = generate_pkce_pair()
        self.assertIsInstance(verifier, str)
        self.assertIsInstance(challenge, str)

    def test_challenge_is_sha256_of_verifier(self):
        verifier, challenge = generate_pkce_pair()
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        expected_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        self.assertEqual(challenge, expected_challenge)

    def test_generates_different_values_each_call(self):
        v1, c1 = generate_pkce_pair()
        v2, c2 = generate_pkce_pair()
        self.assertNotEqual(v1, v2)
        self.assertNotEqual(c1, c2)


class GenerateStateTest(TestCase):
    def test_returns_string(self):
        state = generate_state()
        self.assertIsInstance(state, str)

    def test_generates_different_values(self):
        s1 = generate_state()
        s2 = generate_state()
        self.assertNotEqual(s1, s2)

    def test_is_url_safe(self):
        state = generate_state()
        # URL-safe base64 only contains these characters
        allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")
        self.assertTrue(all(c in allowed for c in state))


class FetchOidcMetadataTest(TestCase):
    def setUp(self):
        cache.clear()

    def test_fetches_from_url_when_not_cached(self):
        metadata = {"issuer": "https://test.auth0.com/", "authorization_endpoint": "https://test.auth0.com/authorize"}
        with requests_mock.Mocker() as m:
            m.get("https://custom.auth0.com/.well-known/openid-configuration", json=metadata)
            result = fetch_oidc_metadata(domain="custom.auth0.com")
        self.assertEqual(result, metadata)

    def test_returns_cached_value(self):
        cached_metadata = {"issuer": "https://cached.auth0.com/"}
        cache.set("auth0_oidc_metadata", cached_metadata)
        result = fetch_oidc_metadata(domain="custom.auth0.com")
        self.assertEqual(result, cached_metadata)

    def test_uses_auth_client_domain_when_no_domain_provided(self):
        metadata = {"issuer": "https://test.auth0.com/"}
        with requests_mock.Mocker() as m:
            m.get("https://test.auth0.com/.well-known/openid-configuration", json=metadata)
            result = fetch_oidc_metadata()
        self.assertEqual(result, metadata)

    def test_caches_result_after_fetch(self):
        metadata = {"issuer": "https://test.auth0.com/"}
        with requests_mock.Mocker() as m:
            m.get("https://custom.auth0.com/.well-known/openid-configuration", json=metadata)
            fetch_oidc_metadata(domain="custom.auth0.com")
        cached = cache.get("auth0_oidc_metadata")
        self.assertEqual(cached, metadata)


class BuildAuthorizationUrlTest(TestCase):
    def test_builds_url_with_required_params(self):
        url = build_authorization_url(
            redirect_uri="https://app.test.com/callback",
            state="test-state",
            code_challenge="test-challenge",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.netloc, "test.auth0.com")
        self.assertEqual(parsed.path, "/authorize")
        self.assertEqual(params["response_type"], ["code"])
        self.assertEqual(params["client_id"], ["test-client-id"])
        self.assertEqual(params["code_challenge_method"], ["S256"])
        self.assertEqual(params["state"], ["test-state"])
        self.assertEqual(params["code_challenge"], ["test-challenge"])
        self.assertEqual(params["redirect_uri"], ["https://app.test.com/callback"])

    def test_includes_scope_from_authorization_params(self):
        url = build_authorization_url(
            redirect_uri="https://app.test.com/callback",
            state="test-state",
            code_challenge="test-challenge",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        self.assertEqual(params["scope"], ["openid profile email offline_access"])

    def test_includes_audience(self):
        url = build_authorization_url(
            redirect_uri="https://app.test.com/callback",
            state="test-state",
            code_challenge="test-challenge",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        self.assertEqual(params["audience"], ["https://api.test.com/"])

    def test_includes_extra_params(self):
        url = build_authorization_url(
            redirect_uri="https://app.test.com/callback",
            state="test-state",
            code_challenge="test-challenge",
            extra_params={"connection": "google-oauth2", "login_hint": "user@example.com"},
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        self.assertEqual(params["connection"], ["google-oauth2"])
        self.assertEqual(params["login_hint"], ["user@example.com"])

    def test_includes_prompt_from_authorization_params(self):
        url = build_authorization_url(
            redirect_uri="https://app.test.com/callback",
            state="test-state",
            code_challenge="test-challenge",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        self.assertEqual(params["prompt"], ["consent"])


class BuildLogoutUrlTest(TestCase):
    def test_builds_logout_url(self):
        url = build_logout_url(return_to="https://app.test.com/")
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.netloc, "test.auth0.com")
        self.assertEqual(parsed.path, "/v2/logout")
        self.assertEqual(params["client_id"], ["test-client-id"])
        self.assertEqual(params["returnTo"], ["https://app.test.com/"])


class ExchangeCodeForTokensTest(TestCase):
    def test_exchanges_code_successfully(self):
        token_response = {
            "access_token": "at_123",
            "id_token": "idt_123",
            "refresh_token": "rt_123",
            "token_type": "Bearer",
            "expires_in": 86400,
            "scope": "openid profile email",
        }
        with requests_mock.Mocker() as m:
            m.post("https://test.auth0.com/oauth/token", json=token_response)
            result = exchange_code_for_tokens("code_123", "https://app.test.com/callback", "verifier_123")
        self.assertEqual(result, token_response)

    def test_sends_correct_payload(self):
        with requests_mock.Mocker() as m:
            m.post("https://test.auth0.com/oauth/token", json={"access_token": "at"})
            exchange_code_for_tokens("code_123", "https://app.test.com/callback", "verifier_123")
        request_body = m.last_request.json()
        self.assertEqual(request_body["grant_type"], "authorization_code")
        self.assertEqual(request_body["client_id"], "test-client-id")
        self.assertEqual(request_body["client_secret"], "test-client-secret")
        self.assertEqual(request_body["code"], "code_123")
        self.assertEqual(request_body["redirect_uri"], "https://app.test.com/callback")
        self.assertEqual(request_body["code_verifier"], "verifier_123")


class ExchangeConnectCodeTest(TestCase):
    def test_exchanges_connect_code_successfully(self):
        connect_response = {"id": "ca_123", "connection": "google-oauth2"}
        with requests_mock.Mocker() as m:
            m.post("https://test.auth0.com/oauth/token", json=connect_response)
            result = exchange_connect_code("connect_code_123", "https://app.test.com/callback", "verifier_123")
        self.assertEqual(result, connect_response)

    def test_sends_correct_grant_type(self):
        with requests_mock.Mocker() as m:
            m.post("https://test.auth0.com/oauth/token", json={})
            exchange_connect_code("connect_code_123", "https://app.test.com/callback", "verifier_123")
        request_body = m.last_request.json()
        self.assertEqual(request_body["grant_type"], "urn:auth0:params:oauth:grant-type:connect:account")


class RefreshAccessTokenTest(TestCase):
    def test_refreshes_token_successfully(self):
        token_response = {
            "access_token": "new_at",
            "expires_in": 86400,
            "scope": "openid profile",
            "token_type": "Bearer",
        }
        with requests_mock.Mocker() as m:
            m.post("https://test.auth0.com/oauth/token", json=token_response)
            result = refresh_access_token("rt_old")
        self.assertIn("access_token", result)
        self.assertIn("expires_at", result)

    def test_adds_expires_at_when_missing(self):
        token_response = {
            "access_token": "new_at",
            "expires_in": 3600,
            "scope": "openid",
            "token_type": "Bearer",
        }
        with requests_mock.Mocker() as m:
            m.post("https://test.auth0.com/oauth/token", json=token_response)
            result = refresh_access_token("rt_old")
        self.assertIn("expires_at", result)

    def test_includes_audience_and_scope_in_payload(self):
        with requests_mock.Mocker() as m:
            m.post("https://test.auth0.com/oauth/token", json={"access_token": "at", "expires_in": 3600, "scope": "s"})
            refresh_access_token("rt_old", audience="https://api.test.com/", scope="read:data")
        request_body = m.last_request.body
        self.assertIn("audience=https", request_body)
        self.assertIn("scope=read", request_body)

    def test_raises_error_on_failure(self):
        error_response = {
            "error": "invalid_grant",
            "error_description": "Unknown or invalid refresh token.",
        }
        with requests_mock.Mocker() as m:
            m.post("https://test.auth0.com/oauth/token", json=error_response, status_code=403)
            with self.assertRaises(ApiOauthClientError) as ctx:
                refresh_access_token("rt_invalid")
        self.assertEqual(ctx.exception.code, "invalid_grant")

    def test_does_not_include_audience_when_none(self):
        with requests_mock.Mocker() as m:
            m.post("https://test.auth0.com/oauth/token", json={"access_token": "at", "expires_in": 3600, "scope": "s"})
            refresh_access_token("rt_old")
        request_body = m.last_request.body
        self.assertNotIn("audience", request_body)


class BearerHeadersTest(TestCase):
    def test_returns_authorization_header(self):
        headers = _bearer_headers("my_token_123")
        self.assertEqual(headers, {"Authorization": "Bearer my_token_123"})


class MyAccountBaseUrlTest(TestCase):
    def test_returns_my_account_audience(self):
        url = _myaccount_base_url()
        self.assertEqual(url, "https://test.auth0.com/me/")


class HandleMyAccountErrorTest(TestCase):
    def test_raises_myaccount_error(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "title": "Bad Request",
            "type": "https://auth0.com/errors/bad_request",
            "detail": "Invalid request body",
            "status": 400,
            "validation_errors": [{"field": "connection", "message": "required"}],
        }
        with self.assertRaises(MyAccountApiOauthClientError) as ctx:
            _handle_myaccount_error(mock_response)
        self.assertEqual(ctx.exception.title, "Bad Request")
        self.assertEqual(ctx.exception.status, 400)
        self.assertEqual(ctx.exception.detail, "Invalid request body")


class MyAccountConnectAccountTest(TestCase):
    def test_connect_account_success(self):
        response_data = {
            "auth_session": "session_123",
            "connect_uri": "https://test.auth0.com/connect",
            "connect_params": {"ticket": "ticket_abc"},
            "expires_in": 300,
        }
        with requests_mock.Mocker() as m:
            m.post("https://test.auth0.com/me/v1/connected-accounts/connect", json=response_data, status_code=201)
            result = myaccount_connect_account("at_123", {"connection": "google-oauth2"})
        self.assertEqual(result, response_data)

    def test_connect_account_error(self):
        error_data = {"title": "Forbidden", "type": "error", "detail": "Access denied", "status": 403}
        with requests_mock.Mocker() as m:
            m.post("https://test.auth0.com/me/v1/connected-accounts/connect", json=error_data, status_code=403)
            with self.assertRaises(MyAccountApiOauthClientError):
                myaccount_connect_account("at_123", {"connection": "google-oauth2"})


class MyAccountCompleteConnectAccountTest(TestCase):
    def test_complete_connect_success(self):
        response_data = {"id": "ca_123", "connection": "google-oauth2"}
        with requests_mock.Mocker() as m:
            m.post("https://test.auth0.com/me/v1/connected-accounts/complete", json=response_data, status_code=201)
            result = myaccount_complete_connect_account(
                "at_123",
                {
                    "auth_session": "session_123",
                    "connect_code": "code_123",
                    "redirect_uri": "https://app.test.com/callback",
                    "code_verifier": "verifier_123",
                },
            )
        self.assertEqual(result, response_data)

    def test_complete_connect_error(self):
        error_data = {"title": "Error", "type": "error", "detail": "Invalid code", "status": 400}
        with requests_mock.Mocker() as m:
            m.post("https://test.auth0.com/me/v1/connected-accounts/complete", json=error_data, status_code=400)
            with self.assertRaises(MyAccountApiOauthClientError):
                myaccount_complete_connect_account("at_123", {})


class MyAccountListConnectedAccountsTest(TestCase):
    def test_list_accounts_success(self):
        response_data = {
            "accounts": [
                {"id": "ca_1", "connection": "google-oauth2", "scopes": ["email"]},
                {"id": "ca_2", "connection": "facebook", "scopes": ["public_profile"]},
            ]
        }
        with requests_mock.Mocker() as m:
            m.get("https://test.auth0.com/me/v1/connected-accounts/accounts", json=response_data)
            result = myaccount_list_connected_accounts("at_123")
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["id"], "ca_1")

    def test_list_accounts_error(self):
        error_data = {"title": "Unauthorized", "type": "error", "detail": "Invalid token", "status": 401}
        with requests_mock.Mocker() as m:
            m.get("https://test.auth0.com/me/v1/connected-accounts/accounts", json=error_data, status_code=401)
            with self.assertRaises(MyAccountApiOauthClientError):
                myaccount_list_connected_accounts("at_invalid")


class MyAccountDeleteConnectedAccountTest(TestCase):
    def test_delete_account_success(self):
        with requests_mock.Mocker() as m:
            m.delete("https://test.auth0.com/me/v1/connected-accounts/accounts/ca_123", status_code=204)
            myaccount_delete_connected_account("at_123", "ca_123")

    def test_delete_account_error(self):
        error_data = {"title": "Not Found", "type": "error", "detail": "Account not found", "status": 404}
        with requests_mock.Mocker() as m:
            m.delete(
                "https://test.auth0.com/me/v1/connected-accounts/accounts/ca_999",
                json=error_data,
                status_code=404,
            )
            with self.assertRaises(MyAccountApiOauthClientError):
                myaccount_delete_connected_account("at_123", "ca_999")


class MyAccountListConnectionsTest(TestCase):
    def test_list_connections_success(self):
        response_data = {
            "connections": [
                {"name": "google-oauth2", "strategy": "google", "scopes": ["email", "profile"]},
            ]
        }
        with requests_mock.Mocker() as m:
            m.get("https://test.auth0.com/me/v1/connected-accounts/connections", json=response_data)
            result = myaccount_list_connections("at_123")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "google-oauth2")

    def test_list_connections_error(self):
        error_data = {"title": "Error", "type": "error", "detail": "Failed", "status": 500}
        with requests_mock.Mocker() as m:
            m.get(
                "https://test.auth0.com/me/v1/connected-accounts/connections",
                json=error_data,
                status_code=500,
            )
            with self.assertRaises(MyAccountApiOauthClientError):
                myaccount_list_connections("at_123")
