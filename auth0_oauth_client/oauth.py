import base64
import hashlib
import logging
import secrets
import time

from urllib.parse import urlencode

import requests

from django.core.cache import cache

from auth0_oauth_client.errors import ApiOauthClientError
from auth0_oauth_client.errors import MyAccountApiOauthClientError
from auth0_oauth_client.typing import AvailableConnection
from auth0_oauth_client.typing import CompleteConnectedAccountRequestBody
from auth0_oauth_client.typing import ConnectedAccountAuthSessionPayload
from auth0_oauth_client.typing import ConnectedAccountResponse
from auth0_oauth_client.typing import TokenResponse

_logger = logging.getLogger("auth0_oauth_client")


# ── PKCE ────────────────────────────────────────────────────────────────────


def generate_pkce_pair() -> tuple[str, str]:
    """Returns (code_verifier, code_challenge_S256)."""
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def generate_state() -> str:
    """Random URL-safe string for CSRF protection."""
    return secrets.token_urlsafe(32)


# ── OIDC Metadata ───────────────────────────────────────────────────────────

_OIDC_METADATA_CACHE_KEY = "auth0_oidc_metadata"


def fetch_oidc_metadata(domain=None) -> dict:
    """GET /.well-known/openid-configuration. Cached in Django cache."""
    cached = cache.get(_OIDC_METADATA_CACHE_KEY)
    if cached:
        return cached
    if domain is None:
        from auth0_oauth_client.client import auth_client

        domain = auth_client.auth0_domain
    url = f"https://{domain}/.well-known/openid-configuration"
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    metadata = response.json()
    cache.set(_OIDC_METADATA_CACHE_KEY, metadata, timeout=3600)
    return metadata


# ── URL builders ────────────────────────────────────────────────────────────


def build_authorization_url(redirect_uri, state, code_challenge, extra_params=None) -> str:
    """Builds https://{domain}/authorize URL with PKCE parameters."""
    from auth0_oauth_client.client import auth_client

    auth_params = auth_client.authorization_params
    params = {
        "response_type": "code",
        "client_id": auth_client.client_id,
        "code_challenge_method": "S256",
        "state": state,
        "code_challenge": code_challenge,
        "redirect_uri": redirect_uri,
    }
    scope = auth_params.get("scope")
    if scope:
        params["scope"] = scope
    if auth_client.audience:
        params["audience"] = auth_client.audience
    # Merge any other default authorization_params (e.g. prompt)
    for k, v in auth_params.items():
        if k not in params:
            params[k] = v
    if extra_params:
        params.update(extra_params)
    return f"https://{auth_client.auth0_domain}/authorize?{urlencode(params)}"


def build_logout_url(return_to) -> str:
    """Builds https://{domain}/v2/logout URL."""
    from auth0_oauth_client.client import auth_client

    params = {
        "client_id": auth_client.client_id,
        "returnTo": return_to,
    }
    return f"https://{auth_client.auth0_domain}/v2/logout?{urlencode(params)}"


# ── Token exchange ──────────────────────────────────────────────────────────


def exchange_code_for_tokens(code, redirect_uri, code_verifier) -> TokenResponse:
    """POST /oauth/token with grant_type=authorization_code.
    Returns {access_token, id_token, refresh_token, token_type, expires_in}."""
    from auth0_oauth_client.client import auth_client

    url = f"https://{auth_client.auth0_domain}/oauth/token"
    payload = {
        "grant_type": "authorization_code",
        "client_id": auth_client.client_id,
        "client_secret": auth_client.client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    response = requests.post(url, json=payload, timeout=30)
    response.raise_for_status()
    return response.json()


def exchange_connect_code(connect_code, redirect_uri, code_verifier) -> dict:
    """POST /oauth/token to exchange connect_code from Connected Accounts flow.
    Returns connected account metadata."""
    from auth0_oauth_client.client import auth_client

    url = f"https://{auth_client.auth0_domain}/oauth/token"
    payload = {
        "grant_type": "urn:auth0:params:oauth:grant-type:connect:account",
        "client_id": auth_client.client_id,
        "client_secret": auth_client.client_secret,
        "code": connect_code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    response = requests.post(url, json=payload, timeout=30)
    response.raise_for_status()
    return response.json()


def refresh_access_token(refresh_token, audience=None, scope=None) -> dict:
    """POST /oauth/token with grant_type=refresh_token.
    Returns {access_token, id_token, refresh_token, token_type, expires_in, scope}."""
    from auth0_oauth_client.client import auth_client

    url = f"https://{auth_client.auth0_domain}/oauth/token"
    payload = {
        "grant_type": "refresh_token",
        "client_id": auth_client.client_id,
        "client_secret": auth_client.client_secret,
        "refresh_token": refresh_token,
    }
    if audience:
        payload["audience"] = audience
    if scope:
        payload["scope"] = scope
    response = requests.post(url, data=payload, timeout=30)
    if response.status_code != 200:
        error_data = response.json()
        raise ApiOauthClientError(
            error_data.get("error", "refresh_token_error"),
            error_data.get("error_description", "Failed to exchange refresh token"),
        )
    token_response = response.json()
    if "expires_in" in token_response and "expires_at" not in token_response:
        token_response["expires_at"] = int(time.time()) + token_response["expires_in"]
    return token_response


# ── MyAccount API ───────────────────────────────────────────────────────────


def _myaccount_base_url():
    from auth0_oauth_client.client import auth_client

    return auth_client.my_account_audience


def _bearer_headers(access_token):
    return {"Authorization": f"Bearer {access_token}"}


def _handle_myaccount_error(response):
    error_data = response.json()
    raise MyAccountApiOauthClientError(
        title=error_data.get("title"),
        type=error_data.get("type"),
        detail=error_data.get("detail"),
        status=error_data.get("status"),
        validation_errors=error_data.get("validation_errors"),
    )


def myaccount_connect_account(access_token, request_data) -> ConnectedAccountAuthSessionPayload:
    """POST /me/v1/connected-accounts/connect. Returns connect response."""
    url = f"{_myaccount_base_url()}v1/connected-accounts/connect"
    response = requests.post(url, json=request_data, headers=_bearer_headers(access_token), timeout=30)
    if response.status_code != 201:
        _handle_myaccount_error(response)
    return response.json()


def myaccount_complete_connect_account(
    access_token: str, request_data: CompleteConnectedAccountRequestBody
) -> ConnectedAccountResponse:
    """Complete a previously started authorization flow to link the authenticated
    user's account with an external identity provider.

    https://auth0.com/docs/api/myaccount/complete-connected-account-request

    Args:
        access_token: It requires `create:me:connected_accounts` scope
        request_data: Request body

    Returns:
        The connected account metadata
    """
    url = f"{_myaccount_base_url()}v1/connected-accounts/complete"
    response = requests.post(url, json=request_data, headers=_bearer_headers(access_token), timeout=30)
    if response.status_code != 201:
        _handle_myaccount_error(response)
    return response.json()


def myaccount_list_connected_accounts(access_token) -> list[ConnectedAccountResponse]:
    """Retrieve connected accounts belonging to the authenticated user.

    https://auth0.com/docs/api/myaccount/get-connected-accounts

    Args:
        access_token: It requires `read:me:connected_accounts` scope

    Returns:
        List of connected accounts with metadata
    """
    url = f"{_myaccount_base_url()}v1/connected-accounts/accounts"
    params = {"take": 20}
    response = requests.get(url, params=params, headers=_bearer_headers(access_token), timeout=30)
    if response.status_code != 200:
        _handle_myaccount_error(response)
    body = response.json()
    return body["accounts"]


def myaccount_delete_connected_account(access_token, account_id) -> None:
    """Delete a connected account belonging to the authenticated user.

    https://auth0.com/docs/api/myaccount/delete-connected-account

    Args:
        access_token: It requires `delete:me:connected_accounts` scope
        account_id: The unique identifier of the connected account

    Returns:
        None
    """
    url = f"{_myaccount_base_url()}v1/connected-accounts/accounts/{account_id}"
    response = requests.delete(url, headers=_bearer_headers(access_token), timeout=30)
    if response.status_code != 204:
        _handle_myaccount_error(response)


def myaccount_list_connections(access_token) -> list[AvailableConnection]:
    """Retrieve available connections that can be used for account linking by the authenticated user.

    https://auth0.com/docs/api/myaccount/get-connected-accounts-connections

    Args:
        access_token: It requires `read:me:connected_accounts` scope

    Returns:
        List of available connections
    """
    url = f"{_myaccount_base_url()}v1/connected-accounts/connections"
    params = {"take": 20}
    response = requests.get(url, params=params, headers=_bearer_headers(access_token), timeout=30)
    if response.status_code != 200:
        _handle_myaccount_error(response)
    body = response.json()
    return body["connections"]
