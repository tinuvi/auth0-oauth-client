# Auth0 OAuth Client

A Django-focused Auth0 integration providing automated OIDC flows, account linking, and connected account (My Account API). It's been created to support the [Auth0 Token Vault](https://auth0.com/docs/secure/call-apis-on-users-behalf/token-vault) feature, which requires Connected Accounts flow.

It's an opinionated library focused on the needs of our own products. Feel free to fork it and adapt it to your needs.

## Read this before using it

This library uses
`uuid7` for the ID columns when the Python version is 3.14 or higher. If you're using Python 3.12 or 3.13, it will use
`uuid4` instead. If your project updates to Python 3.14, it will break. We know this behavior is unacceptable for a library. That's why we are letting you know in advance. Again, fork this library and adapt it to your needs.

## Rules

The [`sample_app`](./samples) demonstrates how to use the library. It implements the following rules:

- Only required scopes are requested for social connections.
- Additional scopes are requested during the [connected account request flow](https://auth0.com/docs/api/myaccount/create-connected-account-request) (progressive consent).
- When the user creates a connected account, that connected account is eligible for automatic account linking.
    - Consider the following scenario:
        - If a user logs in with `xpto@acme.com` and adds
          `qwerty@gmail.com` as a connected account, logging in later with the Gmail address will link both, with
          `xpto@acme.com` remaining the primary account. No confirmation is required.
        - The same is true when the connected account matches the primary account.
- If a user signs up with an email/password, logs out, and later logs back in using a social connection with that same email, the accounts are automatically linked. The original email/password account is used as the primary account.
- If a user signs up via social, logs out, and later tries to log in with a password using the same email, they'll need to re-authenticate with the original social provider to link the accounts. The primary account is the social one.

## Why did we build this?

Auth0 used to be the 'Stripe of Identity' sort of thing, known for its great developer experience. Lately, I’m not so sure. I almost gave up on it, but after finding some workarounds, I decided to build this library. I’m sharing it because seeing these issues go unaddressed hurts my software developer soul. 😬

Read the following Auth0 Community Questions for more details:

- [Auth0 Fails to Store Refresh Tokens for Linked Accounts](https://community.auth0.com/t/auth0-fails-to-store-refresh-tokens-for-linked-accounts/196953?u=tinuvi.solutions).
- [I had built an integration using Token Vault, and it stopped. Understand why](https://community.auth0.com/t/ms-agent-framework-and-python-use-the-auth0-token-vault-to-call-third-party-apis/193959/4?u=tinuvi.solutions).

At the time of writing this README (2026-02-13), [My Account API is not GA yet](https://auth0.com/docs/api/myaccount/). It means this library might eventually break if Auth0 changes its API, again. 😐

## Quick Start

### 1. Install the library

Add `auth0_oauth_client` to your project dependencies. The library requires:

- Django 4.2+
- `requests`
- `PyJWT`
- `auth0-python`

### 2. Add to `INSTALLED_APPS`

```python
INSTALLED_APPS = [
    # ...
    "auth0_oauth_client",
]
```

The library ships with Django models (`AccountLinking`, `ConnectedAccount`,
`AccountToken`), so run migrations after installing:

```bash
python manage.py migrate
```

### 3. Configure settings

Add the `AUTH0_OAUTH_CLIENT` dict to your Django settings:

```python
AUTH0_OAUTH_CLIENT = {
    "auth0_domain": "your-tenant.auth0.com",
    "auth0_management_api_domain": "your-tenant.auth0.com",
    "client_id": "your_client_id",
    "client_secret": "your_client_secret",
    "connections_for_account_linking": ["google-oauth2", "Username-Password-Authentication"],
    # Optional
    "authorization_params": {
        "scope": "openid profile email offline_access",
        "audience": "https://your-api.example.com",
    },
    "custom_scopes": {
        "google-oauth2": [
            "https://www.googleapis.com/auth/calendar",
            "https://www.googleapis.com/auth/userinfo.email",
        ],
    },
    "pushed_authorization_requests": False,
}
```

### 4. Create views and wire URLs

The library does **not** ship with views or URL patterns. You implement them in your Django app using the
`auth_client` singleton. See the [API Reference](#api-reference) below and the [
`sample_app`](./samples) for a full working example.

```python
from auth0_oauth_client import auth_client
from django.shortcuts import redirect
from django.urls import reverse


def login_view(request):
    callback_url = request.build_absolute_uri(reverse("auth:callback"))
    flow_url = auth_client.start_login(request, callback_url)
    return redirect(flow_url)


def callback_view(request):
    callback_url = request.build_absolute_uri(request.get_full_path())
    auth_client.complete_login(request, callback_url)
    return redirect("/dashboard/")


def logout_view(request):
    return_to = request.build_absolute_uri("/")
    logout_url = auth_client.logout(request, return_to=return_to)
    return redirect(logout_url)
```

## Settings Reference

All settings live under the `AUTH0_OAUTH_CLIENT` dictionary in your Django settings module.

### Required keys

| Key                               | Type        | Description                                                                                                                                                                                       |
|-----------------------------------|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `auth0_domain`                    | `str`       | Your Auth0 tenant domain (e.g. `"acme.us.auth0.com"`). Used for OAuth endpoints and the MyAccount API.                                                                                            |
| `auth0_management_api_domain`     | `str`       | Domain for the Auth0 Management API. Often the same as `auth0_domain`, but can differ if you use a custom domain for login vs management.                                                         |
| `client_id`                       | `str`       | The Client ID of your Auth0 application.                                                                                                                                                          |
| `client_secret`                   | `str`       | The Client Secret of your Auth0 application. Used for token exchange and M2M grants.                                                                                                              |
| `connections_for_account_linking` | `list[str]` | List of Auth0 connection names you have in your account (e.g. `["google-oauth2", "Username-Password-Authentication"]`). The library uses this to decide when to trigger the account linking flow. |

### Optional keys

| Key                             | Type                   | Default | Description                                                                                                                                                                                       |
|---------------------------------|------------------------|---------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `audience`                      | `str`                  | `None`  | Default API audience for access tokens.                                                                                                                                                           |
| `authorization_params`          | `dict`                 | `{}`    | Default parameters sent on every `/authorize` call. Typically contains `scope` and `audience`. The `scope` value can be a string or a dict mapping audiences to scope strings.                    |
| `pushed_authorization_requests` | `bool`                 | `False` | Whether to use Pushed Authorization Requests (PAR).                                                                                                                                               |
| `custom_scopes`                 | `dict[str, list[str]]` | `{}`    | Connection-specific scopes for the Connected Accounts flow. Keyed by connection name (e.g. `"google-oauth2"`), with a list of OAuth scopes. These are merged with any scopes passed at call time. |

> **Derived setting:** `my_account_audience` is automatically set to
`https://{auth0_domain}/me/` and used for all MyAccount API calls.

## API Reference

Import the singleton client:

```python
from auth0_oauth_client import auth_client
```

### Login / Logout

#### `auth_client.start_login(request, redirect_uri, authorization_params=None) -> str`

Generates a PKCE code verifier/challenge and random state, stores the transaction in the Django session, and returns the Auth0
`/authorize` URL to redirect the user to.

| Parameter              | Type           | Description                                                                                         |
|------------------------|----------------|-----------------------------------------------------------------------------------------------------|
| `request`              | `HttpRequest`  | The current Django request.                                                                         |
| `redirect_uri`         | `str`          | The absolute callback URL Auth0 will redirect to after authentication.                              |
| `authorization_params` | `dict \| None` | Extra query parameters to include in the `/authorize` URL (e.g. `{"connection": "google-oauth2"}`). |

**Returns:** Authorization URL (`str`).

```python
callback_url = request.build_absolute_uri(reverse("auth:callback"))
flow_url = auth_client.start_login(request, callback_url)
return redirect(flow_url)
```

---

#### `auth_client.complete_login(request, callback_url) -> dict`

Validates the `state` parameter, exchanges the authorization `code` for tokens via PKCE, decodes the ID token to extract
`userinfo`, and stores the session. Also creates/updates an `AccountToken` record for account linking.

| Parameter      | Type          | Description                                                                                                   |
|----------------|---------------|---------------------------------------------------------------------------------------------------------------|
| `request`      | `HttpRequest` | The current Django request.                                                                                   |
| `callback_url` | `str`         | The full callback URL including query parameters (use `request.build_absolute_uri(request.get_full_path())`). |

**Returns:** Token set dict containing `access_token`, `id_token`, `refresh_token`, `userinfo`, `expires_at`, etc.

**Raises:** `MissingRequiredArgumentOauthClientError` if `code` or `state` is missing.
`ApiOauthClientError` on state mismatch or token exchange failure.

```python
callback_url = request.build_absolute_uri(request.get_full_path())
auth_client.complete_login(request, callback_url)
```

---

#### `auth_client.logout(request, return_to=None) -> str`

Clears the library's session data from the Django session and returns the Auth0 `/v2/logout` URL.

| Parameter   | Type          | Description                                       |
|-------------|---------------|---------------------------------------------------|
| `request`   | `HttpRequest` | The current Django request.                       |
| `return_to` | `str \| None` | URL the user is redirected to after Auth0 logout. |

**Returns:** Auth0 logout URL (`str`).

```python
logout_url = auth_client.logout(request, return_to=request.build_absolute_uri("/"))
django_logout(request)  # Also clear Django's own session
return redirect(logout_url)
```

---

#### `auth_client.get_idp_username(request) -> str | None`

Returns the Auth0 user ID (`sub` claim) from the current session, or `None` if there is no session.

---

#### `auth_client.get_refresh_token(request) -> str | None`

Returns the refresh token from the current session, or `None` if there is no session.

### Connected Accounts (MyAccount API)

These methods manage connected accounts through the [Auth0 MyAccount API](https://auth0.com/docs/api/myaccount/), enabling features like Token Vault.

#### `auth_client.start_connect_account(request, connection, redirect_uri, scopes=None, authorization_params=None) -> str`

Initiates the connected account flow. Gets an access token for the MyAccount API, calls the connect endpoint, and returns the URL to redirect the user to.

| Parameter              | Type                | Description                                                              |
|------------------------|---------------------|--------------------------------------------------------------------------|
| `request`              | `HttpRequest`       | The current Django request.                                              |
| `connection`           | `str`               | The connection name (e.g. `"google-oauth2"`).                            |
| `redirect_uri`         | `str`               | Callback URL after the connection flow completes.                        |
| `scopes`               | `list[str] \| None` | Additional scopes to request. Merged with `custom_scopes` from settings. |
| `authorization_params` | `dict \| None`      | Extra parameters for the authorization request.                          |

**Returns:** Connect URL (`str`) to redirect the user to.

**Raises:** `MissingRequiredArgumentOauthClientError` if `redirect_uri` is empty.

```python
callback_url = request.build_absolute_uri(reverse("auth:callback"))
flow_url = auth_client.start_connect_account(
    request,
    connection="google-oauth2",
    redirect_uri=callback_url,
    scopes=["https://www.googleapis.com/auth/calendar"],
)
return redirect(flow_url)
```

---

#### `auth_client.complete_connect_account(request, callback_url) -> dict`

Completes the connected account flow. Validates the `state` and
`connect_code`, calls the MyAccount API completion endpoint, and stores a `ConnectedAccount` record.

| Parameter      | Type          | Description                                       |
|----------------|---------------|---------------------------------------------------|
| `request`      | `HttpRequest` | The current Django request.                       |
| `callback_url` | `str`         | The full callback URL including query parameters. |

**Returns:** Connected account metadata dict (contains `id`, `connection`, etc.).

**Raises:** `MissingRequiredArgumentOauthClientError`, `ApiOauthClientError`.

```python
# In your callback view, check for connect_code to distinguish from login
if "connect_code" in request.GET:
    auth_client.complete_connect_account(request, callback_url)
```

---

#### `auth_client.list_connected_accounts(request) -> list[ConnectedAccountResponse]`

Lists all connected accounts for the authenticated user via the MyAccount API. Requires the
`read:me:connected_accounts` scope.

---

#### `auth_client.list_connected_account_connections(request) -> list[AvailableConnection]`

Lists all available connections that can be used for connected accounts. Requires the
`read:me:connected_accounts` scope.

---

#### `auth_client.delete_connected_account(request, connected_account_id: str) -> None`

Deletes a connected account by its ID, both from Auth0 and from the local database. Requires the
`delete:me:connected_accounts` scope.

**Raises:** `MissingRequiredArgumentOauthClientError` if `connected_account_id` is empty.

### Account Linking

These methods handle automatic and manual account linking when users sign in with multiple identity providers that share the same email.

#### `auth_client.verify_account_linking(request) -> VerifyAccountLinkingResult`

Checks whether the current login requires account linking. Handles two scenarios automatically:

- **Social provider login:** Automatically merges and links accounts if a matching account exists.
- **Password login:** Stores a pending linking payload in the session and returns
  `is_pending_account_linking: True`, requiring the user to confirm by re-authenticating with the original provider.

**Returns:** `{"is_pending_account_linking": bool, "is_account_linked": bool}`.

---

#### `auth_client.complete_account_linking(request) -> CompleteAccountLinkingResult | None`

Completes a pending account linking flow (the manual confirmation path). Verifies the user re-authenticated with the correct account, merges metadata, links the accounts in Auth0, and updates local records.

**Returns:** `{"success": True}` on success,
`{"success": False, "used_different_account": True}` if the wrong account was used, or
`None` if there was no pending linking.

---

#### `auth_client.pending_account_linking(request) -> AccountLinkingPayload | None`

Returns the pending account linking payload from the session, or
`None` if there is no pending flow. Useful for rendering a confirmation page.

---

#### `auth_client.cancel_account_linking(request) -> None`

Cancels a pending account linking flow by removing the payload from the session.

### Token Management

#### `auth_client.get_access_token_for_connection_using_user_refresh_token(refresh_token, connection: str) -> GoogleTokenResult`

Exchanges a user's refresh token for a connection-specific access token using the [federated connection access token](https://auth0.com/docs/secure/call-apis-on-users-behalf/token-vault) grant. This is the core mechanism for calling third-party APIs (e.g. Google, Facebook) on behalf of the user.

| Parameter       | Type  | Description                                   |
|-----------------|-------|-----------------------------------------------|
| `refresh_token` | `str` | The user's Auth0 refresh token.               |
| `connection`    | `str` | The connection name (e.g. `"google-oauth2"`). |

**Returns:** Dict with `access_token`, `expires_in`, and `scope`.

```python
refresh_token = request.user.youruser.idp_refresh_token
result = auth_client.get_access_token_for_connection_using_user_refresh_token(
    refresh_token, "google-oauth2"
)
# Use result["access_token"] to call Google APIs
```

---

#### `auth_client.get_user_info(user_id: str) -> dict`

Fetches the full user profile from the Auth0 Management API using an M2M (client credentials) token. The M2M token is cached automatically.

| Parameter | Type  | Description                                 |
|-----------|-------|---------------------------------------------|
| `user_id` | `str` | The Auth0 user ID (e.g. `"auth0\|abc123"`). |

**Returns:** Full Auth0 user profile dict including `identities`, `email`, `user_metadata`, etc.