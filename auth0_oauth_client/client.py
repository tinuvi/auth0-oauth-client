import hashlib
import logging
import time

from typing import Any
from urllib.parse import parse_qs
from urllib.parse import urlparse

import jwt

from auth0.authentication import GetToken
from auth0.management import Auth0
from django.core.cache import cache
from django.db.models import Q

from auth0_oauth_client.errors import AccessTokenErrorCode
from auth0_oauth_client.errors import AccessTokenOauthClientError
from auth0_oauth_client.errors import ApiOauthClientError
from auth0_oauth_client.errors import MissingRequiredArgumentOauthClientError
from auth0_oauth_client.errors import MissingTransactionOauthClientError
from auth0_oauth_client.oauth import build_authorization_url
from auth0_oauth_client.oauth import build_logout_url
from auth0_oauth_client.oauth import exchange_code_for_tokens
from auth0_oauth_client.oauth import generate_pkce_pair
from auth0_oauth_client.oauth import generate_state
from auth0_oauth_client.oauth import myaccount_complete_connect_account
from auth0_oauth_client.oauth import myaccount_connect_account
from auth0_oauth_client.oauth import myaccount_delete_connected_account
from auth0_oauth_client.oauth import myaccount_list_connected_accounts
from auth0_oauth_client.oauth import myaccount_list_connections
from auth0_oauth_client.oauth import refresh_access_token
from auth0_oauth_client.settings import read_required_key
from auth0_oauth_client.settings import required_setting
from auth0_oauth_client.typing import AccountLinkingPayload
from auth0_oauth_client.typing import AvailableConnection
from auth0_oauth_client.typing import CompleteAccountLinkingResult
from auth0_oauth_client.typing import ConnectedAccountResponse
from auth0_oauth_client.typing import GoogleTokenResult
from auth0_oauth_client.typing import SearchUserResponseBody
from auth0_oauth_client.typing import VerifyAccountLinkingResult

_logger = logging.getLogger("auth0_oauth_client")


class DjangoAuthClient:
    SESSION_KEY_TX = "_auth0_oauth_client_tx"
    SESSION_KEY_ACCOUNT_LINKING_TX = "_auth0_oauth_client_al_tx"
    SESSION_KEY_STATE = "_auth0_oauth_client_session"

    def __init__(self):
        """
        Set all configuration from settings or default values when not provided.
        """
        base_configuration = required_setting("AUTH0_OAUTH_CLIENT")
        self.auth0_domain = read_required_key(base_configuration, "auth0_domain")
        self.auth0_management_api_domain = read_required_key(base_configuration, "auth0_management_api_domain")
        self.client_id = read_required_key(base_configuration, "client_id")
        self.client_secret = read_required_key(base_configuration, "client_secret")
        self.audience = base_configuration.get("audience")
        self.authorization_params = base_configuration.get("authorization_params") or {}
        self.pushed_authorization_requests = base_configuration.get("pushed_authorization_requests", False)
        self.my_account_audience = f"https://{self.auth0_domain}/me/"
        self.connections_for_account_linking = read_required_key(base_configuration, "connections_for_account_linking")
        self.custom_scopes = base_configuration.get("custom_scopes", {})

    def get_idp_username(self, request):
        session_data = self._get_session(request)
        if not session_data:
            return None
        return session_data["userinfo"]["sub"]

    # region Login/Logout Flow

    def start_login(self, request, redirect_uri, authorization_params=None) -> str:
        """Generate PKCE + state, store in session, return Auth0 /authorize URL."""
        code_verifier, code_challenge = generate_pkce_pair()
        state = generate_state()
        self._store_transaction(request, state, code_verifier, redirect_uri)
        return build_authorization_url(redirect_uri, state, code_challenge, extra_params=authorization_params)

    def complete_login(self, request, callback_url):
        """Validate state, exchange code for tokens, fetch userinfo, store session.
        Returns token dict with new session structure."""
        from auth0_oauth_client.models import AccountToken

        parsed = urlparse(callback_url)
        query = parse_qs(parsed.query)
        code = query.get("code", [None])[0]
        state = query.get("state", [None])[0]

        if not code or not state:
            raise MissingRequiredArgumentOauthClientError("code or state")

        tx = self._pop_transaction(request)
        if tx["state"] != state:
            raise ApiOauthClientError("state_mismatch", "State mismatch")

        tokens = exchange_code_for_tokens(code, tx["redirect_uri"], tx["code_verifier"])
        # This mimics the behavior of Authlib
        tokens["userinfo"] = jwt.decode(tokens["id_token"], options={"verify_signature": False})
        user_id = tokens["userinfo"]["sub"]

        _logger.debug("Storing session data for user %s", user_id)
        additional_attributes = {"expires_at": int(time.time()) + (tokens["expires_in"] - 60 * 10)}
        token_set = tokens | additional_attributes
        hashed_key = hashlib.sha256(f"{token_set['scope']}".encode()).hexdigest()
        session_data = {
            "userinfo": tokens["userinfo"],
            "refresh_token": tokens["refresh_token"],
            hashed_key: token_set,
        }
        # `AccountToken` record might be used during account linking flow
        AccountToken.objects.update_or_create(user_id=user_id, defaults={"refresh_token": tokens["refresh_token"]})
        self._store_session(request, session_data)

        return token_set

    def logout(self, request, return_to=None) -> str:
        """Clear SDK session from Django session, return Auth0 /v2/logout URL."""
        if self.SESSION_KEY_STATE in request.session:
            del request.session[self.SESSION_KEY_STATE]
        return build_logout_url(return_to)

    # endregion

    # region Connected Accounts Flow (MyAccount API)

    def start_connect_account(self, request, connection, redirect_uri, scopes=None, authorization_params=None) -> str:
        """Initiate connected account flow via MyAccount API.
        Gets access token for MyAccount, calls connect endpoint, returns connect URL."""
        if not redirect_uri:
            raise MissingRequiredArgumentOauthClientError("redirect_uri")

        code_verifier, code_challenge = generate_pkce_pair()
        state = generate_state()

        access_token = self._get_access_token(
            request,
            audience=self.my_account_audience,
            scope="create:me:connected_accounts",
        )
        request_data = {
            "connection": connection,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
        }
        merged_scopes = list(self.custom_scopes.get(connection, []))
        if scopes:
            merged_scopes.extend(s for s in scopes if s not in merged_scopes)
        if merged_scopes:
            request_data["scopes"] = merged_scopes
        if authorization_params:
            request_data["authorization_params"] = authorization_params

        connect_response = myaccount_connect_account(access_token, request_data)

        self._store_transaction(
            request,
            state,
            code_verifier,
            redirect_uri,
            is_connect=True,
            auth_session=connect_response.get("auth_session"),
        )
        connect_uri = connect_response.get("connect_uri", "")
        connect_params = connect_response.get("connect_params", {})
        ticket = connect_params.get("ticket", "")
        if ticket:
            parsed = urlparse(connect_uri)
            from urllib.parse import urlencode as _urlencode

            query = _urlencode({"ticket": ticket})
            from urllib.parse import urlunparse

            return urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    query,
                    parsed.fragment,
                )
            )
        return connect_uri

    def complete_connect_account(self, request, callback_url):
        """Complete connected account flow via MyAccount API."""
        from auth0_oauth_client.models import AccountLinking
        from auth0_oauth_client.models import ConnectedAccount

        parsed = urlparse(callback_url)
        query = parse_qs(parsed.query)
        connect_code = query.get("connect_code", [None])[0]
        state = query.get("state", [None])[0]

        if not connect_code or not state:
            raise MissingRequiredArgumentOauthClientError("connect_code or state")

        tx = self._pop_transaction(request)
        if tx["state"] != state:
            raise ApiOauthClientError("state_mismatch", "State mismatch")

        access_token = self._get_access_token(
            request,
            audience=self.my_account_audience,
            scope="create:me:connected_accounts",
        )

        complete_data = {
            "auth_session": tx.get("auth_session"),
            "connect_code": connect_code,
            "redirect_uri": tx["redirect_uri"],
            "code_verifier": tx["code_verifier"],
        }

        result = myaccount_complete_connect_account(access_token, complete_data)
        session_data = self._get_session(request)
        user_id_owner = session_data["userinfo"]["sub"]
        is_linked = AccountLinking.objects.filter(
            Q(primary_user_id=user_id_owner) | Q(secondary_user_id=user_id_owner),
            secondary_provider=result["connection"],
        ).exists()
        defaults = {
            "user_id_owner": user_id_owner,
            "provider": result["connection"],
            "email": session_data["userinfo"]["email"],
            "is_account_linked": is_linked,
        }
        ConnectedAccount.objects.update_or_create(connected_account_id=result["id"], defaults=defaults)
        return result

    def list_connected_accounts(self, request) -> list[ConnectedAccountResponse]:
        """List connected accounts for the authenticated user."""
        access_token = self._get_access_token(
            request,
            audience=self.my_account_audience,
            scope="read:me:connected_accounts",
        )
        return myaccount_list_connected_accounts(access_token)

    def delete_connected_account(self, request, connected_account_id: str) -> None:
        """Delete a connected account."""
        from auth0_oauth_client.models import ConnectedAccount

        if not connected_account_id:
            raise MissingRequiredArgumentOauthClientError("connected_account_id")
        access_token = self._get_access_token(
            request,
            audience=self.my_account_audience,
            scope="delete:me:connected_accounts",
        )
        myaccount_delete_connected_account(access_token, connected_account_id)
        ConnectedAccount.objects.filter(connected_account_id=connected_account_id).delete()

    def list_connected_account_connections(self, request) -> list[AvailableConnection]:
        access_token = self._get_access_token(
            request,
            audience=self.my_account_audience,
            scope="read:me:connected_accounts",
        )
        return myaccount_list_connections(access_token)

    # endregion

    # region Account management, including account linking

    def complete_account_linking(self, request) -> CompleteAccountLinkingResult | None:
        from auth0_oauth_client.models import AccountLinking
        from auth0_oauth_client.models import AccountToken
        from auth0_oauth_client.models import ConnectedAccount

        pending_account_linking: AccountLinkingPayload = request.session.pop(self.SESSION_KEY_ACCOUNT_LINKING_TX, None)
        if not pending_account_linking:
            return None

        session_data = self._get_session(request)
        if not session_data:
            return None

        current_user_id = session_data["userinfo"]["sub"]
        primary_user_id = pending_account_linking["primary_user_id"]

        if current_user_id != primary_user_id:
            return {
                "success": False,
                "used_different_account": True,
            }

        self._merge_and_link_accounts(
            current_user_id,
            pending_account_linking["secondary_provider"],
            pending_account_linking["secondary_user_id"],
        )

        session_data["refresh_token"] = AccountToken.objects.get(user_id=current_user_id).refresh_token
        self._store_session(request, session_data)
        AccountLinking.objects.update_or_create(
            primary_user_id=current_user_id,
            secondary_provider=pending_account_linking["secondary_provider"],
            secondary_user_id=pending_account_linking["secondary_user_id"],
        )
        ConnectedAccount.objects.filter(
            Q(user_id_owner=current_user_id) | Q(user_id_owner=pending_account_linking["secondary_user_id"]),
            provider=pending_account_linking["secondary_provider"],
        ).update(is_account_linked=True)

        return {"success": True}

    def verify_account_linking(self, request) -> VerifyAccountLinkingResult:
        from auth0_oauth_client.models import AccountLinking
        from auth0_oauth_client.models import AccountToken
        from auth0_oauth_client.models import ConnectedAccount

        session_data = self._get_session(request)
        if not session_data:
            return {
                "is_pending_account_linking": False,
                "is_account_linked": False,
            }
        user_id = session_data["userinfo"]["sub"]
        userinfo = self.get_user_info(user_id)
        user_email = userinfo["email"]
        current_account_provider = userinfo["identities"][0]["provider"]

        entries = ConnectedAccount.objects.filter(
            is_account_linked=False, email=user_email, provider=current_account_provider
        )
        if entries.exists():
            connected_account_entry = entries.first()
            assert connected_account_entry is not None  # Tell mypy that we know that there is at least one entry
            primary_user_id = connected_account_entry.user_id_owner
            result = self._merge_and_link_accounts(primary_user_id, current_account_provider, user_id)
            session_data["userinfo"]["sub"] = primary_user_id
            session_data["refresh_token"] = AccountToken.objects.get(user_id=primary_user_id).refresh_token
            self._store_session(request, session_data)
            AccountLinking.objects.update_or_create(
                primary_user_id=primary_user_id,
                secondary_provider=current_account_provider,
                secondary_user_id=user_id,
            )
            connected_account_entry.is_account_linked = True
            connected_account_entry.save()
            _logger.debug(
                "Merged and linked accounts for user %s. Returned result: %s",
                user_id,
                result,
            )
            return {
                "is_pending_account_linking": False,
                "is_account_linked": True,
            }
        else:
            number_of_available_connections = len(self.connections_for_account_linking)
            account_link_verification_required = len(userinfo["identities"]) < number_of_available_connections
            if account_link_verification_required:
                current_account_connection_name = userinfo["identities"][0]["connection"]
                existing_accounts = self._search_users_excluding_connection(user_email, current_account_connection_name)
                if existing_accounts:
                    existing_account = existing_accounts[0]
                    existing_account_user_id = existing_account["user_id"]
                    existing_account_provider = existing_account["identities"][0]["provider"]
                    is_eligible_automatic_account_linking = self._is_social_provider(current_account_provider)
                    if is_eligible_automatic_account_linking:
                        result = self._merge_and_link_accounts(
                            existing_account_user_id, current_account_provider, user_id
                        )
                        session_data["userinfo"]["sub"] = existing_account["user_id"]
                        session_data["refresh_token"] = AccountToken.objects.get(
                            user_id=existing_account_user_id
                        ).refresh_token
                        self._store_session(request, session_data)
                        AccountLinking.objects.update_or_create(
                            primary_user_id=existing_account_user_id,
                            secondary_provider=current_account_provider,
                            secondary_user_id=user_id,
                        )
                        ConnectedAccount.objects.filter(
                            Q(user_id_owner=existing_account_user_id) | Q(user_id_owner=user_id),
                            provider=current_account_provider,
                        ).update(is_account_linked=True)
                        _logger.debug(
                            "Merged and linked accounts for user %s. Returned result: %s",
                            user_id,
                            result,
                        )
                        return {
                            "is_pending_account_linking": False,
                            "is_account_linked": True,
                        }
                    else:
                        provider_names = {
                            "auth0": "email e senha",
                            "google-oauth2": "Google",
                            "facebook": "Facebook",
                            "apple": "Apple",
                        }
                        request.session[self.SESSION_KEY_ACCOUNT_LINKING_TX] = {
                            "primary_user_id": existing_account_user_id,
                            "primary_provider": existing_account_provider,
                            "primary_provider_friendly_name": provider_names[existing_account_provider],
                            "primary_connection_name": existing_account["identities"][0]["connection"],
                            "secondary_user_id": user_id,
                            "secondary_provider": current_account_provider,
                            "secondary_connection_name": userinfo["identities"][0]["connection"],
                        }
                        return {
                            "is_pending_account_linking": True,
                            "is_account_linked": False,
                        }
        return {
            "is_pending_account_linking": False,
            "is_account_linked": False,
        }

    def pending_account_linking(self, request) -> AccountLinkingPayload | None:
        return request.session.get(self.SESSION_KEY_ACCOUNT_LINKING_TX)

    def cancel_account_linking(self, request):
        if self.SESSION_KEY_ACCOUNT_LINKING_TX in request.session:
            del request.session[self.SESSION_KEY_ACCOUNT_LINKING_TX]

    def get_user_info(self, user_id: str):
        _tokens = self._get_auth0_token_through_m2m()
        _auth0 = Auth0(self.auth0_management_api_domain, _tokens["access_token"])
        user_details = _auth0.users.get(id=user_id)
        return user_details

    def _search_users_excluding_connection(self, email: str, connection_name: str) -> list[SearchUserResponseBody]:
        _tokens = self._get_auth0_token_through_m2m()
        _auth0 = Auth0(self.auth0_management_api_domain, _tokens["access_token"])
        q = f'email:"{email}" AND NOT identities.connection:"{connection_name}"'
        fields = ["user_id", "identities.provider", "identities.connection"]
        found_users = _auth0.users.list(q=q, fields=fields)["users"]
        # Sample output:
        # [
        #     {
        #         "identities": [{"connection": "Username-Password-Authentication", "provider": "auth0"}],
        #         "user_id": "auth0|69813210040e4b7128ed70f8",
        #     }
        # ]
        return found_users

    def _update_user(self, user_id, body: dict):
        _tokens = self._get_auth0_token_through_m2m()
        _auth0 = Auth0(self.auth0_management_api_domain, _tokens["access_token"])
        user_details = _auth0.users.update(user_id, body)
        return user_details

    def _link_user_accounts(
        self,
        primary_user_id: str,
        secondary_connection_name: str,
        secondary_user_id: str,
    ):
        _tokens = self._get_auth0_token_through_m2m()
        _auth0 = Auth0(self.auth0_management_api_domain, _tokens["access_token"])
        body = {"provider": secondary_connection_name, "user_id": secondary_user_id}
        return _auth0.users.link_user_account(primary_user_id, body)

    def _merge_user_metadata(self, primary_metadata: dict, secondary_metadata: dict) -> dict:
        """
        Merge metadata from secondary into primary.
        - Primary values take precedence for scalar fields
        - Arrays are concatenated (secondary + primary)
        - Nested dicts are recursively merged
        """
        result = {}
        all_keys = set(primary_metadata.keys()) | set(secondary_metadata.keys())
        for key in all_keys:
            p_val = primary_metadata.get(key)
            s_val = secondary_metadata.get(key)
            if p_val is None:
                result[key] = s_val
            elif s_val is None:
                result[key] = p_val
            elif isinstance(p_val, list) and isinstance(s_val, list):
                result[key] = s_val + p_val
            elif isinstance(p_val, dict) and isinstance(s_val, dict):
                result[key] = self._merge_user_metadata(p_val, s_val)
            else:
                result[key] = p_val
        return result

    def _merge_and_link_accounts(
        self, primary_user_id: str, secondary_provider: str, secondary_user_id: str
    ) -> list[dict]:
        primary_user = self.get_user_info(primary_user_id)
        secondary_user = self.get_user_info(secondary_user_id)

        primary_user_metadata = primary_user.get("user_metadata", {})
        secondary_user_metadata = secondary_user.get("user_metadata", {})
        merged_user_metadata = self._merge_user_metadata(primary_user_metadata, secondary_user_metadata)

        primary_app_metadata = primary_user.get("app_metadata", {})
        secondary_app_metadata = secondary_user.get("app_metadata", {})
        merged_app_metadata = self._merge_user_metadata(primary_app_metadata, secondary_app_metadata)

        update_body = {}
        if merged_user_metadata:
            update_body["user_metadata"] = merged_user_metadata
        if merged_app_metadata:
            update_body["app_metadata"] = merged_app_metadata

        if update_body:
            self._update_user(primary_user_id, update_body)

        result = self._link_user_accounts(primary_user_id, secondary_provider, secondary_user_id)
        return result

    def _is_social_provider(self, provider: str) -> bool:
        return provider in ("google-oauth2", "facebook", "apple")

    # endregion

    # region Token Management

    def get_access_token_for_connection(self, request, connection: str) -> GoogleTokenResult:
        refresh_token = self.get_refresh_token(request)
        return self.get_access_token_for_connection(refresh_token, connection)

    def get_access_token_for_connection_using_user_refresh_token(
        self, refresh_token, connection: str
    ) -> GoogleTokenResult:
        auth0_app = GetToken(self.auth0_domain, self.client_id, self.client_secret)
        # fmt: off
        # Know more at: https://github.com/auth0/auth0-api-python/blob/a915434aa15762780a397b962784c6e3ecd821be/src/auth0_api_python/api_client.py#L415C15-L415C46 # noqa: E501
        SUBJECT_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token"  # noqa S105
        REQUESTED_TOKEN_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN = "http://auth0.com/oauth/token-type/federated-connection-access-token"  # noqa S105,E501
        GRANT_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN = "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token"  # noqa S105,E501
        # fmt: on

        params = {
            "connection": connection,
            "requested_token_type": REQUESTED_TOKEN_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN,
            "grant_type": GRANT_TYPE_FEDERATED_CONNECTION_ACCESS_TOKEN,
            "subject_token": refresh_token,
            "subject_token_type": SUBJECT_TYPE_ACCESS_TOKEN,
        }
        result = auth0_app.access_token_for_connection(**params)
        return result

    def get_refresh_token(self, request):
        session_data = self._get_session(request)
        if not session_data:
            return None
        return session_data["refresh_token"]

    def _get_access_token(self, request, audience=None, scope=None) -> str:
        session_data = self._get_session(request)

        if not audience:
            audience = self.audience

        merged_scope = self._merge_scope_with_defaults(scope, audience)

        if not session_data:
            raise AccessTokenOauthClientError(
                AccessTokenErrorCode.MISSING_SESSION,
                "No session found. The user needs to authenticate.",
            )

        hashed_key = hashlib.sha256(f"{audience}{merged_scope}".encode()).hexdigest()
        token_set = session_data.get(hashed_key)

        is_access_token_still_valid = token_set and token_set.get("expires_at", 0) > time.time()
        if is_access_token_still_valid:
            assert token_set is not None  # Tell mypy that we know that token_set is not None
            return token_set["access_token"]

        # Refresh the token
        try:
            refresh_token = session_data["refresh_token"]
            token_response = refresh_access_token(refresh_token, audience=audience, scope=scope)

            _logger.debug(
                "Storing new token set for audience and scope: %s, %s",
                audience,
                merged_scope,
            )
            new_token_set = {
                "audience": audience,
                "access_token": token_response["access_token"],
                "scope": token_response["scope"],
                "expires_at": int(time.time()) + (token_response["expires_in"] - 60 * 10),
            }
            session_data[hashed_key] = new_token_set
            is_refresh_token_rotated = token_response.get("refresh_token") is not None
            if is_refresh_token_rotated:
                session_data["refresh_token"] = token_response["refresh_token"]
            self._store_session(request, session_data)

            return token_response["access_token"]
        except Exception as e:
            if isinstance(e, AccessTokenOauthClientError):
                raise
            raise AccessTokenOauthClientError(
                AccessTokenErrorCode.REFRESH_TOKEN_ERROR,
                f"Failed to get token with refresh token: {str(e)}",
            )

    def _get_auth0_token_through_m2m(self):
        cache_key = "_auth0_oauth_client_m2m_token"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        _get_token = GetToken(self.auth0_management_api_domain, self.client_id, self.client_secret)
        _tokens = _get_token.client_credentials(f"https://{self.auth0_management_api_domain}/api/v2/")

        cache.set(cache_key, _tokens, timeout=_tokens["expires_in"] - 60)

        return _tokens

    def _merge_scope_with_defaults(self, request_scope, audience=None) -> str | None:
        """Merge requested scopes with default authorization params."""
        audience = audience
        default_scopes = ""
        auth_params = self.authorization_params
        if "scope" in auth_params:
            auth_param_scope = auth_params["scope"]
            if isinstance(auth_param_scope, dict) and audience in auth_param_scope:
                default_scopes = auth_param_scope[audience]
            elif isinstance(auth_param_scope, str):
                default_scopes = auth_param_scope

        default_scopes_list = default_scopes.split()
        request_scopes_list = (request_scope or "").split()

        merged_scopes = list(dict.fromkeys(default_scopes_list + request_scopes_list))
        return " ".join(merged_scopes) if merged_scopes else None

    # endregion

    # region Internal memory management

    def _store_transaction(
        self,
        request,
        state,
        code_verifier,
        redirect_uri,
        is_connect=False,
        auth_session=None,
    ):
        tx = {
            "state": state,
            "code_verifier": code_verifier,
            "redirect_uri": redirect_uri,
            "is_connect": is_connect,
        }
        if auth_session is not None:
            tx["auth_session"] = auth_session
        request.session[self.SESSION_KEY_TX] = tx
        request.session.modified = True

    def _pop_transaction(self, request) -> dict:
        tx = request.session.pop(self.SESSION_KEY_TX, None)
        if not tx:
            raise MissingTransactionOauthClientError()
        return tx

    def _get_session(self, request) -> dict[str, Any] | None:
        return request.session.get(self.SESSION_KEY_STATE, None)

    def _store_session(self, request, session_data: dict[str, Any]) -> None:
        """Store SDK session data in Django session."""
        request.session[self.SESSION_KEY_STATE] = session_data
        request.session.modified = True

    # endregion


auth_client = DjangoAuthClient()
