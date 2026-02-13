from typing import Literal
from typing import NotRequired
from typing import TypedDict


class UserinfoPayload(TypedDict):
    aud: str
    email: str
    email_verified: bool
    exp: int
    given_name: str
    iat: int
    iss: str
    name: str
    nickname: str
    picture: str
    sid: str
    sub: str
    updated_at: str


class TokenResponse(TypedDict):
    access_token: str
    expires_in: int
    id_token: str
    refresh_token: NotRequired[str]
    scope: str
    token_type: str
    userinfo: NotRequired[UserinfoPayload]


class ConnectedAccountResponse(TypedDict):
    id: str
    connection: str
    access_type: Literal["offline"]
    scopes: list[str]
    created_at: str
    expires_at: str


class AvailableConnection(TypedDict):
    name: str
    strategy: str
    scopes: list[str]


class ConnectParams(TypedDict):
    ticket: str


class ConnectedAccountAuthSessionPayload(TypedDict):
    auth_session: str
    connect_params: ConnectParams
    connect_uri: str
    expires_in: int


class CompleteConnectedAccountRequestBody(TypedDict):
    auth_session: str
    connect_code: str
    redirect_uri: str
    code_verifier: str


class IdentityResponseBody(TypedDict):
    connection: str
    provider: str


class SearchUserResponseBody(TypedDict):
    identities: list[IdentityResponseBody]
    user_id: str


class AccountLinkingPayload(TypedDict):
    primary_user_id: str
    primary_provider: str
    primary_provider_friendly_name: str
    primary_connection_name: str
    secondary_user_id: str
    secondary_provider: str
    secondary_connection_name: str


class VerifyAccountLinkingResult(TypedDict):
    is_pending_account_linking: bool
    is_account_linked: bool


class CompleteAccountLinkingResult(TypedDict):
    success: bool
    used_different_account: NotRequired[bool]


class GoogleTokenResult(TypedDict):
    access_token: str
    expires_in: int
    scope: str
