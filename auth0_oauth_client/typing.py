from typing import Literal
from typing import NotRequired
from typing import TypedDict


class AddressPayload(TypedDict, total=False):
    country: str


class UserinfoPayload(TypedDict, total=False):
    sub: str
    name: str
    given_name: str
    family_name: str
    middle_name: str
    nickname: str
    preferred_username: str
    profile: str
    picture: str
    website: str
    email: str
    email_verified: bool
    gender: str
    birthdate: str
    zoneinfo: str
    locale: str
    phone_number: str
    phone_number_verified: bool
    address: AddressPayload
    updated_at: int
    aud: str
    exp: int
    iat: int
    iss: str
    sid: str


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


class IdentityProfileData(TypedDict, total=False):
    email: str
    email_verified: bool
    name: str
    username: str
    given_name: str
    phone_number: str
    phone_verified: bool
    family_name: str


class IdentityResponseBody(TypedDict, total=False):
    connection: str
    user_id: str
    provider: str
    isSocial: bool
    access_token: str
    access_token_secret: str
    refresh_token: str
    profileData: IdentityProfileData


class UserDetailsPayload(TypedDict, total=False):
    user_id: str
    email: str
    email_verified: bool
    username: str
    phone_number: str
    phone_verified: bool
    created_at: str
    updated_at: str
    identities: list[IdentityResponseBody]
    app_metadata: dict
    user_metadata: dict
    picture: str
    name: str
    nickname: str
    multifactor: list[str]
    last_ip: str
    last_login: str
    logins_count: int
    blocked: bool
    given_name: str
    family_name: str


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
