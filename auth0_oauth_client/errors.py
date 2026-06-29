from typing import Literal


class Auth0OauthClientError(Exception):
    pass


class Auth0OauthClientImproperlyConfigured(Auth0OauthClientError):
    pass


class MissingTransactionOauthClientError(Auth0OauthClientError):
    """Error raised when a required transaction is missing."""

    code = "missing_transaction_error"

    def __init__(self, message=None):
        super().__init__(message or "The transaction is missing.")


class ApiOauthClientError(Auth0OauthClientError):
    """Error raised when an API request to Auth0 fails."""

    def __init__(self, code, message, cause=None):
        super().__init__(message)
        self.code = code
        self.cause = cause
        if cause:
            self.error = getattr(cause, "error", None)
            self.error_description = getattr(cause, "error_description", None)
        else:
            self.error = None
            self.error_description = None


class AccessTokenOauthClientError(Auth0OauthClientError):
    """Error raised when there's an issue with access tokens."""

    def __init__(self, code, message, cause=None):
        super().__init__(message)
        self.code = code
        self.cause = cause


class AccessTokenForConnectionOauthClientError(Auth0OauthClientError):
    """Error when retrieving access tokens for a specific connection fails."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class MissingRequiredArgumentOauthClientError(Auth0OauthClientError):
    """Error raised when a required argument is missing."""

    code = "missing_required_argument_error"

    def __init__(self, argument):
        message = f"The argument '{argument}' is required but was not provided."
        super().__init__(message)
        self.argument = argument


class InvalidArgumentOauthClientError(Auth0OauthClientError):
    """Error raised when a given argument is an invalid value."""

    code = "invalid_argument"

    def __init__(self, argument, message):
        super().__init__(message)
        self.argument = argument


class CustomTokenExchangeOauthClientError(Auth0OauthClientError):
    """Error raised during custom token exchange operations."""

    def __init__(self, code, message, cause=None):
        super().__init__(message)
        self.code = code
        self.cause = cause


class MyAccountApiOauthClientError(Auth0OauthClientError):
    """Error raised when an API request to My Account API fails."""

    def __init__(self, title=None, type=None, detail=None, status=None, validation_errors=None):
        super().__init__(detail)
        self.title = title
        self.type = type
        self.detail = detail
        self.status = status
        self.validation_errors = validation_errors


class AccessTokenErrorCode:
    """Error codes for access token operations."""

    MISSING_SESSION = "missing_session"
    MISSING_REFRESH_TOKEN = "missing_refresh_token"
    FAILED_TO_REFRESH_TOKEN = "failed_to_refresh_token"
    FAILED_TO_REQUEST_TOKEN = "failed_to_request_token"
    REFRESH_TOKEN_ERROR = "refresh_token_error"
    AUTH_REQ_ID_ERROR = "auth_req_id_error"
    INCORRECT_AUDIENCE = "incorrect_audience"


class AccessTokenForConnectionErrorCode:
    """Error codes for connection-specific token operations."""

    MISSING_REFRESH_TOKEN = "missing_refresh_token"
    FAILED_TO_RETRIEVE = "failed_to_retrieve"
    API_ERROR = "api_error"
    FETCH_ERROR = "retrieval_error"


class CustomTokenExchangeErrorCode:
    """Error codes for custom token exchange operations."""

    INVALID_TOKEN_FORMAT = "invalid_token_format"
    MISSING_ACTOR_TOKEN_TYPE = "missing_actor_token_type"
    TOKEN_EXCHANGE_FAILED = "token_exchange_failed"
    INVALID_RESPONSE = "invalid_response"


class AccountLinkingError(Auth0OauthClientError):
    def __init__(self, message):
        super().__init__(message)


PingStage = Literal["m2m_token", "token_claims", "scope_grant"]


class Auth0PingError(ApiOauthClientError):
    """Raised when DjangoAuthClient.ping() fails."""

    def __init__(
        self,
        stage: PingStage,
        message: str,
        *,
        status_code: int | None = None,
        missing_scopes: frozenset[str] | None = None,
    ):
        self.stage = stage
        self.status_code = status_code
        self.missing_scopes = missing_scopes or frozenset()
        super().__init__(stage, message)


# Stable Auth0 machine code (HTTP 401) returned when the federated refresh token is gone from the
# Token Vault. Always match this machine code, never the human-readable description.
FEDERATED_CONNECTION_REFRESH_TOKEN_NOT_FOUND_CODE = "federated_connection_refresh_token_not_found"


class FederatedConnectionRefreshTokenNotFound(Auth0OauthClientError):
    """Raised when Auth0 returns HTTP 401 with error == 'federated_connection_refresh_token_not_found'.

    The federated connection's refresh token (e.g. google-oauth2) is no longer in the Token Vault, so
    the user must reconnect. Lets callers catch a precise type instead of string-matching. The stable
    machine code is exposed on `.error`/`.code`; the original cause and status are preserved.
    """

    code = FEDERATED_CONNECTION_REFRESH_TOKEN_NOT_FOUND_CODE

    def __init__(self, message=None, *, error_description=None, status_code=401, cause=None):
        super().__init__(message or "Federated connection Refresh Token not found.")
        self.error = self.code
        self.error_description = error_description
        self.status_code = status_code
        self.cause = cause
