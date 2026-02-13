from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "test-secret-key-for-unit-tests"

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "auth0_oauth_client",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}

AUTH0_OAUTH_CLIENT = {
    "auth0_domain": "test.auth0.com",
    "auth0_management_api_domain": "test.auth0.com",
    "client_id": "test-client-id",
    "client_secret": "test-client-secret",
    "audience": "https://api.test.com/",
    "authorization_params": {
        "scope": "openid profile email offline_access",
        "prompt": "consent",
    },
    "base_url": "https://app.test.com",
    "connections_for_account_linking": ["google-oauth2", "facebook"],
}
