from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "test-secret-key-for-unit-tests"

TEST_OUTPUT_DIR = str(BASE_DIR / "tests-reports")
TEST_OUTPUT_FILE_NAME = "junit.xml"

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.messages",
    "django.contrib.sessions",
    "auth0_oauth_client",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
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
