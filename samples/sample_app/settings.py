import os

from logging import Formatter
from pathlib import Path

from sample_app.support.utils import getenv_or_raise_exception
from sample_app.support.utils import strtobool

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "django-insecure-f4c!1dug2--u6wtw0%30n#lqw2mvjjf9@-sb+wxo8!dl6p%3nk"

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = strtobool(os.getenv("DJANGO_DEBUG", "False"))

ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "auth0_oauth_client",
    "sample_app.apps.core",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "sample_app.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "sample_app.wsgi.application"


# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}

# Password validation
# https://docs.djangoproject.com/en/5.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.2/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True

# Logging
# https://docs.djangoproject.com/en/5.2/topics/logging/

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "()": Formatter,
            "format": "%(levelname)-8s [%(asctime)s] %(name)s: %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": os.getenv("DEFAULT_LOG_FORMATTER", "standard"),
        }
    },
    "loggers": {
        "": {"level": os.getenv("ROOT_LOG_LEVEL", "INFO"), "handlers": ["console"]},
        "sample_app": {"level": os.getenv("PROJECT_LOG_LEVEL", "INFO"), "handlers": ["console"]},
        "django": {"level": os.getenv("DJANGO_LOG_LEVEL", "INFO"), "handlers": ["console"]},
        "django.db.backends": {"level": os.getenv("DJANGO_DB_BACKENDS_LOG_LEVEL", "INFO"), "handlers": ["console"]},
        "django.request": {"level": os.getenv("DJANGO_REQUEST_LOG_LEVEL", "INFO"), "handlers": ["console"]},
        "urllib3": {"level": os.getenv("URLLIB3_LOG_LEVEL", "WARNING"), "handlers": ["console"]},
        "auth0_oauth_client": {"level": os.getenv("AUTH0_OAUTH_CLIENT_LOG_LEVEL", "WARNING"), "handlers": ["console"]},
    },
}

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.2/howto/static-files/

STATIC_URL = "static/"

# Default primary key field type
# https://docs.djangoproject.com/en/5.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# The Django authentication system
# https://docs.djangoproject.com/en/5.2/topics/auth/
LOGIN_URL = "/login/"
AUTHENTICATION_BACKENDS = [
    # Allow login with username and password
    "django.contrib.auth.backends.ModelBackend",
    # Allow login with Auth0 using the token returned during the Authorization Code Flow
    "sample_app.apps.core.authentication_backends.Auth0Backend",
]

AUTH0_MANAGEMENT_API_DOMAIN = getenv_or_raise_exception("AUTH0_MANAGEMENT_API")
AUTH0_DOMAIN = getenv_or_raise_exception("AUTH0_DOMAIN")
AUTH0_OAUTH_CLIENT_AUTH_PARAMS_AUDIENCE = os.getenv("AUTH0_OAUTH_CLIENT_AUTH_PARAMS_AUDIENCE")
AUTH0_CLIENT_ID = getenv_or_raise_exception("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = getenv_or_raise_exception("AUTH0_CLIENT_SECRET")
AUTH0_CONNECTIONS_FOR_ACCOUNT_LINKING = getenv_or_raise_exception("AUTH0_CONNECTIONS_FOR_ACCOUNT_LINKING").split(",")
AUTH0_OAUTH_CLIENT = {
    "auth0_domain": AUTH0_DOMAIN,
    "auth0_management_api_domain": AUTH0_MANAGEMENT_API_DOMAIN,
    "client_id": AUTH0_CLIENT_ID,
    "client_secret": AUTH0_CLIENT_SECRET,
    "authorization_params": {
        "scope": "openid profile email offline_access",
        "audience": AUTH0_OAUTH_CLIENT_AUTH_PARAMS_AUDIENCE,
    },
    "custom_scopes": {
        "google-oauth2": [
            "https://www.googleapis.com/auth/adsense",
            "https://www.googleapis.com/auth/analytics.edit",
            "https://www.googleapis.com/auth/calendar",
            "https://www.googleapis.com/auth/tagmanager.edit.containers",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
            "openid",
        ],
    },
    "connections_for_account_linking": AUTH0_CONNECTIONS_FOR_ACCOUNT_LINKING,
}
