from django.contrib import admin
from django.urls import include
from django.urls import path

from sample_app.apps.core import views

auth_patterns = (
    [
        path("login/", views.initiate_login_flow, name="initiate-login-flow"),
        path(
            "callback/",
            views.finalize_login_or_connected_account_flow_callback,
            name="callback",
        ),
        path("logout/", views.auth_logout, name="logout"),
        path(
            "initiate-account-linking/",
            views.initiate_account_linking_flow,
            name="initiate-account-linking-flow",
        ),
        path(
            "cancel-account-linking/",
            views.cancel_account_linking_flow,
            name="cancel-account-linking-flow",
        ),
        path(
            "connect/",
            views.initiate_connected_account_flow,
            name="initiate-connected-account-flow",
        ),
        # Connected Accounts Management
        path(
            "connected-accounts/",
            views.list_connected_accounts,
            name="list-connected-accounts",
        ),
        path(
            "connected-accounts/connections/",
            views.list_available_connections,
            name="list-available-connections",
        ),
        path(
            "connected-accounts/<str:account_id>/",
            views.delete_connected_account,
            name="delete-connected-account",
        ),
    ],
    "auth",
)

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", views.welcome_page, name="welcome"),
    path("internal/", views.internal_page, name="internal"),
    path("link-account/", views.link_account_page, name="link-account"),
    path(
        "spy-access-token-for-connection/",
        views.spy_access_token_for_connection,
        name="spy-access-token-for-connection",
    ),
    path(
        "custom-login/",
        views.initiate_custom_login_flow,
        name="initiate-custom-login-flow",
    ),
    path("auth/", include(auth_patterns)),
]
