from django.contrib import admin

from auth0_oauth_client.models import AccountLinking
from auth0_oauth_client.models import AccountToken
from auth0_oauth_client.models import ConnectedAccount


@admin.register(ConnectedAccount)
class ConnectedAccountAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "connected_account_id",
        "email",
        "provider",
        "user_id_owner",
        "is_account_linked",
        "created_at",
        "updated_at",
    )
    list_filter = (
        "provider",
        "is_account_linked",
    )
    search_fields = (
        "email",
        "user_id_owner",
    )


@admin.register(AccountToken)
class AccountTokenAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user_id",
        "refresh_token",
        "created_at",
        "updated_at",
    )
    search_fields = ("user_id",)


@admin.register(AccountLinking)
class AccountLinkingAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "primary_user_id",
        "secondary_provider",
        "secondary_user_id",
        "created_at",
        "updated_at",
    )
    list_filter = ("secondary_provider",)
    search_fields = (
        "primary_user_id",
        "secondary_user_id",
    )
