from django.db import models

try:
    from uuid import uuid7 as default_uuid
except:  # noqa: B001,E722
    from uuid import uuid4 as default_uuid


class _StandardModelMixin(models.Model):
    id = models.UUIDField(primary_key=True, default=default_uuid, editable=False, verbose_name="Id")
    created_at = models.DateTimeField(auto_now_add=True, editable=False, verbose_name="Created at")
    updated_at = models.DateTimeField(auto_now=True, editable=False, verbose_name="Updated at")

    class Meta:
        abstract = True


class AccountLinking(_StandardModelMixin):
    primary_user_id = models.CharField(max_length=128, verbose_name="Primary User ID")
    secondary_provider = models.CharField(max_length=128, verbose_name="Provider")
    secondary_user_id = models.CharField(max_length=128, verbose_name="Secondary User ID")

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=[
                    "primary_user_id",
                    "secondary_provider",
                    "secondary_user_id",
                ],
                name="unique_account_linking",
            )
        ]


class ConnectedAccount(_StandardModelMixin):
    connected_account_id = models.CharField(max_length=128, unique=True, verbose_name="Connected Account ID")
    email = models.EmailField(verbose_name="Email")
    provider = models.CharField(max_length=128, verbose_name="Provider")
    user_id_owner = models.CharField(max_length=128, verbose_name="User ID Owner")
    is_account_linked = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=[
                    "user_id_owner",
                    "provider",
                ],
                name="unique_connected_account",
            )
        ]


class AccountToken(_StandardModelMixin):
    user_id = models.CharField(max_length=128, unique=True, verbose_name="User ID")
    refresh_token = models.CharField(max_length=128, verbose_name="Refresh Token")
