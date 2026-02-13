import uuid

from django.contrib.auth.models import User
from django.db import models


class YourUser(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid7, editable=False, verbose_name="Id")
    created_at = models.DateTimeField(auto_now_add=True, editable=False, verbose_name="Created at")
    updated_at = models.DateTimeField(auto_now=True, editable=False, verbose_name="Updated at")
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    idp_refresh_token = models.CharField(
        max_length=128,
        null=True,
        blank=True,
        verbose_name="IDP Refresh Token",
    )

    @property
    def idp_username(self):
        return self.user.username.replace("_", "|")
