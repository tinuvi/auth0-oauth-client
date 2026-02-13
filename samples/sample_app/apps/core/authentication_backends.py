from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from django.db import transaction

from sample_app.apps.core.models import YourUser

_User = get_user_model()


class Auth0Backend(BaseBackend):
    def authenticate(self, request, auth0_username=None, refresh_token=None, **kwargs):
        if not auth0_username:
            return None
        allowed_django_username = auth0_username.replace("|", "_")

        try:
            user = _User.objects.get(username=allowed_django_username)
            your_user = user.youruser
            your_user.idp_refresh_token = refresh_token
            your_user.save()
        except _User.DoesNotExist:
            user = _User(username=allowed_django_username)
            with transaction.atomic():
                user.save()
                YourUser.objects.create(user=user, idp_refresh_token=refresh_token)

        return user

    def get_user(self, user_id):
        try:
            return _User.objects.get(pk=user_id)
        except _User.DoesNotExist:
            return None
