from django.contrib import admin

from sample_app.apps.core.models import YourUser
from sample_app.support.django_utills import CustomModelAdminMixin


@admin.register(YourUser)
class YourUserAdmin(CustomModelAdminMixin):
    pass
