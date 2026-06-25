from django.contrib.admin.sites import AdminSite
from django.test import TestCase

from auth0_oauth_client.admin import AccountLinkingAdmin
from auth0_oauth_client.admin import AccountTokenAdmin
from auth0_oauth_client.admin import ConnectedAccountAdmin
from auth0_oauth_client.models import AccountLinking
from auth0_oauth_client.models import AccountToken
from auth0_oauth_client.models import ConnectedAccount


class AdminReadonlyFieldsTest(TestCase):
    def setUp(self):
        self.site = AdminSite()

    def test_connected_account_admin_exposes_timestamps_as_readonly(self):
        model_admin = ConnectedAccountAdmin(ConnectedAccount, self.site)
        readonly_fields = model_admin.get_readonly_fields(request=None)
        self.assertIn("created_at", readonly_fields)
        self.assertIn("updated_at", readonly_fields)

    def test_account_token_admin_exposes_timestamps_as_readonly(self):
        model_admin = AccountTokenAdmin(AccountToken, self.site)
        readonly_fields = model_admin.get_readonly_fields(request=None)
        self.assertIn("created_at", readonly_fields)
        self.assertIn("updated_at", readonly_fields)

    def test_account_linking_admin_exposes_timestamps_as_readonly(self):
        model_admin = AccountLinkingAdmin(AccountLinking, self.site)
        readonly_fields = model_admin.get_readonly_fields(request=None)
        self.assertIn("created_at", readonly_fields)
        self.assertIn("updated_at", readonly_fields)

    def test_connected_account_admin_lists_timestamps(self):
        model_admin = ConnectedAccountAdmin(ConnectedAccount, self.site)
        self.assertIn("created_at", model_admin.list_display)
        self.assertIn("updated_at", model_admin.list_display)

    def test_account_token_admin_lists_timestamps(self):
        model_admin = AccountTokenAdmin(AccountToken, self.site)
        self.assertIn("created_at", model_admin.list_display)
        self.assertIn("updated_at", model_admin.list_display)

    def test_account_linking_admin_lists_timestamps(self):
        model_admin = AccountLinkingAdmin(AccountLinking, self.site)
        self.assertIn("created_at", model_admin.list_display)
        self.assertIn("updated_at", model_admin.list_display)
