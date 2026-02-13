import uuid

from django.db import IntegrityError
from django.test import TransactionTestCase

from auth0_oauth_client.models import AccountLinking
from auth0_oauth_client.models import AccountToken
from auth0_oauth_client.models import ConnectedAccount


class AccountLinkingModelTest(TransactionTestCase):
    def test_create_account_linking(self):
        entry = AccountLinking.objects.create(
            primary_user_id="auth0|primary123",
            secondary_provider="google-oauth2",
            secondary_user_id="google-oauth2|secondary456",
        )
        self.assertEqual(entry.primary_user_id, "auth0|primary123")
        self.assertEqual(entry.secondary_provider, "google-oauth2")
        self.assertEqual(entry.secondary_user_id, "google-oauth2|secondary456")

    def test_auto_generated_fields(self):
        entry = AccountLinking.objects.create(
            primary_user_id="auth0|primary123",
            secondary_provider="google-oauth2",
            secondary_user_id="google-oauth2|secondary456",
        )
        self.assertIsInstance(entry.id, uuid.UUID)
        self.assertIsNotNone(entry.created_at)
        self.assertIsNotNone(entry.updated_at)

    def test_unique_constraint(self):
        AccountLinking.objects.create(
            primary_user_id="auth0|primary123",
            secondary_provider="google-oauth2",
            secondary_user_id="google-oauth2|secondary456",
        )
        with self.assertRaises(IntegrityError):
            AccountLinking.objects.create(
                primary_user_id="auth0|primary123",
                secondary_provider="google-oauth2",
                secondary_user_id="google-oauth2|secondary456",
            )

    def test_different_providers_allowed(self):
        AccountLinking.objects.create(
            primary_user_id="auth0|primary123",
            secondary_provider="google-oauth2",
            secondary_user_id="google-oauth2|secondary456",
        )
        entry2 = AccountLinking.objects.create(
            primary_user_id="auth0|primary123",
            secondary_provider="facebook",
            secondary_user_id="facebook|secondary789",
        )
        self.assertEqual(AccountLinking.objects.count(), 2)
        self.assertEqual(entry2.secondary_provider, "facebook")


class ConnectedAccountModelTest(TransactionTestCase):
    def test_create_connected_account(self):
        entry = ConnectedAccount.objects.create(
            connected_account_id="ca_123",
            email="user@example.com",
            provider="google-oauth2",
            user_id_owner="auth0|user123",
        )
        self.assertEqual(entry.connected_account_id, "ca_123")
        self.assertEqual(entry.email, "user@example.com")
        self.assertEqual(entry.provider, "google-oauth2")
        self.assertEqual(entry.user_id_owner, "auth0|user123")
        self.assertFalse(entry.is_account_linked)

    def test_auto_generated_fields(self):
        entry = ConnectedAccount.objects.create(
            connected_account_id="ca_123",
            email="user@example.com",
            provider="google-oauth2",
            user_id_owner="auth0|user123",
        )
        self.assertIsInstance(entry.id, uuid.UUID)
        self.assertIsNotNone(entry.created_at)
        self.assertIsNotNone(entry.updated_at)

    def test_is_account_linked_default_false(self):
        entry = ConnectedAccount.objects.create(
            connected_account_id="ca_123",
            email="user@example.com",
            provider="google-oauth2",
            user_id_owner="auth0|user123",
        )
        self.assertFalse(entry.is_account_linked)

    def test_is_account_linked_can_be_set_true(self):
        entry = ConnectedAccount.objects.create(
            connected_account_id="ca_123",
            email="user@example.com",
            provider="google-oauth2",
            user_id_owner="auth0|user123",
            is_account_linked=True,
        )
        self.assertTrue(entry.is_account_linked)

    def test_connected_account_id_unique(self):
        ConnectedAccount.objects.create(
            connected_account_id="ca_123",
            email="user@example.com",
            provider="google-oauth2",
            user_id_owner="auth0|user123",
        )
        with self.assertRaises(IntegrityError):
            ConnectedAccount.objects.create(
                connected_account_id="ca_123",
                email="other@example.com",
                provider="facebook",
                user_id_owner="auth0|user456",
            )

    def test_unique_user_provider_constraint(self):
        ConnectedAccount.objects.create(
            connected_account_id="ca_123",
            email="user@example.com",
            provider="google-oauth2",
            user_id_owner="auth0|user123",
        )
        with self.assertRaises(IntegrityError):
            ConnectedAccount.objects.create(
                connected_account_id="ca_456",
                email="user@example.com",
                provider="google-oauth2",
                user_id_owner="auth0|user123",
            )

    def test_same_user_different_provider_allowed(self):
        ConnectedAccount.objects.create(
            connected_account_id="ca_123",
            email="user@example.com",
            provider="google-oauth2",
            user_id_owner="auth0|user123",
        )
        entry2 = ConnectedAccount.objects.create(
            connected_account_id="ca_456",
            email="user@example.com",
            provider="facebook",
            user_id_owner="auth0|user123",
        )
        self.assertEqual(ConnectedAccount.objects.count(), 2)
        self.assertEqual(entry2.provider, "facebook")


class AccountTokenModelTest(TransactionTestCase):
    def test_create_account_token(self):
        entry = AccountToken.objects.create(
            user_id="auth0|user123",
            refresh_token="rt_abc123",
        )
        self.assertEqual(entry.user_id, "auth0|user123")
        self.assertEqual(entry.refresh_token, "rt_abc123")

    def test_auto_generated_fields(self):
        entry = AccountToken.objects.create(
            user_id="auth0|user123",
            refresh_token="rt_abc123",
        )
        self.assertIsInstance(entry.id, uuid.UUID)
        self.assertIsNotNone(entry.created_at)
        self.assertIsNotNone(entry.updated_at)

    def test_user_id_unique(self):
        AccountToken.objects.create(
            user_id="auth0|user123",
            refresh_token="rt_abc123",
        )
        with self.assertRaises(IntegrityError):
            AccountToken.objects.create(
                user_id="auth0|user123",
                refresh_token="rt_def456",
            )

    def test_update_or_create(self):
        AccountToken.objects.create(
            user_id="auth0|user123",
            refresh_token="rt_original",
        )
        AccountToken.objects.update_or_create(
            user_id="auth0|user123",
            defaults={"refresh_token": "rt_updated"},
        )
        entry = AccountToken.objects.get(user_id="auth0|user123")
        self.assertEqual(entry.refresh_token, "rt_updated")
        self.assertEqual(AccountToken.objects.count(), 1)
