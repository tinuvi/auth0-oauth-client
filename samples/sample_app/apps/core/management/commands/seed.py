from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

_User = get_user_model()


class Command(BaseCommand):
    help = "Seed the database"

    def handle(self, *args, **options):
        if not _User.objects.filter(is_superuser=True).exists():
            _User.objects.create_superuser("admin", None, "admin")
            self.stdout.write("Super user has been created")
        else:
            self.stdout.write("Super user already exists")
