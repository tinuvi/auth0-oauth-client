import django

django.setup()

from django.core.management import call_command

call_command("migrate", "--run-syncdb", verbosity=0)
