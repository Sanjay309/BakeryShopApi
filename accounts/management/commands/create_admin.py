from django.core.management.base import BaseCommand, CommandError


from django.contrib.auth import get_user_model
User = get_user_model()

class Command(BaseCommand):
    help = 'Creates admin user,if it does not exist'

    def handle(self, *args, **options):
        user = User.objects.filter(email='sanjaychhabarwal0022@hmail.com').first()
        if user:
            self.stdout.write(self.style.SUCCESS(f"user {user} already exists"))
            return
        else:
            self.stdout.write(self.style.SUCCESS(f"user not found, creating..."))
            user = User.objects.create_superuser('sanjaychhabarwal0022@hmail.com',password='helloadmin')
            user.first_name='sanjay'
            user.last_name='chhabarwal'
            user.save()

        if user:
            self.stdout.write(self.style.SUCCESS(f"created {user} successfully"))
        else:
            self.stdout.write(self.style.ERROR(f"unable to create user"))