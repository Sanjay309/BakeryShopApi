from django.core.management.base import BaseCommand, CommandError

from django.contrib.auth import get_user_model
User = get_user_model()

class Command(BaseCommand):
    help = 'Creates admin user,if it does not exist'

    def handle(self, *args, **options):
        moderators = [{
            'email':'sanjaychhabarwal0011@gmail.com',
            'first_name':'sanjay',
            'last_name':'chhabarwal',
            'password':'AdminOne',
        }]
        for mod in moderators:
            user = User.objects.filter(email=mod['email']).first()
            if user:
                self.stdout.write(self.style.SUCCESS(f"Moderator {mod['email']} already exists"))
                continue
            else:
                self.stdout.write(self.style.SUCCESS(f"Moderator not found, creating..."))
                user = User()
                user.email=mod['email']
                user.first_name=mod['first_name']
                user.last_name=mod['last_name']
                user.set_password(mod['password'])
                # Moderators is a admin
                user.is_admin=True
                user.save()

            if user:
                self.stdout.write(self.style.SUCCESS(f"created {mod['email']} successfully"))
            else:
                self.stdout.write(self.style.ERROR(f"unable to create user:{mod['email']}"))
