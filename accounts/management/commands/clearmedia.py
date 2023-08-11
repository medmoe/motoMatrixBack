from django.core.management.base import BaseCommand
import shutil
import os
from django.conf import settings


class Command(BaseCommand):
    help = 'Clear media files'

    def handle(self, *args, **options):
        media_root = settings.MEDIA_ROOT

        # Confirm the action from the user
        user_confirmation = input(f'Are you sure you want to delete all media files in {media_root}?(yes/no):')
        if user_confirmation.lower() == 'yes':
            for root, dirs, files in os.walk(media_root):
                for file in files:
                    os.remove(os.path.join(root, file))
                for dir in dirs:
                    shutil.rmtree(os.path.join(root, dir))

            self.stdout.write(self.style.SUCCESS('Media files cleared successfully!'))
        else:
            self.stdout.write('Operation cancelled.')
