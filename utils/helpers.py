import json
import tempfile

from PIL import Image
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework.exceptions import PermissionDenied

from accounts.models import UserProfile, Provider, Consumer


def get_object(is_provider, account_id, user):
    try:
        if is_provider.lower() == "true":
            account = Provider.objects.get(userprofile_ptr_id=account_id)
        else:
            account = Consumer.objects.get(userprofile_ptr_id=account_id)

        if account.userprofile_ptr_id != user.id:
            raise PermissionDenied(detail="You do not have permission to perform this action")

        return account
    except UserProfile.DoesNotExist:
        raise PermissionDenied(detail="You do not have permission to perform this action")


def create_file(suffix=".jpg"):
    if suffix == ".jpg":
        # create a simple image
        image = Image.new('RGB', (100, 100))

        # write image data to a file
        temp_image = tempfile.NamedTemporaryFile(suffix=suffix)
        image.save(temp_image)

        # Get the data from the image file
        temp_image.seek(0)

        # create a SimpleUploadedFile object
        uploaded_file = SimpleUploadedFile(
            name='test_image.jpg',
            content=temp_image.read(),
            content_type='image/jpeg',
        )
    elif suffix == '.json':
        # create some sample JSON data
        data = {
            'name': 'test',
            'type': 'sample',
        }
        data_str = json.dumps(data)
        temp_file = tempfile.NamedTemporaryFile(suffix=suffix)
        temp_file.write(data_str.encode())
        temp_file.seek(0)

        # Create a SimpleUploadedFile object for json
        uploaded_file = SimpleUploadedFile(
            name='test_data.json',
            content=temp_file.read(),
            content_type='application/json'
        )
    else:
        raise ValueError(f'Unsupported file type:{suffix}')

    return uploaded_file
