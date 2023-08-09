import json
import tempfile

from PIL import Image
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework import status
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response

from accounts.models import UserProfile, Provider, Consumer


def get_object(id, request):
    try:
        account = UserProfile.objects.get(id=id)
        if account != request.user.userprofile:
            raise PermissionDenied("You do not have permission to perform this action")

        if account.is_provider:
            provider = Provider.objects.get(userprofile_ptr_id=id)
            return provider, True
        consumer = Consumer.objects.get(userprofile_ptr_id=id)
        return consumer, False

    except UserProfile.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)


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
