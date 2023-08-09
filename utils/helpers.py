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


def create_image(suffix=".jpg"):
    # create a simple image
    image = Image.new('RGB', (100, 100))

    # write image data to a file
    temp_image = tempfile.NamedTemporaryFile(suffix=suffix)
    image.save(temp_image)

    # Get the data from the image file
    temp_image.seek(0)

    # create a SimpleUploadedFile object
    uploaded_image = SimpleUploadedFile(
        name='test_image.jpg',
        content=temp_image.read(),
        content_type='image/jpeg',
    )
    return uploaded_image
