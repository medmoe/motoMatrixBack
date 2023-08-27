import json
import os
import tempfile

from PIL import Image
from django.core.files.uploadedfile import SimpleUploadedFile


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


def uploaded_file_directory_path(directory_name, instance, filename):
    """ Return a path in which the uploaded files go to """
    return os.path.join(directory_name, str(instance.user.id), filename)
