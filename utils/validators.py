from PIL import Image, UnidentifiedImageError


def validate_image(file):
    try:
        # Open the image file
        image = Image.open(file)
        image.verify()
        image.close()
        return True
    except (IOError, UnidentifiedImageError):
        return False
