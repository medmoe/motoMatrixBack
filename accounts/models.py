from functools import partial

from django.contrib.auth.models import User
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models
from phonenumber_field.modelfields import PhoneNumberField

from utils.helpers import uploaded_file_directory_path

PROFILE_PIC_DIR = 'profile_pic/'
STORE_LOGO_DIR = 'store_logo/'


class AccountStatus(models.TextChoices):
    APPROVED = 'APPROVED', 'Approved'
    PENDING = 'PENDING', 'Pending'
    SUSPENDED = 'SUSPENDED', 'Suspended'


class ProviderTypes(models.TextChoices):
    STORE = 'STORE', 'Store'
    INDIVIDUAL = 'INDIVIDUAL', 'Individual'
    JUNKYARD = 'JUNKYARD', 'Junkyard'
    WHOLESALER = 'WHOLESALER', 'Wholesaler'
    MANUFACTURER = 'MANUFACTURER', 'Manufacturer'


class UserProfile(models.Model):
    """ Defines the user profile in the system """

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_pic = models.ImageField(upload_to=partial(uploaded_file_directory_path, PROFILE_PIC_DIR), blank=True)
    phone = PhoneNumberField(blank=True)
    address = models.CharField(max_length=200, blank=True)
    city = models.CharField(max_length=50, blank=True)
    country = models.CharField(max_length=50, blank=True)
    zip_code = models.CharField(max_length=20, blank=True)
    sign_up_date = models.DateTimeField(auto_now_add=True)
    last_login_date = models.DateTimeField(auto_now=True)
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username


class Provider(models.Model):
    """ Defines the provider """

    userprofile = models.OneToOneField(UserProfile, on_delete=models.CASCADE)
    store_name = models.CharField(max_length=50, blank=True)
    store_description = models.TextField(blank=True)
    account_status = models.CharField(max_length=20, choices=AccountStatus.choices, default=AccountStatus.PENDING)
    store_logo = models.ImageField(upload_to=partial(uploaded_file_directory_path, STORE_LOGO_DIR), blank=True)
    cached_average_rating = models.DecimalField(max_digits=3, decimal_places=2, null=True, blank=True)
    number_of_sales = models.IntegerField(default=0)
    provider_type = models.CharField(max_length=20, choices=ProviderTypes.choices, null=True)


class Consumer(models.Model):
    """ Defines the consumer """

    userprofile = models.OneToOneField(UserProfile, on_delete=models.CASCADE)
    wishlist = models.ManyToManyField('components.AutoPart', related_name="wishlist")
    cart = models.ManyToManyField('components.AutoPart', related_name="cart")
    favorite_providers = models.ManyToManyField(Provider, related_name="favorite_providers")


class Rating(models.Model):
    """ Defines the rating given to the provider by consumers """

    rated = models.ForeignKey(Provider, on_delete=models.CASCADE, related_name="ratings")
    rater = models.ForeignKey(Consumer, on_delete=models.CASCADE)
    stars = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(5)])
    review_text = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        self.update_cached_average(save=True)

    def delete(self, *args, **kwargs):
        super().delete(*args, **kwargs)
        self.update_cached_average(save=True)

    def update_cached_average(self, save=False):
        average = self.rated.ratings.aggregate(avg_rating=models.Avg('stars'))['avg_rating']
        self.rated.cached_average_rating = average or 0
        if save:
            self.rated.save()
