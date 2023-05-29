from django.db import models
from django.contrib.auth.models import User


# Create your models here.

class UserProfile(models.Model):
    # One-to-One relation with Django User
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    # Common fields
    profile_pic = models.ImageField(upload_to='profile_pics', blank=True)
    phone = models.CharField(max_length=20, blank=True)
    address = models.CharField(max_length=200, blank=True)
    city = models.CharField(max_length=50, blank=True)
    country = models.CharField(max_length=50, blank=True)
    rating = models.IntegerField(default=0)


class Consumer(UserProfile):
    # Additional fields if needed
    pass


class Provider(UserProfile):
    PROVIDER_TYPES = (
        ('store', 'Store'),
        ('individual', 'Individual'),
        ('junkyard', 'Junkyard'),
        ('wholesaler', 'Wholesaler'),
        ('manufacturer', 'Manufacturer'),
    )
    provider_type = models.CharField(max_length=20, choices=PROVIDER_TYPES, blank=True)
    description = models.TextField(blank=True)
