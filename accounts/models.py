from django.db import models
from django.contrib.auth.models import User


# Create your models here.

class UserProfile(models.Model):
    # One-to-One relation with Django User
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    # Common fields
    profile_pic = models.ImageField(upload_to='profile_pics', blank=True)
    is_provider = models.BooleanField(default=False)
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
    ACCOUNT_STATUS = (
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    )
    provider_type = models.CharField(max_length=20, choices=PROVIDER_TYPES, blank=True)
    account_status = models.CharField(max_length=20, choices=ACCOUNT_STATUS, default='pending')
    description = models.TextField(blank=True)

    def __str__(self):
        return self.user.username
