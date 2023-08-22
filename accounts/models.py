from django.contrib.auth.models import User
from django.db import models

from enum import Enum, unique


@unique
class AccountStatus(Enum):
    APPROVED = 'APPROVED'
    PENDING = 'PENDING'
    REJECTED = 'REJECTED'


@unique
class ProviderTypes(Enum):
    STORE = 'STORE'
    INDIVIDUAL = 'INDIVIDUAL'
    JUNKYARD = 'JUNKYARD'
    WHOLESALER = 'WHOLESALER'
    MANUFACTURER = 'MANUFACTURER'


class UserProfile(models.Model):
    # One-to-One relation with Django User
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    # Common fields
    profile_pic = models.ImageField(upload_to='', blank=True)
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
    provider_types = [(provider_type.value, provider_type.name) for provider_type in ProviderTypes]
    accounts_statuses = [(status.value, status.name) for status in AccountStatus]

    provider_type = models.CharField(max_length=20, choices=provider_types, blank=True)
    account_status = models.CharField(max_length=20, choices=accounts_statuses, default=AccountStatus.PENDING.value)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.user.username
