from django.contrib.auth.models import User
from factory import Faker, SubFactory
from factory.django import DjangoModelFactory

from .models import UserProfile, Provider, Consumer, AccountStatus


class UserFactory(DjangoModelFactory):
    class Meta:
        model = User

    first_name = Faker('first_name')
    last_name = Faker('last_name')
    email = Faker('email')
    username = Faker('name')

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        """Override the default _create method to use create_user."""
        password = kwargs.pop('password', 'password')
        user = model_class.objects.create_user(password=password, *args, **kwargs)
        return user


class UserProfileFactory(DjangoModelFactory):
    class Meta:
        model = UserProfile

    user = SubFactory(UserFactory)


class ProviderFactory(DjangoModelFactory):
    class Meta:
        model = Provider

    userprofile = SubFactory(UserProfileFactory)
    account_status = AccountStatus.APPROVED


class ConsumerFactory(DjangoModelFactory):
    class Meta:
        model = Consumer

    userprofile = SubFactory(UserProfileFactory)
