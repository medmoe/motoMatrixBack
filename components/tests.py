import factory
from django.contrib.auth.models import User
from django.db import models
from django.urls import reverse
from django.utils.timezone import is_aware, make_naive
from rest_framework import status
from rest_framework.test import APITestCase

from accounts.authentication import AUTHENTICATION_FAILED_MESSAGES
from accounts.factories import ProviderFactory, ConsumerFactory
from accounts.models import AccountStatus
from accounts.models import Provider, Consumer
from utils.helpers import create_file
from .factories import AutoPartFactory, ComponentFactory
from .models import AutoPart, AutoPartCategories, AutoPartConditions, Component
from .permissions import IsProvider, IsAutoPartOwner, IsProviderApproved

PASSWORD = 'PASSWORD'


def initialize_users(providers_count=1, consumers_count=1):
    return {'providers': ProviderFactory.create_batch(providers_count),
            "consumers": ConsumerFactory.create_batch(consumers_count)}


def initialize_auto_parts(provider, auto_parts_count=1):
    # Create a list of components for the given provider
    components = ComponentFactory.create_batch(auto_parts_count, provider=provider)

    # Create auto parts using those components
    auto_parts = AutoPartFactory.create_batch(auto_parts_count, component=factory.Iterator(components))

    return auto_parts


class AutoPartListTestCases(APITestCase):
    def setUp(self):
        self.auto_part_data = {
            'component': {
                'name': 'name',
                'description': 'description',
                'manufacturer': 'manufacturer',
                'price': 99.99,
                'stock': 55,
                'weight': 25.25,
                'dimensions': 'dimensions',
                'location': 'location',
            },

            'category': AutoPartCategories.SUSPENSION,
            'vehicle_make': 'vehicle_make',
            'vehicle_model': 'vehicle_model',
            'vehicle_year': 'vehicle_year',
            'condition': AutoPartConditions.NEW,
            'oem_number': 'OEM_number',
            'upc_number': 'UPC_number'
        }
        users = initialize_users(2, 1)
        self.provider, self.other_provider = users['providers']
        self.consumer, = users['consumers']

    def get_field_value(self, field, db_auto_part):
        field_name = field.name
        value = getattr(db_auto_part, field_name)
        if isinstance(field, models.ForeignKey):
            return value.id
        elif isinstance(field, models.ImageField):
            return value.url if value and hasattr(value, 'url') else None
        elif isinstance(field, models.DecimalField):
            return str(float(value)) if value is not None else None
        elif isinstance(field, models.DateTimeField):
            if is_aware(value):
                value = make_naive(value)
            return value.isoformat() + "Z"
        else:
            return value

    def compare_api_and_db_fields(self, response_auto_parts):
        db_auto_parts = AutoPart.objects.filter(component__provider=self.provider).order_by('id')
        response_auto_parts = sorted(response_auto_parts, key=lambda x: x['id'])
        self.assertEqual(len(db_auto_parts), len(response_auto_parts))

        failed_assertions = []

        for db_auto_part, response_auto_part in zip(db_auto_parts, response_auto_parts):
            discrepancies = self.compare_fields(db_auto_part, response_auto_part)
            failed_assertions.extend(discrepancies)

        self.assertEqual(len(failed_assertions), 0, f"Fields with mismatches: {', '.join(failed_assertions)}")

    def compare_fields(self, db_instance, response_data, prefix=''):
        discrepancies = []

        if not isinstance(response_data, dict):
            discrepancies.append(f"{prefix}(Expected a dictionary but got {type(response_data)})")
            return discrepancies

        for field in db_instance._meta.fields:
            field_name = field.name
            db_value = getattr(db_instance, field_name)

            # Check if the field is a ForeignKey (might return as ID in the response)
            if isinstance(field, models.ForeignKey):
                db_value = db_value.id

            if field_name in response_data:
                # Handling nested relationships
                if isinstance(db_value, models.Model):
                    nested_discrepancies = self.compare_fields(db_value, response_data.get(field_name, {}),
                                                               f"{prefix}{field_name}.")
                    discrepancies.extend(nested_discrepancies)
                else:
                    if str(db_value) != str(response_data[field_name]):
                        discrepancies.append(f"{prefix}{field_name}")
            else:
                discrepancies.append(f"{prefix}{field_name} (missing in response)")
        return discrepancies

    def authenticate_user(self, username):
        response = self.client.post(reverse('login'), {"username": username, "password": "password"}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_failed_auto_part_creation_with_unauthenticated_account(self):
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn(str(response.data['detail']), AUTHENTICATION_FAILED_MESSAGES)

    def test_failed_auto_part_creation_with_invalid_data(self):
        self.authenticate_user(self.provider.userprofile.user.username)

        # corrupt the data
        self.auto_part_data['component']['price'] = "Invalid input"

        # Attempt to create auto part
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(AutoPart.objects.count())
        self.assertFalse(Component.objects.count())

    def test_successful_auto_part_creation_with_provider_account(self):
        self.authenticate_user(self.provider.userprofile.user.username)
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(AutoPart.objects.count(), 1)

        # Checking that the fields are updated correctly
        auto_part = AutoPart.objects.first()
        decimal_fields = ('price', 'weight')
        component_data = self.auto_part_data['component']
        for attr, value in component_data.items():
            if attr in decimal_fields:
                self.assertEqual(float(getattr(auto_part.component, attr)), value)
            else:
                self.assertEqual(getattr(auto_part.component, attr), value)

        for attr, value in self.auto_part_data.items():
            if attr == 'component':
                continue
            self.assertEqual(getattr(auto_part, attr), value)

        # Checking that the provider of the auto part is the logged-in used
        username = auto_part.component.provider.userprofile.user.username
        self.assertEqual(username, self.provider.userprofile.user.username)

    def test_failed_auto_parts_retrieval_with_unauthenticated_provider(self):
        response = self.client.get(reverse('auto-parts'))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn(str(response.data['detail']), AUTHENTICATION_FAILED_MESSAGES)

    def test_failed_auto_parts_retrieval_of_non_owned_parts(self):
        initialize_auto_parts(self.other_provider, 10)  # arbitrary number
        self.authenticate_user(self.provider.userprofile.user.username)
        response = self.client.get(reverse("auto-parts"))
        # Assertions
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.compare_api_and_db_fields(response.data['results'])

    def test_successful_auto_parts_retrieval_with_provider_account(self):
        self.authenticate_user(self.provider.userprofile.user.username)
        initialize_auto_parts(self.provider, 10)  # Arbitrary number

        # Retrieve auto parts
        response = self.client.get(reverse('auto-parts'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], AutoPart.objects.filter(component__provider=self.provider).count())
        self.compare_api_and_db_fields(response.data['results'])

    def test_failed_auto_parts_creation_with_consumer_account(self):
        self.authenticate_user(self.consumer.userprofile.user.username)

        # Auto part creation attempt
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(str(response.data['detail']), IsProvider.message)

    def test_failed_auto_parts_retrieval_with_consumer_account(self):
        self.authenticate_user(self.consumer.userprofile.user.username)
        response = self.client.get(reverse('auto-parts'))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(str(response.data['detail']), IsProvider.message)

    def test_pagination_returns_correct_page_size(self):
        page_size = 10
        initialize_auto_parts(self.provider, 50)  # Arbitrary number
        self.authenticate_user(self.provider.userprofile.user.username)
        response = self.client.get(reverse('auto-parts'), {'pageSize': page_size})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for key in ('count', 'next', 'previous', 'results'):
            self.assertIn(key, response.data)
        self.assertEqual(len(response.data['results']), page_size)

    def test_pagination_respects_custom_page_size_query_param(self):
        # Set up
        page_size = 5
        initialize_auto_parts(self.provider, 50)  # Arbitrary number
        self.authenticate_user(self.provider.userprofile.user.username)
        response = self.client.get(reverse('auto-parts'), {'pageSize': page_size})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 5)

    def test_image_links_are_correctly_set(self):
        self.authenticate_user(self.provider.userprofile.user.username)
        AutoPart.objects.create(provider=self.provider, image=create_file(), name="test")
        response = self.client.get(reverse('auto-parts'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('image', response.data['results'][0])
        self.assertTrue(response.data['results'][0]['image'].startswith('http'))


class AutoPartDetailTestCases(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='user', password='password', email='test@test.com')
        self.provider = Provider.objects.create(user=self.user,
                                                is_provider=True,
                                                account_status=AccountStatus.APPROVED.value)
        self.auto_part = AutoPart.objects.create(provider=self.provider, vehicle_make="BMW", vehicle_year="1990")

        # Create another user
        self.other_user = User.objects.create_user(username="other", password="password", email="test@test.com")
        self.other_provider = Provider.objects.create(user=self.other_user,
                                                      is_provider=True,
                                                      account_status=AccountStatus.APPROVED.value)
        self.other_auto_part = AutoPart.objects.create(provider=self.other_provider, vehicle_year="1880")

        # Create a consumer
        self.consumer_user = User.objects.create_user(username="consumer",
                                                      password='password',
                                                      email='consumer@test.com')
        self.consumer = Consumer.objects.create(user=self.consumer_user, is_provider=False)

    def authenticate_user_and_make_api_request(self,
                                               auto_part_id,
                                               code,
                                               data=None,
                                               method="GET",
                                               username='user',
                                               password='password'):
        response = self.client.post(reverse('login'), {'username': username, 'password': password}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        if method == 'GET':
            response = self.client.get(reverse('auto-part-detail', args=[auto_part_id]))
            self.assertEqual(response.status_code, code)
            if code == status.HTTP_200_OK:
                auto_part = AutoPart.objects.get(id=auto_part_id)
                self.assertEqual(response.data['vehicle_make'], auto_part.vehicle_make)
                self.assertEqual(response.data['vehicle_year'], auto_part.vehicle_year)
                self.assertEqual(response.data['provider'], self.auto_part.provider.id)
            elif code == status.HTTP_403_FORBIDDEN:
                self.assertEqual(str(response.data['detail']), IsAutoPartOwner.message)
        elif method == 'PUT':
            response = self.client.put(reverse('auto-part-detail', args=[auto_part_id]), data, format='json')
            self.assertEqual(response.status_code, code)
            if code == status.HTTP_202_ACCEPTED:
                auto_part = AutoPart.objects.get(id=auto_part_id)
                for key, value in data.items():
                    self.assertEqual(getattr(auto_part, key), value)
            elif code == status.HTTP_403_FORBIDDEN:
                self.assertEqual(str(response.data['detail']), IsAutoPartOwner.message)

        elif method == 'DELETE':
            response = self.client.delete(reverse('auto-part-detail', args=[auto_part_id]))
            self.assertEqual(response.status_code, code)
            if code == status.HTTP_204_NO_CONTENT:
                auto_part_exists = AutoPart.objects.filter(pk=auto_part_id).exists()
                self.assertFalse(auto_part_exists)
            elif code == status.HTTP_403_FORBIDDEN:
                self.assertEqual(str(response.data['detail']), IsAutoPartOwner.message)

    def test_unauthenticated_provider_cannot_get_auto_part(self):
        response = self.client.get(reverse('auto-part-detail', args=[self.auto_part.id]))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(str(response.data['detail']), "Authentication credentials were not provided.")

    def test_provider_can_get_auto_part(self):
        self.authenticate_user_and_make_api_request(self.auto_part.id, status.HTTP_200_OK)

    def test_provider_cannot_get_other_providers_auto_part(self):
        self.authenticate_user_and_make_api_request(self.other_auto_part.id, status.HTTP_403_FORBIDDEN)

    def test_consumer_cannot_get_providers_auto_part(self):
        response = self.client.post(reverse('login'), {'username': 'consumer', 'password': 'password'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response = self.client.get(reverse('auto-part-detail', args=[self.auto_part.id]))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(str(response.data['detail']), IsProvider.message)

    def test_unauthenticated_provider_cannot_update_auto_part(self):
        data = {'vehicle_make': 'Benz'}
        response = self.client.put(reverse('auto-part-detail', args=[self.auto_part.id]), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(str(response.data['detail']), "Authentication credentials were not provided.")

    def test_provider_can_update_auto_part(self):
        self.authenticate_user_and_make_api_request(self.auto_part.id,
                                                    status.HTTP_202_ACCEPTED,
                                                    {'vehicle_make': 'Benz'},
                                                    method="PUT")

    def test_provider_cannot_update_other_providers_auto_part(self):
        self.authenticate_user_and_make_api_request(self.other_auto_part.id,
                                                    status.HTTP_403_FORBIDDEN,
                                                    {'vehicle_make': 'Benz'},
                                                    method="PUT")

    def test_consumer_cannot_update_auto_part(self):
        response = self.client.post(reverse('login'), {'username': 'consumer', 'password': 'password'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = {'vehicle_make': 'Benz'}
        response = self.client.put(reverse('auto-part-detail', args=[self.auto_part.id]), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(str(response.data['detail']), IsProvider.message)

    def test_unauthenticated_provider_cannot_delete_auto_part(self):
        response = self.client.delete(reverse('auto-part-detail', args=[self.auto_part.id]))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(str(response.data['detail']), 'Authentication credentials were not provided.')

    def test_provider_can_delete_auto_part(self):
        self.authenticate_user_and_make_api_request(self.auto_part.id,
                                                    status.HTTP_204_NO_CONTENT,
                                                    method="DELETE")

    def test_provider_cannot_delete_other_providers_auto_part(self):
        self.authenticate_user_and_make_api_request(self.other_auto_part.id,
                                                    status.HTTP_403_FORBIDDEN,
                                                    method="DELETE")

    def test_consumer_cannot_delete_auto_part(self):
        response = self.client.post(reverse('login'), {'username': 'consumer', 'password': 'password'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response = self.client.delete(reverse('auto-part-detail', args=[self.auto_part.id]))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(str(response.data['detail']), IsProvider.message)


class ImageCreationTestCases(APITestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(username="username", password="password", email="test@test.com")

    def authenticate_user(self, username, password):
        return self.client.post(reverse('login'), {"username": username, "password": password}, format='json')

    def test_provider_can_upload_auto_part_image(self):
        # Authenticate the provider
        provider = Provider.objects.create(user=self.user,
                                           is_provider=True,
                                           account_status=AccountStatus.APPROVED.value)
        response = self.authenticate_user("username", "password")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Upload the image
        response = self.client.post(reverse('upload-file'), {'file': create_file()}, format='multipart')

        # Assertions
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(AutoPart.objects.count(), 1)
        self.assertIs(AutoPart.objects.first().provider.id, provider.id)
        self.assertTrue(AutoPart.objects.first().image)

    def test_consumer_cannot_upload_auto_part_image(self):
        Consumer.objects.create(user=self.user, is_provider=False)
        response = self.authenticate_user("username", "password")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Upload the image
        response = self.client.post(reverse('upload-file'), {'file': create_file()}, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(str(response.data['detail']), IsProvider.message)
        self.assertEqual(AutoPart.objects.count(), 0)

    def test_only_images_can_be_uploaded(self):
        Provider.objects.create(user=self.user, is_provider=True, account_status=AccountStatus.APPROVED.value)
        response = self.authenticate_user("username", "password")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Upload JSON file
        response = self.client.post(reverse('upload-file'), {'file': create_file(".json")}, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(AutoPart.objects.count(), 0)


class AutoPartSearchViewTestCases(APITestCase):
    def setUp(self):
        self.search_term = 'brake'

    def create_and_authenticate_user(self, **kwargs):
        username = kwargs.pop("username", None)
        email = kwargs.pop("email", None)
        is_provider = kwargs.pop("is_provider", None)
        user = User.objects.create_user(username=username, email=email, password=PASSWORD)
        if is_provider:
            account = Provider.objects.create(user=user, is_provider=True, **kwargs)
        else:
            account = Consumer.objects.create(user=user, **kwargs)
        # Authenticate the user
        response = self.client.post(reverse('login'), {"username": username, "password": PASSWORD}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        return account

    def create_auto_parts(self, provider, auto_parts=1, unknown_auto_parts=10, **kwargs):
        """
        Creates auto parts.

        Arguments:
            - provider: The provider associated with the auto parts.
            - auto_parts: The number of auto parts to create with the provided kwargs.
            - unknown_auto_parts: The number of auto parts to create with the name "Unknown".

        Returns:
            List of created AutoPart objects.
        """
        if not isinstance(provider, Provider):
            raise ValueError(f"Expected 'provider' to be an instance of Provider, got {type(provider)}")

        auto_parts_objects = [AutoPart(provider=provider, **kwargs) for _ in range(auto_parts)]
        auto_parts_objects.extend([AutoPart(provider=provider, name="Unknown") for _ in range(unknown_auto_parts)])
        created_auto_parts = AutoPart.objects.bulk_create(auto_parts_objects)

        return created_auto_parts

    def test_unauthenticated_user_cannot_perform_search(self):
        response = self.client.get(reverse('autoparts-search'), {'search': self.search_term})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn(str(response.data['detail']), AUTHENTICATION_FAILED_MESSAGES)

    def test_non_provider_users_cannot_perform_search(self):
        self.create_and_authenticate_user(username="username", email="test@test.com")
        res = self.client.get(reverse('autoparts-search'), {'search': self.search_term})
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(str(res.data['detail']), IsProvider.message)

    def test_unapproved_providers_cannot_perform_search(self):
        account = self.create_and_authenticate_user(username="unapproved", is_provider=True,
                                                    account_status=AccountStatus.APPROVED.value)
        account.account_status = AccountStatus.PENDING.value,
        account.save()
        # Attempt to call the search endpoint
        res = self.client.get(reverse('autoparts-search'), {'search': self.search_term})
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(str(res.data['detail']), IsProviderApproved.message)

    def test_provider_can_retrieve_own_auto_parts_only(self):
        # create another provider and another auto parts associated with them which has the same search term
        other_provider = self.create_and_authenticate_user(username='other_provider',
                                                           is_provider=True,
                                                           account_status=AccountStatus.APPROVED.value)
        self.create_auto_parts(other_provider, name=self.search_term)
        # now we create the provider to perform the search
        provider = self.create_and_authenticate_user(username="provider",
                                                     is_provider=True,
                                                     account_status=AccountStatus.APPROVED.value)

        self.create_auto_parts(provider, name=self.search_term)
        # Attempt to search auto parts
        res = self.client.get(reverse('autoparts-search'), {'search': self.search_term})
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['count'], 1)
        auto_part = res.data['results'][0]
        self.assertEqual(auto_part['provider'], provider.userprofile_ptr_id)
        self.assertEqual(auto_part['name'], self.search_term)

    def test_provider_can_search_auto_parts(self):
        provider = self.create_and_authenticate_user(username="provider",
                                                     is_provider=True,
                                                     account_status=AccountStatus.APPROVED.value)
        self.create_auto_parts(provider, auto_parts=10, name=self.search_term)
        self.assertEqual(AutoPart.objects.filter(name=self.search_term).count(), 10)
        response = self.client.get(reverse('autoparts-search'), {"search": self.search_term})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 10)  # that's the number of auto parts we created with 'search_term'
        for auto_part in response.data['results']:
            self.assertEqual(auto_part['name'], self.search_term)
