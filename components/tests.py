from django.contrib.auth.models import User
from django.db import models
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from accounts.models import AccountStatus
from accounts.models import Provider, Consumer
from utils.helpers import create_file
from .documents import AutoPartDocument
from .models import AutoPart, AutoPartCategories, AutoPartConditions
from .permissions import IsProvider, IsAutoPartOwner, IsProviderApproved


class AutoPartListTestCases(APITestCase):
    def setUp(self):
        self.auto_part_data = {
            'name': 'name',
            'description': 'description',
            'manufacturer': 'manufacturer',
            'price': 99.99,
            'stock': 55,
            'weight': 25.25,
            'dimensions': 'dimensions',
            'location': 'location',
            'category': AutoPartCategories.SUSPENSION.value,
            'vehicle_make': 'vehicle_make',
            'vehicle_model': 'vehicle_model',
            'vehicle_year': 'vehicle_year',
            'condition': AutoPartConditions.NEW.value,
            'oem_number': 'OEM_number',
            'upc_number': 'UPC_number'
        }
        self.user = User.objects.create_user(username="username", password="password", email="test@test.com")
        self.provider = Provider.objects.create(user=self.user,
                                                is_provider=True,
                                                account_status=AccountStatus.APPROVED.value)
        self.other_user = User.objects.create_user(username="other_user", password="password", email="other@test.com")
        self.other_provider = Provider.objects.create(user=self.other_user,
                                                      is_provider=True,
                                                      account_status=AccountStatus.APPROVED.value)
        self.consumer_user = User.objects.create_user(username="consumer", password='password', email='user@test.com')
        self.consumer = Consumer.objects.create(user=self.consumer_user, is_provider=False)

    def get_field_value(self, field, db_auto_part):
        field_name = field.name
        value = getattr(db_auto_part, field_name)
        if isinstance(field, models.ForeignKey):
            return value.id
        elif isinstance(field, models.ImageField):
            return value.url if value and hasattr(value, 'url') else None
        elif isinstance(field, models.DecimalField):
            return str(float(value)) if value is not None else None
        else:
            return value

    def compare_api_and_db_fields(self, response_auto_parts):
        db_auto_parts = AutoPart.objects.filter(provider=self.provider).order_by('name')
        response_auto_parts = sorted(response_auto_parts, key=lambda x: x['name'])
        self.assertEqual(len(db_auto_parts), len(response_auto_parts))

        for db_auto_part, response_auto_part in zip(db_auto_parts, response_auto_parts):
            for field in db_auto_part._meta.fields:
                db_field_value = self.get_field_value(field, db_auto_part)
                self.assertEqual(db_field_value, response_auto_part[field.name])

    def test_unauthenticated_provider_cannot_create_auto_part(self):
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(str(response.data['detail']), 'Authentication credentials were not provided.')

    def test_provider_can_create_auto_part(self):
        # Logging in
        response = self.client.post(reverse('login'), {"username": "username", "password": "password"}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('user', response.data)

        # Creating an auto part
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(AutoPart.objects.count(), 1)

        # Checking that the fields are updated correctly
        auto_part = AutoPart.objects.first()
        decimal_fields = ('price', 'weight')
        for key, value in self.auto_part_data.items():
            if key in decimal_fields:
                self.assertEqual(float(getattr(auto_part, key)), value)
            else:
                self.assertEqual(getattr(auto_part, key), value)

        # Checking that the provider of the auto part is the logged-in used
        self.assertEqual(auto_part.provider.user.username, self.provider.user.username)

    def test_unauthenticated_provider_cannot_retrieve_auto_parts_list(self):
        response = self.client.get(reverse('auto-parts'))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(str(response.data['detail']), "Authentication credentials were not provided.")

    def test_provider_cannot_retrieve_other_providers_auto_parts_list(self):
        # Set up
        AutoPart.objects.create(provider=self.other_provider, vehicle_make="BMW", vehicle_year="1990")
        self.client.post(reverse('login'), {'username': 'username', 'password': 'password'}, format='json')
        response = self.client.get(reverse("auto-parts"))
        # Assertions
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.compare_api_and_db_fields(response.data['results'])

    def test_provider_can_retrieve_auto_parts_list(self):
        # Logging in
        response = self.client.post(reverse('login'), {"username": "username", "password": "password"}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Create auto parts
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(AutoPart.objects.count(), 1)
        _ = AutoPart.objects.create(provider=self.provider, vehicle_make="BMW", vehicle_year="1990")

        # Retrieve auto parts
        response = self.client.get(reverse('auto-parts'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], AutoPart.objects.filter(provider=self.provider).count())
        self.compare_api_and_db_fields(response.data['results'])

    def test_consumer_cannot_create_auto_part(self):
        response = self.client.post(reverse('login'), {"username": 'consumer', 'password': "password"}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Auto part creation attempt
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(str(response.data['detail']), IsProvider.message)

    def test_consumer_cannot_retrieve_auto_parts_list(self):
        response = self.client.post(reverse('login'), {"username": 'consumer', 'password': "password"}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response = self.client.get(reverse('auto-parts'))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(str(response.data['detail']), IsProvider.message)

    def test_pagination(self):
        # Set Up
        page_size = 10
        for i in range(page_size + 5):
            AutoPart.objects.create(provider=self.provider, name=f'Part {i}')
        self.client.post(reverse('login'), {"username": "username", "password": "password"}, format='json')
        response = self.client.get(reverse('auto-parts'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for key in ('count', 'next', 'previous', 'results'):
            self.assertIn(key, response.data)
        self.assertEqual(len(response.data['results']), page_size)

    def test_custom_pagination(self):
        # Set up
        page_size = 5
        for i in range(30):
            AutoPart.objects.create(provider=self.provider, name=f'Part {i}')

        # Authenticate the user
        self.client.post(reverse('login'), {"username": "username", "password": "password"}, format='json')

        # Get auto parts
        response = self.client.get(reverse('auto-parts'), {'pageSize': page_size})

        # Assertions
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 5)

    def test_image_links_are_correctly_set(self):
        self.client.post(reverse('login'), {"username": "username", "password": "password"}, format='json')
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


class AutoPartDocumentViewTestCases(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='username', password='password')
        self.provider = Provider.objects.create(user=self.user,
                                                is_provider=True,
                                                account_status=AccountStatus.APPROVED.value)
        self.client.post(reverse('login'), {'username': 'username', 'password': 'password'}, format='json')
        self.auto_part = AutoPart.objects.create(provider=self.provider, name="Test Brake Pad")

        # Index the data to elasticsearch
        AutoPartDocument().update(self.auto_part)
        self.search_term = 'brake'

    def test_unauthenticated_user_cannot_perform_search(self):
        # Log out the user
        response = self.client.post(reverse('logout'))
        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)
        response = self.client.get(reverse('autoparts-search'), {'search': self.search_term})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(str(response.data['detail']), 'Access token is invalid or expired')

    def test_non_provider_users_cannot_perform_search(self):
        user = User.objects.create_user(username="consumer", password="password")
        Consumer.objects.create(user=user, is_provider=False)
        res = self.client.post(reverse('login'), {"username": user.username, "password": "password"}, format='json')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        # Call Search end point
        res = self.client.get(reverse('autoparts-search'), {'search': self.search_term})
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(str(res.data['detail']), IsProvider.message)

    def test_unapproved_providers_cannot_perform_search(self):
        self.provider.account_status = AccountStatus.PENDING.value
        self.provider.save()

        # Attempt to call the search endpoint
        res = self.client.get(reverse('autoparts-search'), {'search': self.search_term})
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(str(res.data['detail']), IsProviderApproved.message)

    def test_provider_can_retrieve_own_auto_parts_only(self):
        # create another provider and another auto parts associated with them which has the same search term
        other = User.objects.create_user(username='other_provider', password='password')
        provider = Provider.objects.create(user=other, is_provider=True, account_status=AccountStatus.APPROVED.value)
        auto_part = AutoPart.objects.create(provider=provider, name=self.search_term)
        AutoPartDocument().update(auto_part)  # Index the created auto part to elasticsearch
        # Log the created provider
        res = self.client.post(reverse('login'), {"username": other.username, 'password': 'password'})
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        # Attempt to search auto parts
        res = self.client.get(reverse('autoparts-search'), {'search': self.search_term})
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['count'], 1)

    def test_provider_can_search_auto_parts(self):
        response = self.client.get(reverse('autoparts-search'), {"search": self.search_term})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        auto_parts_names = [auto_part['name'] for auto_part in response.data['results']]
        self.assertEqual(response.data['count'], 1)
        self.assertIn(self.auto_part.name, auto_parts_names)
