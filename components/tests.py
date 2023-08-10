from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from accounts.models import Provider, Consumer
from utils.helpers import create_file
from .models import AutoPart
from .types import CATEGORY, CONDITION


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
            'category': CATEGORY[0][0],
            'vehicle_make': 'vehicle_make',
            'vehicle_model': 'vehicle_model',
            'vehicle_year': 'vehicle_year',
            'condition': CONDITION[0][0],
            'OEM_number': 'OEM_number',
            'UPC_number': 'UPC_number'
        }
        self.user = User.objects.create_user(username="username", password="password", email="test@test.com")
        self.provider = Provider.objects.create(user=self.user, is_provider=True, account_status="approved")
        self.other_user = User.objects.create_user(username="other_user", password="password", email="other@test.com")
        self.other_provider = Provider.objects.create(user=self.other_user, is_provider=True, account_status="approved")
        self.consumer_user = User.objects.create_user(username="consumer", password='password', email='user@test.com')
        self.consumer = Consumer.objects.create(user=self.consumer_user, is_provider=False)

    def test_unauthenticated_provider_cannot_create_auto_part(self):
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(str(response.data['detail']), 'Authentication credentials were not provided.')

    def test_provider_can_create_auto_part(self):
        response = self.client.post(reverse('login'), {"username": "username", "password": "password"}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('user', response.data)
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(AutoPart.objects.count(), 1)
        auto_part = AutoPart.objects.first()
        decimal_fields = ('price', 'weight')
        for key, value in self.auto_part_data.items():
            if key in decimal_fields:
                self.assertEqual(float(getattr(auto_part, key)), value)
            else:
                self.assertEqual(getattr(auto_part, key), value)

    def test_provider_cannot_create_auto_part_for_other_providers(self):
        response = self.client.post(reverse('login'), {"username": "username", "password": "password"}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(AutoPart.objects.count(), 1)
        self.assertNotEqual(AutoPart.objects.first().provider.userprofile_ptr_id,
                            self.other_provider.userprofile_ptr_id)

    def test_unauthenticated_provider_cannot_retrieve_auto_parts_list(self):
        response = self.client.get(reverse('auto-parts'))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(str(response.data['detail']), "Authentication credentials were not provided.")

    def test_provider_cannot_retrieve_other_providers_auto_parts_list(self):
        _ = AutoPart.objects.create(provider=self.other_provider, vehicle_make="BMW", vehicle_year="1990")
        response = self.client.post(reverse('login'), {'username': 'username', 'password': 'password'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response = self.client.get(reverse("auto-parts"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), AutoPart.objects.filter(provider=self.provider).count())

    def test_provider_can_retrieve_auto_parts_list(self):
        response = self.client.post(reverse('login'), {"username": "username", "password": "password"}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(AutoPart.objects.count(), 1)
        _ = AutoPart.objects.create(provider=self.provider, vehicle_make="BMW", vehicle_year="1990")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        response = self.client.get(reverse('auto-parts'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), AutoPart.objects.filter(provider=self.provider).count())

    def test_consumer_cannot_create_auto_part(self):
        response = self.client.post(reverse('login'), {"username": 'consumer', 'password': "password"}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Auto part creation attempt
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(str(response.data['detail']), "Only providers can access this endpoint")

    def test_consumer_cannot_retrieve_auto_parts_list(self):
        response = self.client.post(reverse('login'), {"username": 'consumer', 'password': "password"}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response = self.client.get(reverse('auto-parts'))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(str(response.data['detail']), "Only providers can access this endpoint")


class AutoPartDetailTestCases(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='user', password='password', email='test@test.com')
        self.provider = Provider.objects.create(user=self.user, is_provider=True, account_status="approved")
        self.auto_part = AutoPart.objects.create(provider=self.provider, vehicle_make="BMW", vehicle_year="1990")
        # Create another user
        self.other_user = User.objects.create_user(username="other", password="password", email="test@test.com")
        self.other_provider = Provider.objects.create(user=self.other_user, is_provider=True, account_status="approved")
        self.other_auto_part = AutoPart.objects.create(provider=self.other_provider, vehicle_year="1880")
        # Create a consumer
        self.consumer_user = User.objects.create_user(username="consumer", password='password',
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
                self.assertEqual(str(response.data['detail']), "Only owner can access this endpoint")
        elif method == 'PUT':
            response = self.client.put(reverse('auto-part-detail', args=[auto_part_id]), data, format='json')
            self.assertEqual(response.status_code, code)
            if code == status.HTTP_202_ACCEPTED:
                auto_part = AutoPart.objects.get(id=auto_part_id)
                for key, value in data.items():
                    self.assertEqual(getattr(auto_part, key), value)
            elif code == status.HTTP_403_FORBIDDEN:
                self.assertEqual(str(response.data['detail']), "Only owner can access this endpoint")

        elif method == 'DELETE':
            response = self.client.delete(reverse('auto-part-detail', args=[auto_part_id]))
            self.assertEqual(response.status_code, code)
            if code == status.HTTP_204_NO_CONTENT:
                auto_part_exists = AutoPart.objects.filter(pk=auto_part_id).exists()
                self.assertFalse(auto_part_exists)
            elif code == status.HTTP_403_FORBIDDEN:
                self.assertEqual(str(response.data['detail']), "Only owner can access this endpoint")

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
        self.assertEqual(str(response.data['detail']), "Only providers can access this endpoint")

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
        self.assertEqual(str(response.data['detail']), 'Only providers can access this endpoint')

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
        self.assertEqual(str(response.data['detail']), "Only providers can access this endpoint")


class ImageCreationTestCases(APITestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(username="username", password="password", email="test@test.com")

    def authenticate_user(self, username, password):
        return self.client.post(reverse('login'), {"username": username, "password": password}, format='json')

    def test_provider_can_upload_auto_part_image(self):
        # Authenticate the user
        provider = Provider.objects.create(user=self.user, is_provider=True, account_status="approved")
        response = self.authenticate_user("username", "password")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Upload the image
        response = self.client.post(reverse('upload-file'), {'file': create_file()}, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(AutoPart.objects.count(), 1)
        self.assertIs(AutoPart.objects.first().provider.id, provider.id)
        self.assertTrue(AutoPart.objects.first().image)

    def test_consumer_cannot_upload_auto_part_image(self):
        _ = Consumer.objects.create(user=self.user, is_provider=False)
        response = self.authenticate_user("username", "password")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Upload the image
        response = self.client.post(reverse('upload-file'), {'file': create_file()}, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(AutoPart.objects.count(), 0)

    def test_only_images_can_be_uploaded(self):
        _ = Provider.objects.create(user=self.user, is_provider=True, account_status="approved")
        response = self.authenticate_user("username", "password")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Upload JSON file
        response = self.client.post(reverse('upload-file'), {'file': create_file(".json")}, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(AutoPart.objects.count(), 0)
