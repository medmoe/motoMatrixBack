import tempfile

from PIL import Image
from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework import status
from rest_framework.exceptions import ErrorDetail
from rest_framework.test import APITestCase
from utils.helpers import create_file
from accounts.models import Provider, Consumer
from .models import AutoPart
from .types import CATEGORY, CONDITION


class AutoPartTestCases(APITestCase):
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
        self.provider_data = {
            'user': {
                'first_name': 'first_name',
                'last_name': 'last_name',
                'username': 'newUsername',
                'password': 'newPassword',
                'email': 'test@test.com',
            },
            'phone_number': 'phone_number',
            'is_provider': True,
        }
        self.user = User.objects.create(
            first_name='first_name',
            last_name='last_name',
            username='username',
            password='password',
            email='test@test.com'
        )
        self.other_provider = Provider.objects.create(
            user=self.user,
            phone='phone_number',
            is_provider=self.provider_data['is_provider'],
            account_status='approved'
        )
        self.user2 = User.objects.create(
            first_name='first_name2',
            last_name='last_name2',
            username='username2',
            password='password2',
            email='test1@test.com'
        )
        self.other_provider2 = Provider.objects.create(
            user=self.user2,
            phone='phone_number2',
            is_provider=self.provider_data['is_provider']
        )

    def create_auto_part(self, user):
        self.client.force_authenticate(user=user)
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(AutoPart.objects.count(), 1)
        return AutoPart.objects.first()

    def update_auto_part(self, auto_part, user, new_name):
        self.client.force_authenticate(user=user)
        auto_part_data = self.auto_part_data
        auto_part_data['name'] = new_name
        response = self.client.put(reverse('auto-part-detail', args=[auto_part.id]), auto_part_data, format='json')
        return response

    def test_pending_provider_cannot_create_parts(self):
        self.client.force_authenticate(user=self.user2)
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data[0], ErrorDetail(string='Your account is not approved yet', code='invalid'))
        self.assertEqual(AutoPart.objects.count(), 0)

    def test_approved_provider_can_create_parts(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(AutoPart.objects.count(), 1)

    def test_approved_provider_can_retrieve_parts_and_only_see_their_parts(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(AutoPart.objects.count(), 1)
        self.client.force_authenticate(user=self.user2)
        response = self.client.get(reverse('auto-parts'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 0)
        self.client.force_authenticate(user=self.user)
        response = self.client.get(reverse('auto-parts'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_approved_provider_can_update_part_info(self):
        auto_part = self.create_auto_part(user=self.user)
        response = self.update_auto_part(auto_part, user=self.user, new_name='new name')
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(AutoPart.objects.count(), 1)
        self.assertEqual(AutoPart.objects.get().name, 'new name')

    def test_approved_provider_can_delete_part(self):
        auto_part = self.create_auto_part(user=self.user)
        response = self.client.delete(reverse('auto-part-detail', args=[auto_part.id]))
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(AutoPart.objects.count(), 0)

    def test_approved_provider_cannot_delete_other_provider_part(self):
        auto_part = self.create_auto_part(user=self.user)
        self.client.force_authenticate(user=self.user2)
        response = self.client.delete(reverse('auto-part-detail', args=[auto_part.id]))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(AutoPart.objects.count(), 1)

    def test_approved_provider_cannot_update_other_provider_part(self):
        auto_part = self.create_auto_part(user=self.user)
        response = self.update_auto_part(auto_part, user=self.user2, new_name='new name')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(AutoPart.objects.count(), 1)
        self.assertEqual(AutoPart.objects.get().name, 'name')

    def test_approved_provider_cannot_get_other_provider_part(self):
        auto_part = self.create_auto_part(user=self.user)
        self.client.force_authenticate(user=self.user2)
        response = self.client.get(reverse('auto-part-detail', args=[auto_part.id]))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(AutoPart.objects.count(), 1)
        self.assertEqual(AutoPart.objects.get().name, 'name')


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

    def test_unapproved_provider_cannot_upload_auto_part_image(self):
        _ = Provider.objects.create(user=self.user, is_provider=True, account_status="pending")
        response = self.authenticate_user("username", "password")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        # Upload the image
        response = self.client.post(reverse('upload-file'), {'file': create_file()}, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertNotEqual(AutoPart.objects.count(), 1)

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
