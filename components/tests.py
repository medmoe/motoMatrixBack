from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from .types import CATEGORY, CONDITION
from accounts.models import Provider
from .models import AutoPart


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

    def test_pending_provider_cannot_create_parts(self):
        signup_response = self.client.post(reverse('signup'), self.provider_data, format='json')
        self.assertEqual(signup_response.status_code, status.HTTP_201_CREATED)
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
