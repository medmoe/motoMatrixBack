from django.contrib.auth.models import User
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

    def create_provider(self, is_approved=False):
        signup_response = self.client.post(reverse('signup'), self.provider_data, format='json')
        if is_approved:
            provider = Provider.objects.first()
            provider.account_status = 'approved'
            provider.save()
        self.assertEqual(signup_response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Provider.objects.count(), 1)

    def test_pending_provider_cannot_create_parts(self):
        self.create_provider()
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(AutoPart.objects.count(), 0)

    def test_approved_provider_can_create_parts(self):
        self.create_provider(is_approved=True)
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(AutoPart.objects.count(), 1)

    def test_approved_provider_can_update_parts(self):
        self.create_provider(is_approved=True)
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(AutoPart.objects.count(), 1)
        auto_part = AutoPart.objects.first()
        auto_part_data = self.auto_part_data
        auto_part_data['name'] = 'new name'
        response = self.client.put(reverse(f'auto-part-detail', kwargs={'id': auto_part.id}), auto_part_data)
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(AutoPart.objects.count(), 1)
        auto_part = AutoPart.objects.first()
        self.assertEqual(auto_part.name, 'new name')

    def test_approved_provider_can_delete_parts(self):
        self.create_provider(is_approved=True)
        response = self.client.post(reverse('auto-parts'), self.auto_part_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(AutoPart.objects.count(), 1)
        auto_part = AutoPart.objects.first()
        response = self.client.delete(reverse(f'auto-part-detail', kwargs={'id': auto_part.id}))
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(AutoPart.objects.count(), 0)
