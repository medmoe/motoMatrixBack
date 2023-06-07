from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken
from .models import UserProfile


class AccountsTestCases(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(username="testusername", password="testpassword")
        self.refresh = RefreshToken.for_user(self.user)
        self.access = str(self.refresh.access_token)
        self.sign_up_data = {
            'user': {
                'first_name': 'first_name',
                'last_name': 'last_name',
                'username': 'newusername',
                'password': 'newpassword',
                'email': 'new@test.com'
            },
            'phone': '555 555 5555',
            'is_provider': False,
        }

    def test_consumer_signup(self):
        response = self.client.post(reverse('signup'), self.sign_up_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 2)
        self.assertEqual(User.objects.get(id=2).username, 'newusername')
        self.assertEqual(User.objects.get(id=2).email, 'new@test.com')
        self.assertEqual(User.objects.get(id=2).first_name, 'first_name')
        self.assertEqual(User.objects.get(id=2).last_name, 'last_name')
        latest_profile = UserProfile.objects.order_by('-id').first()
        self.assertEqual(latest_profile.phone, '555 555 5555')
        self.assertIs(latest_profile.is_provider, False)

    def test_provider_signup(self):
        self.sign_up_data['is_provider'] = True
        response = self.client.post(reverse('signup'), self.sign_up_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 2)
        latest_profile = UserProfile.objects.order_by('-id').first()
        self.assertIs(latest_profile.is_provider, True)

    def test_duplicate_username(self):
        # First signup
        response = self.client.post(reverse('signup'), self.sign_up_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Second signup with the same data
        response = self.client.post(reverse('signup'), self.sign_up_data, format='json')
        self.assertNotEqual(response.status_code, status.HTTP_201_CREATED)

    def test_duplicate_email(self):
        # First signup
        response = self.client.post(reverse('signup'), self.sign_up_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Second signup with the same data
        self.sign_up_data['user']['username'] = 'anotherusername'
        response = self.client.post(reverse('signup'), self.sign_up_data, format='json')
        self.assertNotEqual(response.status_code, status.HTTP_201_CREATED)

    def test_login(self):
        response = self.client.post(reverse('login'), {'username': 'testusername', 'password': 'testpassword'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_refresh(self):
        response = self.client.post(reverse('refresh'), {'refresh': str(self.refresh)})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)

    def test_logout(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access)
        response = self.client.post(reverse('logout'), {'refresh_token': str(self.refresh)})
        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)
