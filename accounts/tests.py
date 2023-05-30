from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken


# Create your tests here.

class AccountsTestCases(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(username="testuser", password="testpassword")
        self.refresh = RefreshToken.for_user(self.user)
        self.access = str(self.refresh.access_token)

    def test_signup(self):
        data = {'username': 'newuser', 'password': 'newpassword'}
        response = self.client.post(reverse('signup'), data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 2)

    def test_login(self):
        response = self.client.post(reverse('login'), {'username': 'testuser', 'password': 'testpassword'})
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
