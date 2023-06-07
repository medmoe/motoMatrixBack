from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken
from .models import UserProfile, Provider


class AccountsTestCases(APITestCase):

    def setUp(self):
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

    def sign_up(self, is_provider=False):
        self.sign_up_data['is_provider'] = is_provider
        response = self.client.post(reverse('signup'), self.sign_up_data, format='json')
        return response

    def test_consumer_signup(self):
        response = self.sign_up()
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 1)
        latest_profile = UserProfile.objects.order_by('-id').first()
        self.assertIs(latest_profile.is_provider, False)
        self.assertEqual(latest_profile.user.first_name, self.sign_up_data['user']['first_name'])
        self.assertEqual(latest_profile.user.last_name, self.sign_up_data['user']['last_name'])
        self.assertEqual(latest_profile.user.username, self.sign_up_data['user']['username'])
        self.assertEqual(latest_profile.user.email, self.sign_up_data['user']['email'])
        self.assertEqual(latest_profile.phone, self.sign_up_data['phone'])

    def test_provider_signup(self):
        self.sign_up_data['is_provider'] = True
        response = self.client.post(reverse('signup'), self.sign_up_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 1)
        latest_profile = UserProfile.objects.order_by('-id').first()
        self.assertIs(latest_profile.is_provider, True)
        provider = Provider.objects.get(userprofile_ptr_id=latest_profile.id)
        self.assertEqual(provider.account_status, 'pending')

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

    def test_consumer_login(self):
        # signup
        response = self.sign_up()
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # login
        response = self.client.post(reverse('login'), {'username': 'newusername', 'password': 'newpassword'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_provider_login(self):
        response = self.sign_up(is_provider=True)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        response = self.client.post(reverse('login'), {'username': 'newusername', 'password': 'newpassword'})
        self.assertNotEquals(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['detail'], 'Your account is not approved yet')

    def test_refresh_tokens(self):
        # signup
        signup_response = self.sign_up()
        self.assertEqual(signup_response.status_code, status.HTTP_201_CREATED)
        # login
        login_response = self.client.post(reverse('login'), {'username': 'newusername', 'password': 'newpassword'})
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        self.assertIn('access', login_response.data)
        self.assertIn('refresh', login_response.data)
        # refresh
        refresh_response = self.client.post(reverse('refresh'), {'refresh': login_response.data['refresh']})
        self.assertEqual(refresh_response.status_code, status.HTTP_200_OK)
        self.assertIn('access', refresh_response.data)
        self.assertNotEquals(refresh_response.data['access'], login_response.data['access'])

    def test_logout(self):
        # signup
        signup_response = self.sign_up()
        self.assertEqual(signup_response.status_code, status.HTTP_201_CREATED)
        # login
        login_response = self.client.post(reverse('login'), {'username': 'newusername', 'password': 'newpassword'})
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        self.assertIn('access', login_response.data)
        self.assertIn('refresh', login_response.data)

        # set token to the client
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + login_response.data['access'])

        logout_response = self.client.post(reverse('logout'), {'refresh': login_response.data['refresh']})
        self.assertEqual(logout_response.status_code, status.HTTP_205_RESET_CONTENT)
        # refresh
        refresh_response = self.client.post(reverse('refresh'), {'refresh': login_response.data['refresh']})
        self.assertEqual(refresh_response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_fail_on_wrong_refresh_token(self):
        # signup
        signup_response = self.sign_up()
        self.assertEqual(signup_response.status_code, status.HTTP_201_CREATED)
        # login
        login_response = self.client.post(reverse('login'), {'username': 'newusername', 'password': 'newpassword'})
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        self.assertIn('access', login_response.data)
        self.assertIn('refresh', login_response.data)

        # set token to the client
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + login_response.data['access'])

        logout_response = self.client.post(reverse('logout'), {'refresh': 'wrongrefresh'})
        self.assertEqual(logout_response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_fail_on_wrong_credentials(self):
        # signup
        signup_response = self.sign_up()
        self.assertEqual(signup_response.status_code, status.HTTP_201_CREATED)
        # login
        login_response = self.client.post(reverse('login'), {'username': 'newusername', 'password': 'wrongpassword'})
        self.assertEqual(login_response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(login_response.data['detail'], 'No active account found with the given credentials')

    def test_login_fail_on_user_does_not_exist(self):
        # login
        login_response = self.client.post(reverse('login'), {'username': 'newusername', 'password': 'wrongpassword'})
        self.assertEqual(login_response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(login_response.data['detail'], 'No active account found with the given credentials')