from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

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
        self.sign_in_data = {
            'username': 'newusername',
            'password': 'newpassword'
        }

    def sign_up(self, is_provider=False, login=True):
        self.sign_up_data['is_provider'] = is_provider
        response = self.client.post(reverse('signup'), self.sign_up_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # login
        if login:
            response = self.client.post(reverse('login'), self.sign_in_data)
            if not is_provider:
                self.assertEqual(response.status_code, status.HTTP_200_OK)
                self.assertIn('access', response.data)
                self.assertIn('refresh', response.data)
            return response
        return response

    def test_consumer_signup(self):
        response = self.client.post(reverse('signup'), self.sign_up_data, format='json')
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

        # Second signup with the same username
        self.sign_up_data['user']['email'] = 'another@email.co'
        response = self.client.post(reverse('signup'), self.sign_up_data, format='json')
        self.assertNotEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data[0], "Username already exists")

    def test_duplicate_email(self):
        # First signup
        response = self.client.post(reverse('signup'), self.sign_up_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Second signup with the same data
        self.sign_up_data['user']['username'] = 'anotherusername'
        response = self.client.post(reverse('signup'), self.sign_up_data, format='json')
        self.assertNotEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data[0], "Email already exists")

    def test_provider_login(self):
        response = self.sign_up(is_provider=True)
        self.assertEqual(response.data['detail'], 'Your account is not approved yet')

    def test_logout(self):
        # signup
        response = self.sign_up()
        self.client.cookies['refresh'] = response.data['refresh']
        logout_response = self.client.post(reverse('logout'))
        self.assertEqual(logout_response.status_code, status.HTTP_205_RESET_CONTENT)

    def test_logout_fail_on_wrong_refresh_token(self):
        # signup
        _ = self.sign_up()
        # set token to the client as a cookie
        self.client.cookies['refresh'] = "wrongrefresh"
        logout_response = self.client.post(reverse('logout'))
        self.assertEqual(logout_response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_fail_on_wrong_credentials(self):
        # signup
        _ = self.sign_up(login=False)
        # login
        login_response = self.client.post(reverse('login'), {'username': 'newusername', 'password': 'wrongpassword'})
        self.assertEqual(login_response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(login_response.data['detail'], 'No active account found with the given credentials')

    def test_login_fail_on_user_does_not_exist(self):
        # login
        login_response = self.client.post(reverse('login'), {'username': 'newusername', 'password': 'wrongpassword'})
        self.assertEqual(login_response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(login_response.data['detail'], 'No active account found with the given credentials')

    def test_refresh_tokens(self):
        # signup
        response = self.sign_up()
        # added refresh and access token to the client cookie
        self.client.cookies['refresh'] = response.data['refresh']
        self.client.cookies['access'] = response.data['access']
        # refresh
        refresh_response = self.client.post(reverse('refresh'))
        self.assertEqual(refresh_response.status_code, status.HTTP_200_OK)
        self.assertIn('access', refresh_response.data)
        self.assertNotEquals(refresh_response.data['access'], response.data['access'])

    def test_provider_can_update_profile_information(self):
        _ = self.sign_up(is_provider=True, login=False)
        # activate the provider's account
        provider = Provider.objects.first()
        provider.account_status = 'approved'
        provider.save()
        # log the provider in
        login_response = self.client.post(reverse('login'), {'username': 'newusername', 'password': 'newpassword'})
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        self.assertIn("user", login_response.data)
        self.assertIn("dashboard", login_response.data)

        # update the phone number and address
        updated_data = self.sign_up_data
        updated_data['phone'] = '666 666 6666'
        updated_data['address'] = 'New Address'
        update_response = self.client.put(
            reverse('update_profile', args=[provider.userprofile_ptr_id]),
            updated_data,
            format='json')

        self.assertEqual(update_response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(update_response.data.get('phone'), '666 666 6666')  # check response data
        self.assertEqual(update_response.data.get('address'), 'New Address')  # check response data

        # update the provider instance
        provider = Provider.objects.first()
        self.assertEqual(provider.phone, '666 666 6666')
        self.assertEqual(provider.address, 'New Address')

    def test_provider_cannot_update_other_users_information(self):
        # let's register the user
        _ = self.sign_up(is_provider=True, login=False)
        self.sign_up_data['user']['username'] = 'another_user'
        self.sign_up_data['user']['password'] = 'another_password'
        self.sign_up_data['user']['email'] = 'another_email@test.com'
        _ = self.sign_up(is_provider=True, login=False)
        self.assertEqual(Provider.objects.count(), 2)
        # Approve the providers
        first = Provider.objects.first()
        second = Provider.objects.last()
        first.account_status = 'approved'
        second.account_status = 'approved'
        first.save()
        second.save()

        # log the user in
        login_response = self.client.post(reverse('login'), {'username': 'newusername', 'password': 'newpassword'})
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)

        # update other user's information
        updated_data = self.sign_up_data
        updated_data['phone'] = '777 777 7777'
        updated_data['address'] = 'another address'
        update_response = self.client.put(
            reverse('update_profile', args=[second.userprofile_ptr_id]),
            updated_data,
            format='json')
        self.assertEqual(update_response.status_code, status.HTTP_403_FORBIDDEN)

        # update user instance
        second = Provider.objects.last()
        self.assertNotEqual(second.phone, '777 777 7777')
        self.assertNotEqual(second.address, 'another address')
