import os
import tempfile
from unittest.mock import patch

from PIL import Image
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from utils.helpers import create_image
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

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

    def authenticate(self):
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
        return provider

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
        provider = self.authenticate()
        # update phone, address, first_name and last_name
        updated_data = {'user': {"first_name": "new_first", "last_name": "new_last"}, 'phone': '666 666 6666',
                        'address': 'New Address'}
        update_response = self.client.put(reverse('update_profile', args=[provider.userprofile_ptr_id]), updated_data,
                                          format='json')
        self.assertEqual(update_response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(update_response.data.get('phone'), '666 666 6666')  # check response data
        self.assertEqual(update_response.data.get('address'), 'New Address')  # check response data

        # update the provider instance and make sure that the fields are updated
        provider = Provider.objects.get(userprofile_ptr_id=provider.userprofile_ptr_id)
        self.assertNotEqual(provider.user.first_name, self.sign_up_data['user']['first_name'])
        self.assertNotEqual(provider.user.last_name, self.sign_up_data['user']['last_name'])
        self.assertNotEqual(provider.phone, self.sign_up_data['phone'])
        self.assertEqual(provider.address, "New Address")

        # make sure that the rest fields remained unchanged
        self.assertEqual(provider.user.username, self.sign_up_data['user']['username'])
        self.assertEqual(provider.user.email, self.sign_up_data['user']['email'])
        self.assertEqual(provider.is_provider, self.sign_up_data['is_provider'])

        # make sure that the password did not change by log the provider in
        login_response = self.client.post(reverse('login'), {'username': self.sign_up_data['user']['username'],
                                                             'password': self.sign_up_data['user']['password']})
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)

    def test_provider_can_update_password(self):
        provider = self.authenticate()

        # update the password
        updated_data = {'user': {"password": "pass_phrase"}}
        response = self.client.put(reverse('update_profile', args=[provider.userprofile_ptr_id]), updated_data,
                                   format='json')
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)

        # make sure that the password has updated
        login_response = self.client.post(reverse('login'), {'username': self.sign_up_data['user']['username'],
                                                             'password': 'pass_phrase'})
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)

        # make sure that other fields remained unchanged
        provider = Provider.objects.get(userprofile_ptr_id=provider.userprofile_ptr_id)
        self.assertEqual(provider.user.first_name, self.sign_up_data['user']['first_name'])
        self.assertEqual(provider.user.last_name, self.sign_up_data['user']['last_name'])
        self.assertEqual(provider.user.email, self.sign_up_data['user']['email'])
        self.assertEqual(provider.user.username, self.sign_up_data['user']['username'])
        self.assertEqual(provider.phone, self.sign_up_data['phone'])

    def test_provider_cannot_update_username_to_existed_username(self):
        # create the users
        user1 = User.objects.create_user(username="user1", password="password1", email="user1@test.com")
        user2 = User.objects.create_user(username="user2", password="password2", email="user2@test.com")
        _ = Provider.objects.create(user=user1)
        provider2 = Provider.objects.create(user=user2)

        # log the user in
        response = self.client.post(reverse('login'), {"username": "user2", "password": "password2"}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # update current username to an existed username
        response = self.client.put(reverse("update_profile", args=[provider2.userprofile_ptr_id]),
                                   {"user": {"username": "user1"}}, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], "Username is already in use")

    def test_unapproved_provider_cannot_update_account_information(self):
        provider = self.authenticate()
        provider.account_status = "pending"
        provider.save()
        response = self.client.put(reverse("update_profile", args=[provider.userprofile_ptr_id]),
                                   {"user": {"username": "updated_username"}}, format='json')

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data['detail'], "Your account is not approved yet")
        self.assertNotEqual(provider.user.username, "updated_username")

    def test_user_cannot_update_other_user_information(self):
        # create the users
        user1 = User.objects.create_user(username="user1", password="password1", email="user1@test.com")
        user2 = User.objects.create_user(username="user2", password="password2", email="user2@test.com")
        _ = Provider.objects.create(user=user1)
        provider2 = Provider.objects.create(user=user2)
        self.assertEqual(User.objects.count(), 2)
        self.assertEqual(Provider.objects.count(), 2)

        # log the user and make an update call to the other user field
        response = self.client.post(reverse('login'), {"username": "user1", "password": "password1"}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response = self.client.put(reverse('update_profile', args=[provider2.userprofile_ptr_id]),
                                   {"user": {"username": "updated_username"}}, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data['detail'], "You do not have permission to perform this action")
        provider2 = Provider.objects.get(userprofile_ptr_id=provider2.userprofile_ptr_id)
        self.assertEqual(provider2.user.username, "user2")

    def test_image_upload(self):
        user = User.objects.create_user(username="username", password="password", email="test@test.com")
        provider = Provider.objects.create(user=user, is_provider=True, account_status="approved")
        response = self.client.post(reverse('login'),
                                    {"username": "username", "password": "password"},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # create a dictionary of the form data
        data = {
            'profile_pic': create_image()
        }
        # make an update request
        response = self.client.put(reverse('file_upload', args=[provider.userprofile_ptr_id]), data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(os.path.exists("./media/test_image.jpg"))


class EmailTest(TestCase):
    @patch('sendgrid.SendGridAPIClient.send')
    def test_send_email(self, mock_send):
        # create a sample email
        message = Mail(
            from_email='partsplaza23@gmail.com',
            to_emails='med.seffah@gmail.com',
            subject='Account verification',
            html_content='<p> your account is created successfully'
        )

        # send the email
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        sg.send(message)

        # assert that the send method was called
        self.assertTrue(mock_send.called)

        # Get the args that the send method was called with
        args, kwargs = mock_send.call_args

        # Now we can make assertions about the email that was sent
        email = args[0]
        self.assertEqual(email._from_email.email, 'partsplaza23@gmail.com')
        self.assertIn("Account verification", str(email))
