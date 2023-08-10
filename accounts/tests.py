import os
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from utils.helpers import create_file
from .models import Provider, Consumer, UserProfile


class SignUpTestCases(APITestCase):
    def setUp(self):
        self.data = {
            'user': {
                "username": "newusername",
                "password": 'newpassword',
                "email": 'test@test.com',
            },
            'is_provider': True,
        }
        self.existed_user = User.objects.create_user(username='existed_user',
                                                     password="password",
                                                     email="existed@test.com")

    def test_user_can_sign_up(self):
        response = self.client.post(reverse('signup'), self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 2)
        created_user = User.objects.get(id=response.data['user']['id'])
        self.assertEqual(created_user.username, self.data['user']['username'])
        self.assertEqual(created_user.email, self.data['user']['email'])
        self.assertNotEqual(created_user.password, self.data['user']['password'])

    def test_user_must_provide_username(self):
        self.data['user'].pop("username")
        response = self.client.post(reverse('signup'), self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(User.objects.count(), 1)

    def test_user_must_provide_email(self):
        self.data['user'].pop("email")
        response = self.client.post(reverse('signup'), self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(User.objects.count(), 1)

    def test_user_cannot_sign_up_with_an_existed_username(self):
        self.data['user']["username"] = self.existed_user.username
        response = self.client.post(reverse('signup'), self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotEqual(User.objects.count(), 2)

    def test_user_cannot_sign_up_with_an_existed_email(self):
        self.data['user']["email"] = self.existed_user.email
        response = self.client.post(reverse('signup'), self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotEqual(User.objects.count(), 2)


class LoginTestCases(APITestCase):
    def setUp(self) -> None:
        self.existed_user = User.objects.create_user(username="existed_user", password="password",
                                                     email="test@test.com")
        self.provider = Provider.objects.create(user=self.existed_user, is_provider=True, account_status="approved")

    def test_provider_can_login(self) -> None:
        response = self.client.post(reverse("login"), {"username": "existed_user", "password": "password"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # make sure that the data is returned in the response
        self.assertEqual(response.data['user']['username'], self.existed_user.username)
        self.assertEqual(response.data['user']['email'], self.existed_user.email)
        # make sure that the password is not included in the response
        self.assertNotIn("password", response.data['user'])

    def test_pending_provider_cannot_login(self):
        self.provider.account_status = "pending"
        self.provider.save(0)
        response = self.client.post(reverse("login"), {"username": "existed_user", "password": "password"})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertNotIn('user', response.data)
        self.assertEqual(response.data['detail'], "Your account is not approved yet")

    def test_consumer_can_login(self):
        another_user = User.objects.create_user(username="another_user", password="password", email="other@test.com")
        consumer = Consumer.objects.create(user=another_user, is_provider=False)
        response = self.client.post(reverse("login"),
                                    {"username": "another_user", "password": "password"},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['username'], consumer.user.username)
        self.assertEqual(response.data['user']['email'], consumer.user.email)
        self.assertEqual(response.data['user']['is_provider'], consumer.is_provider)

    def test_user_cannot_login_with_wrong_credentials(self):
        response = self.client.post(reverse('login'),
                                    {"username": "does not exist", "password": "password"},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertNotIn('user', response.data)
        self.assertEqual(response.data['detail'], "No active account found with the given credentials")


class LogoutTestCases(APITestCase):
    def setUp(self):
        self.consumer_user = User.objects.create_user(username="consumer",
                                                      password="password",
                                                      email="consumer@test.com")
        self.provider_user = User.objects.create_user(username="provider",
                                                      password="password",
                                                      email="provider@test.com")
        self.consumer = Consumer.objects.create(user=self.consumer_user, is_provider=False)
        self.provider = Provider.objects.create(user=self.provider_user, is_provider=True, account_status="approved")

    def test_consumer_can_log_out(self):
        # Authenticate the consumer first
        response = self.client.post(reverse('login'), {"username": "consumer", "password": "password"}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Logout
        response = self.client.post(reverse('logout'))
        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)

    def test_provider_can_log_out(self):
        # Authenticate the provider
        response = self.client.post(reverse('login'), {"username": "provider", "password": "password"}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Logout
        response = self.client.post(reverse('logout'))
        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)


class UpdateAccountTestCases(APITestCase):
    def setUp(self):
        self.consumer_user_one = User.objects.create_user(username="consumer1",
                                                          password="password",
                                                          email="consumer1@test.com")
        self.provider_user_one = User.objects.create_user(username="provider1",
                                                          password="password",
                                                          email="provider1@test.com")
        self.consumer_one = Consumer.objects.create(user=self.consumer_user_one, is_provider=False)
        self.provider_one = Provider.objects.create(user=self.provider_user_one,
                                                    is_provider=True,
                                                    account_status="approved")
        self.data = {
            "user": {
                "username": "updated_username",
                "email": "updated@test.com",
                "first_name": "updated_first_name",
                "last_name": "updated_last_name",
                "password": "updated_password",
            },
            "phone": "updated_phone",
            "address": "updated_address",
            "city": "updated_city",
            "country": "updated_country",
        }

    def authenticate_user_and_update_account(self, username, account, password="password"):
        response = self.client.post(reverse('login'), {"username": username, "password": password}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # update account information
        response = self.client.put(reverse('update_profile', args=[account.userprofile_ptr_id]),
                                   self.data,
                                   format='json')
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertIn('user', response.data)
        updated_account = UserProfile.objects.get(id=account.userprofile_ptr_id)
        self.assertEqual(updated_account.user.username, self.data['user']['username'])
        self.assertEqual(updated_account.user.email, self.data['user']['email'])
        self.assertEqual(updated_account.user.first_name, self.data['user']['first_name'])
        self.assertEqual(updated_account.user.last_name, self.data['user']['last_name'])
        self.assertEqual(updated_account.phone, self.data['phone'])
        self.assertEqual(updated_account.address, self.data['address'])
        self.assertEqual(updated_account.city, self.data['city'])
        self.assertEqual(updated_account.country, self.data['country'])
        # make sure that the password is updated as well
        response = self.client.post(reverse('logout'))
        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)
        # Authenticate the user
        response = self.client.post(reverse('login'),
                                    {"username": self.data['user']['username'],
                                     "password": self.data['user']['password']},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_consumer_can_update_account_information(self):
        self.authenticate_user_and_update_account(username=self.consumer_one.user.username, account=self.consumer_one)

    def test_provider_can_update_profile_information(self):
        self.authenticate_user_and_update_account(username=self.provider_one.user.username, account=self.provider_one)

    def test_user_cannot_update_username_to_existing_username(self):
        response = self.client.post(reverse('login'),
                                    {"username": self.provider_one.user.username, "password": "password"},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.data['user']['username'] = self.consumer_one.user.username
        response = self.client.put(reverse('update_profile', args=[self.provider_one.userprofile_ptr_id]),
                                   self.data,
                                   format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['user']['username'][0], "Username is already in use")

    def test_user_cannot_update_email_to_existing_email(self):
        response = self.client.post(reverse('login'),
                                    {"username": self.provider_one.user.username, "password": "password"},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.data['user']['email'] = self.consumer_one.user.email
        response = self.client.put(reverse('update_profile', args=[self.provider_one.userprofile_ptr_id]),
                                   self.data,
                                   format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(str(response.data['user']['email'][0]), "Email is already in use")

    def test_only_authenticated_users_can_do_updates(self):
        response = self.client.put(reverse('update_profile', args=[self.provider_one.userprofile_ptr_id]),
                                   self.data,
                                   format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(str(response.data['detail']), "Authentication credentials were not provided.")

    def test_user_cannot_update_other_user_account(self):
        response = self.client.post(reverse('login'),
                                    {"username": self.provider_one.user.username, "password": "password"},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response = self.client.put(reverse('update_profile', args=[self.consumer_one.userprofile_ptr_id]),
                                   self.data,
                                   format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(str(response.data['detail']), "You do not have permission to perform this action")


class FileUploadTestCases(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="user", password="password", email="user@test.com")
        self.provider = Provider.objects.create(user=self.user, is_provider=True, account_status="approved")
        self.data = {'profile_pic': create_file()}

    def uploadFile(self):
        pass

    def authenticate_and_verify_file_upload(self, code):
        response = self.client.put(reverse('file_upload', args=[self.provider.userprofile_ptr_id]),
                                   self.data,
                                   format='multipart')
        self.assertEqual(response.status_code, code)
        provider = Provider.objects.get(userprofile_ptr_id=self.provider.userprofile_ptr_id)
        self.assertFalse(provider.profile_pic)

    def test_unauthenticated_user_cannot_upload_file(self):
        self.authenticate_and_verify_file_upload(status.HTTP_401_UNAUTHORIZED)

    def test_authenticated_user_can_upload_file(self):
        response = self.client.post(reverse('login'),
                                    {"username": self.provider.user.username, "password": "password"},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response = self.client.put(reverse('file_upload', args=[self.provider.userprofile_ptr_id]),
                                   self.data,
                                   format='multipart')

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertIn('file', response.data)
        self.assertEqual(response.data['detail'], 'File uploaded successfully')
        provider = Provider.objects.get(userprofile_ptr_id=self.provider.userprofile_ptr_id)
        self.assertTrue(provider.profile_pic)

    def test_only_images_can_be_uploaded(self):
        response = self.client.post(reverse('login'),
                                    {"username": self.provider.user.username, "password": "password"},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.data = {'profile_pic': create_file(".json")}
        self.authenticate_and_verify_file_upload(status.HTTP_400_BAD_REQUEST)


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
