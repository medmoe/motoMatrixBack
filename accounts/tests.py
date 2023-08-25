import os
from threading import Lock
from unittest import skip
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from rest_framework.status import \
    HTTP_201_CREATED, \
    HTTP_400_BAD_REQUEST, \
    HTTP_403_FORBIDDEN, \
    HTTP_200_OK, \
    HTTP_401_UNAUTHORIZED, \
    HTTP_205_RESET_CONTENT
from rest_framework.test import APITestCase, APITransactionTestCase
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from accounts.authentication import AUTHENTICATION_FAILED_MESSAGES
from utils.helpers import create_file
from .models import Provider, Consumer, AccountStatus, UserProfile
from .permissions import IsAccountOwner
from .serializers import ACCOUNT_STATUS_ERROR, AUTHENTICATION_ERROR


class SignUpTestCases(APITransactionTestCase):
    def setUp(self):
        self.data = {
            'is_provider': True,
            'userprofile': {
                'user': {
                    "username": "newusername",
                    "password": 'newpassword',
                    "email": 'test@test.com',
                },
            }

        }
        self.existed_user = User.objects.create_user(username='existed_user',
                                                     password="password",
                                                     email="existed@test.com")
        self.initial_user_count = User.objects.count()

    def attempt_registration_and_assert_failure(self, data):
        response = self.client.post(reverse('signup'), data, format='json')
        self.assertEqual(response.status_code, HTTP_400_BAD_REQUEST)
        self.assertEqual(User.objects.count(), self.initial_user_count)

    def test_new_user_registration_is_successful(self):
        response = self.client.post(reverse('signup'), self.data, format='json')
        self.assertEqual(response.status_code, HTTP_201_CREATED)
        self.assertNotEqual(User.objects.count(), self.initial_user_count)
        created_user = User.objects.get(id=response.data['userprofile']['user']['id'])
        self.assertEqual(created_user.username, self.data['userprofile']['user']['username'])
        self.assertEqual(created_user.email, self.data['userprofile']['user']['email'])
        self.assertNotEqual(created_user.password, self.data['userprofile']['user']['password'])

    def test_registration_fails_without_username(self):
        self.data['userprofile']['user'].pop("username")
        self.attempt_registration_and_assert_failure(self.data)

    def test_registration_fails_without_email(self):
        self.data['userprofile']['user'].pop("email")
        self.attempt_registration_and_assert_failure(self.data)

    def test_registration_fails_with_existing_username(self):
        self.data['userprofile']['user']["username"] = self.existed_user.username
        self.attempt_registration_and_assert_failure(self.data)

    def test_registration_fails_with_existing_email(self):
        self.data['userprofile']['user']["email"] = self.existed_user.email
        self.attempt_registration_and_assert_failure(self.data)

    def test_registration_fails_with_invalid_email(self):
        self.data['userprofile']['user']['email'] = "invalid_email"
        self.attempt_registration_and_assert_failure(self.data)

    def test_new_provider_cannot_login_due_to_account_status(self):
        # Sign up the user
        response = self.client.post(reverse('signup'), self.data, format='json')
        self.assertEqual(response.status_code, HTTP_201_CREATED)
        self.assertNotEqual(User.objects.count(), self.initial_user_count)

        # Sign the user in
        login_data = {"username": self.data['userprofile']['user']['username'],
                      "password": self.data['userprofile']['user']['password']}
        response = self.client.post(reverse('login'), login_data, format='json')
        self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
        self.assertEqual(str(response.data['detail']), ACCOUNT_STATUS_ERROR)


class LoginTestCases(APITestCase):
    def setUp(self) -> None:
        self.existed_user = User.objects.create_user(username="existed_user", password="password",
                                                     email="test@test.com")
        self.userprofile = UserProfile.objects.create(user=self.existed_user)
        self.provider = Provider.objects.create(userprofile=self.userprofile,
                                                account_status=AccountStatus.APPROVED)

    def test_provider_login_is_successful(self) -> None:
        response = self.client.post(reverse("login"), {"username": self.existed_user.username, "password": "password"})
        self.assertEqual(response.status_code, HTTP_200_OK)
        # make sure that the data is returned in the response
        self.assertEqual(response.data['userprofile']['user']['username'], self.existed_user.username)
        self.assertEqual(response.data['userprofile']['user']['email'], self.existed_user.email)
        # make sure that the password is not included in the response
        self.assertNotIn("password", response.data['userprofile']['user'])
        # make sure that the access and refresh tokens are embedded in the cookies
        for key in ('refresh', 'access'):
            self.assertIn(key, response.cookies)

    def test_provider_login_fails_with_pending_account(self):
        self.provider.account_status = AccountStatus.PENDING
        self.provider.save()
        response = self.client.post(reverse("login"), {"username": self.existed_user.username, "password": "password"})
        self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
        self.assertEqual(str(response.data['detail']), ACCOUNT_STATUS_ERROR)
        for key in ('refresh', 'access'):
            self.assertNotIn(key, response.cookies)

    def test_consumer_can_login(self):
        another_user = User.objects.create_user(username="another_user", password="password", email="other@test.com")
        another_userprofile = UserProfile.objects.create(user=another_user)
        consumer = Consumer.objects.create(userprofile=another_userprofile)
        login_data = {"username": another_user.username, "password": "password"}
        response = self.client.post(reverse("login"), login_data, format='json')
        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertEqual(response.data['userprofile']['user']['username'], consumer.userprofile.user.username)
        self.assertEqual(response.data['userprofile']['user']['email'], consumer.userprofile.user.email)
        for key in ('refresh', 'access'):
            self.assertIn(key, response.cookies)

    def test_user_cannot_login_with_wrong_credentials(self):
        response = self.client.post(reverse('login'),
                                    {"username": "does not exist", "password": "password"},
                                    format='json')
        self.assertEqual(response.status_code, HTTP_401_UNAUTHORIZED)
        self.assertEqual(str(response.data['detail']), AUTHENTICATION_ERROR)


class LogoutTestCases(APITestCase):
    def setUp(self):
        self.consumer_user = User.objects.create_user(username="consumer", password="password",
                                                      email="consumer@test.com")
        self.provider_user = User.objects.create_user(username="provider", password="password",
                                                      email="provider@test.com")
        self.consumer_userprofile = UserProfile.objects.create(user=self.consumer_user)
        self.provider_userprofile = UserProfile.objects.create(user=self.provider_user)
        self.consumer = Consumer.objects.create(userprofile=self.consumer_userprofile)
        self.provider = Provider.objects.create(userprofile=self.provider_userprofile,
                                                account_status=AccountStatus.APPROVED)

    def authenticate_and_logout_with_assertions(self, login_data):
        response = self.client.post(reverse('login'), login_data, format='json')
        self.assertEqual(response.status_code, HTTP_200_OK)
        access = response.cookies.get('access')
        refresh = response.cookies.get('refresh')
        response = self.client.post(reverse('logout'))
        self.assertEqual(response.status_code, HTTP_205_RESET_CONTENT)
        self.assertFalse(OutstandingToken.objects.filter(token=access.value).exists())
        self.assertTrue(BlacklistedToken.objects.filter(token__token=refresh.value).exists())

    def test_consumer_can_log_out(self):
        self.authenticate_and_logout_with_assertions({"username": self.consumer_user.username, "password": "password"})

    def test_provider_can_log_out(self):
        self.authenticate_and_logout_with_assertions({"username": self.provider_user.username, "password": "password"})

    def test_logout_with_absence_of_access_tokens(self):
        login_data = {"username": self.provider_user.username, "password": "password"}
        self.client.post(reverse('login'), login_data, format='json')
        access = self.client.cookies.pop('access', None)
        self.assertIsNotNone(access)
        response = self.client.post(reverse('logout'))
        self.assertEqual(response.status_code, HTTP_401_UNAUTHORIZED)
        self.assertIn(str(response.data['detail']), AUTHENTICATION_FAILED_MESSAGES)


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
                                                    account_status=AccountStatus.APPROVED.value)
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
        self.login_data = {"username": self.provider_one.user.username, "password": "password"}
        self.lock = Lock()

    def authenticate_user_and_update_account(self, username, account, password="password"):
        response = self.client.post(reverse('login'), {"username": username, "password": password}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # update account information
        resolved_url = reverse('update_profile', args=[account.user.username])
        response = self.client.put(resolved_url, self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('user', response.data)
        if account.is_provider:
            updated_account = Provider.objects.filter(userprofile_ptr_id=account.userprofile_ptr_id).first()
        else:
            updated_account = Consumer.objects.filter(userprofile_ptr_id=account.userprofile_ptr_id).first()
        user_data = self.data.pop('user')
        password = user_data.pop('password')
        for key, value in user_data.items():
            self.assertEqual(getattr(updated_account.user, key), value)

        for key, value in self.data.items():
            self.assertEqual(getattr(updated_account, key), value)

        # make sure that the password is updated as well
        response = self.client.post(reverse('logout'))
        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)
        # Authenticate the user
        login_data = {"username": user_data['username'], "password": password}
        response = self.client.post(reverse('login'), login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_consumer_can_update_account_information(self):
        self.authenticate_user_and_update_account(username=self.consumer_one.user.username, account=self.consumer_one, )

    def test_provider_can_update_profile_information(self):
        self.authenticate_user_and_update_account(username=self.provider_one.user.username, account=self.provider_one)

    def test_user_cannot_update_username_to_existing_username(self):
        response = self.client.post(reverse('login'), self.login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.data['user']['username'] = self.consumer_one.user.username
        url = reverse("update_profile", args=[self.provider_one.user.username])
        response = self.client.put(url, self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['user']['username'][0], "Username is already in use")

    def test_user_cannot_update_email_to_existing_email(self):
        response = self.client.post(reverse('login'), self.login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.data['user']['email'] = self.consumer_one.user.email
        url = reverse('update_profile', args=[self.provider_one.user.username])
        response = self.client.put(url, self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(str(response.data['user']['email'][0]), "Email is already in use")

    def test_only_authenticated_users_can_do_updates(self):
        url = reverse('update_profile', args=[self.provider_one.user.username])
        response = self.client.put(url, self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(str(response.data['detail']), "Authentication credentials were not provided.")

    def test_user_cannot_update_other_user_account(self):
        response = self.client.post(reverse('login'), self.login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(User.objects.all().count(), 2)
        url = reverse('update_profile', args=[self.consumer_one.user.username])
        response = self.client.put(url, self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(str(response.data['detail']), IsAccountOwner.message)

    def test_handle_nonexistent_account(self):
        response = self.client.post(reverse('login'), self.login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        url = reverse('update_profile', args=["some_username"])  # random username string that does not exist
        response = self.client.put(url, self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(str(response.data['detail']), "Account does not exist")

    def test_fields_should_not_be_required(self):
        response = self.client.post(reverse('login'), self.login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        url = reverse('update_profile', args=[self.provider_one.user.username])
        # remove the password
        self.data['user'].pop('password')
        response = self.client.put(url, self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class FileUploadTestCases(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="user", password="password", email="user@test.com")
        self.provider = Provider.objects.create(user=self.user,
                                                is_provider=True,
                                                account_status=AccountStatus.APPROVED.value)
        self.consumer_user = User.objects.create_user(username="consumer", password="password")
        self.consumer = Consumer.objects.create(user=self.consumer_user, is_provider=False)
        self.data = {'profile_pic': create_file()}

    def authenticate(self, account):
        login_data = {"username": account.user.username, "password": "password"}
        response = self.client.post(reverse('login'), login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_unauthenticated_user_cannot_upload_file(self):
        url = reverse('file_upload', args=[self.provider.user.username])
        response = self.client.put(url, self.data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        provider = Provider.objects.get(userprofile_ptr_id=self.provider.userprofile_ptr_id)
        self.assertFalse(provider.profile_pic)

    def test_authenticated_account_can_upload_file(self):
        self.authenticate(self.provider)
        url = reverse('file_upload', args=[self.provider.user.username])
        response = self.client.put(url, self.data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('file', response.data)
        self.assertEqual(response.data['detail'], 'File uploaded successfully')
        provider = Provider.objects.get(userprofile_ptr_id=self.provider.userprofile_ptr_id)
        self.assertTrue(provider.profile_pic)

    def test_user_cannot_upload_file_for_another_account(self):
        self.authenticate(self.provider)
        url = reverse('file_upload', args=[self.consumer.user.username])
        response = self.client.put(url, self.data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_only_images_can_be_uploaded(self):
        self.data = {'profile_pic': create_file(".json")}
        self.authenticate(self.provider)
        url = reverse('file_upload', args=[self.provider.user.username])
        response = self.client.put(url, self.data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(str(response.data[0]), "Uploaded file is not a valid image")


@skip("Limited API calls per day")
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
