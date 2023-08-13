import os

from rest_framework import permissions, status
from rest_framework.exceptions import ValidationError, PermissionDenied, NotFound
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from utils.validators import validate_image
from .models import Provider, Consumer
from .permissions import IsAccountOwner
from .serializers import UserProfileSerializer, CustomTokenObtainPairSerializer, ProviderSerializer, ConsumerSerializer


class SignupView(APIView):
    authentication_classes = []
    permission_classes = [permissions.AllowAny, ]

    def post(self, request):
        serializer = UserProfileSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user_profile = serializer.save()
            refresh = RefreshToken.for_user(user_profile.user)

            # send email for verification
            message = Mail(
                from_email='partsplaza23@gmail.com',
                to_emails=user_profile.user.email,
                subject="Account Verification",
                html_content='<p> Account created successfully </p>'
            )
            try:
                sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
                _ = sg.send(message)  # Send grid response here for future uses
            except Exception as e:
                print(e.args)
            finally:
                response = Response(serializer.data, status=status.HTTP_201_CREATED)

                # Only set authentication cookies if user is not a provider
                if not user_profile.is_provider:
                    response.set_cookie(key='refresh', value=str(refresh), httponly=True)
                    response.set_cookie(key='access', value=str(refresh.access_token), httponly=True)

                return response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.COOKIES['refresh']
            if refresh_token is None:
                return Response(status=status.HTTP_400_BAD_REQUEST)
            refresh_token = RefreshToken(refresh_token)
            refresh_token.blacklist()
            response = Response(status=status.HTTP_205_RESET_CONTENT)
            response.delete_cookie('refresh')
            response.delete_cookie('access')
            return response
        except Exception as e:
            return Response({'details': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.data['profile_pic']:
            response.data['profile_pic'] = request.build_absolute_uri(response.data['user']['profile_pic'])
        response.set_cookie(key='refresh', value=response.data['refresh'], httponly=True)
        response.set_cookie(key='access', value=response.data['access'], httponly=True)
        response.data.pop('refresh')
        response.data.pop('access')
        return response


class CustomTokenRefreshView(TokenRefreshView):

    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES['refresh']
        if refresh_token is None:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data={'refresh': refresh_token})
        try:
            serializer.is_valid(raise_exception=True)
            response = Response(serializer.validated_data, status=status.HTTP_200_OK)
            response.set_cookie(key='access', value=response.data['access'], httponly=True)
            return response
        except TokenError as e:
            return Response({'detail': str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class ProfileDetail(APIView):
    permission_classes = (permissions.IsAuthenticated, IsAccountOwner)

    @staticmethod
    def get_account(account_id):
        # Attempt to get account
        account = Provider.objects.filter(userprofile_ptr_id=account_id).first()
        if account:
            # Make sure the account is approved
            if account.account_status == "pending":
                raise PermissionDenied(detail="Your account is not approved yet")
        else:
            account = Consumer.objects.filter(userprofile_ptr_id=account_id).first()
            if not account:
                raise NotFound(detail="Account does not exist")

        return account

    def check_object_permissions(self, request, obj):
        for permission in self.get_permissions():
            if not permission.has_object_permission(request, self, obj):
                self.permission_denied(request, message=getattr(permission, 'message', None))

    def put(self, request, account_id):
        account = self.get_account(account_id)
        self.check_object_permissions(request, account)

        if account.is_provider:
            serializer = ProviderSerializer(account, request.data, context={'request': request})
        else:
            serializer = ConsumerSerializer(account, request.data, context={'request': request})

        if serializer.is_valid():
            serializer.save()
            response_data = serializer.data.copy()
            if response_data['profile_pic']:
                response_data['profile_pic'] = request.build_absolute_uri(response_data['profile_pic'])
            return Response(response_data, status=status.HTTP_200_OK)

        raise ValidationError(detail=serializer.errors)


class CheckAuthView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        return Response({"detail": "You are authenticated"})


class FileUpload(APIView):
    permission_classes = (permissions.IsAuthenticated, IsAccountOwner)

    def check_object_permissions(self, request, obj):
        for permission in self.get_permissions():
            if not permission.has_object_permission(request, self, obj):
                self.permission_denied(request, message=getattr(permission, 'message', None))

    def put(self, request, account_id):
        account = ProfileDetail.get_account(account_id)
        self.check_object_permissions(request, account)

        # check if the file has been sent with the request
        if 'profile_pic' not in request.FILES:
            raise ValidationError(detail="No file provided")

        # get the file from the request
        file = request.FILES['profile_pic']

        if not validate_image(file):
            raise ValidationError(detail="Uploaded file is not a valid image")

        # Assign the file to the account
        account.profile_pic = file
        account.save()

        # get the url of the saved file
        file_url = request.build_absolute_uri(account.profile_pic.url)

        return Response({'detail': "File uploaded successfully", 'file': file_url}, status.HTTP_200_OK)
