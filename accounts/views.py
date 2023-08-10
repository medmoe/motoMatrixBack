import os

from rest_framework import permissions, status
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from utils.helpers import get_object
from utils.validators import validate_image
from .serializers import UserProfileSerializer, CustomTokenObtainPairSerializer, ProviderSerializer, ConsumerSerializer


class SignupView(APIView):
    authentication_classes = []
    permission_classes = [permissions.AllowAny, ]

    def post(self, request):
        serializer = UserProfileSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user_profile = serializer.save()
            refresh = RefreshToken.for_user(user_profile.user)
            data = dict()
            user_data = serializer.data.pop('user')
            for key, value in serializer.data.items():
                if key != "user":
                    user_data[key] = value
            data['user'] = user_data
            if data['user']["is_provider"]:
                data['message'] = "Your account has been created and is pending approval"
            else:
                data['message'] = "Your account is created successfully"

            # send email for verification
            message = Mail(
                from_email='partsplaza23@gmail.com',
                to_emails=data['user']['email'],
                subject="Account Verification",
                html_content=f'<p> {data["message"]}'
            )
            try:
                sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
                _ = sg.send(message)  # Send grid response here for future uses
            except Exception as e:
                print(e.args)
            finally:
                response = Response(data, status=status.HTTP_201_CREATED)

                # Only set authentication cookies if user is not a provider
                if not data['user']['is_provider']:
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
        response.data['user']['profile_pic'] = request.build_absolute_uri(response.data['user']['profile_pic'])
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
    permission_classes = (permissions.IsAuthenticated,)

    def put(self, request, id):
        account, is_provider = get_object(id, request)
        if is_provider:
            # make sure the account is approved
            if account.account_status != "approved":
                raise ValidationError(detail="Your account is not approved yet")

            serializer = ProviderSerializer(account, data=request.data, context={'request': request})
            if serializer.is_valid():
                serializer.save()
                response_data = serializer.data.copy()
                response_data['profile_pic'] = request.build_absolute_uri(response_data['profile_pic'])
                return Response(response_data, status=status.HTTP_202_ACCEPTED)
            raise ValidationError(detail=serializer.errors)
        else:
            serializer = ConsumerSerializer(account, data=request.data, context={'request': request})
            if serializer.is_valid():
                serializer.save()
                response_data = serializer.data.copy()
                response_data['profile_pic'] = request.build_absolute_uri(response_data['profile_pic'])
                return Response(serializer.data, status=status.HTTP_202_ACCEPTED)

            raise ValidationError(detail=serializer.errors)


class CheckAuthView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        return Response({"detail": "You are authenticated"})


class FileUpload(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def put(self, request, id):
        account, is_provider = get_object(id, request)

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

        return Response({'detail': "File uploaded successfully", 'file': file_url}, status.HTTP_202_ACCEPTED)
