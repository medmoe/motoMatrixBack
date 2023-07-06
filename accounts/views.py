from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.exceptions import TokenError
from .serializers import UserProfileSerializer, CustomTokenObtainPairSerializer, ProviderSerializer, ConsumerSerializer
from .models import UserProfile, Provider, Consumer


class SignupView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        serializer = UserProfileSerializer(data=request.data)
        if serializer.is_valid():
            user_profile = serializer.save()
            refresh = RefreshToken.for_user(user_profile.user)
            response = Response(serializer.data, status=status.HTTP_201_CREATED)
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
        response.set_cookie(key='refresh', value=response.data['refresh'], httponly=True)
        response.set_cookie(key='access', value=response.data['access'], httponly=True)
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

    def get_object(self, id, request):
        try:
            account = UserProfile.objects.get(id=id)
            if account != request.user.userprofile:
                raise PermissionDenied("You do not have permission to perform this action")

            if account.is_provider:
                provider = Provider.objects.get(userprofile_ptr_id=id)
                return provider, True
            consumer = Consumer.objects.get(user_profile_ptr=id)
            return consumer, False

        except UserProfile.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

    def put(self, request, id):
        account, is_provider = self.get_object(id, request)
        request.data['user'].pop('username', None)
        if is_provider:
            serializer = ProviderSerializer(account, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_202_ACCEPTED)
        else:
            serializer = ConsumerSerializer(account, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_202_ACCEPTED)

