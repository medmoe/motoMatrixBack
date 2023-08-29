from django.contrib.auth.models import User
from django.core.validators import EmailValidator
from rest_framework import serializers
from rest_framework.exceptions import ValidationError, PermissionDenied, AuthenticationFailed
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from components.serializers import AutoPartSerializer
from .models import Consumer, Provider, UserProfile, AccountStatus

# Validation and Authentication error messages
MISSING_USER_DATA_ERROR = "Required user data is missing."
AUTHENTICATION_ERROR = "No active account found with the given credentials."
ACCOUNT_STATUS_ERROR = "Account is not approved yet."
USERNAME_ALREADY_IN_USE_ERROR = 'Username is already in use.'
EMAIL_ALREADY_IN_USE_ERROR = "Email address is already in use."
INVALID_EMAIL_ERROR = "Enter a valid email address."
ACCOUNT_NOT_FOUND_ERROR = "Account does not exist."
IMAGE_UPLOAD_ERROR = "Uploaded file is not a valid image."
UNKNOWN_PROFILE_TYPE = "The profile type provided does not exist."


# Helper functions
def update_instance_from_data(instance, validated_data):
    for attr, value in validated_data.items():
        setattr(instance, attr, value)
    instance.save()
    return instance


class UserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=False)
    email = serializers.CharField(required=True, validators=[EmailValidator(message=INVALID_EMAIL_ERROR)])

    def __init__(self, *args, **kwargs):
        super(UserSerializer, self).__init__(*args, **kwargs)
        request = self.context.get('request', None)
        if request and request.method == "POST":
            self.fields['password'].required = True

    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name', 'email', 'password']

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

    def update(self, instance, validated_data):
        instance.username = validated_data.get('username', instance.username)
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.email = validated_data.get('email', instance.email)
        # Make sure that the password is hashed
        if 'password' in validated_data:
            instance.set_password(validated_data.get('password', instance.password))
        instance.save()
        return instance

    def to_representation(self, instance):
        """ Ensures that the password is not included in the returned data"""

        rep = super().to_representation(instance)
        rep.pop('password', None)
        return rep

    def validate_username(self, value):
        request = self.context['request']
        if User.objects.exclude(pk=request.user.pk).filter(username=value).exists():
            raise ValidationError(detail=USERNAME_ALREADY_IN_USE_ERROR)
        return value

    def validate_email(self, value):
        request = self.context['request']
        if User.objects.exclude(pk=request.user.pk).filter(email=value).exists():
            raise ValidationError(detail=EMAIL_ALREADY_IN_USE_ERROR)
        return value


class UserProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer()

    class Meta:
        model = UserProfile
        fields = "__all__"

    def create(self, validated_data):
        user_data = validated_data.pop('user', None)
        user_serializer = UserSerializer(data=user_data, context=self.context)
        user_serializer.is_valid(raise_exception=True)
        user = user_serializer.save()
        return UserProfile.objects.create(user=user, **validated_data)

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', None)
        if user_data:
            user_serializer = UserSerializer(instance.user, user_data, context=self.context)
            user_serializer.is_valid(raise_exception=True)
            user_serializer.save()
        return update_instance_from_data(instance, validated_data)


class ProviderSerializer(serializers.ModelSerializer):
    userprofile = UserProfileSerializer()

    class Meta:
        model = Provider
        fields = "__all__"

    def create(self, validated_data):
        userprofile_data = validated_data.pop('userprofile')
        userprofile_serializer = UserProfileSerializer(data=userprofile_data, context=self.context)
        userprofile_serializer.is_valid(raise_exception=True)
        userprofile = userprofile_serializer.save()
        return Provider.objects.create(userprofile=userprofile, **validated_data)

    def update(self, instance, validated_data):
        userprofile_data = validated_data.pop('userprofile')
        userprofile_serializer = UserProfileSerializer(instance.userprofile,
                                                       data=userprofile_data,
                                                       context=self.context)
        userprofile_serializer.is_valid(raise_exception=True)
        userprofile_serializer.save()
        return update_instance_from_data(instance, validated_data)


class ConsumerSerializer(serializers.ModelSerializer):
    userprofile = UserProfileSerializer()
    wishlist = AutoPartSerializer(many=True, read_only=True)
    cart = AutoPartSerializer(many=True, read_only=True)
    favorite_providers = ProviderSerializer(many=True, read_only=True)

    class Meta:
        model = Consumer
        fields = '__all__'

    def create(self, validated_data):
        userprofile_data = validated_data.pop('userprofile')
        userprofile_serializer = UserProfileSerializer(data=userprofile_data, context=self.context)
        userprofile_serializer.is_valid(raise_exception=True)
        userprofile = userprofile_serializer.save()
        return Consumer.objects.create(userprofile=userprofile, **validated_data)

    def update(self, instance, validated_data):
        userprofile_data = validated_data.pop('userprofile')
        userprofile_serializer = UserProfileSerializer(instance.userprofile,
                                                       data=userprofile_data,
                                                       context=self.context)
        userprofile_serializer.is_valid(raise_exception=True)
        userprofile_serializer.save()
        return update_instance_from_data(instance, validated_data)


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        # Attempt to get user
        user = User.objects.filter(username=attrs['username']).first()
        if not user:
            raise AuthenticationFailed(detail=AUTHENTICATION_ERROR)

        # Determine the type of the account( Provider or Consumer)
        account = None
        if Provider.objects.filter(userprofile__user=user).exists():
            provider = Provider.objects.get(userprofile__user=user)
            if provider.account_status == AccountStatus.PENDING.value:
                raise PermissionDenied(detail=ACCOUNT_STATUS_ERROR)
            account = provider
        elif Consumer.objects.filter(userprofile__user=user).exists():
            account = Consumer.objects.get(userprofile__user=user)

        if not account:
            raise AuthenticationFailed(detail=AUTHENTICATION_ERROR)

        data = super().validate(attrs)
        refresh = self.get_token(self.user)
        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)

        # serialize account
        if isinstance(account, Provider):
            serialized_account = ProviderSerializer(account).data
        else:
            serialized_account = ConsumerSerializer(account).data
        data.update(serialized_account)
        return data
