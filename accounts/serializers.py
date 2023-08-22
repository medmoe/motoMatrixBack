from django.contrib.auth.models import User
from rest_framework import exceptions
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import Consumer, Provider, UserProfile, AccountStatus


class UserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
    email = serializers.CharField(required=True)

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
        rep = super().to_representation(instance)
        rep.pop('password', None)
        return rep

    def validate_username(self, value):
        request = self.context['request']
        if User.objects.exclude(pk=request.user.pk).filter(username=value).exists():
            raise serializers.ValidationError(detail="Username is already in use")
        return value

    def validate_email(self, value):
        request = self.context['request']
        if User.objects.exclude(pk=request.user.pk).filter(email=value).exists():
            raise serializers.ValidationError(detail="Email is already in use")
        return value


class UserProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer()

    class Meta:
        model = UserProfile
        fields = ['user', 'profile_pic', 'is_provider', 'phone', 'address', 'city', 'country', 'rating', 'id']

    def create(self, validated_data):
        # Make sure that the email is unique
        if User.objects.filter(email=validated_data['user']['email']).exists():
            raise serializers.ValidationError("Email already exists")
        # Make sure that the username is unique
        if User.objects.filter(username=validated_data['user']['username']).exists():
            raise serializers.ValidationError("Username already exists")

        # Create the user
        user_data = validated_data.pop('user')
        user = UserSerializer.create(UserSerializer(), validated_data=user_data)
        if validated_data['is_provider']:
            provider, created = Provider.objects.update_or_create(user=user, **validated_data)
            return provider
        else:
            consumer, created = Consumer.objects.update_or_create(user=user, **validated_data)
            return consumer

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user')
        UserSerializer.update(UserSerializer(), instance=instance.user, validated_data=user_data)
        # update UserProfile fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):

    def validate(self, attrs):
        # Attempt to get user
        user = User.objects.filter(username=attrs['username']).first()
        if not user:
            raise exceptions.AuthenticationFailed('No active account found with the given credentials')

        # Attempt to get account
        provider = Provider.objects.filter(user=user).first()
        if provider:
            if provider.account_status == AccountStatus.PENDING.value:
                raise exceptions.PermissionDenied(detail="Your account is not approved yet")
            account = provider
        else:
            consumer = Consumer.objects.filter(user=user).first()
            if consumer:
                account = consumer
            else:
                raise exceptions.AuthenticationFailed('No active account found with the given credentials')

        data = super().validate(attrs)
        refresh = self.get_token(self.user)
        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)

        # serialize account
        sa = ProviderSerializer(account).data if isinstance(account, Provider) else ConsumerSerializer(account).data
        data.update(sa)
        return data


class ProviderSerializer(UserProfileSerializer):
    class Meta(UserProfileSerializer.Meta):
        model = Provider
        fields = UserProfileSerializer.Meta.fields + ['provider_type', 'description']

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', None)
        UserSerializer.update(UserSerializer(), instance=instance.user, validated_data=user_data)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


class ConsumerSerializer(UserProfileSerializer):
    class Meta(UserProfileSerializer.Meta):
        model = Consumer
        fields = UserProfileSerializer.Meta.fields

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', None)
        UserSerializer.update(UserSerializer(), instance=instance.user, validated_data=user_data)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance
