from django.contrib.auth.models import User
from rest_framework import exceptions
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import Consumer, Provider, UserProfile
from components.models import AutoPart


class UserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=False)
    password = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'password']

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

    def update(self, instance, validated_data):
        instance.username = validated_data.get('username', instance.username)
        # Make sure that the password is hashed
        if 'password' in validated_data:
            instance.set_password(validated_data.get('password', instance.password))
        else:
            instance.set_password(instance.password)
        instance.save()
        return instance

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep.pop('password', None)
        return rep


class UserProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer()

    class Meta:
        model = UserProfile
        fields = ['user', 'profile_pic', 'is_provider', 'phone', 'address', 'city', 'country', 'rating']

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
        try:
            user = User.objects.get(username=attrs['username'])
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed(
                'No active account found with the given credentials'
            )
        try:
            user_profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            raise exceptions.AuthenticationFailed(
                'No active account found with the given credentials'
            )
        if user_profile.is_provider:
            try:
                provider = Provider.objects.get(userprofile_ptr_id=user_profile.id)
            except Provider.DoesNotExist:
                raise exceptions.AuthenticationFailed(
                    'No active account found with the given credentials'
                )
            if provider.account_status != 'approved':
                raise exceptions.AuthenticationFailed(
                    'Your account is not approved yet'
                )
        data = super().validate(attrs)
        refresh = self.get_token(self.user)
        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)

        # Add extra responses here
        user_fields = ["user_id", "username", "email", "first_name", "last_name"]
        user_profile_fields = ["is_provider", "phone", "address", "city", "country", "rating"]
        data["user"] = dict()
        data["dashboard"] = dict()

        # handle the image separately
        if user_profile.profile_pic and user_profile.profile_pic.name:
            data['user']["profile_pic"] = user_profile.profile_pic.url
        else:
            data["user"]["profile_pic"] = None

        for field in user_fields:
            if field == "user_id":
                data["user"][field] = user.id
            else:
                data["user"][field] = getattr(user, field)

        for field in user_profile_fields:
            data["user"][field] = getattr(user_profile, field)

        if user_profile.is_provider:
            try:
                provider = Provider.objects.get(userprofile_ptr_id=user_profile.id)
                data['user']["bio"] = provider.description
                data['dashboard']["items"] = AutoPart.objects.filter(provider=provider).count()

            except Provider.DoesNotExist:
                raise exceptions.AuthenticationFailed(
                    "No active account found with the given credentials"
                )

        return data


class ProviderSerializer(UserProfileSerializer):
    class Meta(UserProfileSerializer.Meta):
        model = Provider
        fields = UserProfileSerializer.Meta.fields + ['provider_type', 'description']

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', None)
        if user_data:
            password = user_data.pop('password', None)
            if password:
                UserSerializer.update(UserSerializer(), instance=instance.user, validated_data=user_data)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


class ConsumerSerializer(UserProfileSerializer):
    class Meta:
        model = Consumer
        fields = UserProfileSerializer.Meta.fields
