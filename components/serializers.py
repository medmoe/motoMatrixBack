from rest_framework import serializers
from accounts.models import Provider, Consumer, UserProfile
from .models import AutoPart


class AutoPartSerializer(serializers.ModelSerializer):
    class Meta:
        model = AutoPart
        fields = '__all__'
        read_only_fields = ['provider']

    def create(self, validated_data):
        user = self.context['request'].user
        provider = None
        try:
            provider = user.userprofile.provider
        except Provider.DoesNotExist:
            pass
        if provider is None:
            raise serializers.ValidationError("Only providers can create auto parts")

        if provider.account_status != 'approved':
            raise serializers.ValidationError("Your account is not approved yet")

        auto_part = AutoPart.objects.create(provider=provider, **validated_data)
        return auto_part
