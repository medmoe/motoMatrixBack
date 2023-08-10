from rest_framework import serializers

from accounts.models import Provider
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
            raise serializers.ValidationError(detail="You are not allowed to perform this action.")

        if provider.account_status != 'approved':
            raise serializers.ValidationError("Your account is not approved yet")

        auto_part = AutoPart.objects.create(provider=provider, **validated_data)
        return auto_part
