from rest_framework import serializers

from .models import AutoPart


class AutoPartSerializer(serializers.ModelSerializer):
    class Meta:
        model = AutoPart
        fields = '__all__'
        read_only_fields = ['provider']  # Provider will not be affected by incoming payload

    def create(self, validated_data):
        user = self.context['request'].user
        auto_part = AutoPart.objects.create(provider=user.userprofile.provider, **validated_data)
        return auto_part
