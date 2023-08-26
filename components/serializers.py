from rest_framework import serializers

from .models import AutoPart, Component

# Validation and Authentication error messages
AUTO_PART_NOT_FOUND_ERROR = "AutoPart does not exist."
COMPONENT_NOT_FOUND_ERROR = "Component does not exist."


class ComponentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Component
        fields = "__all__"
        read_only_fields = ['provider']  # Provider will not be affected by incoming payload

    def create(self, validated_data):
        user = self.context['request'].user
        component = Component.objects.create(provider=user.userprofile.provider, **validated_data)
        return component

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


class AutoPartSerializer(serializers.ModelSerializer):
    component = ComponentSerializer()

    class Meta:
        model = AutoPart
        fields = '__all__'

    def create(self, validated_data):
        component_data = validated_data.pop('component')
        component_serializer = ComponentSerializer(data=component_data, context=self.context)
        component_serializer.is_valid(raise_exception=True)
        component = component_serializer.save()
        auto_part = AutoPart.objects.create(component=component, **validated_data)
        return auto_part

    def update(self, instance, validated_data):
        component_data = validated_data.pop('component')
        component_serializer = ComponentSerializer(instance.component, data=component_data, context=self.context)
        component_serializer.is_valid(raise_exception=True)
        component_serializer.save()
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance

    def get_image_url(self, obj):
        request = self.context.get('request')
        return request.build_absolute_uri(obj.image.url) if obj.image and obj.image.url else None
