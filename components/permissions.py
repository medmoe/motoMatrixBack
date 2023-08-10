from rest_framework.permissions import BasePermission


class IsProvider(BasePermission):
    message = "Only providers can access this endpoint"

    def has_permission(self, request, view):
        return hasattr(request.user, 'userprofile') and request.user.userprofile.is_provider


class IsAutoPartOwner(BasePermission):
    message = "Only owner can access this endpoint"

    def has_object_permission(self, request, view, obj):
        return obj.provider == request.user.userprofile.provider
