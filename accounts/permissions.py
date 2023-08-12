from rest_framework.permissions import BasePermission


class IsAccountOwner(BasePermission):
    message = "Only owner can access this endpoint"

    def has_object_permission(self, request, view, obj):
        return request.user.id == obj.user.id
