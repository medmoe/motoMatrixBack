from rest_framework.permissions import BasePermission

from accounts.models import AccountStatus, Provider


class IsProvider(BasePermission):
    message = "Only providers can access this endpoint"

    def has_permission(self, request, view):
        return hasattr(request.user, 'userprofile') and hasattr(request.user.userprofile, 'provider')


class IsConsumer(BasePermission):
    message = "Only consumers can access this endpoint"

    def has_permission(self, request, view):
        return hasattr(request.user, 'userprofile') and hasattr(request.user.userprofile, 'consumer')


class IsProviderApproved(BasePermission):
    """
    Ensure that the user is an approved provider
    """
    message = "Only approved providers can access this endpoint"

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        # Check if the authenticated user is an approved provider
        userprofile = request.user.userprofile
        return Provider.objects.filter(userprofile=userprofile, account_status=AccountStatus.APPROVED).exists()


class IsAutoPartOwner(BasePermission):
    message = "Only owner can access this endpoint"

    def has_object_permission(self, request, view, obj):
        return obj.component.provider == request.user.userprofile.provider
