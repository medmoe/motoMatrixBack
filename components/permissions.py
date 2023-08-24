from rest_framework.permissions import BasePermission
from accounts.models import AccountStatus, Provider


class IsProvider(BasePermission):
    message = "Only providers can access this endpoint"

    def has_permission(self, request, view):
        return hasattr(request.user, 'userprofile') and request.user.userprofile.is_provider


class IsProviderApproved(BasePermission):
    """
    Ensure that the user is an approved provider
    """
    message = "Only approved providers can access this endpoint"

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        # Check if the authenticated user is an approved provider
        return Provider.objects.filter(user=request.user, account_status=AccountStatus.APPROVED.value).exists()


class IsAutoPartOwner(BasePermission):
    message = "Only owner can access this endpoint"

    def has_object_permission(self, request, view, obj):
        return obj.provider == request.user.userprofile.provider
