

from rest_framework.permissions import BasePermission

class IsAdmin(BasePermission):
    """Allow access to admins"""

    def has_object_permission(self, request, view, obj):
        return request.user.is_admin