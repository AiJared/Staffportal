from rest_framework.permissions import SAFE_METHODS, BasePermission

class ISWorker(BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            return True

    def has_object_permissions(self, request, view, obj):
        if request.user.role == "worker":
            return True
        if request.method is SAFE_METHODS:
            return True
        return False

class IsAdministrator(BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            return True
        
    def has_object_permission(self, request, view, obj):
        if (request.user.role == "administrator" or
            request.user.is_admin or 
            request.user.is_staff):
            return True
        if request.method in SAFE_METHODS:
            return True
        return False