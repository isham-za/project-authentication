"""
Django Admin configuration for accounts models.
"""

from django.contrib import admin
from .models import UserProfile, LoginAttempt


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "full_name", "created_at", "updated_at")
    search_fields = ("user__username", "user__email", "full_name")
    readonly_fields = ("created_at", "updated_at")


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "username", "ip_address", "success")
    list_filter = ("success", "timestamp")
    search_fields = ("username", "ip_address")
    readonly_fields = ("timestamp", "username", "ip_address", "user_agent", "success")

    def has_add_permission(self, request):
        # Audit logs should be immutable and not manually added
        return False
