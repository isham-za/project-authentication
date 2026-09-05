"""
Database models for accounts and security auditing.
"""

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class UserProfile(models.Model):
    """
    Extends standard Django User with additional profile details.
    Uses OneToOneField to maintain separation of core auth from profile data.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    full_name = models.CharField(max_length=150, blank=True, help_text="User's full legal or display name")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username} Profile"


class LoginAttempt(models.Model):
    """
    Audit log for all authentication attempts.
    Used for brute-force / credential stuffing detection and rate limiting.
    Never stores passwords or sensitive payload data.
    """
    username = models.CharField(max_length=150, db_index=True)
    ip_address = models.GenericIPAddressField(db_index=True)
    user_agent = models.CharField(max_length=255, blank=True)
    success = models.BooleanField(default=False)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        status = "SUCCESS" if self.success else "FAILED"
        return f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {self.username} from {self.ip_address} - {status}"
