"""
Security helpers: brute-force mitigation, rate limiting, and security event logging.
"""

import logging
from datetime import timedelta
from django.utils import timezone
from .models import LoginAttempt

logger = logging.getLogger("security")

# Configuration for rate limiting
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 5


def get_client_ip(request):
    """
    Safely extract client IP address from HTTP request headers.
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR", "0.0.0.0")
    return ip


def is_rate_limited(username, ip_address):
    """
    Check if the user or IP is currently locked out due to excessive failed attempts.
    Returns (is_limited: bool, remaining_seconds: int)
    """
    cutoff = timezone.now() - timedelta(minutes=LOCKOUT_DURATION_MINUTES)
    
    # Count failed attempts by IP or by username within the lockout window
    ip_failures = LoginAttempt.objects.filter(
        ip_address=ip_address,
        success=False,
        timestamp__gte=cutoff
    ).count()
    
    user_failures = 0
    if username:
        user_failures = LoginAttempt.objects.filter(
            username=username,
            success=False,
            timestamp__gte=cutoff
        ).count()

    max_count = max(ip_failures, user_failures)
    if max_count >= MAX_FAILED_ATTEMPTS:
        # Find most recent failure to calculate remaining cool-down time
        most_recent = LoginAttempt.objects.filter(
            success=False,
            timestamp__gte=cutoff
        ).filter(
            ip_address=ip_address
        ).order_by("-timestamp").first()
        
        if most_recent:
            elapsed = (timezone.now() - most_recent.timestamp).total_seconds()
            remaining = max(1, int((LOCKOUT_DURATION_MINUTES * 60) - elapsed))
            return True, remaining
        return True, LOCKOUT_DURATION_MINUTES * 60

    return False, 0


def record_login_attempt(request, username, success):
    """
    Record an authentication attempt in the audit table and security log.
    Never records passwords!
    """
    ip = get_client_ip(request)
    ua = request.META.get("HTTP_USER_AGENT", "")[:250]
    
    LoginAttempt.objects.create(
        username=username or "anonymous",
        ip_address=ip,
        user_agent=ua,
        success=success,
        timestamp=timezone.now(),
    )
    
    if success:
        logger.info(f"AUTH SUCCESS: User '{username}' authenticated from IP {ip}")
    else:
        logger.warning(f"AUTH FAILURE: Failed login attempt for user '{username}' from IP {ip}")
