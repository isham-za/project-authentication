"""
Views for secure authentication, registration, profile, and dashboard.
"""

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.views.decorators.http import require_http_methods
from django.utils.http import url_has_allowed_host_and_scheme

from .models import UserProfile
from .forms import (
    UserRegistrationForm,
    UserLoginForm,
    UserProfileUpdateForm,
    SecurePasswordChangeForm,
)
from .security import get_client_ip, is_rate_limited, record_login_attempt


def home_view(request):
    """
    Public landing page presenting application overview and security features.
    """
    return render(request, "home.html")


def signup_view(request):
    """
    Handles secure user registration.
    Enforces strong password hashing, input validation, and CSRF protection.
    """
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            cleaned = form.cleaned_data
            
            # Safe creation via Django ORM (SQL Injection Defense)
            # Never store plaintext passwords! Use set_password() which uses PBKDF2 SHA-256.
            user = User(
                username=cleaned["username"],
                email=cleaned["email"],
            )
            user.set_password(cleaned["password"])
            user.save()

            # Create associated profile
            UserProfile.objects.create(
                user=user,
                full_name=cleaned["full_name"],
            )

            messages.success(request, "Account created successfully! You can now log in.")
            return redirect("login")
    else:
        form = UserRegistrationForm()

    return render(request, "signup.html", {"form": form})


def login_view(request):
    """
    Handles secure user authentication.
    Implements brute-force rate-limiting, generic error messages, and session cycling.
    """
    if request.user.is_authenticated:
        return redirect("dashboard")

    next_url = request.GET.get("next") or request.POST.get("next") or "dashboard"

    if request.method == "POST":
        form = UserLoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data["username"].strip()
            password = form.cleaned_data["password"]
            ip = get_client_ip(request)

            # 1. Brute-force & Rate Limiting Check
            limited, remaining = is_rate_limited(username, ip)
            if limited:
                messages.error(
                    request,
                    f"Too many failed login attempts. For security, your account/IP is temporarily locked. Please try again in {remaining} seconds."
                )
                return render(request, "login.html", {"form": form, "next": next_url})

            # 2. Secure credential authentication
            user = authenticate(request, username=username, password=password)

            if user is not None and user.is_active:
                # Record successful attempt for audit trail
                record_login_attempt(request, username, success=True)

                # Initialize session
                auth_login(request, user)

                # Rotate session token to prevent session fixation attacks
                request.session.cycle_key()

                messages.success(request, f"Welcome back, {user.username}!")

                # Validate redirect URL to prevent Open Redirect vulnerabilities
                if next_url and url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
                    return redirect(next_url)
                return redirect("dashboard")
            else:
                # Record failed attempt
                record_login_attempt(request, username, success=False)

                # Generic error message to prevent username enumeration
                messages.error(request, "Invalid username or password.")
    else:
        form = UserLoginForm()

    return render(request, "login.html", {"form": form, "next": next_url})


@require_http_methods(["GET", "POST"])
def logout_view(request):
    """
    Terminates user session, flushes cookies, and applies no-cache headers.
    """
    if request.user.is_authenticated:
        username = request.user.username
        auth_logout(request)
        messages.info(request, "You have been logged out securely.")
    
    response = redirect("login")
    # Prevent browser back-button caching of authenticated screens
    response["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response["Pragma"] = "no-cache"
    response["Expires"] = "0"
    return response


@login_required
def dashboard_view(request):
    """
    Protected dashboard visible exclusively to authenticated users.
    """
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    context = {
        "user": request.user,
        "profile": profile,
    }
    return render(request, "dashboard.html", context)


@login_required
def profile_view(request):
    """
    Allows authenticated users to view and safely edit their profile data.
    """
    profile, _ = UserProfile.objects.get_or_create(user=request.user)

    if request.method == "POST":
        form = UserProfileUpdateForm(request.POST, current_user=request.user)
        if form.is_valid():
            # Update user model fields
            request.user.email = form.cleaned_data["email"]
            request.user.save()

            # Update profile model fields
            profile.full_name = form.cleaned_data["full_name"]
            profile.save()

            messages.success(request, "Your profile has been updated successfully.")
            return redirect("profile")
    else:
        initial_data = {
            "full_name": profile.full_name,
            "email": request.user.email,
        }
        form = UserProfileUpdateForm(initial=initial_data, current_user=request.user)

    context = {
        "user": request.user,
        "profile": profile,
        "form": form,
    }
    return render(request, "profile.html", context)


@login_required
def change_password_view(request):
    """
    Enables users to change their password securely.
    Requires current password confirmation and preserves current session hash.
    """
    if request.method == "POST":
        form = SecurePasswordChangeForm(request.POST, user=request.user)
        if form.is_valid():
            new_password = form.cleaned_data["new_password"]
            
            # Hash and persist new password
            request.user.set_password(new_password)
            request.user.save()

            # Maintain user's active session without forcing re-login
            update_session_auth_hash(request, request.user)

            messages.success(request, "Your password has been changed successfully.")
            return redirect("dashboard")
    else:
        form = SecurePasswordChangeForm(user=request.user)

    return render(request, "change_password.html", {"form": form})
