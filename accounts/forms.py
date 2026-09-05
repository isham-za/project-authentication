"""
Secure forms for user registration, authentication, profile updates, and password changes.
"""

import re
from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError


class UserRegistrationForm(forms.Form):
    """
    Form for secure user registration with comprehensive server-side validation.
    """
    full_name = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={
            "class": "form-control",
            "placeholder": "Enter your full name",
            "autocomplete": "name",
        })
    )
    username = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={
            "class": "form-control",
            "placeholder": "Choose a username",
            "autocomplete": "username",
        })
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            "class": "form-control",
            "placeholder": "name@example.com",
            "autocomplete": "email",
        })
    )
    password = forms.CharField(
        required=True,
        widget=forms.PasswordInput(attrs={
            "class": "form-control",
            "placeholder": "Enter a strong password",
            "autocomplete": "new-password",
        })
    )
    confirm_password = forms.CharField(
        required=True,
        widget=forms.PasswordInput(attrs={
            "class": "form-control",
            "placeholder": "Confirm your password",
            "autocomplete": "new-password",
        })
    )

    def clean_username(self):
        username = self.cleaned_data.get("username", "").strip()
        if not re.match(r"^[\w.@+-]+$", username):
            raise ValidationError("Username may contain only letters, numbers, and @/./+/-/_ characters.")
        if User.objects.filter(username__iexact=username).exists():
            raise ValidationError("A user with that username already exists.")
        return username

    def clean_email(self):
        email = self.cleaned_data.get("email", "").strip().lower()
        if User.objects.filter(email__iexact=email).exists():
            raise ValidationError("An account with this email address already exists.")
        return email

    def clean_password(self):
        password = self.cleaned_data.get("password")
        if not password:
            raise ValidationError("Password is required.")

        # Minimum length 8 characters
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long.")

        # At least one uppercase letter
        if not re.search(r"[A-Z]", password):
            raise ValidationError("Password must contain at least one uppercase letter.")

        # At least one lowercase letter
        if not re.search(r"[a-z]", password):
            raise ValidationError("Password must contain at least one lowercase letter.")

        # At least one numeric digit
        if not re.search(r"\d", password):
            raise ValidationError("Password must contain at least one number.")

        # Django built-in validators (common password rejection, similarity, etc.)
        validate_password(password)

        return password

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")

        if password and confirm_password and password != confirm_password:
            self.add_error("confirm_password", "Passwords do not match. Please re-enter.")

        return cleaned_data


class UserLoginForm(forms.Form):
    """
    Login form collecting credentials for verification.
    """
    username = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={
            "class": "form-control",
            "placeholder": "Enter username",
            "autocomplete": "username",
        })
    )
    password = forms.CharField(
        required=True,
        widget=forms.PasswordInput(attrs={
            "class": "form-control",
            "placeholder": "Enter password",
            "autocomplete": "current-password",
        })
    )


class UserProfileUpdateForm(forms.Form):
    """
    Form allowing authenticated users to update their profile information.
    """
    full_name = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={"class": "form-control"})
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={"class": "form-control"})
    )

    def __init__(self, *args, current_user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.current_user = current_user

    def clean_email(self):
        email = self.cleaned_data.get("email", "").strip().lower()
        if self.current_user:
            duplicate = User.objects.filter(email__iexact=email).exclude(pk=self.current_user.pk).exists()
            if duplicate:
                raise ValidationError("This email is already in use by another account.")
        return email


class SecurePasswordChangeForm(forms.Form):
    """
    Form requiring verification of the current password before changing to a new one.
    """
    current_password = forms.CharField(
        required=True,
        widget=forms.PasswordInput(attrs={
            "class": "form-control",
            "placeholder": "Current password",
            "autocomplete": "current-password",
        })
    )
    new_password = forms.CharField(
        required=True,
        widget=forms.PasswordInput(attrs={
            "class": "form-control",
            "placeholder": "New password (min 8 characters, letters & digits)",
            "autocomplete": "new-password",
        })
    )
    confirm_new_password = forms.CharField(
        required=True,
        widget=forms.PasswordInput(attrs={
            "class": "form-control",
            "placeholder": "Confirm new password",
            "autocomplete": "new-password",
        })
    )

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user

    def clean_current_password(self):
        current_password = self.cleaned_data.get("current_password")
        if self.user and not self.user.check_password(current_password):
            raise ValidationError("Current password does not match our records.")
        return current_password

    def clean_new_password(self):
        new_password = self.cleaned_data.get("new_password")
        if not new_password:
            raise ValidationError("New password is required.")

        if len(new_password) < 8:
            raise ValidationError("Password must be at least 8 characters long.")

        if not re.search(r"[A-Z]", new_password):
            raise ValidationError("Password must contain at least one uppercase letter.")

        if not re.search(r"[a-z]", new_password):
            raise ValidationError("Password must contain at least one lowercase letter.")

        if not re.search(r"\d", new_password):
            raise ValidationError("Password must contain at least one number.")

        validate_password(new_password, user=self.user)
        return new_password

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirm_new_password = cleaned_data.get("confirm_new_password")
        current_password = cleaned_data.get("current_password")

        if new_password and confirm_new_password and new_password != confirm_new_password:
            self.add_error("confirm_new_password", "New passwords do not match.")

        if current_password and new_password and current_password == new_password:
            self.add_error("new_password", "New password cannot be identical to the current password.")

        return cleaned_data
