"""
Automated Functional and Security Test Suite for Secure User Authentication System.
Demonstrates defense against SQL Injection, XSS, CSRF, Brute Force, and Session Hijacking.
"""

from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password
from accounts.models import UserProfile, LoginAttempt


class RegistrationTests(TestCase):
    """Test suite verifying secure user registration rules and server-side validation."""

    def setUp(self):
        self.client = Client()
        self.signup_url = reverse("signup")
        self.valid_data = {
            "full_name": "Alice Johnson",
            "username": "alice",
            "email": "alice@example.com",
            "password": "SecurePass123!",
            "confirm_password": "SecurePass123!",
        }

    def test_valid_registration(self):
        """Valid registration creates User, hashes password, and creates UserProfile."""
        response = self.client.post(self.signup_url, self.valid_data)
        self.assertRedirects(response, reverse("login"))

        user = User.objects.filter(username="alice").first()
        self.assertIsNotNone(user)
        self.assertEqual(user.email, "alice@example.com")
        self.assertTrue(check_password("SecurePass123!", user.password))
        self.assertNotEqual(user.password, "SecurePass123!")  # Must NOT be plaintext
        self.assertTrue(UserProfile.objects.filter(user=user).exists())

    def test_missing_fields(self):
        """Submitting empty form fails validation."""
        response = self.client.post(self.signup_url, {})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response.context["form"], "username", "This field is required.")
        self.assertFormError(response.context["form"], "password", "This field is required.")

    def test_invalid_email_format(self):
        """Invalid email strings are rejected."""
        data = self.valid_data.copy()
        data["email"] = "not-an-email"
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username="alice").exists())

    def test_weak_password_rejection(self):
        """Passwords shorter than 8 chars or lacking required char classes are rejected."""
        data = self.valid_data.copy()
        data["password"] = "123456"
        data["confirm_password"] = "123456"
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username="alice").exists())

    def test_password_confirmation_mismatch(self):
        """Mismatched passwords return form error."""
        data = self.valid_data.copy()
        data["confirm_password"] = "DifferentPass123!"
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username="alice").exists())

    def test_duplicate_username_case_insensitive(self):
        """Duplicate usernames (case-insensitive) are rejected."""
        self.client.post(self.signup_url, self.valid_data)
        dup_data = self.valid_data.copy()
        dup_data["username"] = "ALICE"
        dup_data["email"] = "another@example.com"
        response = self.client.post(self.signup_url, dup_data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(User.objects.filter(username__iexact="alice").count(), 1)

    def test_duplicate_email_case_insensitive(self):
        """Duplicate email addresses (case-insensitive) are rejected."""
        self.client.post(self.signup_url, self.valid_data)
        dup_data = self.valid_data.copy()
        dup_data["username"] = "alice2"
        dup_data["email"] = "ALICE@example.com"
        response = self.client.post(self.signup_url, dup_data)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username="alice2").exists())


class AuthenticationTests(TestCase):
    """Test suite verifying login, logout, and session lifecycle."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="bob",
            email="bob@example.com",
            password="BobStrongPassword123"
        )
        self.login_url = reverse("login")
        self.logout_url = reverse("logout")

    def test_correct_credentials_login(self):
        """Valid credentials authenticate user and establish session."""
        response = self.client.post(self.login_url, {
            "username": "bob",
            "password": "BobStrongPassword123"
        })
        self.assertRedirects(response, reverse("dashboard"))
        self.assertIn("_auth_user_id", self.client.session)

    def test_incorrect_password_rejected_with_generic_error(self):
        """Wrong password fails and emits generic error without revealing account existence."""
        response = self.client.post(self.login_url, {
            "username": "bob",
            "password": "WrongPassword999"
        })
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("_auth_user_id", self.client.session)
        # Verify generic error message is present
        messages = list(response.context["messages"])
        self.assertTrue(any("Invalid username or password" in str(m) for m in messages))

    def test_unknown_username_rejected_with_same_generic_error(self):
        """Unknown username emits identical generic error message (user enumeration defense)."""
        response = self.client.post(self.login_url, {
            "username": "nonexistent_user",
            "password": "SomePassword123"
        })
        self.assertEqual(response.status_code, 200)
        messages = list(response.context["messages"])
        self.assertTrue(any("Invalid username or password" in str(m) for m in messages))

    def test_session_invalidation_on_logout(self):
        """Logging out flushes session and prevents subsequent access to protected views."""
        self.client.login(username="bob", password="BobStrongPassword123")
        self.assertIn("_auth_user_id", self.client.session)

        # Execute logout
        logout_res = self.client.post(self.logout_url)
        self.assertRedirects(logout_res, reverse("login"))
        self.assertNotIn("_auth_user_id", self.client.session)

        # Attempt to access dashboard again
        dash_res = self.client.get(reverse("dashboard"))
        self.assertRedirects(dash_res, f"{reverse('login')}?next={reverse('dashboard')}")


class AuthorizationGuardTests(TestCase):
    """Test suite verifying protected routes cannot be accessed anonymously."""

    def setUp(self):
        self.client = Client()

    def test_dashboard_requires_authentication(self):
        response = self.client.get(reverse("dashboard"))
        self.assertRedirects(response, f"{reverse('login')}?next={reverse('dashboard')}")

    def test_profile_requires_authentication(self):
        response = self.client.get(reverse("profile"))
        self.assertRedirects(response, f"{reverse('login')}?next={reverse('profile')}")

    def test_change_password_requires_authentication(self):
        response = self.client.get(reverse("change_password"))
        self.assertRedirects(response, f"{reverse('login')}?next={reverse('change_password')}")


class SecurityVulnerabilityTests(TestCase):
    """Test suite specifically validating protection against OWASP Top 10 vulnerabilities."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="target_user",
            email="target@example.com",
            password="TargetPassword123"
        )

    def test_sql_injection_defense_in_login(self):
        """
        Attack: Classic SQL Injection payload ' OR '1'='1
        Expected: Django ORM parameter binding neutralizes the payload; login is rejected.
        """
        sqli_payload = "' OR '1'='1"
        response = self.client.post(reverse("login"), {
            "username": sqli_payload,
            "password": "arbitrary_password",
        })
        self.assertNotIn("_auth_user_id", self.client.session)
        messages = list(response.context["messages"]) if "messages" in response.context else []
        self.assertTrue(any("Invalid username or password" in str(m) for m in messages))

    def test_xss_auto_escaping(self):
        """
        Attack: Stored XSS payload <script>alert('XSS')</script> in full_name
        Expected: Django template engine escapes '<' and '>' to '&lt;' and '&gt;' preventing browser execution.
        """
        client = Client()
        client.login(username="target_user", password="TargetPassword123")
        xss_payload = '<script>alert("XSS")</script>'
        
        # Save payload via profile
        profile, _ = UserProfile.objects.get_or_create(user=self.user)
        profile.full_name = xss_payload
        profile.save()

        response = client.get(reverse("dashboard"))
        content = response.content.decode("utf-8")
        
        # Must be escaped, must NOT be raw executable script
        self.assertIn("&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;", content)
        self.assertNotIn("<script>alert(\"XSS\")</script>", content)

    def test_csrf_protection_enforced_on_post(self):
        """
        Attack: State-changing POST request submitted without CSRF token.
        Expected: Rejected with HTTP 403 Forbidden.
        """
        csrf_client = Client(enforce_csrf_checks=True)
        # POST without obtaining or submitting csrfmiddlewaretoken
        response = csrf_client.post(reverse("login"), {
            "username": "target_user",
            "password": "TargetPassword123"
        })
        self.assertEqual(response.status_code, 403)

    def test_password_not_plaintext_in_database(self):
        """Password must never be saved in plaintext; must use PBKDF2 hash algorithm."""
        user = User.objects.get(username="target_user")
        self.assertFalse(user.password.startswith("TargetPassword123"))
        self.assertTrue(user.password.startswith("pbkdf2_sha256$"))

    def test_brute_force_rate_limiting(self):
        """
        Attack: 5 consecutive failed login attempts.
        Expected: Subsequent attempts are rate-restricted with a lock warning.
        """
        client = Client()
        for i in range(5):
            client.post(reverse("login"), {
                "username": "target_user",
                "password": f"WrongPass{i}"
            })

        # 6th attempt should trigger rate limiting lockout
        response = client.post(reverse("login"), {
            "username": "target_user",
            "password": "TargetPassword123"  # Even if correct, blocked by lockout window!
        })
        messages = [str(m) for m in response.context["messages"]]
        self.assertTrue(any("Too many failed login attempts" in m for m in messages))
        self.assertNotIn("_auth_user_id", client.session)
