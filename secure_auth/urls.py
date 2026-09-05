"""
URL configuration for secure_auth project.
"""

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("accounts.urls")),
]

# Custom Error Handlers to prevent sensitive information leakage
handler400 = "accounts.error_handlers.error_400"
handler403 = "accounts.error_handlers.error_403"
handler404 = "accounts.error_handlers.error_404"
handler500 = "accounts.error_handlers.error_500"
