"""
Custom safe HTTP error handlers that prevent disclosure of internal stack traces.
"""

from django.shortcuts import render


def error_400(request, exception=None):
    return render(
        request,
        "error.html",
        {
            "status_code": 400,
            "title": "Bad Request",
            "message": "The request could not be processed due to invalid syntax or parameters.",
        },
        status=400,
    )


def error_403(request, exception=None):
    return render(
        request,
        "error.html",
        {
            "status_code": 403,
            "title": "Forbidden",
            "message": "You do not have permission to access this resource or the CSRF token was invalid.",
        },
        status=403,
    )


def error_404(request, exception=None):
    return render(
        request,
        "error.html",
        {
            "status_code": 404,
            "title": "Page Not Found",
            "message": "The page you are looking for does not exist or has been moved.",
        },
        status=404,
    )


def error_500(request):
    return render(
        request,
        "error.html",
        {
            "status_code": 500,
            "title": "Server Error",
            "message": "An unexpected error occurred on the server. Please try again later.",
        },
        status=500,
    )
