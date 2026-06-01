"""URL configuration for phishing_detector project."""
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('detector.urls')),
]
