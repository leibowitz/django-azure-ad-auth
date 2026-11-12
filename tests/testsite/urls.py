from django.contrib import admin
from django.urls import include, path

from .views import login_successful

urlpatterns = [
    path("admin/", admin.site.urls),
    path("azure/", include("azure_ad_auth.urls")),
    path("login_successful/", login_successful, name="login_successful"),
]
