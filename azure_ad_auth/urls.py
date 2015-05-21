from .views import auth, complete
from django.conf.urls import url


urlpatterns = [
    url(r'^login/$', auth, name='azure_login'),
    url(r'^complete/$', complete, name='azure_complete'),
]