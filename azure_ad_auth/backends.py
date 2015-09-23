from .utils import get_email_from_token, get_login_url, get_logout_url, RESPONSE_MODE
from base64 import urlsafe_b64encode
from django.conf import settings
try:
    from django.contrib.auth import get_user_model
except ImportError:
    from django.contrib.auth.models import User

    def get_user_model(*args, **kwargs):
        return User
from hashlib import sha1


class AzureActiveDirectoryBackend(object):
    USER_CREATION = getattr(settings, 'AAD_USER_CREATION', True)
    RESPONSE_MODE = RESPONSE_MODE

    supports_anonymous_user = False
    supports_inactive_user = True
    supports_object_permissions = False

    def __init__(self):
        self.User = get_user_model()

    def login_url(self, redirect_uri, nonce, state):
        return get_login_url(redirect_uri, nonce, state)

    def logout_url(redirect_uri):
        return get_logout_url(redirect_uri)

    def authenticate(self, token=None, nonce=None, **kwargs):
        if token is None:
            return None

        email = get_email_from_token(token, nonce)

        if email is None:
            return None

        users = self.User.objects.filter(email=email)
        if len(users) == 0:
            user = self.create_user(email)
        elif len(users) == 1:
            user = users[0]
        else:
            return None
        user.backend = '{}.{}'.format(self.__class__.__module__, self.__class__.__name__)
        return user

    def get_user(self, user_id):
        try:
            user = self.User.objects.get(pk=user_id)
            return user
        except self.User.DoesNotExist:
            return None

    def create_user(self, email):
        if self.USER_CREATION:
            username_field = getattr(self.User, 'USERNAME_FIELD', 'username')
            user_kwargs = {'email': email}
            user_kwargs[username_field] = self.username_generator(email)
            return self.User.objects.create_user(**user_kwargs)
        else:
            return None

    @staticmethod
    def username_generator(email):
        return urlsafe_b64encode(sha1(email).digest()).rstrip(b'=')
