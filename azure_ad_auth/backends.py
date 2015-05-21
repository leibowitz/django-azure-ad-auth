from base64 import b64decode, urlsafe_b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_der_x509_certificate
from django.conf import settings
try:
    from django.contrib.auth import get_user_model
except ImportError:
    from django.contrib.auth.models import User

    def get_user_model(*args, **kwargs):
        return User
from hashlib import sha1
import jwt
from lxml import etree
import requests
from urllib import urlencode


class AzureActiveDirectoryBackend(object):
    AUTHORIZATION_ENDPOINT = getattr(settings, 'AAD_AUTHORIZATION_ENDPOINT', 'https://login.microsoftonline.com/common/oauth2/authorize')
    SCOPE = getattr(settings, 'AAD_SCOPE', 'openid')
    RESPONSE_TYPE = getattr(settings, 'AAD_RESPONSE_TYPE', 'id_token')
    RESPONSE_MODE = getattr(settings, 'AAD_RESPONSE_MODE', 'form_post')
    CLIENT_ID = getattr(settings, 'AAD_CLIENT_ID', '')
    FEDERATION_METADATA_DOCUMENT = getattr(settings, 'AAD_FEDERATION_METADATA_DOCUMENT')

    USER_CREATION = getattr(settings, 'AAD_USER_CREATION', True)

    supports_anonymous_user = False
    supports_inactive_user = True
    supports_object_permissions = False

    def __init__(self):
        self.User = get_user_model()

    def auth_url(self, nonce, state):
        params = urlencode({
            'response_type': self.RESPONSE_TYPE,
            'response_mode': self.RESPONSE_MODE,
            'scope': self.SCOPE,
            'client_id': self.CLIENT_ID,
            'nonce': nonce,
            'state': state,
        })
        return '{endpoint}?{params}'.format(
            endpoint=self.AUTHORIZATION_ENDPOINT,
            params=params
        )

    def _fetch_federation_metadata_document(self, url):
        response = requests.get(url)
        if not response.ok:
            raise
        return response

    def _get_x509_DERs(self, federation_metadata_document):
        document = etree.fromstring(federation_metadata_document)
        certificate_elems = document.findall('.//{http://www.w3.org/2000/09/xmldsig#}X509Certificate')
        b64encoded_DERs = {certificate_elem.text for certificate_elem in certificate_elems}
        return [b64decode(b64encoded_DER) for b64encoded_DER in b64encoded_DERs]

    def _get_keys(self):
        try:
            response = self._fetch_federation_metadata_document(self.FEDERATION_METADATA_DOCUMENT)
            x509_DERs = self._get_x509_DERs(response.text)
            keys = [load_der_x509_certificate(x509_DER, default_backend()).public_key() for x509_DER in x509_DERs]
        except:
            keys = []
        return keys

    def authenticate(self, token=None, nonce=None, **kwargs):
        for key in self._get_keys():
            try:
                payload = jwt.decode(token, key=key, audience=self.CLIENT_ID)
                if payload['nonce'] == nonce:
                    email = payload['upn']
                    users = self.User.objects.filter(email=email)
                    if len(users) == 0:
                        user = self.create_user(email)
                    elif len(users) == 1:
                        user = users[0]
                    else:
                        return None
                    user.backend = '{}.{}'.format(self.__class__.__module__, self.__class__.__name__)
                    return user
            except (jwt.InvalidTokenError, IndexError) as e:
                pass

        return None

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
