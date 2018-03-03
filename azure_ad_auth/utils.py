from base64 import b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_der_x509_certificate
from django.conf import settings
import jwt
from lxml import etree
import requests
from urllib import urlencode


AUTHORITY = getattr(settings, 'AAD_AUTHORITY', 'https://login.microsoftonline.com')
SCOPE = getattr(settings, 'AAD_SCOPE', 'openid')
RESPONSE_TYPE = getattr(settings, 'AAD_RESPONSE_TYPE', 'id_token')
RESPONSE_MODE = getattr(settings, 'AAD_RESPONSE_MODE', 'form_post')
TENANT_ID = getattr(settings, 'AAD_TENANT_ID')
CLIENT_ID = getattr(settings, 'AAD_CLIENT_ID')


def get_login_url(authority=AUTHORITY, response_type=RESPONSE_TYPE, response_mode=RESPONSE_MODE, scope=SCOPE, client_id=CLIENT_ID, redirect_uri=None, nonce=None, state=None):
    param_dict = {
        'response_type': response_type,
        'response_mode': response_mode,
        'scope': scope,
        'client_id': client_id,
    }
    if redirect_uri is not None:
        param_dict['redirect_uri'] = redirect_uri
    if nonce is not None:
        param_dict['nonce'] = nonce
    if state is not None:
        param_dict['state'] = state
    params = urlencode(param_dict)
    return '{authority}/common/oauth2/authorize?{params}'.format(
        authority=authority,
        params=params,
    )


def get_logout_url(redirect_uri, authority=AUTHORITY):
    params = urlencode({
        'post_logout_redirect_uri': redirect_uri,
    })
    return '{authority}/common/oauth2/logout?{params}'.format(
        authority=authority,
        params=params,
    )

def get_federation_metadata_document_url(authority=AUTHORITY, tenant_id=TENANT_ID):
    return '{authority}/{tenant_id}/federationmetadata/2007-06/federationmetadata.xml'.format(
        authority=authority,
        tenant_id=tenant_id,
    )


def parse_x509_DER_list(federation_metadata_document):
    document = etree.fromstring(federation_metadata_document)
    certificate_elems = document.findall('.//{http://www.w3.org/2000/09/xmldsig#}X509Certificate')
    b64encoded_DERs = {certificate_elem.text for certificate_elem in certificate_elems}
    return [b64decode(b64encoded_DER) for b64encoded_DER in b64encoded_DERs]


def get_public_keys():
    try:
        federation_metadata_document_url = get_federation_metadata_document_url()
        response = requests.get(federation_metadata_document_url)
        if not response.ok:
            raise
        response.encoding = response.apparent_encoding
        x509_DER_list = parse_x509_DER_list(response.text.encode('utf-8'))
        keys = [load_der_x509_certificate(x509_DER, default_backend()).public_key() for x509_DER in x509_DER_list]
    except:
        keys = []
    return keys


def get_email_from_token(token=None, audience=CLIENT_ID, nonce=None):
    for key in get_public_keys():
        try:
            payload = jwt.decode(token, key=key, audience=audience)

            if payload['nonce'] != nonce:
                continue

            return payload['upn']
        except (jwt.InvalidTokenError, IndexError) as e:
            pass

    return None
