Django Azure AD Auth
======================

*Django Azure AD Auth* allows you to authenticate through Azure Active Directory.

Installation
------------

Run `pip install django-azure-ad-auth`

Add the `AzureActiveDirectoryBackend` to your `AUTHENTICATION_BACKENDS` setting:

```python
AUTHENTICATION_BACKENDS = (
    ...
    'azure_ad_auth.backends.AzureActiveDirectoryBackend',
)
```

Settings
--------

###AAD_CLIENT_ID
The Azure Application Client ID.

###AAD_FEDERATION_METADATA_DOCUMENT
The URL of the Federation Metadata Document. Usually of the form `https://login.microsoftonline.com/[azure_id]/federationmetadata/2007-06/federationmetadata.xml`. It contains the certificate with a public key to verify the JWT signature.

###AAD_AUTHORIZATION_ENDPOINT

**default:** `'https://login.microsoftonline.com/common/oauth2/authorize'`
The OAuth endpoint to redirect users to.

###AAD_SCOPE

**default:** `'openid'`
OAuth scope parameter.

###AAD_RESPONSE_TYPE

**default:** `'id_token'`
Tells OAuth to return a JWT token in its response.

###AAD_RESPONSE_MODE

**default:** `'form_post'`
Defines how the response parameters are returned. Valid choices are `fragment` or `form_post`.

###AAD_USER_CREATION

**default:** `True`
Allow creation of new users after successful authentication.
