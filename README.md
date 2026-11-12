Django Azure AD Auth Redux
==========================

*Django Azure AD Auth* allows you to authenticate through Azure Active Directory.

  This fork has the following additional features:
  - Add the specification of the decode algorithm per newer PyJWT requirements.
  - Supports Django 5.2 LTS, 6.0, and 6.1 on Python 3.12–3.15, as listed below.

Compatibility
-------------

| Django | Python |
| --- | --- |
| 5.2 LTS (5.2.8+ for Python 3.14) | 3.12, 3.13, 3.14 |
| 6.0 | 3.12, 3.13, 3.14 |
| 6.1.3+ | 3.12, 3.13, 3.14, 3.15 |

Use the latest patch release in each series. Python 3.15 requires Django 6.1.3
or newer; the package enforces this requirement during installation. Python 3.11
and Django versions older than 5.2 are not supported.

Development
-----------

Install the project and run its checks and tests:

```sh
uv sync --locked
uv run --locked python -Wd tests/manage.py check
uv run --locked python -Wd tests/manage.py test tests
uv build
```

CI tests all combinations in the table above and checks built distributions.
Authentication tests use local signing keys and mocked HTTP responses; no Azure
account or credentials are required. The demonstration project uses placeholder
Azure identifiers, which must be replaced to try an actual Azure login.

Installation
------------

Run `pip install django-azure-ad-auth-redux`

Add the `AzureActiveDirectoryBackend` to your `AUTHENTICATION_BACKENDS` setting:

```python
AUTHENTICATION_BACKENDS = (
    ...
    "azure_ad_auth.backends.AzureActiveDirectoryBackend",
)
```

Settings
--------

### AAD_TENANT_ID

The Azure Tenant ID. It can be found in the URL of the Azure Management Portal.

### AAD_CLIENT_ID

The Azure Application Client ID.

### AAD_AUTHORITY

**default:** `"https://login.microsoftonline.com"`
The domain that is used for authorization, the federation metadata document, and logging out.

### AAD_SCOPE

**default:** `"openid"`
OAuth scope parameter.

### AAD_RESPONSE_TYPE

**default:** `"id_token"`
Tells OAuth to return a JWT token in its response.

### AAD_RESPONSE_MODE

**default:** `"form_post"`
Defines how the response parameters are returned. Valid choices are `fragment` or `form_post`.

### AAD_USER_CREATION

**default:** `True`
Allow creation of new users after successful authentication.

### AAD_USER_MAPPING

**default:** `{}`
Map fields from the token to the user, to be used on creation.

### AAD_USER_STATIC_MAPPING

**default:** `{}`
Map static values to user fields on creation.

### AAD_GROUP_MAPPING

**default:** `{}`
Map group ids to group names for user permissions.
