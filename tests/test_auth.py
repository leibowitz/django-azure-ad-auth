from base64 import b64encode
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.conf import settings
from django.contrib.auth import BACKEND_SESSION_KEY, SESSION_KEY, get_user_model
from django.contrib.auth.models import Group
from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from azure_ad_auth import utils
from azure_ad_auth.backends import AzureActiveDirectoryBackend


class BackendTests(TestCase):
    def setUp(self):
        self.backend = AzureActiveDirectoryBackend()
        self.payload = {"upn": "Alice@Example.com", "given_name": "Alice"}
        self.payload_patch = patch(
            "azure_ad_auth.backends.get_token_payload", return_value=self.payload
        )
        self.payload_patch.start()
        self.addCleanup(self.payload_patch.stop)

    def authenticate(self):
        return self.backend.authenticate(token="test-token", nonce="test-nonce")

    def test_creates_user_with_text_username(self):
        user = self.authenticate()
        self.assertEqual(user.email, "alice@example.com")
        self.assertIsInstance(user.username, str)
        self.assertEqual(
            user.username, self.backend.username_generator("alice@example.com")
        )
        user.refresh_from_db()
        self.assertEqual(
            user.username, self.backend.username_generator("alice@example.com")
        )
        self.assertFalse(user.has_usable_password())

    def test_existing_user_is_reused(self):
        existing = get_user_model().objects.create_user(
            username="alice", email="alice@example.com"
        )
        self.assertEqual(self.authenticate().pk, existing.pk)
        self.assertEqual(get_user_model().objects.count(), 1)

    def test_user_creation_can_be_disabled(self):
        self.backend.USER_CREATION = False
        self.assertIsNone(self.authenticate())
        self.assertFalse(get_user_model().objects.exists())

    def test_duplicate_email_is_rejected(self):
        for username in ("alice", "other"):
            get_user_model().objects.create_user(
                username=username, email="alice@example.com"
            )
        self.assertIsNone(self.authenticate())

    def test_missing_token_is_rejected(self):
        self.assertIsNone(self.backend.authenticate())

    def test_missing_email_is_rejected(self):
        self.payload.clear()
        self.assertIsNone(self.authenticate())

    def test_invalid_payload_is_rejected(self):
        with patch("azure_ad_auth.backends.get_token_payload", return_value=None):
            self.assertIsNone(self.authenticate())

    def test_user_field_and_static_mappings(self):
        self.backend.USER_MAPPING = {
            "first_name": "given_name",
            "last_name": "missing_claim",
        }
        self.backend.USER_STATIC_MAPPING = {"is_staff": True}
        user = self.authenticate()
        self.assertEqual(user.first_name, "Alice")
        self.assertEqual(user.last_name, "")
        self.assertTrue(user.is_staff)

    def test_group_mapping_for_new_and_existing_users(self):
        group = Group.objects.create(name="Editors")
        self.backend.GROUP_MAPPING = {
            "editors-id": "Editors",
            "missing-id": "Does not exist",
        }
        self.payload["groups"] = ["editors-id", "unknown-id", "missing-id"]
        user = self.authenticate()
        self.assertEqual(list(user.groups.all()), [group])
        user.groups.clear()
        self.authenticate()
        self.assertEqual(list(user.groups.all()), [group])

    def test_get_user_and_missing_user(self):
        user = self.authenticate()
        self.assertEqual(self.backend.get_user(user.pk), user)
        self.assertIsNone(self.backend.get_user(user.pk + 1))


class TokenTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(cls.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .sign(cls.key, hashes.SHA256())
        )
        encoded = b64encode(certificate.public_bytes(serialization.Encoding.DER))
        cls.metadata = (
            '<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            f"<ds:X509Certificate>{encoded.decode('ascii')}</ds:X509Certificate>"
            "</root>"
        )

    def setUp(self):
        response = Mock(ok=True, text=self.metadata, apparent_encoding="utf-8")
        self.http_patch = patch(
            "azure_ad_auth.utils.requests.get", return_value=response
        )
        self.http_patch.start()
        self.addCleanup(self.http_patch.stop)

    def token(self, **overrides):
        payload = {
            "aud": settings.AAD_CLIENT_ID,
            "nonce": "test-nonce",
            "upn": "alice@example.com",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        }
        payload.update(overrides)
        return jwt.encode(payload, self.key, algorithm="RS256")

    def test_signed_token_verified_using_federation_certificate(self):
        payload = utils.get_token_payload(self.token(), nonce="test-nonce")
        self.assertEqual(payload["upn"], "alice@example.com")

    def test_wrong_nonce_is_rejected(self):
        self.assertIsNone(utils.get_token_payload(self.token(), nonce="wrong"))

    def test_wrong_audience_is_rejected(self):
        self.assertIsNone(
            utils.get_token_payload(self.token(aud="other"), nonce="test-nonce")
        )

    def test_expired_token_is_rejected(self):
        token = self.token(exp=datetime.now(timezone.utc) - timedelta(minutes=1))
        self.assertIsNone(utils.get_token_payload(token, nonce="test-nonce"))

    def test_wrong_signing_key_is_rejected(self):
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with patch(
            "azure_ad_auth.utils.get_public_keys", return_value=[other_key.public_key()]
        ):
            self.assertIsNone(utils.get_token_payload(self.token(), nonce="test-nonce"))

    def test_unavailable_metadata_is_rejected(self):
        with patch("azure_ad_auth.utils.requests.get", side_effect=OSError("offline")):
            self.assertIsNone(utils.get_token_payload(self.token(), nonce="test-nonce"))

    def test_logout_url_encodes_redirect(self):
        url = utils.get_logout_url("https://example.com/?a=1&b=2")
        self.assertEqual(
            parse_qs(urlparse(url).query)["post_logout_redirect_uri"],
            ["https://example.com/?a=1&b=2"],
        )


class CallbackTests(TestCase):
    def start_login(self):
        return self.client.get(reverse("azure_login"))

    def test_login_redirect_saves_state_and_nonce(self):
        response = self.start_login()
        self.assertEqual(response.status_code, 302)
        query = parse_qs(urlparse(response.url).query)
        self.assertEqual(query["state"], [self.client.session["state"]])
        self.assertEqual(query["nonce"], [self.client.session["nonce"]])
        self.assertEqual(query["redirect_uri"], ["http://testserver/azure/complete/"])
        self.assertIn("no-store", response.headers["Cache-Control"])

    def test_callback_logs_user_into_session(self):
        self.start_login()
        nonce = self.client.session["nonce"]
        with patch(
            "azure_ad_auth.backends.get_token_payload",
            return_value={"upn": "alice@example.com"},
        ) as decode:
            response = self.client.post(
                reverse("azure_complete"),
                {"state": self.client.session["state"], "id_token": "test-token"},
            )
        decode.assert_called_once_with(token="test-token", nonce=nonce)
        self.assertRedirects(response, settings.LOGIN_REDIRECT_URL)
        user = get_user_model().objects.get(email="alice@example.com")
        self.assertEqual(self.client.session[SESSION_KEY], str(user.pk))
        self.assertEqual(
            self.client.session[BACKEND_SESSION_KEY],
            "azure_ad_auth.backends.AzureActiveDirectoryBackend",
        )

    def test_wrong_state_does_not_authenticate(self):
        self.start_login()
        with patch(
            "azure_ad_auth.views.AzureActiveDirectoryBackend.authenticate"
        ) as auth:
            response = self.client.post(
                reverse("azure_complete"), {"state": "wrong", "id_token": "token"}
            )
        auth.assert_not_called()
        self.assertEqual(response.status_code, 302)
        self.assertNotIn(SESSION_KEY, self.client.session)

    def test_invalid_token_does_not_log_in(self):
        self.start_login()
        with patch("azure_ad_auth.backends.get_token_payload", return_value=None):
            response = self.client.post(
                reverse("azure_complete"),
                {"state": self.client.session["state"], "id_token": "token"},
            )
        self.assertEqual(response.status_code, 302)
        self.assertNotIn(SESSION_KEY, self.client.session)

    def test_admin_url_resolves(self):
        response = self.client.get(reverse("admin:index"))
        self.assertEqual(response.status_code, 302)
