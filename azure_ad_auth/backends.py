from base64 import urlsafe_b64encode
from hashlib import sha1
import logging

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ObjectDoesNotExist

from .utils import (
    RESPONSE_MODE,
    get_login_url,
    get_logout_url,
    get_token_payload,
    get_token_payload_email,
)

logger = logging.getLogger("azure_ad_auth")


class AzureActiveDirectoryBackend:
    USER_CREATION = getattr(settings, "AAD_USER_CREATION", True)
    USER_MAPPING = getattr(settings, "AAD_USER_MAPPING", {})
    USER_STATIC_MAPPING = getattr(settings, "AAD_USER_STATIC_MAPPING", {})
    GROUP_MAPPING = getattr(settings, "AAD_GROUP_MAPPING", {})
    RESPONSE_MODE = RESPONSE_MODE

    supports_anonymous_user = False
    supports_inactive_user = True
    supports_object_permissions = False

    def __init__(self):
        self.User = get_user_model()

    def login_url(self, redirect_uri, nonce, state):
        return get_login_url(
            redirect_uri=redirect_uri,
            nonce=nonce,
            state=state,
        )

    def logout_url(self, redirect_uri):
        return get_logout_url(redirect_uri=redirect_uri)

    def authenticate(
        self,
        request=None,  # noqa: ARG002
        token=None,
        nonce=None,
        **kwargs,
    ):
        if token is None:
            logger.error("aad_authenticate: token is None")
            return None

        payload = get_token_payload(token=token, nonce=nonce)
        email = get_token_payload_email(payload)

        if email is None:
            logger.error("aad_authenticate: email is None")
            return None

        email = email.lower()

        new_user = {"email": email}

        users = self.User.objects.filter(email=email)
        if len(users) == 0 and self.USER_CREATION:
            user = self.create_user(new_user, payload)
            logger.info(f"aad_authenticate: No user, creating {user}")

            # Try mapping group claims to matching groups
            self.add_user_to_group(user, payload)
        elif len(users) == 1:
            user = users[0]
            logger.debug(f"aad_authenticate: user is {user}")

            # Try mapping group claims to matching groups
            self.add_user_to_group(user, payload)
        else:
            logger.error(f"aad_authenticate: More than 1 user matches email {email}")
            return None

        user.backend = f"{self.__class__.__module__}.{self.__class__.__name__}"
        return user

    def get_user(self, user_id):
        try:
            user = self.User.objects.get(pk=user_id)
            return user
        except self.User.DoesNotExist:
            return None

    def add_user_to_group(self, user, payload):
        if user is not None and "groups" in payload:
            logger.debug(f"aad_add_user_to_group: payload.groups={payload['groups']}")
            for groupid in payload["groups"]:
                logger.debug(f"aad_add_user_to_group: groupid: {groupid}")
                if groupid not in self.GROUP_MAPPING:
                    logger.error("aad_add_user_to_group: groupid not in GROUP_MAPPING")
                    continue
                group_name = self.GROUP_MAPPING[groupid]
                logger.debug(f"aad_add_user_to_group: group_name={group_name}")
                try:
                    group = Group.objects.get(name=group_name)
                    user.groups.add(group)
                    logger.info(
                        f"aad_add_user_to_group: {user} added to group: {group_name}"
                    )
                except ObjectDoesNotExist:
                    logger.info(
                        f"aad_add_user_to_group: group does not exist: {group_name}"
                    )
        else:
            logger.info(f"aad_add_user_to_group: No groups for user: {user}")

    def create_user(self, user_kwargs, payload):
        username_field = getattr(self.User, "USERNAME_FIELD", "username")
        email = user_kwargs.get("email", None)

        if username_field and username_field != "email" and email:
            user_kwargs[username_field] = self.username_generator(email)

        for user_field, token_field in self.USER_MAPPING.items():
            if token_field not in payload:
                continue
            user_kwargs[user_field] = payload[token_field]

        for user_field, val in self.USER_STATIC_MAPPING.items():
            user_kwargs[user_field] = val

        return self.User.objects.create_user(**user_kwargs)

    @staticmethod
    def username_generator(email):
        return urlsafe_b64encode(
            sha1(  # noqa: S324
                email.encode("utf-8"),
            ).digest(),
        ).rstrip(
            b"=",
        )
