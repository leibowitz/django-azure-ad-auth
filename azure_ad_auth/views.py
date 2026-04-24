import logging
import uuid
from urllib.parse import urlparse

from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME, login
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt

from .backends import AzureActiveDirectoryBackend

logger = logging.getLogger("azure_ad_auth")


@never_cache
def auth(request):
    logger.debug(f"aad_auth start: request={request}")
    backend = AzureActiveDirectoryBackend()
    redirect_uri = request.build_absolute_uri(reverse(complete))
    nonce = str(uuid.uuid4())
    request.session["nonce"] = nonce
    # logger.debug(f"aad_auth nonce: {nonce}")
    state = str(uuid.uuid4())
    request.session["state"] = state
    # logger.debug(f"aad_auth state: {state}")
    login_url = backend.login_url(
        redirect_uri=redirect_uri,
        nonce=nonce,
        state=state,
    )
    logger.debug(f"aad_auth exit: login_url={login_url}")
    return HttpResponseRedirect(login_url)


@never_cache
@csrf_exempt
def complete(request):
    logger.debug(f"aad_complete start: request={request}")
    backend = AzureActiveDirectoryBackend()
    method = "GET" if backend.RESPONSE_MODE == "fragment" else "POST"
    original_state = request.session.get("state")
    # logger.debug(f"aad_complete original_state: {original_state}")
    state = getattr(request, method).get("state")
    # logger.debug(f"aad_complete state: {state}")
    if original_state == state:
        # logger.debug("aad_complete states match")
        token = getattr(request, method).get("id_token")
        nonce = request.session.get("nonce")
        # logger.debug(f"aad_complete nonce: {nonce}")
        user = backend.authenticate(request=request, token=token, nonce=nonce)
        if user is not None:
            login(request, user)
            logger.info("aad_complete exit: user logged in")
            return HttpResponseRedirect(get_login_success_url(request))
    logger.debug("aad_complete exit: failure")
    return HttpResponseRedirect("failure")


def get_login_success_url(request):
    logger.debug(f"aad_get_login_success_url start: request={request}")
    redirect_to = request.GET.get(REDIRECT_FIELD_NAME, "")
    netloc = urlparse(redirect_to)[1]
    if not redirect_to or (netloc and netloc != request.get_host()):
        redirect_to = settings.LOGIN_REDIRECT_URL
    return redirect_to
