"""
CSRF protection middleware for aiohttp.

Generates a random token per browser session (stored in a cookie),
requires it as a hidden form field on every POST request.
"""

import hashlib
import hmac
import logging
import os
import time

from aiohttp import web

logger = logging.getLogger(__name__)

# Token validity: 24 hours
TOKEN_MAX_AGE = 86400
COOKIE_NAME = "_csrf"
FORM_FIELD = "_csrf"

# Secret key for signing tokens. Generated once per process.
# In production, this means tokens are invalidated on restart,
# which is acceptable for a tool like this.
_SECRET = os.urandom(32)


def _generate_token() -> str:
    """Generate a signed CSRF token."""
    timestamp = str(int(time.time()))
    nonce = os.urandom(16).hex()
    payload = f"{timestamp}:{nonce}"
    sig = hmac.new(_SECRET, payload.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{payload}:{sig}"


def _validate_token(token: str) -> bool:
    """Validate a CSRF token's signature and age."""
    if not token:
        return False
    try:
        parts = token.split(":")
        if len(parts) != 3:
            return False
        timestamp, nonce, sig = parts
        # Check age
        if time.time() - int(timestamp) > TOKEN_MAX_AGE:
            return False
        # Check signature
        payload = f"{timestamp}:{nonce}"
        expected = hmac.new(_SECRET, payload.encode(), hashlib.sha256).hexdigest()[:32]
        return hmac.compare_digest(sig, expected)
    except (ValueError, TypeError):
        return False


def get_token(request: web.Request) -> str:
    """Get or create CSRF token for this request."""
    token = request.cookies.get(COOKIE_NAME, "")
    if _validate_token(token):
        return token
    return _generate_token()


def csrf_field(request: web.Request) -> str:
    """Return an HTML hidden input field with the CSRF token."""
    token = get_token(request)
    return f'<input type="hidden" name="{FORM_FIELD}" value="{token}">'


@web.middleware
async def csrf_middleware(request: web.Request, handler):
    """
    Middleware that:
    - Sets a CSRF cookie on every response
    - Validates the CSRF token on every POST request
    """
    if request.method == "POST":
        # Skip CSRF check for API endpoints (they don't use forms)
        if request.path.startswith("/api/"):
            return await handler(request)

        # Get token from form data
        try:
            data = await request.post()
            form_token = data.get(FORM_FIELD, "")
        except Exception:
            form_token = ""

        # Get token from cookie
        cookie_token = request.cookies.get(COOKIE_NAME, "")

        # Both must be present and match
        if not form_token or not cookie_token:
            logger.warning("CSRF: missing token on POST %s", request.path)
            raise web.HTTPForbidden(text="CSRF token missing")

        if not hmac.compare_digest(form_token, cookie_token):
            logger.warning("CSRF: token mismatch on POST %s", request.path)
            raise web.HTTPForbidden(text="CSRF token invalid")

        if not _validate_token(form_token):
            logger.warning("CSRF: expired/invalid token on POST %s", request.path)
            raise web.HTTPForbidden(text="CSRF token expired")

    # Process the request
    response = await handler(request)

    # Set/refresh the CSRF cookie on every response
    if isinstance(response, web.Response):
        token = get_token(request)
        response.set_cookie(
            COOKIE_NAME, token,
            max_age=TOKEN_MAX_AGE,
            httponly=True,
            samesite="Strict",
            path="/",
        )

    return response
