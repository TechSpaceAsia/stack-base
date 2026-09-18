"""HTTP client core: retrying, Bearer-authenticated JSON requests.

Every outbound call to the Hostinger and Cloudflare REST APIs goes through
`request()`. It applies a fixed timeout, retries transient failures (HTTP
429/502/503/504 and low-level network errors) with backoff -- honouring a
`Retry-After` response header when the server sends one -- and never retries
any other 4xx response. On failure it raises `ApiError`. The message, hint,
and captured body are always passed through `secrets.redact()` first, so the
bearer token can never leak into a log line or a top-level error message even
if a misbehaving server echoes it back.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from stackbase import __version__
from stackbase.errors import StackError
from stackbase.secrets import redact

_RETRYABLE_STATUSES = frozenset({429, 502, 503, 504})
_MAX_BODY_CHARS = 500
_MAX_DETAIL_CHARS = 300
_MAX_BACKOFF_SECONDS = 30.0

# Both Hostinger and Cloudflare sit behind Cloudflare's own edge, which
# rejects urllib's default User-Agent ("Python-urllib/3.x") with an HTTP 403
# / "error code: 1010" block -- verified against the live Hostinger API
# (curl with this exact string: 200; urllib's default: 403). An explicit,
# identifying User-Agent -- plus an explicit Accept, since we never want to
# rely on urllib's defaults here either -- sidesteps it.
USER_AGENT = f"stack-base/{__version__} (+https://github.com/TechSpaceAsia/stack-base)"

# Hints are written for whoever is running `bin/up`, not necessarily an
# infra person -- they say what to check, not what went wrong internally.
_STATUS_HINTS: dict[int, str] = {
    400: "the request was malformed -- check the payload being sent",
    401: "the API token is wrong or expired",
    403: "the API token doesn't have permission for this action",
    404: "the resource wasn't found -- check the ID/URL",
    409: "there's a conflict with the current state -- check for a duplicate or stale resource",
    422: "the request was rejected -- check the payload against the API's validation rules",
    429: "the service is rate-limiting requests and retries were exhausted -- wait and try again later",
    502: "the upstream service is temporarily unavailable -- try again later",
    503: "the upstream service is temporarily unavailable -- try again later",
    504: "the upstream service timed out -- try again later",
}

# Cloudflare's own edge-firewall block page for a rejected request (as
# opposed to a 403 the *API itself* returns for a bad/under-scoped token).
# Not a token problem -- retrying with a different token would not help --
# so it gets its own hint instead of the generic 403 "permission" one.
_CLOUDFLARE_BLOCK_MARKER = "error code: 1010"
_CLOUDFLARE_FIREWALL_HINT = (
    "the provider's firewall blocked this request (Cloudflare error 1010) -- this is not a "
    "problem with your token; update stack-base, and if it persists report it"
)


class ApiError(StackError):
    """Raised when an HTTP call to an external API fails (after any retries)."""

    def __init__(self, message: str, hint: str, *, status: int, body: str) -> None:
        super().__init__(message, hint)
        self.status = status
        self.body = body


def request(
    method: str,
    url: str,
    *,
    token: str,
    json_body: Any = None,
    timeout: float = 30,
    retries: int = 4,
    sleep: Any = time.sleep,
) -> dict[str, Any] | list[Any]:
    """Make a Bearer-authenticated JSON HTTP call, retrying transient failures.

    `method` may be "DELETE" -- the guard against deleting VMs/billing lives
    in the API client layer (Task 3), not here.

    Retries on HTTP 429/502/503/504 and on `URLError` (connection-level
    failures), honouring a `Retry-After` response header when present and
    otherwise backing off exponentially (capped). Any other 4xx status is
    raised immediately, without retrying.

    `retries` is the total number of attempts made, not the number of
    *additional* attempts after the first -- the default of 4 means at most
    4 requests go out before `request()` gives up.

    An empty-body 2xx/204 response returns `{}`. A non-JSON body (success or
    error) still produces a well-formed result: for an error, an `ApiError`
    with `.status` and a truncated, redacted `.body`.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    data: bytes | None = None
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    attempts = max(retries, 1)
    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return _parse_success_body(method, url, resp.status, resp.read(), token)
        except urllib.error.HTTPError as exc:
            with exc:  # HTTPError wraps the response fp -- close it however we leave this branch
                body_bytes = exc.read()
                status = exc.code
                if status in _RETRYABLE_STATUSES and attempt < attempts:
                    retry_after = exc.headers.get("Retry-After") if exc.headers is not None else None
                    sleep(_delay_for_attempt(attempt, retry_after))
                    continue
                raise _api_error(method, url, status, body_bytes, token) from exc
        except urllib.error.URLError as exc:
            if attempt < attempts:
                sleep(_delay_for_attempt(attempt, None))
                continue
            raise _network_error(method, url, exc, token) from exc

    # Unreachable: the loop above always returns or raises on its last iteration.
    raise AssertionError("unreachable")


def _delay_for_attempt(attempt: int, retry_after: str | None) -> float:
    if retry_after is not None:
        try:
            return max(float(retry_after), 0.0)
        except ValueError:
            pass
    return min(2.0 ** (attempt - 1), _MAX_BACKOFF_SECONDS)


def _parse_success_body(
    method: str, url: str, status: int, body_bytes: bytes, token: str
) -> dict[str, Any] | list[Any]:
    if not body_bytes:
        return {}
    try:
        return json.loads(body_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _api_error(method, url, status, body_bytes, token) from exc


def _api_error(method: str, url: str, status: int, body_bytes: bytes, token: str) -> ApiError:
    text = body_bytes.decode("utf-8", errors="replace")
    body = redact(_truncate(text), [token])
    base = f"{method} {url} returned HTTP {status}"
    detail = _error_detail(text)
    message = redact(f"{base}: {detail}" if detail else base, [token])
    if status == 403 and _CLOUDFLARE_BLOCK_MARKER in text.lower():
        hint = _CLOUDFLARE_FIREWALL_HINT
    else:
        hint = _STATUS_HINTS.get(status, f"the API returned HTTP {status} -- check the response body for details")
    return ApiError(message, hint, status=status, body=body)


def _error_detail(text: str) -> str | None:
    """Fold a JSON error body's `message`/`errors` into one readable string.

    L2 (a live `--plan` run): a real HTTP 422 printed nothing beyond the
    generic `_STATUS_HINTS[422]` line, even with `--debug` -- the API's own
    explanation was sitting unread in the response body. Hostinger's 4xx
    bodies look like
    `{"message": "...", "errors": {"password": ["..."]}, "correlation_id": "..."}`
    -- sometimes with only `message`. This is deliberately generic (any
    JSON object shaped that way, not Hostinger-specific), but only reads a
    `message` string and an `errors` *object* (field -> message(s)); it
    never touches Cloudflare's own `errors` *list* envelope, which
    `cloudflare.py` already unpacks on the (different) `success: false`
    2xx path -- so there is no double-reporting between the two.

    Returns `None` for a non-JSON body or a JSON body with neither a usable
    `message` nor `errors`, so a plain "returned HTTP {status}" message is
    unchanged from before this existed.
    """
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None

    parts: list[str] = []
    message = parsed.get("message")
    if isinstance(message, str) and message.strip():
        parts.append(message.strip())

    errors = parsed.get("errors")
    if isinstance(errors, dict):
        for field, field_errors in errors.items():
            if not isinstance(field, str):
                continue
            joined = _join_field_errors(field_errors)
            if joined:
                parts.append(f"[{field}: {joined}]")

    if not parts:
        return None
    return _truncate(" ".join(parts), _MAX_DETAIL_CHARS)


def _join_field_errors(field_errors: Any) -> str | None:
    if isinstance(field_errors, str):
        return field_errors.strip() or None
    if isinstance(field_errors, list):
        joined = "; ".join(item.strip() for item in field_errors if isinstance(item, str) and item.strip())
        return joined or None
    return None


def _network_error(method: str, url: str, exc: urllib.error.URLError, token: str) -> ApiError:
    reason = redact(str(exc.reason), [token])
    message = redact(f"{method} {url} failed: {reason}", [token])
    hint = "check network connectivity and that the host is reachable"
    return ApiError(message, hint, status=0, body="")


def _truncate(text: str, limit: int = _MAX_BODY_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "... [truncated]"
