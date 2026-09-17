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

from stackbase.errors import StackError
from stackbase.secrets import redact

_RETRYABLE_STATUSES = frozenset({429, 502, 503, 504})
_MAX_BODY_CHARS = 500
_MAX_BACKOFF_SECONDS = 30.0

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
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
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
    message = redact(f"{method} {url} returned HTTP {status}", [token])
    hint = _STATUS_HINTS.get(status, f"the API returned HTTP {status} -- check the response body for details")
    return ApiError(message, hint, status=status, body=body)


def _network_error(method: str, url: str, exc: urllib.error.URLError, token: str) -> ApiError:
    reason = redact(str(exc.reason), [token])
    message = redact(f"{method} {url} failed: {reason}", [token])
    hint = "check network connectivity and that the host is reachable"
    return ApiError(message, hint, status=0, body="")


def _truncate(text: str, limit: int = _MAX_BODY_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "... [truncated]"
