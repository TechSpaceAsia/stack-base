"""CloudflareClient: reconciler's interface to the Cloudflare v4 REST API.

Every Cloudflare response is wrapped in a common envelope --
`{"success": bool, "errors": [{"code", "message"}, ...], "result": ...}` --
regardless of HTTP status. `stackbase.http.request` already raises `ApiError`
for a non-2xx HTTP status (429/502/503/504 retried, any other 4xx/5xx
immediate); this module additionally checks `success` on a 2xx response and
raises `ApiError` carrying Cloudflare's own error message(s) when it is
`false`. List endpoints (`/zones`, `.../dns_records`) paginate via
`result_info.page` / `result_info.total_pages`; pagination is walked to
completion where the caller needs to see every match (duplicate A-record
detection), and short-circuited on the first hit where it doesn't
(`zone_for`).

This client never issues a DNS/zone/cert delete -- `upsert_a_record` create-
or-updates only, and `create_origin_cert` only ever POSTs a new certificate.
"""

from __future__ import annotations

import time
from typing import Any

from stackbase.errors import StackError
from stackbase.http import ApiError, request

_DEFAULT_BASE_URL = "https://api.cloudflare.com/client/v4"


class CloudflareClient:
    """Bearer-authenticated client for the Cloudflare v4 API.

    Every call goes through `stackbase.http.request` for the HTTP-level
    timeout/retry/backoff policy, plus this module's own `success: false`
    envelope check. `create_origin_cert` overrides to `retries=1` -- issuing
    a certificate is non-idempotent (repeated calls would keep minting new
    certs against Cloudflare's origin-cert quota), so a transient failure
    must surface as an error rather than retry silently.
    """

    def __init__(self, token: str, base_url: str = _DEFAULT_BASE_URL) -> None:
        self._token = token
        self._base_url = base_url.rstrip("/")

    def _call(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        retries: int = 4,
        sleep: Any = time.sleep,
    ) -> dict[str, Any]:
        """Perform the HTTP call and validate the Cloudflare envelope.

        Returns the full parsed body (`success`, `errors`, `result`, and --
        for list endpoints -- `result_info`) so callers can read pagination
        metadata. Raises `ApiError` when `success` is `false`; the HTTP
        status on that path is always 200 -- a non-2xx status is already
        raised by `stackbase.http.request` itself, before `success` is ever
        inspected here.
        """
        parsed = request(
            method,
            f"{self._base_url}{path}",
            token=self._token,
            json_body=json_body,
            retries=retries,
            sleep=sleep,
        )
        if not isinstance(parsed, dict):
            raise ApiError(
                f"{method} {path} returned an unexpected response shape",
                "the Cloudflare API response was not a JSON object -- check the API status",
                status=200,
                body=str(parsed)[:500],
            )
        if not parsed.get("success", False):
            errors = parsed.get("errors")
            message = _format_cf_errors(errors if isinstance(errors, list) else [])
            raise ApiError(
                f"Cloudflare API request failed: {message}",
                "check the Cloudflare API token's permissions and the request payload",
                status=200,
                body=message,
            )
        return parsed

    # -- Zones -----------------------------------------------------------

    def zone_for(self, domain: str) -> tuple[str, str]:
        """Resolve `domain` to its owning Cloudflare zone by longest-suffix match.

        Tries `domain` itself, then each successively shorter parent domain
        (`a.b.example.com` -> `b.example.com` -> `example.com`), stopping at
        the first zone found. Never queries a bare TLD -- the shortest
        candidate tried always has at least two labels.
        """
        labels = domain.split(".")
        for start in range(len(labels) - 1):
            candidate = ".".join(labels[start:])
            zone = self._find_zone(candidate)
            if zone is not None:
                return zone["id"], zone["name"]
        raise StackError(
            f"no Cloudflare zone found for domain '{domain}'",
            "the Cloudflare API token may not have access to the zone for this domain "
            "(or any of its parent domains) -- check the token's Zone permissions",
        )

    def _find_zone(self, name: str) -> dict[str, Any] | None:
        page = 1
        while True:
            parsed = self._call("GET", f"/zones?name={name}&page={page}")
            zones = _dict_items(parsed.get("result"))
            if zones:
                return zones[0]
            if not _has_more_pages(parsed, page):
                return None
            page += 1

    # -- DNS records -------------------------------------------------------

    def upsert_a_record(self, zone_id: str, name: str, ipv4: str, *, proxied: bool = True) -> str:
        """Create or update the A record for `name` in `zone_id`. Returns its id.

        No-ops (no write issued) when a single existing record already has
        the desired `content`/`proxied`. More than one existing A record for
        `name` is ambiguous -- this raises rather than guessing which one to
        keep or update; stack-base never deletes a record it didn't create.
        """
        records = self._find_a_records(zone_id, name)
        if len(records) > 1:
            raise StackError(
                f"multiple A records found for '{name}' in Cloudflare zone {zone_id}",
                "resolve the duplicate in the Cloudflare dashboard -- stack-base will not "
                "guess which record to keep",
            )
        if not records:
            parsed = self._call(
                "POST",
                f"/zones/{zone_id}/dns_records",
                json_body={"type": "A", "name": name, "content": ipv4, "proxied": proxied},
            )
            return parsed["result"]["id"]

        record = records[0]
        if record.get("content") == ipv4 and record.get("proxied") == proxied:
            return record["id"]
        parsed = self._call(
            "PATCH",
            f"/zones/{zone_id}/dns_records/{record['id']}",
            json_body={"content": ipv4, "proxied": proxied},
        )
        return parsed["result"]["id"]

    def _find_a_records(self, zone_id: str, name: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        page = 1
        while True:
            parsed = self._call("GET", f"/zones/{zone_id}/dns_records?type=A&name={name}&page={page}")
            page_records = _dict_items(parsed.get("result"))
            records.extend(page_records)
            if not _has_more_pages(parsed, page):
                break
            page += 1
        return records

    # -- IP ranges -----------------------------------------------------------

    def ip_ranges(self) -> tuple[list[str], list[str]]:
        """Return `(ipv4_cidrs, ipv6_cidrs)` -- Cloudflare's published edge ranges."""
        parsed = self._call("GET", "/ips")
        result = parsed.get("result")
        result = result if isinstance(result, dict) else {}
        v4 = result.get("ipv4_cidrs")
        v6 = result.get("ipv6_cidrs")
        return (list(v4) if isinstance(v4, list) else [], list(v6) if isinstance(v6, list) else [])

    # -- Origin certificates -------------------------------------------------

    def create_origin_cert(self, hostnames: list[str], csr_pem: str, days: int = 5475) -> str:
        """Issue a Cloudflare origin certificate for `hostnames`. Returns the PEM.

        `days` defaults to 5475 (15 years), Cloudflare's maximum validity for
        an origin certificate. `retries=1`: issuing a cert is non-idempotent,
        so a transient failure must raise rather than risk minting a second
        certificate on retry.
        """
        body = {
            "hostnames": list(hostnames),
            "requested_validity": days,
            "request_type": "origin-rsa",
            "csr": csr_pem,
        }
        try:
            parsed = self._call("POST", "/certificates", json_body=body, retries=1)
        except ApiError as exc:
            if exc.status == 403:
                raise StackError(
                    exc.message,
                    "the Cloudflare API token likely lacks the 'Zone -> SSL and Certificates -> "
                    "Edit' permission needed to issue an origin certificate",
                ) from exc
            raise
        result = parsed.get("result")
        cert = result.get("certificate") if isinstance(result, dict) else None
        if not isinstance(cert, str):
            raise StackError(
                "Cloudflare did not return a certificate",
                "check the Cloudflare API response -- origin certificate creation may have "
                "partially failed",
            )
        return cert


def _dict_items(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _has_more_pages(parsed: dict[str, Any], current_page: int) -> bool:
    info = parsed.get("result_info")
    total_pages = info.get("total_pages") if isinstance(info, dict) else None
    return isinstance(total_pages, int) and current_page < total_pages


def _format_cf_errors(errors: list[Any]) -> str:
    parts = []
    for err in errors:
        if not isinstance(err, dict):
            continue
        message = err.get("message", "unknown error")
        code = err.get("code")
        parts.append(f"{message} (code {code})" if code is not None else str(message))
    return "; ".join(parts) if parts else "Cloudflare reported failure with no error detail"
