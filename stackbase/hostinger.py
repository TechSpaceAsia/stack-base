"""HostingerClient: reconciler's interface to the Hostinger VPS REST API.

Every path and payload shape here is checked against the vendored OpenAPI
document at `docs/vendor/hostinger-openapi.json` (Hostinger API 1.53.0,
fetched from https://raw.githubusercontent.com/hostinger/api/main/openapi.json).
Differences from the plan's assumed shapes are called out below and in the
Task 3 commit message.

This module is structurally incapable of cancelling or destroying a virtual
machine or touching billing: no code path here issues `DELETE` against
`/api/vps/v1/virtual-machines*` or `/api/billing/*` (the only `DELETE` this
module issues is against a single firewall *rule*, which the plan explicitly
permits). `tests/test_no_delete.py` proves this by parsing the module source
with `ast` -- it does not just trust the docstring.

Known deviations from the plan's assumed request/response shapes (spec wins):
- `setup_vm`/`purchase_vm` do NOT take `public_key_ids` directly in the
  Hostinger request body. `VPS.V1.VirtualMachine.SetupRequest` only accepts a
  single inline `public_key: {name, key}` object. Existing-key-by-id
  attachment is a separate endpoint,
  `POST /api/vps/v1/public-keys/attach/{virtualMachineId}` with body
  `{"ids": [...]}`. The brief's `public_key_ids: list[int]` signature is kept
  verbatim; internally, `setup_vm`/`purchase_vm` call the setup/purchase
  endpoint first (no inline `public_key`) and then call the attach endpoint
  with `public_key_ids` when non-empty.
- `purchase_vm`'s wire body is `{"item_id": price_item, "setup": {...}}`
  (`VPS.V1.VirtualMachine.PurchaseRequest`), not a flat purchase body -- the
  setup fields (template/data-center/hostname/password) nest under `setup`.
- `list_vms`/`data_center_id`/`template_id` all hit endpoints that return a
  bare JSON array (`VPS.V1.*.*Collection`), not a `{"data": [...]}` wrapper.
  `ensure_public_key` and `ensure_firewall`'s underlying list endpoints
  (`/public-keys`, `/firewall`) DO wrap in `{"data": [...], "meta": {...}}`
  with `?page=` pagination -- handled by walking pages until
  `current_page * per_page >= total`.
"""

from __future__ import annotations

import re
import secrets
import time
from typing import Any

from stackbase.errors import StackError
from stackbase.http import request

_DEFAULT_BASE_URL = "https://developers.hostinger.com"
_PASSWORD_BYTES = 24  # secrets.token_urlsafe(24) -> exactly 32 base64url chars (24*8/6, no padding)
_VERSION_RE = re.compile(r"\d+(?:\.\d+)*")
_HPANEL_HINT = "check hPanel (https://hpanel.hostinger.com/) for the virtual machine's real status"


class HostingerClient:
    """Bearer-authenticated client for the Hostinger VPS API.

    Every call goes through `stackbase.http.request`, which already applies
    the 30s timeout / retry-with-backoff / `Retry-After` policy. `setup_vm`
    and `purchase_vm` override that to `retries=1` -- both are non-idempotent
    (they provision or buy hardware), so a transient failure must surface as
    an error rather than risk a silent double-purchase or double-setup on
    retry.
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
    ) -> Any:
        return request(
            method,
            f"{self._base_url}{path}",
            token=self._token,
            json_body=json_body,
            retries=retries,
            sleep=sleep,
        )

    # -- Virtual machines -----------------------------------------------

    def list_vms(self) -> list[dict[str, Any]]:
        """Return every virtual machine on the account."""
        result = self._call("GET", "/api/vps/v1/virtual-machines")
        return result if isinstance(result, list) else []

    def get_vm(self, vps_id: int) -> dict[str, Any]:
        """Return one virtual machine's detail (id, state, ipv4/ipv6, actions_lock, ...)."""
        return self._call("GET", f"/api/vps/v1/virtual-machines/{vps_id}")

    # -- Data centers / templates -----------------------------------------

    def data_center_id(self, name: str) -> int:
        """Resolve a data-center name (case-insensitive) to its numeric id."""
        data_centers = self._call("GET", "/api/vps/v1/data-centers")
        candidates = [dc for dc in data_centers if isinstance(dc, dict)]
        for dc in candidates:
            if isinstance(dc.get("name"), str) and dc["name"].lower() == name.lower():
                return dc["id"]
        valid_names = sorted({dc["name"] for dc in candidates if isinstance(dc.get("name"), str)})
        raise StackError(
            f"no Hostinger data center named '{name}'",
            f"valid data centers: {', '.join(valid_names)}" if valid_names else "the Hostinger API returned no data centers",
        )

    def template_id(self, name_prefix: str = "NixOS") -> int:
        """Resolve the highest-versioned plain OS template starting with `name_prefix`.

        "Plain OS template" means the template name is exactly
        `<name_prefix> <version>` (e.g. "NixOS 26.05") with nothing trailing
        the version -- a variant like "NixOS 25.11 with Docker" is skipped.
        Versions compare numerically (dot-separated integer components), not
        lexically, so "NixOS 10.0" beats "NixOS 9.0".
        """
        templates = self._call("GET", "/api/vps/v1/templates")
        best: tuple[tuple[int, ...], int] | None = None
        for tpl in templates:
            if not isinstance(tpl, dict):
                continue
            name = tpl.get("name")
            if not isinstance(name, str) or not name.startswith(name_prefix):
                continue
            version = _parse_plain_os_version(name[len(name_prefix):])
            if version is None:
                continue
            if best is None or version > best[0]:
                best = (version, tpl["id"])
        if best is None:
            raise StackError(
                f"no Hostinger template found matching prefix '{name_prefix}'",
                "check the template name in hPanel (VPS -> OS) or the Hostinger templates API",
            )
        return best[1]

    # -- Public keys -------------------------------------------------------

    def ensure_public_key(self, name: str, key: str) -> int:
        """Return the id of a public key matching `key`'s body, creating it if absent."""
        key_body = key.strip()
        for existing in self._list_paginated("/api/vps/v1/public-keys"):
            if isinstance(existing.get("key"), str) and existing["key"].strip() == key_body:
                return existing["id"]
        created = self._call("POST", "/api/vps/v1/public-keys", json_body={"name": name, "key": key})
        return created["id"]

    def _attach_public_keys(self, vps_id: int, public_key_ids: list[int]) -> None:
        if not public_key_ids:
            return
        self._call(
            "POST",
            f"/api/vps/v1/public-keys/attach/{vps_id}",
            json_body={"ids": list(public_key_ids)},
        )

    # -- Setup / purchase ----------------------------------------------------

    def setup_vm(
        self,
        vps_id: int,
        *,
        template_id: int,
        data_center_id: int,
        hostname: str,
        public_key_ids: list[int],
    ) -> None:
        """Set up a purchased-but-uninitialised (`state == "initial"`) VM.

        A random 32-char password is generated with a CSPRNG, sent once to
        satisfy the API's required field, and then discarded -- it is never
        logged or returned. Access is key-only: NixOS disables password
        login, and the SSH keys named by `public_key_ids` are attached via a
        separate call after setup (see module docstring).
        """
        password = secrets.token_urlsafe(_PASSWORD_BYTES)
        body = {
            "template_id": template_id,
            "data_center_id": data_center_id,
            "hostname": hostname,
            "password": password,
        }
        self._call("POST", f"/api/vps/v1/virtual-machines/{vps_id}/setup", json_body=body, retries=1)
        self._attach_public_keys(vps_id, public_key_ids)

    def purchase_vm(
        self,
        *,
        price_item: str,
        template_id: int,
        data_center_id: int,
        hostname: str,
        public_key_ids: list[int],
    ) -> int:
        """Purchase a new VM and set it up in one call. Returns the new vps id.

        `retries=1`: this issues a real charge. A transient failure must
        raise rather than retry -- retrying a purchase risks buying twice.
        """
        password = secrets.token_urlsafe(_PASSWORD_BYTES)
        body = {
            "item_id": price_item,
            "setup": {
                "template_id": template_id,
                "data_center_id": data_center_id,
                "hostname": hostname,
                "password": password,
            },
        }
        result = self._call("POST", "/api/vps/v1/virtual-machines", json_body=body, retries=1)
        vm = result.get("virtual_machine") if isinstance(result, dict) else None
        if not isinstance(vm, dict) or "id" not in vm:
            raise StackError(
                "Hostinger did not return a virtual machine after purchase",
                "the payment may still be processing (HTTP 202) -- "
                + _HPANEL_HINT
                + "; do not retry the purchase blindly, it may have already gone through",
            )
        vps_id = vm["id"]
        self._attach_public_keys(vps_id, public_key_ids)
        return vps_id

    # -- Waiting -------------------------------------------------------------

    def wait_running(
        self,
        vps_id: int,
        timeout: float = 900,
        poll: float = 10,
        sleep: Any = time.sleep,
    ) -> dict[str, Any]:
        """Poll `get_vm` until `state == "running"` and `actions_lock == "unlocked"`."""
        elapsed = 0.0
        while True:
            vm = self.get_vm(vps_id)
            if vm.get("state") == "running" and vm.get("actions_lock") == "unlocked":
                return vm
            if elapsed >= timeout:
                raise StackError(
                    f"virtual machine {vps_id} did not reach 'running'/'unlocked' within {timeout:.0f}s",
                    _HPANEL_HINT + " -- setup may have failed or the VM may still be provisioning",
                )
            sleep(poll)
            elapsed += poll

    # -- Firewall --------------------------------------------------------

    def ensure_firewall(self, name: str, rules: list[dict[str, Any]]) -> int:
        """Ensure a firewall named `name` exists with exactly `rules`.

        Rules are diffed by (protocol, port, source, source_detail) -- the
        full set of fields that make a rule distinct (the brief's shorthand
        "(protocol, port, source)" would collide two `source="custom"` rules
        that differ only by `source_detail`, e.g. two different admin IPs on
        the same port; keying on all four fields is what "no-op when equal"
        and "adds missing + removes stale" actually require). Missing rules
        are added with individual `POST .../rules` calls; rules present on
        the firewall but absent from `rules` are removed with individual
        `DELETE .../rules/{id}` calls -- firewall *rule* deletes are the one
        delete this module is allowed to perform.
        """
        firewall = self._find_firewall(name)
        if firewall is None:
            firewall = self._call("POST", "/api/vps/v1/firewall", json_body={"name": name})
        firewall_id = firewall["id"]

        current = {
            _rule_key(rule): rule
            for rule in firewall.get("rules") or []
            if isinstance(rule, dict)
        }
        desired = {_rule_key(rule): rule for rule in rules}

        for key, rule in desired.items():
            if key not in current:
                self._call(
                    "POST",
                    f"/api/vps/v1/firewall/{firewall_id}/rules",
                    json_body={
                        "protocol": rule["protocol"],
                        "port": str(rule["port"]),
                        "source": rule.get("source", "any"),
                        "source_detail": rule.get("source_detail", rule.get("source", "any")),
                    },
                )

        for key, rule in current.items():
            if key not in desired:
                self._call("DELETE", f"/api/vps/v1/firewall/{firewall_id}/rules/{rule['id']}")

        return firewall_id

    def activate_firewall(self, firewall_id: int, vps_id: int) -> None:
        """Activate `firewall_id` on `vps_id` (only one firewall may be active per VM)."""
        self._call("POST", f"/api/vps/v1/firewall/{firewall_id}/activate/{vps_id}")

    def _find_firewall(self, name: str) -> dict[str, Any] | None:
        for firewall in self._list_paginated("/api/vps/v1/firewall"):
            if firewall.get("name") == name:
                return firewall
        return None

    # -- Pagination helper -------------------------------------------------

    def _list_paginated(self, path: str) -> list[dict[str, Any]]:
        """Walk every page of a `{"data": [...], "meta": {...}}` list endpoint."""
        items: list[dict[str, Any]] = []
        page = 1
        while True:
            result = self._call("GET", f"{path}?page={page}")
            data = result.get("data") if isinstance(result, dict) else None
            if not isinstance(data, list):
                break
            items.extend(item for item in data if isinstance(item, dict))
            meta = result.get("meta") if isinstance(result, dict) else None
            if not isinstance(meta, dict) or not data:
                break
            current_page = meta.get("current_page", page)
            per_page = meta.get("per_page", len(data) or 1)
            total = meta.get("total", len(items))
            if current_page * per_page >= total:
                break
            page += 1
        return items


def _rule_key(rule: dict[str, Any]) -> tuple[Any, Any, Any, Any]:
    return (
        rule.get("protocol"),
        str(rule.get("port")),
        rule.get("source", "any"),
        rule.get("source_detail", rule.get("source", "any")),
    )


def _parse_plain_os_version(rest: str) -> tuple[int, ...] | None:
    """`" 26.05"` -> `(26, 5)`; anything but a bare dotted-integer version -> `None`."""
    stripped = rest.strip()
    if not _VERSION_RE.fullmatch(stripped):
        return None
    return tuple(int(part) for part in stripped.split("."))
