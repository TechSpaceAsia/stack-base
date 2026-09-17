"""Test fakes shared by the suite: a local HTTP server, and subprocess doubles.

`FakeServer` starts `http.server` on `127.0.0.1:0` (an OS-assigned free port)
in a background thread. Queue a response with `.script(method, path, status,
body, headers=None)` before making a request; each call queues one response
per (method, path) pair, consumed first-in-first-out, so a retry scenario is
scripted as multiple `.script()` calls for the same endpoint. Every request
received is recorded in `.requests` as `{"method", "path", "body", "headers"}`
(`body` is the JSON-decoded request body, or `None` if the request had no
body; `headers` is every received header, keyed lowercase).

`FakeRunner` stands in for `subprocess.run` (ssh, rsync, ssh-keyscan,
openssl) and `FakePopen` for `subprocess.Popen` (the streamed
`nixos-rebuild`). Both record every argv they are handed, so a test can
assert on the exact command line without shelling out or touching a network.
"""

from __future__ import annotations

import io
import json
import subprocess
import threading
from collections import deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any


class FakeServer:
    def __init__(self) -> None:
        self._responses: dict[tuple[str, str], deque[tuple[int, bytes, dict[str, str]]]] = {}
        self.requests: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._httpd: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "FakeServer":
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format_: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
                pass  # keep test output pristine -- no per-request access logging

            def _handle(self) -> None:
                fake._handle_request(self)

            do_GET = _handle
            do_POST = _handle
            do_PUT = _handle
            do_PATCH = _handle
            do_DELETE = _handle

        self._httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._httpd = None
        self._thread = None

    @property
    def url(self) -> str:
        if self._httpd is None:
            raise RuntimeError("FakeServer is not running -- use it as a context manager")
        port = self._httpd.server_address[1]
        return f"http://127.0.0.1:{port}"

    def script(self, method: str, path: str, status: int, body: Any = None, headers: dict[str, str] | None = None) -> None:
        """Queue one response for the next request matching `method` + `path`.

        `body` may be `None` (empty body), `bytes`/`str` (sent as-is, useful
        for a non-JSON body), or anything JSON-serialisable (encoded to JSON).
        """
        payload = _encode_body(body)
        key = (method.upper(), path)
        with self._lock:
            self._responses.setdefault(key, deque()).append((status, payload, dict(headers or {})))

    def _handle_request(self, handler: BaseHTTPRequestHandler) -> None:
        length = int(handler.headers.get("Content-Length") or 0)
        raw_body = handler.rfile.read(length) if length else b""
        parsed_body: Any = None
        if raw_body:
            try:
                parsed_body = json.loads(raw_body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                parsed_body = raw_body.decode("utf-8", errors="replace")

        # Keys lowercased: header casing is a wire-protocol detail (urllib
        # sends "User-agent", curl sends "User-Agent", ...) that callers
        # asserting on a specific header shouldn't have to know about.
        headers = {key.lower(): value for key, value in handler.headers.items()}

        with self._lock:
            self.requests.append(
                {"method": handler.command, "path": handler.path, "body": parsed_body, "headers": headers}
            )
            queue = self._responses.get((handler.command, handler.path))
            response = queue.popleft() if queue else None

        if response is None:
            status, payload, extra_headers = 500, b'{"error": "no response scripted"}', {}
        else:
            status, payload, extra_headers = response

        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(payload)))
        for key, value in extra_headers.items():
            handler.send_header(key, value)
        handler.end_headers()
        if payload:
            handler.wfile.write(payload)


class FakeRunner:
    """Records every argv/kwargs it's called with and returns scripted results in order.

    Three ways to supply a result, tried in order: a `handler(argv, kwargs)`
    callable (return `None` to fall through), the FIFO queue filled by
    `.script()`, and finally `default`. With none of them supplying a result
    the call is an error -- a silent "success" for a command the test never
    thought about would make the assertion that follows meaningless.
    """

    def __init__(self, *, handler: Any = None, default: subprocess.CompletedProcess | None = None) -> None:
        self.calls: list[dict] = []
        self._results: list[subprocess.CompletedProcess] = []
        self._handler = handler
        self._default = default

    def script(self, result: subprocess.CompletedProcess) -> None:
        self._results.append(result)

    def __call__(self, argv, **kwargs) -> subprocess.CompletedProcess:
        self.calls.append({"argv": list(argv), "kwargs": kwargs})
        if self._handler is not None:
            result = self._handler(list(argv), kwargs)
            if result is not None:
                return result
        if self._results:
            return self._results.pop(0)
        if self._default is not None:
            return self._default
        raise AssertionError(f"FakeRunner: no result scripted for {argv}")

    def argv_strings(self) -> list[str]:
        """Every recorded call flattened to one string per call, for substring assertions."""
        return [" ".join(call["argv"]) for call in self.calls]


class FakeProcess:
    """A `subprocess.Popen` stand-in whose stdout replays a canned transcript."""

    def __init__(self, argv: list[str], returncode: int, output: str) -> None:
        self.args = argv
        self.returncode = returncode
        self.stdout = io.StringIO(output)

    def __enter__(self) -> "FakeProcess":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stdout.close()

    def wait(self) -> int:
        return self.returncode


class FakePopen:
    """Records every argv and returns scripted (returncode, output) transcripts in order."""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self._results: list[tuple[int, str]] = []

    def script(self, returncode: int = 0, output: str = "") -> None:
        self._results.append((returncode, output))

    def __call__(self, argv, **kwargs) -> FakeProcess:
        self.calls.append({"argv": list(argv), "kwargs": kwargs})
        if not self._results:
            raise AssertionError(f"FakePopen: no result scripted for {argv}")
        returncode, output = self._results.pop(0)
        return FakeProcess(list(argv), returncode, output)

    def argv_strings(self) -> list[str]:
        return [" ".join(call["argv"]) for call in self.calls]


def _encode_body(body: Any) -> bytes:
    if body is None:
        return b""
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8")
    return json.dumps(body).encode("utf-8")
