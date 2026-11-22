from __future__ import annotations

import base64
import copy
import hmac
import hashlib
import http.client
import json
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Sequence
from urllib.parse import quote, unquote, urlparse


SE_SESSION_REDACT_RE = re.compile(
    r"(?<!<redacted-)(?:se-session|oc-relay|worker-relay)-(?!token>|REDACTED\b)[A-Za-z0-9_-]+"
)
CREDENTIAL_PREFIX_RE = re.compile(
    r"(?:se-session|oc-relay|worker-relay)-[A-Za-z0-9_-]{12,}"
)
BASE64_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
KNOWN_B64_PREFIXES: tuple[str, ...] = (
    "c2Utc2Vzc2lvbi0",  # base64("se-session-")[:15]
    "b2MtcmVsYXkt",      # base64("oc-relay-")[:12]
    "d29ya2VyLXJlbGF5LQ",  # base64("worker-relay-")[:18]
)
MAX_JSON_CONTAINER_DEPTH = 64
MAX_EMBEDDED_JSON_DECODES = 6
MAX_VISITED_JSON_NODES = 20_000
MAX_BASE64_CANDIDATES_PER_STRING = 16_384
MAX_BASE64_CANDIDATE_TOKEN_LEN = 65_536


def redact_session_tokens(text: str) -> str:
    return SE_SESSION_REDACT_RE.sub("se-session-REDACTED", text)


def _secret_encoding_needles(secret: str) -> list[str]:
    cleaned = secret.strip()
    if len(cleaned) < 8:
        return []
    raw_bytes = cleaned.encode("utf-8")
    b64_std = base64.b64encode(raw_bytes).decode("ascii")
    b64_url = base64.urlsafe_b64encode(raw_bytes).decode("ascii")
    basic_oc = base64.b64encode(f"opencode:{cleaned}".encode("utf-8")).decode("ascii")
    basic_empty = base64.b64encode(f":{cleaned}".encode("utf-8")).decode("ascii")

    candidates = [
        cleaned,
        quote(cleaned, safe=""),
        b64_std,
        b64_std.rstrip("="),
        b64_url,
        b64_url.rstrip("="),
        basic_oc,
        basic_oc.rstrip("="),
        basic_empty,
        basic_empty.rstrip("="),
    ]
    out: list[str] = []
    for item in candidates:
        if len(item) >= 8 and item not in out:
            out.append(item)
    return out


def _decode_json_escapes_lenient(text: str) -> str:
    if "\\" not in text:
        return text
    out: list[str] = []
    idx = 0
    n = len(text)
    while idx < n:
        ch = text[idx]
        if ch == "\\" and idx + 1 < n:
            nxt = text[idx + 1]
            if nxt == "/":
                out.append("/")
                idx += 2
            elif nxt == '"':
                out.append('"')
                idx += 2
            elif nxt == "\\":
                out.append("\\")
                idx += 2
            elif nxt == "n":
                out.append("\n")
                idx += 2
            elif nxt == "r":
                out.append("\r")
                idx += 2
            elif nxt == "t":
                out.append("\t")
                idx += 2
            elif nxt == "b":
                out.append("\b")
                idx += 2
            elif nxt == "f":
                out.append("\f")
                idx += 2
            elif nxt == "u" and idx + 6 <= n:
                hex4 = text[idx + 2 : idx + 6]
                try:
                    code_unit = int(hex4, 16)
                except ValueError:
                    out.append(ch)
                    idx += 1
                else:
                    if 0xD800 <= code_unit <= 0xDBFF and idx + 12 <= n and text[idx + 6 : idx + 8] == "\\u":
                        low_hex = text[idx + 8 : idx + 12]
                        try:
                            low_unit = int(low_hex, 16)
                        except ValueError:
                            low_unit = 0
                        if 0xDC00 <= low_unit <= 0xDFFF:
                            cp = 0x10000 + ((code_unit - 0xD800) << 10) + (low_unit - 0xDC00)
                            out.append(chr(cp))
                            idx += 12
                            continue
                    out.append(chr(code_unit))
                    idx += 6
            else:
                out.append(ch)
                idx += 1
        else:
            out.append(ch)
            idx += 1
    return "".join(out)


def _decode_base64_candidate(token: str) -> bytes | None:
    normalized = token.replace("-", "+").replace("_", "/").rstrip("=")
    if len(normalized) < 12:
        return None
    rem = len(normalized) % 4
    if rem == 1:
        return None
    if rem:
        normalized += "=" * (4 - rem)
    try:
        return base64.b64decode(normalized.encode("ascii"), validate=True)
    except Exception:
        return None


def _text_matches_direct_leak(text: str, needles: Sequence[str]) -> bool:
    if not text:
        return False
    if CREDENTIAL_PREFIX_RE.search(text):
        return True
    for needle in needles:
        if needle in text:
            return True
    return False


def _string_contains_credential_leak(
    raw_string: str,
    *,
    needles: Sequence[str],
    raw_secrets: Sequence[str],
) -> bool:
    if not raw_string:
        return False
    candidates: list[str] = []

    def _add(s: str) -> None:
        if s and s not in candidates:
            candidates.append(s)

    _add(raw_string)
    _add(unquote(raw_string))
    cur = raw_string
    for _ in range(4):
        nxt = _decode_json_escapes_lenient(cur)
        if nxt == cur:
            break
        _add(nxt)
        _add(unquote(nxt))
        cur = nxt

    for cand in candidates:
        if _text_matches_direct_leak(cand, needles):
            return True
        cand_count = 0
        for match in BASE64_CANDIDATE_RE.finditer(cand):
            cand_count += 1
            if cand_count > MAX_BASE64_CANDIDATES_PER_STRING:
                return True
            tok = match.group(0)
            if len(tok) > MAX_BASE64_CANDIDATE_TOKEN_LEN:
                return True
            for offset in range(4):
                sliced = tok if offset == 0 else tok[offset:]
                if len(sliced) < 12:
                    continue
                decoded_bytes = _decode_base64_candidate(sliced)
                if not decoded_bytes:
                    continue
                decoded_str = decoded_bytes.decode("utf-8", errors="replace")
                decoded_unq = unquote(decoded_str)
                decoded_unesc = _decode_json_escapes_lenient(decoded_str)
                for sub in (decoded_str, decoded_unq, decoded_unesc):
                    if not sub:
                        continue
                    for sec in raw_secrets:
                        if sec in sub:
                            return True
                    if _text_matches_direct_leak(sub, needles):
                        return True
    return False


def _build_needles_and_raw_secrets(secrets_to_block: Sequence[str]) -> tuple[list[str], list[str]]:
    raw_secrets = [
        s.strip() for s in secrets_to_block if isinstance(s, str) and len(s.strip()) >= 8
    ]
    needles: list[str] = list(KNOWN_B64_PREFIXES)
    for sec in raw_secrets:
        for variant in _secret_encoding_needles(sec):
            if variant not in needles:
                needles.append(variant)
    return needles, raw_secrets


def contains_credential_leak(
    raw_body: bytes,
    *,
    secrets_to_block: Sequence[str],
) -> bool:
    if not raw_body:
        return False
    text = raw_body.decode("utf-8", errors="replace")
    needles, raw_secrets = _build_needles_and_raw_secrets(secrets_to_block)
    if _string_contains_credential_leak(text, needles=needles, raw_secrets=raw_secrets):
        return True
    stripped = text.strip()
    if stripped and stripped[0] in ("{", "[", '"'):
        try:
            parsed = json.loads(stripped)
        except RecursionError:
            return True
        except Exception:
            parsed = None
        else:
            if _parsed_json_contains_credential_leak(
                parsed, secrets_to_block=secrets_to_block
            ):
                return True
    return False


def _parsed_json_contains_credential_leak(
    value: Any,
    *,
    secrets_to_block: Sequence[str],
) -> bool:
    needles, raw_secrets = _build_needles_and_raw_secrets(secrets_to_block)
    visited_nodes = 0
    # Stack items: (node, container_depth, embedded_decode_depth)
    stack: list[tuple[Any, int, int]] = [(value, 0, 0)]
    while stack:
        cur, depth, emb_depth = stack.pop()
        visited_nodes += 1
        if depth > MAX_JSON_CONTAINER_DEPTH or visited_nodes > MAX_VISITED_JSON_NODES:
            return True
        if isinstance(cur, str):
            safe_str = cur.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
            if _string_contains_credential_leak(
                safe_str, needles=needles, raw_secrets=raw_secrets
            ):
                return True
            trimmed = safe_str.strip()
            if trimmed and trimmed[0] in ("{", "[", '"'):
                try:
                    nested = json.loads(trimmed)
                except RecursionError:
                    return True
                except Exception:
                    nested = None
                else:
                    if emb_depth >= MAX_EMBEDDED_JSON_DECODES:
                        return True
                    stack.append((nested, 0, emb_depth + 1))
        elif isinstance(cur, dict):
            next_depth = depth + 1
            if next_depth > MAX_JSON_CONTAINER_DEPTH:
                return True
            for k, v in cur.items():
                stack.append((v, next_depth, emb_depth))
                stack.append((k, next_depth, emb_depth))
        elif isinstance(cur, (list, tuple)):
            next_depth = depth + 1
            if next_depth > MAX_JSON_CONTAINER_DEPTH:
                return True
            for item in cur:
                stack.append((item, next_depth, emb_depth))
    return False


class SessionAuthRelay:
    """In-process loopback HTTP relay keeping upstream tokens outside OpenCode and child sandboxes."""

    def __init__(
        self,
        *,
        upstream_base_url: str,
        upstream_session_token: str,
        token_prefix: str = "oc-relay",
        token_hex_bytes: int = 32,
        extra_canary_secrets: Sequence[str] = (),
        max_chat_requests: int = 25,
        max_request_bytes: int = 131072,
        max_tokens_cap: int = 2048,
        ttl_seconds: float | None = None,
        upstream_timeout_seconds: float = 120.0,
        max_response_bytes: int = 16 * 1024 * 1024,
        default_chat_params: dict[str, Any] | None = None,
        error_cls: type[ValueError] | None = None,
        chat_params_validator: Callable[[dict[str, Any] | None], dict[str, Any]] | None = None,
        lease_provider: Callable[[], dict[str, Any]] | None = None,
        follow_session_window: bool = False,
    ) -> None:
        exc_type = error_cls or ValueError
        parsed = urlparse(upstream_base_url.rstrip("/"))
        if parsed.hostname not in ("127.0.0.1", "localhost") or parsed.port is None:
            raise exc_type(
                f"{self.__class__.__name__} requires a localhost upstream URL with explicit port, got {upstream_base_url!r}."
            )
        if not upstream_session_token or not upstream_session_token.strip():
            raise exc_type(f"{self.__class__.__name__} requires a non-empty upstream token.")
        clean_prefix = token_prefix.strip().rstrip("-")
        if not re.match(r"^[A-Za-z0-9_-]{2,32}$", clean_prefix):
            raise exc_type(f"Invalid relay token_prefix: {token_prefix!r}")

        self.upstream_host = parsed.hostname
        self.upstream_port = parsed.port
        self._upstream_session_token = upstream_session_token.strip()
        self._known_upstream_tokens = [self._upstream_session_token]
        self.lease_provider = lease_provider
        self.follow_session_window = follow_session_window
        self.relay_token = f"{clean_prefix}-{secrets.token_hex(max(16, int(token_hex_bytes)))}"
        self._extra_canary_secrets: tuple[str, ...] = tuple(
            s.strip() for s in extra_canary_secrets if isinstance(s, str) and s.strip()
        )
        self.max_chat_requests = max(1, int(max_chat_requests))
        self.max_request_bytes = max(256, int(max_request_bytes))
        self.max_tokens_cap = max(1, int(max_tokens_cap))
        self.ttl_seconds: float | None = (
            max(0.01, float(ttl_seconds)) if ttl_seconds is not None else None
        )
        self._expires_at_mono: float | None = (
            (time.monotonic() + self.ttl_seconds) if self.ttl_seconds is not None else None
        )
        self.upstream_timeout_seconds = max(1.0, float(upstream_timeout_seconds))
        self.max_response_bytes = max(4096, int(max_response_bytes))
        if chat_params_validator is not None:
            self.default_chat_params = chat_params_validator(default_chat_params)
        else:
            from .security_profile import validate_default_chat_params

            self.default_chat_params = validate_default_chat_params(default_chat_params)
        self._lock = threading.RLock()
        self._inflight_sem = threading.BoundedSemaphore(16)
        self.chat_requests_used = 0
        self.local_request_cap_exhausted = False
        self.upstream_session_cap_exhausted = False
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def api_base_url(self) -> str:
        if self._httpd is None:
            raise RuntimeError(f"{self.__class__.__name__} has not been started.")
        _, port = self._httpd.server_address[:2]
        return f"http://127.0.0.1:{port}/v1"

    @property
    def port(self) -> int:
        if self._httpd is None:
            raise RuntimeError(f"{self.__class__.__name__} has not been started.")
        return int(self._httpd.server_address[1])

    def _all_guarded_secrets(self) -> tuple[str, ...]:
        with self._lock:
            return (*self._known_upstream_tokens, self.relay_token, *self._extra_canary_secrets)

    def _current_lease(self, *, refresh: bool = False) -> dict[str, Any] | None:
        if self.lease_provider is None:
            return None
        refresh_fn = getattr(self.lease_provider, 'refresh', None)
        lease = refresh_fn() if refresh and callable(refresh_fn) else self.lease_provider()
        if (lease.get('state') != 'ON' or lease.get('remaining_seconds', 0) <= 0
                or type(lease.get('generation')) is not int or lease['generation'] < 1
                or not isinstance(lease.get('token'), str)):
            raise ValueError('Session lease unavailable.')
        with self._lock:
            if lease['token'] not in self._known_upstream_tokens:
                self._known_upstream_tokens.append(lease['token'])
        return lease

    @staticmethod
    def _verified_stale(error: dict, old: dict, new: dict, nonce: str) -> bool:
        if (new.get('session_id') != old.get('session_id') or new.get('pid') != old.get('pid')
                or new.get('generation', 0) <= old.get('generation', 0)
                or error.get('code') != 'session_credential_stale'
                or error.get('session_id') != new.get('session_id')
                or error.get('generation') != new.get('generation')
                or error.get('request_id') != nonce or not isinstance(error.get('proof'), str)):
            return False
        material = f"free-inference-stale-v1|{new['session_id']}|{new['generation']}|{nonce}"
        expected = hmac.new(new['token'].encode(), material.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, error['proof'])

    def _scrub_error_message(self, message: str) -> str:
        scrubbed = message
        for sec in self._all_guarded_secrets():
            if sec:
                scrubbed = scrubbed.replace(sec, "[REDACTED]")
        return redact_session_tokens(scrubbed)

    def start(self) -> "SessionAuthRelay":
        relay = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self) -> None:
                try:
                    self.request.settimeout(min(30.0, relay.upstream_timeout_seconds))
                except OSError:
                    pass
                super().setup()

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _send_json_error(self, status: int, message: str, err_type: str) -> None:
                safe_msg = relay._scrub_error_message(message)
                payload = json.dumps(
                    {
                        "error": {
                            "code": err_type,
                            "type": err_type,
                            "message": safe_msg,
                        }
                    }
                ).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    self.wfile.write(payload)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def _check_auth(self) -> bool:
                if (
                    not relay.follow_session_window and relay._expires_at_mono is not None
                    and time.monotonic() >= relay._expires_at_mono
                ):
                    self._send_json_error(
                        401, "Session relay TTL has expired.", "session_expired"
                    )
                    return False
                auth_hdr = self.headers.get("Authorization", "")
                if not auth_hdr.startswith("Bearer "):
                    self._send_json_error(
                        401, "Missing Bearer token for session relay.", "auth_error"
                    )
                    return False
                candidate = auth_hdr[len("Bearer ") :].strip()
                if not hmac.compare_digest(
                    candidate.encode("utf-8"), relay.relay_token.encode("utf-8")
                ):
                    self._send_json_error(
                        401, "Invalid Bearer token for session relay.", "auth_error"
                    )
                    return False
                try:
                    self._session_lease = relay._current_lease()
                except Exception:
                    self._send_json_error(401, 'Session authorization is unavailable.', 'session_expired')
                    return False
                return True

            def do_GET(self) -> None:
                if not self._check_auth():
                    return
                if self.path != "/v1/models":
                    self._send_json_error(
                        404, f"Session relay path {self.path!r} is not permitted.", "not_found"
                    )
                    return
                self._forward_upstream("GET", "/v1/models", None)

            def do_POST(self) -> None:
                if not self._check_auth():
                    return
                if self.path != "/v1/chat/completions":
                    if self.path == "/v1/models":
                        self._send_json_error(405, "Method not allowed.", "method_not_allowed")
                    else:
                        self._send_json_error(
                            404, f"Session relay path {self.path!r} is not permitted.", "not_found"
                        )
                    return

                if self.headers.get("Transfer-Encoding") is not None:
                    self._send_json_error(
                        400,
                        "Chunked Transfer-Encoding is not supported; Content-Length is required.",
                        "invalid_request_error",
                    )
                    return
                raw_cl = self.headers.get("Content-Length")
                if raw_cl is None:
                    self._send_json_error(
                        411, "Content-Length header is required.", "invalid_request_error"
                    )
                    return
                try:
                    content_length = int(raw_cl)
                except ValueError:
                    self._send_json_error(
                        400, "Invalid Content-Length header.", "invalid_request_error"
                    )
                    return
                if content_length < 0:
                    self._send_json_error(
                        400, "Negative Content-Length is invalid.", "invalid_request_error"
                    )
                    return
                if content_length > relay.max_request_bytes:
                    self._send_json_error(
                        413,
                        f"Request body ({content_length} bytes) exceeds max_request_bytes ({relay.max_request_bytes}).",
                        "request_too_large",
                    )
                    return

                raw_body = self.rfile.read(content_length)
                if contains_credential_leak(
                    raw_body,
                    secrets_to_block=relay._all_guarded_secrets(),
                ):
                    self._send_json_error(
                        400,
                        "Outbound request blocked: active or session credential material detected in request payload.",
                        "credential_leak_blocked",
                    )
                    return

                try:
                    parsed_body = json.loads(raw_body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self._send_json_error(
                        400, "Request body must be valid UTF-8 JSON.", "invalid_request_error"
                    )
                    return
                if not isinstance(parsed_body, dict):
                    self._send_json_error(
                        400, "Request body must be a JSON object.", "invalid_request_error"
                    )
                    return

                for k, default_val in relay.default_chat_params.items():
                    if k == "chat_template_kwargs" and isinstance(default_val, dict):
                        if k not in parsed_body or parsed_body[k] is None:
                            parsed_body[k] = copy.deepcopy(default_val)
                        elif isinstance(parsed_body[k], dict):
                            merged_kw = dict(parsed_body[k])
                            for sub_k, sub_v in default_val.items():
                                if sub_k not in merged_kw:
                                    merged_kw[sub_k] = copy.deepcopy(sub_v)
                            parsed_body[k] = merged_kw
                    elif k not in parsed_body:
                        parsed_body[k] = copy.deepcopy(default_val)

                if "n" in parsed_body:
                    parsed_body["n"] = 1
                if "best_of" in parsed_body:
                    parsed_body["best_of"] = 1

                req_max_tok = parsed_body.get("max_tokens")
                req_max_out = parsed_body.pop("maxOutputTokens", None)
                if isinstance(req_max_tok, int) and not isinstance(req_max_tok, bool):
                    parsed_body["max_tokens"] = min(max(1, req_max_tok), relay.max_tokens_cap)
                elif isinstance(req_max_out, int) and not isinstance(req_max_out, bool):
                    parsed_body["max_tokens"] = min(max(1, req_max_out), relay.max_tokens_cap)
                else:
                    parsed_body["max_tokens"] = relay.max_tokens_cap

                req_max_comp = parsed_body.get("max_completion_tokens")
                if isinstance(req_max_comp, int) and not isinstance(req_max_comp, bool):
                    parsed_body["max_completion_tokens"] = min(
                        max(1, req_max_comp), relay.max_tokens_cap
                    )

                forwarded_bytes = json.dumps(parsed_body).encode("utf-8")
                if len(forwarded_bytes) > relay.max_request_bytes:
                    self._send_json_error(
                        413,
                        "Clamped request body exceeds max_request_bytes.",
                        "request_too_large",
                    )
                    return

                guarded_secrets = relay._all_guarded_secrets()
                canonical_utf8 = json.dumps(parsed_body, ensure_ascii=False).encode("utf-8")
                if (
                    contains_credential_leak(forwarded_bytes, secrets_to_block=guarded_secrets)
                    or contains_credential_leak(canonical_utf8, secrets_to_block=guarded_secrets)
                    or _parsed_json_contains_credential_leak(
                        parsed_body, secrets_to_block=guarded_secrets
                    )
                ):
                    self._send_json_error(
                        400,
                        "Outbound request blocked: active or session credential material detected in decoded JSON payload.",
                        "credential_leak_blocked",
                    )
                    return

                with relay._lock:
                    if relay.chat_requests_used >= relay.max_chat_requests:
                        relay.local_request_cap_exhausted = True
                        self._send_json_error(
                            429,
                            f"Session relay max_chat_requests ({relay.max_chat_requests}) reached.",
                            "rate_limit_error",
                        )
                        return
                    relay.chat_requests_used += 1

                self._forward_upstream("POST", "/v1/chat/completions", forwarded_bytes)

            def do_PUT(self) -> None:
                if not self._check_auth():
                    return
                self._send_json_error(405, "Method not allowed.", "method_not_allowed")

            def do_DELETE(self) -> None:
                if not self._check_auth():
                    return
                self._send_json_error(405, "Method not allowed.", "method_not_allowed")

            def _forward_upstream(
                self, method: str, path: str, body: bytes | None
            ) -> None:
                if not relay._inflight_sem.acquire(timeout=5.0):
                    self._send_json_error(
                        429,
                        "Too many concurrent session relay requests.",
                        "rate_limit_error",
                    )
                    return
                conn = http.client.HTTPConnection(
                    relay.upstream_host,
                    relay.upstream_port,
                    timeout=relay.upstream_timeout_seconds,
                )
                headers_sent = False
                try:
                    lease = getattr(self, '_session_lease', None)
                    conn.connect()
                    check_connection = getattr(relay.lease_provider, 'check_connection', None)
                    if lease and callable(check_connection):
                        check_connection(conn.sock)
                    nonce = secrets.token_hex(16)
                    up_headers: dict[str, str] = {
                        "Authorization": f"Bearer {lease['token'] if lease else relay._upstream_session_token}",
                        "Accept": self.headers.get("Accept", "application/json"),
                        "Connection": "close",
                        "X-Session-Request-ID": nonce,
                    }
                    if body is not None:
                        up_headers["Content-Type"] = "application/json"
                        up_headers["Content-Length"] = str(len(body))
                    conn.request(method, path, body=body, headers=up_headers)
                    resp = conn.getresponse()
                    if lease and resp.status == 401:
                        # This consumes only a bounded authentication refusal. A retry requires
                        # a key-holder HMAC bound to our nonce and a newer protected lease.
                        refused = resp.read(4097)
                        try:
                            failure = json.loads(refused).get('error', {}) if len(refused) <= 4096 else {}
                        except (ValueError, AttributeError):
                            failure = {}
                        replacement = None
                        if isinstance(failure, dict) and failure.get('code') == 'session_credential_stale':
                            try:
                                replacement = relay._current_lease(refresh=True)
                            except Exception:
                                pass
                        if replacement and isinstance(failure, dict) and relay._verified_stale(failure, lease, replacement, nonce):
                            conn.close()
                            conn = http.client.HTTPConnection(relay.upstream_host, relay.upstream_port,
                                                              timeout=relay.upstream_timeout_seconds)
                            conn.connect()
                            if callable(check_connection):
                                check_connection(conn.sock)
                            up_headers['Authorization'] = f"Bearer {replacement['token']}"
                            up_headers['X-Session-Request-ID'] = secrets.token_hex(16)
                            conn.request(method, path, body=body, headers=up_headers)
                            resp = conn.getresponse()
                        else:
                            self._send_json_error(401, 'Upstream authorization refused; request was not retried.', 'auth_error')
                            return
                    content_type = resp.getheader("Content-Type", "application/json")
                    is_sse = "text/event-stream" in content_type.lower()

                    self.send_response(resp.status)
                    headers_sent = True
                    self.send_header("Content-Type", content_type)
                    for pass_hdr in ("Retry-After", "x-request-id"):
                        hdr_val = resp.getheader(pass_hdr)
                        if hdr_val is not None:
                            self.send_header(pass_hdr, hdr_val)
                    if not is_sse:
                        up_cl = resp.getheader("Content-Length")
                        if up_cl is not None:
                            self.send_header("Content-Length", up_cl)
                    else:
                        self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "close")
                    self.end_headers()

                    total_read = 0
                    cap_probe_buf = bytearray() if (resp.status == 429 and not is_sse) else None
                    read_fn = getattr(resp, "read1", None)
                    while True:
                        chunk = read_fn(4096) if callable(read_fn) else resp.read(4096)
                        if not chunk:
                            break
                        if cap_probe_buf is not None and len(cap_probe_buf) < 4096:
                            cap_probe_buf.extend(chunk[: 4096 - len(cap_probe_buf)])
                        total_read += len(chunk)
                        if total_read > relay.max_response_bytes:
                            if is_sse:
                                self.wfile.write(
                                    b'\ndata: {"error":{"message":"Response exceeded max_response_bytes","type":"response_truncated"}}\n\n'
                                )
                                self.wfile.flush()
                            break
                        self.wfile.write(chunk)
                        self.wfile.flush()
                    if cap_probe_buf is not None and total_read <= 4096:
                        try:
                            err_doc = json.loads(cap_probe_buf.decode("utf-8"))
                            err_obj = err_doc.get("error") if isinstance(err_doc, dict) else None
                            if isinstance(err_obj, dict):
                                err_code = err_obj.get("code")
                                err_type = err_obj.get("type")
                                err_msg = err_obj.get("message")
                                if (
                                    err_code == "session_request_budget_exceeded"
                                    or err_type == "session_request_budget_exceeded"
                                    or (
                                        isinstance(err_msg, str)
                                        and (
                                            "Session chat request cap (" in err_msg
                                            or "se-key-proxy max_chat_requests" in err_msg
                                        )
                                    )
                                ):
                                    with relay._lock:
                                        relay.upstream_session_cap_exhausted = True
                        except Exception:
                            pass
                except (BrokenPipeError, ConnectionResetError):
                    self.close_connection = True
                except Exception as exc:
                    self.close_connection = True
                    if not headers_sent:
                        try:
                            self._send_json_error(
                                502,
                                f"Upstream proxy error: {exc}",
                                "upstream_error",
                            )
                        except Exception:
                            pass
                finally:
                    relay._inflight_sem.release()
                    try:
                        conn.close()
                    except Exception:
                        pass

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="session-auth-relay",
            daemon=True,
        )
        self._thread.start()
        return self

    def close(self) -> None:
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
            except Exception:
                pass
            try:
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        close_lease = getattr(self.lease_provider, 'close', None)
        if callable(close_lease):
            close_lease()


class _WorkerTokenRelay(SessionAuthRelay):
    """Worker-mode alias preserving worker-relay-* prefix and SecurityProfileError validation."""

    def __init__(
        self,
        *,
        upstream_base_url: str,
        upstream_session_token: str,
        extra_canary_secrets: Sequence[str] = (),
        max_chat_requests: int = 25,
        max_request_bytes: int = 131072,
        max_tokens_cap: int = 2048,
        ttl_seconds: float | None = None,
        upstream_timeout_seconds: float = 120.0,
        max_response_bytes: int = 16 * 1024 * 1024,
        default_chat_params: dict[str, Any] | None = None,
        lease_provider: Callable[[], dict[str, Any]] | None = None,
    ) -> None:
        from .security_profile import SecurityProfileError, validate_default_chat_params

        super().__init__(
            upstream_base_url=upstream_base_url,
            upstream_session_token=upstream_session_token,
            token_prefix="worker-relay",
            token_hex_bytes=32,
            extra_canary_secrets=extra_canary_secrets,
            max_chat_requests=max_chat_requests,
            max_request_bytes=max_request_bytes,
            max_tokens_cap=max_tokens_cap,
            ttl_seconds=ttl_seconds,
            upstream_timeout_seconds=upstream_timeout_seconds,
            max_response_bytes=max_response_bytes,
            default_chat_params=default_chat_params,
            error_cls=SecurityProfileError,
            chat_params_validator=validate_default_chat_params,
            lease_provider=lease_provider,
        )
