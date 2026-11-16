from __future__ import annotations

import base64
import http.server
import json
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from local_assist.se_key import (
    RELEASE_BINARY_PATH,
    TEST_BINARY_PATH,
    SEKeyIntegrityError,
    build_se_key_proxy,
    verify_se_key_proxy_binary,
)


class _ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def _free_port_pair() -> int:
    import random

    for _ in range(128):
        port = random.randint(22000, 48000)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s1:
            try:
                s1.bind(("127.0.0.1", port))
            except OSError:
                continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
            try:
                s2.bind(("127.0.0.1", port + 1000))
            except OSError:
                continue
        return port
    raise RuntimeError("Could not allocate free loopback port pair")


@unittest.skipUnless(
    sys.platform == "darwin" and shutil.which("swiftc") is not None,
    "requires macOS and swiftc",
)
class SEKeyProxyLeakBackstopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        release_valid = False
        try:
            verify_se_key_proxy_binary()
            release_valid = True
        except SEKeyIntegrityError:
            release_valid = False
        if not release_valid or not TEST_BINARY_PATH.exists():
            build_se_key_proxy(include_test_binary=True)
        cls.assertTrue = unittest.TestCase.assertTrue
        assert RELEASE_BINARY_PATH.exists()

    def test_outbound_body_blocks_raw_and_encoded_credentials_with_400(self) -> None:
        real_api_key = "tf-canary-provider-secret-884422"
        session_token = "se-session-" + ("a1b2" * 16)
        allowed_model = "deepseek-v4-1-flash"
        forwarded_bodies: list[dict[str, object]] = []

        class _UpstreamHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                forwarded_bodies.append(body)
                resp = json.dumps(
                    {
                        "id": "chatcmpl-clean",
                        "object": "chat.completion",
                        "model": allowed_model,
                        "choices": [
                            {"index": 0, "message": {"role": "assistant", "content": "clean"}}
                        ],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

        upstream_srv = _ThreadedHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
        upstream_port = int(upstream_srv.server_address[1])
        upstream_thread = threading.Thread(target=upstream_srv.serve_forever, daemon=True)
        upstream_thread.start()

        proxy_port = _free_port_pair()
        with tempfile.TemporaryDirectory() as tmp:
            tok_file = Path(tmp) / ".se-session-leaktest.token"
            tok_file.write_text(session_token + "\n", encoding="utf-8")
            os.chmod(tok_file, 0o600)

            tok_r, tok_w = os.pipe()
            key_r, key_w = os.pipe()
            ready_r, ready_w = os.pipe()
            os.write(tok_w, (session_token + "\n").encode("utf-8"))
            os.close(tok_w)
            os.write(key_w, (real_api_key + "\n").encode("utf-8"))
            os.close(key_w)

            proxy_proc = subprocess.Popen(
                [
                    str(TEST_BINARY_PATH),
                    "proxy",
                    "--service",
                    "free-inference.leaktest",
                    "--listen-host",
                    "127.0.0.1",
                    "--listen-port",
                    str(proxy_port),
                    "--upstream-url",
                    f"http://127.0.0.1:{upstream_port}/v1",
                    "--upstream-pid",
                    str(os.getpid()),
                    "--allowed-model",
                    allowed_model,
                    "--session-token-fd",
                    str(tok_r),
                    "--session-token-file",
                    str(tok_file),
                    "--max-chat-requests",
                    "5",
                    "--max-tokens-cap",
                    "256",
                    "--max-request-bytes",
                    "16384",
                    "--ttl-seconds",
                    "60",
                    "--stream-timeout-seconds",
                    "5",
                    "--ready-fd",
                    str(ready_w),
                    "--test-ephemeral-key-fd",
                    str(key_r),
                ],
                pass_fds=(tok_r, key_r, ready_w),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            os.close(tok_r)
            os.close(key_r)
            os.close(ready_w)
            try:
                ready_obj = json.loads(os.read(ready_r, 256).decode("utf-8").strip())
                os.close(ready_r)
                self.assertEqual(ready_obj.get("status"), "ready")

                url = f"http://127.0.0.1:{proxy_port}/v1/chat/completions"
                headers = {
                    "Authorization": f"Bearer {session_token}",
                    "Content-Type": "application/json",
                }

                # Encode variants of session_token, real_api_key, and relay prefixes
                pct_tok = f"se-session%2D{session_token[len('se-session-'):]}"
                b64_tok = base64.b64encode(session_token.encode("utf-8")).decode("ascii")
                b64url_tok = (
                    base64.urlsafe_b64encode(session_token.encode("utf-8"))
                    .decode("ascii")
                    .rstrip("=")
                )
                pct_key = quote(real_api_key, safe="")
                if pct_key == real_api_key:
                    pct_key = f"tf%2D{real_api_key[3:]}"
                b64_key = base64.b64encode(real_api_key.encode("utf-8")).decode("ascii")
                relay_tok = "oc-relay-" + ("9f" * 32)
                b64_relay = base64.b64encode(relay_tok.encode("utf-8")).decode("ascii")

                leak_cases = [
                    ("raw_session_token", session_token),
                    ("percent_session_token", pct_tok),
                    ("base64_session_token", b64_tok),
                    ("base64url_session_token", b64url_tok),
                    ("raw_api_key", real_api_key),
                    ("percent_api_key", pct_key),
                    ("base64_api_key", b64_key),
                    ("raw_oc_relay", relay_tok),
                    ("base64_oc_relay", b64_relay),
                ]

                for label, payload_secret in leak_cases:
                    body_bytes = json.dumps(
                        {
                            "model": allowed_model,
                            "messages": [
                                {"role": "user", "content": f"probe {label}: {payload_secret}"}
                            ],
                        }
                    ).encode("utf-8")
                    req = Request(url, data=body_bytes, headers=headers, method="POST")
                    with self.assertRaises(HTTPError, msg=f"Expected HTTP 400 for {label}") as ctx:
                        urlopen(req, timeout=5)
                    err_body = ctx.exception.read().decode("utf-8", errors="replace")
                    ctx.exception.close()
                    self.assertEqual(ctx.exception.code, 400, f"{label}: {err_body}")
                    err_json = json.loads(err_body)
                    err_obj = err_json.get("error") or {}
                    self.assertEqual(
                        err_obj.get("type") or err_obj.get("code"),
                        "credential_leak_blocked",
                        f"{label}: {err_json}",
                    )
                    self.assertNotIn(session_token, err_body)
                    self.assertNotIn(real_api_key, err_body)

                # Zero leaked payloads were forwarded upstream and none consumed the 5-request cap
                self.assertEqual(len(forwarded_bodies), 0)

                # Subsequent clean request succeeds with HTTP 200
                clean_bytes = json.dumps(
                    {
                        "model": allowed_model,
                        "messages": [{"role": "user", "content": "Hello clean world"}],
                    }
                ).encode("utf-8")
                with urlopen(Request(url, data=clean_bytes, headers=headers, method="POST"), timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    resp_obj = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(resp_obj["choices"][0]["message"]["content"], "clean")
                self.assertEqual(len(forwarded_bodies), 1)
            finally:
                proxy_proc.terminate()
                try:
                    proxy_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proxy_proc.kill()
                    proxy_proc.wait(timeout=5)
                for stream in (proxy_proc.stdout, proxy_proc.stderr):
                    if stream is not None:
                        stream.close()
                upstream_srv.shutdown()
                upstream_srv.server_close()

    def test_f3_iso_p3_slash_and_unicode_escaped_provider_keys_in_values_keys_and_nested_json(self) -> None:
        real_api_key = "sk-prov-test/slash/key-99887766"
        session_token = "se-session-" + ("c3d4" * 16)
        allowed_model = "deepseek-v4-1-flash"
        forwarded_bodies: list[dict[str, object]] = []

        class _UpstreamHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                forwarded_bodies.append(body)
                resp = json.dumps(
                    {
                        "id": "chatcmpl-clean-f3",
                        "object": "chat.completion",
                        "model": allowed_model,
                        "choices": [
                            {"index": 0, "message": {"role": "assistant", "content": "clean-f3"}}
                        ],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

        upstream_srv = _ThreadedHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
        upstream_port = int(upstream_srv.server_address[1])
        threading.Thread(target=upstream_srv.serve_forever, daemon=True).start()

        proxy_port = _free_port_pair()
        with tempfile.TemporaryDirectory() as tmp:
            tok_file = Path(tmp) / ".se-session-f3test.token"
            tok_file.write_text(session_token + "\n", encoding="utf-8")
            os.chmod(tok_file, 0o600)

            tok_r, tok_w = os.pipe()
            key_r, key_w = os.pipe()
            ready_r, ready_w = os.pipe()
            os.write(tok_w, (session_token + "\n").encode("utf-8"))
            os.close(tok_w)
            os.write(key_w, (real_api_key + "\n").encode("utf-8"))
            os.close(key_w)

            proxy_proc = subprocess.Popen(
                [
                    str(TEST_BINARY_PATH),
                    "proxy",
                    "--service",
                    "free-inference.f3test",
                    "--listen-host",
                    "127.0.0.1",
                    "--listen-port",
                    str(proxy_port),
                    "--upstream-url",
                    f"http://127.0.0.1:{upstream_port}/v1",
                    "--upstream-pid",
                    str(os.getpid()),
                    "--allowed-model",
                    allowed_model,
                    "--session-token-fd",
                    str(tok_r),
                    "--session-token-file",
                    str(tok_file),
                    "--max-chat-requests",
                    "5",
                    "--max-tokens-cap",
                    "256",
                    "--max-request-bytes",
                    "327680",
                    "--ttl-seconds",
                    "60",
                    "--stream-timeout-seconds",
                    "5",
                    "--ready-fd",
                    str(ready_w),
                    "--test-ephemeral-key-fd",
                    str(key_r),
                ],
                pass_fds=(tok_r, key_r, ready_w),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            os.close(tok_r)
            os.close(key_r)
            os.close(ready_w)
            try:
                ready_obj = json.loads(os.read(ready_r, 256).decode("utf-8").strip())
                os.close(ready_r)
                self.assertEqual(ready_obj.get("status"), "ready")

                url = f"http://127.0.0.1:{proxy_port}/v1/chat/completions"
                headers = {
                    "Authorization": f"Bearer {session_token}",
                    "Content-Type": "application/json",
                }

                full_u_escaped = "".join(f"\\u{ord(ch):04x}" for ch in real_api_key)
                slash_u_escaped = real_api_key.replace("/", "\\u002f")
                slash_bs_escaped = real_api_key.replace("/", "\\/")
                nested_json_u_escaped = '{"leaked_arg":"' + full_u_escaped + '"}'
                nested_json_slash_escaped = '{"leaked_arg":"' + slash_bs_escaped + '"}'
                b64_prefixed = base64.b64encode(f"header:{real_api_key}:tail".encode("utf-8")).decode("ascii")
                wrapped_offset2_b64 = base64.b64encode(
                    f"xy{real_api_key}Z".encode("utf-8")
                ).decode("ascii")
                key_b64_std = base64.b64encode(real_api_key.encode("utf-8")).decode("ascii")
                key_b64_nopad = key_b64_std.rstrip("=")
                key_b64_url = key_b64_nopad.replace("+", "-").replace("/", "_")
                key_basic_oc = (
                    base64.b64encode(f"opencode:{real_api_key}".encode("utf-8"))
                    .decode("ascii")
                    .rstrip("=")
                )
                key_basic_anon = (
                    base64.b64encode(f":{real_api_key}".encode("utf-8"))
                    .decode("ascii")
                    .rstrip("=")
                )
                for direct_needle in (
                    real_api_key,
                    key_b64_std,
                    key_b64_nopad,
                    key_b64_url,
                    key_basic_oc,
                    key_basic_anon,
                    "se-session-",
                    "oc-relay-",
                    "worker-relay-",
                ):
                    self.assertNotIn(direct_needle, wrapped_offset2_b64)
                padded_b64_leak = ("AbcdEfghIjklMnopQrst " * 300) + wrapped_offset2_b64
                budget_exhaustion_padding = "AbcdEfghIjklMnop " * 16400

                deep_container: object = "safe"
                for _ in range(70):
                    deep_container = [deep_container]

                raw_wire_cases: list[tuple[str, bytes]] = [
                    (
                        "unicode_slash_wire_value",
                        (
                            '{"model":"'
                            + allowed_model
                            + '","messages":[{"role":"user","content":"key='
                            + slash_u_escaped
                            + '"}]}'
                        ).encode("utf-8"),
                    ),
                    (
                        "backslash_slash_wire_value",
                        (
                            '{"model":"'
                            + allowed_model
                            + '","messages":[{"role":"user","content":"key='
                            + slash_bs_escaped
                            + '"}]}'
                        ).encode("utf-8"),
                    ),
                    (
                        "full_unicode_wire_key",
                        (
                            '{"model":"'
                            + allowed_model
                            + '","messages":[{"role":"user","content":"hi"}],"extra":{"'
                            + full_u_escaped
                            + '":"v"}}'
                        ).encode("utf-8"),
                    ),
                    (
                        "nested_json_in_message_content_unicode",
                        json.dumps(
                            {
                                "model": allowed_model,
                                "messages": [
                                    {"role": "user", "content": nested_json_u_escaped}
                                ],
                            }
                        ).encode("utf-8"),
                    ),
                    (
                        "nested_json_in_tool_call_arguments_deep_container_unicode",
                        json.dumps(
                            {
                                "model": allowed_model,
                                "messages": [
                                    {
                                        "role": "assistant",
                                        "content": None,
                                        "tool_calls": [
                                            {
                                                "id": "call_1",
                                                "type": "function",
                                                "function": {
                                                    "name": "probe_tool",
                                                    "arguments": nested_json_u_escaped,
                                                },
                                            }
                                        ],
                                    }
                                ],
                            }
                        ).encode("utf-8"),
                    ),
                    (
                        "nested_json_in_tool_call_arguments_slash_escaped",
                        json.dumps(
                            {
                                "model": allowed_model,
                                "messages": [
                                    {
                                        "role": "assistant",
                                        "content": None,
                                        "tool_calls": [
                                            {
                                                "id": "call_2",
                                                "type": "function",
                                                "function": {
                                                    "name": "probe_tool",
                                                    "arguments": nested_json_slash_escaped,
                                                },
                                            }
                                        ],
                                    }
                                ],
                            }
                        ).encode("utf-8"),
                    ),
                    (
                        "base64_wrapped_slash_key",
                        json.dumps(
                            {
                                "model": allowed_model,
                                "messages": [
                                    {"role": "user", "content": f"blob={b64_prefixed}"}
                                ],
                            }
                        ).encode("utf-8"),
                    ),
                    (
                        "r2_labeled_offset2_wrapped_base64",
                        json.dumps(
                            {
                                "model": allowed_model,
                                "messages": [
                                    {"role": "user", "content": f"blob={wrapped_offset2_b64}"}
                                ],
                            }
                        ).encode("utf-8"),
                    ),
                    (
                        "r2_token_label_offset2_wrapped_base64",
                        json.dumps(
                            {
                                "model": allowed_model,
                                "messages": [
                                    {"role": "user", "content": f"token={wrapped_offset2_b64}"}
                                ],
                            }
                        ).encode("utf-8"),
                    ),
                    (
                        "r2_long_label_offset2_wrapped_base64",
                        json.dumps(
                            {
                                "model": allowed_model,
                                "messages": [
                                    {
                                        "role": "user",
                                        "content": f"long_parameter_label={wrapped_offset2_b64}",
                                    }
                                ],
                            }
                        ).encode("utf-8"),
                    ),
                    (
                        "over_depth_container_fails_closed",
                        json.dumps(
                            {
                                "model": allowed_model,
                                "messages": [{"role": "user", "content": "depth check"}],
                                "nested": deep_container,
                            }
                        ).encode("utf-8"),
                    ),
                    (
                        "iso_w3_padded_beyond_256_base64_candidates",
                        json.dumps(
                            {
                                "model": allowed_model,
                                "messages": [{"role": "user", "content": padded_b64_leak}],
                            }
                        ).encode("utf-8"),
                    ),
                    (
                        "iso_w3_candidate_budget_exhaustion_fails_closed",
                        json.dumps(
                            {
                                "model": allowed_model,
                                "messages": [
                                    {"role": "user", "content": budget_exhaustion_padding}
                                ],
                            }
                        ).encode("utf-8"),
                    ),
                ]

                for label, body_bytes in raw_wire_cases:
                    req = Request(url, data=body_bytes, headers=headers, method="POST")
                    with self.assertRaises(HTTPError, msg=f"Expected HTTP 400 for {label}") as ctx:
                        urlopen(req, timeout=5)
                    err_body = ctx.exception.read().decode("utf-8", errors="replace")
                    ctx.exception.close()
                    self.assertEqual(ctx.exception.code, 400, f"{label}: {err_body}")
                    err_json = json.loads(err_body)
                    err_obj = err_json.get("error") or {}
                    self.assertEqual(
                        err_obj.get("type") or err_obj.get("code"),
                        "credential_leak_blocked",
                        f"{label}: {err_json}",
                    )
                    self.assertNotIn(real_api_key, err_body)

                self.assertEqual(len(forwarded_bodies), 0)

                # Clean nested tool_calls arguments control must pass with HTTP 200
                clean_nested_bytes = json.dumps(
                    {
                        "model": allowed_model,
                        "messages": [
                            {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [
                                    {
                                        "id": "call_ok",
                                        "type": "function",
                                        "function": {
                                            "name": "safe_tool",
                                            "arguments": json.dumps({"path": "src/app/main.py", "line": 42}),
                                        },
                                    }
                                ],
                            },
                            {"role": "tool", "tool_call_id": "call_ok", "content": "ok"},
                        ],
                    }
                ).encode("utf-8")
                with urlopen(Request(url, data=clean_nested_bytes, headers=headers, method="POST"), timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                self.assertEqual(len(forwarded_bodies), 1)

                # Clean control with >256 harmless base64-shaped words must also pass with HTTP 200
                clean_padded_bytes = json.dumps(
                    {
                        "model": allowed_model,
                        "messages": [
                            {
                                "role": "user",
                                "content": "AbcdEfghIjklMnopQrst " * 300,
                            }
                        ],
                    }
                ).encode("utf-8")
                with urlopen(Request(url, data=clean_padded_bytes, headers=headers, method="POST"), timeout=5) as resp2:
                    self.assertEqual(resp2.status, 200)
                self.assertEqual(len(forwarded_bodies), 2)
            finally:
                proxy_proc.terminate()
                try:
                    proxy_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proxy_proc.kill()
                    proxy_proc.wait(timeout=5)
                for stream in (proxy_proc.stdout, proxy_proc.stderr):
                    if stream is not None:
                        stream.close()
                upstream_srv.shutdown()
                upstream_srv.server_close()


if __name__ == "__main__":
    unittest.main()
