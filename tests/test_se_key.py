from __future__ import annotations

import hashlib
import http.server
import importlib.machinery
import importlib.util
import json
import os
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from local_assist.registry import (
    SESSION_TOKEN_ENV_VAR,
    RegistryError,
    build_promptfoo_provider_entry,
    get_process_lstart,
    resolve_endpoint,
)
from local_assist.se_key import (
    RELEASE_BINARY_PATH,
    STAMP_PATH,
    SWIFT_SOURCE_PATH,
    TEST_BINARY_PATH,
    SEKeyIntegrityError,
    build_se_key_proxy,
    redact_session_tokens,
    scan_and_redact_directory_tokens,
    verify_se_key_proxy_binary,
)


def _load_script_module(name: str, rel_path: str) -> ModuleType:
    script_path = ROOT / rel_path
    loader = importlib.machinery.SourceFileLoader(name, str(script_path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_USED_TEST_PORTS: set[int] = set()


def _free_port() -> int:
    for _ in range(50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = int(s.getsockname()[1])
        if port <= 60000 and port not in _USED_TEST_PORTS and (port + 1000) not in _USED_TEST_PORTS:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
                try:
                    s2.bind(("127.0.0.1", port + 1000))
                except OSError:
                    continue
            _USED_TEST_PORTS.add(port)
            _USED_TEST_PORTS.add(port + 1000)
            return port
    for candidate in range(25000, 59000, 17):
        if candidate in _USED_TEST_PORTS or (candidate + 1000) in _USED_TEST_PORTS:
            continue
        with (
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s1,
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2,
        ):
            try:
                s1.bind(("127.0.0.1", candidate))
                s2.bind(("127.0.0.1", candidate + 1000))
            except OSError:
                continue
        _USED_TEST_PORTS.add(candidate)
        _USED_TEST_PORTS.add(candidate + 1000)
        return candidate
    raise RuntimeError("Could not allocate a free loopback port <= 60000")


class _ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


@unittest.skipUnless(
    sys.platform == "darwin" and shutil.which("swiftc") is not None,
    "requires macOS and swiftc",
)
class SEKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not RELEASE_BINARY_PATH.exists() or not STAMP_PATH.exists() or not TEST_BINARY_PATH.exists():
            build_se_key_proxy(include_test_binary=True)

    def test_se_key_selftest_and_live_biometric_gate(self) -> None:
        proc = subprocess.run(
            [str(RELEASE_BINARY_PATH), "selftest"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertIn(
            proc.returncode,
            (0, 77),
            f"Unexpected selftest exit code {proc.returncode}: stdout={proc.stdout} stderr={proc.stderr}",
        )
        payload = json.loads(proc.stdout.strip())
        if proc.returncode == 77:
            self.assertEqual(payload.get("status"), "skipped")
            self.assertTrue(payload.get("skipped"))
            if "software_ecies_roundtrip_ok" in payload:
                self.assertIs(payload.get("software_ecies_roundtrip_ok"), True)
                self.assertIs(payload.get("wrong_service_aad_rejected"), True)
                self.assertIs(payload.get("tampered_ciphertext_rejected"), True)
                self.assertIs(payload.get("connect_deadline_underflow_protected"), True)
                self.assertIs(payload.get("cancel_after_close_noop"), True)
            self.skipTest(str(payload.get("reason", "Secure Enclave or Touch ID unavailable")))

        self.assertEqual(proc.returncode, 0)
        self.assertEqual(payload.get("status"), "passed")
        self.assertIs(payload.get("secure_enclave_available"), True)
        self.assertIs(payload.get("biometrics_available"), True)
        self.assertIs(payload.get("software_ecies_roundtrip_ok"), True)
        self.assertIs(payload.get("wrong_service_aad_rejected"), True)
        self.assertIs(payload.get("tampered_ciphertext_rejected"), True)
        self.assertIs(payload.get("connect_deadline_underflow_protected"), True)
        self.assertIs(payload.get("cancel_after_close_noop"), True)
        self.assertIs(payload.get("unseal_blocked_without_interaction"), True)
        self.assertIn(payload.get("block_error_code"), (-1004, -25308, -25293))
        self.assertTrue(str(payload.get("block_error") or "").strip())

    def test_release_binary_rejects_test_flags_and_stamp_integrity(self) -> None:
        # 1. Release binary must pass verification and reject --test-ephemeral-key-fd with exit code 2
        verified_bin = verify_se_key_proxy_binary()
        self.assertEqual(verified_bin, RELEASE_BINARY_PATH.resolve())

        proc = subprocess.run(
            [str(RELEASE_BINARY_PATH), "proxy", "--test-ephemeral-key-fd", "0"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("Unknown proxy argument", proc.stderr)

        proc_url = subprocess.run(
            [str(RELEASE_BINARY_PATH), "proxy", "--test-force-urlsession"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(proc_url.returncode, 2)
        self.assertIn("Unknown proxy argument", proc_url.stderr)

        # 2. Tampering with source or binary or stamp fails closed with SEKeyIntegrityError
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            fake_src = tmp_dir / "main.swift"
            fake_bin = tmp_dir / "se-key-proxy"
            fake_stamp = tmp_dir / ".se-key-proxy.stamp"

            shutil.copy2(SWIFT_SOURCE_PATH, fake_src)
            shutil.copy2(RELEASE_BINARY_PATH, fake_bin)
            shutil.copy2(STAMP_PATH, fake_stamp)

            # Valid when paths match stamp
            ok_path = verify_se_key_proxy_binary(
                source_path=fake_src,
                binary_path=fake_bin,
                stamp_path=fake_stamp,
                env={},
            )
            self.assertEqual(ok_path, fake_bin.resolve())

            # Modify source without rebuilding -> SEKeyIntegrityError
            fake_src.write_text(
                fake_src.read_text(encoding="utf-8") + "\n// tampered\n",
                encoding="utf-8",
            )
            with self.assertRaises(SEKeyIntegrityError) as src_ctx:
                verify_se_key_proxy_binary(
                    source_path=fake_src,
                    binary_path=fake_bin,
                    stamp_path=fake_stamp,
                    env={},
                )
            self.assertIn("source drift", str(src_ctx.exception).lower())

            # Restore source, tamper with stamp binary_sha256 -> SEKeyIntegrityError
            shutil.copy2(SWIFT_SOURCE_PATH, fake_src)
            stamp_data = json.loads(fake_stamp.read_text(encoding="utf-8"))
            stamp_data["binary_sha256"] = "0" * 64
            fake_stamp.write_text(json.dumps(stamp_data), encoding="utf-8")
            with self.assertRaises(SEKeyIntegrityError) as bin_ctx:
                verify_se_key_proxy_binary(
                    source_path=fake_src,
                    binary_path=fake_bin,
                    stamp_path=fake_stamp,
                    env={},
                )
            self.assertIn("mismatch", str(bin_ctx.exception).lower())

            # Restore stamp, corrupt binary bytes -> codesign or hash failure -> SEKeyIntegrityError
            shutil.copy2(STAMP_PATH, fake_stamp)
            raw_bytes = bytearray(fake_bin.read_bytes())
            raw_bytes[-1] ^= 0xFF
            fake_bin.write_bytes(bytes(raw_bytes))
            with self.assertRaises(SEKeyIntegrityError):
                verify_se_key_proxy_binary(
                    source_path=fake_src,
                    binary_path=fake_bin,
                    stamp_path=fake_stamp,
                    env={},
                )

            # 3. FREE_INFERENCE_SE_PROXY_BIN override rejects user-owned binaries (requires root uid=0)
            shutil.copy2(RELEASE_BINARY_PATH, fake_bin)
            with self.assertRaises(SEKeyIntegrityError) as root_ctx:
                verify_se_key_proxy_binary(
                    env={"FREE_INFERENCE_SE_PROXY_BIN": str(fake_bin)},
                )
            self.assertIn("owned by root", str(root_ctx.exception))

    def test_se_key_proxy_http_and_policy_enforcement(self) -> None:
        real_api_key = "tf-test-real-api-key-9999"
        session_token = "se-session-" + ("c" * 64)
        allowed_model = "deepseek-ai/DeepSeek-V3.1"

        received_requests: list[dict[str, object]] = []
        sse_chunk1_sent = threading.Event()
        sse_release_chunk2 = threading.Event()

        class MockUpstreamHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_GET(self) -> None:
                received_requests.append(
                    {
                        "method": "GET",
                        "path": self.path,
                        "auth": self.headers.get("Authorization"),
                        "accept_encoding": self.headers.get("Accept-Encoding"),
                        "x_leak": self.headers.get("X-Leak"),
                        "cookie": self.headers.get("Cookie"),
                    }
                )
                body = json.dumps({"object": "list", "data": [{"id": allowed_model}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(length)
                parsed = json.loads(raw_body.decode("utf-8"))
                received_requests.append(
                    {
                        "method": "POST",
                        "path": self.path,
                        "auth": self.headers.get("Authorization"),
                        "accept_encoding": self.headers.get("Accept-Encoding"),
                        "x_leak": self.headers.get("X-Leak"),
                        "cookie": self.headers.get("Cookie"),
                        "body": parsed,
                    }
                )
                if parsed.get("stream_stall"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                    self.end_headers()
                    try:
                        self.wfile.write(b'data: {"choices":[{"delta":{"content":"stall"}}]}\n\n')
                        self.wfile.flush()
                        time.sleep(2.0)
                        self.wfile.write(b"data: LATE_CORRUPTION\n\n")
                        self.wfile.flush()
                    except OSError:
                        pass
                    return
                if parsed.get("stream"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                    self.end_headers()
                    chunk1 = b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'
                    self.wfile.write(chunk1)
                    self.wfile.flush()
                    sse_chunk1_sent.set()
                    sse_release_chunk2.wait(timeout=5.0)
                    chunk2 = b"data: [DONE]\n\n"
                    self.wfile.write(chunk2)
                    self.wfile.flush()
                    return

                resp_body = json.dumps(
                    {
                        "id": "chatcmpl-1",
                        "object": "chat.completion",
                        "model": allowed_model,
                        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)

        upstream_srv = _ThreadedHTTPServer(("127.0.0.1", 0), MockUpstreamHandler)
        upstream_port = int(upstream_srv.server_address[1])
        upstream_thread = threading.Thread(target=upstream_srv.serve_forever, daemon=True)
        upstream_thread.start()

        proxy_port = _free_port()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            tok_file = tmp_dir / ".se-session-test.token"
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
                    "free-inference.test",
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
                    "4",
                    "--max-tokens-cap",
                    "128",
                    "--max-request-bytes",
                    "1024",
                    "--ttl-seconds",
                    "60",
                    "--stream-timeout-seconds",
                    "1",
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
                ready_bytes = os.read(ready_r, 256)
                os.close(ready_r)
                ready_obj = json.loads(ready_bytes.decode("utf-8").strip())
                self.assertEqual(ready_obj.get("status"), "ready")
                self.assertEqual(ready_obj.get("listen_port"), proxy_port)

                base_url = f"http://127.0.0.1:{proxy_port}/v1"

                # 1. Missing or wrong session token -> 401 Unauthorized, never reaches upstream
                for bad_headers in ({}, {"Authorization": "Bearer wrong-token"}):
                    req = Request(f"{base_url}/models", headers=bad_headers, method="GET")
                    with self.assertRaises(HTTPError) as err_401:
                        urlopen(req, timeout=3)
                    self.assertEqual(err_401.exception.code, 401)
                    err_401.exception.close()
                self.assertEqual(len(received_requests), 0)

                # 2. Non-loopback Host header -> 400 Bad Request
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as s:
                    s.sendall(
                        f"GET /v1/models HTTP/1.1\r\n"
                        f"Host: evil.example.com\r\n"
                        f"Authorization: Bearer {session_token}\r\n\r\n".encode("utf-8")
                    )
                    raw_resp = s.recv(4096).decode("utf-8", errors="replace")
                self.assertTrue(raw_resp.startswith("HTTP/1.1 400"))
                self.assertEqual(len(received_requests), 0)

                # 3. Transfer-Encoding: chunked, missing Content-Length, and duplicate conflicting Content-Length -> 400/411
                for raw_http, expected_code in (
                    (
                        f"POST /v1/chat/completions HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{proxy_port}\r\n"
                        f"Authorization: Bearer {session_token}\r\n"
                        f"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                        "400",
                    ),
                    (
                        f"POST /v1/chat/completions HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{proxy_port}\r\n"
                        f"Authorization: Bearer {session_token}\r\n\r\n",
                        "411",
                    ),
                    (
                        f"POST /v1/chat/completions HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{proxy_port}\r\n"
                        f"Authorization: Bearer {session_token}\r\n"
                        f"Content-Length: 2\r\n"
                        f"Content-Length: 4\r\n\r\n{{}}",
                        "400",
                    ),
                ):
                    with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as s:
                        s.sendall(raw_http.encode("utf-8"))
                        resp_line = s.recv(4096).decode("utf-8", errors="replace")
                    self.assertTrue(
                        resp_line.startswith(f"HTTP/1.1 {expected_code}"),
                        f"Expected {expected_code}, got: {resp_line}",
                    )
                self.assertEqual(len(received_requests), 0)

                # 4. Disallowed paths, path traversal, and percent-encoded slashes/dots -> 403 Forbidden
                for bad_path in (
                    "/v1/files",
                    "/admin",
                    "/v1/../admin",
                    "/v1/chat/../files",
                    "/v1/%2e%2e/admin",
                    "/v1/chat%2fcompletions",
                ):
                    with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as s:
                        s.sendall(
                            f"GET {bad_path} HTTP/1.1\r\n"
                            f"Host: 127.0.0.1:{proxy_port}\r\n"
                            f"Authorization: Bearer {session_token}\r\n\r\n".encode("utf-8")
                        )
                        resp_line = s.recv(4096).decode("utf-8", errors="replace")
                    self.assertTrue(
                        resp_line.startswith("HTTP/1.1 403"),
                        f"Path {bad_path} expected 403, got: {resp_line}",
                    )
                self.assertEqual(len(received_requests), 0)

                # 5. Duplicate "model" JSON key -> 400 Bad Request; mismatched model -> 403 Forbidden
                dup_json = (
                    f'{{"model":"{allowed_model}","model":"other/model",'
                    f'"messages":[{{"role":"user","content":"hi"}}]}}'
                ).encode("utf-8")
                req_dup = Request(
                    f"{base_url}/chat/completions",
                    data=dup_json,
                    headers={
                        "Authorization": f"Bearer {session_token}",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                with self.assertRaises(HTTPError) as err_dup:
                    urlopen(req_dup, timeout=3)
                self.assertEqual(err_dup.exception.code, 400)
                err_dup.exception.close()

                wrong_model_json = json.dumps(
                    {"model": "other/model", "messages": [{"role": "user", "content": "hi"}]}
                ).encode("utf-8")
                req_wrong = Request(
                    f"{base_url}/chat/completions",
                    data=wrong_model_json,
                    headers={
                        "Authorization": f"Bearer {session_token}",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                with self.assertRaises(HTTPError) as err_wrong:
                    urlopen(req_wrong, timeout=3)
                self.assertEqual(err_wrong.exception.code, 403)
                err_wrong.exception.close()
                self.assertEqual(len(received_requests), 0)

                # 6. Oversized body (> 1024 bytes) -> 413 Payload Too Large
                huge_body = json.dumps(
                    {
                        "model": allowed_model,
                        "messages": [{"role": "user", "content": "x" * 1500}],
                    }
                ).encode("utf-8")
                req_huge = Request(
                    f"{base_url}/chat/completions",
                    data=huge_body,
                    headers={
                        "Authorization": f"Bearer {session_token}",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                with self.assertRaises(HTTPError) as err_413:
                    urlopen(req_huge, timeout=3)
                self.assertEqual(err_413.exception.code, 413)
                err_413.exception.close()
                self.assertEqual(len(received_requests), 0)

                # 7. Valid GET /v1/models?foo=1 -> 200 OK, upstream receives real key, Accept-Encoding: identity, query string, and strips caller headers
                req_models = Request(
                    f"{base_url}/models?foo=1",
                    headers={
                        "Authorization": f"Bearer {session_token}",
                        "X-Leak": "1",
                        "Cookie": "s=1",
                    },
                    method="GET",
                )
                with urlopen(req_models, timeout=3) as resp_m:
                    self.assertEqual(resp_m.status, 200)
                    models_payload = json.loads(resp_m.read().decode("utf-8"))
                self.assertEqual(models_payload["data"][0]["id"], allowed_model)
                self.assertEqual(len(received_requests), 1)
                self.assertEqual(received_requests[0]["path"], "/v1/models?foo=1")
                self.assertEqual(received_requests[0]["auth"], f"Bearer {real_api_key}")
                self.assertEqual(received_requests[0]["accept_encoding"], "identity")
                self.assertIsNone(received_requests[0]["x_leak"])
                self.assertIsNone(received_requests[0]["cookie"])

                # 8. Valid POST /v1/chat/completions (JSON) with max_tokens=999 -> clamped to 128 and strips caller headers
                chat_payload = json.dumps(
                    {
                        "model": allowed_model,
                        "messages": [{"role": "user", "content": "hello"}],
                        "max_tokens": 999,
                    }
                ).encode("utf-8")
                req_chat = Request(
                    f"{base_url}/chat/completions",
                    data=chat_payload,
                    headers={
                        "Authorization": f"Bearer {session_token}",
                        "Content-Type": "application/json",
                        "X-Leak": "1",
                        "Cookie": "s=1",
                    },
                    method="POST",
                )
                with urlopen(req_chat, timeout=3) as resp_c:
                    self.assertEqual(resp_c.status, 200)
                    chat_resp = json.loads(resp_c.read().decode("utf-8"))
                self.assertEqual(chat_resp["choices"][0]["message"]["content"], "ok")
                self.assertEqual(len(received_requests), 2)
                forwarded_body = received_requests[1]["body"]
                assert isinstance(forwarded_body, dict)
                self.assertEqual(forwarded_body["max_tokens"], 128)
                self.assertEqual(received_requests[1]["auth"], f"Bearer {real_api_key}")
                self.assertIsNone(received_requests[1]["x_leak"])
                self.assertIsNone(received_requests[1]["cookie"])

                # 9. Valid POST /v1/chat/completions (streaming SSE) delivers chunk 1 BEFORE chunk 2 is released
                sse_payload = json.dumps(
                    {
                        "model": allowed_model,
                        "messages": [{"role": "user", "content": "stream"}],
                        "stream": True,
                    }
                ).encode("utf-8")
                req_sse = Request(
                    f"{base_url}/chat/completions",
                    data=sse_payload,
                    headers={
                        "Authorization": f"Bearer {session_token}",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                with urlopen(req_sse, timeout=5) as resp_sse:
                    self.assertTrue(sse_chunk1_sent.wait(timeout=3.0))
                    first_line = resp_sse.readline().decode("utf-8")
                    self.assertIn('"content":"hello"', first_line)
                    self.assertFalse(sse_release_chunk2.is_set())
                    sse_release_chunk2.set()
                    rest = resp_sse.read().decode("utf-8")
                    self.assertIn("[DONE]", rest)

                # 9b. Stalled streaming request (--stream-timeout-seconds 1) cancels and drains cleanly
                # before closing clientFD, never corrupting a subsequent client connection (W2).
                stall_payload = json.dumps(
                    {
                        "model": allowed_model,
                        "messages": [{"role": "user", "content": "stall"}],
                        "stream": True,
                        "stream_stall": True,
                    }
                ).encode("utf-8")
                req_stall = Request(
                    f"{base_url}/chat/completions",
                    data=stall_payload,
                    headers={
                        "Authorization": f"Bearer {session_token}",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                t0 = time.monotonic()
                with urlopen(req_stall, timeout=5) as resp_stall:
                    stall_text = resp_stall.read().decode("utf-8", errors="replace")
                elapsed_stall = time.monotonic() - t0
                self.assertIn('"content":"stall"', stall_text)
                self.assertNotIn("LATE_CORRUPTION", stall_text)
                self.assertLess(elapsed_stall, 3.0)

                # Subsequent client requests immediately after timeout must receive uncorrupted responses
                with urlopen(req_models, timeout=3) as resp_m2:
                    self.assertEqual(resp_m2.status, 200)
                    models_payload_2 = json.loads(resp_m2.read().decode("utf-8"))
                self.assertEqual(models_payload_2["data"][0]["id"], allowed_model)

                # 10. Chat request cap (--max-chat-requests 4): we have made 3 valid POST chat requests so far.
                # Chat request #4 succeeds; chat request #5 returns 429 Too Many Requests.
                with urlopen(req_chat, timeout=3) as resp_4:
                    self.assertEqual(resp_4.status, 200)
                with self.assertRaises(HTTPError) as err_429:
                    urlopen(req_chat, timeout=3)
                self.assertEqual(err_429.exception.code, 429)
                err_429.exception.close()
            finally:
                proxy_proc.terminate()
                try:
                    proxy_proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proxy_proc.kill()
                if proxy_proc.stdout:
                    proxy_proc.stdout.close()
                if proxy_proc.stderr:
                    proxy_proc.stderr.close()

            # 11. Verify --ttl-seconds teardown kills --upstream-pid and unlinks --session-token-file
            ttl_tok_file = tmp_dir / ".se-session-ttl.token"
            ttl_tok_file.write_text(session_token + "\n", encoding="utf-8")
            os.chmod(ttl_tok_file, 0o600)
            ttl_up_port = _free_port()
            dummy_upstream = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    f"import socket, time; s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('127.0.0.1', {ttl_up_port})); s.listen(5); time.sleep(60)",
                ]
            )
            tok_r2, tok_w2 = os.pipe()
            key_r2, key_w2 = os.pipe()
            ready_r2, ready_w2 = os.pipe()
            os.write(tok_w2, (session_token + "\n").encode("utf-8"))
            os.close(tok_w2)
            os.write(key_w2, (real_api_key + "\n").encode("utf-8"))
            os.close(key_w2)
            ttl_port = _free_port()
            ttl_proxy = subprocess.Popen(
                [
                    str(TEST_BINARY_PATH),
                    "proxy",
                    "--service",
                    "free-inference.test",
                    "--listen-host",
                    "127.0.0.1",
                    "--listen-port",
                    str(ttl_port),
                    "--upstream-url",
                    f"http://127.0.0.1:{ttl_up_port}/v1",
                    "--allowed-model",
                    allowed_model,
                    "--session-token-fd",
                    str(tok_r2),
                    "--session-token-file",
                    str(ttl_tok_file),
                    "--upstream-pid",
                    str(dummy_upstream.pid),
                    "--ttl-seconds",
                    "1",
                    "--ready-fd",
                    str(ready_w2),
                    "--test-ephemeral-key-fd",
                    str(key_r2),
                ],
                pass_fds=(tok_r2, key_r2, ready_w2),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            os.close(tok_r2)
            os.close(key_r2)
            os.close(ready_w2)
            try:
                ready2 = os.read(ready_r2, 256)
                os.close(ready_r2)
                ready2_obj = json.loads(ready2.decode("utf-8").strip())
                self.assertEqual(ready2_obj.get("status"), "ready")
                ttl_proxy.wait(timeout=5)
                dummy_upstream.wait(timeout=5)
                self.assertFalse(ttl_tok_file.exists())
            finally:
                if ttl_proxy.poll() is None:
                    ttl_proxy.kill()
                if dummy_upstream.poll() is None:
                    dummy_upstream.kill()
                if ttl_proxy.stdout:
                    ttl_proxy.stdout.close()
                if ttl_proxy.stderr:
                    ttl_proxy.stderr.close()

        upstream_srv.shutdown()
        upstream_srv.server_close()

    def test_serve_model_rollback_on_unlock_or_upstream_failure(self) -> None:
        serve_mod = _load_script_module("serve_model_rollback_script", "scripts/serve-model")
        stop_mod = _load_script_module("stop_model_rollback_script", "scripts/stop-model")
        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = Path(tmp)
            serve_mod.RUNS = runs_dir
            stop_mod.RUNS = runs_dir
            port = _free_port()
            up_pid_file = runs_dir / "inner_upstream.pid"

            # Case A: Inner upstream binds its port and stays alive, se-key-proxy fails to unlock (missing keychain item).
            # serve-model must kill the inner upstream process and remove all PID and session-token files.
            model_entry_a = {
                "id": "tinfoil-rollback-test",
                "repo": "deepseek-ai/DeepSeek-V3.1",
                "runtime": "proxy",
                "serve_command": (
                    f"{sys.executable} -c "
                    f"\"import os, pathlib, socket, time; "
                    f"s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
                    f"s.bind(('127.0.0.1', {{port}})); s.listen(5); "
                    f"pathlib.Path({str(up_pid_file)!r}).write_text(str(os.getpid())); time.sleep(60)\" "
                    f"--host {{host}} --port {{port}}"
                ),
                "promptfoo_provider": {
                    "apiBaseUrl": f"http://127.0.0.1:{port}/v1",
                    "apiKeyKeychainService": "free-inference.tinfoil-nonexistent",
                },
                "remote_trust": {
                    "tier": "enclave_runtime_attested",
                    "attestation_method": "tinfoil-proxy-sigstore",
                },
            }
            with patch.object(serve_mod, "load_model", return_value=model_entry_a):
                rc_a = serve_mod.main(
                    [
                        "scripts/serve-model",
                        "tinfoil-rollback-test",
                        "--max-tokens-cap",
                        "512",
                        "--max-request-bytes",
                        "32768",
                    ]
                )
            self.assertEqual(rc_a, 1)
            self.assertTrue(up_pid_file.exists())
            inner_pid = int(up_pid_file.read_text(encoding="utf-8").strip())
            self.assertFalse(serve_mod._pid_is_alive(inner_pid))
            self.assertEqual(list(runs_dir.glob(".serve*.pid")), [])
            self.assertEqual(list(runs_dir.glob(".se-session*.token")), [])
            self.assertFalse(serve_mod._port_is_bound("127.0.0.1", port))

            # Case B: Inner upstream exits immediately with code 1 before se-key-proxy starts.
            model_entry_b = dict(model_entry_a)
            model_entry_b["serve_command"] = (
                f"{sys.executable} -c \"import sys; sys.exit(1)\" --host {{host}} --port {{port}}"
            )
            with patch.object(serve_mod, "load_model", return_value=model_entry_b):
                rc_b = serve_mod.main(["scripts/serve-model", "tinfoil-rollback-test"])
            self.assertEqual(rc_b, 1)
            self.assertEqual(list(runs_dir.glob(".serve*.pid")), [])
            self.assertEqual(list(runs_dir.glob(".se-session*.token")), [])

            # W10: stop-model _safe_unlink_token_file refuses paths outside RUNS or not matching .se-session-*.token
            outside_file = runs_dir / "not-a-token.txt"
            outside_file.write_text("keep", encoding="utf-8")
            stop_mod._safe_unlink_token_file(outside_file, runs_dir)
            self.assertTrue(outside_file.exists())

    def test_registry_and_session_token_redaction(self) -> None:
        # 1. Rung 1 rejects apiKeyKeychainService and upstreamBaseUrl
        for bad_local_prov in (
            {"apiBaseUrl": "http://127.0.0.1:8080/v1", "apiKeyKeychainService": "free-inference.local"},
            {"apiBaseUrl": "http://127.0.0.1:8080/v1", "upstreamBaseUrl": "https://api.example.com/v1"},
        ):
            with self.assertRaises(RegistryError):
                resolve_endpoint(
                    {
                        "id": "bad-local",
                        "repo": "org/m",
                        "runtime": "mlx-lm",
                        "promptfoo_provider": bad_local_prov,
                    },
                    require_api_key=False,
                )

        # 2. Rung 2/3 rejects upstreamBaseUrl or missing serve_command
        for bad_tee in (
            {
                "id": "tee-direct-url",
                "repo": "org/m",
                "runtime": "proxy",
                "serve_command": "tinfoil-proxy -h {host} -p {port}",
                "promptfoo_provider": {
                    "apiBaseUrl": "http://127.0.0.1:8081/v1",
                    "apiKeyKeychainService": "free-inference.tinfoil",
                    "upstreamBaseUrl": "https://enclave.example.com/v1",
                },
                "remote_trust": {"tier": "enclave_runtime_attested", "attestation_method": "sev-snp"},
            },
            {
                "id": "tee-no-cmd",
                "repo": "org/m",
                "runtime": "proxy",
                "promptfoo_provider": {
                    "apiBaseUrl": "http://127.0.0.1:8081/v1",
                    "apiKeyKeychainService": "free-inference.tinfoil",
                },
                "remote_trust": {"tier": "enclave_runtime_attested", "attestation_method": "sev-snp"},
            },
        ):
            with self.assertRaises(RegistryError):
                resolve_endpoint(bad_tee, require_api_key=False)

        # 3. Rung 4/5 rejects serve_command, missing upstreamBaseUrl, http://, non-443 port, userinfo,
        # .local, trailing dot, or loopback/private/numeric IPv4 host (W6, W9).
        with self.assertRaises(RegistryError):
            resolve_endpoint(
                {
                    "id": "bad-rung4-cmd",
                    "repo": "org/m",
                    "runtime": "proxy",
                    "serve_command": "some-proxy --host {host} --port {port}",
                    "promptfoo_provider": {
                        "apiBaseUrl": "http://127.0.0.1:8082/v1",
                        "apiKeyKeychainService": "free-inference.remote",
                        "upstreamBaseUrl": "https://api.example.com/v1",
                    },
                    "remote_trust": {"tier": "zdr_contract"},
                },
                require_api_key=False,
            )

        for bad_upstream in (
            None,
            "http://api.example.com/v1",
            "https://api.example.com:8443/v1",
            "https://user:pass@api.example.com/v1",
            "https://127.0.0.1/v1",
            "https://localhost/v1",
            "https://localhost./v1",
            "https://box.local/v1",
            "https://2130706433/v1",
            "https://127.1/v1",
            "https://0x7f.1/v1",
            "https://10.0.0.1/v1",
            "https://192.168.1.1/v1",
            "https://169.254.169.254/v1",
        ):
            prov: dict[str, object] = {
                "apiBaseUrl": "http://127.0.0.1:8082/v1",
                "apiKeyKeychainService": "free-inference.remote",
            }
            if bad_upstream is not None:
                prov["upstreamBaseUrl"] = bad_upstream
            with self.assertRaises(RegistryError, msg=f"Expected failure for upstreamBaseUrl={bad_upstream!r}"):
                resolve_endpoint(
                    {
                        "id": "bad-rung4",
                        "repo": "org/m",
                        "runtime": "proxy",
                        "promptfoo_provider": prov,
                        "remote_trust": {"tier": "zdr_contract"},
                    },
                    require_api_key=False,
                )

        # 4. Verify render-suite and opencode-smoke never write se-session- into files on disk,
        # and write-metrics / opencode-smoke redaction scrubs se-session- tokens and fails closed (W5).
        render_suite_mod = _load_script_module("render_suite_se_key", "scripts/render-suite")
        opencode_mod = _load_script_module("opencode_smoke_se_key", "scripts/opencode-smoke")
        write_metrics_mod = _load_script_module("write_metrics_se_key", "scripts/write-metrics")
        with_tok_mod = _load_script_module("with_session_token_script", "scripts/with-session-token")
        verify_mod = _load_script_module("verify_served_model_se_key", "scripts/verify-served-model")

        fake_tok = "se-session-" + ("d" * 64)
        sample_log = f'Authorization: Bearer {fake_tok}\n"apiKey": "{fake_tok}"\n'
        scrubbed = redact_session_tokens(sample_log)
        self.assertNotIn(fake_tok, scrubbed)
        self.assertIn("[REDACTED_SESSION_TOKEN]", scrubbed)

        # 5. Verify render-suite, opencode-smoke config rendering, write-metrics fail-closed redaction,
        # and with-session-token injection with a live session token in pid_record.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            tok_file = tmp_dir / ".se-session-test.token"
            tok_file.write_text(fake_tok + "\n", encoding="utf-8")
            os.chmod(tok_file, 0o600)
            model_entry = {
                "id": "tinfoil-tok-test",
                "repo": "deepseek-ai/DeepSeek-V3.1",
                "runtime": "proxy",
                "serve_command": "tinfoil-proxy -h {host} -p {port}",
                "promptfoo_provider": {
                    "apiBaseUrl": "http://127.0.0.1:8081/v1",
                    "apiKeyKeychainService": "free-inference.tinfoil",
                },
                "remote_trust": {
                    "tier": "enclave_runtime_attested",
                    "attestation_method": "tinfoil-proxy-sigstore",
                },
            }
            fake_pid_record = {
                "pid": os.getpid(),
                "pid_lstart": get_process_lstart(os.getpid()),
                "session_token_file": str(tok_file),
            }

            # Render suite.yaml and opencode.json into disk directories while session token is active
            run_dir = tmp_dir / "eval_run"
            home_dir = tmp_dir / ".home"
            run_dir.mkdir(parents=True, exist_ok=True)
            home_dir.mkdir(parents=True, exist_ok=True)
            suite_out = run_dir / "suite.yaml"
            with (
                patch.object(render_suite_mod, "load_model", return_value=model_entry),
                patch.object(render_suite_mod, "load_models", return_value=[model_entry]),
                patch.object(render_suite_mod, "read_pid_record_for_model", return_value=fake_pid_record),
            ):
                rc_suite = render_suite_mod.main(
                    ["scripts/render-suite", "sanity", "tinfoil-tok-test", "--output", str(suite_out)]
                )
            self.assertEqual(rc_suite, 0)

            active_ep = resolve_endpoint(model_entry, pid_record=fake_pid_record, require_api_key=True)
            self.assertEqual(active_ep.api_key, fake_tok)
            opencode_cfg_path = home_dir / "opencode.json"
            opencode_cfg_path.write_text(opencode_mod.render_opencode_config(active_ep), encoding="utf-8")

            # Walk every file in run_dir and home_dir before any post-hoc redaction and assert zero se-session- leaks
            for scan_root in (run_dir, home_dir):
                for p in scan_root.rglob("*"):
                    if p.is_file():
                        content = p.read_text(encoding="utf-8")
                        self.assertNotIn("se-session-", content, f"Token leaked in {p}")
                        self.assertIn(SESSION_TOKEN_ENV_VAR, content)

            # Verify write-metrics scrubs a simulated se-session- leak in output.json, records session_token_redactions > 0, and returns 1
            (run_dir / "output.json").write_text(
                json.dumps(
                    {
                        "results": {
                            "results": [
                                {
                                    "success": True,
                                    "score": 1.0,
                                    "latencyMs": 100,
                                    "response": {
                                        "output": f"leaked {fake_tok}",
                                        "tokenUsage": {"total": 10, "prompt": 5, "completion": 5},
                                    },
                                }
                            ]
                        }
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(write_metrics_mod, "load_model", return_value=model_entry):
                rc_metrics = write_metrics_mod.main(
                    [
                        "scripts/write-metrics",
                        "sanity",
                        "tinfoil-tok-test",
                        "openai:chat:deepseek-ai/DeepSeek-V3.1",
                        str(suite_out),
                        "0",
                        str(run_dir),
                    ]
                )
            self.assertEqual(rc_metrics, 1)
            self.assertNotIn("se-session-", (run_dir / "output.json").read_text(encoding="utf-8"))
            metrics_obj = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))
            self.assertGreater(metrics_obj.get("session_token_redactions", 0), 0)
            scan_manifest = metrics_obj.get("session_token_scan", {})
            self.assertEqual(scan_manifest.get("matches_found"), 1)
            self.assertEqual(scan_manifest.get("redactions_applied"), 1)
            self.assertEqual(scan_manifest.get("remaining_unredacted_matches"), 0)
            self.assertGreater(scan_manifest.get("files_scanned", 0), 0)
            self.assertGreater(scan_manifest.get("bytes_scanned", 0), 0)
            self.assertEqual(scan_manifest.get("files_skipped"), [])
            self.assertIn(str(run_dir), scan_manifest.get("roots", []))
            self.assertEqual(scan_manifest.get("matched_files"), [str(run_dir / "output.json")])

            out_file = tmp_dir / "child_env.txt"
            with (
                patch.object(with_tok_mod, "load_model", return_value=model_entry),
                patch.object(with_tok_mod, "read_pid_record_for_model", return_value=fake_pid_record),
            ):
                rc = with_tok_mod.main(
                    [
                        "scripts/with-session-token",
                        "tinfoil-tok-test",
                        "--",
                        sys.executable,
                        "-c",
                        f"import os, pathlib; pathlib.Path({str(out_file)!r}).write_text(os.environ['{SESSION_TOKEN_ENV_VAR}'])",
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertEqual(out_file.read_text(encoding="utf-8"), fake_tok)

            # 6. Verify check_once_detailed fails closed when upstream_pid is dead on dual-process Rung 2/3 proxy
            ep = resolve_endpoint(model_entry, require_api_key=False)
            ok_dead_up, msg_dead_up, _ = verify_mod.check_once_detailed(
                ep,
                1.0,
                pid_record={
                    "model_id": "tinfoil-tok-test",
                    "pid": os.getpid(),
                    "pid_lstart": get_process_lstart(os.getpid()),
                    "upstream_pid": 999999,
                },
                runs_dir=tmp_dir,
            )
            self.assertFalse(ok_dead_up)
            self.assertIn("upstream proxy process", msg_dead_up)

        # 7. Verify scan_and_redact_directory_tokens manifest and SQLite byte preservation (P3)
        with tempfile.TemporaryDirectory() as tmp2:
            tmp2_dir = Path(tmp2)
            out2 = tmp2_dir / "out"
            pf_home = tmp2_dir / ".home" / ".promptfoo"
            out2.mkdir(parents=True, exist_ok=True)
            pf_home.mkdir(parents=True, exist_ok=True)

            # Clean directory scan
            (out2 / "output.json").write_text('{"ok": true}\n', encoding="utf-8")
            (out2 / "promptfoo.log").write_text("all clean\n", encoding="utf-8")
            clean_db_bytes = b"SQLite format 3\x00\x10\x00\x01\x01\x00@  \x00\x00\x00\x01" + os.urandom(64)
            (pf_home / "promptfoo.db").write_bytes(clean_db_bytes)

            clean_scan = scan_and_redact_directory_tokens([out2, pf_home])
            self.assertEqual(clean_scan["files_scanned"], 3)
            self.assertEqual(clean_scan["redactions_applied"], 0)
            self.assertEqual(clean_scan["matches_found"], 0)
            self.assertEqual((pf_home / "promptfoo.db").read_bytes(), clean_db_bytes)

            # Simulated token in promptfoo.db must increment matches_found without mutating promptfoo.db
            dirty_db_bytes = clean_db_bytes + f" leaked {fake_tok} ".encode("utf-8") + b"\x00\xff\xfe"
            (pf_home / "promptfoo.db").write_bytes(dirty_db_bytes)
            dirty_scan = scan_and_redact_directory_tokens([out2, pf_home])
            self.assertEqual(dirty_scan["files_scanned"], 3)
            self.assertEqual(dirty_scan["redactions_applied"], 0)
            self.assertEqual(dirty_scan["matches_found"], 1)
            self.assertEqual((pf_home / "promptfoo.db").read_bytes(), dirty_db_bytes)

            # R2-F2 & S2-2: Verify opencode HOME/XDG directories built by build_isolated_env are scanned
            # and a planted token in XDG_DATA_HOME fails evaluate_smoke_gate, plus excluded_dirs and walk_error
            oc_run_dir = tmp2_dir / "oc_run"
            oc_ws_dir = oc_run_dir / "workspace"
            oc_iso_home = oc_run_dir / ".home"
            oc_ws_dir.mkdir(parents=True, exist_ok=True)
            for subdir in (".config", ".local/share", ".cache", ".local/state"):
                (oc_iso_home / subdir).mkdir(parents=True, exist_ok=True)
            oc_cfg = oc_run_dir / "opencode.json"
            oc_cfg.write_text("{}", encoding="utf-8")
            oc_env = opencode_mod.build_isolated_env(oc_ws_dir, oc_iso_home, oc_cfg, ep)
            xdg_data_state = Path(oc_env["XDG_DATA_HOME"]) / "opencode" / "state.json"
            xdg_data_state.parent.mkdir(parents=True, exist_ok=True)
            xdg_data_state.write_text(f'{{"cached_auth": "{fake_tok}"}}\n', encoding="utf-8")

            # Also create top-level .home excluded dirs (huggingface, .npm), a nested workspace/huggingface dir (not excluded),
            # a symlink dir, and an unreadable dir
            hf_dir = tmp2_dir / ".home" / "huggingface"
            hf_dir.mkdir(parents=True, exist_ok=True)
            (hf_dir / "ignored_weights.bin").write_text(fake_tok, encoding="utf-8")
            npm_dir = tmp2_dir / ".home" / ".npm"
            npm_dir.mkdir(parents=True, exist_ok=True)
            nested_hf_dir = oc_ws_dir / "huggingface"
            nested_hf_dir.mkdir(parents=True, exist_ok=True)
            (nested_hf_dir / "clean_note.txt").write_text("clean nested file\n", encoding="utf-8")
            sym_target = tmp2_dir / "outside_dir"
            sym_target.mkdir(parents=True, exist_ok=True)
            sym_dir = oc_run_dir / "linked_dir"
            sym_dir.symlink_to(sym_target)
            unreadable_dir = oc_run_dir / "unreadable_sub"
            unreadable_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(unreadable_dir, 0o000)
            try:
                (pf_home / "promptfoo.db").write_bytes(clean_db_bytes)
                oc_scan = scan_and_redact_directory_tokens(
                    [oc_run_dir, tmp2_dir / ".home", tmp2_dir / "nonexistent_root"]
                )
            finally:
                os.chmod(unreadable_dir, 0o700)

            self.assertEqual(oc_scan["matches_found"], 1)
            self.assertIn(str(xdg_data_state), oc_scan["matched_files"])
            self.assertEqual(oc_scan["missing_roots"], [str(tmp2_dir / "nonexistent_root")])
            excluded_paths = {item["path"]: item["reason"] for item in oc_scan["excluded_dirs"]}
            self.assertEqual(excluded_paths.get(str(hf_dir)), "excluded_dir_name")
            self.assertEqual(excluded_paths.get(str(npm_dir)), "excluded_dir_name")
            self.assertNotIn(str(nested_hf_dir), excluded_paths)
            self.assertEqual(excluded_paths.get(str(sym_dir)), "symlink_dir")
            self.assertTrue(
                any(
                    item["path"] == str(unreadable_dir) and "walk_error:" in item["reason"]
                    for item in oc_scan["files_skipped"]
                ),
                f"Expected walk_error in files_skipped, got {oc_scan['files_skipped']!r}",
            )
            gate_res = opencode_mod.evaluate_smoke_gate(
                returncode=0,
                opencode_host_dirs_unchanged=True,
                observer_available=True,
                observer_errors=[],
                run_poll_count=5,
                run_positive_socket_samples=2,
                run_parsed_socket_lines=2,
                non_localhost_lines=[],
                unconnected_udp_lines=[],
                forwarder_bound_localhost=True,
                server_request_count=2,
                blocked_chat_requests=0,
                max_chat_requests=3,
                parsed_events={
                    "read_tool_called": True,
                    "only_read_tool_called": True,
                    "read_target_only": True,
                    "token_in_tool_output": True,
                    "token_verified": True,
                    "denied_or_error_count": 0,
                },
                session_token_redactions=oc_scan["redactions_applied"],
                session_token_matches=oc_scan["matches_found"],
            )
            self.assertFalse(gate_res["passed"])

            # R2-F5 & S2-4: End-to-end scripts/eval test with a failing scripts/timing that writes partial JSON
            # while promptfoo output.json contains a leaked se-session-* token.
            fake_lab = tmp2_dir / "fake_lab"
            fake_scripts = fake_lab / "scripts"
            fake_scripts.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / "scripts" / "eval", fake_scripts / "eval")
            shutil.copy2(ROOT / "scripts" / "write-metrics", fake_scripts / "write-metrics")
            (fake_lab / "local_assist").symlink_to(ROOT / "local_assist")
            (fake_lab / "models.yaml").symlink_to(ROOT / "models.yaml")
            (fake_lab / ".venv").symlink_to(ROOT / ".venv")

            def _write_exec_stub(path: Path, body: str) -> None:
                path.write_text(body, encoding="utf-8")
                os.chmod(path, 0o755)

            _write_exec_stub(
                fake_scripts / "provider-id",
                "#!/usr/bin/env bash\necho 'openai:chat:Qwen/Qwen3-1.7B-MLX-4bit'\n",
            )
            _write_exec_stub(
                fake_scripts / "render-suite",
                '#!/usr/bin/env bash\nOUT="$4"\necho "suite: stub" > "$OUT"\necho "$OUT"\n',
            )
            _write_exec_stub(
                fake_scripts / "verify-served-model",
                "#!/usr/bin/env bash\necho 'verified stub'\n",
            )
            _write_exec_stub(
                fake_scripts / "with-session-token",
                f'#!/usr/bin/env bash\n'
                f'for ((i=1; i<=$#; i++)); do\n'
                f'  if [ "${{!i}}" = "--output" ]; then\n'
                f'    next=$((i+1))\n'
                f'    OUT_JSON="${{!next}}"\n'
                f'    printf \'{{"results":{{"results":[{{"response":{{"output":"leaked {fake_tok}"}}}}]}}}}\' > "$OUT_JSON"\n'
                f'  fi\n'
                f'done\n'
                f'echo "promptfoo stub log {fake_tok}"\n'
                f'exit 0\n',
            )
            _write_exec_stub(
                fake_scripts / "timing",
                '#!/usr/bin/env bash\nprintf "{corrupt_partial_json"\nexit 1\n',
            )

            eval_cp = subprocess.run(
                ["bash", str(fake_scripts / "eval"), "sanity", "qwen3-1.7b-mlx-4bit"],
                cwd=str(fake_lab),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertNotEqual(eval_cp.returncode, 0)
            eval_runs = list((fake_lab / "runs").glob("*sanity*"))
            self.assertEqual(len(eval_runs), 1)
            eval_out_dir = eval_runs[0]
            self.assertTrue((eval_out_dir / "notes.md").exists())
            self.assertTrue((eval_out_dir / "metrics.json").exists())
            self.assertNotIn(fake_tok, (eval_out_dir / "output.json").read_text(encoding="utf-8"))
            self.assertNotIn(fake_tok, (eval_out_dir / "promptfoo.log").read_text(encoding="utf-8"))
            eval_metrics = json.loads((eval_out_dir / "metrics.json").read_text(encoding="utf-8"))
            self.assertIsNone(eval_metrics["timing_probe"])
            self.assertTrue(bool(eval_metrics.get("timing_probe_error")))
            self.assertEqual(eval_metrics["session_token_scan"]["matches_found"], 2)
            self.assertEqual(eval_metrics["session_token_scan"]["redactions_applied"], 2)

    def test_f1_loopback_upstream_kernel_pcb_verification_and_chunked_forwarding(self) -> None:
        real_api_key = "tf-f1-real-secret-key-8888"
        session_token = "se-session-" + ("e" * 64)
        allowed_model = "deepseek-ai/DeepSeek-V3.1"

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)

            # --- P1c: Startup refusals ---
            # 1) Loopback HTTP without --upstream-pid -> exit 2
            p_no_pid = subprocess.run(
                [
                    str(TEST_BINARY_PATH),
                    "proxy",
                    "--service",
                    "free-inference.test",
                    "--listen-host",
                    "127.0.0.1",
                    "--listen-port",
                    str(_free_port()),
                    "--upstream-url",
                    f"http://127.0.0.1:{_free_port()}/v1",
                    "--allowed-model",
                    allowed_model,
                    "--session-token-fd",
                    "0",
                ],
                input=(session_token + "\n").encode("utf-8"),
                capture_output=True,
                timeout=5,
                check=False,
            )
            self.assertEqual(p_no_pid.returncode, 2)
            self.assertIn(b"--upstream-pid", p_no_pid.stderr)

            # 2) Loopback HTTP where --upstream-pid is a different process than the listener owner -> exit 1
            other_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            other_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            other_listener.bind(("127.0.0.1", 0))
            other_listener.listen(5)
            other_port = int(other_listener.getsockname()[1])
            unrelated_proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
            try:
                tok_r, tok_w = os.pipe()
                key_r, key_w = os.pipe()
                os.write(tok_w, (session_token + "\n").encode("utf-8"))
                os.close(tok_w)
                os.write(key_w, (real_api_key + "\n").encode("utf-8"))
                os.close(key_w)
                # Use short timeout by killing unrelated_proc after 0.3s so waitForUpstreamBinding returns nil fast
                threading.Timer(0.3, unrelated_proc.terminate).start()
                p_wrong_pid = subprocess.run(
                    [
                        str(TEST_BINARY_PATH),
                        "proxy",
                        "--service",
                        "free-inference.test",
                        "--listen-host",
                        "127.0.0.1",
                        "--listen-port",
                        str(_free_port()),
                        "--upstream-url",
                        f"http://127.0.0.1:{other_port}/v1",
                        "--upstream-pid",
                        str(unrelated_proc.pid),
                        "--allowed-model",
                        allowed_model,
                        "--session-token-fd",
                        str(tok_r),
                        "--test-ephemeral-key-fd",
                        str(key_r),
                    ],
                    pass_fds=(tok_r, key_r),
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                os.close(tok_r)
                os.close(key_r)
                self.assertEqual(p_wrong_pid.returncode, 1)
            finally:
                other_listener.close()
                if unrelated_proc.poll() is None:
                    unrelated_proc.kill()
                unrelated_proc.wait(timeout=3)

            # 3) Listener with SO_REUSEPORT enabled -> rejected at startup (exit 1)
            reuseport_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            reuseport_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            reuseport_sock.bind(("127.0.0.1", 0))
            reuseport_sock.listen(5)
            rp_port = int(reuseport_sock.getsockname()[1])
            rp_proc = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    f"import socket, time; s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1); s.bind(('127.0.0.1', {rp_port})); s.listen(5); time.sleep(60)",
                ]
            )
            try:
                time.sleep(0.15)
                threading.Timer(0.4, rp_proc.terminate).start()
                tok_r, tok_w = os.pipe()
                key_r, key_w = os.pipe()
                os.write(tok_w, (session_token + "\n").encode("utf-8"))
                os.close(tok_w)
                os.write(key_w, (real_api_key + "\n").encode("utf-8"))
                os.close(key_w)
                p_rp = subprocess.run(
                    [
                        str(TEST_BINARY_PATH),
                        "proxy",
                        "--service",
                        "free-inference.test",
                        "--listen-host",
                        "127.0.0.1",
                        "--listen-port",
                        str(_free_port()),
                        "--upstream-url",
                        f"http://127.0.0.1:{rp_port}/v1",
                        "--upstream-pid",
                        str(rp_proc.pid),
                        "--allowed-model",
                        allowed_model,
                        "--session-token-fd",
                        str(tok_r),
                        "--test-ephemeral-key-fd",
                        str(key_r),
                    ],
                    pass_fds=(tok_r, key_r),
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                os.close(tok_r)
                os.close(key_r)
                self.assertEqual(p_rp.returncode, 1)
            finally:
                reuseport_sock.close()
                if rp_proc.poll() is None:
                    rp_proc.kill()
                rp_proc.wait(timeout=3)

            # --- P1d, Q2, Q3: Verified POSIX socket chunked SSE, trailers, malformed chunk, Set-Cookie stripping, and --test-force-urlsession ---
            raw_up_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_up_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            raw_up_sock.bind(("127.0.0.1", 0))
            raw_up_sock.listen(16)
            raw_up_port = int(raw_up_sock.getsockname()[1])
            stop_raw_up = threading.Event()

            def _serve_raw_http() -> None:
                while not stop_raw_up.is_set():
                    try:
                        raw_up_sock.settimeout(0.2)
                        conn, _ = raw_up_sock.accept()
                    except OSError:
                        continue
                    with conn:
                        conn.settimeout(2.0)
                        req_data = b""
                        while b"\r\n\r\n" not in req_data:
                            chunk = conn.recv(4096)
                            if not chunk:
                                break
                            req_data += chunk
                        if b"GET /v1/models?mode=chunked" in req_data:
                            # Chunked response with standard hex chunk sizes, trailer header, and Set-Cookie
                            part1 = b'{"object":"list","data":['
                            part2 = f'{{"id":"{allowed_model}"}}]}}'.encode("utf-8")
                            resp = (
                                b"HTTP/1.1 200 OK\r\n"
                                b"Content-Type: application/json\r\n"
                                b"Set-Cookie: tracking=secret123\r\n"
                                b"Transfer-Encoding: chunked\r\n\r\n"
                                + f"{len(part1):x}\r\n".encode("utf-8")
                                + part1
                                + b"\r\n"
                                + f"{len(part2):X}\r\n".encode("utf-8")
                                + part2
                                + b"\r\n0\r\nX-Trailer: ignored\r\n\r\n"
                            )
                            conn.sendall(resp)
                        elif b"GET /v1/models?mode=chunkext" in req_data:
                            # Chunked response with RFC 9112 chunk extension (;ext=1) for POSIX forwarder
                            part1 = b'{"object":"list","data":['
                            part2 = f'{{"id":"{allowed_model}"}}]}}'.encode("utf-8")
                            resp = (
                                b"HTTP/1.1 200 OK\r\n"
                                b"Content-Type: application/json\r\n"
                                b"Transfer-Encoding: chunked\r\n\r\n"
                                + f"{len(part1):x};ext=1\r\n".encode("utf-8")
                                + part1
                                + b"\r\n"
                                + f"{len(part2):X}\r\n".encode("utf-8")
                                + part2
                                + b"\r\n0\r\n\r\n"
                            )
                            conn.sendall(resp)
                        elif b"GET /v1/models?mode=badchunk" in req_data:
                            resp = (
                                b"HTTP/1.1 200 OK\r\n"
                                b"Content-Type: application/json\r\n"
                                b"Transfer-Encoding: chunked\r\n\r\n"
                                b"ZZZZ\r\ncorrupt\r\n0\r\n\r\n"
                            )
                            conn.sendall(resp)
                        elif b"GET /v1/models?mode=pluschunk" in req_data:
                            resp = (
                                b"HTTP/1.1 200 OK\r\n"
                                b"Content-Type: application/json\r\n"
                                b"Transfer-Encoding: chunked\r\n\r\n"
                                b"+7\r\ncorrupt\r\n0\r\n\r\n"
                            )
                            conn.sendall(resp)
                        elif b"GET /v1/models?mode=redirect" in req_data:
                            body = b'{"redirect":true}'
                            resp = (
                                b"HTTP/1.1 302 Found\r\n"
                                b"Location: https://evil.example.com/steal\r\n"
                                b"Set-Cookie: s=1\r\n"
                                b"Content-Type: application/json\r\n"
                                + f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
                                + body
                            )
                            conn.sendall(resp)
                        else:
                            body = json.dumps({"object": "list", "data": [{"id": allowed_model}]}).encode("utf-8")
                            resp = (
                                b"HTTP/1.1 200 OK\r\n"
                                b"Content-Type: application/json\r\n"
                                + f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
                                + body
                            )
                            conn.sendall(resp)

            raw_up_thread = threading.Thread(target=_serve_raw_http, daemon=True)
            raw_up_thread.start()

            # Test both default verified POSIX forwarder and --test-force-urlsession
            for force_urlsession in (False, True):
                p_port = _free_port()
                tok_r, tok_w = os.pipe()
                key_r, key_w = os.pipe()
                ready_r, ready_w = os.pipe()
                os.write(tok_w, (session_token + "\n").encode("utf-8"))
                os.close(tok_w)
                os.write(key_w, (real_api_key + "\n").encode("utf-8"))
                os.close(key_w)
                cmd = [
                    str(TEST_BINARY_PATH),
                    "proxy",
                    "--service",
                    "free-inference.test",
                    "--listen-host",
                    "127.0.0.1",
                    "--listen-port",
                    str(p_port),
                    "--upstream-url",
                    f"http://127.0.0.1:{raw_up_port}/v1",
                    "--upstream-pid",
                    str(os.getpid()),
                    "--allowed-model",
                    allowed_model,
                    "--session-token-fd",
                    str(tok_r),
                    "--ready-fd",
                    str(ready_w),
                    "--test-ephemeral-key-fd",
                    str(key_r),
                ]
                if force_urlsession:
                    cmd.append("--test-force-urlsession")
                proc = subprocess.Popen(
                    cmd,
                    pass_fds=(tok_r, key_r, ready_w),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                os.close(tok_r)
                os.close(key_r)
                os.close(ready_w)
                try:
                    ready_data = os.read(ready_r, 256)
                    os.close(ready_r)
                    self.assertEqual(json.loads(ready_data.decode("utf-8"))["status"], "ready")

                    # Chunked decoding + Set-Cookie stripping
                    req_c = Request(
                        f"http://127.0.0.1:{p_port}/v1/models?mode=chunked",
                        headers={"Authorization": f"Bearer {session_token}"},
                        method="GET",
                    )
                    with urlopen(req_c, timeout=3) as resp_c:
                        self.assertEqual(resp_c.status, 200)
                        self.assertIsNone(resp_c.headers.get("Set-Cookie"))
                        self.assertIsNone(resp_c.headers.get("Transfer-Encoding"))
                        data_c = json.loads(resp_c.read().decode("utf-8"))
                    self.assertEqual(data_c["data"][0]["id"], allowed_model)

                    if not force_urlsession:
                        # Chunk extension (;ext=1) works in POSIX forwarder
                        req_ext = Request(
                            f"http://127.0.0.1:{p_port}/v1/models?mode=chunkext",
                            headers={"Authorization": f"Bearer {session_token}"},
                            method="GET",
                        )
                        with urlopen(req_ext, timeout=3) as resp_ext:
                            self.assertEqual(resp_ext.status, 200)
                            data_ext = json.loads(resp_ext.read().decode("utf-8"))
                        self.assertEqual(data_ext["data"][0]["id"], allowed_model)

                        # Malformed chunk hex (or leading '+') closes connection cleanly without crashing proxy
                        for bad_mode in ("badchunk", "pluschunk"):
                            req_bad = Request(
                                f"http://127.0.0.1:{p_port}/v1/models?mode={bad_mode}",
                                headers={"Authorization": f"Bearer {session_token}"},
                                method="GET",
                            )
                            with urlopen(req_bad, timeout=3) as resp_bad:
                                body_bad = resp_bad.read()
                            self.assertEqual(body_bad, b"")

                        # 302 redirect is never followed and Location/Set-Cookie are stripped
                        with socket.create_connection(("127.0.0.1", p_port), timeout=3) as s:
                            s.sendall(
                                f"GET /v1/models?mode=redirect HTTP/1.1\r\n"
                                f"Host: 127.0.0.1:{p_port}\r\n"
                                f"Authorization: Bearer {session_token}\r\n\r\n".encode("utf-8")
                            )
                            raw_302 = s.recv(4096).decode("utf-8", errors="replace")
                        self.assertTrue(raw_302.startswith("HTTP/1.1 302"))
                        self.assertNotIn("Location:", raw_302)
                        self.assertNotIn("Set-Cookie:", raw_302)
                finally:
                    proc.terminate()
                    proc.wait(timeout=3)
                    if proc.stdout:
                        proc.stdout.close()
                    if proc.stderr:
                        proc.stderr.close()

            stop_raw_up.set()
            raw_up_sock.close()
            raw_up_thread.join(timeout=2)

            # --- P1a: Approved vendor stays alive, closes listening socket, rogue process binds same port ---
            # se-key-proxy MUST detect PCB/owner mismatch after connect(), send 0 bytes to rogue listener,
            # return 502 upstream_identity_mismatch to caller, and exit 1.
            swap_port = _free_port()
            close_sig_file = tmp_dir / "close_listener.sig"
            closed_ack_file = tmp_dir / "listener_closed.ack"
            vendor_script = (
                "import pathlib, socket, time\n"
                f"s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
                f"s.bind(('127.0.0.1', {swap_port}))\n"
                "s.listen(5)\n"
                f"sig = pathlib.Path({str(close_sig_file)!r})\n"
                f"ack = pathlib.Path({str(closed_ack_file)!r})\n"
                "while not sig.exists():\n"
                "    time.sleep(0.02)\n"
                "s.close()\n"
                "ack.write_text('closed')\n"
                "time.sleep(60)\n"
            )
            vendor_proc = subprocess.Popen([sys.executable, "-c", vendor_script])
            rogue_received: list[bytes] = []
            rogue_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                p1a_port = _free_port()
                tok_path = tmp_dir / ".se-session-p1a.token"
                tok_path.write_text(session_token + "\n", encoding="utf-8")
                os.chmod(tok_path, 0o600)
                tok_r, tok_w = os.pipe()
                key_r, key_w = os.pipe()
                ready_r, ready_w = os.pipe()
                os.write(tok_w, (session_token + "\n").encode("utf-8"))
                os.close(tok_w)
                os.write(key_w, (real_api_key + "\n").encode("utf-8"))
                os.close(key_w)

                p1a_proxy = subprocess.Popen(
                    [
                        str(TEST_BINARY_PATH),
                        "proxy",
                        "--service",
                        "free-inference.test",
                        "--listen-host",
                        "127.0.0.1",
                        "--listen-port",
                        str(p1a_port),
                        "--upstream-url",
                        f"http://127.0.0.1:{swap_port}/v1",
                        "--upstream-pid",
                        str(vendor_proc.pid),
                        "--allowed-model",
                        allowed_model,
                        "--session-token-fd",
                        str(tok_r),
                        "--session-token-file",
                        str(tok_path),
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

                ready_b = os.read(ready_r, 256)
                os.close(ready_r)
                self.assertEqual(json.loads(ready_b.decode("utf-8"))["status"], "ready")

                # Instruct vendor_proc to close its listening socket while staying alive
                close_sig_file.write_text("close", encoding="utf-8")
                deadline = time.monotonic() + 3.0
                while not closed_ack_file.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(closed_ack_file.exists())

                # Bind rogue listener on the exact same port
                rogue_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                rogue_sock.bind(("127.0.0.1", swap_port))
                rogue_sock.listen(5)

                def _rogue_accept() -> None:
                    try:
                        rogue_sock.settimeout(3.0)
                        conn, _ = rogue_sock.accept()
                        with conn:
                            conn.settimeout(1.0)
                            data = conn.recv(4096)
                            rogue_received.append(data)
                    except OSError:
                        pass

                rogue_thread = threading.Thread(target=_rogue_accept, daemon=True)
                rogue_thread.start()

                req_swap = Request(
                    f"http://127.0.0.1:{p1a_port}/v1/models",
                    headers={"Authorization": f"Bearer {session_token}"},
                    method="GET",
                )
                with self.assertRaises(HTTPError) as err_502:
                    urlopen(req_swap, timeout=3)
                self.assertEqual(err_502.exception.code, 502)
                err_body = json.loads(err_502.exception.read().decode("utf-8"))
                err_502.exception.close()
                self.assertEqual(err_body["error"]["code"], "upstream_identity_mismatch")

                rogue_thread.join(timeout=2)
                # Rogue listener must have received 0 bytes (never saw Authorization header)
                self.assertTrue(all(len(chunk) == 0 for chunk in rogue_received), f"Rogue received bytes: {rogue_received!r}")

                p1a_proxy.wait(timeout=3)
                self.assertEqual(p1a_proxy.returncode, 1)
                self.assertFalse(tok_path.exists())
            finally:
                rogue_sock.close()
                if vendor_proc.poll() is None:
                    vendor_proc.kill()
                vendor_proc.wait(timeout=3)
                if p1a_proxy.stdout:
                    p1a_proxy.stdout.close()
                if p1a_proxy.stderr:
                    p1a_proxy.stderr.close()

            # --- P1b: Vendor process exits -> DispatchSourceProcess triggers proxy exit within 2s ---
            p1b_up_port = _free_port()
            p1b_vendor = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    f"import socket, time; s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('127.0.0.1', {p1b_up_port})); s.listen(5); time.sleep(60)",
                ]
            )
            p1b_port = _free_port()
            p1b_tok = tmp_dir / ".se-session-p1b.token"
            p1b_tok.write_text(session_token + "\n", encoding="utf-8")
            os.chmod(p1b_tok, 0o600)
            tok_r, tok_w = os.pipe()
            key_r, key_w = os.pipe()
            ready_r, ready_w = os.pipe()
            os.write(tok_w, (session_token + "\n").encode("utf-8"))
            os.close(tok_w)
            os.write(key_w, (real_api_key + "\n").encode("utf-8"))
            os.close(key_w)
            p1b_proxy = subprocess.Popen(
                [
                    str(TEST_BINARY_PATH),
                    "proxy",
                    "--service",
                    "free-inference.test",
                    "--listen-host",
                    "127.0.0.1",
                    "--listen-port",
                    str(p1b_port),
                    "--upstream-url",
                    f"http://127.0.0.1:{p1b_up_port}/v1",
                    "--upstream-pid",
                    str(p1b_vendor.pid),
                    "--allowed-model",
                    allowed_model,
                    "--session-token-fd",
                    str(tok_r),
                    "--session-token-file",
                    str(p1b_tok),
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
                ready_b2 = os.read(ready_r, 256)
                os.close(ready_r)
                self.assertEqual(json.loads(ready_b2.decode("utf-8"))["status"], "ready")
                p1b_vendor.kill()
                p1b_vendor.wait(timeout=2)
                p1b_proxy.wait(timeout=2)
                self.assertEqual(p1b_proxy.returncode, 1)
                self.assertFalse(p1b_tok.exists())
            finally:
                if p1b_vendor.poll() is None:
                    p1b_vendor.kill()
                if p1b_proxy.poll() is None:
                    p1b_proxy.kill()
                if p1b_proxy.stdout:
                    p1b_proxy.stdout.close()
                if p1b_proxy.stderr:
                    p1b_proxy.stderr.close()

    def test_f2_startup_interruption_provisional_pid_and_epipe_cleanup(self) -> None:
        serve_mod = _load_script_module("serve_model_f2_script", "scripts/serve-model")
        stop_mod = _load_script_module("stop_model_f2_script", "scripts/stop-model")
        verify_mod = _load_script_module("verify_model_f2_script", "scripts/verify-served-model")
        with_tok_mod = _load_script_module("with_tok_f2_script", "scripts/with-session-token")

        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = Path(tmp)
            serve_mod.RUNS = runs_dir
            stop_mod.RUNS = runs_dir
            port = _free_port()
            up_pid_file = runs_dir / "f2_upstream.pid"

            model_entry = {
                "id": "tinfoil-f2-test",
                "repo": "deepseek-ai/DeepSeek-V3.1",
                "runtime": "proxy",
                "serve_command": (
                    f"{sys.executable} -c "
                    f"\"import os, pathlib, socket, time; "
                    f"s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
                    f"s.bind(('127.0.0.1', {{port}})); s.listen(5); "
                    f"pathlib.Path({str(up_pid_file)!r}).write_text(str(os.getpid())); time.sleep(60)\" "
                    f"--host {{host}} --port {{port}}"
                ),
                "promptfoo_provider": {
                    "apiBaseUrl": f"http://127.0.0.1:{port}/v1",
                    "apiKeyKeychainService": "free-inference.tinfoil-f2",
                },
                "remote_trust": {
                    "tier": "enclave_runtime_attested",
                    "attestation_method": "tinfoil-proxy-sigstore",
                },
            }

            # 1) KeyboardInterrupt during readiness wait -> exit 130, kills BOTH children, removes PID & token files
            captured_pids_1: dict[str, Any] = {}

            def _raise_kbint(*_args: object, **_kwargs: object) -> tuple[list[int], list[int], list[int]]:
                m_pid = serve_mod.pid_file_for_model("tinfoil-f2-test", runs_dir)
                if m_pid.exists():
                    captured_pids_1.update(json.loads(m_pid.read_text(encoding="utf-8")))
                raise KeyboardInterrupt

            with (
                patch.object(serve_mod, "load_model", return_value=model_entry),
                patch.object(serve_mod.select, "select", side_effect=_raise_kbint),
            ):
                rc_int = serve_mod.main(["scripts/serve-model", "tinfoil-f2-test"])
            self.assertEqual(rc_int, 130)
            up_pid_1 = int(up_pid_file.read_text(encoding="utf-8").strip())
            self.assertFalse(serve_mod._pid_is_alive(up_pid_1))
            self.assertIsInstance(captured_pids_1.get("pid"), int)
            self.assertFalse(serve_mod._pid_is_alive(int(captured_pids_1["pid"])))
            self.assertEqual(list(runs_dir.glob(".serve*.pid")), [])
            self.assertEqual(list(runs_dir.glob(".se-session*.token")), [])

            # 2) SIGTERM during readiness wait -> exit 143 (128 + SIGTERM), kills BOTH children, removes PID & token files
            up_pid_file.unlink(missing_ok=True)
            captured_pids_2: dict[str, Any] = {}

            def _raise_sigterm(*_args: object, **_kwargs: object) -> tuple[list[int], list[int], list[int]]:
                m_pid = serve_mod.pid_file_for_model("tinfoil-f2-test", runs_dir)
                if m_pid.exists():
                    captured_pids_2.update(json.loads(m_pid.read_text(encoding="utf-8")))
                os.kill(os.getpid(), signal.SIGTERM)
                return ([], [], [])

            with (
                patch.object(serve_mod, "load_model", return_value=model_entry),
                patch.object(serve_mod.select, "select", side_effect=_raise_sigterm),
            ):
                rc_term = serve_mod.main(["scripts/serve-model", "tinfoil-f2-test"])
            self.assertEqual(rc_term, 128 + signal.SIGTERM)
            up_pid_2 = int(up_pid_file.read_text(encoding="utf-8").strip())
            self.assertFalse(serve_mod._pid_is_alive(up_pid_2))
            self.assertIsInstance(captured_pids_2.get("pid"), int)
            self.assertFalse(serve_mod._pid_is_alive(int(captured_pids_2["pid"])))
            self.assertEqual(list(runs_dir.glob(".serve*.pid")), [])
            self.assertEqual(list(runs_dir.glob(".se-session*.token")), [])

            # 3) Readiness pipe EPIPE in se-key-proxy: parent closes ready_r before proxy writes ready JSON ->
            # se-key-proxy detects EPIPE, kills --upstream-pid, unlinks token file, and exits 1.
            epipe_up_port = _free_port()
            epipe_vendor = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    f"import socket, time; s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('127.0.0.1', {epipe_up_port})); s.listen(5); time.sleep(60)",
                ]
            )
            epipe_tok = runs_dir / ".se-session-epipe.token"
            epipe_tok.write_text("se-session-" + ("f" * 64) + "\n", encoding="utf-8")
            os.chmod(epipe_tok, 0o600)
            tok_r, tok_w = os.pipe()
            key_r, key_w = os.pipe()
            ready_r, ready_w = os.pipe()
            os.write(tok_w, ("se-session-" + ("f" * 64) + "\n").encode("utf-8"))
            os.close(tok_w)
            os.write(key_w, b"tf-real-key\n")
            os.close(key_w)
            # Close ready_r BEFORE launching proxy so writeAllToFD(readyFD) gets EPIPE
            os.close(ready_r)
            epipe_proxy = subprocess.Popen(
                [
                    str(TEST_BINARY_PATH),
                    "proxy",
                    "--service",
                    "free-inference.test",
                    "--listen-host",
                    "127.0.0.1",
                    "--listen-port",
                    str(_free_port()),
                    "--upstream-url",
                    f"http://127.0.0.1:{epipe_up_port}/v1",
                    "--upstream-pid",
                    str(epipe_vendor.pid),
                    "--allowed-model",
                    "deepseek-ai/DeepSeek-V3.1",
                    "--session-token-fd",
                    str(tok_r),
                    "--session-token-file",
                    str(epipe_tok),
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
                epipe_proxy.wait(timeout=3)
                self.assertEqual(epipe_proxy.returncode, 1)
                epipe_vendor.wait(timeout=3)
                self.assertFalse(epipe_tok.exists())
            finally:
                if epipe_vendor.poll() is None:
                    epipe_vendor.kill()
                if epipe_proxy.poll() is None:
                    epipe_proxy.kill()
                if epipe_proxy.stdout:
                    epipe_proxy.stdout.close()
                if epipe_proxy.stderr:
                    epipe_proxy.stderr.close()

            # 4) Simulated SIGKILL during startup leaving provisional PID record on disk (Q1, Q5):
            # verify-served-model and with-session-token reject status=="starting", and stop-model cleans up
            # even when pid/upstream_pid are null or live.
            prov_tok = runs_dir / ".se-session-prov.token"
            prov_tok.write_text("se-session-" + ("a" * 64) + "\n", encoding="utf-8")
            os.chmod(prov_tok, 0o600)
            orphan_up = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
            try:
                prov_rec = {
                    "model_id": "tinfoil-f2-test",
                    "repo": "deepseek-ai/DeepSeek-V3.1",
                    "runtime": "proxy",
                    "api_base_url": f"http://127.0.0.1:{port}/v1",
                    "port": port,
                    "pid": None,
                    "upstream_pid": orphan_up.pid,
                    "upstream_pid_lstart": get_process_lstart(orphan_up.pid),
                    "session_token_file": str(prov_tok),
                    "status": "starting",
                    "startup_nonce": "deadbeef",
                }
                model_pid_path = serve_mod.pid_file_for_model("tinfoil-f2-test", runs_dir)
                default_pid_path = serve_mod.legacy_pid_file(runs_dir)
                serve_mod._write_pid_files(model_pid_path, default_pid_path, prov_rec)

                # Q5: verify-served-model reports "still starting"
                ep = resolve_endpoint(model_entry, require_api_key=False)
                ok_st, msg_st, _ = verify_mod.check_once_detailed(ep, 1.0, pid_record=prov_rec)
                self.assertFalse(ok_st)
                self.assertIn("still starting", msg_st)

                # Q5: with-session-token rejects status=="starting" with exit code 1
                with (
                    patch.object(with_tok_mod, "load_model", return_value=model_entry),
                    patch.object(with_tok_mod, "read_pid_record_for_model", return_value=prov_rec),
                ):
                    rc_wt = with_tok_mod.main(
                        ["scripts/with-session-token", "tinfoil-f2-test", "--", "true"]
                    )
                self.assertEqual(rc_wt, 1)

                # stop-model kills orphan_up, removes prov_tok and PID files
                rc_stop = stop_mod.main(["scripts/stop-model", "tinfoil-f2-test"])
                self.assertEqual(rc_stop, 0)
                orphan_up.wait(timeout=3)
                self.assertFalse(prov_tok.exists())
                self.assertFalse(model_pid_path.exists())
                self.assertFalse(default_pid_path.exists())

                # Q1: stop-model also removes token file when both pid and upstream_pid are None
                prov_tok.write_text("se-session-" + ("b" * 64) + "\n", encoding="utf-8")
                prov_rec_null = dict(prov_rec, pid=None, upstream_pid=None)
                serve_mod._write_pid_files(model_pid_path, default_pid_path, prov_rec_null)
                rc_stop_null = stop_mod.main(["scripts/stop-model", "tinfoil-f2-test"])
                self.assertEqual(rc_stop_null, 0)
                self.assertFalse(prov_tok.exists())
                self.assertFalse(model_pid_path.exists())
            finally:
                if orphan_up.poll() is None:
                    orphan_up.kill()

            # 5a) R2-F1: Early concurrent stop-model immediately after the first provisional null-PID write
            # (before upstream_proc or se_proc is spawned) -> neither child is spawned, records are not recreated.
            up_pid_file.unlink(missing_ok=True)

            def _early_stop_hook() -> None:
                stop_mod.main(["scripts/stop-model", "tinfoil-f2-test"])

            with (
                patch.object(serve_mod, "load_model", return_value=model_entry),
                patch.object(serve_mod, "_after_initial_provisional_write_hook", side_effect=_early_stop_hook),
            ):
                rc_early = serve_mod.main(["scripts/serve-model", "tinfoil-f2-test"])
            self.assertEqual(rc_early, 1)
            self.assertFalse(up_pid_file.exists())
            self.assertEqual(list(runs_dir.glob(".serve*.pid")), [])
            self.assertEqual(list(runs_dir.glob(".se-session*.token")), [])

            # 5b) S2-1: Concurrent stop-model between upstream_proc spawn and se_proc spawn ->
            # se_proc is NEVER launched, upstream_proc is killed, and no PID/token files remain.
            up_pid_file.unlink(missing_ok=True)
            orig_port_bound = serve_mod._port_is_bound
            se_spawn_attempted = False
            orig_popen = serve_mod.subprocess.Popen

            def _stop_during_upstream_bind(host: str, check_port: int) -> bool:
                res = orig_port_bound(host, check_port)
                if res and check_port == port + 1000:
                    stop_mod.main(["scripts/stop-model", "tinfoil-f2-test"])
                return res

            def _tracking_popen(cmd_arg: Any, *args: Any, **kwargs: Any) -> Any:
                nonlocal se_spawn_attempted
                if isinstance(cmd_arg, list) and len(cmd_arg) > 1 and cmd_arg[1] == "proxy":
                    se_spawn_attempted = True
                return orig_popen(cmd_arg, *args, **kwargs)

            with (
                patch.object(serve_mod, "load_model", return_value=model_entry),
                patch.object(serve_mod, "_port_is_bound", side_effect=_stop_during_upstream_bind),
                patch.object(serve_mod.subprocess, "Popen", side_effect=_tracking_popen),
            ):
                rc_mid = serve_mod.main(["scripts/serve-model", "tinfoil-f2-test"])
            self.assertEqual(rc_mid, 1)
            self.assertFalse(se_spawn_attempted)
            if up_pid_file.exists():
                self.assertFalse(serve_mod._pid_is_alive(int(up_pid_file.read_text(encoding="utf-8").strip())))
            self.assertEqual(list(runs_dir.glob(".serve*.pid")), [])
            self.assertEqual(list(runs_dir.glob(".se-session*.token")), [])

            # 5c) R2-F1: Concurrent stop-model during readiness wait where helper STILL writes {"status":"ready"} ->
            # serve-model must detect the removed provisional record via _assert_provisional_record_active,
            # roll back both processes, and refuse to recreate the PID file.
            up_pid_file.unlink(missing_ok=True)
            fake_se_helper = runs_dir / "fake_se_helper.py"
            fake_se_helper.write_text(
                "#!/usr/bin/env python3\n"
                "import os, signal, sys, time\n"
                "signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))\n"
                "args = sys.argv[1:]\n"
                "rfd = int(args[args.index('--ready-fd') + 1])\n"
                "lport = int(args[args.index('--listen-port') + 1])\n"
                "os.write(rfd, f'{{\"status\":\"ready\",\"listen_port\":{lport}}}\\n'.encode())\n"
                "os.close(rfd)\n"
                "time.sleep(60)\n",
                encoding="utf-8",
            )
            os.chmod(fake_se_helper, 0o755)
            orig_select = serve_mod.select.select
            stop_ran_in_select = False

            def _stop_but_deliver_ready(rlist: Any, wlist: Any, xlist: Any, timeout: Any = None) -> Any:
                nonlocal stop_ran_in_select
                res = orig_select(rlist, wlist, xlist, timeout)
                if not stop_ran_in_select:
                    stop_ran_in_select = True
                    # Delete provisional PID files directly under _pid_lock (simulating stop-model removing the record
                    # while the helper still delivers its ready line)
                    with serve_mod._pid_lock(runs_dir):
                        for pf in runs_dir.glob(".serve*.pid"):
                            pf.unlink(missing_ok=True)
                return res

            with (
                patch.object(serve_mod, "load_model", return_value=model_entry),
                patch.object(serve_mod, "verify_se_key_proxy_binary", return_value=fake_se_helper),
                patch.object(serve_mod.select, "select", side_effect=_stop_but_deliver_ready),
            ):
                rc_conc = serve_mod.main(["scripts/serve-model", "tinfoil-f2-test"])
            self.assertEqual(rc_conc, 1)
            self.assertEqual(list(runs_dir.glob(".serve*.pid")), [])
            self.assertEqual(list(runs_dir.glob(".se-session*.token")), [])

            # 6) Injected PID-file write failure on the SE-key branch after both children are spawned ->
            # terminates both upstream_proc and se_proc and removes model_pid_file and token_path.
            up_pid_file.unlink(missing_ok=True)
            orig_write_pid = serve_mod._write_pid_files
            se_write_calls = 0
            se_spawned_pids: dict[str, Any] = {}

            def _fail_on_third_se_write(m_file: Path, d_file: Path, rec: dict[str, object]) -> None:
                nonlocal se_write_calls
                se_write_calls += 1
                if se_write_calls == 3:
                    se_spawned_pids.update(rec)
                    m_file.write_text(json.dumps(rec))
                    raise OSError("Simulated disk full writing default_pid_file after se_proc spawn")
                orig_write_pid(m_file, d_file, rec)

            with (
                patch.object(serve_mod, "load_model", return_value=model_entry),
                patch.object(serve_mod, "_write_pid_files", side_effect=_fail_on_third_se_write),
            ):
                rc_se_disk = serve_mod.main(["scripts/serve-model", "tinfoil-f2-test"])
            self.assertEqual(rc_se_disk, 1)
            self.assertIsInstance(se_spawned_pids.get("pid"), int)
            self.assertIsInstance(se_spawned_pids.get("upstream_pid"), int)
            self.assertFalse(serve_mod._pid_is_alive(int(se_spawned_pids["pid"])))
            self.assertFalse(serve_mod._pid_is_alive(int(se_spawned_pids["upstream_pid"])))
            self.assertEqual(list(runs_dir.glob(".serve*.pid")), [])
            self.assertEqual(list(runs_dir.glob(".se-session*.token")), [])

            # 7) Rung 1 local serve-model failure when writing default_pid_file after Popen -> terminates child and unlinks model_pid_file
            local_pid_file = runs_dir / "local_child.pid"
            local_model_entry = {
                "id": "local-f2-test",
                "repo": "org/local-model",
                "runtime": "mlx-lm",
                "promptfoo_provider": {
                    "apiBaseUrl": f"http://127.0.0.1:{_free_port()}/v1",
                },
                "remote_trust": {"tier": "local"},
            }
            write_calls = 0

            def _fail_on_second_write(m_file: Path, d_file: Path, rec: dict[str, object]) -> None:
                nonlocal write_calls
                write_calls += 1
                if write_calls == 2:
                    m_file.write_text(json.dumps(rec))
                    raise OSError("Simulated disk full writing default_pid_file")
                orig_write_pid(m_file, d_file, rec)

            with (
                patch.object(serve_mod, "load_model", return_value=local_model_entry),
                patch.object(
                    serve_mod,
                    "build_command",
                    return_value=(
                        [
                            sys.executable,
                            "-c",
                            f"import os, pathlib, time; pathlib.Path({str(local_pid_file)!r}).write_text(str(os.getpid())); time.sleep(60)",
                        ],
                        None,
                    ),
                ),
                patch.object(serve_mod, "_write_pid_files", side_effect=_fail_on_second_write),
            ):
                rc_loc = serve_mod.main(["scripts/serve-model", "local-f2-test"])
            self.assertEqual(rc_loc, 1)
            for _ in range(30):
                if local_pid_file.exists():
                    break
                time.sleep(0.02)
            if local_pid_file.exists():
                loc_pid = int(local_pid_file.read_text(encoding="utf-8").strip())
                self.assertFalse(serve_mod._pid_is_alive(loc_pid))
            self.assertEqual(list(runs_dir.glob(".serve*.pid")), [])

    def test_f3_and_f4_unicode_surrogate_json_and_downstream_write_backpressure(self) -> None:
        real_api_key = "tf-f3f4-real-key"
        session_token = "se-session-" + ("9" * 64)
        allowed_model = "deepseek-ai/DeepSeek-V3.1"

        class FastStreamingUpstream(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_GET(self) -> None:
                body = json.dumps({"object": "list", "data": [{"id": allowed_model}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(length)
                parsed = json.loads(raw_body.decode("utf-8"))
                if parsed.get("flood_stream"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    # Write 8 MB of SSE data rapidly so a non-reading client's socket buffer fills
                    block = b"data: " + (b"X" * 32768) + b"\n\n"
                    try:
                        for _ in range(256):
                            self.wfile.write(block)
                        self.wfile.flush()
                    except OSError:
                        pass
                    return
                resp_body = json.dumps(
                    {
                        "id": "chatcmpl-f3",
                        "object": "chat.completion",
                        "model": allowed_model,
                        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)

        upstream_srv = _ThreadedHTTPServer(("127.0.0.1", 0), FastStreamingUpstream)
        upstream_port = int(upstream_srv.server_address[1])
        upstream_thread = threading.Thread(target=upstream_srv.serve_forever, daemon=True)
        upstream_thread.start()

        proxy_port = _free_port()
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
                "free-inference.test",
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
                "--max-chat-requests",
                "20",
                "--max-request-bytes",
                "65536",
                "--stream-timeout-seconds",
                "1",
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
            ready_b = os.read(ready_r, 256)
            os.close(ready_r)
            self.assertEqual(json.loads(ready_b.decode("utf-8"))["status"], "ready")
            base_url = f"http://127.0.0.1:{proxy_port}/v1"

            # --- F3: Valid surrogate pair (\uD83D\uDE00) and \u0000 in JSON strings -> 200 OK ---
            for valid_raw in (
                f'{{"messages":[{{"role":"user","content":"hello \\uD83D\\uDE00"}}],"model":"{allowed_model}"}}'.encode("utf-8"),
                f'{{"messages":[{{"role":"user","content":"null\\u0000byte"}}],"model":"{allowed_model}"}}'.encode("utf-8"),
            ):
                req_ok = Request(
                    f"{base_url}/chat/completions",
                    data=valid_raw,
                    headers={
                        "Authorization": f"Bearer {session_token}",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                with urlopen(req_ok, timeout=3) as resp_ok:
                    self.assertEqual(resp_ok.status, 200)

            # --- F3: Duplicate escaped "m\u006fdel" key, unpaired high/low surrogates, invalid escapes, raw control char -> 400 ---
            for invalid_raw in (
                f'{{"model":"{allowed_model}","m\\u006fdel":"{allowed_model}","messages":[]}}'.encode("utf-8"),
                f'{{"messages":[{{"role":"user","content":"\\uD83D"}}],"model":"{allowed_model}"}}'.encode("utf-8"),
                f'{{"messages":[{{"role":"user","content":"\\uDE00"}}],"model":"{allowed_model}"}}'.encode("utf-8"),
                f'{{"messages":[{{"role":"user","content":"\\uD83D\\u0041"}}],"model":"{allowed_model}"}}'.encode("utf-8"),
                f'{{"messages":[{{"role":"user","content":"\\u12G4"}}],"model":"{allowed_model}"}}'.encode("utf-8"),
                f'{{"messages":[{{"role":"user","content":"\\u+041"}}],"model":"{allowed_model}"}}'.encode("utf-8"),
                f'{{"messages":[{{"role":"user","content":"\\uD83D\\u+E00"}}],"model":"{allowed_model}"}}'.encode("utf-8"),
                f'{{"messages":[{{"role":"user","content":"\\x41"}}],"model":"{allowed_model}"}}'.encode("utf-8"),
                f'{{"messages":[{{"role":"user","content":"raw\nnewline"}}],"model":"{allowed_model}"}}'.encode("utf-8"),
            ):
                req_bad = Request(
                    f"{base_url}/chat/completions",
                    data=invalid_raw,
                    headers={
                        "Authorization": f"Bearer {session_token}",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                with self.assertRaises(HTTPError, msg=f"Expected 400 for {invalid_raw!r}") as err_400:
                    urlopen(req_bad, timeout=3)
                self.assertEqual(err_400.exception.code, 400)
                err_400.exception.close()

            # --- F4 & R2-F3 & S2-3: Non-reading downstream client with small SO_RCVBUF times out within < 3.5s
            # and receives strictly less than 2 MiB out of the 8 MiB flood stream on both POSIX and URLSession forwarders ---
            flood_body = json.dumps(
                {
                    "model": allowed_model,
                    "messages": [{"role": "user", "content": "flood"}],
                    "flood_stream": True,
                }
            ).encode("utf-8")

            for test_port_mode in ("posix", "urlsession"):
                target_port = proxy_port
                url_proc: subprocess.Popen[Any] | None = None
                if test_port_mode == "urlsession":
                    target_port = _free_port()
                    u_tok_r, u_tok_w = os.pipe()
                    u_key_r, u_key_w = os.pipe()
                    u_ready_r, u_ready_w = os.pipe()
                    os.write(u_tok_w, (session_token + "\n").encode("utf-8"))
                    os.close(u_tok_w)
                    os.write(u_key_w, (real_api_key + "\n").encode("utf-8"))
                    os.close(u_key_w)
                    url_proc = subprocess.Popen(
                        [
                            str(TEST_BINARY_PATH),
                            "proxy",
                            "--service",
                            "free-inference.test",
                            "--listen-host",
                            "127.0.0.1",
                            "--listen-port",
                            str(target_port),
                            "--upstream-url",
                            f"http://127.0.0.1:{upstream_port}/v1",
                            "--upstream-pid",
                            str(os.getpid()),
                            "--allowed-model",
                            allowed_model,
                            "--session-token-fd",
                            str(u_tok_r),
                            "--max-chat-requests",
                            "20",
                            "--max-request-bytes",
                            "65536",
                            "--stream-timeout-seconds",
                            "1",
                            "--ready-fd",
                            str(u_ready_w),
                            "--test-ephemeral-key-fd",
                            str(u_key_r),
                            "--test-force-urlsession",
                        ],
                        pass_fds=(u_tok_r, u_key_r, u_ready_w),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    os.close(u_tok_r)
                    os.close(u_key_r)
                    os.close(u_ready_w)
                    u_ready_b = os.read(u_ready_r, 256)
                    os.close(u_ready_r)
                    self.assertEqual(json.loads(u_ready_b.decode("utf-8"))["status"], "ready")

                try:
                    t0 = time.monotonic()
                    total_received = 0
                    with socket.create_connection(("127.0.0.1", target_port), timeout=5) as slow_sock:
                        slow_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                        req_bytes = (
                            f"POST /v1/chat/completions HTTP/1.1\r\n"
                            f"Host: 127.0.0.1:{target_port}\r\n"
                            f"Authorization: Bearer {session_token}\r\n"
                            f"Content-Type: application/json\r\n"
                            f"Content-Length: {len(flood_body)}\r\n\r\n".encode("utf-8")
                            + flood_body
                        )
                        slow_sock.sendall(req_bytes)
                        # Keep client socket unread until after the 1s stream timeout expires
                        time.sleep(1.5)
                        slow_sock.settimeout(2.0)
                        while True:
                            chunk = slow_sock.recv(65536)
                            if not chunk:
                                break
                            total_received += len(chunk)
                    elapsed_f4 = time.monotonic() - t0
                    self.assertLess(elapsed_f4, 3.5)
                    # Prove the stream was aborted on timeout while unread rather than completing all 8 MiB after reading resumed
                    self.assertLess(total_received, 2 * 1024 * 1024)

                    # Verify subsequent requests succeed cleanly
                    req_after = Request(
                        f"http://127.0.0.1:{target_port}/v1/models",
                        headers={"Authorization": f"Bearer {session_token}"},
                        method="GET",
                    )
                    with urlopen(req_after, timeout=3) as resp_after:
                        self.assertEqual(resp_after.status, 200)
                        after_data = json.loads(resp_after.read().decode("utf-8"))
                    self.assertEqual(after_data["data"][0]["id"], allowed_model)
                finally:
                    if url_proc is not None:
                        url_proc.terminate()
                        url_proc.wait(timeout=3)
                        if url_proc.stdout:
                            url_proc.stdout.close()
                        if url_proc.stderr:
                            url_proc.stderr.close()
        finally:
            proxy_proc.terminate()
            proxy_proc.wait(timeout=3)
            if proxy_proc.stdout:
                proxy_proc.stdout.close()
            if proxy_proc.stderr:
                proxy_proc.stderr.close()
            upstream_srv.shutdown()
            upstream_srv.server_close()

    def test_se_key_smoke_script_harness(self) -> None:
        smoke_mod = _load_script_module("se_key_smoke_script", "scripts/se-key-smoke")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            smoke_mod.RUNS = tmp_dir
            call_count_file = tmp_dir / "proxy_call_count.txt"
            call_count_file.write_text("0", encoding="utf-8")
            fake_se_bin = tmp_dir / "fake_se_bin.py"
            fake_se_bin.write_text(
                f"#!/usr/bin/env python3\n"
                f"import json, os, pathlib, sys\n"
                f"cmd = sys.argv[1] if len(sys.argv) > 1 else ''\n"
                f"if cmd == 'seal':\n"
                f"    fd_idx = sys.argv.index('--secret-fd') + 1\n"
                f"    _ = os.read(int(sys.argv[fd_idx]), 256)\n"
                f"    print(json.dumps({{'status': 'sealed', 'service': 'free-inference.selftest'}}))\n"
                f"    sys.exit(0)\n"
                f"if cmd == 'status':\n"
                f"    print(json.dumps({{'exists': True, 'service': 'free-inference.selftest'}}))\n"
                f"    sys.exit(0)\n"
                f"if cmd == 'delete':\n"
                f"    print(json.dumps({{'deleted': True, 'service': 'free-inference.selftest'}}))\n"
                f"    sys.exit(0)\n"
                f"if cmd == 'proxy':\n"
                f"    cnt_path = pathlib.Path({str(call_count_file)!r})\n"
                f"    cnt = int(cnt_path.read_text().strip()) + 1\n"
                f"    cnt_path.write_text(str(cnt))\n"
                f"    if cnt >= 3:\n"
                f"        sys.exit(1)\n"
                f"    r_fd, w_fd = os.pipe()\n"
                f"    os.write(w_fd, ({smoke_mod.SYNTHETIC_REAL_KEY!r} + '\\n').encode('utf-8'))\n"
                f"    os.close(w_fd)\n"
                f"    os.set_inheritable(r_fd, True)\n"
                f"    os.execv({str(TEST_BINARY_PATH)!r}, [{str(TEST_BINARY_PATH)!r}, *sys.argv[1:], '--test-ephemeral-key-fd', str(r_fd)])\n",
                encoding="utf-8",
            )
            os.chmod(fake_se_bin, 0o700)

            with (
                patch.object(smoke_mod, "verify_se_key_proxy_binary", return_value=fake_se_bin),
                patch.object(smoke_mod, "_confirm_prompt", return_value=True),
                patch("local_assist.se_key.verify_se_key_proxy_binary", return_value=fake_se_bin),
            ):
                rc = smoke_mod.main(["scripts/se-key-smoke", "--operator-approved"])
            self.assertEqual(rc, 0)
            summaries = list(tmp_dir.glob("*-se-key-smoke/summary.json"))
            self.assertEqual(len(summaries), 1)
            summary_data = json.loads(summaries[0].read_text(encoding="utf-8"))
            self.assertIs(summary_data.get("all_passed"), True)
            self.assertIs(summary_data.get("unlock_1_models_ok"), True)
            self.assertIs(summary_data.get("unlock_1_token_file_cleaned"), True)
            self.assertIs(summary_data.get("unlock_2_token_file_cleaned"), True)
            self.assertIs(summary_data.get("cancel_3_rollback_clean"), True)
            self.assertIs(summary_data.get("upstream_received_real_bearer"), True)
            self.assertIs(summary_data.get("keychain_entry_removed"), True)

    def test_setup_script_handles_selftest_exit_77_and_npm_ci(self) -> None:
        pkg = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(pkg.get("name"), "free-inference")
        pf_ver = pkg.get("devDependencies", {}).get("promptfoo", "")
        self.assertRegex(pf_ver, r"^\d+\.\d+\.\d+$")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            fake_repo = tmp_dir / "repo"
            (fake_repo / "scripts").mkdir(parents=True, exist_ok=True)
            (fake_repo / ".venv").mkdir(parents=True, exist_ok=True)
            (fake_repo / "bin").mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / "scripts" / "setup", fake_repo / "scripts" / "setup")

            fake_bin = tmp_dir / "fake_bin"
            fake_bin.mkdir(parents=True, exist_ok=True)
            npm_log = tmp_dir / "npm_args.txt"

            for cmd_name, body in [
                ("uv", "#!/usr/bin/env bash\nexit 0\n"),
                ("npm", f"#!/usr/bin/env bash\necho \"$@\" > {str(npm_log)!r}\nexit 0\n"),
                ("shasum", "#!/usr/bin/env bash\necho '6b526fe32244bcccfcfde3c5d181618b4b06b48498e649cd944cc9b64acf994b  bin/tinfoil-proxy'\n"),
                ("codesign", "#!/usr/bin/env bash\necho 'TeamIdentifier=8KSH668LZT'\nexit 0\n"),
                ("gh", "#!/usr/bin/env bash\nexit 1\n"),
                ("curl", "#!/usr/bin/env bash\nexit 0\n"),
                (
                    "unzip",
                    "#!/usr/bin/env bash\n"
                    "# args: -q <zip> -d <dest>\n"
                    "dest=\"${4:-.}\"\n"
                    "printf '#!/usr/bin/env bash\\nexit 0\\n' > \"$dest/tinfoil-proxy-darwin-arm64\"\n"
                    "exit 0\n",
                ),
            ]:
                p = fake_bin / cmd_name
                p.write_text(body, encoding="utf-8")
                os.chmod(p, 0o755)

            tp = fake_repo / "bin" / "tinfoil-proxy"
            tp.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            os.chmod(tp, 0o755)

            se_key_stub = fake_repo / "scripts" / "se-key"
            se_key_stub.write_text(
                "#!/usr/bin/env bash\nif [ \"$1\" = \"selftest\" ]; then exit 77; fi\nexit 0\n",
                encoding="utf-8",
            )
            os.chmod(se_key_stub, 0o755)

            env = dict(os.environ)
            env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
            env.pop("FREE_INFERENCE_REQUIRE_GH_ATTESTATION", None)

            # Case 0: Strict mode FREE_INFERENCE_REQUIRE_GH_ATTESTATION=1 fails closed when gh is unauthenticated
            env_strict = dict(env)
            env_strict["FREE_INFERENCE_REQUIRE_GH_ATTESTATION"] = "1"
            proc_strict = subprocess.run(
                [str(fake_repo / "scripts" / "setup")],
                cwd=str(fake_repo),
                env=env_strict,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc_strict.returncode, 1)
            self.assertIn("FREE_INFERENCE_REQUIRE_GH_ATTESTATION=1", proc_strict.stderr)

            # Case 1: Default setup with se-key selftest exit 77 and unauthenticated gh -> warns on gh, skips selftest, succeeds (rc=0)
            proc77 = subprocess.run(
                [str(fake_repo / "scripts" / "setup")],
                cwd=str(fake_repo),
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc77.returncode, 0, msg=proc77.stderr + "\n" + proc77.stdout)
            self.assertIn("selftest skipped (exit 77", proc77.stdout)
            self.assertIn("WARNING: 'gh' CLI is missing or not authenticated", proc77.stderr)
            self.assertIn("Setup complete.", proc77.stdout)
            self.assertEqual(npm_log.read_text(encoding="utf-8").strip(), "ci")

            # Case 2 (QA F6a): Wrong tinfoil-proxy SHA-256 -> setup fails closed with SHA-256 mismatch
            (fake_bin / "shasum").write_text(
                "#!/usr/bin/env bash\necho '0000000000000000000000000000000000000000000000000000000000000000  bin/tinfoil-proxy'\n",
                encoding="utf-8",
            )
            proc_bad_sha = subprocess.run(
                [str(fake_repo / "scripts" / "setup")],
                cwd=str(fake_repo),
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc_bad_sha.returncode, 1)
            self.assertIn("SHA-256 mismatch", proc_bad_sha.stderr)
            (fake_bin / "shasum").write_text(
                "#!/usr/bin/env bash\necho '6b526fe32244bcccfcfde3c5d181618b4b06b48498e649cd944cc9b64acf994b  bin/tinfoil-proxy'\n",
                encoding="utf-8",
            )

            # Case 3 (QA F6b): codesign -v --strict failure -> setup fails closed
            (fake_bin / "codesign").write_text(
                "#!/usr/bin/env bash\nif [ \"$1\" = \"-v\" ]; then exit 1; fi\necho 'TeamIdentifier=8KSH668LZT'\nexit 0\n",
                encoding="utf-8",
            )
            proc_bad_cs = subprocess.run(
                [str(fake_repo / "scripts" / "setup")],
                cwd=str(fake_repo),
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc_bad_cs.returncode, 1)
            self.assertIn("failed codesign -v --strict verification", proc_bad_cs.stderr)

            # Case 4 (QA F6c): Wrong TeamIdentifier -> setup fails closed
            (fake_bin / "codesign").write_text(
                "#!/usr/bin/env bash\necho 'TeamIdentifier=WRONGTEAM9'\nexit 0\n",
                encoding="utf-8",
            )
            proc_bad_team = subprocess.run(
                [str(fake_repo / "scripts" / "setup")],
                cwd=str(fake_repo),
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc_bad_team.returncode, 1)
            self.assertIn("TeamIdentifier=8KSH668LZT", proc_bad_team.stderr)
            (fake_bin / "codesign").write_text(
                "#!/usr/bin/env bash\necho 'TeamIdentifier=8KSH668LZT'\nexit 0\n",
                encoding="utf-8",
            )

            # Case 5: se-key selftest exits 1 -> setup fails closed (rc=1)
            se_key_stub.write_text(
                "#!/usr/bin/env bash\nif [ \"$1\" = \"selftest\" ]; then exit 1; fi\nexit 0\n",
                encoding="utf-8",
            )
            proc1 = subprocess.run(
                [str(fake_repo / "scripts" / "setup")],
                cwd=str(fake_repo),
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc1.returncode, 1)

            # Case 6: Unsupported Node version (e.g. 18.19.0) -> setup fails early with actionable message
            node_stub = fake_bin / "node"
            node_stub.write_text(
                "#!/usr/bin/env bash\n"
                "echo 'ERROR: Node.js v18.19.0 is unsupported; promptfoo requires ^20.20.0 || >=22.22.0' >&2\n"
                "exit 1\n",
                encoding="utf-8",
            )
            os.chmod(node_stub, 0o755)
            proc_node = subprocess.run(
                [str(fake_repo / "scripts" / "setup")],
                cwd=str(fake_repo),
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc_node.returncode, 1)
            self.assertIn("^20.20.0 || >=22.22.0", proc_node.stderr)

    def test_lexical_ancestor_symlink_and_with_session_token_scrubbing(self) -> None:
        from local_assist.registry import get_process_lstart
        from local_assist.se_key import verify_root_owned_binary_and_ancestors

        with_tok_mod = _load_script_module("with_tok_scrub_test", "scripts/with-session-token")
        se_key_mod = _load_script_module("se_key_cli_test", "scripts/se-key")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)

            # 1. Lexical ancestor symlink check (review-agy 1) & dot-segment traversal (F6, PLAN-MINOR-5):
            # a symlinked parent dir is rejected even if target is root-owned /usr/bin, and '..' after a symlink is rejected before abspath
            sym_dir = tmp_dir / "sym_usr_bin"
            sym_dir.symlink_to("/usr/bin")
            with self.assertRaises(SEKeyIntegrityError) as ctx_sym:
                verify_root_owned_binary_and_ancestors(sym_dir / "true")
            self.assertIn("symlink", str(ctx_sym.exception).lower())

            for dot_path in (
                Path(f"{sym_dir}/../true"),
                "/usr/bin/./true",
                Path("relative/se-key-proxy"),
            ):
                with self.assertRaises(SEKeyIntegrityError) as ctx_dot:
                    verify_root_owned_binary_and_ancestors(dot_path)
                self.assertTrue(
                    "dot-segment" in str(ctx_dot.exception).lower()
                    or "absolute path" in str(ctx_dot.exception).lower(),
                    str(ctx_dot.exception),
                )

            # 2. with-session-token strips ambient LOCAL_ASSIST_SESSION_TOKEN on Rung 1 local models while preserving PROMPTFOO_DISABLE_TELEMETRY=1
            out_env_file = tmp_dir / "rung1_env.txt"
            with patch.dict(
                os.environ,
                {
                    SESSION_TOKEN_ENV_VAR: "se-session-" + ("a" * 64),
                    "PROMPTFOO_DISABLE_TELEMETRY": "1",
                },
                clear=False,
            ):
                rc_local = with_tok_mod.main(
                    [
                        "scripts/with-session-token",
                        "qwen3-1.7b-mlx-4bit",
                        "--",
                        sys.executable,
                        "-c",
                        f"import json, os, pathlib; pathlib.Path({str(out_env_file)!r}).write_text(json.dumps({{'tok': {SESSION_TOKEN_ENV_VAR!r} in os.environ, 'pf': os.environ.get('PROMPTFOO_DISABLE_TELEMETRY')}}))",
                    ]
                )
            self.assertEqual(rc_local, 0)
            env_res = json.loads(out_env_file.read_text(encoding="utf-8"))
            self.assertIs(env_res["tok"], False)
            self.assertEqual(env_res["pf"], "1")

            # 3. with-session-token rejects dead proxy PID OR mismatched upstream_pid_lstart on Rung 3 models (review-agy 5, WORK-MINOR-1)
            tok_file = tmp_dir / ".se-session-dead.token"
            tok_file.write_text("se-session-" + ("b" * 64) + "\n", encoding="utf-8")
            dead_pid_rec = {
                "model_id": "tinfoil-deepseek-v4-1-flash",
                "pid": 999999,
                "pid_lstart": "Thu Jan  1 00:00:00 1970",
                "session_token_file": str(tok_file),
            }
            with patch.object(with_tok_mod, "read_pid_record_for_model", return_value=dead_pid_rec):
                rc_dead = with_tok_mod.main(
                    [
                        "scripts/with-session-token",
                        "tinfoil-deepseek-v4-1-flash",
                        "--",
                        sys.executable,
                        "-c",
                        "pass",
                    ]
                )
            self.assertEqual(rc_dead, 1)

            my_lstart = get_process_lstart(os.getpid())
            bad_upstream_rec = {
                "model_id": "tinfoil-deepseek-v4-1-flash",
                "pid": os.getpid(),
                "pid_lstart": my_lstart,
                "upstream_pid": os.getpid(),
                "upstream_pid_lstart": "Thu Jan  1 00:00:00 1970",
                "session_token_file": str(tok_file),
            }
            with patch.object(with_tok_mod, "read_pid_record_for_model", return_value=bad_upstream_rec):
                rc_bad_up = with_tok_mod.main(
                    [
                        "scripts/with-session-token",
                        "tinfoil-deepseek-v4-1-flash",
                        "--",
                        sys.executable,
                        "-c",
                        "pass",
                    ]
                )
            self.assertEqual(rc_bad_up, 1)

            # Missing or blank pid_lstart / upstream_pid_lstart on live PIDs must also be rejected (F2)
            for missing_rec in (
                {
                    "model_id": "tinfoil-deepseek-v4-1-flash",
                    "pid": os.getpid(),
                    "pid_lstart": None,
                    "session_token_file": str(tok_file),
                },
                {
                    "model_id": "tinfoil-deepseek-v4-1-flash",
                    "pid": os.getpid(),
                    "pid_lstart": "   ",
                    "session_token_file": str(tok_file),
                },
                {
                    "model_id": "tinfoil-deepseek-v4-1-flash",
                    "pid": os.getpid(),
                    "pid_lstart": my_lstart,
                    "upstream_pid": os.getpid(),
                    "upstream_pid_lstart": "",
                    "session_token_file": str(tok_file),
                },
            ):
                with patch.object(with_tok_mod, "read_pid_record_for_model", return_value=missing_rec):
                    self.assertEqual(
                        with_tok_mod.main(
                            [
                                "scripts/with-session-token",
                                "tinfoil-deepseek-v4-1-flash",
                                "--",
                                sys.executable,
                                "-c",
                                "pass",
                            ]
                        ),
                        1,
                    )

            # 4. se-key rejects invalid Keychain service names with exit code 2 (L27)
            for bad_svc in ("../bad", "spaces not allowed", ""):
                self.assertEqual(
                    se_key_mod.main(["scripts/se-key", "status", bad_svc]),
                    2,
                )

    def test_build_se_key_proxy_preserves_verified_release_binary_cdhash(self) -> None:
        from local_assist.se_key import EXPECTED_SWIFT_SOURCE_SHA256, SWIFT_SOURCE_PATH, sha256_file

        self.assertEqual(sha256_file(SWIFT_SOURCE_PATH), EXPECTED_SWIFT_SOURCE_SHA256)
        verified_path = verify_se_key_proxy_binary()
        self.assertEqual(verified_path, RELEASE_BINARY_PATH.resolve())

        with tempfile.TemporaryDirectory() as td:
            tmp_bin_dir = Path(td)
            shutil.copy2(RELEASE_BINARY_PATH, tmp_bin_dir / "se-key-proxy")
            shutil.copy2(STAMP_PATH, tmp_bin_dir / ".se-key-proxy.stamp")
            before_sha = sha256_file(tmp_bin_dir / "se-key-proxy")

            real_run = subprocess.run
            swiftc_targets: list[str] = []

            def spy_run(cmd: Any, *args: Any, **kwargs: Any) -> Any:
                if isinstance(cmd, list) and cmd and cmd[0] == "swiftc" and "-o" in cmd:
                    out_idx = cmd.index("-o") + 1
                    if out_idx < len(cmd):
                        swiftc_targets.append(Path(cmd[out_idx]).name)
                return real_run(cmd, *args, **kwargs)

            with patch("local_assist.se_key.subprocess.run", side_effect=spy_run):
                res = build_se_key_proxy(
                    include_test_binary=False,
                    bin_dir=tmp_bin_dir,
                )
            self.assertEqual(swiftc_targets, [])
            self.assertEqual(res["binary_sha256"], before_sha)
            self.assertEqual(sha256_file(tmp_bin_dir / "se-key-proxy"), before_sha)


if __name__ == "__main__":
    unittest.main()
