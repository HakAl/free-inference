from __future__ import annotations

import atexit
import base64
import ctypes
import hashlib
import http.client
import importlib.machinery
import importlib.util
import json
import os
import pty
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from local_assist.launch import get_process_lstart

OPENCODE_BIN = shutil.which("opencode")
SANDBOX_EXEC_BIN = Path("/usr/bin/sandbox-exec")
_NATIVE_OPENCODE_TEST_DIR: str | None = None
_NATIVE_OPENCODE_TEST_BIN: Path | None = None


def _get_native_opencode_test_binary() -> Path:
    """Compile a minimal Mach-O executable named `opencode` for genuine argv[0] + TCP LISTEN tests."""
    global _NATIVE_OPENCODE_TEST_DIR, _NATIVE_OPENCODE_TEST_BIN
    if _NATIVE_OPENCODE_TEST_BIN is not None and _NATIVE_OPENCODE_TEST_BIN.is_file():
        return _NATIVE_OPENCODE_TEST_BIN

    cc_bin = Path("/usr/bin/cc")
    if not cc_bin.is_file():
        raise AssertionError("Required host C compiler '/usr/bin/cc' is missing for R1 native service tests")

    tmp_dir = tempfile.mkdtemp(prefix="oc-native-test-")
    atexit.register(shutil.rmtree, tmp_dir, True)
    src_path = Path(tmp_dir) / "opencode_stub.c"
    bin_path = Path(tmp_dir) / "opencode"
    src_path.write_text(
        """
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int req_port = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            req_port = atoi(argv[i + 1]);
            i++;
        } else if (strncmp(argv[i], "--port=", 7) == 0) {
            req_port = atoi(argv[i] + 7);
        }
    }
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 2;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)(req_port > 0 && req_port <= 65535 ? req_port : 0));
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == 0 && listen(s, 4) == 0) {
        socklen_t len = sizeof(addr);
        if (getsockname(s, (struct sockaddr *)&addr, &len) != 0) return 3;
        printf("%d\\n", (int)ntohs(addr.sin_port));
        fflush(stdout);
    } else if (req_port > 0) {
        close(s);
        printf("%d\\n", req_port);
        fflush(stdout);
    } else {
        close(s);
        return 4;
    }
    for (;;) {
        pause();
    }
    return 0;
}
""",
        encoding="utf-8",
    )
    comp = subprocess.run(
        [str(cc_bin), "-O0", str(src_path), "-o", str(bin_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if comp.returncode != 0 or not bin_path.is_file():
        raise AssertionError(
            f"Failed to compile native opencode test binary (rc={comp.returncode}): {comp.stderr}"
        )
    os.chmod(bin_path, 0o755)
    _NATIVE_OPENCODE_TEST_DIR = tmp_dir
    _NATIVE_OPENCODE_TEST_BIN = bin_path
    return bin_path


def _planner_server(handler):
    # Launcher --port reserves room for an upstream port at +1000. macOS's
    # sequential ephemeral port counter can sit in 64536..65535 across many
    # consecutive port=0 binds, so fall back to a single-wrap scan of 49152..64535.
    import random

    for _ in range(16):
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        if server.server_address[1] <= 64535:
            return server
        server.server_close()
    lo, hi = 49152, 64535
    span = hi - lo + 1
    offset = random.randrange(span)
    for i in range(span):
        cand = lo + ((offset + i) % span)
        try:
            return ThreadingHTTPServer(('127.0.0.1', cand), handler)
        except OSError:
            continue
    raise RuntimeError('Could not allocate a bounded planner port in 49152..64535.')


def _load_script_module(name: str, rel_path: str) -> ModuleType:
    script_path = ROOT / rel_path
    loader = importlib.machinery.SourceFileLoader(name, str(script_path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _read_kern_procargs2(pid: int) -> bytes:
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    mib = (ctypes.c_int * 3)(1, 49, int(pid))  # CTL_KERN=1, KERN_PROCARGS2=49
    size = ctypes.c_size_t(0)
    if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0 or size.value == 0:
        return b""
    buf = ctypes.create_string_buffer(size.value + 4096)
    size = ctypes.c_size_t(len(buf))
    if libc.sysctl(mib, 3, buf, ctypes.byref(size), None, 0) != 0:
        return b""
    return buf.raw[: size.value]


def _secret_variants(secret: str) -> list[str]:
    variants: list[str] = []
    for cand in (
        secret,
        quote(secret, safe=""),
        base64.b64encode(secret.encode("utf-8")).decode("ascii"),
        base64.urlsafe_b64encode(secret.encode("utf-8")).decode("ascii").rstrip("="),
        base64.b64encode(f"opencode:{secret}".encode("utf-8")).decode("ascii"),
        base64.b64encode(f":{secret}".encode("utf-8")).decode("ascii"),
    ):
        if cand and cand not in variants:
            variants.append(cand)
    return variants


def _scan_sinks_for_secrets(roots: list[Path], secrets_list: list[str]) -> list[str]:
    needles: list[bytes] = []
    for s in secrets_list:
        for v in _secret_variants(s):
            b = v.encode("utf-8")
            if b not in needles:
                needles.append(b)
    hits: list[str] = []
    for root in roots:
        if not root.exists():
            continue
        files = [root] if root.is_file() else list(root.rglob("*"))
        for fp in files:
            if fp.is_symlink() or not fp.is_file():
                continue
            try:
                data = fp.read_bytes()
            except OSError:
                continue
            for n in needles:
                if n in data:
                    hits.append(f"{fp}:matched({len(n)}B)")
                    break
    return hits


def _send_openai_reply(
    handler: BaseHTTPRequestHandler,
    *,
    req_json: dict[str, Any],
    turn_id: int,
    model_name: str,
    msg_obj: dict[str, Any],
    finish_reason: str,
) -> None:
    if req_json.get("stream"):
        handler.send_response(200)
        handler.send_header("Content-Type", "text/event-stream")
        handler.send_header("Cache-Control", "no-cache")
        handler.end_headers()
        delta: dict[str, Any] = {"role": "assistant"}
        if msg_obj.get("content") is not None:
            delta["content"] = msg_obj["content"]
        if msg_obj.get("tool_calls"):
            delta["tool_calls"] = [
                {
                    "index": idx,
                    "id": tc["id"],
                    "type": "function",
                    "function": tc["function"],
                }
                for idx, tc in enumerate(msg_obj["tool_calls"])
            ]
        chunk = {
            "id": f"chatcmpl-{turn_id}",
            "object": "chat.completion.chunk",
            "model": model_name,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
        }
        handler.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode("utf-8"))
        handler.wfile.write(b"data: [DONE]\n\n")
        handler.wfile.flush()
        return

    resp_body = json.dumps(
        {
            "id": f"chatcmpl-{turn_id}",
            "object": "chat.completion",
            "model": model_name,
            "choices": [
                {
                    "index": 0,
                    "message": msg_obj,
                    "finish_reason": finish_reason,
                }
            ],
        }
    ).encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(resp_body)))
    handler.end_headers()
    handler.wfile.write(resp_body)


@unittest.skipUnless(
    sys.platform == "darwin" and SANDBOX_EXEC_BIN.is_file(),
    "requires macOS sandbox-exec",
)
class SessionCredentialIsolationTests(unittest.TestCase):
    def test_session_auth_relay_custody_and_outbound_leak_backstop(self) -> None:
        from local_assist.relay import SessionAuthRelay, _WorkerTokenRelay

        upstream_tok = "se-session-" + ("ab12" * 16)
        service_pw = "svc-pw-canary-9876543210abcdef"
        seen_auth: list[str] = []
        seen_bodies: list[dict[str, Any]] = []

        class _MockUpstream(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                seen_auth.append(self.headers.get("Authorization", ""))
                body = json.dumps({"data": [{"id": "deepseek-v4-1-flash"}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                seen_auth.append(self.headers.get("Authorization", ""))
                cl = int(self.headers.get("Content-Length", "0"))
                parsed = json.loads(self.rfile.read(cl).decode("utf-8"))
                seen_bodies.append(parsed)
                _send_openai_reply(
                    self,
                    req_json=parsed,
                    turn_id=1,
                    model_name="deepseek-v4-1-flash",
                    msg_obj={"role": "assistant", "content": "ok"},
                    finish_reason="stop",
                )

        up_srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockUpstream)
        up_srv.daemon_threads = True
        up_thread = threading.Thread(target=up_srv.serve_forever, daemon=True)
        up_thread.start()

        relay = SessionAuthRelay(
            upstream_base_url=f"http://127.0.0.1:{up_srv.server_address[1]}/v1",
            upstream_session_token=upstream_tok,
            token_prefix="oc-relay",
            extra_canary_secrets=[service_pw],
            max_chat_requests=3,
            max_request_bytes=65536,
            max_tokens_cap=1024,
        ).start()
        worker_alias = _WorkerTokenRelay(
            upstream_base_url=f"http://127.0.0.1:{up_srv.server_address[1]}/v1",
            upstream_session_token=upstream_tok,
        )
        self.assertTrue(relay.relay_token.startswith("oc-relay-"))
        self.assertEqual(len(relay.relay_token), len("oc-relay-") + 64)
        self.assertTrue(worker_alias.relay_token.startswith("worker-relay-"))

        try:
            chat_url = f"{relay.api_base_url}/chat/completions"

            # Wrong credential class (presenting upstream se-session-* or service_pw to relay) -> 401
            for wrong_tok in (upstream_tok, service_pw, "oc-relay-wrong"):
                req_401 = Request(
                    f"{relay.api_base_url}/models",
                    headers={"Authorization": f"Bearer {wrong_tok}"},
                    method="GET",
                )
                with self.assertRaises(HTTPError) as ctx_401:
                    urlopen(req_401, timeout=5)
                self.assertEqual(ctx_401.exception.code, 401)
                ctx_401.exception.close()
            self.assertEqual(len(seen_auth), 0)

            # Outbound leak variants -> HTTP 400 credential_leak_blocked, 0 upstream forwards
            headers = {
                "Authorization": f"Bearer {relay.relay_token}",
                "Content-Type": "application/json",
            }
            for secret_label, secret_val in (
                ("upstream_tok", upstream_tok),
                ("relay_tok", relay.relay_token),
                ("service_pw", service_pw),
                ("other_se_session", "se-session-" + ("f0" * 20)),
            ):
                for variant in _secret_variants(secret_val):
                    body = json.dumps(
                        {
                            "model": "deepseek-v4-1-flash",
                            "messages": [{"role": "user", "content": f"leak {variant}"}],
                        }
                    ).encode("utf-8")
                    with self.assertRaises(
                        HTTPError, msg=f"Expected 400 for {secret_label} ({variant[:18]})"
                    ) as ctx_400:
                        urlopen(Request(chat_url, data=body, headers=headers, method="POST"), timeout=5)
                    err_raw = ctx_400.exception.read().decode("utf-8", errors="replace")
                    ctx_400.exception.close()
                    self.assertEqual(ctx_400.exception.code, 400)
                    err_obj = json.loads(err_raw).get("error") or {}
                    self.assertEqual(err_obj.get("type"), "credential_leak_blocked")
                    self.assertNotIn(upstream_tok, err_raw)
                    self.assertNotIn(service_pw, err_raw)

                # SIR-W7: JSON Unicode-escaped (\uXXXX) spelling on wire that decodes after json.loads()
                u_escaped = "".join(f"\\u{ord(ch):04x}" for ch in secret_val)
                raw_u_body = (
                    '{"model":"deepseek-v4-1-flash","messages":[{"role":"user","content":"leak '
                    + u_escaped
                    + '"}]}'
                ).encode("ascii")
                self.assertNotIn(secret_val.encode("utf-8"), raw_u_body)
                with self.assertRaises(
                    HTTPError, msg=f"Expected 400 for JSON-escaped {secret_label}"
                ) as ctx_u400:
                    urlopen(
                        Request(chat_url, data=raw_u_body, headers=headers, method="POST"),
                        timeout=5,
                    )
                err_u_raw = ctx_u400.exception.read().decode("utf-8", errors="replace")
                ctx_u400.exception.close()
                self.assertEqual(ctx_u400.exception.code, 400)
                err_u_obj = json.loads(err_u_raw).get("error") or {}
                self.assertEqual(err_u_obj.get("type"), "credential_leak_blocked")
                self.assertNotIn(upstream_tok, err_u_raw)
                self.assertNotIn(service_pw, err_u_raw)

            self.assertEqual(len(seen_bodies), 0)
            self.assertEqual(relay.chat_requests_used, 0)

            # Clean request forwards with upstream se-session-* token
            clean_body = json.dumps(
                {
                    "model": "deepseek-v4-1-flash",
                    "messages": [{"role": "user", "content": "clean turn"}],
                }
            ).encode("utf-8")
            with urlopen(
                Request(chat_url, data=clean_body, headers=headers, method="POST"), timeout=5
            ) as resp:
                self.assertEqual(resp.status, 200)
            self.assertEqual(seen_auth[-1], f"Bearer {upstream_tok}")
            self.assertEqual(len(seen_bodies), 1)

            # Relay TTL expiry enforcement -> HTTP 401 session_expired, zero additional upstream forwards
            short_relay = SessionAuthRelay(
                upstream_base_url=f"http://127.0.0.1:{up_srv.server_address[1]}/v1",
                upstream_session_token=upstream_tok,
                token_prefix="oc-relay",
                extra_canary_secrets=[service_pw],
                ttl_seconds=0.08,
            ).start()
            try:
                time.sleep(0.14)
                exp_headers = {
                    "Authorization": f"Bearer {short_relay.relay_token}",
                    "Content-Type": "application/json",
                }
                with self.assertRaises(HTTPError) as ctx_exp:
                    urlopen(
                        Request(
                            f"{short_relay.api_base_url}/chat/completions",
                            data=clean_body,
                            headers=exp_headers,
                            method="POST",
                        ),
                        timeout=5,
                    )
                exp_raw = ctx_exp.exception.read().decode("utf-8", errors="replace")
                ctx_exp.exception.close()
                self.assertEqual(ctx_exp.exception.code, 401)
                self.assertEqual((json.loads(exp_raw).get("error") or {}).get("type"), "session_expired")
                self.assertEqual(len(seen_bodies), 1)
            finally:
                short_relay.close()
        finally:
            relay.close()
            up_srv.shutdown()
            up_srv.server_close()

    def test_legacy_home_containment_gate_and_cleanup_tool(self) -> None:
        from local_assist.launch import publish_and_run_opencode
        from local_assist.registry import load_model, resolve_endpoint

        containment_script = ROOT / "scripts" / "check-credential-containment"
        self.assertTrue(containment_script.is_file(), "Missing scripts/check-credential-containment")

        canary_tok = "se-session-" + ("deadbeef" * 8)
        canary_pw = "legacy-service-pw-112233445566"
        synthetic_incident = "SESSION-CREDENTIAL-001-SYNTHETIC"
        ep_ds = resolve_endpoint(load_model("tinfoil-deepseek-v4-1-flash"), require_api_key=False)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            legacy_home = tmp_dir / "legacy_home"
            preserved_dir = tmp_dir / "preserved_snapshot"
            runs_dir = tmp_dir / "runs"
            ws_dir = tmp_dir / "ws"
            evidence_path = tmp_dir / "evidence.json"
            for d in (
                legacy_home / ".local" / "state" / "opencode",
                legacy_home / ".local" / "share" / "opencode" / "log",
                legacy_home / ".configs",
                preserved_dir,
                runs_dir,
                ws_dir,
            ):
                d.mkdir(parents=True, exist_ok=True)

            # Spawn a genuine native `opencode serve --service` listener bound to legacy_home
            native_oc_bin = _get_native_opencode_test_binary()
            listener_proc = subprocess.Popen(
                [str(native_oc_bin), "serve", "--service"],
                env={
                    "HOME": str(legacy_home),
                    "OPENCODE_TEST_HOME": str(legacy_home),
                    "PATH": "/usr/bin:/bin",
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                assert listener_proc.stdout is not None
                legacy_port = int(listener_proc.stdout.readline().strip())
                svc_file = legacy_home / ".local" / "state" / "opencode" / "service.json"
                svc_file.write_text(
                    json.dumps(
                        {
                            "pid": listener_proc.pid,
                            "hostname": "127.0.0.1",
                            "port": legacy_port,
                            "password": canary_pw,
                        }
                    ),
                    encoding="utf-8",
                )
                os.chmod(svc_file, 0o600)
                svc_id_file = legacy_home / ".service-identity.json"
                svc_id_file.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "id": "legacy",
                            "pid": listener_proc.pid,
                            "pid_lstart": get_process_lstart(listener_proc.pid),
                            "service_port": legacy_port,
                        }
                    ),
                    encoding="utf-8",
                )
                os.chmod(svc_id_file, 0o400)

                # Populate contaminated SQLite DB + WAL + log + stale config
                db_path = legacy_home / ".local" / "share" / "opencode" / "opencode.db"
                conn = sqlite3.connect(str(db_path))
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("CREATE TABLE part (id TEXT, data TEXT)")
                conn.execute("INSERT INTO part VALUES ('p1', ?)", (f"leaked {canary_tok}",))
                conn.commit()
                conn.close()
                wal_path = legacy_home / ".local" / "share" / "opencode" / "opencode.db-wal"
                if not wal_path.exists():
                    wal_path.write_bytes(b"synthetic-wal")

                log_path = legacy_home / ".local" / "share" / "opencode" / "log" / "opencode.log"
                log_path.write_text(f"2026-11-14 header Bearer {canary_tok}\n", encoding="utf-8")
                stale_cfg = legacy_home / ".configs" / "opencode-stale.json"
                stale_cfg.write_text('{"stale": true}\n', encoding="utf-8")

                # Preserve immutable forensic snapshots OUTSIDE legacy_home (SIR-W5)
                pres_db = preserved_dir / "opencode.db"
                pres_log = preserved_dir / "opencode.log"
                pres_svc = preserved_dir / "service.json"
                shutil.copy2(db_path, pres_db)
                shutil.copy2(log_path, pres_log)
                shutil.copy2(svc_file, pres_svc)

                db_sha_before = hashlib.sha256(pres_db.read_bytes()).hexdigest()
                log_sha_before = hashlib.sha256(pres_log.read_bytes()).hexdigest()
                svc_sha_before = hashlib.sha256(pres_svc.read_bytes()).hexdigest()

                evidence_payload = {
                    "incident_id": synthetic_incident,
                    "captured_at": "2026-11-14T00:00:00Z",
                    "target_home": str(legacy_home),
                    "artifacts": {
                        str(pres_db): db_sha_before,
                        str(pres_log): log_sha_before,
                        str(pres_svc): svc_sha_before,
                    },
                }
                evidence_path.write_text(json.dumps(evidence_payload, indent=2), encoding="utf-8")

                # SIR2: Ordinary publish_and_run_opencode startup against uncontained legacy_home
                # MUST fail closed (rc == 1) WITHOUT stopping listener_proc or mutating files!
                popen_called = False

                def _never_popen(*_a: Any, **_kw: Any) -> Any:
                    nonlocal popen_called
                    popen_called = True
                    raise AssertionError("popen_fn must not be called on uncontained legacy home")

                rc_gate = publish_and_run_opencode(
                    opencode_bin="/usr/bin/true",
                    opencode_args=["run", "hello"],
                    caller_cwd=ws_dir,
                    isolated_home=legacy_home,
                    endpoint=ep_ds,
                    config_text='{"model": "ds"}',
                    build_env_fn=lambda p: {"OPENCODE_CONFIG": str(p)},
                    current_sync={"model_id": ep_ds.model_id},
                    popen_fn=_never_popen,
                )
                self.assertEqual(rc_gate, 1)
                self.assertFalse(popen_called)
                self.assertIsNone(listener_proc.poll(), "Legacy listener must NOT be killed by startup!")
                self.assertTrue(svc_file.exists())
                self.assertEqual(hashlib.sha256(svc_file.read_bytes()).hexdigest(), svc_sha_before)
                self.assertEqual(hashlib.sha256(db_path.read_bytes()).hexdigest(), db_sha_before)
                self.assertEqual(hashlib.sha256(log_path.read_bytes()).hexdigest(), log_sha_before)

                # 1. --check is strictly read-only and outputs booleans + counts only (zero secrets/hashes)
                chk = subprocess.run(
                    [
                        sys.executable,
                        str(containment_script),
                        "--check",
                        "--home",
                        str(legacy_home),
                        "--runs-dir",
                        str(runs_dir),
                        "--evidence-path",
                        str(evidence_path),
                        "--incident-id",
                        synthetic_incident,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertNotIn(canary_tok, chk.stdout + chk.stderr)
                self.assertNotIn(canary_pw, chk.stdout + chk.stderr)
                self.assertNotIn(db_sha_before, chk.stdout + chk.stderr)
                chk_json = json.loads(chk.stdout)
                self.assertIs(chk_json["evidence_schema_valid"], True)
                self.assertIs(chk_json["evidence_integrity_valid"], True)
                self.assertIs(chk_json["evidence_snapshot_valid"], True)
                self.assertIs(chk_json["holder_inspection_ok"], True)
                self.assertIs(chk_json["legacy_service_files_present"], True)
                self.assertGreaterEqual(chk_json["db_matching_records"], 1)
                self.assertIs(chk_json["wal_or_journal_present"], True)
                self.assertGreaterEqual(chk_json["log_matching_lines"], 1)

                # 2. --apply WITHOUT --operator-approved is refused and mutates nothing
                no_app = subprocess.run(
                    [
                        sys.executable,
                        str(containment_script),
                        "--apply",
                        "--home",
                        str(legacy_home),
                        "--runs-dir",
                        str(runs_dir),
                        "--evidence-path",
                        str(evidence_path),
                        "--incident-id",
                        synthetic_incident,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertNotEqual(no_app.returncode, 0)
                self.assertIsNone(listener_proc.poll())
                self.assertTrue(svc_file.exists())

                # 3. SIR-W5 negative fixtures: fabricated schema, altered digest, absent artifact,
                # wrong incident, wrong target_home, unpreserved artifact inside legacy_home,
                # and schema-valid provenance records omitting lab_head or required SQLite event stores.
                flipped_sha = ("0" if db_sha_before[0] != "0" else "1") + db_sha_before[1:]
                real_head = subprocess.run(
                    ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout.strip()
                real_sec_blob = subprocess.run(
                    ["git", "-C", str(ROOT), "show", f"{real_head}:SECURITY.md"],
                    capture_output=True,
                    check=True,
                ).stdout
                real_sec_sha = hashlib.sha256(real_sec_blob).hexdigest()
                bad_sec_sha = ("0" if real_sec_sha[0] != "0" else "1") + real_sec_sha[1:]
                valid_prov_event = {
                    "message_id": "msg_prov_1",
                    "session_sequence": 1,
                    "tool_name": "bash",
                    "event_label": "probe",
                    "snapshot_rowid": 1,
                }
                negative_cases: list[tuple[str, dict[str, Any], str, bool]] = [
                    (
                        "invalid_shape",
                        {"invalid": True},
                        synthetic_incident,
                        False,
                    ),
                    (
                        "fabricated_provenance_counterexample",
                        {
                            "tracking_id": synthetic_incident,
                            "session_id": "s1",
                            "events": [{}],
                            "source_sha256": {"a": "not-a-digest"},
                        },
                        synthetic_incident,
                        False,
                    ),
                    (
                        "provenance_omitting_lab_head_and_artifacts",
                        {
                            "tracking_id": synthetic_incident,
                            "target_home": str(legacy_home),
                            "session_id": "s_prov",
                            "events": [valid_prov_event],
                            "source_sha256": {"lab/SECURITY.md": real_sec_sha},
                        },
                        synthetic_incident,
                        True,
                    ),
                    (
                        "provenance_malformed_lab_head",
                        {
                            "tracking_id": synthetic_incident,
                            "target_home": str(legacy_home),
                            "lab_head": "not-a-valid-40-hex-commit-identifier",
                            "session_id": "s_prov",
                            "events": [valid_prov_event],
                            "source_sha256": {"lab/SECURITY.md": real_sec_sha},
                        },
                        synthetic_incident,
                        True,
                    ),
                    (
                        "provenance_unmatched_git_digest",
                        {
                            "tracking_id": synthetic_incident,
                            "target_home": str(legacy_home),
                            "lab_head": real_head,
                            "session_id": "s_prov",
                            "events": [valid_prov_event],
                            "source_sha256": {"lab/SECURITY.md": bad_sec_sha},
                        },
                        synthetic_incident,
                        True,
                    ),
                    (
                        "altered_digest",
                        {
                            **evidence_payload,
                            "artifacts": {**evidence_payload["artifacts"], str(pres_db): flipped_sha},
                        },
                        synthetic_incident,
                        True,
                    ),
                    (
                        "absent_artifact",
                        {
                            **evidence_payload,
                            "artifacts": {str(preserved_dir / "missing.db"): db_sha_before},
                        },
                        synthetic_incident,
                        True,
                    ),
                    (
                        "wrong_incident",
                        evidence_payload,
                        "OTHER-INCIDENT-999",
                        True,
                    ),
                    (
                        "wrong_target_home",
                        {
                            **evidence_payload,
                            "target_home": str(tmp_dir / "other_unrelated_home"),
                        },
                        synthetic_incident,
                        True,
                    ),
                    (
                        "artifact_inside_target_home",
                        {
                            **evidence_payload,
                            "artifacts": {str(db_path): db_sha_before},
                        },
                        synthetic_incident,
                        True,
                    ),
                ]
                for case_name, bad_payload, inc_arg, exp_schema_ok in negative_cases:
                    bad_ev_file = tmp_dir / f"bad_{case_name}.json"
                    bad_ev_file.write_text(json.dumps(bad_payload), encoding="utf-8")
                    bad_chk = subprocess.run(
                        [
                            sys.executable,
                            str(containment_script),
                            "--check",
                            "--home",
                            str(legacy_home),
                            "--runs-dir",
                            str(runs_dir),
                            "--evidence-path",
                            str(bad_ev_file),
                            "--incident-id",
                            inc_arg,
                        ],
                        capture_output=True,
                        text=True,
                        timeout=15,
                        check=False,
                    )
                    bad_chk_json = json.loads(bad_chk.stdout)
                    self.assertIs(bad_chk_json["evidence_schema_valid"], exp_schema_ok, case_name)
                    self.assertIs(bad_chk_json["evidence_integrity_valid"], False, case_name)
                    self.assertIs(bad_chk_json["evidence_snapshot_valid"], False, case_name)

                    bad_app = subprocess.run(
                        [
                            sys.executable,
                            str(containment_script),
                            "--apply",
                            "--operator-approved",
                            "--home",
                            str(legacy_home),
                            "--runs-dir",
                            str(runs_dir),
                            "--evidence-path",
                            str(bad_ev_file),
                            "--incident-id",
                            inc_arg,
                        ],
                        capture_output=True,
                        text=True,
                        timeout=15,
                        check=False,
                    )
                    self.assertNotEqual(bad_app.returncode, 0, case_name)
                    self.assertIsNone(listener_proc.poll(), case_name)
                    self.assertTrue(svc_file.exists(), case_name)
                    self.assertTrue(db_path.exists(), case_name)

                # SIR-W5 missing required SQLite event store when provenance record omits external artifacts:
                missing_db_home = tmp_dir / "missing_db_home"
                missing_db_svc = missing_db_home / ".local" / "state" / "opencode" / "service.json"
                missing_db_svc.parent.mkdir(parents=True, exist_ok=True)
                missing_db_svc.write_text('{"pid": 999997, "port": 59997, "password": "pw"}\n', encoding="utf-8")
                missing_db_ev = tmp_dir / "bad_provenance_missing_db.json"
                missing_db_ev.write_text(
                    json.dumps(
                        {
                            "tracking_id": synthetic_incident,
                            "target_home": str(missing_db_home),
                            "lab_head": real_head,
                            "session_id": "s_prov",
                            "events": [valid_prov_event],
                            "source_sha256": {"lab/SECURITY.md": real_sec_sha},
                        }
                    ),
                    encoding="utf-8",
                )
                md_chk = subprocess.run(
                    [
                        sys.executable,
                        str(containment_script),
                        "--check",
                        "--home",
                        str(missing_db_home),
                        "--runs-dir",
                        str(runs_dir),
                        "--evidence-path",
                        str(missing_db_ev),
                        "--incident-id",
                        synthetic_incident,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                md_chk_json = json.loads(md_chk.stdout)
                self.assertIs(md_chk_json["evidence_schema_valid"], True)
                self.assertIs(md_chk_json["evidence_integrity_valid"], False)
                md_app = subprocess.run(
                    [
                        sys.executable,
                        str(containment_script),
                        "--apply",
                        "--operator-approved",
                        "--home",
                        str(missing_db_home),
                        "--runs-dir",
                        str(runs_dir),
                        "--evidence-path",
                        str(missing_db_ev),
                        "--incident-id",
                        synthetic_incident,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertNotEqual(md_app.returncode, 0)
                self.assertIsNone(listener_proc.poll())
                self.assertTrue(missing_db_svc.exists())

                # 4. --apply --operator-approved with valid evidence stops affected proxy + legacy listener and cleans home
                # Use the module-level import; a local import shadows earlier fixture setup.

                canary_proxy_proc = subprocess.Popen(
                    [sys.executable, "-c", "import time; print('P', flush=True); time.sleep(60)"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    assert canary_proxy_proc.stdout is not None
                    self.assertEqual(canary_proxy_proc.stdout.readline().strip(), "P")
                    closed_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    closed_sock.bind(("127.0.0.1", 0))
                    canary_proxy_port = int(closed_sock.getsockname()[1])
                    closed_sock.close()
                    canary_tok_file = runs_dir / ".se-session-canary.token"
                    canary_tok_file.write_text(canary_tok + "\n", encoding="utf-8")
                    canary_pid_file = runs_dir / ".serve.canary-proxy.pid"
                    canary_pid_file.write_text(
                        json.dumps(
                            {
                                "model_id": "tinfoil-deepseek-v4-1-flash",
                                "trust_tier": "enclave_runtime_attested",
                                "pid": canary_proxy_proc.pid,
                                "pid_lstart": get_process_lstart(canary_proxy_proc.pid),
                                "port": canary_proxy_port,
                                "session_token_file": str(canary_tok_file),
                                "status": "ready",
                            }
                        ),
                        encoding="utf-8",
                    )

                    ok_app = subprocess.run(
                        [
                            sys.executable,
                            str(containment_script),
                            "--apply",
                            "--operator-approved",
                            "--home",
                            str(legacy_home),
                            "--runs-dir",
                            str(runs_dir),
                            "--evidence-path",
                            str(evidence_path),
                            "--incident-id",
                            synthetic_incident,
                        ],
                        capture_output=True,
                        text=True,
                        timeout=20,
                        check=False,
                    )
                    self.assertEqual(ok_app.returncode, 0, ok_app.stderr + ok_app.stdout)
                    self.assertNotIn(canary_tok, ok_app.stdout + ok_app.stderr)
                    self.assertNotIn(canary_pw, ok_app.stdout + ok_app.stderr)
                    app_json = json.loads(ok_app.stdout)
                    self.assertIs(app_json["containment_clean"], True)
                    self.assertIs(app_json["session_revocation_verified"], True)
                    self.assertIs(app_json["legacy_service_files_present"], False)
                    self.assertEqual(app_json["db_matching_records"], 0)
                    self.assertIs(app_json["wal_or_journal_present"], False)
                    self.assertEqual(app_json["log_matching_lines"], 0)
                    self.assertFalse(svc_file.exists())
                    self.assertFalse(svc_id_file.exists())
                    self.assertFalse(db_path.exists())
                    self.assertFalse(log_path.exists())
                    self.assertFalse(stale_cfg.exists())
                    # Preserved forensic snapshots outside legacy_home remain intact!
                    self.assertEqual(hashlib.sha256(pres_db.read_bytes()).hexdigest(), db_sha_before)
                    self.assertEqual(hashlib.sha256(pres_log.read_bytes()).hexdigest(), log_sha_before)
                    self.assertEqual(hashlib.sha256(pres_svc.read_bytes()).hexdigest(), svc_sha_before)
                    self.assertIsNotNone(canary_proxy_proc.wait(timeout=5))
                    self.assertIsNotNone(listener_proc.wait(timeout=5))
                finally:
                    if canary_proxy_proc.poll() is None:
                        canary_proxy_proc.kill()
                        canary_proxy_proc.wait(timeout=5)
                    for _cpipe in (canary_proxy_proc.stdout, canary_proxy_proc.stderr):
                        if _cpipe is not None:
                            _cpipe.close()
            finally:
                if listener_proc.poll() is None:
                    listener_proc.kill()
                    listener_proc.wait(timeout=5)
                for _pipe in (listener_proc.stdout, listener_proc.stderr):
                    if _pipe is not None:
                        _pipe.close()

    def test_sir_w1_and_w6_entry_point_legacy_gate_and_missing_seatbelt_preflight(self) -> None:
        from local_assist.launch import publish_and_run_opencode
        from local_assist.registry import get_process_lstart, load_model, resolve_endpoint

        att_mod = _load_script_module("opencode_attested_sir_w1", "scripts/opencode-attested")
        loc_mod = _load_script_module("opencode_local_sir_w1", "scripts/opencode-local")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            legacy_home = tmp_dir / "legacy_home"
            clean_home = tmp_dir / "clean_home"
            runs_dir = tmp_dir / "runs"
            ws_dir = tmp_dir / "ws"
            for d in (
                legacy_home / ".local" / "state" / "opencode",
                clean_home,
                runs_dir,
                ws_dir,
            ):
                d.mkdir(parents=True, exist_ok=True)

            svc_file = legacy_home / ".local" / "state" / "opencode" / "service.json"
            svc_file.write_text('{"pid": 999999, "port": 54321, "password": "legacy-pw-12345678"}\n', encoding="utf-8")
            os.chmod(svc_file, 0o600)

            # Low-cap PID record that would trigger automatic session refresh if ensure_model_served ran!
            low_cap_pid = runs_dir / ".serve.tinfoil-deepseek-v4-1-flash.pid"
            low_cap_rec = {
                "model_id": "tinfoil-deepseek-v4-1-flash",
                "repo": "deepseek-v4-1-flash",
                "port": 18081,
                "upstream_port": 19081,
                "pid": os.getpid(),
                "pid_lstart": get_process_lstart(os.getpid()),
                "status": "ready",
                "max_chat_requests": 10,
                "max_tokens_cap": 1024,
                "max_request_bytes": 65536,
                "ttl_seconds": 600,
            }
            low_cap_pid.write_text(json.dumps(low_cap_rec), encoding="utf-8")
            pid_sha_before = hashlib.sha256(low_cap_pid.read_bytes()).hexdigest()

            orig_att_ensure = att_mod.ensure_model_served
            orig_loc_ensure = loc_mod.ensure_model_served
            orig_env = dict(os.environ)
            try:
                def _forbid_ensure(*_a: Any, **_kw: Any) -> Any:
                    raise AssertionError("ensure_model_served must NOT run before preflight gates!")

                att_mod.ensure_model_served = _forbid_ensure
                loc_mod.ensure_model_served = _forbid_ensure

                # SIR-W1: Both main() entry points refuse legacy_home BEFORE ensure_model_served
                # (including low-cap auto-refresh and explicit --refresh-session).
                os.environ["FREE_INFERENCE_RUNS_DIR"] = str(runs_dir)
                os.environ["FREE_INFERENCE_OPENCODE_ATTESTED_HOME"] = str(legacy_home)
                os.environ["FREE_INFERENCE_OPENCODE_LOCAL_HOME"] = str(legacy_home)

                rc_att_auto = att_mod.main(
                    ["opencode-attested", "--model", "tinfoil-deepseek-v4-1-flash", "--", "run", "hi"]
                )
                self.assertEqual(rc_att_auto, 1)
                rc_att_ref = att_mod.main(
                    [
                        "opencode-attested",
                        "--model",
                        "tinfoil-deepseek-v4-1-flash",
                        "--refresh-session",
                        "--",
                        "run",
                        "hi",
                    ]
                )
                self.assertEqual(rc_att_ref, 1)
                rc_loc = loc_mod.main(["opencode-local", "--", "run", "hi"])
                self.assertEqual(rc_loc, 1)
                self.assertEqual(hashlib.sha256(low_cap_pid.read_bytes()).hexdigest(), pid_sha_before)
                self.assertTrue(svc_file.exists())

                # SIR-W6: Missing sandbox-exec fails closed BEFORE ensure_model_served, relay startup,
                # or creating .invocations/ / service.json!
                missing_sb = tmp_dir / "missing-sandbox-exec"
                os.environ["FREE_INFERENCE_OPENCODE_ATTESTED_HOME"] = str(clean_home)
                os.environ["FREE_INFERENCE_OPENCODE_LOCAL_HOME"] = str(clean_home)
                os.environ["FREE_INFERENCE_SANDBOX_EXEC_BIN"] = str(missing_sb)

                if OPENCODE_BIN is not None:
                    rc_att_sb = att_mod.main(
                        [
                            "opencode-attested",
                            "--model",
                            "tinfoil-deepseek-v4-1-flash",
                            "--no-serve",
                            "--",
                            "run",
                            "hi",
                        ]
                    )
                    self.assertEqual(rc_att_sb, 1)
                    rc_loc_sb = loc_mod.main(["opencode-local", "--no-serve", "--", "run", "hi"])
                    self.assertEqual(rc_loc_sb, 1)
                    self.assertFalse((clean_home / ".invocations").exists())

                relay_started = False

                def _forbid_relay(_pw: str) -> Any:
                    nonlocal relay_started
                    relay_started = True
                    raise AssertionError("relay_factory must NOT be called when sandbox-exec is missing")

                ep_ds = resolve_endpoint(load_model("tinfoil-deepseek-v4-1-flash"), require_api_key=False)
                rc_pub_sb = publish_and_run_opencode(
                    opencode_bin="/usr/bin/true",
                    opencode_args=["run", "hi"],
                    caller_cwd=ws_dir,
                    isolated_home=clean_home,
                    endpoint=ep_ds,
                    config_text='{"model": "ds"}',
                    build_env_fn=lambda p: {"OPENCODE_CONFIG": str(p)},
                    current_sync={"model_id": ep_ds.model_id},
                    relay_factory=_forbid_relay,
                    use_token_relay=True,
                    sandbox_exec_bin=missing_sb,
                )
                self.assertEqual(rc_pub_sb, 1)
                self.assertFalse(relay_started)
                self.assertFalse((clean_home / ".invocations").exists())
            finally:
                att_mod.ensure_model_served = orig_att_ensure
                loc_mod.ensure_model_served = orig_loc_ensure
                os.environ.clear()
                os.environ.update(orig_env)

    def test_sir_w2_w3_w4_scoped_revocation_and_holder_fail_closed(self) -> None:
        from local_assist.registry import get_process_lstart

        cont_mod = _load_script_module("check_containment_sir_w234", "scripts/check-credential-containment")
        aff_tok = "se-session-" + ("11aa22bb" * 8)
        unrel_tok = "se-session-" + ("99cc88dd" * 8)
        inc_id = "SESSION-CREDENTIAL-001-W234"

        def _spawn_http_token_listener(expected_tok: str) -> tuple[subprocess.Popen[str], int]:
            code = (
                "import sys, json\n"
                "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
                f"TOK = {expected_tok!r}\n"
                "class H(BaseHTTPRequestHandler):\n"
                "    def log_message(self, *a): pass\n"
                "    def do_GET(self):\n"
                "        if self.headers.get('Authorization') == f'Bearer {TOK}':\n"
                "            b = b'{\"data\":[]}'\n"
                "            self.send_response(200)\n"
                "            self.send_header('Content-Length', str(len(b)))\n"
                "            self.end_headers()\n"
                "            self.wfile.write(b)\n"
                "        else:\n"
                "            self.send_response(401)\n"
                "            self.end_headers()\n"
                "srv = HTTPServer(('127.0.0.1', 0), H)\n"
                "print(srv.server_address[1], flush=True)\n"
                "srv.serve_forever()\n"
            )
            p = subprocess.Popen(
                [sys.executable, "-c", code],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            assert p.stdout is not None
            port = int(p.stdout.readline().strip())
            return p, port

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            legacy_home = tmp_dir / "legacy_home"
            pres_dir = tmp_dir / "preserved"
            runs_dir = tmp_dir / "runs"
            ev_path = tmp_dir / "evidence.json"
            for d in (
                legacy_home / ".local" / "state" / "opencode",
                legacy_home / ".local" / "share" / "opencode" / "log",
                pres_dir,
                runs_dir,
            ):
                d.mkdir(parents=True, exist_ok=True)

            aff_proc, aff_port = _spawn_http_token_listener(aff_tok)
            unrel_proc, unrel_port = _spawn_http_token_listener(unrel_tok)
            loc_proc = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            holder_proc: subprocess.Popen[str] | None = None
            try:
                # Populate legacy_home contaminated ONLY with aff_tok
                svc_file = legacy_home / ".local" / "state" / "opencode" / "service.json"
                svc_file.write_text('{"pid": 999998, "port": 59999, "password": "svc-pw-w234-abcdef"}\n', encoding="utf-8")
                db_path = legacy_home / ".local" / "share" / "opencode" / "opencode.db"
                conn = sqlite3.connect(str(db_path))
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("CREATE TABLE part (id TEXT, data TEXT)")
                conn.execute("INSERT INTO part VALUES ('p1', ?)", (f"Authorization: Bearer {aff_tok}",))
                conn.commit()
                conn.close()
                wal_path = legacy_home / ".local" / "share" / "opencode" / "opencode.db-wal"
                if not wal_path.exists():
                    wal_path.write_bytes(b"wal")
                log_path = legacy_home / ".local" / "share" / "opencode" / "log" / "opencode.log"
                log_path.write_text(f"leaked {aff_tok}\n", encoding="utf-8")
                (legacy_home / "opencode.json").write_text(
                    json.dumps(
                        {
                            "provider": {
                                "private-attested": {
                                    "options": {"baseURL": f"http://127.0.0.1:{aff_port}/v1"}
                                }
                            }
                        }
                    ),
                    encoding="utf-8",
                )

                shutil.copy2(db_path, pres_dir / "opencode.db")
                shutil.copy2(log_path, pres_dir / "opencode.log")
                shared_second = "2026-11-13T00:46:13-0500"
                ev_path.write_text(
                    json.dumps(
                        {
                            "incident_id": inc_id,
                            "target_home": str(legacy_home),
                            "target_proxy_started_at": shared_second,
                            "artifacts": {
                                str(pres_dir / "opencode.db"): hashlib.sha256(
                                    (pres_dir / "opencode.db").read_bytes()
                                ).hexdigest(),
                                str(pres_dir / "opencode.log"): hashlib.sha256(
                                    (pres_dir / "opencode.log").read_bytes()
                                ).hexdigest(),
                            },
                        }
                    ),
                    encoding="utf-8",
                )

                # Write mixed PID records: 1 affected proxy and 1 unrelated proxy started in the
                # EXACT same wall-clock second (SIR-W2), plus 1 Rung 1 local server.
                aff_tok_file = runs_dir / ".se-session-affected.token"
                aff_tok_file.write_text(aff_tok + "\n", encoding="utf-8")
                unrel_tok_file = runs_dir / ".se-session-unrelated.token"
                unrel_tok_file.write_text(unrel_tok + "\n", encoding="utf-8")

                aff_pid_file = runs_dir / ".serve.tinfoil-deepseek-v4-1-flash.pid"
                aff_pid_file.write_text(
                    json.dumps(
                        {
                            "model_id": "tinfoil-deepseek-v4-1-flash",
                            "trust_tier": "enclave_runtime_attested",
                            "pid": aff_proc.pid,
                            "pid_lstart": get_process_lstart(aff_proc.pid),
                            "port": aff_port,
                            "started_at": shared_second,
                            "session_token_file": str(aff_tok_file),
                            "status": "ready",
                        }
                    ),
                    encoding="utf-8",
                )
                unrel_pid_file = runs_dir / ".serve.tinfoil-kimi-k3-1-pro.pid"
                unrel_pid_file.write_text(
                    json.dumps(
                        {
                            "model_id": "tinfoil-kimi-k3-1-pro",
                            "trust_tier": "enclave_runtime_attested",
                            "pid": unrel_proc.pid,
                            "pid_lstart": get_process_lstart(unrel_proc.pid),
                            "port": unrel_port,
                            "started_at": shared_second,
                            "session_token_file": str(unrel_tok_file),
                            "status": "ready",
                        }
                    ),
                    encoding="utf-8",
                )
                loc_pid_file = runs_dir / ".serve.qwen3-30b-a3b-4bit.pid"
                loc_pid_file.write_text(
                    json.dumps(
                        {
                            "model_id": "qwen3-30b-a3b-4bit",
                            "trust_tier": "local",
                            "pid": loc_proc.pid,
                            "pid_lstart": get_process_lstart(loc_proc.pid),
                            "port": 18080,
                            "started_at": shared_second,
                            "status": "ready",
                        }
                    ),
                    encoding="utf-8",
                )

                st_initial = cont_mod.inspect_containment_state(
                    home_dir=legacy_home,
                    runs_dir=runs_dir,
                    evidence_path=ev_path,
                    incident_id=inc_id,
                )
                self.assertEqual(st_initial["affected_proxy_sessions"], 1)
                self.assertEqual(st_initial["unrelated_active_models"], 2)
                self.assertEqual(st_initial["ambiguous_proxy_sessions"], 0)

                # SIR-W2 timestamp-only match without token disambiguation MUST be treated as ambiguous,
                # never auto-selecting a session on whole-second started_at alone!
                ts_only_home = tmp_dir / "ts_only_home"
                (ts_only_home / ".local" / "state" / "opencode").mkdir(parents=True, exist_ok=True)
                ts_svc = ts_only_home / ".local" / "state" / "opencode" / "service.json"
                ts_svc.write_text('{"pid": 999996, "port": 59996, "password": "pw"}\n', encoding="utf-8")
                ts_ev = tmp_dir / "ts_only_ev.json"
                ts_ev.write_text(
                    json.dumps(
                        {
                            "incident_id": inc_id,
                            "target_home": str(ts_only_home),
                            "target_proxy_started_at": shared_second,
                            "artifacts": {
                                str(pres_dir / "opencode.log"): hashlib.sha256(
                                    (pres_dir / "opencode.log").read_bytes()
                                ).hexdigest(),
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                st_ts_only = cont_mod.inspect_containment_state(
                    home_dir=ts_only_home,
                    runs_dir=runs_dir,
                    evidence_path=ts_ev,
                    incident_id=inc_id,
                )
                self.assertEqual(st_ts_only["affected_proxy_sessions"], 0)
                self.assertEqual(st_ts_only["ambiguous_proxy_sessions"], 2)
                rc_ts_only, _, err_ts_only = cont_mod.apply_containment(
                    home_dir=ts_only_home,
                    runs_dir=runs_dir,
                    evidence_path=ts_ev,
                    incident_id=inc_id,
                )
                self.assertEqual(rc_ts_only, 1)
                self.assertIn("ambiguous", (err_ts_only or "").lower())
                self.assertIsNone(aff_proc.poll())
                self.assertIsNone(unrel_proc.poll())
                self.assertTrue(ts_svc.exists())

                # SIR-W2 ambiguous target refusal: unverified pid_lstart aborts before touching anything
                ambig_pid_file = runs_dir / ".serve.ambiguous.pid"
                ambig_pid_file.write_text(
                    json.dumps(
                        {
                            "model_id": "tinfoil-ambig",
                            "trust_tier": "enclave_runtime_attested",
                            "pid": aff_proc.pid,
                            "pid_lstart": "unavailable",
                            "port": aff_port + 100,
                            "session_token_file": str(aff_tok_file),
                            "status": "ready",
                        }
                    ),
                    encoding="utf-8",
                )
                rc_ambig, _, err_ambig = cont_mod.apply_containment(
                    home_dir=legacy_home,
                    runs_dir=runs_dir,
                    evidence_path=ev_path,
                    incident_id=inc_id,
                )
                self.assertEqual(rc_ambig, 1)
                self.assertIn("ambiguous", (err_ambig or "").lower())
                self.assertIsNone(aff_proc.poll())
                self.assertTrue(db_path.exists())
                ambig_pid_file.unlink()

                # SIR-W3 Case A: stop_model_fn returns False -> aborts BEFORE unlinking forensic files
                rc_stop_fail, _, err_stop_fail = cont_mod.apply_containment(
                    home_dir=legacy_home,
                    runs_dir=runs_dir,
                    evidence_path=ev_path,
                    incident_id=inc_id,
                    stop_model_fn=lambda _s: False,
                )
                self.assertEqual(rc_stop_fail, 1)
                self.assertIn("failed to stop", (err_stop_fail or "").lower())
                self.assertTrue(svc_file.exists())
                self.assertTrue(db_path.exists())
                self.assertTrue(log_path.exists())

                # SIR-W3 Case B: stop_model_fn claims True while listener STILL accepts aff_tok -> aborts!
                rc_still_auth, _, err_still_auth = cont_mod.apply_containment(
                    home_dir=legacy_home,
                    runs_dir=runs_dir,
                    evidence_path=ev_path,
                    incident_id=inc_id,
                    stop_model_fn=lambda _s: True,
                )
                self.assertEqual(rc_still_auth, 1)
                self.assertIn("still accepted", (err_still_auth or "").lower())
                self.assertTrue(svc_file.exists())
                self.assertTrue(db_path.exists())
                self.assertTrue(log_path.exists())

                # SIR-W4 Case A & B: missing lsof and failing lsof -> holder_inspection_ok False -> aborts!
                bad_lsof = tmp_dir / "failing_lsof"
                bad_lsof.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
                os.chmod(bad_lsof, 0o755)
                for lsof_cand in (tmp_dir / "missing_lsof", bad_lsof):
                    st_bad_lsof = cont_mod.inspect_containment_state(
                        home_dir=legacy_home,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id=inc_id,
                        lsof_bin=lsof_cand,
                    )
                    self.assertIs(st_bad_lsof["holder_inspection_ok"], False)
                    rc_lsof, _, _ = cont_mod.apply_containment(
                        home_dir=legacy_home,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id=inc_id,
                        lsof_bin=lsof_cand,
                        stop_model_fn=lambda _s: False,
                    )
                    self.assertEqual(rc_lsof, 1)
                    self.assertTrue(db_path.exists())

                # SIR-W4 Case C: real child process holding opencode.db open -> aborts before touching SQLite/logs/service.json!
                holder_proc = subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        f"import time; fh = open({str(db_path)!r}, 'rb'); print('HELD', flush=True); time.sleep(60)",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                assert holder_proc.stdout is not None
                self.assertEqual(holder_proc.stdout.readline().strip(), "HELD")
                st_held = cont_mod.inspect_containment_state(
                    home_dir=legacy_home,
                    runs_dir=runs_dir,
                    evidence_path=ev_path,
                    incident_id=inc_id,
                )
                self.assertIs(st_held["holder_inspection_ok"], True)
                self.assertGreaterEqual(st_held["active_opencode_holders"], 1)

                # Stop aff_proc only when real apply runs, while holder_proc still holds opencode.db:
                # Step 2 must abort BEFORE deleting service.json, opencode.db, WAL, or opencode.log!
                rc_held, _, err_held = cont_mod.apply_containment(
                    home_dir=legacy_home,
                    runs_dir=runs_dir,
                    evidence_path=ev_path,
                    incident_id=inc_id,
                )
                self.assertEqual(rc_held, 1)
                self.assertIn("hold open files", (err_held or "").lower())
                self.assertIsNotNone(aff_proc.wait(timeout=5))
                # Unrelated proxy and Rung 1 local server MUST remain untouched!
                self.assertIsNone(unrel_proc.poll())
                self.assertIsNone(loc_proc.poll())
                self.assertTrue(svc_file.exists(), "service.json must be preserved when holder check aborts!")
                self.assertTrue(db_path.exists(), "opencode.db must be preserved when holder is active!")
                self.assertTrue(wal_path.exists())
                self.assertTrue(log_path.exists())

                # Close holder_proc so we can test:
                # 1. SIR-W3 stale/missing PID record with (a) stalled/timeout listener and (b) malformed HTTP listener -> probe=unknown -> aborts!
                # 2. SIR-W4 / SIR-R2-C1 unmasked missing/failing lsof AFTER Step 1 revocation succeeds -> aborts before unlinking!
                holder_proc.terminate()
                holder_proc.wait(timeout=5)
                self.assertFalse(aff_pid_file.exists(), "aff_pid_file was removed by Step 1")

                stalled_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                stalled_srv.bind(("127.0.0.1", 0))
                stalled_srv.listen(4)
                stalled_port = int(stalled_srv.getsockname()[1])

                def _serve_stalled() -> None:
                    while True:
                        try:
                            conn, _ = stalled_srv.accept()
                        except OSError:
                            break
                        with conn:
                            time.sleep(3.2)

                threading.Thread(target=_serve_stalled, daemon=True).start()

                malformed_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                malformed_srv.bind(("127.0.0.1", 0))
                malformed_srv.listen(4)
                malformed_port = int(malformed_srv.getsockname()[1])

                def _serve_malformed() -> None:
                    while True:
                        try:
                            conn, _ = malformed_srv.accept()
                        except OSError:
                            break
                        with conn:
                            try:
                                _ = conn.recv(512)
                                conn.sendall(b"NOT_HTTP_GARBAGE\r\n\r\n")
                            except OSError:
                                pass

                threading.Thread(target=_serve_malformed, daemon=True).start()
                try:
                    for probe_case, bad_port in (("stalled_timeout", stalled_port), ("malformed_http", malformed_port)):
                        # Bind bad_port via a verified runs_dir proxy PID record (never untrusted opencode.json text, per F6).
                        rot_tok_file = runs_dir / ".se-session-rotated.token"
                        rot_tok_file.write_text("se-session-" + ("33445566" * 8) + "\n", encoding="utf-8")
                        rot_pid_file = runs_dir / ".serve.rotated-port-owner.pid"
                        rot_pid_file.write_text(
                            json.dumps(
                                {
                                    "model_id": "tinfoil-rotated-owner",
                                    "trust_tier": "enclave_runtime_attested",
                                    "pid": unrel_proc.pid,
                                    "pid_lstart": get_process_lstart(unrel_proc.pid),
                                    "port": bad_port,
                                    "session_token_file": str(rot_tok_file),
                                    "status": "ready",
                                }
                            ),
                            encoding="utf-8",
                        )
                        probe_aff_tok_file = runs_dir / ".se-session-probe-aff.token"
                        probe_aff_tok_file.write_text(aff_tok + "\n", encoding="utf-8")
                        probe_dummy = subprocess.Popen(
                            [sys.executable, "-c", "import time; print('D', flush=True); time.sleep(60)"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                        )
                        assert probe_dummy.stdout is not None
                        self.assertEqual(probe_dummy.stdout.readline().strip(), "D")
                        probe_aff_pid_file = runs_dir / ".serve.probe-aff.pid"
                        probe_aff_pid_file.write_text(
                            json.dumps(
                                {
                                    "model_id": "tinfoil-deepseek-v4-1-flash",
                                    "trust_tier": "enclave_runtime_attested",
                                    "pid": probe_dummy.pid,
                                    "pid_lstart": get_process_lstart(probe_dummy.pid),
                                    "port": bad_port,
                                    "session_token_file": str(probe_aff_tok_file),
                                    "status": "ready",
                                }
                            ),
                            encoding="utf-8",
                        )
                        try:
                            rc_unk, _, err_unk = cont_mod.apply_containment(
                                home_dir=legacy_home,
                                runs_dir=runs_dir,
                                evidence_path=ev_path,
                                incident_id=inc_id,
                            )
                            self.assertEqual(rc_unk, 1, probe_case)
                            self.assertIn("probe=unknown", (err_unk or "").lower(), probe_case)
                            self.assertTrue(svc_file.exists(), probe_case)
                            self.assertTrue(db_path.exists(), probe_case)
                            self.assertTrue(wal_path.exists(), probe_case)
                            self.assertTrue(log_path.exists(), probe_case)
                            self.assertIsNone(unrel_proc.poll(), probe_case)
                        finally:
                            if probe_dummy.poll() is None:
                                probe_dummy.kill()
                                probe_dummy.wait(timeout=5)
                            for _dp in (probe_dummy.stdout, probe_dummy.stderr):
                                if _dp is not None:
                                    _dp.close()
                            rot_pid_file.unlink(missing_ok=True)
                            rot_tok_file.unlink(missing_ok=True)
                            probe_aff_pid_file.unlink(missing_ok=True)
                            probe_aff_tok_file.unlink(missing_ok=True)
                finally:
                    stalled_srv.close()
                    malformed_srv.close()

                # Restore closed aff_port so Step 1 revocation probe positively sees ECONNREFUSED ("revoked").
                (legacy_home / "opencode.json").write_text(
                    json.dumps(
                        {
                            "provider": {
                                "private-attested": {
                                    "options": {"baseURL": f"http://127.0.0.1:{aff_port}/v1"}
                                }
                            }
                        }
                    ),
                    encoding="utf-8",
                )

                # Unmasked SIR-W4 / SIR-R2-C1 check: Step 1 revocation succeeds completely (no stop_model_fn),
                # and Step 2 missing/failing lsof aborts BEFORE unlinking service.json, opencode.db, WAL, or logs!
                with mock.patch.object(
                    cont_mod, "_list_current_uid_ps_commands", return_value=([], True), create=True
                ):
                    for lsof_cand in (tmp_dir / "missing_lsof", bad_lsof):
                        rc_unmasked, _, err_unmasked = cont_mod.apply_containment(
                            home_dir=legacy_home,
                            runs_dir=runs_dir,
                            evidence_path=ev_path,
                            incident_id=inc_id,
                            lsof_bin=lsof_cand,
                        )
                        self.assertEqual(rc_unmasked, 1)
                        self.assertIn("holder inspection failed", (err_unmasked or "").lower())
                        self.assertTrue(svc_file.exists())
                        self.assertTrue(db_path.exists())
                        self.assertTrue(wal_path.exists())
                        self.assertTrue(log_path.exists())

                    rc_ok, rep_ok, err_ok = cont_mod.apply_containment(
                        home_dir=legacy_home,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id=inc_id,
                    )
                self.assertEqual(rc_ok, 0, err_ok)
                assert rep_ok is not None
                self.assertIs(rep_ok["containment_clean"], True)
                self.assertIs(rep_ok["session_revocation_verified"], True)
                self.assertEqual(rep_ok["unrelated_active_models"], 2)
                self.assertIsNone(unrel_proc.poll(), "Unrelated attested proxy must stay running!")
                self.assertIsNone(loc_proc.poll(), "Rung 1 local model must stay running!")
                self.assertTrue(unrel_pid_file.exists())
                self.assertTrue(loc_pid_file.exists())
                self.assertFalse(svc_file.exists())
                self.assertFalse(db_path.exists())
                self.assertFalse(log_path.exists())
            finally:
                for p in (aff_proc, unrel_proc, loc_proc, holder_proc):
                    if p is not None:
                        if p.poll() is None:
                            p.kill()
                            p.wait(timeout=5)
                        for _pipe in (p.stdout, p.stderr):
                            if _pipe is not None:
                                _pipe.close()

    def test_credential_guard_plugin_delayed_mcp_registration_timeout(self) -> None:
        from local_assist.security_profile import _locate_host_node_binary

        node_bin = _locate_host_node_binary()
        if node_bin is None:
            self.skipTest("requires node binary")
        plugin_url = (ROOT / "config" / "plugins" / "credential-guard" / "server.js").resolve().as_uri()

        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "opencode.json"
            cfg_path.write_text(
                json.dumps({"mcp": {"servers": {"local_assist": {"disabled": False}}}}),
                encoding="utf-8",
            )
            script = (
                f"import mod from {json.dumps(plugin_url)};\n"
                "let promptHook = null;\n"
                "let listCalls = 0;\n"
                "const ctx = {\n"
                "  session: { hook: async (name, fn) => { if (name === 'prompt') promptHook = fn; } },\n"
                "  tool: {\n"
                "    list: async () => { listCalls += 1; return []; },\n"
                "    hook: async () => {},\n"
                "  },\n"
                "};\n"
                "await mod.setup(ctx);\n"
                "const t0 = Date.now();\n"
                "await promptHook({});\n"
                "const elapsed1 = Date.now() - t0;\n"
                "const t1 = Date.now();\n"
                "await promptHook({});\n"
                "const elapsed2 = Date.now() - t1;\n"
                "console.log(JSON.stringify({ elapsed1, elapsed2, listCalls }));\n"
            )
            env = dict(os.environ)
            env["OPENCODE_CONFIG"] = str(cfg_path)
            res = subprocess.run(
                [str(node_bin), "--input-type=module", "-e", script],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(res.returncode, 0, res.stderr + res.stdout)
            out_obj = json.loads(res.stdout.strip())
            self.assertGreaterEqual(out_obj["elapsed1"], 2400)
            self.assertLess(out_obj["elapsed1"], 4800)
            self.assertGreater(out_obj["listCalls"], 10)
            # Warned only once across repeated prompt turns when MCP remains unavailable
            self.assertEqual(
                res.stderr.count("local_assist MCP tools did not finish registering within 2500ms"),
                1,
            )

    @unittest.skipUnless(OPENCODE_BIN is not None, "requires opencode binary")
    def test_exec_pipe_fd_handoff_cleans_parent_kern_procargs2_and_closes_fd(self) -> None:
        from local_assist.registry import get_process_lstart

        env_tok = "se-session-" + ("7788" * 16)
        env_pw = "initial-env-opencode-pw-secret-999"
        seen_upstream_auth: list[str] = []
        probe_results: list[dict[str, Any]] = []
        turn_idx = 0

        class _MockPlanner(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                seen_upstream_auth.append(self.headers.get("Authorization", ""))
                body = json.dumps({"data": [{"id": "deepseek-v4-1-flash"}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                nonlocal turn_idx
                seen_upstream_auth.append(self.headers.get("Authorization", ""))
                cl = int(self.headers.get("Content-Length", "0"))
                req_json = json.loads(self.rfile.read(cl).decode("utf-8"))
                req_tools = [
                    str((t.get("function") or {}).get("name"))
                    for t in (req_json.get("tools") or [])
                    if isinstance(t, dict)
                ]
                if not req_tools:
                    _send_openai_reply(
                        self,
                        req_json=req_json,
                        turn_id=0,
                        model_name="deepseek-v4-1-flash",
                        msg_obj={"role": "assistant", "content": "Handoff title"},
                        finish_reason="stop",
                    )
                    return

                for m in req_json.get("messages") or []:
                    if m.get("role") == "tool":
                        raw_content = str(m.get("content", ""))
                        parsed_item: dict[str, Any] | None = None
                        for line in raw_content.splitlines():
                            ls = line.strip()
                            if ls.startswith("{") and "has_fd_env" in ls:
                                try:
                                    parsed_item = json.loads(ls)
                                    break
                                except Exception:
                                    pass
                        probe_results.append(parsed_item if parsed_item is not None else {"raw": raw_content})

                turn_idx += 1
                bash_tool_name = "bash" if "bash" in req_tools else "shell"
                if turn_idx == 1:
                    _send_openai_reply(
                        self,
                        req_json=req_json,
                        turn_id=turn_idx,
                        model_name="deepseek-v4-1-flash",
                        msg_obj={
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call_fd_probe",
                                    "type": "function",
                                    "function": {
                                        "name": bash_tool_name,
                                        "arguments": json.dumps(
                                            {"command": "python3 fd_probe.py", "description": "fd probe"}
                                        ),
                                    },
                                }
                            ],
                        },
                        finish_reason="tool_calls",
                    )
                else:
                    _send_openai_reply(
                        self,
                        req_json=req_json,
                        turn_id=turn_idx,
                        model_name="deepseek-v4-1-flash",
                        msg_obj={"role": "assistant", "content": "HANDOFF_OK"},
                        finish_reason="stop",
                    )

        planner_srv = _planner_server(_MockPlanner)
        planner_srv.daemon_threads = True
        planner_port = int(planner_srv.server_address[1])
        threading.Thread(target=planner_srv.serve_forever, daemon=True).start()

        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_dir = Path(tmp)
                ws_dir = tmp_dir / "ws"
                iso_home = tmp_dir / "iso_home"
                runs_dir = tmp_dir / "runs"
                ws_dir.mkdir(parents=True)
                iso_home.mkdir(parents=True)
                runs_dir.mkdir(parents=True)
                subprocess.run(["git", "init", "-q"], cwd=str(ws_dir), check=True)
                (ws_dir / "fd_probe.py").write_text(
                    "import json, os, stat\n"
                    "open_pipes = []\n"
                    "for fd in range(3, 64):\n"
                    "    try:\n"
                    "        st = os.fstat(fd)\n"
                    "        if stat.S_ISFIFO(st.st_mode):\n"
                    "            open_pipes.append(fd)\n"
                    "    except OSError:\n"
                    "        pass\n"
                    "print(json.dumps({\n"
                    "    'has_fd_env': '_FREE_INFERENCE_TOKEN_FD' in os.environ,\n"
                    "    'has_tok_env': 'LOCAL_ASSIST_SESSION_TOKEN' in os.environ,\n"
                    "    'has_pw_env': 'OPENCODE_PASSWORD' in os.environ,\n"
                    "    'open_pipes': open_pipes,\n"
                    "    'ppid': os.getppid(),\n"
                    "}))\n",
                    encoding="utf-8",
                )

                # Write PID record WITHOUT session_token_file so opencode-attested MUST rely on the
                # pipe-FD handoff from initial LOCAL_ASSIST_SESSION_TOKEN!
                pid_rec = {
                    "model_id": "tinfoil-deepseek-v4-1-flash",
                    "repo": "deepseek-v4-1-flash",
                    "port": planner_port,
                    "upstream_port": planner_port + 1000,
                    "pid": os.getpid(),
                    "pid_lstart": get_process_lstart(os.getpid()),
                    "status": "ready",
                    "max_chat_requests": 200,
                    "max_tokens_cap": 8192,
                    "max_request_bytes": 2097152,
                    "ttl_seconds": 3600,
                }
                (runs_dir / ".serve.tinfoil-deepseek-v4-1-flash.pid").write_text(
                    json.dumps(pid_rec), encoding="utf-8"
                )

                # Write a tiny wrapper that invokes scripts/opencode-attested with isolated_home & runs_dir overrides
                # ONLY via non-secret test path overrides while exercising the real scripts/opencode-attested binary entry!
                child_env = dict(os.environ)
                child_env["LOCAL_ASSIST_SESSION_TOKEN"] = env_tok
                child_env["OPENCODE_PASSWORD"] = env_pw
                child_env["OPENCODE_SERVER_PASSWORD"] = env_pw
                child_env["FREE_INFERENCE_RUNS_DIR"] = str(runs_dir)
                child_env["FREE_INFERENCE_OPENCODE_ATTESTED_HOME"] = str(iso_home)
                # Auto-allow bash inside test workspace so non-interactive opencode run executes bash tool
                proc = subprocess.Popen(
                    [
                        str(ROOT / "scripts" / "opencode-attested"),
                        "--model",
                        "tinfoil-deepseek-v4-1-flash",
                        "--port",
                        str(planner_port),
                        "--no-serve",
                        "--allow-bash",
                        "--",
                        "run",
                        "--format",
                        "json",
                        "Run handoff check",
                    ],
                    cwd=str(ws_dir),
                    env=child_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                # Poll post-exec parent KERN_PROCARGS2 while opencode-attested is live!
                sampled_parent_procargs: list[bytes] = []
                deadline = time.monotonic() + 30.0
                while proc.poll() is None and time.monotonic() < deadline:
                    raw_pa = _read_kern_procargs2(proc.pid)
                    if raw_pa and b"_FREE_INFERENCE_TOKEN_FD=" in raw_pa:
                        # Capture post-exec image procargs (after os.execve scrubbed secrets)
                        sampled_parent_procargs.append(raw_pa)
                    time.sleep(0.05)

                out, err = proc.communicate(timeout=20)
                self.assertEqual(proc.returncode, 0, f"stdout={out}\nstderr={err}")
                self.assertIn("HANDOFF_OK", out)
                self.assertTrue(
                    any(a == f"Bearer {env_tok}" for a in seen_upstream_auth),
                    f"Upstream did not receive handoff token: {seen_upstream_auth}",
                )
                self.assertTrue(sampled_parent_procargs, "Did not sample post-exec parent KERN_PROCARGS2")
                observed_handoff_fds: set[int] = set()
                for raw_pa in sampled_parent_procargs:
                    self.assertNotIn(env_tok.encode("utf-8"), raw_pa)
                    self.assertNotIn(env_pw.encode("utf-8"), raw_pa)
                    for tok_bytes in raw_pa.split(b"\x00"):
                        if tok_bytes.startswith(b"_FREE_INFERENCE_TOKEN_FD="):
                            fd_str = tok_bytes.split(b"=", 1)[1].decode("ascii", errors="ignore")
                            if fd_str.isdigit():
                                observed_handoff_fds.add(int(fd_str))
                self.assertTrue(observed_handoff_fds, "Expected _FREE_INFERENCE_TOKEN_FD=<N> in parent procargs")
                self.assertTrue(probe_results, f"Tool output not recorded: out={out}")
                self.assertIs(probe_results[0].get("has_fd_env"), False)
                self.assertIs(probe_results[0].get("has_tok_env"), False)
                self.assertIs(probe_results[0].get("has_pw_env"), False)
                child_open_pipes = set(probe_results[0].get("open_pipes") or [])
                for h_fd in observed_handoff_fds:
                    self.assertNotIn(
                        h_fd,
                        child_open_pipes,
                        f"Handoff pipe descriptor {h_fd} was not closed before child spawn!",
                    )

                # Direct unit check on _consume_handoff_token: read descriptor is closed (EBADF) immediately
                att_mod = _load_script_module("opencode_attested_fd_close", "scripts/opencode-attested")
                r_fd, w_fd = os.pipe()
                os.write(w_fd, env_tok.encode("utf-8"))
                os.close(w_fd)
                prev_fd_env = os.environ.get("_FREE_INFERENCE_TOKEN_FD")
                try:
                    os.environ["_FREE_INFERENCE_TOKEN_FD"] = str(r_fd)
                    ok_tok, val_tok, err_tok = att_mod._consume_handoff_token()
                    self.assertTrue(ok_tok, err_tok)
                    self.assertEqual(val_tok, env_tok)
                    with self.assertRaises(OSError) as ebadf_ctx:
                        os.fstat(r_fd)
                    self.assertEqual(ebadf_ctx.exception.errno, 9)  # errno.EBADF
                finally:
                    if prev_fd_env is None:
                        os.environ.pop("_FREE_INFERENCE_TOKEN_FD", None)
                    else:
                        os.environ["_FREE_INFERENCE_TOKEN_FD"] = prev_fd_env
        finally:
            planner_srv.shutdown()
            planner_srv.server_close()

    @unittest.skipUnless(OPENCODE_BIN is not None, "requires opencode binary")
    def test_real_opencode_cli_and_tui_zero_credential_custody_workflows_and_hooks(self) -> None:
        from local_assist.registry import get_process_lstart

        canary_session_tok = "se-session-" + ("c0ffee11" * 8)
        accidental_tool_tok = "se-session-" + ("facefeed" * 8)
        seen_planner_bodies: list[bytes] = []
        seen_turn1_tools: list[str] = []
        seen_tool_messages: list[str] = []
        seen_tui_tool_messages: list[str] = []
        observed_inv_dirs: list[Path] = []
        observed_service_passwords: list[str] = []
        observed_relay_tokens: list[str] = []
        turn_no = 0
        tui_turn_no = 0
        rung1_served_id = "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit"

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            ws_dir = tmp_dir / "ws"
            iso_home = tmp_dir / "iso_home"
            runs_dir = tmp_dir / "runs"
            ssh_sock_dir = tmp_dir / "ssh_agent"
            for d in (ws_dir, iso_home, runs_dir, ssh_sock_dir):
                d.mkdir(parents=True, exist_ok=True)

            # Spawn a dedicated local Rung 1 HTTP process with --model <served_id> so
            # verify-served-model listener verification AND model-backed MCP compress_context both succeed!
            rung1_log_file = tmp_dir / "rung1_requests.jsonl"
            mock_rung1_py = tmp_dir / "mock_rung1_server.py"
            mock_rung1_py.write_text(
                "import json, sys\n"
                "from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer\n"
                f"MODEL_ID = {rung1_served_id!r}\n"
                f"LOG_PATH = {str(rung1_log_file)!r}\n"
                "class H(BaseHTTPRequestHandler):\n"
                "    protocol_version = 'HTTP/1.1'\n"
                "    def log_message(self, *a): pass\n"
                "    def do_GET(self):\n"
                "        b = json.dumps({'data': [{'id': MODEL_ID}]}).encode('utf-8')\n"
                "        self.send_response(200)\n"
                "        self.send_header('Content-Type', 'application/json')\n"
                "        self.send_header('Content-Length', str(len(b)))\n"
                "        self.end_headers()\n"
                "        self.wfile.write(b)\n"
                "    def do_POST(self):\n"
                "        cl = int(self.headers.get('Content-Length', '0'))\n"
                "        req = json.loads(self.rfile.read(cl).decode('utf-8'))\n"
                "        with open(LOG_PATH, 'a', encoding='utf-8') as fh:\n"
                "            fh.write(json.dumps(req) + '\\n')\n"
                "        msgs = json.dumps(req.get('messages') or [])\n"
                "        if 'Return exactly OK.' in msgs:\n"
                "            content = 'OK'\n"
                "        else:\n"
                "            content = json.dumps({\n"
                "                'summary': 'Updated app.py VALUE from 1 to 2 for unit tests.',\n"
                "                'key_points': ['app.py sets VALUE = 2'],\n"
                "                'changed_files': ['app.py'],\n"
                "                'failures': [],\n"
                "                'risks': [],\n"
                "                'commands': [],\n"
                "                'followups': [],\n"
                "                'omitted': [],\n"
                "            })\n"
                "        b = json.dumps({\n"
                "            'id': 'cmpl-r1',\n"
                "            'object': 'chat.completion',\n"
                "            'model': MODEL_ID,\n"
                "            'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': content}, 'finish_reason': 'stop'}],\n"
                "            'usage': {'prompt_tokens': 42, 'completion_tokens': 28, 'total_tokens': 70},\n"
                "        }).encode('utf-8')\n"
                "        self.send_response(200)\n"
                "        self.send_header('Content-Type', 'application/json')\n"
                "        self.send_header('Content-Length', str(len(b)))\n"
                "        self.end_headers()\n"
                "        self.wfile.write(b)\n"
                "srv = ThreadingHTTPServer(('127.0.0.1', 0), H)\n"
                "print(srv.server_address[1], flush=True)\n"
                "srv.serve_forever()\n",
                encoding="utf-8",
            )
            rung1_proc = subprocess.Popen(
                [sys.executable, str(mock_rung1_py), "--model", rung1_served_id],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            assert rung1_proc.stdout is not None
            rung1_port = int(rung1_proc.stdout.readline().strip())

            subprocess.run(["git", "init", "-q"], cwd=str(ws_dir), check=True)
            subprocess.run(["git", "config", "user.name", "test"], cwd=str(ws_dir), check=True)
            subprocess.run(["git", "config", "user.email", "test@local"], cwd=str(ws_dir), check=True)
            (ws_dir / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
            (ws_dir / "test_app.py").write_text(
                "import unittest, app\n"
                "class T(unittest.TestCase):\n"
                "    def test_v(self): self.assertEqual(app.VALUE, 2)\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "."], cwd=str(ws_dir), check=True)
            subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=str(ws_dir), check=True)

            # Start a mock SSH_AUTH_SOCK unix domain socket server
            ssh_sock_path = ssh_sock_dir / "agent.sock"
            ssh_srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            ssh_srv.bind(str(ssh_sock_path))
            ssh_srv.listen(4)

            def _serve_ssh_sock() -> None:
                while True:
                    try:
                        conn, _ = ssh_srv.accept()
                    except OSError:
                        break
                    with conn:
                        _ = conn.recv(64)
                        conn.sendall(b"SSH_AGENT_OK")

            threading.Thread(target=_serve_ssh_sock, daemon=True).start()

            tok_file = runs_dir / ".se-session-tinfoil-deepseek-v4-1-flash.token"
            tok_file.write_text(canary_session_tok + "\n", encoding="utf-8")
            os.chmod(tok_file, 0o600)

            class _MockAttestedPlanner(BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"

                def log_message(self, format: str, *args: Any) -> None:
                    return

                def do_GET(self) -> None:
                    if self.headers.get("Authorization") != f"Bearer {canary_session_tok}":
                        self.send_response(401)
                        self.end_headers()
                        return
                    body = json.dumps({"data": [{"id": "deepseek-v4-1-flash"}]}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def do_POST(self) -> None:
                    nonlocal turn_no, tui_turn_no
                    if self.headers.get("Authorization") != f"Bearer {canary_session_tok}":
                        self.send_response(401)
                        self.end_headers()
                        return
                    cl = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(cl)
                    seen_planner_bodies.append(raw_body)
                    req_json = json.loads(raw_body.decode("utf-8"))
                    req_tools = [
                        str((t.get("function") or {}).get("name"))
                        for t in (req_json.get("tools") or [])
                        if isinstance(t, dict)
                    ]
                    if not req_tools:
                        _send_openai_reply(
                            self,
                            req_json=req_json,
                            turn_id=0,
                            model_name="deepseek-v4-1-flash",
                            msg_obj={"role": "assistant", "content": "Isolation test"},
                            finish_reason="stop",
                        )
                        return

                    if b"TUI_INTERACTIVE_TURN_MARKER" in raw_body:
                        for m in req_json.get("messages") or []:
                            if m.get("role") == "tool":
                                seen_tui_tool_messages.append(str(m.get("content", "")))
                        tui_turn_no += 1
                        tui_bash = "bash" if "bash" in req_tools else "shell"
                        if tui_turn_no == 1:
                            tui_inv_str = ""
                            tui_svc_port_num = 9999
                            tui_rel_port_num = 9998
                            inv_root_tui = iso_home / ".invocations"
                            if inv_root_tui.is_dir():
                                for cand_tui in inv_root_tui.iterdir():
                                    if cand_tui.is_dir():
                                        tui_inv_str = str(cand_tui)
                                        svc_f = cand_tui / ".config" / "opencode" / "service.json"
                                        if svc_f.is_file():
                                            tui_svc_port_num = int(
                                                json.loads(svc_f.read_text(encoding="utf-8"))["port"]
                                            )
                                        oc_f = cand_tui / "opencode.json"
                                        if oc_f.is_file():
                                            r_url = (
                                                json.loads(oc_f.read_text(encoding="utf-8"))
                                                .get("provider", {})
                                                .get("private-attested", {})
                                                .get("options", {})
                                                .get("baseURL", "http://127.0.0.1:9998/v1")
                                            )
                                            tui_rel_port_num = int(r_url.split(":")[2].split("/")[0])
                                        break
                            (ws_dir / "run_probe_tui.py").write_text(
                                "import ctypes, hashlib, json, os, socket, subprocess, pathlib\n"
                                "libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib')\n"
                                "found_markers = []\n"
                                "candidate_hashes = []\n"
                                "my_pid = os.getpid()\n"
                                "pids = set([os.getppid()] + list(range(max(2, my_pid - 80), my_pid + 20)))\n"
                                "for pid in sorted(pids):\n"
                                "    mib = (ctypes.c_int * 3)(1, 49, int(pid))\n"
                                "    sz = ctypes.c_size_t(0)\n"
                                "    if libc.sysctl(mib, 3, None, ctypes.byref(sz), None, 0) != 0 or sz.value == 0:\n"
                                "        continue\n"
                                "    buf = ctypes.create_string_buffer(sz.value + 1024)\n"
                                "    sz2 = ctypes.c_size_t(len(buf))\n"
                                "    if libc.sysctl(mib, 3, buf, ctypes.byref(sz2), None, 0) != 0:\n"
                                "        continue\n"
                                "    raw = buf.raw[:sz2.value]\n"
                                "    if b'opencode' not in raw and pid != os.getppid():\n"
                                "        continue\n"
                                "    for tok in raw.split(b'\\x00'):\n"
                                "        if not tok: continue\n"
                                "        for m in (b'se-session-', b'oc-relay-', b'OPENCODE_PASSWORD=', b'OPENCODE_SERVER_PASSWORD='):\n"
                                "            if m in tok:\n"
                                "                found_markers.append(m.decode())\n"
                                "        if b'=' in tok:\n"
                                "            val = tok.split(b'=', 1)[1]\n"
                                "            candidate_hashes.append(hashlib.sha256(val).hexdigest())\n"
                                "        else:\n"
                                "            candidate_hashes.append(hashlib.sha256(tok).hexdigest())\n"
                                f"targets = [\n"
                                f"    {tui_inv_str + '/opencode.json'!r},\n"
                                f"    {tui_inv_str + '/.config/opencode/service.json'!r},\n"
                                f"    {tui_inv_str + '/.state/opencode/service.json'!r},\n"
                                f"    {str(iso_home / '.local/share/opencode/opencode.db')!r},\n"
                                f"    str(pathlib.Path({str(Path.home())!r}) / '.ssh'),\n"
                                f"    {str(ROOT / 'runs')!r},\n"
                                f"]\n"
                                "fs_blocked = {}\n"
                                "for idx, t in enumerate(targets):\n"
                                "    try:\n"
                                "        p = pathlib.Path(t)\n"
                                "        data = p.read_bytes() if not p.is_dir() else b''.join(x.name.encode() for x in p.iterdir())\n"
                                "        fs_blocked[t] = 'READ_ALLOWED'\n"
                                "        candidate_hashes.append(hashlib.sha256(data).hexdigest())\n"
                                "    except OSError as exc:\n"
                                "        fs_blocked[t] = exc.errno\n"
                                "    sym = pathlib.Path(f'sym_tui_{idx}')\n"
                                "    try:\n"
                                "        sym.unlink(missing_ok=True)\n"
                                "        sym.symlink_to(t)\n"
                                "        _ = sym.read_bytes()\n"
                                "        fs_blocked[t + ':sym'] = 'SYM_ALLOWED'\n"
                                "    except OSError as exc:\n"
                                "        fs_blocked[t + ':sym'] = exc.errno\n"
                                "    finally:\n"
                                "        sym.unlink(missing_ok=True)\n"
                                "port_blocked = {}\n"
                                f"for port in ({tui_rel_port_num}, {tui_svc_port_num}, 8081):\n"
                                "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                                "    s.settimeout(1.0)\n"
                                "    try:\n"
                                "        s.connect(('127.0.0.1', port))\n"
                                "        port_blocked[str(port)] = 'CONNECTED'\n"
                                "    except OSError as exc:\n"
                                "        port_blocked[str(port)] = exc.errno\n"
                                "    finally:\n"
                                "        s.close()\n"
                                "try:\n"
                                "    ps_rc = subprocess.run(['/bin/ps', 'aux'], capture_output=True).returncode\n"
                                "except OSError:\n"
                                "    ps_rc = -1\n"
                                "try:\n"
                                f"    oc_reexec_rc = subprocess.run([{str(Path(OPENCODE_BIN).resolve())!r}, '--version'], capture_output=True).returncode\n"
                                "except OSError:\n"
                                "    oc_reexec_rc = -1\n"
                                f"accidental = 'se-session-' + {'facefeed' * 8!r}\n"
                                "print(json.dumps({\n"
                                "    'found_markers': found_markers,\n"
                                "    'candidate_hashes': candidate_hashes,\n"
                                "    'fs_blocked': fs_blocked,\n"
                                "    'port_blocked': port_blocked,\n"
                                "    'ps_rc': ps_rc,\n"
                                "    'oc_reexec_rc': oc_reexec_rc,\n"
                                "    'accidental_echo': f'Authorization: Bearer {accidental}',\n"
                                "}))\n",
                                encoding="utf-8",
                            )
                            _send_openai_reply(
                                self,
                                req_json=req_json,
                                turn_id=98,
                                model_name="deepseek-v4-1-flash",
                                msg_obj={
                                    "role": "assistant",
                                    "content": None,
                                    "tool_calls": [
                                        {
                                            "id": "call_tui_adv_probe",
                                            "type": "function",
                                            "function": {
                                                "name": tui_bash,
                                                "arguments": json.dumps(
                                                    {
                                                        "command": "python3 run_probe_tui.py",
                                                        "description": "run tui probe",
                                                    }
                                                ),
                                            },
                                        }
                                    ],
                                },
                                finish_reason="tool_calls",
                            )
                        else:
                            _send_openai_reply(
                                self,
                                req_json=req_json,
                                turn_id=99,
                                model_name="deepseek-v4-1-flash",
                                msg_obj={"role": "assistant", "content": "TUI_TURN_COMPLETED_OK"},
                                finish_reason="stop",
                            )
                        return

                    # Snapshot active per-invocation secrets from host side so we can verify
                    # zero raw or SHA-256-derived retrieval by the sandboxed child!
                    inv_root = iso_home / ".invocations"
                    if inv_root.is_dir():
                        for cand_inv in inv_root.iterdir():
                            if cand_inv.is_dir() and cand_inv not in observed_inv_dirs:
                                observed_inv_dirs.append(cand_inv)
                                svc_cfg = cand_inv / ".config" / "opencode" / "service.json"
                                if svc_cfg.is_file():
                                    pw = json.loads(svc_cfg.read_text(encoding="utf-8"))["password"]
                                    observed_service_passwords.append(pw)
                                oc_cfg = cand_inv / "opencode.json"
                                if oc_cfg.is_file():
                                    rtok = json.loads(oc_cfg.read_text(encoding="utf-8"))[
                                        "provider"
                                    ]["private-attested"]["options"]["apiKey"]
                                    observed_relay_tokens.append(rtok)

                    for m in req_json.get("messages") or []:
                        if m.get("role") == "tool":
                            seen_tool_messages.append(str(m.get("content", "")))

                    turn_no += 1
                    bash_tool = "bash" if "bash" in req_tools else "shell"
                    if turn_no == 1:
                        seen_turn1_tools.extend(req_tools)
                        # Turn 1: call MCP assist_status, MCP check_eval_assertion (Node inside Seatbelt!),
                        # model-backed MCP compress_context (loopback to Rung 1!), edit app.py, and
                        # trigger execute.before block on .se-session-
                        _send_openai_reply(
                            self,
                            req_json=req_json,
                            turn_id=turn_no,
                            model_name="deepseek-v4-1-flash",
                            msg_obj={
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [
                                    {
                                        "id": "call_status",
                                        "type": "function",
                                        "function": {
                                            "name": "local_assist_assist_status",
                                            "arguments": "{}",
                                        },
                                    },
                                    {
                                        "id": "call_assert",
                                        "type": "function",
                                        "function": {
                                            "name": "local_assist_check_eval_assertion",
                                            "arguments": json.dumps(
                                                {
                                                    "assertion": {
                                                        "type": "javascript",
                                                        "value": "output.trim() === '42'",
                                                    },
                                                    "passing_outputs": ["42"],
                                                    "failing_outputs": ["41"],
                                                }
                                            ),
                                        },
                                    },
                                    {
                                        "id": "call_compress",
                                        "type": "function",
                                        "function": {
                                            "name": "local_assist_compress_context",
                                            "arguments": json.dumps(
                                                {
                                                    "kind": "diff",
                                                    "text": "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-VALUE = 1\n+VALUE = 2\n",
                                                    "focus": "value change",
                                                }
                                            ),
                                        },
                                    },
                                    {
                                        "id": "call_edit",
                                        "type": "function",
                                        "function": {
                                            "name": "write",
                                            "arguments": json.dumps(
                                                {
                                                    "path": "app.py",
                                                    "content": "VALUE = 2\n",
                                                }
                                            ),
                                        },
                                    },
                                    {
                                        "id": "call_blocked_before",
                                        "type": "function",
                                        "function": {
                                            "name": bash_tool,
                                            "arguments": json.dumps(
                                                {
                                                    "command": "cat .se-session-probe.token",
                                                    "description": "blocked probe",
                                                }
                                            ),
                                        },
                                    },
                                ],
                            },
                            finish_reason="tool_calls",
                        )
                    elif turn_no == 2:
                        inv_dir_str = str(observed_inv_dirs[0]) if observed_inv_dirs else ""
                        svc_cfg_obj = (
                            json.loads(
                                (
                                    observed_inv_dirs[0] / ".config" / "opencode" / "service.json"
                                ).read_text(encoding="utf-8")
                            )
                            if observed_inv_dirs
                            else {"port": 9999}
                        )
                        oc_cfg_obj = (
                            json.loads((observed_inv_dirs[0] / "opencode.json").read_text(encoding="utf-8"))
                            if observed_inv_dirs
                            else {}
                        )
                        relay_url_str = (
                            oc_cfg_obj.get("provider", {})
                            .get("private-attested", {})
                            .get("options", {})
                            .get("baseURL", "http://127.0.0.1:9998/v1")
                        )
                        relay_port_num = int(relay_url_str.split(":")[2].split("/")[0])
                        service_port_num = int(svc_cfg_obj["port"])

                        # Adversarial child probe: KERN_PROCARGS2 across nearby PIDs + file/symlink EPERM +
                        # loopback port EPERM + SSH_AUTH_SOCK ok while ~/.ssh EPERM + git diff + unit test +
                        # accidental token emission to verify execute.after pre-DB/pre-planner redaction!
                        probe_py = ws_dir / "run_probe.py"
                        probe_py.write_text(
                            "import ctypes, errno, hashlib, json, os, socket, subprocess, pathlib\n"
                            "libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib')\n"
                            "found_markers = []\n"
                            "candidate_hashes = []\n"
                            "my_pid = os.getpid()\n"
                            "pids = set([os.getppid()] + list(range(max(2, my_pid - 80), my_pid + 20)))\n"
                            "for pid in sorted(pids):\n"
                            "    mib = (ctypes.c_int * 3)(1, 49, int(pid))\n"
                            "    sz = ctypes.c_size_t(0)\n"
                            "    if libc.sysctl(mib, 3, None, ctypes.byref(sz), None, 0) != 0 or sz.value == 0:\n"
                            "        continue\n"
                            "    buf = ctypes.create_string_buffer(sz.value + 1024)\n"
                            "    sz2 = ctypes.c_size_t(len(buf))\n"
                            "    if libc.sysctl(mib, 3, buf, ctypes.byref(sz2), None, 0) != 0:\n"
                            "        continue\n"
                            "    raw = buf.raw[:sz2.value]\n"
                            "    if b'opencode' not in raw and pid != os.getppid():\n"
                            "        continue\n"
                            "    for tok in raw.split(b'\\x00'):\n"
                            "        if not tok: continue\n"
                            "        for m in (b'se-session-', b'oc-relay-', b'OPENCODE_PASSWORD=', b'OPENCODE_SERVER_PASSWORD='):\n"
                            "            if m in tok:\n"
                            "                found_markers.append(m.decode())\n"
                            "        if b'=' in tok:\n"
                            "            val = tok.split(b'=', 1)[1]\n"
                            "            candidate_hashes.append(hashlib.sha256(val).hexdigest())\n"
                            "        else:\n"
                            "            candidate_hashes.append(hashlib.sha256(tok).hexdigest())\n"
                            f"targets = [\n"
                            f"    {inv_dir_str + '/opencode.json'!r},\n"
                            f"    {inv_dir_str + '/.config/opencode/service.json'!r},\n"
                            f"    {inv_dir_str + '/.state/opencode/service.json'!r},\n"
                            f"    {str(iso_home / '.local/share/opencode/opencode.db')!r},\n"
                            f"    str(pathlib.Path({str(Path.home())!r}) / '.ssh'),\n"
                            f"    {str(ROOT / 'runs')!r},\n"
                            f"]\n"
                            "fs_Blocked = {}\n"
                            "for idx, t in enumerate(targets):\n"
                            "    try:\n"
                            "        p = pathlib.Path(t)\n"
                            "        data = p.read_bytes() if not p.is_dir() else b''.join(x.name.encode() for x in p.iterdir())\n"
                            "        fs_Blocked[t] = 'READ_ALLOWED'\n"
                            "        candidate_hashes.append(hashlib.sha256(data).hexdigest())\n"
                            "    except OSError as exc:\n"
                            "        fs_Blocked[t] = exc.errno\n"
                            "    sym = pathlib.Path(f'sym_{idx}')\n"
                            "    try:\n"
                            "        sym.unlink(missing_ok=True)\n"
                            "        sym.symlink_to(t)\n"
                            "        _ = sym.read_bytes()\n"
                            "        fs_Blocked[t + ':sym'] = 'SYM_ALLOWED'\n"
                            "    except OSError as exc:\n"
                            "        fs_Blocked[t + ':sym'] = exc.errno\n"
                            "    finally:\n"
                            "        sym.unlink(missing_ok=True)\n"
                            "port_Blocked = {}\n"
                            f"for port in ({relay_port_num}, {service_port_num}, 8081):\n"
                            "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                            "    s.settimeout(1.0)\n"
                            "    try:\n"
                            "        s.connect(('127.0.0.1', port))\n"
                            "        port_Blocked[str(port)] = 'CONNECTED'\n"
                            "    except OSError as exc:\n"
                            "        port_Blocked[str(port)] = exc.errno\n"
                            "    finally:\n"
                            "        s.close()\n"
                            "try:\n"
                            "    ps_rc = subprocess.run(['/bin/ps', 'aux'], capture_output=True).returncode\n"
                            "except OSError:\n"
                            "    ps_rc = -1\n"
                            "try:\n"
                            f"    oc_reexec_rc = subprocess.run([{str(Path(OPENCODE_BIN).resolve())!r}, '--version'], capture_output=True).returncode\n"
                            "except OSError:\n"
                            "    oc_reexec_rc = -1\n"
                            "ssh_ok = False\n"
                            "sock_p = os.environ.get('SSH_AUTH_SOCK', '')\n"
                            "if sock_p:\n"
                            "    us = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
                            "    us.connect(sock_p)\n"
                            "    us.sendall(b'ping')\n"
                            "    ssh_ok = (us.recv(32) == b'SSH_AGENT_OK')\n"
                            "    us.close()\n"
                            "git_diff = subprocess.run(['git', 'diff', '--name-only'], capture_output=True, text=True).stdout.strip()\n"
                            "ut_rc = subprocess.run(['python3', '-m', 'unittest', 'test_app'], capture_output=True).returncode\n"
                            f"accidental = 'se-session-' + {'facefeed' * 8!r}\n"
                            "print(json.dumps({\n"
                            "    'found_markers': found_markers,\n"
                            "    'candidate_hashes': candidate_hashes,\n"
                            "    'fs_blocked': fs_Blocked,\n"
                            "    'port_blocked': port_Blocked,\n"
                            "    'ps_rc': ps_rc,\n"
                            "    'oc_reexec_rc': oc_reexec_rc,\n"
                            "    'ssh_ok': ssh_ok,\n"
                            "    'git_diff': git_diff,\n"
                            "    'ut_rc': ut_rc,\n"
                            "    'accidental_echo': f'Authorization: Bearer {accidental}',\n"
                            "}))\n",
                            encoding="utf-8",
                        )
                        _send_openai_reply(
                            self,
                            req_json=req_json,
                            turn_id=turn_no,
                            model_name="deepseek-v4-1-flash",
                            msg_obj={
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [
                                    {
                                        "id": "call_adv_probe",
                                        "type": "function",
                                        "function": {
                                            "name": bash_tool,
                                            "arguments": json.dumps(
                                                {
                                                    "command": "python3 run_probe.py",
                                                    "description": "run probe",
                                                }
                                            ),
                                        },
                                    }
                                ],
                            },
                            finish_reason="tool_calls",
                        )
                    else:
                        _send_openai_reply(
                            self,
                            req_json=req_json,
                            turn_id=turn_no,
                            model_name="deepseek-v4-1-flash",
                            msg_obj={"role": "assistant", "content": "ALL_GATES_VERIFIED"},
                            finish_reason="stop",
                        )

            planner_srv = _planner_server(_MockAttestedPlanner)
            planner_srv.daemon_threads = True
            planner_port = int(planner_srv.server_address[1])
            threading.Thread(target=planner_srv.serve_forever, daemon=True).start()

            try:
                pid_rec = {
                    "model_id": "tinfoil-deepseek-v4-1-flash",
                    "repo": "deepseek-v4-1-flash",
                    "port": planner_port,
                    "upstream_port": planner_port + 1000,
                    "pid": os.getpid(),
                    "pid_lstart": get_process_lstart(os.getpid()),
                    "status": "ready",
                    "session_token_file": str(tok_file),
                    "max_chat_requests": 200,
                    "max_tokens_cap": 8192,
                    "max_request_bytes": 2097152,
                    "ttl_seconds": 3600,
                }
                (runs_dir / ".serve.tinfoil-deepseek-v4-1-flash.pid").write_text(
                    json.dumps(pid_rec), encoding="utf-8"
                )
                rung1_pid_rec = {
                    "model_id": "qwen3-30b-a3b-2507-mlx-4bit",
                    "repo": rung1_served_id,
                    "trust_tier": "local",
                    "port": rung1_port,
                    "pid": rung1_proc.pid,
                    "pid_lstart": get_process_lstart(rung1_proc.pid),
                    "status": "ready",
                    "hf_offline": True,
                }
                (runs_dir / ".serve.qwen3-30b-a3b-2507-mlx-4bit.pid").write_text(
                    json.dumps(rung1_pid_rec), encoding="utf-8"
                )

                run_env = dict(os.environ)
                run_env["SSH_AUTH_SOCK"] = str(ssh_sock_path)
                run_env["FREE_INFERENCE_RUNS_DIR"] = str(runs_dir)
                run_env["FREE_INFERENCE_OPENCODE_ATTESTED_HOME"] = str(iso_home)
                run_env["FREE_INFERENCE_LOCAL_ASSIST_BASE_URL"] = f"http://127.0.0.1:{rung1_port}/v1"

                # Part A: Full multi-turn CLI run
                proc = subprocess.run(
                    [
                        str(ROOT / "scripts" / "opencode-attested"),
                        "--model",
                        "tinfoil-deepseek-v4-1-flash",
                        "--port",
                        str(planner_port),
                        "--no-serve",
                        "--allow-edit",
                        "--allow-bash",
                        "--",
                        "run",
                        "--format",
                        "json",
                        "Verify isolation",
                    ],
                    cwd=str(ws_dir),
                    env=run_env,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0, f"stdout={proc.stdout}\nstderr={proc.stderr}")
                self.assertIn("ALL_GATES_VERIFIED", proc.stdout)

                # Gate 5: Turn-1 MCP tool schemas deterministically delivered
                for expected_mcp in (
                    "local_assist_assist_status",
                    "local_assist_check_eval_assertion",
                    "local_assist_select_context",
                    "local_assist_compress_context",
                    "local_assist_extract_fields",
                    "local_assist_delegate_task",
                    "local_assist_propose_eval_prompts",
                ):
                    self.assertIn(expected_mcp, seen_turn1_tools)

                joined_tools = "\n".join(seen_tool_messages)
                # MCP check_eval_assertion ran Node inside Seatbelt without nested sandbox-exec failure!
                self.assertIn('"passed": true', joined_tools)
                # Model-backed MCP compress_context executed against Rung 1 inside Seatbelt!
                self.assertIn("Updated app.py VALUE from 1 to 2", joined_tools)
                self.assertTrue(rung1_log_file.is_file(), "Expected Rung 1 POST requests from compress_context")
                rung1_posts = [
                    json.loads(line)
                    for line in rung1_log_file.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                self.assertGreaterEqual(len(rung1_posts), 2)  # smoke + compress_context
                # execute.before blocked .se-session- command before child spawn!
                self.assertIn("credential-guard", joined_tools.lower())
                # execute.after scrubbed accidental se-session-* before planner & DB persistence!
                self.assertIn("[REDACTED_CREDENTIAL]", joined_tools)
                self.assertNotIn(accidental_tool_tok, joined_tools)

                # Parse adversarial probe JSON output from seen_tool_messages
                probe_json: dict[str, Any] | None = None
                for msg_txt in seen_tool_messages:
                    for line in msg_txt.splitlines():
                        line_s = line.strip()
                        if line_s.startswith("{") and "candidate_hashes" in line_s:
                            probe_json = json.loads(line_s)
                            break
                self.assertIsNotNone(probe_json, f"Missing probe JSON in {seen_tool_messages}")
                assert probe_json is not None

                # SIR1: Zero secret markers in KERN_PROCARGS2 and zero SHA-256 hash matches!
                self.assertEqual(probe_json["found_markers"], [])
                self.assertTrue(observed_service_passwords)
                self.assertTrue(observed_relay_tokens)
                real_secret_hashes = {
                    hashlib.sha256(s.encode("utf-8")).hexdigest()
                    for s in (
                        canary_session_tok,
                        *observed_service_passwords,
                        *observed_relay_tokens,
                    )
                }
                self.assertEqual(
                    real_secret_hashes.intersection(set(probe_json["candidate_hashes"])),
                    set(),
                    "Child probe derived SHA-256 of a real credential!",
                )
                for k, v in probe_json["fs_blocked"].items():
                    self.assertNotIn(v, ("READ_ALLOWED", "SYM_ALLOWED"), f"Unexpected read {k}: {v}")
                for k, v in probe_json["port_blocked"].items():
                    self.assertNotEqual(v, "CONNECTED", f"Unexpected port connect {k}: {v}")
                self.assertNotEqual(probe_json["ps_rc"], 0)
                self.assertNotEqual(probe_json["oc_reexec_rc"], 0)
                self.assertIs(probe_json["ssh_ok"], True)
                self.assertIn("app.py", probe_json["git_diff"])
                self.assertEqual(probe_json["ut_rc"], 0)

                # Invocation directory and private opencode serve --service were reaped on exit!
                self.assertFalse(observed_inv_dirs[0].exists())

                # Gate 2: Zero-canary sink & encoding audit across iso_home + planner bodies + negative control
                planner_dump = tmp_dir / "planner_bodies.bin"
                planner_dump.write_bytes(b"\n".join(seen_planner_bodies))
                all_canaries = [
                    canary_session_tok,
                    accidental_tool_tok,
                    *observed_service_passwords,
                    *observed_relay_tokens,
                ]
                hits = _scan_sinks_for_secrets([iso_home, planner_dump], all_canaries)
                self.assertEqual(hits, [], f"Secret canary leaked to sink: {hits}")

                # Negative control: deliberate base64 canary injection MUST be caught by _scan_sinks_for_secrets
                neg_file = tmp_dir / "negative_control.log"
                neg_file.write_text(
                    base64.b64encode(canary_session_tok.encode("utf-8")).decode("ascii"),
                    encoding="utf-8",
                )
                self.assertGreater(len(_scan_sinks_for_secrets([neg_file], all_canaries)), 0)

                # Part B (SIR1 & SIR-R2-C1): Real interactive TUI over a PTY (`opencode` with no `run` subcommand)
                # dispatching a model-directed adversarial probe turn ("TUI_INTERACTIVE_TURN_MARKER") and
                # proving rotated HTTP Basic-auth enforcement on OpenCode's control server!
                m_fd, s_fd = pty.openpty()
                tui_proc = subprocess.Popen(
                    [
                        str(ROOT / "scripts" / "opencode-attested"),
                        "--model",
                        "tinfoil-deepseek-v4-1-flash",
                        "--port",
                        str(planner_port),
                        "--no-serve",
                        "--allow-bash",
                        "--",
                        "--prompt",
                        "TUI_INTERACTIVE_TURN_MARKER",
                    ],
                    cwd=str(ws_dir),
                    env=run_env,
                    stdin=s_fd,
                    stdout=s_fd,
                    stderr=s_fd,
                    close_fds=True,
                )
                os.close(s_fd)
                tui_service_pid: int | None = None
                tui_service_port: int | None = None
                tui_inv_dir: Path | None = None
                tui_pw: str | None = None
                tui_relay_tok: str | None = None
                try:
                    # Drain PTY output in background thread and reply to terminal CPR/OSC queries if emitted
                    def _drain_pty() -> None:
                        while True:
                            try:
                                data = os.read(m_fd, 4096)
                                if not data:
                                    break
                                if b"\x1b[6n" in data:
                                    try:
                                        os.write(m_fd, b"\x1b[1;1R")
                                    except OSError:
                                        pass
                            except OSError:
                                break

                    threading.Thread(target=_drain_pty, daemon=True).start()

                    # Wait until opencode serve --service writes <inv_dir>/.state/opencode/service.json
                    deadline_tui = time.monotonic() + 25.0
                    while time.monotonic() < deadline_tui and tui_proc.poll() is None:
                        inv_parent = iso_home / ".invocations"
                        if inv_parent.is_dir():
                            for cand in inv_parent.iterdir():
                                st_svc = cand / ".state" / "opencode" / "service.json"
                                cfg_svc = cand / ".config" / "opencode" / "service.json"
                                oc_cfg = cand / "opencode.json"
                                if st_svc.is_file() and cfg_svc.is_file() and oc_cfg.is_file():
                                    try:
                                        st_data = json.loads(st_svc.read_text(encoding="utf-8"))
                                        cfg_data = json.loads(cfg_svc.read_text(encoding="utf-8"))
                                        oc_data = json.loads(oc_cfg.read_text(encoding="utf-8"))
                                        if isinstance(st_data.get("pid"), int):
                                            tui_service_pid = int(st_data["pid"])
                                            tui_service_port = int(cfg_data["port"])
                                            tui_inv_dir = cand
                                            tui_pw = str(cfg_data["password"])
                                            tui_relay_tok = str(
                                                oc_data["provider"]["private-attested"]["options"]["apiKey"]
                                            )
                                            break
                                    except Exception:
                                        pass
                        if tui_service_pid is not None:
                            break
                        time.sleep(0.1)

                    self.assertIsNotNone(
                        tui_service_pid, "TUI did not spawn per-invocation opencode serve --service"
                    )
                    assert tui_service_pid is not None
                    assert tui_service_port is not None
                    assert tui_inv_dir is not None
                    assert tui_pw is not None
                    assert tui_relay_tok is not None

                    # Per-invocation control password and relay token MUST rotate across invocations!
                    self.assertNotIn(tui_pw, observed_service_passwords)
                    self.assertNotIn(tui_relay_tok, observed_relay_tokens)

                    # SIR-R2-C1: Prove over real HTTP that OpenCode's live control server rejects
                    # unauthenticated requests, the prior CLI invocation's rotated password, and
                    # wrong credential classes (proxy session token & relay token), while accepting tui_pw!
                    def _probe_control_http(auth_header: str | None) -> int:
                        assert tui_service_port is not None
                        c = http.client.HTTPConnection("127.0.0.1", tui_service_port, timeout=5.0)
                        try:
                            hdrs = {"Connection": "close"}
                            if auth_header is not None:
                                hdrs["Authorization"] = auth_header
                            c.request("GET", "/api/info", headers=hdrs)
                            resp = c.getresponse()
                            _ = resp.read()
                            return int(resp.status)
                        finally:
                            c.close()

                    prior_cli_basic = "Basic " + base64.b64encode(
                        f"opencode:{observed_service_passwords[0]}".encode("utf-8")
                    ).decode("ascii")
                    relay_basic = "Basic " + base64.b64encode(
                        f"opencode:{tui_relay_tok}".encode("utf-8")
                    ).decode("ascii")
                    current_tui_basic = "Basic " + base64.b64encode(
                        f"opencode:{tui_pw}".encode("utf-8")
                    ).decode("ascii")
                    self.assertEqual(_probe_control_http(None), 401)
                    self.assertEqual(_probe_control_http(prior_cli_basic), 401)
                    self.assertEqual(_probe_control_http(f"Bearer {canary_session_tok}"), 401)
                    self.assertEqual(_probe_control_http(f"Bearer {tui_relay_tok}"), 401)
                    self.assertEqual(_probe_control_http(relay_basic), 401)
                    self.assertEqual(_probe_control_http(current_tui_basic), 200)

                    # Wait for the interactive TUI to submit its prompt turn AND execute the
                    # model-directed adversarial bash tool probe (sending Enter over PTY if needed).
                    sent_enter = False
                    turn_deadline = time.monotonic() + 28.0
                    while time.monotonic() < turn_deadline and tui_proc.poll() is None:
                        if seen_tui_tool_messages:
                            break
                        if (
                            not sent_enter
                            and not any(b"TUI_INTERACTIVE_TURN_MARKER" in b for b in seen_planner_bodies)
                            and (time.monotonic() + 26.0) >= turn_deadline
                        ):
                            try:
                                os.write(m_fd, b"\r")
                                sent_enter = True
                            except OSError:
                                pass
                        time.sleep(0.15)

                    self.assertTrue(
                        any(b"TUI_INTERACTIVE_TURN_MARKER" in b for b in seen_planner_bodies),
                        "Interactive PTY TUI did not submit a model-driven prompt turn!",
                    )
                    self.assertTrue(
                        seen_tui_tool_messages,
                        "Interactive PTY TUI did not dispatch the model-directed adversarial bash probe!",
                    )
                    joined_tui_tools = "\n".join(seen_tui_tool_messages)
                    self.assertIn("[REDACTED_CREDENTIAL]", joined_tui_tools)
                    self.assertNotIn(accidental_tool_tok, joined_tui_tools)

                    tui_probe_json: dict[str, Any] | None = None
                    for msg_txt in seen_tui_tool_messages:
                        for line in msg_txt.splitlines():
                            line_s = line.strip()
                            if line_s.startswith("{") and "candidate_hashes" in line_s:
                                tui_probe_json = json.loads(line_s)
                                break
                    self.assertIsNotNone(
                        tui_probe_json, f"Missing TUI probe JSON in {seen_tui_tool_messages}"
                    )
                    assert tui_probe_json is not None
                    self.assertEqual(tui_probe_json["found_markers"], [])
                    tui_secret_hashes = {
                        hashlib.sha256(s.encode("utf-8")).hexdigest()
                        for s in (
                            canary_session_tok,
                            tui_pw,
                            tui_relay_tok,
                            *observed_service_passwords,
                            *observed_relay_tokens,
                        )
                    }
                    self.assertEqual(
                        tui_secret_hashes.intersection(set(tui_probe_json["candidate_hashes"])),
                        set(),
                        "TUI child probe derived SHA-256 of a real credential!",
                    )
                    for k, v in tui_probe_json["fs_blocked"].items():
                        self.assertNotIn(v, ("READ_ALLOWED", "SYM_ALLOWED"), f"Unexpected TUI read {k}: {v}")
                    for k, v in tui_probe_json["port_blocked"].items():
                        self.assertNotEqual(v, "CONNECTED", f"Unexpected TUI port connect {k}: {v}")
                    self.assertNotEqual(tui_probe_json["ps_rc"], 0)
                    self.assertNotEqual(tui_probe_json["oc_reexec_rc"], 0)

                    # Inspect KERN_PROCARGS2 of TUI launcher and service daemon:
                    # ZERO occurrences of tui_pw, canary_session_tok, or OPENCODE_PASSWORD!
                    for check_pid in (tui_proc.pid, tui_service_pid):
                        pa = _read_kern_procargs2(check_pid)
                        self.assertTrue(pa, f"Expected KERN_PROCARGS2 for pid {check_pid}")
                        self.assertNotIn(tui_pw.encode("utf-8"), pa)
                        self.assertNotIn(canary_session_tok.encode("utf-8"), pa)
                        self.assertNotIn(b"OPENCODE_PASSWORD=", pa)

                    # Verify a child shell under interactive.sb gets EPERM reading TUI service.json
                    sb_probe = subprocess.run(
                        [
                            str(SANDBOX_EXEC_BIN),
                            "-f",
                            str(tui_inv_dir / "interactive.sb"),
                            "/bin/cat",
                            str(tui_inv_dir / ".state" / "opencode" / "service.json"),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    self.assertNotEqual(sb_probe.returncode, 0)
                    self.assertNotIn(tui_pw, sb_probe.stdout + sb_probe.stderr)
                finally:
                    if tui_proc.poll() is None:
                        tui_proc.send_signal(signal.SIGTERM)
                        try:
                            tui_proc.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            tui_proc.kill()
                            tui_proc.wait(timeout=5)
                    try:
                        os.close(m_fd)
                    except OSError:
                        pass

                # Confirm TUI teardown reaped opencode serve --service and removed tui_inv_dir
                if tui_inv_dir is not None:
                    self.assertFalse(tui_inv_dir.exists())
                if tui_service_pid is not None:
                    deadline_reap = time.monotonic() + 5.0
                    while time.monotonic() < deadline_reap:
                        try:
                            os.kill(tui_service_pid, 0)
                            time.sleep(0.05)
                        except ProcessLookupError:
                            break
                    with self.assertRaises(ProcessLookupError):
                        os.kill(tui_service_pid, 0)

                # Post-TUI sink & planner audit including rotated tui_pw and tui_relay_tok!
                planner_dump.write_bytes(b"\n".join(seen_planner_bodies))
                post_tui_hits = _scan_sinks_for_secrets(
                    [iso_home, planner_dump],
                    [*all_canaries, *( [tui_pw] if tui_pw else [] ), *( [tui_relay_tok] if tui_relay_tok else [] )],
                )
                self.assertEqual(post_tui_hits, [], f"Post-TUI canary leaked to sink: {post_tui_hits}")
            finally:
                ssh_srv.close()
                planner_srv.shutdown()
                planner_srv.server_close()
                if rung1_proc.poll() is None:
                    rung1_proc.kill()
                    rung1_proc.wait(timeout=5)
                for _pipe in (rung1_proc.stdout, rung1_proc.stderr):
                    if _pipe is not None:
                        _pipe.close()

    @unittest.skipUnless(OPENCODE_BIN is not None, "requires opencode binary")
    def test_concurrent_invocations_and_continue_session_resume(self) -> None:
        from local_assist.registry import get_process_lstart

        canary_tok = "se-session-" + ("55aa" * 16)
        lock = threading.Lock()
        seen_prompts: list[str] = []

        class _MockPlanner(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                body = json.dumps({"data": [{"id": "deepseek-v4-1-flash"}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                cl = int(self.headers.get("Content-Length", "0"))
                req_json = json.loads(self.rfile.read(cl).decode("utf-8"))
                req_tools = req_json.get("tools") or []
                if not req_tools:
                    _send_openai_reply(
                        self,
                        req_json=req_json,
                        turn_id=0,
                        model_name="deepseek-v4-1-flash",
                        msg_obj={"role": "assistant", "content": "Conc"},
                        finish_reason="stop",
                    )
                    return
                msgs_blob = json.dumps(req_json.get("messages") or [])
                with lock:
                    seen_prompts.append(msgs_blob)
                reply = "CONCURRENT_DONE"
                if "TURN_ONE_MARKER_XYZ" in msgs_blob and "FOLLOWUP_MARKER_ABC" in msgs_blob:
                    reply = "RESUMED_WITH_HISTORY_OK"
                elif "TURN_ONE_MARKER_XYZ" in msgs_blob:
                    reply = "FIRST_TURN_SAVED_OK"
                _send_openai_reply(
                    self,
                    req_json=req_json,
                    turn_id=1,
                    model_name="deepseek-v4-1-flash",
                    msg_obj={"role": "assistant", "content": reply},
                    finish_reason="stop",
                )

        planner_srv = _planner_server(_MockPlanner)
        planner_srv.daemon_threads = True
        planner_port = int(planner_srv.server_address[1])
        threading.Thread(target=planner_srv.serve_forever, daemon=True).start()

        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_dir = Path(tmp)
                ws_a = tmp_dir / "ws_a"
                ws_b = tmp_dir / "ws_b"
                iso_home = tmp_dir / "iso_home"
                runs_dir = tmp_dir / "runs"
                for d in (ws_a, ws_b, iso_home, runs_dir):
                    d.mkdir(parents=True, exist_ok=True)
                subprocess.run(["git", "init", "-q"], cwd=str(ws_a), check=True)
                subprocess.run(["git", "init", "-q"], cwd=str(ws_b), check=True)

                tok_file = runs_dir / ".se-session-tinfoil-deepseek-v4-1-flash.token"
                tok_file.write_text(canary_tok + "\n", encoding="utf-8")
                os.chmod(tok_file, 0o600)
                pid_rec = {
                    "model_id": "tinfoil-deepseek-v4-1-flash",
                    "repo": "deepseek-v4-1-flash",
                    "port": planner_port,
                    "upstream_port": planner_port + 1000,
                    "pid": os.getpid(),
                    "pid_lstart": get_process_lstart(os.getpid()),
                    "status": "ready",
                    "session_token_file": str(tok_file),
                    "max_chat_requests": 200,
                    "max_tokens_cap": 8192,
                    "max_request_bytes": 2097152,
                    "ttl_seconds": 3600,
                }
                (runs_dir / ".serve.tinfoil-deepseek-v4-1-flash.pid").write_text(
                    json.dumps(pid_rec), encoding="utf-8"
                )

                env = dict(os.environ)
                env["FREE_INFERENCE_RUNS_DIR"] = str(runs_dir)
                env["FREE_INFERENCE_OPENCODE_ATTESTED_HOME"] = str(iso_home)

                # 1. Two concurrent invocations in ws_a and ws_b sharing iso_home
                cmd_base = [
                    str(ROOT / "scripts" / "opencode-attested"),
                    "--model",
                    "tinfoil-deepseek-v4-1-flash",
                    "--port",
                    str(planner_port),
                    "--no-serve",
                    "--",
                    "run",
                    "--format",
                    "json",
                ]
                p_a = subprocess.Popen(
                    [*cmd_base, "Concurrent A"],
                    cwd=str(ws_a),
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                p_b = subprocess.Popen(
                    [*cmd_base, "Concurrent B"],
                    cwd=str(ws_b),
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                out_a, err_a = p_a.communicate(timeout=45)
                out_b, err_b = p_b.communicate(timeout=45)
                self.assertEqual(p_a.returncode, 0, err_a)
                self.assertEqual(p_b.returncode, 0, err_b)
                self.assertIn("CONCURRENT_DONE", out_a)
                self.assertIn("CONCURRENT_DONE", out_b)

                # 2. Sequential --continue resumes session history in ws_a
                r1 = subprocess.run(
                    [*cmd_base, "TURN_ONE_MARKER_XYZ"],
                    cwd=str(ws_a),
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=45,
                    check=False,
                )
                self.assertEqual(r1.returncode, 0, r1.stderr)
                self.assertIn("FIRST_TURN_SAVED_OK", r1.stdout)

                r2 = subprocess.run(
                    [
                        str(ROOT / "scripts" / "opencode-attested"),
                        "--model",
                        "tinfoil-deepseek-v4-1-flash",
                        "--port",
                        str(planner_port),
                        "--no-serve",
                        "--",
                        "run",
                        "--continue",
                        "--format",
                        "json",
                        "FOLLOWUP_MARKER_ABC",
                    ],
                    cwd=str(ws_a),
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=45,
                    check=False,
                )
                self.assertEqual(r2.returncode, 0, r2.stderr)
                self.assertIn("RESUMED_WITH_HISTORY_OK", r2.stdout)

                # Zero leftover invocation directories
                inv_root = iso_home / ".invocations"
                if inv_root.is_dir():
                    self.assertEqual(list(inv_root.iterdir()), [])
        finally:
            planner_srv.shutdown()
            planner_srv.server_close()

    def test_f1_iso_p1_iso_p2_bound_service_cleanup_race_and_teardown_preservation(self) -> None:
        from unittest import mock
        from local_assist import launch as launch_mod
        from local_assist import security_profile as sp_mod

        self.assertEqual(
            getattr(launch_mod, "PID_IDENTITY_STATES", None),
            ("matched", "reused", "dead", "unavailable"),
        )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp).resolve()
            iso_home = tmp_dir / "iso_home"
            inv_root = iso_home / ".invocations"
            inv_root.mkdir(parents=True)

            # 1. Stale invocation with reused PID running an UNRELATED 'opencode' process:
            # must send ZERO signals to the reused PID and still sweep the dead invocation cleanly.
            stale_inv = inv_root / "inv-999999-aabbccdd1122"
            (stale_inv / ".state" / "opencode").mkdir(parents=True)
            (stale_inv / ".config" / "opencode").mkdir(parents=True)
            (stale_inv / "owner.json").write_text(
                json.dumps(
                    {
                        "invocation_id": stale_inv.name,
                        "pid": 999999,
                        "pid_lstart": "Mon Jan  1 00:00:00 2024",
                        "service_port": 45123,
                    }
                ),
                encoding="utf-8",
            )
            reused_pid = os.getpid()
            (stale_inv / ".state" / "opencode" / "service.json").write_text(
                json.dumps({"pid": reused_pid, "port": 45123}),
                encoding="utf-8",
            )

            sent_signals: list[tuple[int, int]] = []
            orig_kill = os.kill
            orig_run = subprocess.run

            def _spy_kill(p: int, s: int) -> None:
                if int(s) == 0:
                    orig_kill(p, 0)
                    return
                sent_signals.append((p, int(s)))

            def _fake_ps_lsof_unrelated(cmd: Any, *a: Any, **kw: Any) -> Any:
                argv = [str(x) for x in cmd]
                if argv and argv[0].endswith("/ps"):
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        stdout="/opt/homebrew/bin/opencode serve --hostname 127.0.0.1 --port 55999 OPENCODE_TEST_HOME=/other/home\n",
                        stderr="",
                    )
                if argv and "lsof" in argv[0]:
                    return subprocess.CompletedProcess(argv, 1, stdout="", stderr="")
                return orig_run(cmd, *a, **kw)

            with (
                mock.patch.object(os, "kill", side_effect=_spy_kill),
                mock.patch.object(launch_mod.subprocess, "run", side_effect=_fake_ps_lsof_unrelated),
                mock.patch.object(launch_mod, "reap_worker_processes_detailed", return_value=([], True)),
            ):
                reaped_ok = launch_mod._reap_invocation_service_and_children(
                    stale_inv, invocation_id=stale_inv.name
                )
            self.assertTrue(reaped_ok)
            self.assertEqual(sent_signals, [], "Unrelated reused opencode PID must receive zero signals")

            # 2. ISO-P1: Identity swap between initial lstart observation and post-ownership recheck
            # must refuse to write service-identity.json and send zero signals.
            race_inv = inv_root / "inv-888888-11223344aabb"
            (race_inv / ".state" / "opencode").mkdir(parents=True)
            state_svc = race_inv / ".state" / "opencode" / "service.json"
            state_svc.write_text(json.dumps({"pid": reused_pid, "port": 45124}), encoding="utf-8")
            sidecar_path = race_inv / "service-identity.json"

            lstart_seq = iter(["Mon Jan  1 00:00:01 2026", "Mon Jan  1 00:00:09 2026"])

            def _owned_ps(cmd: Any, *a: Any, **kw: Any) -> Any:
                argv = [str(x) for x in cmd]
                if argv and argv[0].endswith("/ps"):
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        stdout=f"/opt/homebrew/bin/opencode serve --port 45124 XDG_STATE_HOME={race_inv}/.state\n",
                        stderr="",
                    )
                return orig_run(cmd, *a, **kw)

            with (
                mock.patch.object(launch_mod, "get_process_lstart", side_effect=lambda _pid: next(lstart_seq)),
                mock.patch.object(launch_mod.subprocess, "run", side_effect=_owned_ps),
            ):
                bound_ok = launch_mod._try_bind_service_identity_sidecar(
                    scope_dir=race_inv,
                    state_svc_file=state_svc,
                    sidecar_path=sidecar_path,
                    scope_id=race_inv.name,
                    service_port=45124,
                )
            self.assertFalse(bound_ok)
            self.assertFalse(sidecar_path.exists())

            # Normal coherent case binds sidecar with mode 0400
            stable_lstart = "Mon Jan  1 00:00:01 2026"
            with (
                mock.patch.object(launch_mod, "get_process_lstart", return_value=stable_lstart),
                mock.patch.object(launch_mod.subprocess, "run", side_effect=_owned_ps),
            ):
                bound_ok2 = launch_mod._try_bind_service_identity_sidecar(
                    scope_dir=race_inv,
                    state_svc_file=state_svc,
                    sidecar_path=sidecar_path,
                    scope_id=race_inv.name,
                    service_port=45124,
                )
            self.assertTrue(bound_ok2)
            self.assertTrue(sidecar_path.is_file())
            self.assertEqual(sidecar_path.stat().st_mode & 0o777, 0o400)

            # 3. Malformed owner.json ({}, bad pid, missing pid_lstart) must be preserved by _sweep_dead_invocations
            for idx, bad_payload in enumerate(
                [
                    "{}",
                    json.dumps({"pid": "not-int", "pid_lstart": "Mon Jan  1 00:00:00 2025"}),
                    json.dumps({"pid": 999998}),
                    json.dumps({"pid": 999998, "pid_lstart": "unavailable"}),
                ]
            ):
                bad_inv = inv_root / f"inv-999998-bad{idx:02d}"
                bad_inv.mkdir(parents=True)
                (bad_inv / "owner.json").write_text(bad_payload, encoding="utf-8")
            launch_mod._sweep_dead_invocations(iso_home)
            for idx in range(4):
                self.assertTrue(
                    (inv_root / f"inv-999998-bad{idx:02d}").is_dir(),
                    f"Malformed owner.json case {idx} must be preserved",
                )

            # 4. ISO-P2: Worker run_worker_sandbox_lifecycle must propagate pre_teardown_hook / service
            # observation failure into preserving worker home and returning exit_code != 0 even when
            # process group and general reaper succeed!
            worker_home = tmp_dir / "worker-test-home"
            (worker_home / ".local" / "state" / "opencode").mkdir(parents=True)
            (worker_home / ".service-identity.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "id": "worker-test-home",
                        "pid": reused_pid,
                        "pid_lstart": stable_lstart,
                        "service_port": 45125,
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(sp_mod, "reap_worker_processes_detailed", return_value=([], True)):
                rc_worker, td_res = sp_mod.run_worker_sandbox_lifecycle(
                    ["/usr/bin/true"],
                    cwd=tmp_dir,
                    env={"PATH": "/usr/bin:/bin"},
                    isolated_home=worker_home,
                    worker_id="worker-test-home",
                    harvest_logs=False,
                    remove_home=True,
                    reap_processes=True,
                    pre_teardown_hook=lambda: False,
                )
            self.assertNotEqual(rc_worker, 0)
            self.assertFalse(td_res["clean"])
            self.assertFalse(td_res["removed"])
            self.assertTrue(worker_home.is_dir(), "Worker home must be preserved when service cleanup fails")
            self.assertTrue((worker_home / ".service-identity.json").is_file())

            # 5. ISO-P2: Unavailable lstart on live service PID during teardown_worker_home and
            # interactive _reap_invocation_service_and_children must preserve directories with zero signals.
            unavail_worker = tmp_dir / "worker-unavail-home"
            (unavail_worker / ".local" / "state" / "opencode").mkdir(parents=True)
            (unavail_worker / ".service-identity.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "id": "worker-unavail-home",
                        "pid": reused_pid,
                        "pid_lstart": stable_lstart,
                        "service_port": 45126,
                    }
                ),
                encoding="utf-8",
            )
            sent_signals.clear()
            with (
                mock.patch.object(os, "kill", side_effect=_spy_kill),
                mock.patch.object(launch_mod, "get_process_lstart", return_value=None),
                mock.patch.object(sp_mod, "reap_worker_processes_detailed", return_value=([], True)),
                mock.patch.object(launch_mod, "reap_worker_processes_detailed", return_value=([], True)),
            ):
                td_unavail = sp_mod.teardown_worker_home(
                    unavail_worker,
                    worker_id="worker-unavail-home",
                    remove_home=True,
                    reap_processes=True,
                )
                inv_unavail_ok = launch_mod._reap_invocation_service_and_children(
                    race_inv, invocation_id=race_inv.name
                )
            self.assertFalse(td_unavail["clean"])
            self.assertFalse(td_unavail["removed"])
            self.assertTrue(unavail_worker.is_dir())
            self.assertFalse(inv_unavail_ok)
            self.assertEqual(sent_signals, [])

    def test_f10_credential_guard_scrubs_object_keys_collisions_frozen_and_error_objects(self) -> None:
        node_bin = shutil.which("node")
        if not node_bin:
            self.skipTest("node required for credential-guard plugin test")

        plugin_js = ROOT / "config" / "plugins" / "credential-guard" / "server.js"
        script = f"""
import plugin from {json.dumps(plugin_js.as_uri())};

let afterHook = null;
const ctx = {{
  tool: {{
    hook: async (name, fn) => {{
      if (name === "execute.after") afterHook = fn;
    }}
  }}
}};
await plugin.setup(ctx);

const tok1 = "se-session-" + "11223344".repeat(4);
const tok2 = "oc-relay-" + "aabbccdd".repeat(4);
const sharedFrozen = Object.freeze({{ [tok1]: "keep-v1", safe: "ok" }});
const frozenArr = Object.freeze([sharedFrozen, sharedFrozen]);

const frozenErrDirty = new Error(`boom ${{tok1}}`, {{ cause: `cause ${{tok2}}` }});
void frozenErrDirty.stack;
frozenErrDirty[tok1] = "first";
frozenErrDirty[tok2] = "second";
Object.freeze(frozenErrDirty);

const frozenErrClean = new Error("clean message");
frozenErrClean[tok1] = "alpha";
frozenErrClean[tok2] = "beta";
Object.freeze(frozenErrClean);

const ev = {{
  result: {{
    [tok1]: "first-val",
    [tok2]: "second-val",
    "[REDACTED_CREDENTIAL]": "already-literal",
    nestedFrozen: sharedFrozen,
    nestedFrozenAlias: sharedFrozen,
    frozenArr,
    errAliases: Object.freeze([frozenErrDirty, frozenErrDirty]),
    cleanFrozenErr: frozenErrClean,
  }},
  error: frozenErrDirty,
}};
await afterHook(ev);
console.log(JSON.stringify({{
  ev,
  errIsInstance: ev.error instanceof Error,
  errMessage: ev.error.message,
  errStack: String(ev.error.stack || ""),
  errCause: String(ev.error.cause || ""),
  errSerialized: JSON.stringify(ev.error),
  sameErrRef: ev.result.errAliases[0] === ev.result.errAliases[1] && ev.result.errAliases[0] === ev.error,
  cleanErrIsInstance: ev.result.cleanFrozenErr instanceof Error,
  cleanErrMessage: ev.result.cleanFrozenErr.message,
  cleanErrSerialized: JSON.stringify(ev.result.cleanFrozenErr),
}}));
"""
        proc = subprocess.run(
            [node_bin, "--input-type=module", "-e", script],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out_str = proc.stdout.strip()
        self.assertNotIn("se-session-", out_str)
        self.assertNotIn("oc-relay-", out_str)
        outer = json.loads(out_str)
        parsed = outer["ev"]
        res_vals = sorted(v for v in parsed["result"].values() if isinstance(v, str))
        self.assertEqual(res_vals, ["already-literal", "first-val", "second-val"])
        self.assertEqual(parsed["result"]["nestedFrozen"]["[REDACTED_CREDENTIAL]"], "keep-v1")
        self.assertEqual(parsed["result"]["nestedFrozen"]["safe"], "ok")
        self.assertEqual(parsed["result"]["nestedFrozenAlias"]["[REDACTED_CREDENTIAL]"], "keep-v1")
        self.assertEqual(parsed["result"]["nestedFrozenAlias"]["safe"], "ok")
        self.assertEqual(len(parsed["result"]["frozenArr"]), 2)
        self.assertEqual(parsed["result"]["frozenArr"][0]["[REDACTED_CREDENTIAL]"], "keep-v1")
        self.assertEqual(parsed["result"]["frozenArr"][1]["[REDACTED_CREDENTIAL]"], "keep-v1")
        self.assertIs(outer["errIsInstance"], True)
        self.assertEqual(outer["errMessage"], "boom [REDACTED_CREDENTIAL]")
        self.assertEqual(outer["errCause"], "cause [REDACTED_CREDENTIAL]")
        self.assertIs(outer["sameErrRef"], True)
        err_dict = json.loads(outer["errSerialized"])
        self.assertEqual(
            err_dict,
            {"[REDACTED_CREDENTIAL]": "first", "[REDACTED_CREDENTIAL]#2": "second"},
        )
        self.assertIs(outer["cleanErrIsInstance"], True)
        self.assertEqual(outer["cleanErrMessage"], "clean message")
        self.assertEqual(
            json.loads(outer["cleanErrSerialized"]),
            {"[REDACTED_CREDENTIAL]": "alpha", "[REDACTED_CREDENTIAL]#2": "beta"},
        )

    def test_claude_b_f1_worker_relay_uses_64_hex_token_and_forwards_session_ttl(self) -> None:
        from local_assist.relay import _WorkerTokenRelay

        relay = _WorkerTokenRelay(
            upstream_base_url="http://127.0.0.1:18081/v1",
            upstream_session_token="se-session-" + ("ab12" * 16),
            ttl_seconds=120.0,
        )
        self.assertTrue(relay.relay_token.startswith("worker-relay-"))
        suffix = relay.relay_token[len("worker-relay-") :]
        self.assertEqual(len(suffix), 64)
        self.assertEqual(relay.ttl_seconds, 120.0)
        self.assertIsNotNone(relay._expires_at_mono)

    def test_f1_f11_f12_containment_service_and_proxy_pid_reuse_and_upstream_stop(self) -> None:
        from local_assist.registry import get_process_lstart

        cont_mod = _load_script_module("check_containment_f1_11_12", "scripts/check-credential-containment")
        inc_id = "ISO-001-F1-F11-F12"

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            legacy_home = tmp_dir / "legacy_home"
            other_home = tmp_dir / "other_home"
            pres_dir = tmp_dir / "preserved"
            runs_dir = tmp_dir / "runs"
            ev_path = tmp_dir / "evidence.json"
            for d in (
                legacy_home / ".local" / "state" / "opencode",
                other_home / ".local" / "state" / "opencode",
                pres_dir,
                runs_dir,
            ):
                d.mkdir(parents=True, exist_ok=True)

            native_oc_bin = _get_native_opencode_test_binary()
            unrelated_oc_proc = subprocess.Popen(
                [str(native_oc_bin), "serve", "--port", "59991"],
                env={
                    "HOME": str(other_home),
                    "OPENCODE_TEST_HOME": str(other_home),
                    "PATH": "/usr/bin:/bin",
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            owned_oc_proc = subprocess.Popen(
                [str(native_oc_bin), "serve", "--service"],
                env={
                    "HOME": str(legacy_home),
                    "OPENCODE_TEST_HOME": str(legacy_home),
                    "PATH": "/usr/bin:/bin",
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            proxy_proc = subprocess.Popen(
                [sys.executable, "-c", "import time; print('P', flush=True); time.sleep(60)"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            upstream_proc = subprocess.Popen(
                [sys.executable, "-c", "import time; print('U', flush=True); time.sleep(60)"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                assert unrelated_oc_proc.stdout is not None
                assert owned_oc_proc.stdout is not None
                assert proxy_proc.stdout is not None
                assert upstream_proc.stdout is not None
                self.assertEqual(int(unrelated_oc_proc.stdout.readline().strip()), 59991)
                owned_port = int(owned_oc_proc.stdout.readline().strip())
                self.assertEqual(proxy_proc.stdout.readline().strip(), "P")
                self.assertEqual(upstream_proc.stdout.readline().strip(), "U")

                # Preserve a synthetic non-empty snapshot outside legacy_home
                pres_marker = pres_dir / "snapshot.log"
                pres_marker.write_text("synthetic incident log\n", encoding="utf-8")
                ev_path.write_text(
                    json.dumps(
                        {
                            "incident_id": inc_id,
                            "target_home": str(legacy_home),
                            "artifacts": {
                                str(pres_marker): hashlib.sha256(pres_marker.read_bytes()).hexdigest()
                            },
                        }
                    ),
                    encoding="utf-8",
                )

                # Sub-case A (F1): service.json records reused PID of an unrelated opencode session
                svc_file = legacy_home / ".local" / "state" / "opencode" / "service.json"
                svc_file.write_text(
                    json.dumps(
                        {"pid": unrelated_oc_proc.pid, "port": 54321, "password": "pw-reused-12345678"}
                    ),
                    encoding="utf-8",
                )
                st_reused = cont_mod.inspect_containment_state(
                    home_dir=legacy_home,
                    runs_dir=runs_dir,
                    evidence_path=ev_path,
                    incident_id=inc_id,
                )
                self.assertEqual(st_reused["active_opencode_holders"], 0)

                kill_signals: list[tuple[int, int]] = []
                orig_kill = os.kill

                def _spy_kill(p: int, sig: int) -> None:
                    if int(sig) != 0:
                        kill_signals.append((int(p), int(sig)))
                    orig_kill(p, sig)

                with mock.patch("os.kill", side_effect=_spy_kill):
                    rc_reused, rep_reused, err_reused = cont_mod.apply_containment(
                        home_dir=legacy_home,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id=inc_id,
                    )
                self.assertEqual(rc_reused, 0, err_reused)
                self.assertIsNotNone(rep_reused)
                assert rep_reused is not None
                self.assertIs(rep_reused["containment_clean"], True)
                self.assertIsNone(
                    unrelated_oc_proc.poll(),
                    "Unrelated opencode process on reused PID must NOT be signaled!",
                )
                self.assertEqual(
                    [s for s in kill_signals if s[0] == unrelated_oc_proc.pid],
                    [],
                )

                # Sub-case B + C (F1 owned service + F11 reused proxy PID + F12 custom-runs upstream_pid)
                svc_file.write_text(
                    json.dumps(
                        {"pid": owned_oc_proc.pid, "port": owned_port, "password": "pw-owned-12345678"}
                    ),
                    encoding="utf-8",
                )
                owned_sidecar = legacy_home / ".service-identity.json"
                owned_sidecar.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "id": "legacy",
                            "pid": owned_oc_proc.pid,
                            "pid_lstart": get_process_lstart(owned_oc_proc.pid),
                            "service_port": owned_port,
                        }
                    ),
                    encoding="utf-8",
                )
                os.chmod(owned_sidecar, 0o400)
                # Stale PID record whose PID was reused by unrelated_oc_proc (F11: classify_pid_identity == 'reused')
                reused_pid_file = runs_dir / ".serve.reused-stale.pid"
                reused_pid_file.write_text(
                    json.dumps(
                        {
                            "model_id": "tinfoil-deepseek-v4-1-flash",
                            "trust_tier": "enclave_runtime_attested",
                            "pid": unrelated_oc_proc.pid,
                            "pid_lstart": "Mon Jan  1 00:00:00 2024",
                            "port": 59992,
                            "status": "ready",
                        }
                    ),
                    encoding="utf-8",
                )
                # Live affected proxy record with both primary pid and start-time-bound upstream_pid (F12)
                closed_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                closed_sock.bind(("127.0.0.1", 0))
                unused_proxy_port = int(closed_sock.getsockname()[1])
                closed_sock.close()

                real_tok_file = runs_dir / ".se-session-real.token"
                real_tok_file.write_text("se-session-" + ("aa11bb22" * 8) + "\n", encoding="utf-8")
                real_pid_file = runs_dir / ".serve.real-proxy.pid"
                real_pid_file.write_text(
                    json.dumps(
                        {
                            "model_id": "tinfoil-deepseek-v4-1-flash",
                            "trust_tier": "enclave_runtime_attested",
                            "pid": proxy_proc.pid,
                            "pid_lstart": get_process_lstart(proxy_proc.pid),
                            "upstream_pid": upstream_proc.pid,
                            "upstream_pid_lstart": get_process_lstart(upstream_proc.pid),
                            "port": unused_proxy_port,
                            "session_token_file": str(real_tok_file),
                            "status": "ready",
                        }
                    ),
                    encoding="utf-8",
                )

                st_f11 = cont_mod.inspect_containment_state(
                    home_dir=legacy_home,
                    runs_dir=runs_dir,
                    evidence_path=ev_path,
                    incident_id=inc_id,
                    target_model_id="tinfoil-deepseek-v4-1-flash",
                )
                self.assertEqual(st_f11["ambiguous_proxy_sessions"], 0)
                self.assertEqual(st_f11["affected_proxy_sessions"], 1)
                self.assertEqual(st_f11["active_opencode_holders"], 1)

                kill_signals.clear()
                with mock.patch("os.kill", side_effect=_spy_kill):
                    rc_full, rep_full, err_full = cont_mod.apply_containment(
                        home_dir=legacy_home,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id=inc_id,
                        target_model_id="tinfoil-deepseek-v4-1-flash",
                    )
                self.assertEqual(rc_full, 0, err_full)
                assert rep_full is not None
                self.assertIs(rep_full["containment_clean"], True)
                self.assertIsNotNone(owned_oc_proc.wait(timeout=5))
                self.assertIsNotNone(proxy_proc.wait(timeout=5))
                self.assertIsNotNone(upstream_proc.wait(timeout=5), "F12: upstream_pid must be stopped!")
                self.assertFalse(real_pid_file.exists())
                self.assertFalse(real_tok_file.exists())
                self.assertIsNone(unrelated_oc_proc.poll())
                self.assertEqual(
                    [s for s in kill_signals if s[0] == unrelated_oc_proc.pid],
                    [],
                )
            finally:
                for p in (unrelated_oc_proc, owned_oc_proc, proxy_proc, upstream_proc):
                    if p.poll() is None:
                        p.kill()
                        p.wait(timeout=5)
                    for pipe in (p.stdout, p.stderr):
                        if pipe is not None:
                            pipe.close()

    def test_f4_source_path_normalization_dirty_flag_and_protected_baselines(self) -> None:
        cont_mod = _load_script_module("check_containment_f4", "scripts/check-credential-containment")
        inc_id = "ISO-001-F4"

        real_head = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

        def _blob_sha(rel_path: str) -> str:
            blob = subprocess.run(
                ["git", "-C", str(ROOT), "cat-file", "blob", f"{real_head}:{rel_path}"],
                capture_output=True,
                check=True,
            ).stdout
            return hashlib.sha256(blob).hexdigest()

        sec_sha = _blob_sha("SECURITY.md")
        swift_sha = _blob_sha("tools/se_key_proxy/main.swift")
        readme_sha = _blob_sha("README.md")
        bad_sha = ("0" if sec_sha[0] != "0" else "1") + sec_sha[1:]
        dirty_sha_a = "a" * 64
        dirty_sha_b = "b" * 64
        dirty_sha_c = "c" * 64

        valid_event = {
            "message_id": "msg_f4_1",
            "session_sequence": 1,
            "tool_name": "bash",
            "event_label": "probe",
            "snapshot_rowid": 1,
        }

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            home_dir = tmp_dir / "home"
            runs_dir = tmp_dir / "runs"
            db_dir = home_dir / ".local" / "share" / "opencode"
            db_dir.mkdir(parents=True, exist_ok=True)
            runs_dir.mkdir(parents=True, exist_ok=True)

            db_path = db_dir / "opencode.db"
            conn = sqlite3.connect(str(db_path))
            conn.execute("CREATE TABLE session_message (id TEXT, session_id TEXT, seq INTEGER)")
            conn.execute("INSERT INTO session_message (rowid, id, session_id, seq) VALUES (1, 'msg_f4_1', 'sess_f4', 1)")
            conn.commit()
            conn.close()

            def _eval_payload(payload: dict[str, Any], name: str) -> dict[str, Any]:
                ev_file = tmp_dir / f"ev_{name}.json"
                ev_file.write_text(json.dumps(payload), encoding="utf-8")
                return cont_mod.inspect_containment_state(
                    home_dir=home_dir,
                    runs_dir=runs_dir,
                    evidence_path=ev_file,
                    incident_id=inc_id,
                )

            base_prov = {
                "tracking_id": inc_id,
                "target_home": str(home_dir),
                "lab_head": real_head,
                "session_id": "sess_f4",
                "events": [valid_event],
            }

            # 1. F4 unprefixed SECURITY.md mismatch with worktree_dirty_before_diagnosis=True MUST be rejected!
            res_unprefixed_sec = _eval_payload(
                {
                    **base_prov,
                    "worktree_dirty_before_diagnosis": True,
                    "source_sha256": {
                        "README.md": readme_sha,
                        "SECURITY.md": bad_sha,
                        "tools/se_key_proxy/main.swift": swift_sha,
                    },
                },
                "unprefixed_sec",
            )
            self.assertIs(res_unprefixed_sec["evidence_schema_valid"], True)
            self.assertIs(res_unprefixed_sec["evidence_integrity_valid"], False)

            # 2. Unprefixed tools/se_key_proxy/main.swift mismatch with worktree_dirty_before_diagnosis=True
            res_unprefixed_swift = _eval_payload(
                {
                    **base_prov,
                    "worktree_dirty_before_diagnosis": True,
                    "source_sha256": {
                        "README.md": readme_sha,
                        "lab/SECURITY.md": sec_sha,
                        "tools/se_key_proxy/main.swift": bad_sha,
                    },
                },
                "unprefixed_swift",
            )
            self.assertIs(res_unprefixed_swift["evidence_integrity_valid"], False)

            # 3. Missing required protected baseline (tools/se_key_proxy/main.swift omitted)
            res_missing_prot = _eval_payload(
                {
                    **base_prov,
                    "worktree_dirty_before_diagnosis": False,
                    "source_sha256": {
                        "SECURITY.md": sec_sha,
                        "README.md": readme_sha,
                    },
                },
                "missing_protected",
            )
            self.assertIs(res_missing_prot["evidence_integrity_valid"], False)

            # 4. Duplicate canonical alias keys ('SECURITY.md' and 'lab/SECURITY.md')
            res_dup_alias = _eval_payload(
                {
                    **base_prov,
                    "worktree_dirty_before_diagnosis": False,
                    "source_sha256": {
                        "SECURITY.md": sec_sha,
                        "lab/SECURITY.md": sec_sha,
                        "tools/se_key_proxy/main.swift": swift_sha,
                    },
                },
                "dup_alias",
            )
            self.assertIs(res_dup_alias["evidence_integrity_valid"], False)

            # 5. Non-boolean worktree_dirty_before_diagnosis ('true', 1) rejected at schema check
            for idx, bad_dirty in enumerate(("true", 1, ["dirty"])):
                res_bad_dirty = _eval_payload(
                    {
                        **base_prov,
                        "worktree_dirty_before_diagnosis": bad_dirty,
                        "source_sha256": {
                            "SECURITY.md": sec_sha,
                            "tools/se_key_proxy/main.swift": swift_sha,
                        },
                    },
                    f"bad_dirty_{idx}",
                )
                self.assertIs(res_bad_dirty["evidence_schema_valid"], False)
                self.assertIs(res_bad_dirty["evidence_integrity_valid"], False)

            # 6. Non-existent tracked path with worktree_dirty_before_diagnosis=True rejected
            res_untracked = _eval_payload(
                {
                    **base_prov,
                    "worktree_dirty_before_diagnosis": True,
                    "source_sha256": {
                        "SECURITY.md": sec_sha,
                        "tools/se_key_proxy/main.swift": swift_sha,
                        "lab/DOES_NOT_EXIST_IN_GIT.py": dirty_sha_a,
                    },
                },
                "untracked_path",
            )
            self.assertIs(res_untracked["evidence_integrity_valid"], False)

            # 7. Valid 5-file dirty-worktree receipt with clean protected baselines passes and reports dirty_unverified_sources=3
            res_valid_dirty = _eval_payload(
                {
                    **base_prov,
                    "worktree_dirty_before_diagnosis": True,
                    "source_sha256": {
                        "lab/SECURITY.md": sec_sha,
                        "lab/tools/se_key_proxy/main.swift": swift_sha,
                        "lab/README.md": dirty_sha_a,
                        "lab/models.yaml": dirty_sha_b,
                        "lab/local_assist/client.py": dirty_sha_c,
                    },
                },
                "valid_5file_dirty",
            )
            self.assertIs(res_valid_dirty["evidence_schema_valid"], True)
            self.assertIs(res_valid_dirty["evidence_integrity_valid"], True)
            self.assertEqual(res_valid_dirty["dirty_unverified_sources"], 3)

    def test_f5_unlink_failure_corrupt_sqlite_and_config_sink_reporting(self) -> None:
        cont_mod = _load_script_module("check_containment_f5", "scripts/check-credential-containment")
        inc_id = "ISO-001-F5"
        canary_relay = "oc-relay-" + ("deadbeef" * 8)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            home_dir = tmp_dir / "home"
            runs_dir = tmp_dir / "runs"
            pres_dir = tmp_dir / "preserved"
            ev_path = tmp_dir / "evidence.json"
            for d in (
                home_dir / ".configs",
                home_dir / ".local" / "share" / "opencode",
                runs_dir,
                pres_dir,
            ):
                d.mkdir(parents=True, exist_ok=True)

            stale_cfg = home_dir / ".configs" / "opencode-stale.json"
            stale_cfg.write_text(json.dumps({"token": canary_relay}), encoding="utf-8")
            pres_cfg = pres_dir / "opencode-stale.json"
            shutil.copy2(stale_cfg, pres_cfg)
            ev_path.write_text(
                json.dumps(
                    {
                        "incident_id": inc_id,
                        "target_home": str(home_dir),
                        "artifacts": {
                            str(pres_cfg): hashlib.sha256(pres_cfg.read_bytes()).hexdigest()
                        },
                    }
                ),
                encoding="utf-8",
            )

            # Sub-case A: config sink detection + forced unlink failure -> exit 1, containment_clean=False
            st_pre = cont_mod.inspect_containment_state(
                home_dir=home_dir,
                runs_dir=runs_dir,
                evidence_path=ev_path,
                incident_id=inc_id,
            )
            self.assertIs(st_pre["sink_inspection_ok"], True)
            self.assertGreaterEqual(st_pre["config_matching_files"], 1)
            self.assertGreaterEqual(st_pre["legacy_config_files_present"], 1)

            orig_unlink = Path.unlink

            def _fail_stale_unlink(self_path: Path, *args: Any, **kwargs: Any) -> None:
                if self_path.name == "opencode-stale.json":
                    raise PermissionError("simulated unlink failure")
                orig_unlink(self_path, *args, **kwargs)

            with mock.patch.object(Path, "unlink", _fail_stale_unlink):
                rc_fail, rep_fail, _ = cont_mod.apply_containment(
                    home_dir=home_dir,
                    runs_dir=runs_dir,
                    evidence_path=ev_path,
                    incident_id=inc_id,
                )
            self.assertEqual(rc_fail, 1)
            self.assertIsNotNone(rep_fail)
            assert rep_fail is not None
            self.assertIs(rep_fail["containment_clean"], False)
            self.assertGreaterEqual(rep_fail["unlink_failures"], 1)
            self.assertGreaterEqual(rep_fail["config_matching_files"], 1)
            self.assertTrue(stale_cfg.exists())

            # Sub-case B: invalid/corrupt SQLite file is NOT reported as a clean scan
            corrupt_db = home_dir / ".local" / "share" / "opencode" / "opencode.db"
            corrupt_db.write_bytes(b"NOT_A_VALID_SQLITE_DB " + canary_relay.encode("utf-8"))
            st_corrupt = cont_mod.inspect_containment_state(
                home_dir=home_dir,
                runs_dir=runs_dir,
                evidence_path=ev_path,
                incident_id=inc_id,
            )
            self.assertIs(st_corrupt["sink_inspection_ok"], False)
            rc_corrupt, _, _ = cont_mod.apply_containment(
                home_dir=home_dir,
                runs_dir=runs_dir,
                evidence_path=ev_path,
                incident_id=inc_id,
            )
            self.assertEqual(rc_corrupt, 1)
            self.assertTrue(corrupt_db.exists())

            # Sub-case C (ISO-W1): unreadable directory enumeration (.configs, log, shell/nested)
            # using real OS chmod 0o000 (not mocked Path.glob) must NOT report clean!
            if os.geteuid() != 0:
                for case_label, rel_dir, rel_file in (
                    ("unreadable_configs", Path(".configs"), Path(".configs/opencode-hidden.json")),
                    (
                        "unreadable_logs",
                        Path(".local/share/opencode/log"),
                        Path(".local/share/opencode/log/opencode.log.1"),
                    ),
                    (
                        "unreadable_spool_subdir",
                        Path(".local/share/opencode/shell/nested"),
                        Path(".local/share/opencode/shell/nested/cmd.out"),
                    ),
                    (
                        "unreadable_share_parent_metadata_denied",
                        Path(".local/share"),
                        Path(".local/share/opencode/log/opencode.log"),
                    ),
                ):
                    case_home = tmp_dir / f"home_{case_label}"
                    case_db = case_home / ".local" / "share" / "opencode" / "opencode.db"
                    case_db.parent.mkdir(parents=True, exist_ok=True)
                    conn = sqlite3.connect(str(case_db))
                    conn.execute("CREATE TABLE part (id TEXT, data TEXT)")
                    conn.execute("INSERT INTO part VALUES ('p_clean', 'benign row')")
                    conn.commit()
                    conn.close()

                    hidden_file = case_home / rel_file
                    hidden_file.parent.mkdir(parents=True, exist_ok=True)
                    hidden_file.write_text(f'{{"secret": "{canary_relay}"}}\n', encoding="utf-8")

                    case_ev = tmp_dir / f"ev_{case_label}.json"
                    case_ev.write_text(
                        json.dumps(
                            {
                                "incident_id": inc_id,
                                "target_home": str(case_home),
                                "artifacts": {
                                    str(pres_cfg): hashlib.sha256(pres_cfg.read_bytes()).hexdigest()
                                },
                            }
                        ),
                        encoding="utf-8",
                    )

                    locked_dir = case_home / rel_dir
                    os.chmod(locked_dir, 0o000)
                    try:
                        st_locked = cont_mod.inspect_containment_state(
                            home_dir=case_home,
                            runs_dir=runs_dir,
                            evidence_path=case_ev,
                            incident_id=inc_id,
                        )
                        self.assertIs(
                            st_locked["sink_inspection_ok"],
                            False,
                            f"{case_label}: unreadable directory must fail sink_inspection_ok!",
                        )
                        rc_locked, rep_locked, _ = cont_mod.apply_containment(
                            home_dir=case_home,
                            runs_dir=runs_dir,
                            evidence_path=case_ev,
                            incident_id=inc_id,
                        )
                        self.assertEqual(rc_locked, 1, case_label)
                        if rep_locked is not None:
                            self.assertIs(rep_locked["containment_clean"], False, case_label)
                    finally:
                        os.chmod(locked_dir, 0o700)
                    self.assertTrue(
                        hidden_file.exists(),
                        f"{case_label}: hidden contaminated file still exists",
                    )
                    self.assertTrue(
                        case_db.exists(),
                        f"{case_label}: forensic opencode.db must be preserved when sink scan fails!",
                    )

            # Sub-case D (ISO-W1): underlying os.scandir failure during Step 3 deletion increments
            # unlink_failures and refuses containment_clean=True!
            scandir_home = tmp_dir / "home_scandir_step3"
            scandir_cfg = scandir_home / ".configs" / "opencode-step3.json"
            scandir_cfg.parent.mkdir(parents=True, exist_ok=True)
            scandir_cfg.write_text(f'{{"secret": "{canary_relay}"}}\n', encoding="utf-8")
            scandir_ev = tmp_dir / "ev_scandir_step3.json"
            scandir_ev.write_text(
                json.dumps(
                    {
                        "incident_id": inc_id,
                        "target_home": str(scandir_home),
                        "artifacts": {
                            str(pres_cfg): hashlib.sha256(pres_cfg.read_bytes()).hexdigest()
                        },
                    }
                ),
                encoding="utf-8",
            )
            orig_scandir = os.scandir
            scandir_calls = 0

            def _fail_on_third_configs_scandir(target_p: Any) -> Any:
                nonlocal scandir_calls
                if Path(target_p).name == ".configs":
                    scandir_calls += 1
                    # 1st call: pre-apply _extract_persisted_session_tokens_in_memory
                    # 2nd call: Step 3 deletion -> raise PermissionError!
                    if scandir_calls >= 2:
                        raise PermissionError("simulated scandir failure during Step 3")
                return orig_scandir(target_p)

            with mock.patch("os.scandir", side_effect=_fail_on_third_configs_scandir):
                rc_sd, rep_sd, _ = cont_mod.apply_containment(
                    home_dir=scandir_home,
                    runs_dir=runs_dir,
                    evidence_path=scandir_ev,
                    incident_id=inc_id,
                )
            self.assertEqual(rc_sd, 1)
            self.assertIsNotNone(rep_sd)
            assert rep_sd is not None
            self.assertIs(rep_sd["containment_clean"], False)
            self.assertGreaterEqual(rep_sd["unlink_failures"], 1)
            self.assertIs(rep_sd["sink_inspection_ok"], False)
            self.assertTrue(scandir_cfg.exists())

    def test_f6_no_token_replay_to_untrusted_text_ports_and_unaccounted_proxy_refusal(self) -> None:
        cont_mod = _load_script_module("check_containment_f6", "scripts/check-credential-containment")
        inc_id = "ISO-001-F6"
        canary_tok = "se-session-" + ("cafebabe" * 8)

        spy_hits: list[bytes] = []
        spy_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        spy_srv.bind(("127.0.0.1", 0))
        spy_srv.listen(4)
        spy_port = int(spy_srv.getsockname()[1])

        def _serve_spy() -> None:
            while True:
                try:
                    conn, _ = spy_srv.accept()
                except OSError:
                    break
                with conn:
                    conn.settimeout(0.5)
                    try:
                        data = conn.recv(2048)
                    except OSError:
                        data = b""
                    spy_hits.append(data)
                    try:
                        conn.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                    except OSError:
                        pass

        threading.Thread(target=_serve_spy, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_dir = Path(tmp)
                home_dir = tmp_dir / "home"
                runs_dir = tmp_dir / "runs"
                pres_dir = tmp_dir / "preserved"
                ev_path = tmp_dir / "evidence.json"
                for d in (
                    home_dir / ".local" / "share" / "opencode" / "log",
                    runs_dir,
                    pres_dir,
                ):
                    d.mkdir(parents=True, exist_ok=True)

                db_path = home_dir / ".local" / "share" / "opencode" / "opencode.db"
                conn = sqlite3.connect(str(db_path))
                conn.execute("CREATE TABLE part (id TEXT, data TEXT)")
                conn.execute(
                    "INSERT INTO part VALUES ('p1', ?)",
                    (f"mention http://127.0.0.1:{spy_port}/v1 with {canary_tok}",),
                )
                conn.commit()
                conn.close()
                (home_dir / "opencode.json").write_text(
                    json.dumps(
                        {
                            "provider": {
                                "private-attested": {
                                    "options": {"baseURL": f"http://127.0.0.1:{spy_port}/v1"}
                                }
                            }
                        }
                    ),
                    encoding="utf-8",
                )
                shutil.copy2(db_path, pres_dir / "opencode.db")
                ev_path.write_text(
                    json.dumps(
                        {
                            "incident_id": inc_id,
                            "target_home": str(home_dir),
                            "artifacts": {
                                str(pres_dir / "opencode.db"): hashlib.sha256(
                                    (pres_dir / "opencode.db").read_bytes()
                                ).hexdigest()
                            },
                        }
                    ),
                    encoding="utf-8",
                )

                # Sub-case A (F6 + ISO-W2): live production se-key-proxy whose --session-token-file
                # points OUTSIDE custom runs_dir MUST remain unaccounted, fail closed with ZERO
                # signals and ZERO token replay, and preserve home_dir intact!
                out_of_runs_ps = [
                    (
                        42424,
                        "/opt/free-inference/bin/se-key-proxy proxy --listen-port 8081 "
                        "--session-token-file /other/checkout/runs/.se-session-prod.token",
                    ),
                    (42425, "/opt/free-inference/bin/se-key-proxy-test proxy --listen-port 18081"),
                ]
                sent_signals: list[tuple[int, int]] = []
                orig_kill = os.kill

                def _spy_kill_f6(p: int, sig: int) -> None:
                    if int(sig) != 0:
                        sent_signals.append((int(p), int(sig)))
                    orig_kill(p, sig)

                with mock.patch.object(
                    cont_mod,
                    "_list_current_uid_ps_commands",
                    return_value=(out_of_runs_ps, True),
                    create=True,
                ), mock.patch("os.kill", side_effect=_spy_kill_f6):
                    rc_unacc, _, err_unacc = cont_mod.apply_containment(
                        home_dir=home_dir,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id=inc_id,
                    )
                self.assertEqual(rc_unacc, 1)
                self.assertIn("unaccounted", (err_unacc or "").lower())
                self.assertEqual(sent_signals, [], "Must NEVER signal unrelated out-of-runs se-key-proxy!")
                self.assertEqual(spy_hits, [], "Must NEVER probe untrusted port from persisted text!")
                self.assertTrue(db_path.exists())
                self.assertTrue((home_dir / "opencode.json").exists())

                # Sub-case B: apply_containment with fake clean ps list (only test binary + python worker,
                # independent of ambient operator sessions) succeeds with ZERO connections to spy_port!
                clean_ps = [
                    (42425, "/opt/free-inference/bin/se-key-proxy-test proxy --listen-port 18081"),
                    (42426, "/usr/bin/python3 worker.py"),
                ]
                with mock.patch.object(
                    cont_mod,
                    "_list_current_uid_ps_commands",
                    return_value=(clean_ps, True),
                    create=True,
                ):
                    rc_clean, rep_clean, err_clean = cont_mod.apply_containment(
                        home_dir=home_dir,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id=inc_id,
                    )
                self.assertEqual(rc_clean, 0, err_clean)
                assert rep_clean is not None
                self.assertIs(rep_clean["containment_clean"], True)
                self.assertEqual(spy_hits, [], "Must NEVER connect or send Authorization to untrusted text port!")
        finally:
            spy_srv.close()

    def test_f7_pre_cleanup_binding_receipt_survives_apply_retry_and_clean_db(self) -> None:
        cont_mod = _load_script_module("check_containment_f7", "scripts/check-credential-containment")
        inc_id = "ISO-001-F7"
        canary_tok = "se-session-" + ("77889900" * 8)
        canary_sha = hashlib.sha256(canary_tok.encode("utf-8")).hexdigest()

        real_head = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        sec_sha = hashlib.sha256(
            subprocess.run(
                ["git", "-C", str(ROOT), "cat-file", "blob", f"{real_head}:SECURITY.md"],
                capture_output=True,
                check=True,
            ).stdout
        ).hexdigest()
        swift_sha = hashlib.sha256(
            subprocess.run(
                ["git", "-C", str(ROOT), "cat-file", "blob", f"{real_head}:tools/se_key_proxy/main.swift"],
                capture_output=True,
                check=True,
            ).stdout
        ).hexdigest()

        prov_event = {
            "message_id": "msg_f7_1",
            "session_sequence": 1,
            "tool_name": "bash",
            "event_label": "probe",
            "snapshot_rowid": 1,
        }

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            home_dir = tmp_dir / "home"
            unauth_home = tmp_dir / "unauth_home"
            runs_dir = tmp_dir / "runs"
            ev_dir = tmp_dir / "evidence_store"
            for d in (
                home_dir / ".local" / "share" / "opencode" / "log",
                unauth_home / ".local" / "share" / "opencode",
                runs_dir,
                ev_dir,
            ):
                d.mkdir(parents=True, exist_ok=True)

            def _init_db(p: Path, *, with_events: bool, with_canary: bool) -> None:
                conn = sqlite3.connect(str(p))
                conn.execute("CREATE TABLE session_message (id TEXT, session_id TEXT, seq INTEGER, body TEXT)")
                if with_events:
                    body = f"leaked {canary_tok}" if with_canary else "clean"
                    conn.execute(
                        "INSERT INTO session_message (rowid, id, session_id, seq, body) VALUES (1, 'msg_f7_1', 'sess_f7', 1, ?)",
                        (body,),
                    )
                conn.commit()
                conn.close()

            db_path = home_dir / ".local" / "share" / "opencode" / "opencode.db"
            _init_db(db_path, with_events=True, with_canary=True)
            log_path = home_dir / ".local" / "share" / "opencode" / "log" / "opencode.log"
            log_path.write_text(f"log {canary_tok}\n", encoding="utf-8")

            ev_path = ev_dir / "evidence.json"
            ev_payload = {
                "tracking_id": inc_id,
                "target_home": str(home_dir),
                "lab_head": real_head,
                "session_id": "sess_f7",
                "events": [prov_event],
                "source_sha256": {
                    "SECURITY.md": sec_sha,
                    "tools/se_key_proxy/main.swift": swift_sha,
                },
            }
            ev_path.write_text(json.dumps(ev_payload), encoding="utf-8")

            # 1. Pre-cleanup --check passes
            st_before = cont_mod.inspect_containment_state(
                home_dir=home_dir,
                runs_dir=runs_dir,
                evidence_path=ev_path,
                incident_id=inc_id,
            )
            self.assertIs(st_before["evidence_integrity_valid"], True)

            # 2. Manual deletion of opencode.db WITHOUT authorized --apply fails closed
            unauth_db = unauth_home / ".local" / "share" / "opencode" / "opencode.db"
            _init_db(unauth_db, with_events=True, with_canary=True)
            unauth_ev = ev_dir / "unauth_evidence.json"
            unauth_ev.write_text(
                json.dumps({**ev_payload, "target_home": str(unauth_home)}),
                encoding="utf-8",
            )
            unauth_db.unlink()
            st_unauth = cont_mod.inspect_containment_state(
                home_dir=unauth_home,
                runs_dir=runs_dir,
                evidence_path=unauth_ev,
                incident_id=inc_id,
            )
            self.assertIs(st_unauth["evidence_integrity_valid"], False)

            # 3. Partial unlink failure during first --apply writes value-free 0400 receipt and allows retry
            orig_unlink = Path.unlink

            def _fail_db_wal_or_marker(self_path: Path, *args: Any, **kwargs: Any) -> None:
                # Let opencode.db unlink, fail on a second file so retry exercises missing opencode.db!
                if self_path.name == "opencode-retry.json":
                    raise PermissionError("simulated partial unlink failure")
                orig_unlink(self_path, *args, **kwargs)

            retry_cfg = home_dir / ".configs" / "opencode-retry.json"
            retry_cfg.parent.mkdir(parents=True, exist_ok=True)
            retry_cfg.write_text('{"retry": true}\n', encoding="utf-8")

            with mock.patch.object(
                cont_mod, "_list_current_uid_ps_commands", return_value=([], True), create=True
            ), mock.patch.object(Path, "unlink", _fail_db_wal_or_marker):
                rc_partial, rep_partial, _ = cont_mod.apply_containment(
                    home_dir=home_dir,
                    runs_dir=runs_dir,
                    evidence_path=ev_path,
                    incident_id=inc_id,
                )
            self.assertEqual(rc_partial, 1)
            assert rep_partial is not None
            self.assertIs(rep_partial["containment_clean"], False)
            self.assertFalse(db_path.exists(), "opencode.db was deleted in partial run")

            receipts = list(ev_dir.glob(".containment-state-*.json"))
            self.assertEqual(len(receipts), 1)
            receipt_text = receipts[0].read_text(encoding="utf-8")
            self.assertEqual(receipts[0].stat().st_mode & 0o777, 0o400)
            self.assertNotIn(canary_tok, receipt_text)
            self.assertNotIn(canary_sha, receipt_text)
            self.assertEqual(json.loads(receipt_text)["state"], "in_progress")

            # Retry --apply succeeds even though opencode.db is already absent!
            with mock.patch.object(
                cont_mod, "_list_current_uid_ps_commands", return_value=([], True), create=True
            ):
                rc_retry, rep_retry, err_retry = cont_mod.apply_containment(
                    home_dir=home_dir,
                    runs_dir=runs_dir,
                    evidence_path=ev_path,
                    incident_id=inc_id,
                )
            self.assertEqual(rc_retry, 0, err_retry)
            assert rep_retry is not None
            self.assertIs(rep_retry["containment_clean"], True)
            self.assertEqual(json.loads(receipts[0].read_text(encoding="utf-8"))["state"], "completed")
            self.assertEqual(receipts[0].stat().st_mode & 0o777, 0o400)

            # 4. Subsequent --check with opencode.db absent passes WITHOUT weakening require_db_event_binding
            st_post = cont_mod.inspect_containment_state(
                home_dir=home_dir,
                runs_dir=runs_dir,
                evidence_path=ev_path,
                incident_id=inc_id,
            )
            self.assertIs(st_post["evidence_integrity_valid"], True)
            self.assertIs(st_post["evidence_snapshot_valid"], True)

            # 5. Subsequent --check after a clean replacement opencode.db is created ALSO passes!
            _init_db(db_path, with_events=False, with_canary=False)
            st_clean_db = cont_mod.inspect_containment_state(
                home_dir=home_dir,
                runs_dir=runs_dir,
                evidence_path=ev_path,
                incident_id=inc_id,
            )
            self.assertIs(st_clean_db["evidence_integrity_valid"], True)
            self.assertIs(st_clean_db["sink_inspection_ok"], True)
            self.assertEqual(st_clean_db["db_matching_records"], 0)

    def test_r1_legacy_service_classifier_strict_executable_and_port_binding(self) -> None:
        cont_mod = _load_script_module("check_containment_r1", "scripts/check-credential-containment")
        uid = os.getuid()
        stable_lstart = "Sat Nov 14 20:00:00 2026"

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            home_dir = tmp_dir / "opencode-private-attested"
            other_home = tmp_dir / "other-opencode-home"
            fake_lsof = tmp_dir / "fake-lsof"
            fake_lsof.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(fake_lsof, 0o755)
            for d in (
                home_dir / ".local" / "state" / "opencode",
                home_dir / ".local" / "share" / "opencode",
                other_home / ".local" / "state" / "opencode",
            ):
                d.mkdir(parents=True, exist_ok=True)

            def _run_case(
                *,
                port: int | None,
                ps_line: str,
                listen_ports: set[int],
                expected_lstart: str | None = None,
            ) -> tuple[str, str | None]:
                def _fake_subproc(cmd: list[str], **_kw: Any) -> subprocess.CompletedProcess[str]:
                    if cmd and cmd[0] == "/bin/ps":
                        return subprocess.CompletedProcess(cmd, 0, stdout=f"{uid} {ps_line}\n", stderr="")
                    if "-sTCP:LISTEN" in cmd:
                        queried = [a.split(":", 1)[1] for a in cmd if a.startswith("-iTCP:")]
                        qport = int(queried[0]) if queried else -1
                        if qport in listen_ports:
                            return subprocess.CompletedProcess(
                                cmd, 0, stdout=f"p4242\nn127.0.0.1:{qport}\n", stderr=""
                            )
                        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")
                    return subprocess.CompletedProcess(
                        cmd,
                        0,
                        stdout=f"p4242\nn{home_dir / '.local' / 'share' / 'opencode' / 'opencode.db'}\n",
                        stderr="",
                    )

                with mock.patch.object(cont_mod, "pid_is_alive", return_value=True), mock.patch.object(
                    cont_mod, "pid_is_zombie", return_value=False
                ), mock.patch.object(
                    cont_mod, "get_process_lstart", return_value=stable_lstart
                ), mock.patch.object(
                    cont_mod,
                    "classify_pid_identity",
                    side_effect=lambda _pid, exp: "matched" if exp == stable_lstart else "reused",
                ), mock.patch.object(
                    cont_mod.subprocess, "run", side_effect=_fake_subproc
                ):
                    if expected_lstart is not None:
                        return cont_mod._classify_legacy_service_pid(
                            4242, port, home_dir, expected_lstart=expected_lstart, lsof_bin=fake_lsof
                        )
                    return cont_mod._classify_legacy_service_pid(
                        4242, port, home_dir, lsof_bin=fake_lsof
                    )

            # Row 1a: Owned legacy service with explicit --port and matching home -> matched
            st_1a, ls_1a = _run_case(
                port=54321,
                ps_line=f"/opt/homebrew/bin/opencode serve --hostname 127.0.0.1 --port 54321 HOME={home_dir} OPENCODE_TEST_HOME={home_dir}",
                listen_ports={54321},
            )
            self.assertEqual((st_1a, ls_1a), ("matched", stable_lstart))

            # Row 1b: Owned legacy service without CLI --port, verified listening on port via lsof -> matched
            st_1b, ls_1b = _run_case(
                port=54321,
                ps_line=f"/opt/homebrew/bin/opencode serve --service HOME={home_dir} OPENCODE_TEST_HOME={home_dir}",
                listen_ports={54321},
            )
            self.assertEqual((st_1b, ls_1b), ("matched", stable_lstart))

            # Row 1c: Owned legacy service with global flags and = option forms -> matched
            st_1c, ls_1c = _run_case(
                port=54321,
                ps_line=(
                    f"/opt/homebrew/bin/opencode --log-level info serve --hostname=127.0.0.1 "
                    f"--port=54321 --service=true HOME={home_dir} OPENCODE_TEST_HOME={home_dir}"
                ),
                listen_ports={54321},
            )
            self.assertEqual((st_1c, ls_1c), ("matched", stable_lstart))

            # Row 2 (Lookout R1 witness): Unrelated Python tool, same HOME, invocation-specific state, no --port -> reused
            st_2, ls_2 = _run_case(
                port=54321,
                ps_line=(
                    f"{home_dir}/.invocations/inv-99/bin/local-assist-python -I -m local_assist.server "
                    f"HOME={home_dir} OPENCODE_TEST_HOME={home_dir} "
                    f"XDG_STATE_HOME={home_dir}/.invocations/inv-99/.state"
                ),
                listen_ports=set(),
            )
            self.assertEqual((st_2, ls_2), ("reused", None))

            # Row 2b (Plan review F1): Same-home Python listener carrying fixture token or 'opencode serve' args without sidecar -> reused
            for fake_py_cmd in (
                f"/usr/bin/python3 -c import socket opencode-legacy-service-fixture HOME={home_dir}",
                f"/usr/bin/python3 -c import socket opencode serve HOME={home_dir}",
            ):
                st_2b, ls_2b = _run_case(
                    port=54321,
                    ps_line=fake_py_cmd,
                    listen_ports={54321},
                )
                self.assertEqual((st_2b, ls_2b), ("reused", None), fake_py_cmd)

            # Row 2c (Work review F1): Same-home OpenCode client subcommands, prompts containing 'serve --port',
            # '--' argument separators, and '--service=false' must NEVER grant signal authority -> reused
            for client_cmd in (
                f"/opt/homebrew/bin/opencode run explain serve --port 54321 HOME={home_dir} OPENCODE_TEST_HOME={home_dir}",
                f"/opt/homebrew/bin/opencode -- serve --port 54321 HOME={home_dir} OPENCODE_TEST_HOME={home_dir}",
                f"/opt/homebrew/bin/opencode serve -- run --port 54321 HOME={home_dir} OPENCODE_TEST_HOME={home_dir}",
                f"/opt/homebrew/bin/opencode --service=false --port 54321 HOME={home_dir} OPENCODE_TEST_HOME={home_dir}",
                f"/opt/homebrew/bin/opencode serve --service=false --port 54321 HOME={home_dir} OPENCODE_TEST_HOME={home_dir}",
                f"/opt/homebrew/bin/opencode service status HOME={home_dir} OPENCODE_TEST_HOME={home_dir}",
                f"/opt/homebrew/bin/opencode serve positional-arg --port 54321 HOME={home_dir} OPENCODE_TEST_HOME={home_dir}",
            ):
                st_2c, ls_2c = _run_case(
                    port=54321,
                    ps_line=client_cmd,
                    listen_ports={54321},
                )
                self.assertEqual((st_2c, ls_2c), ("reused", None), client_cmd)

            # Row 3: Different-home opencode service (even if listening on same port) -> reused
            st_3, ls_3 = _run_case(
                port=54321,
                ps_line=f"/opt/homebrew/bin/opencode serve --port 54321 HOME={other_home} OPENCODE_TEST_HOME={other_home}",
                listen_ports={54321},
            )
            self.assertEqual((st_3, ls_3), ("reused", None))

            # Row 4: Same-home opencode service with explicit conflicting --port -> reused
            st_4, ls_4 = _run_case(
                port=54321,
                ps_line=f"/opt/homebrew/bin/opencode serve --port 59991 HOME={home_dir} OPENCODE_TEST_HOME={home_dir}",
                listen_ports={59991},
            )
            self.assertEqual((st_4, ls_4), ("reused", None))

            # Row 5: Unattributable historical record (port=None, no bound lstart) on live PID -> unavailable (refuses automatic termination)
            st_5, ls_5 = _run_case(
                port=None,
                ps_line=f"/opt/homebrew/bin/opencode serve --service HOME={home_dir}",
                listen_ports={54321},
            )
            self.assertEqual((st_5, ls_5), ("unavailable", None))

            # End-to-end apply refusal on conflicting sidecars & zero signals on same-home Python tool
            pres_dir = tmp_dir / "pres"
            runs_dir = tmp_dir / "runs"
            pres_dir.mkdir()
            runs_dir.mkdir()
            marker = pres_dir / "marker.log"
            marker.write_text("evidence\n", encoding="utf-8")
            ev_path = tmp_dir / "ev.json"
            ev_path.write_text(
                json.dumps(
                    {
                        "incident_id": "R1-TEST",
                        "target_home": str(home_dir),
                        "artifacts": {
                            str(marker): hashlib.sha256(marker.read_bytes()).hexdigest()
                        },
                    }
                ),
                encoding="utf-8",
            )
            py_tool = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    "import time; print('TOOL', flush=True); time.sleep(60)",
                    "opencode-legacy-service-fixture",
                ],
                env={
                    **os.environ,
                    "HOME": str(home_dir),
                    "OPENCODE_TEST_HOME": str(home_dir),
                    "XDG_STATE_HOME": str(home_dir / ".invocations" / "inv-1" / ".state"),
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                assert py_tool.stdout is not None
                self.assertEqual(py_tool.stdout.readline().strip(), "TOOL")
                svc_file = home_dir / ".local" / "state" / "opencode" / "service.json"
                svc_file.write_text(
                    json.dumps({"pid": py_tool.pid, "port": 54321, "password": "pw-r1-12345678"}),
                    encoding="utf-8",
                )
                signals_sent: list[tuple[int, int]] = []
                orig_kill = os.kill

                def _spy_kill(p: int, sig: int) -> None:
                    if int(sig) != 0:
                        signals_sent.append((int(p), int(sig)))
                    orig_kill(p, sig)

                with mock.patch("os.kill", side_effect=_spy_kill):
                    rc_tool, rep_tool, err_tool = cont_mod.apply_containment(
                        home_dir=home_dir,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id="R1-TEST",
                    )
                self.assertEqual(rc_tool, 0, err_tool)
                assert rep_tool is not None
                self.assertEqual(rep_tool["legacy_services_stopped"], 0)
                self.assertIsNone(py_tool.poll(), "Same-home Python tool must NOT be signaled!")
                self.assertEqual([s for s in signals_sent if s[0] == py_tool.pid], [])

                # Work-review F1 end-to-end: un-sidecar'd service.json pointing at a live same-home
                # 'opencode run explain serve --port 54321' client must NEVER receive a signal!
                svc_file.write_text(
                    json.dumps({"pid": py_tool.pid, "port": 54321, "password": "pw-r1-12345678"}),
                    encoding="utf-8",
                )
                orig_subproc_run = cont_mod.subprocess.run

                def _mock_ps_opencode_run_client(cmd: Any, *args: Any, **kwargs: Any) -> Any:
                    if isinstance(cmd, list) and cmd[:3] == ["/bin/ps", "eww", "-p"] and str(py_tool.pid) in cmd:
                        return subprocess.CompletedProcess(
                            cmd,
                            0,
                            stdout=(
                                f"  {os.getuid()} /opt/homebrew/bin/opencode run explain serve "
                                f"--port 54321 HOME={home_dir} OPENCODE_TEST_HOME={home_dir}\n"
                            ),
                            stderr="",
                        )
                    return orig_subproc_run(cmd, *args, **kwargs)

                with mock.patch("os.kill", side_effect=_spy_kill), mock.patch.object(
                    cont_mod.subprocess, "run", side_effect=_mock_ps_opencode_run_client
                ):
                    rc_client, rep_client, err_client = cont_mod.apply_containment(
                        home_dir=home_dir,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id="R1-TEST",
                    )
                self.assertEqual(rc_client, 0, err_client)
                assert rep_client is not None
                self.assertEqual(rep_client["legacy_services_stopped"], 0)
                self.assertIsNone(py_tool.poll(), "Same-home opencode run client must NOT be signaled!")
                self.assertEqual([s for s in signals_sent if s[0] == py_tool.pid], [])

                # Conflicting sidecar lstarts -> refuses automatic termination and preserves service.json
                svc_file.write_text(
                    json.dumps(
                        {
                            "pid": py_tool.pid,
                            "pid_lstart": get_process_lstart(py_tool.pid),
                            "port": 54321,
                            "password": "pw-r1-12345678",
                        }
                    ),
                    encoding="utf-8",
                )
                conflict_sc = home_dir / ".local" / "state" / "opencode" / "service-identity.json"
                conflict_sc.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "id": "legacy",
                            "pid": py_tool.pid,
                            "pid_lstart": "Mon Jan  1 00:00:00 2024",
                            "service_port": 54321,
                        }
                    ),
                    encoding="utf-8",
                )
                with mock.patch("os.kill", side_effect=_spy_kill):
                    rc_conf, _, _ = cont_mod.apply_containment(
                        home_dir=home_dir,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id="R1-TEST",
                    )
                self.assertEqual(rc_conf, 1)
                self.assertTrue(svc_file.exists())
                self.assertIsNone(py_tool.poll())
            finally:
                if py_tool.poll() is None:
                    py_tool.kill()
                    py_tool.wait(timeout=5)
                for pipe in (py_tool.stdout, py_tool.stderr):
                    if pipe is not None:
                        pipe.close()

    def test_r1_untrusted_inline_and_nested_identity_cannot_bypass_attribution(self) -> None:
        cont_mod = _load_script_module("check_containment_r1_auth", "scripts/check-credential-containment")
        native_oc_bin = _get_native_opencode_test_binary()

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            home_dir = tmp_dir / "legacy-home"
            other_home = tmp_dir / "other-home"
            pres_dir = tmp_dir / "pres"
            runs_dir = tmp_dir / "runs"
            for d in (
                home_dir / ".local" / "state" / "opencode",
                home_dir / ".local" / "share" / "opencode",
                other_home / ".local" / "state" / "opencode",
                pres_dir,
                runs_dir,
            ):
                d.mkdir(parents=True, exist_ok=True)

            marker = pres_dir / "marker.log"
            marker.write_text("evidence\n", encoding="utf-8")
            ev_path = tmp_dir / "ev.json"
            ev_path.write_text(
                json.dumps(
                    {
                        "incident_id": "R1-AUTH",
                        "target_home": str(home_dir),
                        "artifacts": {
                            str(marker): hashlib.sha256(marker.read_bytes()).hexdigest()
                        },
                    }
                ),
                encoding="utf-8",
            )

            svc_file = home_dir / ".local" / "state" / "opencode" / "service.json"
            nested_sc = home_dir / ".local" / "state" / "opencode" / "service-identity.json"
            nested_dot_sc = home_dir / ".local" / "state" / "opencode" / ".service-identity.json"
            root_sc = home_dir / ".service-identity.json"

            # Spawn a live same-UID Python process with NO .invocations substring and NO --port flag
            # (exact Lookout Round-3 R1 counterexample).
            unrelated_proc = subprocess.Popen(
                [sys.executable, "-c", "import time; print('UNREL', flush=True); time.sleep(60)"],
                env={"HOME": str(other_home), "PATH": "/usr/bin:/bin"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            client_oc_proc = subprocess.Popen(
                [str(native_oc_bin), "run", "explain", "serve"],
                env={
                    "HOME": str(home_dir),
                    "OPENCODE_TEST_HOME": str(home_dir),
                    "PATH": "/usr/bin:/bin",
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            other_home_oc_proc = subprocess.Popen(
                [str(native_oc_bin), "serve", "--service"],
                env={
                    "HOME": str(other_home),
                    "OPENCODE_TEST_HOME": str(other_home),
                    "PATH": "/usr/bin:/bin",
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            spawned_extra: list[subprocess.Popen[str]] = []
            try:
                assert unrelated_proc.stdout is not None
                assert client_oc_proc.stdout is not None
                assert other_home_oc_proc.stdout is not None
                self.assertEqual(unrelated_proc.stdout.readline().strip(), "UNREL")
                _ = int(client_oc_proc.stdout.readline().strip())
                other_oc_port = int(other_home_oc_proc.stdout.readline().strip())

                unrelated_ls = get_process_lstart(unrelated_proc.pid)
                assert isinstance(unrelated_ls, str) and unrelated_ls.strip()
                norm_unrel_ls = " ".join(unrelated_ls.split())

                signals_sent: list[tuple[int, int]] = []
                orig_kill = os.kill

                def _spy_kill(p: int, sig: int) -> None:
                    if int(sig) != 0:
                        signals_sent.append((int(p), int(sig)))
                    orig_kill(p, sig)

                def _cleanup_sidecars() -> None:
                    for fp in (svc_file, nested_sc, nested_dot_sc, root_sc):
                        try:
                            if fp.exists() or fp.is_symlink():
                                os.chmod(fp, 0o600)
                                fp.unlink()
                        except OSError:
                            pass

                # U1 (Lookout counterexample): consistent inline service.json.pid_lstart naming unrelated process -> zero signals!
                _cleanup_sidecars()
                svc_file.write_text(
                    json.dumps(
                        {
                            "pid": unrelated_proc.pid,
                            "pid_lstart": unrelated_ls,
                            "port": 54321,
                            "password": "pw-u1-12345678",
                        }
                    ),
                    encoding="utf-8",
                )
                parsed_u1 = cont_mod._parse_legacy_service_record(svc_file, home_dir)
                self.assertEqual(parsed_u1, (True, unrelated_proc.pid, 54321, norm_unrel_ls, False))
                signals_sent.clear()
                with mock.patch("os.kill", side_effect=_spy_kill):
                    rc_u1, rep_u1, err_u1 = cont_mod.apply_containment(
                        home_dir=home_dir,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id="R1-AUTH",
                    )
                self.assertEqual(rc_u1, 0, err_u1)
                assert rep_u1 is not None
                self.assertEqual(rep_u1["legacy_services_stopped"], 0)
                self.assertIsNone(unrelated_proc.poll(), "Inline pid_lstart must NOT signal unrelated process!")
                self.assertEqual(signals_sent, [])

                # U2: consistent nested 0400 service-identity.json and .service-identity.json -> launcher_bound=False, zero signals!
                for sc_target in (nested_sc, nested_dot_sc):
                    _cleanup_sidecars()
                    svc_file.write_text(
                        json.dumps({"pid": unrelated_proc.pid, "port": 54321, "password": "pw-u2-12345678"}),
                        encoding="utf-8",
                    )
                    sc_target.write_text(
                        json.dumps(
                            {
                                "schema_version": 1,
                                "id": "legacy",
                                "pid": unrelated_proc.pid,
                                "pid_lstart": unrelated_ls,
                                "service_port": 54321,
                            }
                        ),
                        encoding="utf-8",
                    )
                    os.chmod(sc_target, 0o400)
                    parsed_u2 = cont_mod._parse_legacy_service_record(svc_file, home_dir)
                    self.assertEqual(parsed_u2, (True, unrelated_proc.pid, 54321, norm_unrel_ls, False))
                    signals_sent.clear()
                    with mock.patch("os.kill", side_effect=_spy_kill):
                        rc_u2, rep_u2, err_u2 = cont_mod.apply_containment(
                            home_dir=home_dir,
                            runs_dir=runs_dir,
                            evidence_path=ev_path,
                            incident_id="R1-AUTH",
                        )
                    self.assertEqual(rc_u2, 0, err_u2)
                    assert rep_u2 is not None
                    self.assertEqual(rep_u2["legacy_services_stopped"], 0)
                    self.assertIsNone(unrelated_proc.poll(), f"Nested {sc_target.name} must NOT signal unrelated process!")
                    self.assertEqual(signals_sent, [])

                # Nested sidecar claiming pid absent from service.json fails closed (never synthesizes svc_pid)
                _cleanup_sidecars()
                svc_file.write_text(json.dumps({"port": 54321, "password": "pw-u2b-12345678"}), encoding="utf-8")
                nested_sc.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "id": "legacy",
                            "pid": unrelated_proc.pid,
                            "pid_lstart": unrelated_ls,
                            "service_port": 54321,
                        }
                    ),
                    encoding="utf-8",
                )
                os.chmod(nested_sc, 0o400)
                self.assertEqual(
                    cont_mod._parse_legacy_service_record(svc_file, home_dir),
                    (False, None, None, None, False),
                )
                signals_sent.clear()
                with mock.patch("os.kill", side_effect=_spy_kill):
                    rc_u2b, _, _ = cont_mod.apply_containment(
                        home_dir=home_dir,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id="R1-AUTH",
                    )
                self.assertEqual(rc_u2b, 1)
                self.assertTrue(svc_file.exists())
                self.assertEqual(signals_sent, [])

                # U3: consistent inline + nested 0400 sidecar naming same-home `opencode run` client or other-home `opencode serve` -> zero signals!
                for non_owned_proc, non_owned_port in (
                    (client_oc_proc, 54321),
                    (other_home_oc_proc, other_oc_port),
                ):
                    _cleanup_sidecars()
                    proc_ls = get_process_lstart(non_owned_proc.pid)
                    assert isinstance(proc_ls, str) and proc_ls.strip()
                    svc_file.write_text(
                        json.dumps(
                            {
                                "pid": non_owned_proc.pid,
                                "pid_lstart": proc_ls,
                                "port": non_owned_port,
                                "password": "pw-u3-12345678",
                            }
                        ),
                        encoding="utf-8",
                    )
                    nested_sc.write_text(
                        json.dumps(
                            {
                                "schema_version": 1,
                                "id": "legacy",
                                "pid": non_owned_proc.pid,
                                "pid_lstart": proc_ls,
                                "service_port": non_owned_port,
                            }
                        ),
                        encoding="utf-8",
                    )
                    os.chmod(nested_sc, 0o400)
                    signals_sent.clear()
                    with mock.patch("os.kill", side_effect=_spy_kill):
                        rc_u3, rep_u3, err_u3 = cont_mod.apply_containment(
                            home_dir=home_dir,
                            runs_dir=runs_dir,
                            evidence_path=ev_path,
                            incident_id="R1-AUTH",
                        )
                    self.assertEqual(rc_u3, 0, err_u3)
                    assert rep_u3 is not None
                    self.assertEqual(rep_u3["legacy_services_stopped"], 0)
                    self.assertIsNone(non_owned_proc.poll())
                    self.assertEqual(signals_sent, [])

                # U4a: writable (0600) home-root .service-identity.json fails closed (rc == 1, zero signals)
                _cleanup_sidecars()
                svc_file.write_text(
                    json.dumps({"pid": unrelated_proc.pid, "port": 54321, "password": "pw-u4a-12345678"}),
                    encoding="utf-8",
                )
                root_sc.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "id": "legacy",
                            "pid": unrelated_proc.pid,
                            "pid_lstart": unrelated_ls,
                            "service_port": 54321,
                        }
                    ),
                    encoding="utf-8",
                )
                os.chmod(root_sc, 0o600)
                self.assertEqual(
                    cont_mod._parse_legacy_service_record(svc_file, home_dir),
                    (False, None, None, None, False),
                )
                signals_sent.clear()
                with mock.patch("os.kill", side_effect=_spy_kill):
                    rc_u4a, _, _ = cont_mod.apply_containment(
                        home_dir=home_dir,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id="R1-AUTH",
                    )
                self.assertEqual(rc_u4a, 1)
                self.assertTrue(svc_file.exists())
                self.assertEqual(signals_sent, [])

                # U4b: forged 0400 home-root .service-identity.json naming non-service process -> launcher_bound=True, still zero signals!
                os.chmod(root_sc, 0o400)
                self.assertEqual(
                    cont_mod._parse_legacy_service_record(svc_file, home_dir),
                    (True, unrelated_proc.pid, 54321, norm_unrel_ls, True),
                )
                signals_sent.clear()
                with mock.patch("os.kill", side_effect=_spy_kill):
                    rc_u4b, rep_u4b, err_u4b = cont_mod.apply_containment(
                        home_dir=home_dir,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id="R1-AUTH",
                    )
                self.assertEqual(rc_u4b, 0, err_u4b)
                assert rep_u4b is not None
                self.assertEqual(rep_u4b["legacy_services_stopped"], 0)
                self.assertIsNone(unrelated_proc.poll())
                self.assertEqual(signals_sent, [])

                # C1 & C2 (Plan review Minor 1): constraint-only untrusted lstart on a genuine native `opencode serve --service`
                c_svc = subprocess.Popen(
                    [str(native_oc_bin), "serve", "--service"],
                    env={
                        "HOME": str(home_dir),
                        "OPENCODE_TEST_HOME": str(home_dir),
                        "PATH": "/usr/bin:/bin",
                    },
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                spawned_extra.append(c_svc)
                assert c_svc.stdout is not None
                c_port = int(c_svc.stdout.readline().strip())
                c_ls = get_process_lstart(c_svc.pid)
                assert isinstance(c_ls, str) and c_ls.strip()

                # C0: explicit null inline pid_lstart must fail closed as malformed (record_ok=False, rc=1, zero signals, service.json preserved)
                _cleanup_sidecars()
                svc_file.write_text(
                    json.dumps(
                        {
                            "pid": c_svc.pid,
                            "pid_lstart": None,
                            "port": c_port,
                            "password": "pw-c0-12345678",
                        }
                    ),
                    encoding="utf-8",
                )
                self.assertEqual(
                    cont_mod._parse_legacy_service_record(svc_file, home_dir),
                    (False, None, None, None, False),
                )
                signals_sent.clear()
                with mock.patch("os.kill", side_effect=_spy_kill):
                    rc_c0, _, _ = cont_mod.apply_containment(
                        home_dir=home_dir,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id="R1-AUTH",
                    )
                self.assertEqual(rc_c0, 1)
                self.assertIsNone(c_svc.poll())
                self.assertTrue(svc_file.exists())
                self.assertEqual(signals_sent, [])

                # C1: stale untrusted inline pid_lstart rejects PID reuse on genuine service (zero signals)
                _cleanup_sidecars()
                svc_file.write_text(
                    json.dumps(
                        {
                            "pid": c_svc.pid,
                            "pid_lstart": "Mon Jan  1 00:00:00 2024",
                            "port": c_port,
                            "password": "pw-c1-12345678",
                        }
                    ),
                    encoding="utf-8",
                )
                signals_sent.clear()
                with mock.patch("os.kill", side_effect=_spy_kill):
                    rc_c1, rep_c1, err_c1 = cont_mod.apply_containment(
                        home_dir=home_dir,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id="R1-AUTH",
                    )
                self.assertEqual(rc_c1, 0, err_c1)
                assert rep_c1 is not None
                self.assertEqual(rep_c1["legacy_services_stopped"], 0)
                self.assertIsNone(c_svc.poll())
                self.assertEqual(signals_sent, [])

                # C2: consistent inline pid_lstart + nested 0400 sidecar (no root sidecar) on genuine service -> matched & stopped!
                _cleanup_sidecars()
                svc_file.write_text(
                    json.dumps(
                        {
                            "pid": c_svc.pid,
                            "pid_lstart": c_ls,
                            "port": c_port,
                            "password": "pw-c2-12345678",
                        }
                    ),
                    encoding="utf-8",
                )
                nested_sc.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "id": "legacy",
                            "pid": c_svc.pid,
                            "pid_lstart": c_ls,
                            "service_port": c_port,
                        }
                    ),
                    encoding="utf-8",
                )
                os.chmod(nested_sc, 0o400)
                signals_sent.clear()
                with mock.patch("os.kill", side_effect=_spy_kill):
                    rc_c2, rep_c2, err_c2 = cont_mod.apply_containment(
                        home_dir=home_dir,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id="R1-AUTH",
                    )
                self.assertEqual(rc_c2, 0, err_c2)
                assert rep_c2 is not None
                self.assertEqual(rep_c2["legacy_services_stopped"], 1)
                self.assertIsNotNone(c_svc.wait(timeout=5))
                self.assertEqual([s for s in signals_sent if s[0] == unrelated_proc.pid], [])

                # B1 & B2: legitimate root-bound (0400 .service-identity.json) and unbound historical native services -> matched & stopped!
                for bind_root_sc in (True, False):
                    _cleanup_sidecars()
                    b_svc = subprocess.Popen(
                        [str(native_oc_bin), "serve", "--service"],
                        env={
                            "HOME": str(home_dir),
                            "OPENCODE_TEST_HOME": str(home_dir),
                            "PATH": "/usr/bin:/bin",
                        },
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    spawned_extra.append(b_svc)
                    assert b_svc.stdout is not None
                    b_port = int(b_svc.stdout.readline().strip())
                    b_ls = get_process_lstart(b_svc.pid)
                    assert isinstance(b_ls, str) and b_ls.strip()
                    svc_file.write_text(
                        json.dumps({"pid": b_svc.pid, "port": b_port, "password": "pw-b-12345678"}),
                        encoding="utf-8",
                    )
                    if bind_root_sc:
                        root_sc.write_text(
                            json.dumps(
                                {
                                    "schema_version": 1,
                                    "id": "legacy",
                                    "pid": b_svc.pid,
                                    "pid_lstart": b_ls,
                                    "service_port": b_port,
                                }
                            ),
                            encoding="utf-8",
                        )
                        os.chmod(root_sc, 0o400)
                    parsed_b = cont_mod._parse_legacy_service_record(svc_file, home_dir)
                    self.assertIs(parsed_b[0], True)
                    self.assertIs(parsed_b[4], bind_root_sc)
                    signals_sent.clear()
                    with mock.patch("os.kill", side_effect=_spy_kill):
                        rc_b, rep_b, err_b = cont_mod.apply_containment(
                            home_dir=home_dir,
                            runs_dir=runs_dir,
                            evidence_path=ev_path,
                            incident_id="R1-AUTH",
                        )
                    self.assertEqual(rc_b, 0, err_b)
                    assert rep_b is not None
                    self.assertEqual(rep_b["legacy_services_stopped"], 1)
                    self.assertIsNotNone(b_svc.wait(timeout=5))
                    self.assertIsNone(unrelated_proc.poll())
                    self.assertEqual([s for s in signals_sent if s[0] == unrelated_proc.pid], [])
            finally:
                for p in (unrelated_proc, client_oc_proc, other_home_oc_proc, *spawned_extra):
                    if p.poll() is None:
                        p.kill()
                        p.wait(timeout=5)
                    for pipe in (p.stdout, p.stderr):
                        if pipe is not None:
                            pipe.close()

    def test_r2_relay_labeled_wrapped_base64_and_json_budget_parity(self) -> None:
        from local_assist.relay import SessionAuthRelay, contains_credential_leak

        upstream_tok = "se-session-" + ("aa55bb66" * 8)
        canary_key = "sk-prov/secret+key_9876543210"
        wrapped_offset2_b64 = base64.b64encode(f"xy{canary_key}Z".encode("utf-8")).decode("ascii")
        for direct_needle in (
            canary_key,
            base64.b64encode(canary_key.encode("utf-8")).decode("ascii").rstrip("="),
            base64.urlsafe_b64encode(canary_key.encode("utf-8")).decode("ascii").rstrip("="),
            base64.b64encode(f"opencode:{canary_key}".encode("utf-8")).decode("ascii").rstrip("="),
            base64.b64encode(f":{canary_key}".encode("utf-8")).decode("ascii").rstrip("="),
        ):
            self.assertNotIn(direct_needle, wrapped_offset2_b64)

        def _nested_lists(levels: int) -> Any:
            cur: Any = 1
            for _ in range(levels):
                cur = [cur]
            return cur

        def _nested_embedded_json(decodes: int) -> str:
            cur = json.dumps({"k": 1})
            for _ in range(decodes - 1):
                cur = json.dumps({"n": cur})
            return cur

        escaped_slash = canary_key.replace("/", "\\/")
        cand_word = "AbcdEfghIjklMnop"

        # Exact-at-limit accepted boundary controls across all 5 relay guards
        # (including explicit max_tokens so SessionAuthRelay clamping adds 0 extra nodes):
        # 1. MAX_JSON_CONTAINER_DEPTH = 64 (root dict depth=0 + 63 nested lists -> leaf depth=64)
        # 2. MAX_VISITED_JSON_NODES = 20_000 (dict + 'max_tokens':64 + 'a':[1]*19_995 = 20_000 nodes)
        # 3. MAX_EMBEDDED_JSON_DECODES = 6 (6 nested JSON string decodes)
        # 4. MAX_BASE64_CANDIDATES_PER_STRING = 16_384 (16_384 16-char tokens; 'max_tokens' is 10 chars)
        # 5. MAX_BASE64_CANDIDATE_TOKEN_LEN = 65_536 (single 65_536-char token)
        accepted_cases: tuple[tuple[str, dict[str, Any]], ...] = (
            (
                "clean_labeled_short",
                {"model": "m", "max_tokens": 64, "messages": [{"role": "user", "content": "blob=hello_world"}]},
            ),
            ("at_depth_64", {"max_tokens": 64, "d": _nested_lists(63)}),
            ("at_nodes_20000", {"max_tokens": 64, "a": [1] * 19_995}),
            ("at_embedded_6", {"max_tokens": 64, "m": _nested_embedded_json(6)}),
            ("at_candidates_16384", {"max_tokens": 64, "m": " ".join([cand_word] * 16_384)}),
            ("at_tok_len_65536", {"max_tokens": 64, "m": "A" * 65_536}),
        )

        leak_cases: tuple[tuple[str, dict[str, Any]], ...] = (
            (
                "token_offset2",
                {"model": "m", "messages": [{"role": "user", "content": f"token={wrapped_offset2_b64}"}]},
            ),
            (
                "blob_offset2",
                {"model": "m", "messages": [{"role": "user", "content": f"blob={wrapped_offset2_b64}"}]},
            ),
            (
                "long_label_offset2",
                {
                    "model": "m",
                    "messages": [{"role": "user", "content": f"long_parameter_label={wrapped_offset2_b64}"}],
                },
            ),
            (
                "nested_json_slash_escape",
                {
                    "model": "m",
                    "messages": [{"role": "user", "content": '{"nested":"' + escaped_slash + '"}'}],
                },
            ),
            ("over_depth_65", {"max_tokens": 64, "d": _nested_lists(64)}),
            ("over_nodes_20001", {"max_tokens": 64, "a": [1] * 19_996}),
            ("over_embedded_7", {"max_tokens": 64, "m": _nested_embedded_json(7)}),
            ("over_candidates_16385", {"max_tokens": 64, "m": " ".join([cand_word] * 16_385)}),
            ("over_tok_len_65537", {"max_tokens": 64, "m": "A" * 65_537}),
        )
        for label, payload in leak_cases:
            self.assertTrue(
                contains_credential_leak(
                    json.dumps(payload).encode("utf-8"),
                    secrets_to_block=(upstream_tok, canary_key),
                ),
                f"Expected contains_credential_leak=True for {label}",
            )
        for label, payload in accepted_cases:
            self.assertFalse(
                contains_credential_leak(
                    json.dumps(payload).encode("utf-8"),
                    secrets_to_block=(upstream_tok, canary_key),
                ),
                f"Expected contains_credential_leak=False for {label}",
            )

        forwarded = 0

        class _StubUpstream(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_POST(self) -> None:
                nonlocal forwarded
                length = int(self.headers.get("Content-Length") or "0")
                _ = self.rfile.read(length)
                forwarded += 1
                out = b'{"id":"ok","choices":[{"message":{"role":"assistant","content":"hi"}}]}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _StubUpstream)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        relay = SessionAuthRelay(
            upstream_base_url=f"http://127.0.0.1:{srv.server_address[1]}/v1",
            upstream_session_token=upstream_tok,
            extra_canary_secrets=(canary_key,),
            max_request_bytes=1024 * 1024,
        ).start()
        try:
            url = f"{relay.api_base_url}/chat/completions"
            headers = {
                "Authorization": f"Bearer {relay.relay_token}",
                "Content-Type": "application/json",
            }
            for label, payload in leak_cases:
                req = Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
                with self.assertRaises(HTTPError, msg=f"Expected HTTP 400 for {label}") as ctx:
                    urlopen(req, timeout=5)
                ctx.exception.close()
                self.assertEqual(ctx.exception.code, 400, label)

            self.assertEqual(forwarded, 0)
            self.assertEqual(relay.chat_requests_used, 0)

            for label, payload in accepted_cases:
                clean_req = Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                with urlopen(clean_req, timeout=5) as resp:
                    self.assertEqual(resp.status, 200, label)
            self.assertEqual(forwarded, len(accepted_cases))
            self.assertEqual(relay.chat_requests_used, len(accepted_cases))
        finally:
            relay.close()
            srv.shutdown()
            srv.server_close()

    def test_r3_explicit_target_model_retry_and_early_receipt_db_gate(self) -> None:
        cont_mod = _load_script_module("check_containment_r3", "scripts/check-credential-containment")
        inc_id = "ISO-001-R3"
        canary_tok = "se-session-" + ("33445566" * 8)
        canary_sha = hashlib.sha256(canary_tok.encode("utf-8")).hexdigest()
        target_model = "tinfoil-deepseek-v4-1-flash"

        real_head = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        sec_sha = hashlib.sha256(
            subprocess.run(
                ["git", "-C", str(ROOT), "cat-file", "blob", f"{real_head}:SECURITY.md"],
                capture_output=True,
                check=True,
            ).stdout
        ).hexdigest()
        swift_sha = hashlib.sha256(
            subprocess.run(
                ["git", "-C", str(ROOT), "cat-file", "blob", f"{real_head}:tools/se_key_proxy/main.swift"],
                capture_output=True,
                check=True,
            ).stdout
        ).hexdigest()

        prov_event = {
            "message_id": "msg_r3_1",
            "session_sequence": 1,
            "tool_name": "bash",
            "event_label": "probe",
            "snapshot_rowid": 1,
        }

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            home_dir = tmp_dir / "home"
            runs_dir = tmp_dir / "runs"
            ev_dir = tmp_dir / "evidence_store"
            for d in (
                home_dir / ".local" / "share" / "opencode" / "log",
                home_dir / ".configs",
                runs_dir,
                ev_dir,
            ):
                d.mkdir(parents=True, exist_ok=True)

            db_path = home_dir / ".local" / "share" / "opencode" / "opencode.db"
            conn = sqlite3.connect(str(db_path))
            conn.execute("CREATE TABLE session_message (id TEXT, session_id TEXT, seq INTEGER, body TEXT)")
            conn.execute(
                "INSERT INTO session_message (rowid, id, session_id, seq, body) VALUES (1, 'msg_r3_1', 'sess_r3', 1, ?)",
                (f"leaked {canary_tok}",),
            )
            conn.commit()
            conn.close()

            ev_path = ev_dir / "evidence.json"
            ev_path.write_text(
                json.dumps(
                    {
                        "tracking_id": inc_id,
                        "target_home": str(home_dir),
                        "lab_head": real_head,
                        "session_id": "sess_r3",
                        "events": [prov_event],
                        "source_sha256": {
                            "SECURITY.md": sec_sha,
                            "tools/se_key_proxy/main.swift": swift_sha,
                        },
                    }
                ),
                encoding="utf-8",
            )

            # 0. Fresh nonexistent --target-model refuses before any receipt exists
            with mock.patch.object(cont_mod, "_list_current_uid_ps_commands", return_value=([], True)):
                rc_nonexist, _, _ = cont_mod.apply_containment(
                    home_dir=home_dir,
                    runs_dir=runs_dir,
                    evidence_path=ev_path,
                    incident_id=inc_id,
                    target_model_id="nonexistent-model",
                )
            self.assertEqual(rc_nonexist, 1)

            # Spawn virtual target proxy so Step 1 stops it and removes its PID/token records
            # Choose a currently free port instead of probing a fixed port that
            # may belong to another test or the review CLI.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as closed_port:
                closed_port.bind(('127.0.0.1', 0))
                unused_port = closed_port.getsockname()[1]

            proxy_proc = subprocess.Popen(
                [sys.executable, "-c", "import time; print('P', flush=True); time.sleep(60)"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            holder_proc = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    f"import time; fh = open({str(db_path)!r}, 'rb'); print('H', flush=True); time.sleep(60)",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                assert proxy_proc.stdout is not None and holder_proc.stdout is not None
                self.assertEqual(proxy_proc.stdout.readline().strip(), "P")
                self.assertEqual(holder_proc.stdout.readline().strip(), "H")

                tok_file = runs_dir / f".se-session-{target_model}.token"
                tok_file.write_text(canary_tok + "\n", encoding="utf-8")
                pid_file = runs_dir / f".serve.{target_model}.pid"
                pid_file.write_text(
                    json.dumps(
                        {
                            "model_id": target_model,
                            "trust_tier": "enclave_runtime_attested",
                            "pid": proxy_proc.pid,
                            "pid_lstart": get_process_lstart(proxy_proc.pid),
                            "port": unused_port,
                            "session_token_file": str(tok_file),
                            "status": "ready",
                        }
                    ),
                    encoding="utf-8",
                )

                # 1. Run 1 aborts at Step 2 (open holder) AFTER Step 1 stops target_model:
                # early revocation receipt must NOT satisfy DB event binding if opencode.db is removed out-of-band!
                with mock.patch.object(cont_mod, "_list_current_uid_ps_commands", return_value=([], True)):
                    rc_step2, _, _ = cont_mod.apply_containment(
                        home_dir=home_dir,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id=inc_id,
                        target_model_id=target_model,
                    )
                self.assertEqual(rc_step2, 1)
                self.assertIsNotNone(proxy_proc.wait(timeout=5))
                holder_proc.terminate()
                holder_proc.wait(timeout=5)

                db_backup = tmp_dir / "db_backup.sqlite"
                shutil.copy2(db_path, db_backup)
                db_path.unlink()
                st_missing_db = cont_mod.inspect_containment_state(
                    home_dir=home_dir,
                    runs_dir=runs_dir,
                    evidence_path=ev_path,
                    incident_id=inc_id,
                )
                self.assertIs(
                    st_missing_db["evidence_integrity_valid"],
                    False,
                    "Early Step-1 revocation receipt must NOT substitute for Step 2.5 DB event binding!",
                )
                shutil.copy2(db_backup, db_path)

                # 2. Run 2 with identical explicit --target-model reaches Step 3, unlinks opencode.db, and hits late unlink failure
                retry_cfg = home_dir / ".configs" / "opencode-retry.json"
                retry_cfg.write_text('{"retry": true}\n', encoding="utf-8")
                orig_unlink = Path.unlink

                def _fail_late_cfg(self_path: Path, *args: Any, **kwargs: Any) -> None:
                    if self_path.name == "opencode-retry.json":
                        raise PermissionError("simulated late unlink failure")
                    orig_unlink(self_path, *args, **kwargs)

                with mock.patch.object(
                    cont_mod, "_list_current_uid_ps_commands", return_value=([], True)
                ), mock.patch.object(Path, "unlink", _fail_late_cfg):
                    rc_late, rep_late, _ = cont_mod.apply_containment(
                        home_dir=home_dir,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id=inc_id,
                        target_model_id=target_model,
                    )
                self.assertEqual(rc_late, 1)
                self.assertIsNotNone(rep_late)
                self.assertFalse(db_path.exists())
                self.assertTrue(retry_cfg.exists())

                # 3. Retry with a DIFFERENT --target-model must still refuse!
                with mock.patch.object(cont_mod, "_list_current_uid_ps_commands", return_value=([], True)):
                    rc_wrong_target, _, _ = cont_mod.apply_containment(
                        home_dir=home_dir,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id=inc_id,
                        target_model_id="privatemode-glm-5-3-flash",
                    )
                self.assertEqual(rc_wrong_target, 1)
                self.assertTrue(retry_cfg.exists())

                # 3b. Merge-true preservation: a subsequent Step-1 receipt write with
                # db_events_verified_pre_cleanup=False MUST preserve prior True and merge targets!
                ev_sha = hashlib.sha256(ev_path.read_bytes()).hexdigest()
                home_res = home_dir.resolve()
                wrote_merge = cont_mod._write_containment_receipt(
                    evidence_path=ev_path,
                    evidence_sha256=ev_sha,
                    home_resolved=home_res,
                    incident_id=inc_id,
                    state="in_progress",
                    session_id="sess_r3",
                    events=[prov_event],
                    db_events_verified_pre_cleanup=False,
                    revoked_target_models=["tinfoil-kimi-k3-1-pro"],
                )
                self.assertIs(wrote_merge, True)
                merged_rec = cont_mod._read_verified_containment_receipt(
                    evidence_path=ev_path,
                    evidence_sha256=ev_sha,
                    home_resolved=home_res,
                    expected_incident_id=inc_id,
                    session_id="sess_r3",
                    events=[prov_event],
                )
                assert merged_rec is not None
                self.assertIs(
                    merged_rec["db_events_verified_pre_cleanup"],
                    True,
                    "Prior db_events_verified_pre_cleanup=True must be preserved across later Step-1 writes!",
                )
                self.assertEqual(
                    merged_rec["revoked_target_models"],
                    sorted([target_model, "tinfoil-kimi-k3-1-pro"]),
                )

                # 4. Identical explicit --target-model retry resumes partial cleanup and exits 0!
                with mock.patch.object(cont_mod, "_list_current_uid_ps_commands", return_value=([], True)):
                    rc_ok, rep_ok, err_ok = cont_mod.apply_containment(
                        home_dir=home_dir,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id=inc_id,
                        target_model_id=target_model,
                    )
                self.assertEqual(rc_ok, 0, err_ok)
                assert rep_ok is not None
                self.assertIs(rep_ok["containment_clean"], True)
                self.assertFalse(retry_cfg.exists())

                receipts = list(ev_dir.glob(".containment-state-*.json"))
                self.assertEqual(len(receipts), 1)
                rec_text = receipts[0].read_text(encoding="utf-8")
                self.assertEqual(receipts[0].stat().st_mode & 0o777, 0o400)
                self.assertNotIn(canary_tok, rec_text)
                self.assertNotIn(canary_sha, rec_text)
                rec_obj = json.loads(rec_text)
                self.assertEqual(rec_obj["state"], "completed")
                self.assertIn(target_model, rec_obj.get("revoked_target_models", []))
            finally:
                for p in (proxy_proc, holder_proc):
                    if p.poll() is None:
                        p.kill()
                        p.wait(timeout=5)
                    for pipe in (p.stdout, p.stderr):
                        if pipe is not None:
                            pipe.close()

    def test_live_opencode_url_service_record_and_launch_strict_validation(self) -> None:
        from unittest import mock
        from local_assist import launch as launch_mod

        cont_mod = _load_script_module("check_containment_live_url", "scripts/check-credential-containment")
        native_oc_bin = _get_native_opencode_test_binary()

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp).resolve()
            home_dir = tmp_dir / "legacy_home"
            runs_dir = tmp_dir / "runs"
            ev_dir = tmp_dir / "evidence_bundle"
            (home_dir / ".local" / "state" / "opencode").mkdir(parents=True)
            (home_dir / ".local" / "share" / "opencode").mkdir(parents=True)
            (home_dir / ".config" / "opencode").mkdir(parents=True)
            runs_dir.mkdir(parents=True)
            ev_dir.mkdir(parents=True)

            inc_id = "LIVE-URL-001"
            marker = ev_dir / "marker.log"
            marker.write_text("evidence\n", encoding="utf-8")
            ev_path = ev_dir / "ev.json"
            ev_path.write_text(
                json.dumps(
                    {
                        "incident_id": inc_id,
                        "target_home": str(home_dir),
                        "artifacts": {
                            str(marker): hashlib.sha256(marker.read_bytes()).hexdigest()
                        },
                    }
                ),
                encoding="utf-8",
            )
            svc_file = home_dir / ".local" / "state" / "opencode" / "service.json"

            # 1. Parser accepts valid IPv4/localhost/IPv6 loopback URLs and rejects all malformed/non-loopback/conflicting forms
            svc_file.write_text(
                json.dumps(
                    {
                        "id": "oc-ipv6",
                        "password": "pw-ipv6-12345678",
                        "pid": 4242,
                        "url": "http://[::1]:49374",
                        "version": "2.0.32",
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                cont_mod._parse_legacy_service_record(svc_file, home_dir),
                (True, 4242, 49374, None, False),
            )
            svc_file.write_text(
                json.dumps(
                    {
                        "id": "oc-agree",
                        "password": "pw-agree-12345678",
                        "pid": 4242,
                        "port": 49374,
                        "url": "https://localhost:49374/",
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                cont_mod._parse_legacy_service_record(svc_file, home_dir),
                (True, 4242, 49374, None, False),
            )

            bad_records = [
                {"pid": None, "url": "http://127.0.0.1:49374"},
                {"pid": 4242, "port": None, "url": "http://127.0.0.1:49374"},
                {"pid": 4242, "url": None},
                {"pid": 4242, "port": True},
                {"pid": 4242, "port": 0},
                {"pid": 4242, "port": 65536},
                {"pid": 4242, "url": ""},
                {"pid": 4242, "url": "http://127.0.0.1"},
                {"pid": 4242, "url": "http://127.0.0.1:0"},
                {"pid": 4242, "url": "http://127.0.0.1:99999"},
                {"pid": 4242, "url": "http://127.0.0.1:abc"},
                {"pid": 4242, "url": "http://[::1:49374"},
                {"pid": 4242, "url": "ftp://127.0.0.1:49374"},
                {"pid": 4242, "url": "http://example.com:49374"},
                {"pid": 4242, "url": "http://0.0.0.0:49374"},
                {"pid": 4242, "url": "http://user:pw@127.0.0.1:49374"},
                {"pid": 4242, "url": "http://127.0.0.1:49374/api"},
                {"pid": 4242, "url": "http://127.0.0.1:49374?x=1"},
                {"pid": 4242, "url": "http://127.0.0.1:49374#frag"},
                {"pid": 4242, "port": 49374, "url": "http://127.0.0.1:49375"},
            ]
            for bad_rec in bad_records:
                svc_file.write_text(json.dumps(bad_rec), encoding="utf-8")
                self.assertEqual(
                    cont_mod._parse_legacy_service_record(svc_file, home_dir),
                    (False, None, None, None, False),
                    f"Expected fail-closed rejection for malformed record: {bad_rec!r}",
                )

            # 2. Live native `opencode serve --service` with OpenCode 2.0.32 url-only service.json -> holder_inspection_ok=True and stopped cleanly
            svc_proc = subprocess.Popen(
                [str(native_oc_bin), "serve", "--service"],
                env={
                    "HOME": str(home_dir),
                    "OPENCODE_TEST_HOME": str(home_dir),
                    "PATH": "/usr/bin:/bin",
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                assert svc_proc.stdout is not None
                live_port = int(svc_proc.stdout.readline().strip())

                # Conflict/malformed URL against a live genuine service must refuse with zero signals
                signals_sent: list[tuple[int, int]] = []
                real_kill = os.kill

                def _spy_kill(pid: int, sig: int) -> None:
                    signals_sent.append((pid, int(sig)))
                    return real_kill(pid, sig)

                svc_file.write_text(
                    json.dumps(
                        {
                            "id": "oc-bad-url",
                            "password": "pw-bad-url-12345678",
                            "pid": svc_proc.pid,
                            "url": f"http://example.com:{live_port}",
                            "version": "2.0.32",
                        }
                    ),
                    encoding="utf-8",
                )
                with mock.patch("os.kill", side_effect=_spy_kill):
                    rc_bad, _, _ = cont_mod.apply_containment(
                        home_dir=home_dir,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id=inc_id,
                    )
                self.assertEqual(rc_bad, 1)
                self.assertEqual(signals_sent, [])
                self.assertIsNone(svc_proc.poll())

                # Valid OpenCode 2.0.32 url-only service.json -> holder_inspection_ok=True, active_opencode_holders=1 (matched!), apply stops 1 service and leaves 0 holders!
                svc_file.write_text(
                    json.dumps(
                        {
                            "id": "oc-live-url",
                            "password": "pw-live-url-12345678",
                            "pid": svc_proc.pid,
                            "url": f"http://127.0.0.1:{live_port}",
                            "version": "2.0.32",
                        }
                    ),
                    encoding="utf-8",
                )
                chk = cont_mod.inspect_containment_state(
                    home_dir=home_dir,
                    runs_dir=runs_dir,
                    evidence_path=ev_path,
                    incident_id=inc_id,
                )
                self.assertIs(chk["holder_inspection_ok"], True)
                self.assertEqual(chk["active_opencode_holders"], 1)

                rc_ok, rep_ok, err_ok = cont_mod.apply_containment(
                    home_dir=home_dir,
                    runs_dir=runs_dir,
                    evidence_path=ev_path,
                    incident_id=inc_id,
                )
                self.assertEqual(rc_ok, 0, err_ok)
                assert rep_ok is not None
                self.assertEqual(rep_ok["legacy_services_stopped"], 1)
                self.assertEqual(rep_ok["active_opencode_holders"], 0)
                self.assertIsNotNone(svc_proc.wait(timeout=5))

                # 3. launch.py strict service.json url/port validation across sidecar binding and cleanup
                scope_dir = tmp_dir / "inv_scope"
                state_rel = Path(".state") / "opencode" / "service.json"
                cfg_rel = Path(".config") / "opencode" / "service.json"
                (scope_dir / state_rel.parent).mkdir(parents=True)
                (scope_dir / cfg_rel.parent).mkdir(parents=True)

                svc_proc2 = subprocess.Popen(
                    [str(native_oc_bin), "serve", "--service"],
                    env={
                        "HOME": str(scope_dir),
                        "OPENCODE_TEST_HOME": str(scope_dir),
                        "PATH": "/usr/bin:/bin",
                    },
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    assert svc_proc2.stdout is not None
                    port2 = int(svc_proc2.stdout.readline().strip())
                    state_file = scope_dir / state_rel
                    sc_path = scope_dir / "service-identity.json"

                    # Malformed/null/conflicting port or url in state_svc_file must fail closed in both bind and cleanup!
                    for bad_state in (
                        {"pid": svc_proc2.pid, "port": None, "url": f"http://127.0.0.1:{port2}"},
                        {"pid": svc_proc2.pid, "url": None},
                        {"pid": svc_proc2.pid, "url": f"http://example.com:{port2}"},
                        {"pid": svc_proc2.pid, "port": port2, "url": f"http://127.0.0.1:{port2 + 1}"},
                    ):
                        state_file.write_text(json.dumps(bad_state), encoding="utf-8")
                        self.assertIs(
                            launch_mod._try_bind_service_identity_sidecar(
                                scope_dir=scope_dir,
                                state_svc_file=state_file,
                                sidecar_path=sc_path,
                                scope_id="inv12345678",
                                service_port=None,
                            ),
                            False,
                        )
                        self.assertIs(
                            launch_mod._cleanup_scope_opencode_service(
                                scope_dir,
                                state_svc_rel=state_rel,
                                sidecar_name="service-identity.json",
                                cfg_svc_rel=cfg_rel,
                                scope_id="inv12345678",
                            ),
                            False,
                        )
                        self.assertIsNone(svc_proc2.poll())

                    # Valid url-only state_svc_file binds service_port=port2!
                    state_file.write_text(
                        json.dumps({"pid": svc_proc2.pid, "url": f"http://127.0.0.1:{port2}"}),
                        encoding="utf-8",
                    )
                    self.assertIs(
                        launch_mod._try_bind_service_identity_sidecar(
                            scope_dir=scope_dir,
                            state_svc_file=state_file,
                            sidecar_path=sc_path,
                            scope_id="inv12345678",
                            service_port=None,
                        ),
                        True,
                    )
                    bound_sc = json.loads(sc_path.read_text(encoding="utf-8"))
                    self.assertEqual(bound_sc["service_port"], port2)

                    # Work Review Major 1a: With a VALID sidecar present, malformed or conflicting state_svc
                    # MUST fail closed BEFORE invoking _terminate_bound_opencode_service (0 calls)!
                    for bad_state_with_sidecar in (
                        {"pid": svc_proc2.pid, "port": port2, "url": f"http://127.0.0.1:{port2 + 1}"},
                        {"pid": svc_proc2.pid, "port": None, "url": f"http://127.0.0.1:{port2}"},
                        {"pid": svc_proc2.pid, "url": f"http://example.com:{port2}"},
                        {"pid": svc_proc2.pid, "port": port2 + 1},
                        {"pid": None, "port": port2},
                    ):
                        state_file.write_text(json.dumps(bad_state_with_sidecar), encoding="utf-8")
                        with mock.patch.object(
                            launch_mod,
                            "_terminate_bound_opencode_service",
                            wraps=launch_mod._terminate_bound_opencode_service,
                        ) as spy_term:
                            self.assertIs(
                                launch_mod._cleanup_scope_opencode_service(
                                    scope_dir,
                                    state_svc_rel=state_rel,
                                    sidecar_name="service-identity.json",
                                    cfg_svc_rel=cfg_rel,
                                    scope_id="inv12345678",
                                    fallback_port=port2,
                                ),
                                False,
                                f"Expected False for state={bad_state_with_sidecar!r}",
                            )
                            self.assertEqual(
                                spy_term.call_count,
                                0,
                                f"Expected 0 termination calls on malformed/conflicting state={bad_state_with_sidecar!r}",
                            )
                        self.assertIsNone(svc_proc2.poll())

                    # Restore valid state_file, then test Work Review Major 1b:
                    # Invalid/conflicting cfg_svc_rel or owner.json + valid fallback_port + valid sidecar + valid state
                    # MUST fail closed with 0 termination calls!
                    state_file.write_text(
                        json.dumps({"pid": svc_proc2.pid, "url": f"http://127.0.0.1:{port2}"}),
                        encoding="utf-8",
                    )
                    cfg_file = scope_dir / cfg_rel
                    owner_file = scope_dir / "owner.json"
                    for bad_cfg in (
                        {"port": None},
                        {"url": "http://example.com:49374"},
                        {"port": port2, "url": f"http://127.0.0.1:{port2 + 1}"},
                        {"port": port2 + 1},
                        {"hostname": "0.0.0.0", "port": port2},
                    ):
                        cfg_file.write_text(json.dumps(bad_cfg), encoding="utf-8")
                        with mock.patch.object(
                            launch_mod,
                            "_terminate_bound_opencode_service",
                            wraps=launch_mod._terminate_bound_opencode_service,
                        ) as spy_term_cfg:
                            self.assertIs(
                                launch_mod._cleanup_scope_opencode_service(
                                    scope_dir,
                                    state_svc_rel=state_rel,
                                    sidecar_name="service-identity.json",
                                    cfg_svc_rel=cfg_rel,
                                    scope_id="inv12345678",
                                    fallback_port=port2,
                                ),
                                False,
                                f"Expected False for cfg={bad_cfg!r}",
                            )
                            self.assertEqual(
                                spy_term_cfg.call_count,
                                0,
                                f"Expected 0 termination calls on invalid/conflicting cfg={bad_cfg!r}",
                            )
                        self.assertIsNone(svc_proc2.poll())
                    cfg_file.unlink()

                    for bad_owner in (
                        {"service_port": "not-an-int"},
                        {"service_port": port2 + 1},
                    ):
                        owner_file.write_text(json.dumps(bad_owner), encoding="utf-8")
                        with mock.patch.object(
                            launch_mod,
                            "_terminate_bound_opencode_service",
                            wraps=launch_mod._terminate_bound_opencode_service,
                        ) as spy_term_owner:
                            self.assertIs(
                                launch_mod._cleanup_scope_opencode_service(
                                    scope_dir,
                                    state_svc_rel=state_rel,
                                    sidecar_name="service-identity.json",
                                    cfg_svc_rel=cfg_rel,
                                    scope_id="inv12345678",
                                    fallback_port=port2,
                                ),
                                False,
                                f"Expected False for owner={bad_owner!r}",
                            )
                            self.assertEqual(
                                spy_term_owner.call_count,
                                0,
                                f"Expected 0 termination calls on invalid/conflicting owner={bad_owner!r}",
                            )
                        self.assertIsNone(svc_proc2.poll())
                    owner_file.unlink()

                    # Finally, valid url-only state_svc_file (without sidecar) cleans up svc_proc2 cleanly!
                    sc_path.chmod(0o600)
                    sc_path.unlink()
                    self.assertIs(
                        launch_mod._cleanup_scope_opencode_service(
                            scope_dir,
                            state_svc_rel=state_rel,
                            sidecar_name="service-identity.json",
                            cfg_svc_rel=cfg_rel,
                            scope_id="inv12345678",
                        ),
                        True,
                    )
                    self.assertIsNotNone(svc_proc2.wait(timeout=5))
                finally:
                    if svc_proc2.poll() is None:
                        svc_proc2.kill()
                        svc_proc2.wait(timeout=5)
                    for pipe in (svc_proc2.stdout, svc_proc2.stderr):
                        if pipe is not None:
                            pipe.close()
            finally:
                if svc_proc.poll() is None:
                    svc_proc.kill()
                    svc_proc.wait(timeout=5)
                for pipe in (svc_proc.stdout, svc_proc.stderr):
                    if pipe is not None:
                        pipe.close()

    def test_streaming_log_scanner_large_base64_and_cumulative_cap_enforcement(self) -> None:
        import stat
        from unittest import mock

        cont_mod = _load_script_module("check_containment_stream_log", "scripts/check-credential-containment")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp).resolve()
            home_dir = tmp_dir / "legacy_home"
            log_dir = home_dir / ".local" / "share" / "opencode" / "log"
            spool_dir = home_dir / ".local" / "share" / "opencode" / "shell"
            log_dir.mkdir(parents=True)
            spool_dir.mkdir(parents=True)

            tok_start = "se-session-retiredStartToken9876543210abcdef"
            tok_mid = "se-session-retiredMidToken9876543210abcdef12"
            tok_end = "se-session-retiredEndToken9876543210abcdef34"
            tok_nested = "se-session-retiredNestedTok9876543210abcdef56"

            # Build >64 KiB (~160 KiB) base64 container with tokens at start, middle, and end, plus nested base64-inside-JSON-inside-base64
            filler_60k = "x" * 62000
            large_json = json.dumps(
                {
                    "a_start": tok_start,
                    "b_pad1": filler_60k,
                    "c_mid": tok_mid,
                    "d_pad2": filler_60k,
                    "e_end": tok_end,
                }
            )
            b64_large = base64.b64encode(large_json.encode("utf-8")).decode("ascii")
            self.assertGreater(len(b64_large), 150 * 1024)

            inner_b64 = base64.b64encode(json.dumps({"tok": tok_nested, "pad": "y" * 50000}).encode("utf-8")).decode("ascii")
            outer_b64 = base64.b64encode(json.dumps({"inner": inner_b64, "pad": "z" * 50000}).encode("utf-8")).decode("ascii")
            self.assertGreater(len(outer_b64), 130 * 1024)

            # Write a ~9.2 MiB (>8 MiB) opencode.log placing large containers across 2 MiB batch boundaries
            log_file = log_dir / "opencode.log"
            benign_line = (
                "2026-11-15T12:00:00Z INFO url=http://127.0.0.1/path%20space "
                "ansi=\\u001b[0m esc=\\\\\\\\n "
                + ("a" * 900)
                + "\n"
            )
            with log_file.open("w", encoding="utf-8") as fh:
                # ~2.0 MiB - 10 KiB
                for _ in range(2040):
                    fh.write(benign_line)
                fh.write(f"2026-11-15T12:01:00Z payload={b64_large}\n")
                # ~2.2 MiB more (total ~4.4 MiB)
                for _ in range(2200):
                    fh.write(benign_line)
                fh.write(f"2026-11-15T12:02:00Z nested={outer_b64}\n")
                # ~5.1 MiB more -> total > 9.5 MiB (> 9 * 1024 * 1024)
                for _ in range(5200):
                    fh.write(benign_line)
            self.assertGreater(log_file.stat().st_size, 9 * 1024 * 1024)

            tokens, ok = cont_mod._extract_persisted_session_tokens_in_memory(home_dir)
            self.assertIs(ok, True)
            self.assertEqual(
                set(tokens),
                {tok_start, tok_mid, tok_end, tok_nested},
            )

            # 1b. End-to-end apply_containment on >8 MiB opencode.log with >64 KiB base64 retired tokens:
            # sink_inspection_ok=True, and apply_containment refuses unattributed deletion when an active
            # attested proxy has rotated to a different generation token without --target-model!
            runs_dir = tmp_dir / "runs"
            ev_dir = tmp_dir / "evidence_bundle"
            runs_dir.mkdir(parents=True)
            ev_dir.mkdir(parents=True)
            marker = ev_dir / "marker.log"
            marker.write_text("evidence\n", encoding="utf-8")
            ev_path = ev_dir / "ev.json"
            ev_path.write_text(
                json.dumps(
                    {
                        "incident_id": "STREAM-LOG-001",
                        "target_home": str(home_dir),
                        "artifacts": {
                            str(marker): hashlib.sha256(marker.read_bytes()).hexdigest()
                        },
                    }
                ),
                encoding="utf-8",
            )
            rotated_tok = "se-session-activeRotatedToken1234567890abcdef"
            proxy_proc = subprocess.Popen(
                [sys.executable, "-c", "import time; print('P', flush=True); time.sleep(60)"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                assert proxy_proc.stdout is not None
                self.assertEqual(proxy_proc.stdout.readline().strip(), "P")
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as closed_sock:
                    closed_sock.bind(("127.0.0.1", 0))
                    unused_port = closed_sock.getsockname()[1]
                tok_file = runs_dir / ".se-session-tinfoil-deepseek-v4-1-flash.token"
                tok_file.write_text(
                    json.dumps(
                        {
                            "token": rotated_tok,
                            "generation": 2,
                            "session_id": "sess-rot-001",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                pid_file = runs_dir / ".serve.tinfoil-deepseek-v4-1-flash.pid"
                pid_file.write_text(
                    json.dumps(
                        {
                            "model_id": "tinfoil-deepseek-v4-1-flash",
                            "trust_tier": "enclave_runtime_attested",
                            "pid": proxy_proc.pid,
                            "pid_lstart": get_process_lstart(proxy_proc.pid),
                            "port": unused_port,
                            "session_token_file": str(tok_file),
                            "status": "ready",
                        }
                    ),
                    encoding="utf-8",
                )
                with mock.patch.object(cont_mod, "_list_current_uid_ps_commands", return_value=([], True)):
                    st_stream = cont_mod.inspect_containment_state(
                        home_dir=home_dir,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id="STREAM-LOG-001",
                    )
                    self.assertIs(st_stream["sink_inspection_ok"], True)
                    self.assertEqual(st_stream["ambiguous_proxy_sessions"], 1)
                    rc_ambig, _, err_ambig = cont_mod.apply_containment(
                        home_dir=home_dir,
                        runs_dir=runs_dir,
                        evidence_path=ev_path,
                        incident_id="STREAM-LOG-001",
                    )
                self.assertEqual(rc_ambig, 1)
                self.assertIn("ambiguous", err_ambig)
                self.assertTrue(log_file.exists())
                self.assertIsNone(proxy_proc.poll())
            finally:
                if proxy_proc.poll() is None:
                    proxy_proc.kill()
                    proxy_proc.wait(timeout=5)
                for pipe in (proxy_proc.stdout, proxy_proc.stderr):
                    if pipe is not None:
                        pipe.close()

            # 2. Unbroken single line > max_single_unit_chars fails closed (extract_ok=False)
            spool_file = spool_dir / "giant.out"
            spool_file.write_text("B" * 4096, encoding="utf-8")
            _, ok_unbroken = cont_mod._extract_persisted_session_tokens_in_memory(
                home_dir, max_single_unit_chars=2048
            )
            self.assertIs(ok_unbroken, False)
            spool_file.unlink()
            log_file.unlink()

            # 3. Cumulative byte-read cap: cap-1 and cap pass; cap+1 fails closed
            cap_test = 8192
            for sz, expected_ok in ((cap_test - 1, True), (cap_test, True), (cap_test + 1, False)):
                log_file.write_bytes(b"a" * (sz - 1) + b"\n")
                _, got_ok = cont_mod._extract_persisted_session_tokens_in_memory(
                    home_dir, max_file_bytes=cap_test
                )
                self.assertIs(got_ok, expected_ok, f"size={sz} vs cap={cap_test}")

            # 4. Concurrent growth after fstat (fstat reports < cap, os.read yields > cap) -> fails closed!
            log_file.write_bytes(b"small\n")
            real_os_read = os.read
            chunks_iter = iter([b"x" * 3000 + b"\n", b"y" * 3000 + b"\n", b""])
            with mock.patch("os.read", side_effect=lambda fd, n: next(chunks_iter, b"")):
                _, got_growth_ok = cont_mod._extract_persisted_session_tokens_in_memory(
                    home_dir, max_file_bytes=4096
                )
            self.assertIs(got_growth_ok, False)

            # 5. os.read OSError -> fails closed!
            with mock.patch("os.read", side_effect=OSError("simulated I/O read failure")):
                _, got_io_err_ok = cont_mod._extract_persisted_session_tokens_in_memory(home_dir)
            self.assertIs(got_io_err_ok, False)

            # 6. Deterministic post-_lstat_strict replacement with a writerless FIFO -> returns promptly with extract_ok=False and zero leaked FDs!
            log_file.unlink(missing_ok=True)
            log_file.write_bytes(b"regular\n")
            real_lstat = cont_mod._lstat_strict

            def _swap_to_fifo_after_lstat(p: Path):
                res = real_lstat(p)
                if p == log_file and p.exists() and not stat.S_ISFIFO(os.lstat(p).st_mode):
                    p.unlink()
                    os.mkfifo(p, 0o600)
                return res

            open_fds_before = len(os.listdir("/dev/fd"))
            t0 = time.monotonic()
            with mock.patch.object(cont_mod, "_lstat_strict", side_effect=_swap_to_fifo_after_lstat):
                _, got_fifo_ok = cont_mod._extract_persisted_session_tokens_in_memory(home_dir)
            elapsed_fifo = time.monotonic() - t0
            open_fds_after = len(os.listdir("/dev/fd"))
            self.assertIs(got_fifo_ok, False)
            self.assertLess(elapsed_fifo, 1.0, "Opening writerless FIFO must not block!")
            self.assertEqual(open_fds_after, open_fds_before, "File descriptor leaked on FIFO rejection!")
            log_file.unlink()

    def test_lsof_linux_usr_bin_fallback_and_transient_holder_retry(self) -> None:
        cont_mod = _load_script_module("containment_lsof_021", ROOT / "scripts" / "check-credential-containment")

        # 1. _resolve_default_lsof_bin selects /usr/bin/lsof when /usr/sbin/lsof is absent (Linux CI)
        with (
            mock.patch.dict(os.environ, {}, clear=False),
            mock.patch(
                "os.path.isfile",
                side_effect=lambda p: str(p) == "/usr/bin/lsof",
            ),
            mock.patch(
                "os.access",
                side_effect=lambda p, m: str(p) == "/usr/bin/lsof",
            ),
        ):
            os.environ.pop("FREE_INFERENCE_LSOF_BIN", None)
            resolved_lsof = cont_mod._resolve_default_lsof_bin()
            self.assertEqual(resolved_lsof, Path("/usr/bin/lsof"))

        # 2. _inspect_opencode_holders retries transient non-zero lsof exit once and succeeds,
        #    while failing closed if all 3 attempts fail.
        with tempfile.TemporaryDirectory() as td:
            home_dir = Path(td) / "home"
            (home_dir / ".local" / "share" / "opencode").mkdir(parents=True)
            fake_lsof = Path(td) / "fake_lsof"
            fake_lsof.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_lsof.chmod(0o755)

            attempts = {"count": 0}

            def _transient_lsof(cmd: list[str], **_kw: object) -> subprocess.CompletedProcess[str]:
                attempts["count"] += 1
                if attempts["count"] == 1:
                    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="transient reap")
                return subprocess.CompletedProcess(cmd, 0, stdout="p123\nn/tmp/unrelated\n", stderr="")

            with (
                mock.patch.object(cont_mod.subprocess, "run", side_effect=_transient_lsof),
                mock.patch.object(cont_mod.time, "sleep"),
            ):
                ok_retry, holders_retry = cont_mod._inspect_opencode_holders(
                    home_dir, [], lsof_bin=fake_lsof
                )
            self.assertIs(ok_retry, True)
            self.assertEqual(holders_retry, set())
            self.assertEqual(attempts["count"], 2)

            with (
                mock.patch.object(
                    cont_mod.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess(["lsof"], 1, stdout="", stderr="always fail"),
                ) as mock_fail_run,
                mock.patch.object(cont_mod.time, "sleep"),
            ):
                ok_fail, _ = cont_mod._inspect_opencode_holders(
                    home_dir, [], lsof_bin=fake_lsof
                )
            self.assertIs(ok_fail, False)
            self.assertEqual(mock_fail_run.call_count, 3)


if __name__ == "__main__":
    unittest.main()
