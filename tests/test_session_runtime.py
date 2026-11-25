from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
import tempfile
import subprocess
import os
import threading
import http.server
import http.client
import shutil
import socket
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from local_assist.session import control_request, control_path, SessionLeaseSupplier

_SHARED_BUILD_DIR: tempfile.TemporaryDirectory[str] | None = None
_SHARED_BINARIES: tuple[Path, Path] | None = None


def _get_shared_binaries() -> tuple[Path, Path]:
    global _SHARED_BUILD_DIR, _SHARED_BINARIES
    if _SHARED_BINARIES is not None:
        return _SHARED_BINARIES
    from local_assist.se_key import verify_swift_source
    verify_swift_source()
    (ROOT / 'bin').mkdir(exist_ok=True)
    _SHARED_BUILD_DIR = tempfile.TemporaryDirectory(prefix='session-build-', dir=ROOT / 'bin')
    test_bin = Path(_SHARED_BUILD_DIR.name) / 'proxy-test'
    rel_bin = Path(_SHARED_BUILD_DIR.name) / 'proxy-release'
    for binary, flags in [(test_bin, ['-D', 'SE_KEY_TESTING']), (rel_bin, [])]:
        subprocess.run(
            ['swiftc', '-module-cache-path', str(ROOT / '.home/swift-cache'),
             *flags, str(ROOT / 'tools/se_key_proxy/main.swift'), '-o', str(binary)],
            check=True, capture_output=True, timeout=120,
        )
    _SHARED_BINARIES = (test_bin, rel_bin)
    return _SHARED_BINARIES


def tearDownModule() -> None:
    global _SHARED_BUILD_DIR, _SHARED_BINARIES
    if _SHARED_BUILD_DIR is not None:
        _SHARED_BUILD_DIR.cleanup()
        _SHARED_BUILD_DIR = None
        _SHARED_BINARIES = None


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'requires macOS Swift')
class SessionRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary, cls.release = _get_shared_binaries()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='sw-', dir='/private/tmp')
        self.base = Path(self.tmp.name)
        self.model = 'session-model'
        self.token = 'se-session-' + 'a' * 64
        self.key = 'synthetic-provider-key-never-live'
        self.forwarded = []
        forwarded = self.forwarded
        class Upstream(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                forwarded.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
                body = getattr(self.server, 'failure_body', b'{"choices":[{"message":{"content":"ok"}}]}')
                self.send_response(401 if hasattr(self.server, 'failure_body') else 200)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Content-Type', 'application/json'); self.end_headers(); self.wfile.write(body)
        self.upstream = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
        threading.Thread(target=self.upstream.serve_forever, daemon=True).start()
        self.proc = None
        self.auth_writer = None

    def tearDown(self):
        if self.proc:
            self.proc.terminate()
            try: self.proc.wait(5)
            except subprocess.TimeoutExpired: self.proc.kill(); self.proc.wait()
            self.proc.stdout.close(); self.proc.stderr.close()
        if self.auth_writer is not None: os.close(self.auth_writer)
        self.upstream.shutdown(); self.upstream.server_close(); self.tmp.cleanup()

    def start(self, ttl=20, limit=5, fault=None):
        import socket
        from local_assist.registry import session_token_file_for_model, get_process_lstart
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0)); self.port = s.getsockname()[1]
        self.token_path = session_token_file_for_model(self.model, self.base)
        self.token_path.write_text(self.token); self.token_path.chmod(0o600)
        self.socket_path = control_path(self.base, self.model)
        (tr, tw), (kr, kw), (rr, rw), (ar, aw) = [os.pipe() for _ in range(4)]
        os.write(tw, self.token.encode()); os.close(tw)
        os.write(kw, self.key.encode()); os.close(kw)
        self.auth_writer = aw
        cmd = [str(self.binary), 'proxy', '--service', 'free-inference.synthetic-session',
            '--listen-port', str(self.port), '--upstream-url', f'http://127.0.0.1:{self.upstream.server_port}/v1',
            '--upstream-pid', str(os.getpid()), '--allowed-model', self.model,
            '--session-token-fd', str(tr), '--test-ephemeral-key-fd', str(kr),
            '--test-renewal-fd', str(ar), '--ready-fd', str(rw),
            '--session-token-file', str(self.token_path), '--control-socket', str(self.socket_path),
            '--ttl-seconds', str(ttl), '--max-chat-requests', str(limit), '--stream-timeout-seconds', '3']
        if fault is not None: cmd += ['--test-publication-fault', str(fault)]
        self.proc = subprocess.Popen(cmd, pass_fds=(tr, kr, ar, rw), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for fd in (tr, kr, ar, rw): os.close(fd)
        import select
        self.assertTrue(select.select([rr], [], [], 15)[0], 'proxy did not become ready')
        ready = os.read(rr, 512); os.close(rr)
        if not ready:
            self.fail('proxy initialization failed: ' + self.proc.stderr.read().decode()[:1000])
        self.assertEqual(json.loads(ready)['status'], 'ready')
        self.record = dict(model_id=self.model, repo=self.model, pid=self.proc.pid,
            pid_lstart=get_process_lstart(self.proc.pid), session_token_file=str(self.token_path), port=self.port)

    def control(self, request):
        return control_request(self.socket_path, request, expected_pid=self.proc.pid)

    def chat(self, token, port=None, nonce=None):
        c = http.client.HTTPConnection('127.0.0.1', port or self.port, timeout=5)
        body = json.dumps({'model': self.model, 'messages': [{'role': 'user', 'content': 'synthetic'}]})
        try:
            headers = {'Authorization': 'Bearer '+token, 'Content-Type': 'application/json'}
            if nonce is not None: headers['X-Session-Request-ID'] = nonce
            c.request('POST', '/v1/chat/completions', body, headers)
            r = c.getresponse(); return r.status, r.read()
        finally: c.close()

    def renew(self, info, allow=True, seconds=20):
        os.write(self.auth_writer, b'1' if allow else b'0')
        return self.control(dict(action='renew', seconds=seconds, session_id=info['session_id'], generation=info['generation']))

    def test_authoritative_status_atomic_budget_and_redaction(self):
        self.start(limit=3)
        info = self.control({'action': 'status'})
        self.assertEqual(info['requests_remaining'], 3)
        self.assertNotIn(self.token, json.dumps(info)); self.assertNotIn(self.key, json.dumps(info))
        with ThreadPoolExecutor(max_workers=6) as pool:
            statuses = list(pool.map(lambda _: self.chat(self.token)[0], range(6)))
        self.assertEqual(statuses.count(200), 3)
        self.assertEqual(statuses.count(429), 3)
        self.assertEqual(self.control({'action': 'status'})['requests_remaining'], 0)
        with self.assertRaises(ValueError): self.renew(info)

    def test_renew_rotates_without_restarting_or_refilling(self):
        self.start()
        self.assertEqual(self.chat(self.token)[0], 200)
        before = self.control({'action': 'status'})
        after = self.renew(before)
        envelope = json.loads(self.token_path.read_text())
        self.assertEqual(after['pid'], before['pid'])
        self.assertEqual(after['session_id'], before['session_id'])
        self.assertEqual(after['generation'], before['generation'] + 1)
        self.assertEqual(after['requests_remaining'], before['requests_remaining'])
        self.assertEqual(envelope['generation'], after['generation'])
        self.assertNotEqual(envelope['token'], self.token)
        self.assertEqual(self.chat(self.token)[0], 401)
        self.assertEqual(self.chat(envelope['token'])[0], 200)

    def test_stale_proof_is_only_issued_for_a_retired_session_credential(self):
        self.start()
        self.renew(self.control({'action': 'status'}))
        nonce = '1'*32
        status, body = self.chat('se-session-' + 'c'*64, nonce=nonce)
        self.assertEqual(status, 401)
        self.assertNotIn('proof', json.loads(body)['error'])
        self.assertNotIn('session_id', json.loads(body)['error'])
        status, body = self.chat(self.token, nonce=nonce)
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)['error']['code'], 'session_credential_stale')

    def test_cancelled_authorization_preserves_lease_and_credential(self):
        self.start()
        before = self.control({'action': 'status'}); envelope = self.token_path.read_bytes()
        with self.assertRaises(ValueError): self.renew(before, allow=False)
        after = self.control({'action': 'status'})
        self.assertEqual(after['generation'], before['generation'])
        self.assertEqual(after['expires_at'], before['expires_at'])
        self.assertEqual(self.token_path.read_bytes(), envelope)

    def test_publication_failure_before_rename_preserves_lease(self):
        self.start(fault=1)
        before = self.control({'action': 'status'}); raw = self.token_path.read_bytes()
        with self.assertRaises(ValueError): self.renew(before)
        self.assertEqual(self.control({'action': 'status'})['generation'], before['generation'])
        self.assertEqual(self.token_path.read_bytes(), raw)

    def test_publication_failure_after_rename_fails_closed(self):
        self.start(fault=2)
        before = self.control({'action': 'status'})
        with self.assertRaises((ValueError, OSError)): self.renew(before)
        self.assertEqual(self.proc.wait(5), 1)
        self.assertFalse(self.token_path.exists())
        with self.assertRaises(OSError): self.chat(self.token)

    def test_release_rejects_test_authorization_flags_before_touch_id(self):
        for flag in ['--test-renewal-fd', '--test-publication-fault']:
            p = subprocess.run([str(self.release), 'proxy', flag, '1'],
                               capture_output=True, timeout=5)
            self.assertEqual(p.returncode, 2)
            self.assertIn(b'Unknown proxy argument', p.stderr)

    def test_expiry_is_enforced_and_does_not_restart(self):
        self.start(ttl=1)
        self.assertEqual(self.proc.wait(5), 0)
        self.assertFalse(self.socket_path.exists()); self.assertFalse(self.token_path.exists())
        with self.assertRaises(OSError): self.chat(self.token)

    def test_control_works_under_a_checkout_path_longer_than_sun_path(self):
        self.base = self.base / ('deep-checkout-'*10)
        self.base.mkdir()
        self.start()
        self.assertGreater(len(str(self.socket_path).encode()), 103)
        self.assertEqual(self.control({'action': 'status'})['state'], 'ON')
        self.assertEqual(self.renew(self.control({'action': 'status'}))['generation'], 2)

    def test_stop_removes_socket_left_by_sigkill(self):
        from local_assist.registry import pid_file_for_model
        self.start()
        self.proc.kill(); self.proc.wait(5)
        self.assertTrue(self.socket_path.exists())
        pid_file_for_model(self.model, self.base).write_text(json.dumps(self.record))
        result = subprocess.run([sys.executable, str(ROOT/'scripts/stop-model'), self.model],
            env=dict(os.environ, FREE_INFERENCE_RUNS_DIR=str(self.base)), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.socket_path.exists())

    def test_attached_relay_survives_renewal_and_proven_stale_race(self):
        from local_assist.relay import SessionAuthRelay
        self.start()
        supplier = SessionLeaseSupplier(self.record, self.base)
        old = supplier()
        calls = 0
        def lease():
            nonlocal calls
            calls += 1
            if calls == 1:
                self.renew(old)
                return old  # Deliberately race rotation after the relay's lease read.
            return supplier()
        lease.refresh = supplier.refresh
        lease.check_connection = supplier.check_connection
        lease.close = supplier.close
        relay = SessionAuthRelay(upstream_base_url=f'http://127.0.0.1:{self.port}/v1',
            upstream_session_token=self.token, lease_provider=lease, max_chat_requests=5,
            ttl_seconds=1, follow_session_window=True, max_request_bytes=4096, upstream_timeout_seconds=3).start()
        try:
            self.assertEqual(self.chat(relay.relay_token, relay.port)[0], 200)
            self.assertEqual(len(self.forwarded), 1, 'retry must not double-forward or double-charge')
            self.assertEqual(self.chat(relay.relay_token, relay.port)[0], 200)
            self.assertEqual(len(self.forwarded), 2)
            self.assertEqual(self.control({'action': 'status'})['requests_remaining'], 3)
        finally: relay.close()

    def test_worker_follows_rotation_but_keeps_own_expiry(self):
        from local_assist.relay import _WorkerTokenRelay
        import time
        self.start()
        supplier = SessionLeaseSupplier(self.record, self.base)
        relay = _WorkerTokenRelay(upstream_base_url=f'http://127.0.0.1:{self.port}/v1',
            upstream_session_token=self.token, lease_provider=supplier, ttl_seconds=0.5,
            upstream_timeout_seconds=3).start()
        try:
            self.renew(self.control({'action': 'status'}))
            self.assertEqual(self.chat(relay.relay_token, relay.port)[0], 200)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                if self.chat(relay.relay_token, relay.port)[0] == 401:
                    break
                time.sleep(0.02)
            else: self.fail('worker outlived its independent deadline')
            self.assertEqual(self.control({'action': 'status'})['state'], 'ON')
        finally: relay.close()

    def test_cached_relay_refreshes_on_stale_token_after_operator_renewal(self):
        from local_assist.relay import SessionAuthRelay
        self.start()
        supplier = SessionLeaseSupplier(self.record, self.base)
        supplier()
        relay = SessionAuthRelay(upstream_base_url=f'http://127.0.0.1:{self.port}/v1',
            upstream_session_token=self.token, lease_provider=supplier,
            follow_session_window=True, upstream_timeout_seconds=3).start()
        try:
            self.renew(self.control({'action': 'status'}))
            self.assertEqual(self.chat(relay.relay_token, relay.port)[0], 200)
            self.assertEqual(len(self.forwarded), 1)
            self.assertEqual(supplier()['generation'], 2)
        finally: relay.close()

    def _assert_replacement_receives_no_request(self, *, expire):
        from local_assist.relay import SessionAuthRelay
        self.start(ttl=1 if expire else 20)
        supplier = SessionLeaseSupplier(self.record, self.base)
        supplier()
        relay = SessionAuthRelay(upstream_base_url=f'http://127.0.0.1:{self.port}/v1',
            upstream_session_token=self.token, lease_provider=supplier,
            follow_session_window=True, upstream_timeout_seconds=3).start()
        received = []
        class Replacement(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                received.append(True)
                self.rfile.read(int(self.headers['Content-Length']))
                body = b'{"choices":[{"message":{"content":"replacement"}}]}'
                self.send_response(200); self.send_header('Content-Length', str(len(body)))
                self.end_headers(); self.wfile.write(body)
        replacement = None
        try:
            if not expire: self.proc.kill()
            self.proc.wait(5)
            replacement = http.server.ThreadingHTTPServer(('127.0.0.1', self.port), Replacement)
            threading.Thread(target=replacement.serve_forever, daemon=True).start()
            status, _ = self.chat(relay.relay_token, relay.port)
            self.assertEqual(status, 401)
            self.assertEqual(len(received), 0, 'replacement received prompt or credential')
        finally:
            relay.close()
            if replacement: replacement.shutdown(); replacement.server_close()

    def test_expired_cached_relay_does_not_send_to_replacement_listener(self):
        self._assert_replacement_receives_no_request(expire=True)

    def test_renewed_proxy_remains_usable_after_cached_deadline(self):
        import time
        from local_assist.session import _continuous_time
        from local_assist.relay import SessionAuthRelay
        self.start(ttl=1)
        supplier = SessionLeaseSupplier(self.record, self.base)
        supplier()
        first_deadline = supplier._deadline
        self.renew(self.control({'action': 'status'}))
        relay = SessionAuthRelay(upstream_base_url=f'http://127.0.0.1:{self.port}/v1',
            upstream_session_token=self.token, lease_provider=supplier,
            follow_session_window=True, upstream_timeout_seconds=3).start()
        try:
            timeout = time.monotonic() + 3
            while _continuous_time() < first_deadline and time.monotonic() < timeout:
                time.sleep(0.01)
            self.assertGreaterEqual(_continuous_time(), first_deadline)
            self.assertEqual(self.chat(relay.relay_token, relay.port)[0], 200)
            self.assertEqual(supplier()['generation'], 2)
            self.assertEqual(self.control({'action': 'status'})['requests_remaining'], 4)
        finally: relay.close()

    def test_killed_proxy_cached_relay_does_not_send_to_replacement_listener(self):
        self._assert_replacement_receives_no_request(expire=False)

    def test_generation_history_is_bounded_without_resetting_requests(self):
        self.start(ttl=120)
        info = self.control({'action': 'status'})
        for _ in range(31): info = self.renew(info, seconds=120)
        self.assertEqual(info['generation'], 32)
        self.assertEqual(info['requests_remaining'], 5)
        with self.assertRaises(ValueError): self.renew(info, seconds=120)
        self.assertEqual(self.control({'action': 'status'})['generation'], 32)

    def test_control_rejects_wrong_identity_and_invalid_renew_without_authorizing(self):
        self.start()
        before = self.control({'action': 'status'})
        with self.assertRaises(ValueError):
            control_request(self.socket_path, {'action': 'status'}, expected_pid=os.getpid())
        for fields in [dict(seconds=86401), dict(seconds=True), dict(generation=0),
                       dict(session_id='other'), dict(unexpected='field')]:
            request = dict(action='renew', seconds=20, session_id=before['session_id'], generation=1)
            request.update(fields)
            with self.subTest(fields=fields), self.assertRaises(ValueError): self.control(request)
        self.assertEqual(self.control({'action': 'status'})['generation'], 1)

    def test_unproven_auth_refusal_is_never_retried(self):
        from local_assist.relay import SessionAuthRelay
        self.upstream.failure_body = b'{"error":{"code":"session_credential_stale","proof":"forged"}}'
        calls = 0
        def supplier():
            nonlocal calls
            calls += 1
            return dict(state='ON', remaining_seconds=20, session_id='same', pid=123,
                        generation=calls, token=self.token if calls == 1 else 'se-session-' + 'b'*64)
        relay = SessionAuthRelay(upstream_base_url=f'http://127.0.0.1:{self.upstream.server_port}/v1',
            upstream_session_token=self.token, lease_provider=supplier, upstream_timeout_seconds=3).start()
        try:
            status, body = self.chat(relay.relay_token, relay.port)
            self.assertEqual(status, 401)
            self.assertEqual(len(self.forwarded), 1)
            self.assertNotIn(b'forged', body)
        finally: relay.close()

    def test_expiry_during_authorization_cannot_resurrect_proxy(self):
        self.start(ttl=1)
        before = self.control({'action': 'status'})
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.control, dict(action='renew', seconds=20,
                session_id=before['session_id'], generation=before['generation']))
            self.assertEqual(self.proc.wait(5), 0)
            with self.assertRaises((ValueError, OSError)): pending.result(timeout=5)
        self.assertFalse(self.token_path.exists())

    def test_unavailable_refresh_returns_controlled_401_without_exception_text(self):
        from local_assist.relay import SessionAuthRelay
        self.upstream.failure_body = b'{"error":{"code":"session_expired"}}'
        calls = 0
        def supplier():
            nonlocal calls
            calls += 1
            if calls > 1: raise OSError('arbitrary-sensitive-store-error')
            return dict(state='ON', remaining_seconds=20, session_id='same', pid=123,
                        generation=1, token=self.token)
        relay = SessionAuthRelay(upstream_base_url=f'http://127.0.0.1:{self.upstream.server_port}/v1',
            upstream_session_token=self.token, lease_provider=supplier, upstream_timeout_seconds=3).start()
        try:
            status, body = self.chat(relay.relay_token, relay.port)
            self.assertEqual(status, 401)
            self.assertEqual(len(self.forwarded), 1)
            self.assertNotIn(b'sensitive-store', body)
        finally: relay.close()


class _RawScriptedUpstream:
    """Minimal raw-TCP HTTP server for exact wire-framing and timing tests."""
    def __init__(self, handler=None, *, bind_port: int = 0):
        self._handler = handler
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(('127.0.0.1', bind_port))
        self.port = self._sock.getsockname()[1]
        self._sock.listen(64)
        self._sock.settimeout(0.1)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

    def set_handler(self, handler) -> None:
        self._handler = handler

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._serve_conn, args=(conn,), daemon=True)
            self._threads.append(t)
            t.start()

    def _serve_conn(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5.0)
            handler = self._handler
            if handler is not None:
                handler(conn)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def read_http_request(conn: socket.socket) -> bytes:
        buf = bytearray()
        while b'\r\n\r\n' not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return bytes(buf)
            buf.extend(chunk)
        sep = buf.index(b'\r\n\r\n') + 4
        hdr_text = buf[:sep].decode('latin-1', errors='replace')
        content_len = 0
        for line in hdr_text.split('\r\n')[1:]:
            if line.lower().startswith('content-length:'):
                content_len = int(line.split(':', 1)[1].strip())
        while len(buf) - sep < content_len:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf)

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._accept_thread.join(timeout=2)
        for t in self._threads:
            t.join(timeout=1)


def _http_json_resp(body_bytes: bytes, status: str = '200 OK', extra_headers: bytes = b'') -> bytes:
    return (
        f'HTTP/1.1 {status}\r\n'
        f'Content-Type: application/json\r\n'
        f'Content-Length: {len(body_bytes)}\r\n'
        f'Connection: close\r\n'
    ).encode('ascii') + extra_headers + b'\r\n' + body_bytes


def _chunked_bytes(chunks: list[bytes], trailer: bytes = b'\r\n') -> bytes:
    out = bytearray()
    for ch in chunks:
        out.extend(f'{len(ch):x}\r\n'.encode('ascii'))
        out.extend(ch)
        out.extend(b'\r\n')
    out.extend(b'0\r\n')
    out.extend(trailer)
    return bytes(out)


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'requires macOS Swift')
class LiveSpendMeteringRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary, cls.release = _get_shared_binaries()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='lsm-', dir='/private/tmp')
        self.base = Path(self.tmp.name)
        self.model = 'session-model'
        self.token = 'se-session-' + 'a' * 64
        self.key = 'synthetic-provider-key-never-live'
        self.upstream: _RawScriptedUpstream | None = _RawScriptedUpstream()
        self.proc = None
        self.auth_writer = None

    def tearDown(self):
        self._stop_proxy()
        if self.upstream is not None:
            self.upstream.close()
            self.upstream = None
        self.tmp.cleanup()

    def _stop_proxy(self):
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
            if self.proc.stdout:
                self.proc.stdout.close()
            if self.proc.stderr:
                self.proc.stderr.close()
            self.proc = None
        if self.auth_writer is not None:
            os.close(self.auth_writer)
            self.auth_writer = None

    def start(
        self,
        *,
        ttl: int = 60,
        limit: int = 50,
        price_in: str | None = '1.0',
        price_out: str | None = '2.0',
        price_cached: str | None = '0.25',
        max_actual_usd: str | None = None,
        max_tokens_cap: int = 256,
        max_request_bytes: int | None = None,
        stream_timeout: int = 3,
        force_urlsession: bool = False,
        upstream_port: int | None = None,
        binary: Path | None = None,
    ):
        self._stop_proxy()
        import select
        from local_assist.registry import session_token_file_for_model
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            self.port = s.getsockname()[1]
        self.token_path = session_token_file_for_model(self.model, self.base)
        self.token_path.write_text(self.token)
        self.token_path.chmod(0o600)
        self.socket_path = control_path(self.base, self.model)
        if self.socket_path.exists():
            self.socket_path.unlink()
        (tr, tw), (kr, kw), (rr, rw), (ar, aw) = [os.pipe() for _ in range(4)]
        os.write(tw, self.token.encode()); os.close(tw)
        os.write(kw, self.key.encode()); os.close(kw)
        self.auth_writer = aw
        uport = upstream_port if upstream_port is not None else self.upstream.port
        cmd = [
            str(binary or self.binary), 'proxy',
            '--service', 'free-inference.synthetic-lsm',
            '--listen-port', str(self.port),
            '--upstream-url', f'http://127.0.0.1:{uport}/v1',
            '--upstream-pid', str(os.getpid()),
            '--allowed-model', self.model,
            '--session-token-fd', str(tr),
            '--test-ephemeral-key-fd', str(kr),
            '--test-renewal-fd', str(ar),
            '--ready-fd', str(rw),
            '--session-token-file', str(self.token_path),
            '--control-socket', str(self.socket_path),
            '--ttl-seconds', str(ttl),
            '--max-chat-requests', str(limit),
            '--max-tokens-cap', str(max_tokens_cap),
            '--stream-timeout-seconds', str(stream_timeout),
        ]
        if price_in is not None:
            cmd += ['--price-input-per-m', price_in]
        if price_out is not None:
            cmd += ['--price-output-per-m', price_out]
        if price_cached is not None:
            cmd += ['--price-cached-input-per-m', price_cached]
        if max_actual_usd is not None:
            cmd += ['--max-actual-usd', max_actual_usd]
        if max_request_bytes is not None:
            cmd += ['--max-request-bytes', str(max_request_bytes)]
        if force_urlsession:
            cmd += ['--test-force-urlsession']
        self.proc = subprocess.Popen(
            cmd, pass_fds=(tr, kr, ar, rw), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        for fd in (tr, kr, ar, rw):
            os.close(fd)
        self.assertTrue(select.select([rr], [], [], 15)[0], 'proxy did not become ready')
        ready = os.read(rr, 512)
        os.close(rr)
        if not ready:
            self.fail('proxy initialization failed: ' + self.proc.stderr.read().decode()[:1000])
        self.assertEqual(json.loads(ready)['status'], 'ready')

    def control(self, req: dict):
        return control_request(self.socket_path, req, expected_pid=self.proc.pid)

    def renew(self, info: dict, allow: bool = True, seconds: int = 60):
        os.write(self.auth_writer, b'1' if allow else b'0')
        return self.control(dict(
            action='renew', seconds=seconds,
            session_id=info['session_id'], generation=info['generation'],
        ))

    def chat(self, token: str | None = None, content: str = 'hello', timeout: float = 8.0, nonce: str | None = None):
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=timeout)
        body = json.dumps({'model': self.model, 'messages': [{'role': 'user', 'content': content}]})
        headers = {'Authorization': 'Bearer ' + (token or self.token), 'Content-Type': 'application/json'}
        if nonce is not None:
            headers['X-Session-Request-ID'] = nonce
        try:
            c.request('POST', '/v1/chat/completions', body, headers)
            r = c.getresponse()
            return r.status, r.read()
        finally:
            c.close()

    def test_json_usage_all_cached_keys_zero_vs_unknown_and_rejections(self):
        self.start(price_in='1.0', price_out='2.0', price_cached='0.25')
        # 1. All 4 cached keys + explicit null + valid zero usage + no prompt/response/secret in status
        prompt_canary = 'CANARY_PROMPT_SECRET_9911'
        resp_canary = 'CANARY_ASSISTANT_REPLY_7733'
        valid_cases = [
            ('prompt_tokens_details', b'{"choices":[{"message":{"content":"' + resp_canary.encode() + b'"}}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"prompt_tokens_details":{"cached_tokens":400}}}', 1000, 400, 500),
            ('cached_prompt_tokens', b'{"choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":0,"cached_prompt_tokens":200,"cached_tokens":null}}', 1000, 200, 0),
            ('cached_tokens', b'{"choices":[],"usage":{"prompt_tokens":500,"completion_tokens":100,"cached_tokens":100}}', 500, 100, 100),
            ('prompt_cache_hit_tokens', b'{"choices":[],"usage":{"prompt_tokens":600,"completion_tokens":200,"prompt_cache_hit_tokens":300,"prompt_tokens_details":null}}', 600, 300, 200),
            ('valid_zero_usage', b'{"choices":[],"usage":{"prompt_tokens":0,"completion_tokens":0}}', 0, 0, 0),
            ('valid_utf8_multibyte', '{"choices":[{"message":{"content":"caf\u00e9\U0001f680"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}'.encode('utf-8'), 10, 0, 5),
        ]
        exp_p = exp_c = exp_o = 0
        for idx, (label, body, dp, dc, do) in enumerate(valid_cases, start=1):
            def _h(conn, b=body):
                _RawScriptedUpstream.read_http_request(conn)
                conn.sendall(_http_json_resp(b))
            self.upstream.set_handler(_h)
            st, _ = self.chat(content=prompt_canary)
            self.assertEqual(st, 200, label)
            exp_p += dp; exp_c += dc; exp_o += do
            info = self.control({'action': 'status'})
            self.assertEqual(info['prompt_tokens'], exp_p, label)
            self.assertEqual(info['cached_prompt_tokens'], exp_c, label)
            self.assertEqual(info['completion_tokens'], exp_o, label)
            self.assertEqual(info['usage_reported_requests'], idx, label)
            self.assertEqual(info['usage_unreported_requests'], 0, label)
            dumped = json.dumps(info)
            self.assertNotIn(prompt_canary, dumped)
            self.assertNotIn(resp_canary, dumped)
            self.assertNotIn(self.token, dumped)
            self.assertNotIn(self.key, dumped)
        # Expected spend: uncached=2110 * 1.0 + cached=1000 * 0.25 + completion=805 * 2.0 = 3970 microUsd
        self.assertEqual(self.control({'action': 'status'})['estimated_micro_usd'], 3970)

        # 2. Invalid usage JSON cases (duplicate keys, float, exponent, bool, negative, leading-zero, conflicting cached, cached>prompt, raw invalid UTF-8 in keys/values, missing)
        invalid_bodies = [
            ('dup_top_usage', b'{"usage":{"prompt_tokens":10,"completion_tokens":5},"usage":{"prompt_tokens":10,"completion_tokens":5}}'),
            ('dup_metered_key', b'{"usage":{"prompt_tokens":10,"prompt_tokens":10,"completion_tokens":5}}'),
            ('float_token', b'{"usage":{"prompt_tokens":10.0,"completion_tokens":5}}'),
            ('exponent_token', b'{"usage":{"prompt_tokens":1e2,"completion_tokens":5}}'),
            ('bool_token', b'{"usage":{"prompt_tokens":true,"completion_tokens":5}}'),
            ('negative_token', b'{"usage":{"prompt_tokens":-1,"completion_tokens":5}}'),
            ('leading_zero_token', b'{"usage":{"prompt_tokens":01,"completion_tokens":5}}'),
            ('conflicting_cached', b'{"usage":{"prompt_tokens":100,"completion_tokens":5,"cached_prompt_tokens":10,"cached_tokens":20}}'),
            ('cached_gt_prompt', b'{"usage":{"prompt_tokens":10,"completion_tokens":5,"cached_prompt_tokens":11}}'),
            ('invalid_utf8_in_value', b'{"choices":"\xff","usage":{"prompt_tokens":10,"completion_tokens":5}}'),
            ('invalid_utf8_overlong_value', b'{"choices":"\xc0\xaf","usage":{"prompt_tokens":10,"completion_tokens":5}}'),
            ('invalid_utf8_surrogate_value', b'{"choices":"\xed\xa0\x80","usage":{"prompt_tokens":10,"completion_tokens":5}}'),
            ('invalid_utf8_in_key', b'{"bad\xffkey":1,"usage":{"prompt_tokens":10,"completion_tokens":5}}'),
            ('missing_usage', b'{"choices":[{"message":{"content":"no usage"}}]}'),
            ('usage_null', b'{"choices":[],"usage":null}'),
        ]
        for idx, (label, body) in enumerate(invalid_bodies, start=1):
            def _h(conn, b=body):
                _RawScriptedUpstream.read_http_request(conn)
                conn.sendall(_http_json_resp(b))
            self.upstream.set_handler(_h)
            st, _ = self.chat()
            self.assertEqual(st, 200, label)
            info = self.control({'action': 'status'})
            self.assertEqual(info['prompt_tokens'], exp_p, label)
            self.assertEqual(info['usage_reported_requests'], len(valid_cases), label)
            self.assertEqual(info['usage_unreported_requests'], idx, label)

    def test_sse_streaming_chunked_multiline_escapes_done_and_unfinished_eof(self):
        self.start(price_in='1.0', price_out='2.0', price_cached='0.5')

        def _send_sse_chunked(payload: bytes, slice_size: int = 7):
            chunks = [payload[i:i + slice_size] for i in range(0, len(payload), slice_size)]
            raw = (
                b'HTTP/1.1 200 OK\r\n'
                b'Content-Type: text/event-stream; charset=utf-8\r\n'
                b'Transfer-Encoding: chunked\r\n'
                b'Connection: close\r\n\r\n'
            ) + _chunked_bytes(chunks)
            def _h(conn, data=raw):
                _RawScriptedUpstream.read_http_request(conn)
                for i in range(0, len(data), 11):
                    conn.sendall(data[i:i + 11])
            return _h

        # 1. Valid multi-line SSE, escaped "us\u0061ge" & "prompt_\u0074okens", last-chunk-wins, [DONE]
        sse_ok = (
            b': comment line\n'
            b'event: message\n'
            b'data: {"choices":[],"usage":{"prompt_tokens":50,"completion_tokens":10}}\n\n'
            b'data: {"choices":[],\n'
            b'data: "us\\u0061ge":{"prompt_\\u0074okens":1000,"completion_tokens":200,"cached_tokens":200}}\r\n\r\n'
            b'data: [DONE]\n\n'
        )
        self.upstream.set_handler(_send_sse_chunked(sse_ok))
        st, _ = self.chat()
        self.assertEqual(st, 200)
        info = self.control({'action': 'status'})
        self.assertEqual((info['prompt_tokens'], info['cached_prompt_tokens'], info['completion_tokens']), (1000, 200, 200))
        self.assertEqual((info['usage_reported_requests'], info['usage_unreported_requests']), (1, 0))

        # 2. Terminal invalid usage overrides earlier valid usage, post-[DONE] invalidates, unfinished SSE at clean EOF invalidates
        bad_sse_cases = [
            ('terminal_invalid_usage', b'data: {"usage":{"prompt_tokens":100,"completion_tokens":10}}\n\ndata: {"usage":{"prompt_tokens":1.5,"completion_tokens":10}}\n\ndata: [DONE]\n\n'),
            ('post_done_event', b'data: {"usage":{"prompt_tokens":100,"completion_tokens":10}}\n\ndata: [DONE]\n\ndata: {"extra":1}\n\n'),
            ('unfinished_nonempty_data', b'data: {"usage":{"prompt_tokens":100,"completion_tokens":10}}\n\ndata: {"usage":{"prompt_tokens":200,"completion_tokens":20}}\n'),
            ('unfinished_empty_data_colon', b'data: {"usage":{"prompt_tokens":100,"completion_tokens":10}}\n\ndata:\n'),
            ('unfinished_bare_colonless_data', b'data: {"usage":{"prompt_tokens":100,"completion_tokens":10}}\n\ndata\n'),
        ]
        for idx, (label, payload) in enumerate(bad_sse_cases, start=1):
            self.upstream.set_handler(_send_sse_chunked(payload, slice_size=13))
            st, _ = self.chat()
            self.assertEqual(st, 200, label)
            info = self.control({'action': 'status'})
            self.assertEqual(info['prompt_tokens'], 1000, label)
            self.assertEqual(info['usage_unreported_requests'], idx, label)

        # Verify capped session sets spend_indeterminate on unfinished bare colonless `data\n`
        self.start(price_in='1.0', price_out='2.0', max_actual_usd='5.00', max_tokens_cap=256)
        self.upstream.set_handler(_send_sse_chunked(b'data: {"usage":{"prompt_tokens":100,"completion_tokens":10}}\n\ndata\n'))
        st, _ = self.chat()
        self.assertEqual(st, 200)
        info_cap = self.control({'action': 'status'})
        self.assertTrue(info_cap['spend_indeterminate'])
        st2, body2 = self.chat()
        self.assertEqual(st2, 429)
        self.assertEqual(json.loads(body2)['error']['code'], 'session_spend_indeterminate')

        # 3. Leading UTF-8 BOM (SSE standard §9.2.6): single BOM stripped (whole & split 1-byte chunks), double BOM leaves 2nd BOM
        self.start(price_in='1.0', price_out='2.0', max_actual_usd='5.00', max_tokens_cap=256)
        bom_single = b'\xef\xbb\xbfdata: {"choices":[],"usage":{"prompt_tokens":200,"completion_tokens":40}}\n\ndata: [DONE]\n\n'
        self.upstream.set_handler(_send_sse_chunked(bom_single, slice_size=len(bom_single)))
        st_b1, body_b1 = self.chat()
        self.assertEqual(st_b1, 200)
        self.assertEqual(body_b1, bom_single)
        info_b1 = self.control({'action': 'status'})
        self.assertEqual((info_b1['prompt_tokens'], info_b1['completion_tokens']), (200, 40))
        self.assertFalse(info_b1['spend_indeterminate'])

        # Split BOM across 1-byte chunks (0xEF, 0xBB, 0xBF in separate chunks)
        self.upstream.set_handler(_send_sse_chunked(bom_single, slice_size=1))
        st_b2, body_b2 = self.chat()
        self.assertEqual(st_b2, 200)
        self.assertEqual(body_b2, bom_single)
        info_b2 = self.control({'action': 'status'})
        self.assertEqual((info_b2['prompt_tokens'], info_b2['completion_tokens']), (400, 80))
        self.assertFalse(info_b2['spend_indeterminate'])

        # Double BOM: only one leading BOM is consumed, so the second hides the first event's field name
        bom_double = b'\xef\xbb\xbf\xef\xbb\xbfdata: {"choices":[],"usage":{"prompt_tokens":200,"completion_tokens":40}}\n\ndata: [DONE]\n\n'
        self.upstream.set_handler(_send_sse_chunked(bom_double, slice_size=1))
        st_b3, _ = self.chat()
        self.assertEqual(st_b3, 200)
        info_b3 = self.control({'action': 'status'})
        self.assertEqual((info_b3['prompt_tokens'], info_b3['completion_tokens']), (400, 80))
        self.assertTrue(info_b3['spend_indeterminate'])

    def test_strict_raw_byte_posix_framing_and_obs_text(self):
        good_json = b'{"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":50}}'

        # 1. Legal obs-text (0x80-0xFF) in non-framing header settles cleanly on capped session
        self.start(price_in='1.0', price_out='2.0', max_actual_usd='5.00', max_tokens_cap=256)
        raw_obs = _http_json_resp(good_json, extra_headers=b'X-Obs: \x80\xfe\xff\r\n')
        self.upstream.set_handler(lambda conn: (_RawScriptedUpstream.read_http_request(conn), conn.sendall(raw_obs)))
        st, _ = self.chat()
        self.assertEqual(st, 200)
        info = self.control({'action': 'status'})
        self.assertEqual((info['prompt_tokens'], info['completion_tokens']), (100, 50))
        self.assertFalse(info['spend_indeterminate'])

        # 2. Malformed framing cases -> uncapped increments usage_unreported_requests without settling; capped sets spend_indeterminate
        chunk_body = _chunked_bytes([good_json])
        bad_raw_cases = [
            ('status_http_1_9', b'HTTP/1.9 200 OK\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(good_json)).encode() + b'\r\n\r\n' + good_json),
            ('status_missing_separator', b'HTTP/1.1 200\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(good_json)).encode() + b'\r\n\r\n' + good_json),
            ('status_extra_space', b'HTTP/1.1  200 OK\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(good_json)).encode() + b'\r\n\r\n' + good_json),
            ('colonless_header', _http_json_resp(good_json, extra_headers=b'BadHeaderWithoutColon\r\n')),
            ('whitespace_header_name', _http_json_resp(good_json, extra_headers=b'X Bad: 1\r\n')),
            ('dup_content_length', b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(good_json)).encode() + b'\r\nContent-Length: ' + str(len(good_json)).encode() + b'\r\nConnection: close\r\n\r\n' + good_json),
            ('invalid_content_length', b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12abc\r\nConnection: close\r\n\r\n' + good_json),
            ('dup_transfer_encoding', b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n' + chunk_body),
            ('non_chunked_te', b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: gzip\r\nConnection: close\r\n\r\n' + good_json),
            ('te_and_cl_conflict', b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nContent-Length: ' + str(len(good_json)).encode() + b'\r\nConnection: close\r\n\r\n' + chunk_body),
            ('chunk_ext_empty', b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n' + f'{len(good_json):x};\r\n'.encode() + good_json + b'\r\n0\r\n\r\n'),
            ('chunk_ext_named', b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n' + f'{len(good_json):x};foo=bar\r\n'.encode() + good_json + b'\r\n0\r\n\r\n'),
            ('chunk_ext_space', b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n' + f'{len(good_json):x} ;foo=bar\r\n'.encode() + good_json + b'\r\n0\r\n\r\n'),
            ('chunk_ext_tab', b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n' + f'{len(good_json):x}\t;foo=bar\r\n'.encode() + good_json + b'\r\n0\r\n\r\n'),
            ('chunk_ext_terminal_space', b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n' + f'{len(good_json):x}\r\n'.encode() + good_json + b'\r\n0 ;ext=1\r\n\r\n'),
            ('malformed_chunk_size', b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nZZ\r\n' + good_json),
            ('malformed_chunk_trailing_ws', b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n' + f'{len(good_json):x} \r\n'.encode() + good_json + b'\r\n0\r\n\r\n'),
            ('malformed_chunk_leading_ws', b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n' + f' {len(good_json):x};foo=bar\r\n'.encode() + good_json + b'\r\n0\r\n\r\n'),
            ('malformed_chunk_trailer', b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n' + _chunked_bytes([good_json], trailer=b'BadTrailer\r\n\r\n')),
            ('missing_empty_trailer_line', b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n' + _chunked_bytes([good_json], trailer=b'')),
        ]
        # Uncapped: all fail to settle as known usage; valid chunk-ext (including BWS before ';') still forwards full body!
        self.start(price_in='1.0', price_out='2.0', limit=50)
        strict_502_labels = {'status_http_1_9', 'status_missing_separator', 'status_extra_space'}
        full_body_ext_labels = {'chunk_ext_empty', 'chunk_ext_named', 'chunk_ext_space', 'chunk_ext_tab', 'chunk_ext_terminal_space'}
        for idx, (label, raw) in enumerate(bad_raw_cases, start=1):
            self.upstream.set_handler(lambda conn, r=raw: (_RawScriptedUpstream.read_http_request(conn), conn.sendall(r)))
            if label in strict_502_labels:
                st_b, _ = self.chat()
                self.assertEqual(st_b, 502, label)
            elif label in full_body_ext_labels:
                st_b, body_b = self.chat()
                self.assertEqual(st_b, 200, label)
                self.assertEqual(body_b, good_json, label)
            else:
                try:
                    self.chat()
                except (OSError, http.client.HTTPException):
                    pass
            info = self.control({'action': 'status'})
            self.assertEqual(info['prompt_tokens'], 0, label)
            self.assertEqual(info['usage_unreported_requests'], idx, label)

        # Capped spot checks (including spaced chunk-ext forwarding full body while setting spend_indeterminate=True)
        for label in ('status_missing_separator', 'status_http_1_9', 'chunk_ext_named', 'chunk_ext_space', 'chunk_ext_tab', 'missing_empty_trailer_line', 'dup_content_length'):
            raw = dict(bad_raw_cases)[label]
            self.start(price_in='1.0', price_out='2.0', max_actual_usd='5.00', max_tokens_cap=256)
            self.upstream.set_handler(lambda conn, r=raw: (_RawScriptedUpstream.read_http_request(conn), conn.sendall(r)))
            if label in strict_502_labels:
                st_c, _ = self.chat()
                self.assertEqual(st_c, 502, label)
            elif label in full_body_ext_labels:
                st_c, body_c = self.chat()
                self.assertEqual(st_c, 200, label)
                self.assertEqual(body_c, good_json, label)
            else:
                try:
                    self.chat()
                except (OSError, http.client.HTTPException):
                    pass
            info = self.control({'action': 'status'})
            self.assertTrue(info['spend_indeterminate'], label)

    def test_conservative_capped_billability_and_uncapped_telemetry(self):
        # 1. Pre-write failure (upstream stops before connect/write) leaves capped session intact & renewable
        temp_up = _RawScriptedUpstream()
        temp_port = temp_up.port
        self.start(price_in='1.0', price_out='2.0', max_actual_usd='5.00', max_tokens_cap=256, upstream_port=temp_port)
        temp_up.close()
        st, _ = self.chat()
        self.assertEqual(st, 502)
        info = self.control({'action': 'status'})
        self.assertFalse(info['spend_indeterminate'])
        self.assertEqual(info['usage_unreported_requests'], 0)
        renewed = self.renew(info)
        self.assertEqual(renewed['generation'], 2)

        # 2. Cleanly framed 400/429/302/500: uncapped non-metered vs capped spend_indeterminate
        self.start(price_in='1.0', price_out='2.0')
        for code_str in ('400 Bad Request', '429 Too Many Requests', '302 Found', '500 Internal Server Error'):
            raw = _http_json_resp(b'{"error":"upstream"}', status=code_str)
            self.upstream.set_handler(lambda conn, r=raw: (_RawScriptedUpstream.read_http_request(conn), conn.sendall(r)))
            st, _ = self.chat()
            self.assertEqual(st, int(code_str.split()[0]))
        info_u = self.control({'action': 'status'})
        self.assertEqual(info_u['usage_unreported_requests'], 0)

        for code_str in ('400 Bad Request', '429 Too Many Requests', '302 Found', '500 Internal Server Error'):
            self.start(price_in='1.0', price_out='2.0', max_actual_usd='5.00', max_tokens_cap=256)
            raw = _http_json_resp(b'{"error":"upstream"}', status=code_str)
            self.upstream.set_handler(lambda conn, r=raw: (_RawScriptedUpstream.read_http_request(conn), conn.sendall(r)))
            st, _ = self.chat()
            self.assertEqual(st, int(code_str.split()[0]))
            info_c = self.control({'action': 'status'})
            self.assertTrue(info_c['spend_indeterminate'], code_str)
            st2, body2 = self.chat()
            self.assertEqual(st2, 429)
            self.assertEqual(json.loads(body2)['error']['code'], 'session_spend_indeterminate')
            with self.assertRaises(ValueError):
                self.renew(info_c)

        # 3. Oversized JSON (>512 KiB), oversized split SSE line (>64 KiB), truncation/timeout, true partial write RST, client early disconnect
        import struct
        big_json = b'{"choices":[{"message":{"content":"' + (b'a' * 540_000) + b'"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}'
        big_sse = b'data: ' + (b'b' * 70_000) + b'\n\ndata: [DONE]\n\n'
        partial_bytes_seen: list[int] = []
        def _partial_write_rst_handler(conn):
            try:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            except OSError:
                pass
            chunk = conn.recv(64)
            partial_bytes_seen.append(len(chunk))
            conn.close()
        post_write_cases = [
            ('absent_usage', 'hi', lambda conn: (_RawScriptedUpstream.read_http_request(conn), conn.sendall(_http_json_resp(b'{"choices":[]}')))),
            ('oversized_json', 'hi', lambda conn: (_RawScriptedUpstream.read_http_request(conn), conn.sendall(_http_json_resp(big_json)))),
            ('oversized_split_sse', 'hi', lambda conn: (
                _RawScriptedUpstream.read_http_request(conn),
                conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n' + _chunked_bytes([big_sse[i:i+4096] for i in range(0, len(big_sse), 4096)])),
            )),
            ('truncated_cl', 'hi', lambda conn: (_RawScriptedUpstream.read_http_request(conn), conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 500\r\n\r\n{"usage":{"prompt_tokens":10,"completion_tokens":5}}'))),
            ('partial_write_rst', '!' * 2_000_000, _partial_write_rst_handler),
            ('upstream_timeout', 'hi', lambda conn: (_RawScriptedUpstream.read_http_request(conn), time.sleep(2.2))),
        ]
        # Uncapped: telemetry only, proxy keeps serving & renewing
        self.start(price_in='1.0', price_out='2.0', stream_timeout=1, max_request_bytes=4_194_304)
        for idx, (label, prompt_text, h) in enumerate(post_write_cases, start=1):
            if label == 'partial_write_rst':
                partial_bytes_seen.clear()
            self.upstream.set_handler(h)
            if label == 'partial_write_rst':
                st_pw, _ = self.chat(content=prompt_text, timeout=20.0)
                self.assertEqual(st_pw, 502, label)
                self.assertEqual(len(partial_bytes_seen), 1, label)
                self.assertGreater(partial_bytes_seen[0], 0, label)
                self.assertLessEqual(partial_bytes_seen[0], 64, label)
            else:
                try:
                    self.chat(content=prompt_text, timeout=5.0)
                except (OSError, http.client.HTTPException):
                    pass
            info = self.control({'action': 'status'})
            self.assertEqual(info['usage_unreported_requests'], idx, label)
        self.assertEqual(self.renew(self.control({'action': 'status'}))['generation'], 2)

        # Capped: every post-write failure sets spend_indeterminate and blocks chat + renew
        for label, prompt_text, h in post_write_cases:
            if label == 'partial_write_rst':
                partial_bytes_seen.clear()
            self.start(price_in='1.0', price_out='2.0', max_actual_usd='5.00', max_tokens_cap=256, stream_timeout=1, max_request_bytes=4_194_304)
            self.upstream.set_handler(h)
            if label == 'partial_write_rst':
                st_pwc, _ = self.chat(content=prompt_text, timeout=20.0)
                self.assertEqual(st_pwc, 502, label)
                self.assertEqual(len(partial_bytes_seen), 1, label)
                self.assertGreater(partial_bytes_seen[0], 0, label)
                self.assertLessEqual(partial_bytes_seen[0], 64, label)
            else:
                try:
                    self.chat(content=prompt_text, timeout=5.0)
                except (OSError, http.client.HTTPException):
                    pass
            info = self.control({'action': 'status'})
            self.assertTrue(info['spend_indeterminate'], label)
            st2, body2 = self.chat()
            self.assertEqual(st2, 429, label)
            self.assertEqual(json.loads(body2)['error']['code'], 'session_spend_indeterminate', label)
            with self.assertRaises(ValueError):
                self.renew(info)

        # Client early disconnect before framing completion on capped session:
        # Upstream sends ~66 KiB of short (< 512 B each, well under 64 KiB SSE line cap) comment lines PLUS valid
        # terminal usage + 0\r\n\r\n AFTER client closes, proving early disconnect itself stops forwarding before settlement.
        self.start(price_in='1.0', price_out='2.0', max_actual_usd='5.00', max_tokens_cap=256, stream_timeout=2)
        client_closed = threading.Event()
        upstream_finished = threading.Event()
        def _disconnect_then_complete_stream(conn):
            _RawScriptedUpstream.read_http_request(conn)
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n')
            conn.sendall(b'a\r\ndata: hi\n\n\r\n')
            client_closed.wait(timeout=3.0)
            try:
                pad = (b': ' + (b'p' * 500) + b'\n') * 132 + b'\n'
                conn.sendall(f'{len(pad):x}\r\n'.encode() + pad + b'\r\n')
                fin = b'data: {"usage":{"prompt_tokens":100,"completion_tokens":50}}\n\ndata: [DONE]\n\n'
                conn.sendall(f'{len(fin):x}\r\n'.encode() + fin + b'\r\n0\r\n\r\n')
            except OSError:
                pass
            finally:
                upstream_finished.set()
        self.upstream.set_handler(_disconnect_then_complete_stream)
        s = socket.create_connection(('127.0.0.1', self.port), timeout=5)
        body = json.dumps({'model': self.model, 'messages': [{'role': 'user', 'content': 'hi'}]}).encode()
        s.sendall(
            f'POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nAuthorization: Bearer {self.token}\r\n'
            f'Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n'.encode() + body
        )
        first_bytes = s.recv(128)
        self.assertIn(b'200 OK', first_bytes)
        s.close()
        client_closed.set()
        upstream_finished.wait(timeout=4.0)
        deadline = time.monotonic() + 4.0
        while time.monotonic() < deadline:
            info = self.control({'action': 'status'})
            if info.get('spend_indeterminate'):
                break
            time.sleep(0.05)
        final_disc = self.control({'action': 'status'})
        self.assertTrue(final_disc['spend_indeterminate'])
        self.assertEqual(final_disc['prompt_tokens'], 0)
        self.assertEqual(final_disc['usage_reported_requests'], 0)

    def test_urlsession_parity_and_late_delegate_detachment(self):
        # 1. JSON + SSE parity under --test-force-urlsession
        self.start(price_in='1.0', price_out='2.0', price_cached='0.5', force_urlsession=True, stream_timeout=2)
        self.upstream.set_handler(lambda conn: (
            _RawScriptedUpstream.read_http_request(conn),
            conn.sendall(_http_json_resp(b'{"choices":[],"usage":{"prompt_tokens":400,"completion_tokens":100,"cached_tokens":100}}')),
        ))
        self.assertEqual(self.chat()[0], 200)
        sse_raw = (
            b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n'
            + _chunked_bytes([b'data: {"usage":{"prompt_tokens":600,"completion_tokens":200}}\n\ndata: [DONE]\n\n'])
        )
        self.upstream.set_handler(lambda conn: (_RawScriptedUpstream.read_http_request(conn), conn.sendall(sse_raw)))
        self.assertEqual(self.chat()[0], 200)
        info = self.control({'action': 'status'})
        self.assertEqual((info['prompt_tokens'], info['cached_prompt_tokens'], info['completion_tokens']), (1000, 100, 300))
        self.assertEqual(self.control({'action': 'debug_pool_stats'})['current_reserved_bytes'], 0)

        # 2. Controlled post-detach late response under --test-force-urlsession:
        # Upstream sends HTTP 200 chunked headers immediately, then blocks on allow_late_body until the test
        # OBSERVES spend_indeterminate==True (post-timeout + post-detach), then writes valid usage + 0\r\n\r\n.
        self.start(price_in='1.0', price_out='2.0', max_actual_usd='5.00', max_tokens_cap=256, force_urlsession=True, stream_timeout=1)
        headers_sent = threading.Event()
        allow_late_body = threading.Event()
        late_finished = threading.Event()
        def _late_handler(conn):
            _RawScriptedUpstream.read_http_request(conn)
            try:
                conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n')
                headers_sent.set()
                allow_late_body.wait(timeout=6.0)
                conn.sendall(_chunked_bytes([b'{"choices":[],"usage":{"prompt_tokens":999,"completion_tokens":999}}']))
            except OSError:
                pass
            finally:
                late_finished.set()
        self.upstream.set_handler(_late_handler)
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(self.chat, timeout=6.0)
            self.assertTrue(headers_sent.wait(timeout=3.0))
            # Wait until proxy timeout + detach actually completes on control socket
            det_deadline = time.monotonic() + 5.0
            while time.monotonic() < det_deadline:
                if self.control({'action': 'status'}).get('spend_indeterminate'):
                    break
                time.sleep(0.05)
            self.assertTrue(self.control({'action': 'status'})['spend_indeterminate'])
            # Now release late valid usage from upstream AFTER detachment
            allow_late_body.set()
            late_finished.wait(timeout=3.0)
            try:
                fut.result(timeout=3.0)
            except Exception:
                pass
        info_late = self.control({'action': 'status'})
        self.assertEqual(info_late['prompt_tokens'], 0)
        self.assertEqual(info_late['usage_reported_requests'], 0)
        self.assertEqual(info_late['usage_unreported_requests'], 1)
        self.assertTrue(info_late['spend_indeterminate'])
        self.assertEqual(self.control({'action': 'debug_pool_stats'})['current_reserved_bytes'], 0)

    def test_observer_memory_pool_2mib_ceiling_and_zero_leak(self):
        self.start(price_in='1.0', price_out='2.0', limit=20, stream_timeout=5)
        n_workers = 5
        arrived = threading.Barrier(n_workers, timeout=5)
        body_prefix = b'{"choices":[{"message":{"content":"' + (b'x' * 400_000)
        body_suffix = (b'y' * 40_000) + b'"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}'
        total_len = len(body_prefix) + len(body_suffix)

        def _concurrent_handler(conn):
            _RawScriptedUpstream.read_http_request(conn)
            conn.sendall(
                f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {total_len}\r\nConnection: close\r\n\r\n'.encode()
            )
            conn.sendall(body_prefix)
            try:
                arrived.wait()
            except threading.BrokenBarrierError:
                pass
            time.sleep(0.15)
            conn.sendall(body_suffix)

        self.upstream.set_handler(_concurrent_handler)
        with ThreadPoolExecutor(max_workers=n_workers) as pool:
            results = list(pool.map(lambda _: self.chat(timeout=10.0), range(n_workers)))
        for st, body in results:
            self.assertEqual(st, 200)
            self.assertEqual(len(body), total_len)

        stats = self.control({'action': 'debug_pool_stats'})
        self.assertEqual(stats['limit_bytes'], 2_097_152)
        self.assertLessEqual(stats['peak_reserved_bytes'], 2_097_152)
        self.assertGreater(stats['peak_reserved_bytes'], 0)
        self.assertEqual(stats['current_reserved_bytes'], 0)
        # At least one concurrent request must have hit the 2 MiB pool ceiling during growth
        self.assertGreaterEqual(self.control({'action': 'status'})['usage_unreported_requests'], 1)

    def test_owned_single_flight_timeout_cancel_renew_race_and_token_revalidation(self):
        # 1. Two concurrent capped chats serialize -> at most 1 crosses cap
        self.start(price_in='1.0', price_out='0', max_actual_usd='0.001', max_tokens_cap=256, stream_timeout=5)
        def _slow_cap_crossing(conn):
            _RawScriptedUpstream.read_http_request(conn)
            time.sleep(0.25)
            conn.sendall(_http_json_resp(b'{"choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":0}}'))
        self.upstream.set_handler(_slow_cap_crossing)
        with ThreadPoolExecutor(max_workers=2) as pool:
            res = list(pool.map(lambda _: self.chat(timeout=8.0), range(2)))
        statuses = sorted(st for st, _ in res)
        self.assertEqual(statuses, [200, 429])
        err_bodies = [json.loads(b)['error']['code'] for st, b in res if st == 429]
        self.assertEqual(err_bodies, ['session_spend_budget_exceeded'])

        # 2. Timed-out waiter does NOT release owner's slot + renew during in-flight capped chat is refused
        self.start(price_in='1.0', price_out='0', max_actual_usd='5.00', max_tokens_cap=256, stream_timeout=1)
        active_lock = threading.Lock()
        active_now = 0
        max_concurrent = 0
        call_num = 0
        owner1_entered = threading.Event()
        owner2_entered = threading.Event()
        release_owner2 = threading.Event()

        def _guarded_handler(conn):
            nonlocal active_now, max_concurrent, call_num
            _RawScriptedUpstream.read_http_request(conn)
            with active_lock:
                call_num += 1
                my_num = call_num
                active_now += 1
                if active_now > max_concurrent:
                    max_concurrent = active_now
            if my_num == 1:
                owner1_entered.set()
                # Healthy 0.65s request #1 (well within 1s stream timeout)
                time.sleep(0.65)
            elif my_num == 2:
                owner2_entered.set()
                # Healthy request #2 held until waiter #1 (which queued during #1) hits 1s waitDeadline
                release_owner2.wait(timeout=0.75)
            conn.sendall(_http_json_resp(b'{"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":0}}'))
            with active_lock:
                active_now -= 1

        self.upstream.set_handler(_guarded_handler)
        with ThreadPoolExecutor(max_workers=4) as pool:
            f_owner1 = pool.submit(self.chat, timeout=8.0)
            self.assertTrue(owner1_entered.wait(timeout=3.0))
            # Renew during in-flight capped chat must be refused
            with self.assertRaises(ValueError):
                self.renew(self.control({'action': 'status'}))
            # Queue two chats behind owner1: one becomes owner2 at T=0.65s, the other stays queued past 1.0s -> 503 session_busy
            f_q1 = pool.submit(self.chat, timeout=8.0)
            f_q2 = pool.submit(self.chat, timeout=8.0)
            self.assertTrue(owner2_entered.wait(timeout=3.0))
            # One of (f_q1, f_q2) is owner2 (still running) and the other times out at ~1.0s with 503 session_busy
            deadline_wait = time.monotonic() + 3.0
            timed_out_fut = None
            owner2_fut = None
            while time.monotonic() < deadline_wait:
                if f_q1.done():
                    timed_out_fut, owner2_fut = f_q1, f_q2
                    break
                if f_q2.done():
                    timed_out_fut, owner2_fut = f_q2, f_q1
                    break
                time.sleep(0.02)
            self.assertIsNotNone(timed_out_fut, 'expected one queued waiter to time out with 503 session_busy')
            st_to, body_to = timed_out_fut.result(timeout=2.0)
            self.assertEqual(st_to, 503)
            self.assertEqual(json.loads(body_to)['error']['code'], 'session_busy')
            # Launch waiter #3 AFTER the timeout while owner2 STILL holds slot -> must queue without concurrent overlap
            f_after = pool.submit(self.chat, timeout=8.0)
            # Confirm owner2 is still running and has not overlapped before releasing it
            self.assertFalse(owner2_fut.done())
            self.assertEqual(max_concurrent, 1, 'timed-out waiter must not release owner2 slot')
            release_owner2.set()
            self.assertEqual(f_owner1.result(timeout=5.0)[0], 200)
            self.assertEqual(owner2_fut.result(timeout=5.0)[0], 200)
            self.assertEqual(f_after.result(timeout=5.0)[0], 200)
        self.assertEqual(max_concurrent, 1)

        # 3. Post-wait token revalidation rejects rotated token at admission lock with 401 session_credential_stale
        self.start(price_in='1.0', price_out='0', max_actual_usd='5.00', max_tokens_cap=256, stream_timeout=5)
        upstream_hits = []
        self.upstream.set_handler(lambda conn: (
            upstream_hits.append(_RawScriptedUpstream.read_http_request(conn)),
            conn.sendall(_http_json_resp(b'{"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":0}}')),
        ))
        body_bytes = json.dumps({'model': self.model, 'messages': [{'role': 'user', 'content': 'stale-check'}]}).encode()
        nonce = 'a' * 32
        raw_sock = socket.create_connection(('127.0.0.1', self.port), timeout=5)
        try:
            # Send headers + first byte so proxy passes initial auth check and blocks awaiting body remainder
            raw_sock.sendall(
                f'POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nAuthorization: Bearer {self.token}\r\n'
                f'X-Session-Request-ID: {nonce}\r\nContent-Type: application/json\r\n'
                f'Content-Length: {len(body_bytes)}\r\nConnection: close\r\n\r\n'.encode() + body_bytes[:1]
            )
            # Observe socket stays open with no early auth error before rotating the session token
            import select as _sel
            self.assertEqual(_sel.select([raw_sock], [], [], 0.15)[0], [], 'expected proxy to accept headers and wait for body')
            # Rotate token via renew while request is paused before admission lock
            renewed = self.renew(self.control({'action': 'status'}))
            self.assertEqual(renewed['generation'], 2)
            # Now finish body -> admission lock MUST revalidate activeSessionToken and reject 401 session_credential_stale
            raw_sock.sendall(body_bytes[1:])
            resp_raw = b''
            while True:
                ch = raw_sock.recv(4096)
                if not ch:
                    break
                resp_raw += ch
        finally:
            raw_sock.close()
        self.assertIn(b'401 Unauthorized', resp_raw)
        resp_body = json.loads(resp_raw.split(b'\r\n\r\n', 1)[1])
        self.assertEqual(resp_body['error']['code'], 'session_credential_stale')
        self.assertIn('proof', resp_body['error'])
        self.assertEqual(len(upstream_hits), 0)
        self.assertEqual(self.control({'action': 'status'})['requests_used'], 0)

        # 4. Owner cancellation releases slot cleanly (next chat gets 429 spend_indeterminate, not 503 session_busy)
        self.start(price_in='1.0', price_out='0', max_actual_usd='5.00', max_tokens_cap=256, stream_timeout=2)
        started_cancel = threading.Event()
        cancel_closed = threading.Event()
        def _hang_cancel(conn):
            _RawScriptedUpstream.read_http_request(conn)
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n')
            conn.sendall(b'a\r\ndata: hi\n\n\r\n')
            started_cancel.set()
            cancel_closed.wait(timeout=3.0)
            try:
                pad = (b': ' + (b'c' * 500) + b'\n') * 132 + b'\n'
                for _ in range(4):
                    conn.sendall(f'{len(pad):x}\r\n'.encode() + pad + b'\r\n')
                    time.sleep(0.05)
            except OSError:
                pass
        self.upstream.set_handler(_hang_cancel)
        cs = socket.create_connection(('127.0.0.1', self.port), timeout=5)
        cs.sendall(
            f'POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nAuthorization: Bearer {self.token}\r\n'
            f'Content-Type: application/json\r\nContent-Length: {len(body_bytes)}\r\n\r\n'.encode() + body_bytes
        )
        self.assertTrue(started_cancel.wait(timeout=3.0))
        self.assertIn(b'200 OK', cs.recv(128))
        cs.close()
        cancel_closed.set()
        st_after, body_after = self.chat(timeout=5.0)
        self.assertEqual(st_after, 429)
        self.assertEqual(json.loads(body_after)['error']['code'], 'session_spend_indeterminate')

        # 5. Abandoned queued waiter (RST disconnect) skips admission and preserves budgets, while a
        #    half-closed waiter (shutdown(SHUT_WR)) is STILL admitted and receives its full response!
        import concurrent.futures as _cf
        import struct as _struct
        self.start(price_in='1.0', price_out='0', max_actual_usd='5.00', max_tokens_cap=256, stream_timeout=5)
        owner_in = threading.Event()
        release_owner = threading.Event()
        up_lock = threading.Lock()
        up_bodies: list[bytes] = []
        def _waiter_handler(conn):
            req_raw = _RawScriptedUpstream.read_http_request(conn)
            with up_lock:
                up_bodies.append(req_raw)
                idx = len(up_bodies)
            if idx == 1:
                owner_in.set()
                release_owner.wait(timeout=4.0)
            resp_json = json.dumps({'choices': [{'index': idx}], 'usage': {'prompt_tokens': 100, 'completion_tokens': 0}}).encode()
            conn.sendall(_http_json_resp(resp_json))
        self.upstream.set_handler(_waiter_handler)

        def _make_raw_post(tag: str) -> bytes:
            b = json.dumps({'model': self.model, 'messages': [{'role': 'user', 'content': tag}]}).encode()
            return (
                f'POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nAuthorization: Bearer {self.token}\r\n'
                f'Content-Type: application/json\r\nContent-Length: {len(b)}\r\nConnection: close\r\n\r\n'.encode() + b
            )

        with _cf.ThreadPoolExecutor(max_workers=2) as pool:
            f_own = pool.submit(self.chat, content='owner-tag', timeout=6.0)
            self.assertTrue(owner_in.wait(timeout=3.0))

            # Waiter A: enters queue then aborts with TCP RST (SO_LINGER(1, 0))
            sock_rst = socket.create_connection(('127.0.0.1', self.port), timeout=5)
            sock_rst.sendall(_make_raw_post('abandoned-rst-tag'))
            time.sleep(0.15)
            sock_rst.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, _struct.pack('ii', 1, 0))
            sock_rst.close()

            # Waiter B: enters queue and legally half-closes its write side (shutdown(SHUT_WR)) while still reading
            sock_half = socket.create_connection(('127.0.0.1', self.port), timeout=5)
            try:
                sock_half.sendall(_make_raw_post('half-closed-tag'))
                sock_half.shutdown(socket.SHUT_WR)
                time.sleep(0.25)
                release_owner.set()
                st_own, _ = f_own.result(timeout=5.0)
                self.assertEqual(st_own, 200)
                half_resp = b''
                sock_half.settimeout(5.0)
                while True:
                    chunk = sock_half.recv(4096)
                    if not chunk:
                        break
                    half_resp += chunk
            finally:
                sock_half.close()

        self.assertIn(b'200 OK', half_resp)
        half_json = json.loads(half_resp.split(b'\r\n\r\n', 1)[1])
        self.assertEqual(half_json['usage']['prompt_tokens'], 100)
        with up_lock:
            self.assertEqual(len(up_bodies), 2, 'abandoned RST waiter must not be forwarded upstream')
            joined_up = b''.join(up_bodies)
            self.assertNotIn(b'abandoned-rst-tag', joined_up)
            self.assertIn(b'half-closed-tag', joined_up)
        st_final = self.control({'action': 'status'})
        self.assertEqual(st_final['requests_used'], 2)
        self.assertEqual(st_final['prompt_tokens'], 200)
        self.assertFalse(st_final['spend_indeterminate'])

    def test_half_microdollar_boundary_and_saturation_monotonicity(self):
        # 1. Half-microdollar boundary: 1000 tokens * $0.0005/1M = 0.5 microdollar vs $0.000001 (1 microdollar) cap
        self.start(price_in='0.0005', price_out='0', price_cached='0', max_actual_usd='0.000001', max_tokens_cap=256)
        self.upstream.set_handler(lambda conn: (
            _RawScriptedUpstream.read_http_request(conn),
            conn.sendall(_http_json_resp(b'{"choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":0}}')),
        ))
        self.assertEqual(self.chat()[0], 200)
        info1 = self.control({'action': 'status'})
        self.assertEqual(info1['estimated_micro_usd'], 1)
        self.assertFalse(info1['spend_cap_exceeded'])
        self.assertFalse(info1['spend_cap_low'])
        # Renewal MUST succeed at 0.5 microdollars (< 1 microdollar cap)
        renewed = self.renew(info1)
        self.assertEqual(renewed['generation'], 2)
        new_tok = json.loads(self.token_path.read_text())['token']

        # 2nd request crosses exact 1.0 microdollar cap
        self.assertEqual(self.chat(token=new_tok)[0], 200)
        info2 = self.control({'action': 'status'})
        self.assertTrue(info2['spend_cap_exceeded'])
        self.assertFalse(info2['spend_cap_low'])
        self.assertEqual(info2['requests_used'], 2)
        # 3rd request blocked with 429 session_spend_budget_exceeded WITHOUT incrementing requests_used
        st3, body3 = self.chat(token=new_tok)
        self.assertEqual(st3, 429)
        self.assertEqual(json.loads(body3)['error']['code'], 'session_spend_budget_exceeded')
        self.assertEqual(self.control({'action': 'status'})['requests_used'], 2)
        with self.assertRaises(ValueError):
            self.renew(info2)

        # 2. Saturation monotonicity & --max-chat-requests 2147483647 accepted
        self.start(limit=2_147_483_647, price_in='10000', price_out='10000', price_cached='10000')
        self.assertEqual(self.control({'action': 'status'})['request_limit'], 2_147_483_647)
        self.upstream.set_handler(lambda conn: (
            _RawScriptedUpstream.read_http_request(conn),
            conn.sendall(_http_json_resp(b'{"choices":[],"usage":{"prompt_tokens":1000000000,"cached_prompt_tokens":500000000,"completion_tokens":1000000000}}')),
        ))
        prev_est = -1
        for i in range(1, 4):
            self.assertEqual(self.chat()[0], 200)
            st_i = self.control({'action': 'status'})
            self.assertEqual(st_i['prompt_tokens'], i * 1_000_000_000)
            self.assertEqual(st_i['cached_prompt_tokens'], i * 500_000_000)
            self.assertEqual(st_i['completion_tokens'], i * 1_000_000_000)
            self.assertGreaterEqual(st_i['estimated_micro_usd'], prev_est)
            prev_est = st_i['estimated_micro_usd']
