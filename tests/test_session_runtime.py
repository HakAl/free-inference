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
from concurrent.futures import ThreadPoolExecutor

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from local_assist.session import control_request, control_path, SessionLeaseSupplier


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'requires macOS Swift')
class SessionRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from local_assist.se_key import verify_swift_source
        verify_swift_source()
        (ROOT / 'bin').mkdir(exist_ok=True)
        cls.build_dir = tempfile.TemporaryDirectory(prefix='session-build-', dir=ROOT / 'bin')
        cls.addClassCleanup(cls.build_dir.cleanup)
        cls.binary = Path(cls.build_dir.name) / 'proxy-test'
        cls.release = Path(cls.build_dir.name) / 'proxy-release'
        for binary, flags in [(cls.binary, ['-D', 'SE_KEY_TESTING']), (cls.release, [])]:
            subprocess.run(['swiftc', '-module-cache-path', str(ROOT / '.home/swift-cache'),
                *flags, str(ROOT / 'tools/se_key_proxy/main.swift'), '-o', str(binary)],
                check=True, capture_output=True, timeout=120)

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

    def renew(self, info, allow=True):
        os.write(self.auth_writer, b'1' if allow else b'0')
        return self.control(dict(action='renew', seconds=20, session_id=info['session_id'], generation=info['generation']))

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
        self.start()
        info = self.control({'action': 'status'})
        for _ in range(31): info = self.renew(info)
        self.assertEqual(info['generation'], 32)
        self.assertEqual(info['requests_remaining'], 5)
        with self.assertRaises(ValueError): self.renew(info)
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
