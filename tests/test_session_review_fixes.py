from __future__ import annotations

import base64
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def load_script(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(ROOT / path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class EnvelopeContainmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.runs = self.base / 'runs'; self.runs.mkdir()
        self.home = self.base / 'home'
        self.db = self.home / '.local/share/opencode/opencode.db'
        self.db.parent.mkdir(parents=True)
        self.token = 'se-session-' + 'a'*64
        self.old = 'se-session-' + 'b'*64
        self.token_file = self.runs / '.se-session-test.token'
        self.evidence = self.base / 'evidence.json'
        self.evidence.write_text('{}')
        self.mod = load_script('envelope_containment', 'scripts/check-credential-containment')
        self.dead = False
        self.alive_pids = {424242}
        self.stopped_pids = set()
        self.closed_ports = set()
        self.stopped = []
        record = dict(model_id='test', trust_tier='enclave_runtime_attested', pid=424242,
            pid_lstart='verified', port=23456, session_token_file=str(self.token_file), status='ready')
        (self.runs / '.serve.test.pid').write_text(json.dumps(record))

    def envelope(self, generation=1):
        self.token_file.write_text(json.dumps(dict(token=self.token, session_id='synthetic-session',
                                                   generation=generation)))
        self.token_file.chmod(0o600)

    def persist(self, token):
        conn = sqlite3.connect(self.db)
        with conn:
            conn.execute('CREATE TABLE part (id TEXT, data TEXT)')
            conn.execute('INSERT INTO part VALUES (?, ?)', ('part1', json.dumps({'text': token})))
        conn.close()

    def identity(self, pid, start):
        return 'dead' if pid in self.stopped_pids else 'matched'

    def stop(self, session):
        self.stopped.append(session['model_id'])
        self.stopped_pids.add(session['pid']); self.closed_ports.add(session['port'])
        return True

    def apply(self, target=None):
        # The pre-existing suite verifies evidence gates and real process revocation.
        # Isolate this representation migration while keeping actual SQLite cleanup.
        with patch.object(self.mod, '_validate_evidence_snapshot', return_value=(True, True, {}, False, 'f'*64)), \
             patch.object(self.mod, 'classify_pid_identity', side_effect=self.identity), \
             patch.object(self.mod, 'pid_is_alive', side_effect=lambda pid: pid in self.alive_pids and pid not in self.stopped_pids), \
             patch.object(self.mod, 'pid_is_zombie', return_value=False), \
             patch.object(self.mod, '_probe_tcp_listener_closed', side_effect=lambda p: 'closed' if p in self.closed_ports else 'open'), \
             patch.object(self.mod, '_find_unaccounted_se_key_proxy_pids', return_value=([], True)), \
             patch.object(self.mod, '_list_current_uid_ps_commands', return_value=([], True)):
            return self.mod.apply_containment(home_dir=self.home, runs_dir=self.runs,
                evidence_path=self.evidence, incident_id='synthetic', target_model_id=target,
                stop_model_fn=self.stop)

    def test_current_envelope_leak_is_stopped_before_forensic_cleanup(self):
        self.envelope(); self.persist(self.token)
        rc, report, err = self.apply()
        self.assertEqual(self.stopped, ['test'], err)
        self.assertEqual(rc, 0, err)
        self.assertTrue(report['session_revocation_verified'])
        self.assertFalse(self.db.exists())

    def test_envelope_needles_include_encoded_actual_token(self):
        self.envelope()
        needles, ok = self.mod._collect_in_memory_needles(self.home, self.runs, [])
        self.assertTrue(ok)
        self.assertIn(base64.b64encode(('opencode:'+self.token).encode()).decode(), needles)

    def test_malformed_envelope_preserves_forensics(self):
        self.token_file.write_text('{"token":false,"generation":1}')
        self.persist(self.token)
        rc, report, err = self.apply()
        self.assertEqual(rc, 1)
        self.assertIsNone(report)
        self.assertEqual(self.stopped, [])
        self.assertTrue(self.db.exists())

    def test_retired_exposure_requires_attribution_before_cleanup(self):
        self.envelope(generation=3); self.persist(self.old)
        rc, report, err = self.apply()
        self.assertEqual(rc, 1)
        self.assertEqual(self.stopped, [])
        self.assertTrue(self.db.exists())

    def test_encoded_retired_exposure_preserves_forensics(self):
        self.envelope(generation=3)
        self.persist(base64.b64encode(('opencode:'+self.old).encode()).decode())
        rc, report, err = self.apply()
        self.assertEqual(rc, 1)
        self.assertTrue(self.db.exists())
        self.assertEqual(self.stopped, [])

    def test_json_serialized_literal_unicode_retired_exposure_preserves_forensics(self):
        self.envelope(generation=3)
        literal_unicode = ''.join('\\u%04x' % ord(c) for c in self.old)
        self.persist(literal_unicode)
        tokens, ok = self.mod._extract_persisted_session_tokens_in_memory(self.home)
        self.assertTrue(ok)
        self.assertIn(self.old, tokens)
        rc, report, err = self.apply()
        self.assertEqual(rc, 1, err)
        self.assertIsNone(report)
        self.assertTrue(self.db.exists())
        self.assertEqual(self.stopped, [])

    def test_nested_json_unicode_decoding_retains_depth_and_size_bounds(self):
        literal_unicode = ''.join('\\u%04x' % ord(c) for c in self.old)
        self.persist(json.dumps({'nested': literal_unicode}))
        tokens, ok = self.mod._extract_persisted_session_tokens_in_memory(self.home)
        self.assertTrue(ok)
        self.assertIn(self.old, tokens)
        # A raw single-escape representation still works without serialization.
        with sqlite3.connect(self.db) as conn:
            conn.execute('UPDATE part SET data = ?', (literal_unicode,))
        conn.close()
        tokens, ok = self.mod._extract_persisted_session_tokens_in_memory(self.home)
        self.assertTrue(ok)
        self.assertIn(self.old, tokens)
        # Deeply escaped and oversized single cells remain unverifiable.
        deep = literal_unicode
        for _ in range(8):
            deep = json.dumps({'nested': deep})
        for value in (deep, 'x' * (8*1024*1024 + 1)):
            with sqlite3.connect(self.db) as conn:
                conn.execute('UPDATE part SET data = ?', (value,))
            conn.close()
            _, ok = self.mod._extract_persisted_session_tokens_in_memory(self.home)
            self.assertFalse(ok)

    def test_attributed_current_exposure_does_not_stop_unrelated_rotated_proxy(self):
        self.envelope(); self.persist(self.token)
        other = self.runs / '.se-session-other.token'
        other.write_text(json.dumps(dict(token=self.old, generation=3, session_id='other')))
        other.chmod(0o600)
        record = dict(model_id='other', trust_tier='enclave_runtime_attested', pid=424243,
            pid_lstart='verified-other', port=23457, session_token_file=str(other), status='ready')
        (self.runs / '.serve.other.pid').write_text(json.dumps(record))
        self.alive_pids.add(424243)
        rc, report, err = self.apply(target='test')
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.stopped, ['test'])
        self.assertNotIn(424243, self.stopped_pids)
        self.assertTrue(other.exists())

    def test_explicit_target_revokes_rotated_session_before_cleanup(self):
        self.envelope(generation=3); self.persist(self.old)
        rc, report, err = self.apply(target='test')
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.stopped, ['test'])
        self.assertFalse(self.db.exists())


class LeaseAndAdmissionTests(unittest.TestCase):
    def test_dangling_or_unverifiable_control_node_is_not_legacy_absence(self):
        from local_assist.session import control_node_present
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'control.sock'
            self.assertFalse(control_node_present(path))
            path.symlink_to(Path(tmp)/'missing')
            self.assertTrue(control_node_present(path))
            with patch.object(Path, 'lstat', side_effect=PermissionError):
                self.assertTrue(control_node_present(path))
    def test_start_preflights_do_not_spawn_on_archived_keyless_or_legacy_state(self):
        import dataclasses, io
        from contextlib import redirect_stderr, redirect_stdout
        from local_assist.registry import resolve_endpoint, load_model
        from local_assist.session import main
        endpoint = resolve_endpoint(load_model('tinfoil-deepseek-v4-1-flash'), require_api_key=False)
        for ep, legacy in [(dataclasses.replace(endpoint, status='archived'), None),
                           (dataclasses.replace(endpoint, api_key_keychain_service=None), None),
                           (endpoint, 'uncontained')]:
            with patch('local_assist.session.select_model', return_value=endpoint.model_id), \
                 patch('local_assist.session.read_pid_record_for_model', return_value=None), \
                 patch('local_assist.session.resolve_endpoint', return_value=ep), \
                 patch('local_assist.launch.check_uncontained_legacy_home', return_value=legacy), \
                 patch('local_assist.session.subprocess.run') as run, \
                 redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                self.assertEqual(main(['start']), 1)
                run.assert_not_called()

    def test_entrypoint_preserves_isolated_interpreter(self):
        import os, runpy, io
        from contextlib import redirect_stdout
        original_flags = sys.flags
        class IsolatedFlags:
            isolated = 1
            def __getattr__(self, name): return getattr(original_flags, name)
        with patch.object(sys, 'argv', ['session', '--help']), \
             patch.object(sys, 'executable', '/different/python'), \
             patch.object(sys, 'flags', IsolatedFlags()), \
             patch.object(os, 'execv') as reexec, redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as result:
                runpy.run_path(str(ROOT/'scripts/session'), run_name='__main__')
            self.assertEqual(result.exception.code, 0)
            reexec.assert_not_called()

    def test_cached_supplier_refreshes_only_when_requested(self):
        from local_assist.session import SessionLeaseSupplier
        from local_assist.registry import session_token_file_for_model
        with tempfile.TemporaryDirectory() as tmp:
            store = Path(tmp)
            path = session_token_file_for_model('test', store)
            path.write_text(json.dumps(dict(token='se-session-'+'a'*64, generation=1, session_id='same')))
            path.chmod(0o600)
            state = dict(state='ON', remaining_seconds=20, generation=1, session_id='same', pid=123)
            supplier = SessionLeaseSupplier(dict(model_id='test', repo='served', pid=123), store)
            with patch('local_assist.session.status_for_record', return_value=state) as status, \
                 patch('local_assist.session._ProcessWatch') as watch:
                watch.return_value.exited.return_value = False
                first = supplier()
                from types import SimpleNamespace
                supplier.record['port'] = 23456
                with self.assertRaises(ValueError):
                    supplier.check_connection(SimpleNamespace(getpeername=lambda: ('::1', 23456)))
                for _ in range(10): self.assertEqual(supplier(), first)
                self.assertEqual(status.call_count, 2)
                state['generation'] = 2
                path.write_text(json.dumps(dict(token='se-session-'+'b'*64, generation=2, session_id='same')))
                self.assertEqual(supplier.refresh()['generation'], 2)
                self.assertEqual(status.call_count, 4)

    def test_cached_deadline_refreshes_without_authorizing_and_rejects_off(self):
        from local_assist.session import SessionLeaseSupplier
        from local_assist.registry import session_token_file_for_model
        with tempfile.TemporaryDirectory() as tmp:
            store = Path(tmp); path = session_token_file_for_model('test', store)
            path.write_text(json.dumps(dict(token='se-session-'+'a'*64, generation=1, session_id='same')))
            path.chmod(0o600)
            state = dict(state='ON', remaining_seconds=1, remaining_milliseconds=1000,
                         generation=1, session_id='same', pid=123)
            supplier = SessionLeaseSupplier(dict(model_id='test', repo='served', pid=123), store)
            with patch('local_assist.session.status_for_record', return_value=state) as status, \
                 patch('local_assist.session._ProcessWatch') as watch, \
                 patch('local_assist.session._continuous_time', return_value=0) as clock, \
                 patch('local_assist.session.subprocess.run') as authorize:
                watch.return_value.exited.return_value = False
                supplier()
                clock.return_value = 2
                state['state'] = 'OFF'; state['remaining_seconds'] = 0
                with self.assertRaises(ValueError): supplier()
                self.assertEqual(status.call_count, 3)
                authorize.assert_not_called()

    def test_default_model_environment_is_honored(self):
        import os
        from local_assist.session import select_model
        with patch.dict(os.environ, FREE_INFERENCE_DEFAULT_ATTESTED_MODEL='privatemode-glm-5-3-flash'):
            self.assertEqual(select_model(None, Path('/unused')), 'privatemode-glm-5-3-flash')

    def test_shared_parser_refuses_partial_duplicate_and_invalid_envelopes(self):
        from local_assist.registry import parse_session_token_raw
        token = 'se-session-'+'a'*64
        self.assertEqual(parse_session_token_raw(token), token)
        self.assertEqual(parse_session_token_raw(json.dumps(dict(token=token, generation=2, session_id='same'))), token)
        for raw in ['{"token":"'+token+'"}', '{"token":false}', '{bad',
                    json.dumps(dict(token=token, generation=True, session_id='same')),
                    '{"token":"'+token+'","token":"'+token+'","generation":1,"session_id":"same"}']:
            self.assertIsNone(parse_session_token_raw(raw))


if __name__ == '__main__':
    unittest.main()
