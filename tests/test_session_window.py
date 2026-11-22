from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from local_assist.session import parse_duration, sanitize_status, format_status, warning_reason
from unittest.mock import patch


class SessionPolicyTests(unittest.TestCase):
    def test_duration_units_and_hard_max(self):
        for text, expected in [('1s', 1), ('30m', 1800), ('2h', 7200), ('12h', 43200), ('24h', 86400)]:
            self.assertEqual(parse_duration(text), expected)
        for text in ['0h', '-1h', 'nan', 'inf', '2', '1.5h', '25h', '86401s', '1h30m', '', True]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_duration(text)

    def status(self):
        return dict(protocol=1, session_id='test-session', pid=123, model='served-model',
                    generation=1, remaining_seconds=120, expires_at=2000000000,
                    requests_used=3, request_limit=10, requests_remaining=7,
                    window_seconds=7200, state='ON')

    def test_status_whitelist_and_identity(self):
        raw = self.status()
        raw['password'] = 'secret-that-must-not-be-returned'
        result = sanitize_status(raw, expected_model='served-model', expected_pid=123)
        self.assertNotIn('secret', json.dumps(result))
        for field, value in [('pid', 124), ('model', 'different'), ('requests_remaining', 8),
                             ('remaining_seconds', -1), ('generation', True), ('protocol', 2)]:
            raw = self.status(); raw[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                sanitize_status(raw, expected_model='served-model', expected_pid=123)

    def test_formatter_does_not_describe_requests_as_turns(self):
        line = format_status(dict(self.status(), model_id='test-model'))
        self.assertIn('ON', line)
        self.assertIn('7/10 requests', line)
        self.assertNotIn('turn', line)
        self.assertIn('UNKNOWN', format_status({'state': 'UNKNOWN', 'model_id': 'test-model'}))
        self.assertIn('OFF', format_status({'state': 'OFF', 'model_id': 'test-model'}))

    def test_warnings_are_read_only_thresholds(self):
        self.assertEqual(warning_reason(self.status()), 'expires soon')
        self.assertEqual(warning_reason(dict(self.status(), remaining_seconds=3600,
                                             requests_remaining=1, requests_used=9)), 'requests low')
        self.assertIsNone(warning_reason(dict(self.status(), remaining_seconds=3600,
                                             request_limit=100, requests_remaining=90)))
        self.assertIsNone(warning_reason({'state': 'UNKNOWN'}))

    def test_stale_refusal_proof_requires_new_generation_session_and_nonce(self):
        import hashlib, hmac
        from local_assist.relay import SessionAuthRelay
        old = dict(session_id='same', pid=12, generation=1, token='old-secret')
        new = dict(old, generation=2, token='new-secret')
        nonce = 'fresh'
        error = dict(code='session_credential_stale', session_id='same', generation=2,
                     request_id=nonce, proof=hmac.new(b'new-secret', b'free-inference-stale-v1|same|2|fresh', hashlib.sha256).hexdigest())
        self.assertTrue(SessionAuthRelay._verified_stale(error, old, new, nonce))
        for bad in [dict(error, proof='0'*64), dict(error, request_id='replayed'),
                    dict(error, session_id='other'), dict(error, generation=1), dict(error, code='unauthorized')]:
            self.assertFalse(SessionAuthRelay._verified_stale(bad, old, new, nonce))
        self.assertFalse(SessionAuthRelay._verified_stale(error, old, old, nonce))

    def test_unknown_live_probe_is_not_off_and_does_not_read_token(self):
        from local_assist.session import status_for_record
        record = dict(model_id='test', repo='served-model', pid=123, pid_lstart='verified')
        with patch('local_assist.launch.classify_pid_identity', return_value='matched'), \
             patch('local_assist.session.control_request', side_effect=OSError):
            self.assertEqual(status_for_record(record, ROOT / 'runs')['state'], 'UNKNOWN')
        with patch('local_assist.launch.classify_pid_identity', return_value='dead'):
            self.assertEqual(status_for_record(record, ROOT / 'runs')['state'], 'OFF')
        self.assertEqual(status_for_record({}, ROOT / 'runs')['state'], 'UNKNOWN')

    def test_start_and_stop_are_idempotent_and_unknown_does_not_restart(self):
        from local_assist.session import main
        from contextlib import redirect_stdout, redirect_stderr
        import io
        record = dict(model_id='test', repo='served-model', pid=123)
        for action, state, existing in [('start', 'ON', record), ('stop', 'OFF', None),
                                        ('start', 'UNKNOWN', record)]:
            with self.subTest(action=action, state=state), \
                 patch('local_assist.session.select_model', return_value='test'), \
                 patch('local_assist.session.read_pid_record_for_model', return_value=existing), \
                 patch('local_assist.session.status_for_record', return_value=dict(self.status(), state=state)), \
                 patch('local_assist.session.subprocess.run') as run, \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(main([action]), 1 if state == 'UNKNOWN' else 0)
                run.assert_not_called()

    def test_selection_refuses_ambiguity(self):
        from local_assist.session import select_model
        records = [(Path('ignored'), dict(model_id=m, session_token_file='protected', pid=1))
                   for m in ['a', 'b']]
        with patch('local_assist.session.list_pid_records', return_value=records), \
             patch('local_assist.launch.classify_pid_identity', return_value='matched'):
            with self.assertRaises(ValueError): select_model(None, ROOT / 'runs')

    def test_implicit_selection_checks_model_admission_and_malformed_records(self):
        from local_assist.session import select_model
        from types import SimpleNamespace
        for record in [dict(model_id='local', session_token_file='protected', pid=1),
                       dict(session_token_file='protected', pid=1)]:
            with patch('local_assist.session.list_pid_records', return_value=[(Path('ignored'), record)]), \
                 patch('local_assist.launch.classify_pid_identity', return_value='matched'), \
                 patch('local_assist.session.load_model', return_value={}), \
                 patch('local_assist.session.resolve_endpoint', return_value=SimpleNamespace(trust_tier='local')):
                with self.assertRaises(ValueError): select_model(None, ROOT / 'runs')

    def test_supplier_refuses_writable_store_before_reading_credentials(self):
        import tempfile
        from local_assist.session import SessionLeaseSupplier
        with tempfile.TemporaryDirectory() as tmp:
            store = Path(tmp); store.chmod(0o777)
            try:
                with patch('local_assist.session.os.open') as read:
                    with self.assertRaises(ValueError):
                        SessionLeaseSupplier({'model_id': 'test'}, store)()
                    read.assert_not_called()
            finally:
                store.chmod(0o700)

    def test_stop_cli_targets_the_explicit_runs_store(self):
        import tempfile, subprocess, os
        from local_assist.registry import pid_file_for_model, session_token_file_for_model, get_process_lstart
        model = 'tinfoil-deepseek-v4-1-flash'
        tmp_base = '/private/tmp' if os.path.isdir('/private/tmp') else '/tmp'
        with tempfile.TemporaryDirectory(prefix='sw-stop-', dir=tmp_base) as tmp:
            store = Path(tmp)
            proc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
            try:
                record = dict(model_id=model, repo='deepseek-v4-1-flash', pid=proc.pid,
                              pid_lstart=get_process_lstart(proc.pid), status='ready')
                pid_path = pid_file_for_model(model, store)
                token_path = session_token_file_for_model(model, store)
                record['session_token_file'] = str(token_path)
                token_path.write_text('se-session-'+'a'*64); token_path.chmod(0o600)
                pid_path.write_text(json.dumps(record))
                env = dict(os.environ, FREE_INFERENCE_RUNS_DIR=str(store))
                result = subprocess.run([sys.executable, str(ROOT/'scripts/session'), 'stop',
                    '--model', model, '--json'], env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)['state'], 'OFF')
                self.assertIsNotNone(proc.wait(5))
                self.assertFalse(pid_path.exists()); self.assertFalse(token_path.exists())
            finally:
                if proc.poll() is None: proc.terminate(); proc.wait(5)

    def test_notification_failure_does_not_stop_watcher(self):
        from local_assist import custody
        from local_assist.session import main
        from contextlib import redirect_stdout, redirect_stderr
        import io, subprocess
        real_platform = sys.platform
        real_validate = custody.validate_creatable_runs_dir

        def _validate_with_real_platform(*args, **kwargs):
            with patch.object(sys, 'platform', real_platform):
                return real_validate(*args, **kwargs)

        for error in [OSError('private-path'), subprocess.TimeoutExpired('osascript', 5)]:
            with patch('local_assist.session.select_model', return_value='test'), \
                 patch('local_assist.session.read_pid_record_for_model', return_value={'model_id': 'test'}), \
                 patch('local_assist.session.status_for_record', side_effect=[self.status(), {'state': 'OFF'}]), \
                 patch('local_assist.session.time.sleep'), \
                 patch('local_assist.custody.validate_creatable_runs_dir', side_effect=_validate_with_real_platform), \
                 patch('local_assist.session.sys.platform', 'darwin'), \
                 patch('local_assist.session.subprocess.run', side_effect=error), \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(main(['watch', '--notify']), 0, stderr.getvalue())
                self.assertIn('continuing to watch', stderr.getvalue())
                self.assertNotIn('private-path', stderr.getvalue())

    def test_watch_warns_once_per_generation_without_authorizing(self):
        from local_assist.session import main
        from contextlib import redirect_stdout, redirect_stderr
        import io
        info = dict(self.status(), model_id='test')
        warnings = io.StringIO()
        with patch('local_assist.session.select_model', return_value='test'), \
             patch('local_assist.session.read_pid_record_for_model', return_value={'model_id': 'test'}), \
             patch('local_assist.session.status_for_record', side_effect=[info, info, dict(info, generation=2), {'state': 'OFF'}]), \
             patch('local_assist.session.time.sleep'), patch('local_assist.session.control_request') as control, \
             patch('local_assist.session.subprocess.run') as run, \
             redirect_stdout(io.StringIO()), redirect_stderr(warnings):
            self.assertEqual(main(['watch']), 0)
            control.assert_not_called(); run.assert_not_called()
        self.assertEqual(warnings.getvalue().count('expires soon'), 2)

    def test_models_reports_renewed_deadline_even_after_initial_window_elapsed(self):
        import importlib.machinery, types
        loader = importlib.machinery.SourceFileLoader('session_models', str(ROOT / 'scripts/models'))
        module = types.ModuleType(loader.name); module.__file__ = str(ROOT / 'scripts/models')
        loader.exec_module(module)
        record = dict(model_id='tinfoil-deepseek-v4-1-flash', repo='deepseek-v4-1-flash',
            runtime='proxy', pid=123, ttl_seconds=7200, started_at='2000-01-01T00:00:00+00:00')
        live = dict(self.status(), window_seconds=43200, generation=2)
        with patch.object(module, 'classify_pid_identity', return_value='matched'), \
             patch('local_assist.session.status_for_record', return_value=live):
            info = module._classify_session_record(record)
        from datetime import datetime
        self.assertTrue(info['active'])
        self.assertEqual(int(datetime.fromisoformat(info['expires_at']).timestamp()), live['expires_at'])
        self.assertEqual(info['remaining_ttl_seconds'], live['remaining_seconds'])


if __name__ == '__main__':
    unittest.main()
