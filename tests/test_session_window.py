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

    def test_usd_and_price_parsing_and_formatting(self):
        from local_assist.session import (
            format_micro_usd_decimal,
            parse_usd_to_micro_usd,
            price_float_to_micro_usd,
        )
        for raw, expected in [
            ('0.000001', 1),
            ('0.5', 500_000),
            ('1', 1_000_000),
            ('1.45', 1_450_000),
            ('100000', 100_000_000_000),
            ('100000.000000', 100_000_000_000),
        ]:
            self.assertEqual(parse_usd_to_micro_usd(raw), expected)
        for bad in [
            '', '0', '0.0', '0.000000', '-1', '+1', '1.0000001', '1e2', 'nan', 'inf',
            ' 1.0', '1.0 ', '100000.000001', '1000000', '\u0661.5', '\uff11.0',
            '1' + ('0' * 33), True, 1.5,
        ]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_usd_to_micro_usd(bad)  # type: ignore[arg-type]

        for val, expected in [
            (0, 0),
            (0.0, 0),
            (1e-06, 1),
            (0.15, 150_000),
            (10000, 10_000_000_000),
            (10000.0, 10_000_000_000),
        ]:
            self.assertEqual(price_float_to_micro_usd(val), expected)
        for bad_price in [True, False, -0.01, float('nan'), float('inf'), 10000.000001, 1e-07, '0.5']:
            with self.subTest(bad_price=bad_price), self.assertRaises(ValueError):
                price_float_to_micro_usd(bad_price)  # type: ignore[arg-type]

        self.assertEqual(format_micro_usd_decimal(0), '0')
        self.assertEqual(format_micro_usd_decimal(1), '0.000001')
        self.assertEqual(format_micro_usd_decimal(2_000_000), '2')
        self.assertEqual(format_micro_usd_decimal(1_450_000), '1.45')
        self.assertEqual(format_micro_usd_decimal(500), '0.0005')

    def test_sanitize_status_usage_and_cap_groups_bounds_and_compat(self):
        # Legacy protocol-1 status without usage keys stays valid
        legacy = sanitize_status(self.status(), expected_model='served-model', expected_pid=123)
        self.assertNotIn('prompt_tokens', legacy)

        def full_status():
            s = self.status()
            s.update(
                prompt_tokens=1500,
                cached_prompt_tokens=500,
                completion_tokens=200,
                usage_reported_requests=2,
                usage_unreported_requests=1,
                estimated_micro_usd=420,
                max_actual_micro_usd=1_000_000,
                spend_cap_exceeded=False,
                spend_cap_low=False,
                spend_indeterminate=False,
            )
            return s

        ok = sanitize_status(full_status(), expected_model='served-model', expected_pid=123)
        self.assertEqual(ok['prompt_tokens'], 1500)
        self.assertEqual(ok['max_actual_micro_usd'], 1_000_000)

        # Boundary acceptance: 10^12 per limb and 2_147_483_647 request counters
        boundary = full_status()
        boundary.update(
            prompt_tokens=2_000_000_000_000,
            cached_prompt_tokens=1_000_000_000_000,
            completion_tokens=1_000_000_000_000,
            requests_used=2_147_483_647,
            request_limit=2_147_483_647,
            requests_remaining=0,
            usage_reported_requests=2_147_483_647,
            usage_unreported_requests=0,
            estimated_micro_usd=100_000_000_000_000,
            max_actual_micro_usd=100_000_000_000,
        )
        ok_b = sanitize_status(boundary, expected_model='served-model', expected_pid=123)
        self.assertEqual(ok_b['prompt_tokens'], 2_000_000_000_000)
        self.assertEqual(ok_b['usage_reported_requests'], 2_147_483_647)

        bad_cases = [
            # Partial usage group
            ('partial_usage', lambda s: s.pop('completion_tokens')),
            # estimated_micro_usd without usage group
            ('est_without_usage', lambda s: [s.pop(k) for k in (
                'prompt_tokens', 'cached_prompt_tokens', 'completion_tokens',
                'usage_reported_requests', 'usage_unreported_requests',
                'max_actual_micro_usd', 'spend_cap_exceeded', 'spend_cap_low', 'spend_indeterminate',
            )]),
            # Cap group without estimated_micro_usd
            ('cap_without_est', lambda s: s.pop('estimated_micro_usd')),
            # Partial cap group
            ('partial_cap', lambda s: s.pop('spend_indeterminate')),
            # cached > prompt
            ('cached_gt_prompt', lambda s: s.update(prompt_tokens=100, cached_prompt_tokens=101)),
            # uncached > 10^12
            ('uncached_over_limit', lambda s: s.update(prompt_tokens=1_000_000_000_001, cached_prompt_tokens=0)),
            # cached > 10^12
            ('cached_over_limit', lambda s: s.update(prompt_tokens=1_000_000_000_001, cached_prompt_tokens=1_000_000_000_001)),
            # completion > 10^12
            ('completion_over_limit', lambda s: s.update(completion_tokens=1_000_000_000_001)),
            # usage requests > requests_used
            ('usage_reqs_gt_used', lambda s: s.update(usage_reported_requests=3, usage_unreported_requests=1)),
            # requests_used > INT32_MAX
            ('reqs_over_int32_max', lambda s: s.update(requests_used=2_147_483_648, request_limit=2_147_483_648, requests_remaining=0)),
            # usage_reported_requests > INT32_MAX
            ('rep_over_int32_max', lambda s: s.update(usage_reported_requests=2_147_483_648)),
            # bool instead of int
            ('bool_tokens', lambda s: s.update(prompt_tokens=True)),
            # int instead of bool
            ('int_cap_bool', lambda s: s.update(spend_cap_exceeded=1)),
            # cap_exceeded and cap_low both True
            ('exceeded_and_low', lambda s: s.update(spend_cap_exceeded=True, spend_cap_low=True)),
            # cap < 1
            ('cap_zero', lambda s: s.update(max_actual_micro_usd=0)),
            # cap > 100_000_000_000
            ('cap_over_max', lambda s: s.update(max_actual_micro_usd=100_000_000_001)),
            # estimated_micro_usd > 100_000_000_000_000
            ('est_over_max', lambda s: s.update(estimated_micro_usd=100_000_000_000_001)),
        ]
        for label, mutate in bad_cases:
            with self.subTest(label=label):
                s = full_status()
                mutate(s)
                with self.assertRaises(ValueError):
                    sanitize_status(s, expected_model='served-model', expected_pid=123)

    def test_warning_reason_priority_and_format_status_spend(self):
        base = dict(
            self.status(),
            model_id='test-model',
            remaining_seconds=3600,
            request_limit=100,
            requests_used=10,
            requests_remaining=90,
            prompt_tokens=12_500,
            cached_prompt_tokens=2_500,
            completion_tokens=1_200,
            usage_reported_requests=10,
            usage_unreported_requests=1,
            estimated_micro_usd=150_000,
            estimated_usd=0.15,
            estimated_usd_source='proxy',
            max_actual_micro_usd=500_000,
            max_actual_usd=0.5,
            spend_cap_exceeded=False,
            spend_cap_low=True,
            spend_indeterminate=False,
        )
        # Priority: spend indeterminate > spend cap reached > expires soon > requests low > spend cap low
        self.assertEqual(warning_reason(base), 'spend cap low')
        self.assertEqual(warning_reason(dict(base, requests_remaining=5)), 'requests low')
        self.assertEqual(warning_reason(dict(base, requests_remaining=5, remaining_seconds=120)), 'expires soon')
        self.assertEqual(
            warning_reason(dict(base, requests_remaining=5, remaining_seconds=120, spend_cap_exceeded=True, spend_cap_low=False)),
            'spend cap reached',
        )
        self.assertEqual(
            warning_reason(dict(base, requests_remaining=5, remaining_seconds=120, spend_cap_exceeded=True, spend_cap_low=False, spend_indeterminate=True)),
            'spend indeterminate',
        )

        line = format_status(base)
        self.assertIn('12.5k in (2.5k cached) / 1.2k out', line)
        self.assertIn('~$0.1500/$0.5000 cap', line)
        self.assertIn('(1 unreported)', line)
        self.assertIn('SPEND INDETERMINATE', format_status(dict(base, spend_indeterminate=True)))
        self.assertIn('SPEND CAP REACHED', format_status(dict(base, spend_cap_exceeded=True, spend_cap_low=False)))

    def test_shared_enrich_status_across_renew_and_models_active(self):
        from local_assist.session import enrich_status, main
        from contextlib import redirect_stdout, redirect_stderr
        import importlib.machinery, io, types

        # enrich_status strips raw 'token' and sets proxy vs catalog provenance
        raw_proxy = dict(
            self.status(),
            prompt_tokens=1000,
            cached_prompt_tokens=0,
            completion_tokens=500,
            usage_reported_requests=1,
            usage_unreported_requests=0,
            estimated_micro_usd=250_000,
            max_actual_micro_usd=1_000_000,
            spend_cap_exceeded=False,
            spend_cap_low=False,
            spend_indeterminate=False,
            token='se-session-' + 'f' * 64,
        )
        enriched = enrich_status(raw_proxy, model_id='tinfoil-deepseek-v4-1-flash')
        self.assertNotIn('token', enriched)
        self.assertEqual(enriched['estimated_usd'], 0.25)
        self.assertEqual(enriched['estimated_usd_source'], 'proxy')
        self.assertEqual(enriched['max_actual_usd'], 1.0)

        # Catalog fallback when estimated_micro_usd is absent
        raw_no_price = dict(
            self.status(),
            prompt_tokens=1_000_000,
            cached_prompt_tokens=0,
            completion_tokens=1_000_000,
            usage_reported_requests=1,
            usage_unreported_requests=0,
        )
        enriched_cat = enrich_status(raw_no_price, model_id='tinfoil-deepseek-v4-1-flash')
        self.assertEqual(enriched_cat['estimated_usd_source'], 'catalog')
        self.assertIsInstance(enriched_cat['estimated_usd'], float)

        # session renew enriches output (JSON + human) and refuses exceeded/indeterminate/0-req sessions
        rec = dict(model_id='tinfoil-deepseek-v4-1-flash', repo='deepseek-v4-1-flash', pid=123, pid_lstart='v')
        for bad_label, mut in [
            ('indeterminate', {'spend_indeterminate': True}),
            ('exceeded', {'spend_cap_exceeded': True}),
            ('zero_reqs', {'requests_remaining': 0, 'requests_used': 10}),
        ]:
            bad_live = dict(enriched, **mut)
            with self.subTest(bad_label=bad_label), \
                 patch('local_assist.session.select_model', return_value='tinfoil-deepseek-v4-1-flash'), \
                 patch('local_assist.session.read_pid_record_for_model', return_value=rec), \
                 patch('local_assist.session.status_for_record', return_value=bad_live), \
                 patch('local_assist.session.control_request') as ctrl, \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(main(['renew', '--for', '2h']), 1)
                ctrl.assert_not_called()

        renewed_raw = dict(raw_proxy, generation=2, model='deepseek-v4-1-flash')
        renewed_raw.pop('token')
        out_json = io.StringIO()
        with patch('local_assist.session.select_model', return_value='tinfoil-deepseek-v4-1-flash'), \
             patch('local_assist.session.read_pid_record_for_model', return_value=rec), \
             patch('local_assist.session.status_for_record', return_value=enriched), \
             patch('local_assist.session.control_request', return_value=renewed_raw), \
             redirect_stdout(out_json), redirect_stderr(io.StringIO()):
            self.assertEqual(main(['renew', '--for', '2h', '--json']), 0)
        parsed = json.loads(out_json.getvalue())
        self.assertEqual(parsed['estimated_usd'], 0.25)
        self.assertEqual(parsed['estimated_usd_source'], 'proxy')
        self.assertEqual(parsed['max_actual_usd'], 1.0)

        out_human = io.StringIO()
        with patch('local_assist.session.select_model', return_value='tinfoil-deepseek-v4-1-flash'), \
             patch('local_assist.session.read_pid_record_for_model', return_value=rec), \
             patch('local_assist.session.status_for_record', return_value=enriched), \
             patch('local_assist.session.control_request', return_value=renewed_raw), \
             redirect_stdout(out_human), redirect_stderr(io.StringIO()):
            self.assertEqual(main(['renew', '--for', '2h']), 0)
        self.assertIn('~$0.2500/$1.00 cap', out_human.getvalue())

        # scripts/models --active separates recorded_max_actual_usd from live max_actual_usd
        loader = importlib.machinery.SourceFileLoader('session_models_cap', str(ROOT / 'scripts/models'))
        mod = types.ModuleType(loader.name); mod.__file__ = str(ROOT / 'scripts/models')
        loader.exec_module(mod)
        pid_rec = dict(
            model_id='tinfoil-deepseek-v4-1-flash',
            repo='deepseek-v4-1-flash',
            runtime='proxy',
            pid=123,
            ttl_seconds=7200,
            max_actual_usd=2.5,
            max_actual_micro_usd=2_500_000,
        )
        # Legacy / unreachable control socket -> recorded_max_actual_usd only, live max_actual_usd is None
        with patch.object(mod, 'classify_pid_identity', return_value='matched'), \
             patch('local_assist.session.status_for_record', return_value={'state': 'UNKNOWN', 'model_id': 'tinfoil-deepseek-v4-1-flash'}):
            info_unk = mod._classify_session_record(pid_rec)
        self.assertEqual(info_unk['recorded_max_actual_usd'], 2.5)
        self.assertIsNone(info_unk['max_actual_usd'])

        # Verified ON control socket with live cap -> live max_actual_usd populated from authorization
        with patch.object(mod, 'classify_pid_identity', return_value='matched'), \
             patch('local_assist.session.status_for_record', return_value=enriched):
            info_on = mod._classify_session_record(pid_rec)
        self.assertEqual(info_on['recorded_max_actual_usd'], 2.5)
        self.assertEqual(info_on['max_actual_usd'], 1.0)
        self.assertEqual(info_on['authorization']['estimated_usd'], 0.25)

        # Sub-cent ($0.000001) live and recorded caps render with microdollar precision, never rounded to $0.00
        subcent_live = dict(enriched, max_actual_micro_usd=1, max_actual_usd=0.000001)
        subcent_rec = dict(pid_rec, max_actual_usd=0.000001, max_actual_micro_usd=1)
        with patch.object(mod, 'list_active_sessions', return_value=[
            dict(info_on, mode='interactive', max_actual_usd=0.000001, authorization=subcent_live),
            dict(info_unk, mode='interactive', max_actual_usd=None, recorded_max_actual_usd=0.000001, authorization=None),
        ]), redirect_stdout(out_subcent := io.StringIO()):
            self.assertEqual(mod.main(['models', '--active']), 0)
        subcent_txt = out_subcent.getvalue()
        self.assertIn('max_actual_usd=$0.000001', subcent_txt)
        self.assertIn('recorded_max_actual_usd=$0.000001 (launch intent)', subcent_txt)
        self.assertNotIn('max_actual_usd=$0.00 ', subcent_txt)

        # Malformed recorded caps (1e400/inf, nan, negative, over-bound, bool) never crash or emit nonstandard JSON;
        # valid bounded max_actual_micro_usd is preferred over a malformed max_actual_usd field.
        with patch.object(mod, 'classify_pid_identity', return_value='matched'), \
             patch('local_assist.session.status_for_record', return_value={'state': 'UNKNOWN', 'model_id': 'tinfoil-deepseek-v4-1-flash'}):
            pref_rec = dict(pid_rec, max_actual_micro_usd=2_500_000, max_actual_usd=float('inf'))
            self.assertEqual(mod._classify_session_record(pref_rec)['recorded_max_actual_usd'], 2.5)
            legacy_rec = {k: v for k, v in pid_rec.items() if k != 'max_actual_micro_usd'}
            legacy_rec['max_actual_usd'] = 1.25
            self.assertEqual(mod._classify_session_record(legacy_rec)['recorded_max_actual_usd'], 1.25)
            for bad_cap in (float('inf'), float('-inf'), float('nan'), -1.0, 0.0, 0.0000006, 100000.0000004, 100001.0, 10**310, True, 'bad'):
                bad_rec = {k: v for k, v in pid_rec.items() if k != 'max_actual_micro_usd'}
                bad_rec['max_actual_usd'] = bad_cap
                classified_bad = mod._classify_session_record(bad_rec)
                self.assertIsNone(classified_bad['recorded_max_actual_usd'], f'bad_cap={bad_cap!r}')
            for bad_micro in (0, -5, 100_000_000_001, True, '100', 1.5):
                bad_m_rec = dict(pid_rec, max_actual_micro_usd=bad_micro, max_actual_usd=1.0)
                self.assertIsNone(mod._classify_session_record(bad_m_rec)['recorded_max_actual_usd'], f'bad_micro={bad_micro!r}')

            # End-to-end human and strict JSON rendering on malformed 1e400 PID record never raises or emits Infinity
            inf_rec = json.loads(json.dumps({k: v for k, v in pid_rec.items() if k != 'max_actual_micro_usd'}).replace('2.5', '1e400'))
            inf_classified = dict(mod._classify_session_record(inf_rec), mode='interactive')
            with patch.object(mod, 'list_active_sessions', return_value=[inf_classified]), \
                 redirect_stdout(out_inf_h := io.StringIO()):
                self.assertEqual(mod.main(['models', '--active']), 0)
            self.assertNotIn('recorded_max_actual_usd=', out_inf_h.getvalue())
            with patch.object(mod, 'list_active_sessions', return_value=[inf_classified]), \
                 redirect_stdout(out_inf_j := io.StringIO()):
                self.assertEqual(mod.main(['models', '--active', '--json']), 0)
            parsed_inf_j = json.loads(out_inf_j.getvalue(), parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
            self.assertIsNone(parsed_inf_j['sessions'][0]['recorded_max_actual_usd'])

        # verify_live_spend_cap directly requires literal False for spend_indeterminate and spend_cap_exceeded
        from local_assist.session import verify_live_spend_cap
        valid_info = dict(enriched)
        self.assertIsNone(verify_live_spend_cap(valid_info, 1_000_000, model_id='tinfoil-deepseek-v4-1-flash'))
        for field in ('spend_indeterminate', 'spend_cap_exceeded'):
            for bad_val in ('__missing__', None, 0, 'false', True):
                mut = dict(valid_info)
                if bad_val == '__missing__':
                    mut.pop(field, None)
                else:
                    mut[field] = bad_val
                with self.subTest(field=field, bad_val=bad_val):
                    self.assertIsNotNone(verify_live_spend_cap(mut, 1_000_000, model_id='tinfoil-deepseek-v4-1-flash'))

    def test_session_start_max_actual_usd_reuse_and_cold_start(self):
        from local_assist.session import main
        from contextlib import redirect_stdout, redirect_stderr
        import io, os, subprocess, tempfile

        rec = dict(model_id='tinfoil-deepseek-v4-1-flash', repo='deepseek-v4-1-flash', pid=123)
        healthy_cap = dict(
            self.status(),
            model_id='tinfoil-deepseek-v4-1-flash',
            prompt_tokens=0,
            cached_prompt_tokens=0,
            completion_tokens=0,
            usage_reported_requests=0,
            usage_unreported_requests=0,
            estimated_micro_usd=0,
            estimated_usd=0.0,
            estimated_usd_source='proxy',
            max_actual_micro_usd=1_000_000,
            max_actual_usd=1.0,
            spend_cap_exceeded=False,
            spend_cap_low=False,
            spend_indeterminate=False,
        )
        with tempfile.TemporaryDirectory() as tmp_runs:
            Path(tmp_runs).chmod(0o700)
            env_patch = {'FREE_INFERENCE_RUNS_DIR': tmp_runs}
            # Already-ON reuse checks
            for label, status_obj, req_arg, expected_rc in [
                ('equal_cap', healthy_cap, '1.00', 0),
                ('stricter_live_cap', healthy_cap, '2.00', 0),
                ('looser_live_cap', healthy_cap, '0.50', 1),
                ('legacy_no_cap', dict(self.status(), model_id='tinfoil-deepseek-v4-1-flash'), '1.00', 1),
                ('zero_requests_remaining', dict(healthy_cap, requests_remaining=0, requests_used=10), '1.00', 1),
                ('indeterminate', dict(healthy_cap, spend_indeterminate=True), '1.00', 1),
                ('exceeded', dict(healthy_cap, spend_cap_exceeded=True), '1.00', 1),
            ]:
                with self.subTest(label=label), \
                     patch.dict(os.environ, env_patch), \
                     patch('local_assist.session.select_model', return_value='tinfoil-deepseek-v4-1-flash'), \
                     patch('local_assist.session.read_pid_record_for_model', return_value=rec), \
                     patch('local_assist.session.status_for_record', return_value=status_obj), \
                     patch('local_assist.session.subprocess.run') as run, \
                     redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(main(['start', '--max-actual-usd', req_arg]), expected_rc)
                    run.assert_not_called()

            # Cold start forwards --max-actual-usd to serve-model and verifies post-start status
            captured_cmds = []
            def _fake_run(cmd, **kw):
                captured_cmds.append(list(cmd))
                return subprocess.CompletedProcess(cmd, 0)

            with patch.dict(os.environ, env_patch), \
                 patch('local_assist.session.select_model', return_value='tinfoil-deepseek-v4-1-flash'), \
                 patch('local_assist.session.read_pid_record_for_model', side_effect=[None, rec]), \
                 patch('local_assist.session.status_for_record', return_value=healthy_cap), \
                 patch('local_assist.session.subprocess.run', side_effect=_fake_run), \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(main(['start', '--max-actual-usd', '1.00']), 0)
            self.assertEqual(len(captured_cmds), 1)
            self.assertIn('--max-actual-usd', captured_cmds[0])
            self.assertEqual(captured_cmds[0][captured_cmds[0].index('--max-actual-usd') + 1], '1')

            # Cold start fails closed if post-start status is missing cap or exceeded
            with patch.dict(os.environ, env_patch), \
                 patch('local_assist.session.select_model', return_value='tinfoil-deepseek-v4-1-flash'), \
                 patch('local_assist.session.read_pid_record_for_model', side_effect=[None, rec]), \
                 patch('local_assist.session.status_for_record', return_value=dict(healthy_cap, spend_cap_exceeded=True)), \
                 patch('local_assist.session.subprocess.run', side_effect=_fake_run), \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(main(['start', '--max-actual-usd', '1.00']), 1)

        # CLI rejects Unicode / overlong --max-actual-usd with SystemExit(2)
        for bad_arg in ['\u0661.5', '1' + ('0' * 33), '0', '1e2']:
            with self.subTest(bad_arg=bad_arg), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as ctx:
                    main(['start', '--max-actual-usd', bad_arg])
                self.assertEqual(ctx.exception.code, 2)

    def test_lease_supplier_identity_and_cap_binding_initial_and_refresh(self):
        import os, tempfile
        from local_assist.registry import session_token_file_for_model
        from local_assist.session import SessionLeaseSupplier

        model_id = 'tinfoil-deepseek-v4-1-flash'
        tok = 'se-session-' + 'b' * 64
        with tempfile.TemporaryDirectory() as tmp:
            store = Path(tmp)
            store.chmod(0o700)
            tok_path = session_token_file_for_model(model_id, store)
            tok_path.write_text(json.dumps({'session_id': 'sess-1', 'generation': 1, 'token': tok}), encoding='utf-8')
            tok_path.chmod(0o600)
            rec = {'model_id': model_id, 'repo': 'deepseek-v4-1-flash', 'pid': os.getpid(), 'port': 8081}

            base_snap = dict(
                self.status(),
                session_id='sess-1',
                pid=os.getpid(),
                remaining_milliseconds=60_000,
                prompt_tokens=0,
                cached_prompt_tokens=0,
                completion_tokens=0,
                usage_reported_requests=0,
                usage_unreported_requests=0,
                estimated_micro_usd=0,
                max_actual_micro_usd=1_000_000,
                spend_cap_exceeded=False,
                spend_cap_low=False,
                spend_indeterminate=False,
            )

            # Initial acquisition fails if session_id, cap, or usability mismatches
            for label, snap in [
                ('wrong_session_id', dict(base_snap, session_id='sess-2')),
                ('missing_cap', self.status() | {'session_id': 'sess-1', 'pid': os.getpid(), 'remaining_milliseconds': 60_000}),
                ('looser_cap', dict(base_snap, max_actual_micro_usd=2_000_000)),
                ('indeterminate', dict(base_snap, spend_indeterminate=True)),
                ('exceeded', dict(base_snap, spend_cap_exceeded=True)),
                ('zero_reqs', dict(base_snap, requests_remaining=0, requests_used=10)),
            ]:
                with self.subTest(label=label):
                    sup = SessionLeaseSupplier(rec, store, expected_session_id='sess-1', required_max_actual_micro_usd=1_000_000)
                    try:
                        with patch('local_assist.session.status_for_record', return_value=snap):
                            with self.assertRaises(ValueError):
                                sup()
                    finally:
                        sup.close()

            # Initial acquisition succeeds, then mid-session refresh keeps bound session usable even after cap exceeded
            sup = SessionLeaseSupplier(rec, store, expected_session_id='sess-1', required_max_actual_micro_usd=1_000_000)
            try:
                with patch('local_assist.session.status_for_record', return_value=base_snap):
                    first = sup()
                self.assertEqual(first['token'], tok)
                # Mid-session refresh after cap exhausted on SAME session_id still returns token so proxy 429 reaches client
                after_exceeded = dict(base_snap, spend_cap_exceeded=True)
                with patch('local_assist.session.status_for_record', return_value=after_exceeded):
                    refreshed = sup.refresh()
                self.assertEqual(refreshed['token'], tok)
                # Mid-session refresh refuses if cap disappears or loosens or session_id changes
                for bad_ref in [
                    dict(base_snap, max_actual_micro_usd=2_000_000),
                    dict(base_snap, session_id='sess-other'),
                    {k: v for k, v in base_snap.items() if k != 'max_actual_micro_usd'},
                ]:
                    with patch('local_assist.session.status_for_record', return_value=bad_ref):
                        with self.assertRaises(ValueError):
                            sup.refresh()
            finally:
                sup.close()


if __name__ == '__main__':
    unittest.main()
