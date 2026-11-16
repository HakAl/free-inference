"""Operator-only session control. Never return credentials or read them for status."""
from __future__ import annotations

import argparse
import ctypes
import errno
import functools
import hashlib
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import subprocess
import sys
import time
import threading
from typing import Any

from .paths import ROOT
from .registry import (ATTESTED_ENCLAVE_TIERS, list_pid_records, load_model, load_models,
                       read_pid_record_for_model, resolve_endpoint, session_token_file_for_model)
from .registry import _effective_runs_dir

DEFAULT_WINDOW_SECONDS = 7200
MAX_WINDOW_SECONDS = 86400


class OperatorError(ValueError):
    """A static, safe-to-display operator diagnostic, never an external exception."""


@functools.lru_cache(maxsize=1)
def _continuous_clock():
    if sys.platform == 'darwin':
        class Timebase(ctypes.Structure):
            _fields_ = [('numer', ctypes.c_uint32), ('denom', ctypes.c_uint32)]
        library = ctypes.CDLL('/usr/lib/libSystem.B.dylib')
        info = Timebase()
        library.mach_timebase_info.argtypes = [ctypes.POINTER(Timebase)]
        if library.mach_timebase_info(ctypes.byref(info)) != 0 or not info.denom:
            raise ValueError('Continuous clock unavailable.')
        clock = library.mach_continuous_time
        clock.argtypes = []; clock.restype = ctypes.c_uint64
        scale = info.numer / info.denom / 1_000_000_000
        return lambda: clock() * scale
    if hasattr(time, 'CLOCK_BOOTTIME'):
        return lambda: time.clock_gettime(time.CLOCK_BOOTTIME)
    raise ValueError('Sleep-aware clock unavailable.')


def _continuous_time() -> float:
    return _continuous_clock()()


class _ProcessWatch:
    """Kernel lifetime observation, without process spawning or filesystem polling."""
    def __init__(self, pid: int):
        self.queue = None
        self.pidfd = None
        if hasattr(select, 'kqueue'):
            self.queue = select.kqueue()
            event = select.kevent(pid, filter=select.KQ_FILTER_PROC,
                flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_ONESHOT,
                fflags=select.KQ_NOTE_EXIT)
            self.queue.control([event], 0, 0)
        elif hasattr(os, 'pidfd_open'):
            self.pidfd = os.pidfd_open(pid)
        else:
            raise ValueError('Process lifetime observation unavailable.')

    def exited(self) -> bool:
        try:
            if self.queue is not None:
                return bool(self.queue.control([], 1, 0))
            if self.pidfd is not None:
                return bool(select.select([self.pidfd], [], [], 0)[0])
        except (OSError, ValueError):
            pass
        return True

    def close(self):
        if self.queue is not None:
            self.queue.close(); self.queue = None
        if self.pidfd is not None:
            os.close(self.pidfd); self.pidfd = None

    def __del__(self):
        try: self.close()
        except Exception: pass


def parse_duration(text: str) -> int:
    match = re.fullmatch(r'([0-9]+)([smh])', text) if isinstance(text, str) else None
    if not match or len(match[1]) > 8:
        raise ValueError('Window must be a positive integer with s, m, or h units (maximum 24h).')
    seconds = int(match[1]) * {'s': 1, 'm': 60, 'h': 3600}[match[2]]
    if not 1 <= seconds <= MAX_WINDOW_SECONDS:
        raise ValueError('Window must be between 1s and 24h.')
    return seconds


def control_path(runs_dir: Path, model_id: str) -> Path:
    return runs_dir / '.control' / (hashlib.sha256(model_id.encode()).hexdigest()[:16] + '.sock')


def control_node_present(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def _validate_store(runs_dir: Path) -> None:
    node = runs_dir.lstat()
    if (not stat.S_ISDIR(node.st_mode) or node.st_uid != os.geteuid()
            or stat.S_IMODE(node.st_mode) & 0o022):
        raise ValueError('Untrusted session store directory.')


def control_request(path: Path, request: dict, *, expected_pid: int, timeout: float = 3) -> dict:
    # No bearer secret. Kernel peer identity and a protected socket authorize control.
    _validate_store(path.parent.parent)
    parent = path.parent.lstat()
    node = path.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) != 0o700 or path.parent.is_symlink()
            or not stat.S_ISSOCK(node.st_mode) or node.st_uid != os.geteuid()
            or stat.S_IMODE(node.st_mode) != 0o600):
        raise ValueError('Untrusted session control socket.')
    wire = json.dumps(request, separators=(',', ':')).encode() + b'\n'
    if len(wire) > 4096:
        raise ValueError('Control request too large.')
    if len(os.fsencode(path)) >= 104:
        # A separate process may chdir without changing the launcher's thread state.
        # No credential is sent in argv or environment; requests travel over stdin.
        code = ('import os,sys;sys.path.insert(0,sys.argv[1]);'
                'from local_assist.session import _control_exchange;os.chdir(sys.argv[2])\n'
                'try: out=_control_exchange(sys.argv[3],sys.stdin.buffer.read(4097),int(sys.argv[4]),float(sys.argv[5]))\n'
                'except OSError as exc: raise SystemExit(exc.errno if exc.errno and 0<exc.errno<126 else 1)\n'
                'sys.stdout.buffer.write(out)')
        try:
            proc = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(ROOT),
                str(path.parent), path.name, str(expected_pid), str(timeout)], input=wire,
                capture_output=True, timeout=timeout+2, env={'PATH': os.defpath})
        except subprocess.SubprocessError:
            raise ValueError('Session control helper unavailable.') from None
        if proc.returncode:
            if 0 < proc.returncode < 126:
                raise OSError(proc.returncode, 'Session control connection failed.')
            raise ValueError('Session control helper unavailable.')
        raw = proc.stdout
    else:
        raw = _control_exchange(str(path), wire, expected_pid, timeout)
    result = json.loads(raw.split(b'\n', 1)[0])
    if not isinstance(result, dict) or 'error' in result:
        raise ValueError('Session control refused the operation; check status before retrying.')
    return result


def _control_exchange(address: str, wire: bytes, expected_pid: int, timeout: float) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout)
        conn.connect(address)
        if sys.platform == 'darwin':
            peer = struct.unpack('i', conn.getsockopt(0, 2, 4))[0]  # LOCAL_PEERPID
        elif hasattr(socket, 'SO_PEERCRED'):
            peer = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[0]
        else:
            raise ValueError('Cannot verify control-server process identity.')
        if peer != expected_pid:
            raise ValueError('Control-server process identity changed.')
        if len(wire) > 4096:
            raise ValueError('Control request too large.')
        conn.sendall(wire)
        raw = bytearray()
        while b'\n' not in raw and len(raw) < 4096:
            chunk = conn.recv(min(1024, 4096 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if b'\n' not in raw:
            raise ValueError('Incomplete or oversized control response.')
        return bytes(raw)


def remove_stale_control_socket(runs_dir: Path, model_id: str, expected_pid: int) -> bool:
    path = control_path(runs_dir, model_id)
    try:
        node = path.lstat()
    except FileNotFoundError:
        return True
    try:
        control_request(path, {'action': 'status'}, expected_pid=expected_pid, timeout=0.25)
    except OSError as exc:
        if exc.errno != errno.ECONNREFUSED:
            return False
    except ValueError:
        return False
    else:
        return False  # Never unlink a listening endpoint, including a replacement.
    current = path.lstat()
    if (not stat.S_ISSOCK(current.st_mode) or current.st_uid != os.geteuid()
            or stat.S_IMODE(current.st_mode) != 0o600
            or (current.st_dev, current.st_ino) != (node.st_dev, node.st_ino)):
        return False
    path.unlink()
    return True


def sanitize_status(raw: dict, *, expected_model: str, expected_pid: int) -> dict:
    if (not isinstance(raw, dict) or raw.get('protocol') != 1 or type(raw.get('protocol')) is not int
            or raw.get('model') != expected_model or raw.get('pid') != expected_pid
            or raw.get('state') not in ('ON', 'OFF')):
        raise ValueError('Session status identity or protocol mismatch.')
    keys = ('generation', 'remaining_seconds', 'expires_at', 'requests_used', 'request_limit',
            'requests_remaining', 'window_seconds')
    for key in keys:
        value = raw.get(key)
        if type(value) is not int or value < 0:
            raise ValueError('Invalid session status counter.')
    if (not 1 <= raw['window_seconds'] <= MAX_WINDOW_SECONDS or raw['generation'] < 1
            or raw['request_limit'] < 1 or raw['requests_remaining'] != raw['request_limit'] - raw['requests_used']
            or raw['remaining_seconds'] > raw['window_seconds']):
        raise ValueError('Inconsistent session status counters.')
    if (raw['state'] == 'OFF') != (raw['remaining_seconds'] == 0):
        raise ValueError('Inconsistent authorization state.')
    identity = raw.get('session_id')
    if not isinstance(identity, str) or not re.fullmatch(r'[A-Za-z0-9-]{1,64}', identity):
        raise ValueError('Invalid session identity.')
    result = {k: raw[k] for k in ('protocol', 'session_id', 'pid', 'model', 'state', *keys)}
    if 'remaining_milliseconds' in raw:
        milliseconds = raw['remaining_milliseconds']
        if (type(milliseconds) is not int or milliseconds < 0
                or not max(0, raw['remaining_seconds']-1)*1000 <= milliseconds <= raw['remaining_seconds']*1000):
            raise ValueError('Invalid continuous remaining time.')
        result['remaining_milliseconds'] = milliseconds
    return result


def status_for_record(record: dict, runs_dir: Path) -> dict:
    from .launch import classify_pid_identity
    model_id = record.get('model_id')
    if not isinstance(model_id, str) or not model_id.strip():
        return {'state': 'UNKNOWN', 'model_id': 'unknown'}
    identity = classify_pid_identity(record.get('pid'), record.get('pid_lstart'))
    if identity in ('dead', 'reused'):
        return {'state': 'OFF', 'model_id': model_id}
    if identity != 'matched':
        return {'state': 'UNKNOWN', 'model_id': model_id}
    try:
        raw = control_request(control_path(runs_dir, model_id), {'action': 'status'},
                              expected_pid=record['pid'])
        result = sanitize_status(raw, expected_model=record['repo'], expected_pid=record['pid'])
        return dict(result, model_id=model_id)
    except (OSError, ValueError, KeyError):
        return {'state': 'UNKNOWN', 'model_id': model_id}


def format_status(info: dict) -> str:
    state = info.get('state', 'UNKNOWN')
    model = info.get('model_id', info.get('model', 'session'))
    if state != 'ON':
        return f'{state}  {model}'
    remaining = info['remaining_seconds']
    return (f"ON  {model}  {remaining // 3600}h {(remaining % 3600) // 60}m {remaining % 60}s remaining  "
            f"{info['requests_remaining']}/{info['request_limit']} requests left")


def warning_reason(info: dict) -> str | None:
    if info.get('state') != 'ON':
        return None
    if info['remaining_seconds'] <= 300:
        return 'expires soon'
    if info['requests_remaining'] <= min(10, max(1, info['request_limit'] // 10)):
        return 'requests low'
    return None


class SessionLeaseSupplier:
    """Trusted parent only; identity-bound reads of atomically published credentials."""
    def __init__(self, record: dict, runs_dir: Path):
        self.record = dict(record)
        self.runs_dir = runs_dir
        self.session_id: str | None = None
        self._cached: dict | None = None
        self._lock = threading.RLock()
        self._watch: _ProcessWatch | None = None
        self._exited = False
        self._deadline = 0.0

    def __call__(self) -> dict:
        with self._lock:
            self._check_process()
            if self._cached is None or _continuous_time() >= self._deadline:
                return self.refresh()
            return dict(self._cached)

    def _check_process(self):
        if self._watch is not None and self._watch.exited():
            self._exited = True
        if self._exited:
            raise ValueError('Session process has exited.')

    def check_connection(self, connection: socket.socket):
        # Called after TCP connect and before sending any HTTP header/body. The
        # listener cannot transfer an established connection to a later process.
        self()
        peer = connection.getpeername()
        # se-key-proxy binds IPv4 loopback. An IPv6 localhost listener could be a
        # different receiver even while that process remains alive.
        if peer[0] != '127.0.0.1' or peer[1] != self.record.get('port'):
            raise ValueError('Session receiver changed.')

    def close(self):
        with self._lock:
            self._exited = True
            if self._watch is not None: self._watch.close()

    def refresh(self) -> dict:
        with self._lock:
            self._check_process()
            observed_at = _continuous_time()
            result = self._read_current()
            # Milliseconds are floored by the key holder. Anchor before RPC/file
            # reads, so transport time can only shorten the cached grant.
            remaining_ms = result.get('remaining_milliseconds', max(0, result['remaining_seconds']-1)*1000)
            deadline = observed_at + remaining_ms/1000
            if _continuous_time() >= deadline:
                raise ValueError('Cached session authorization has expired.')
            self._deadline = deadline
            self._cached = result
            return dict(result)

    def _read_current(self) -> dict:
        _validate_store(self.runs_dir)
        path = session_token_file_for_model(self.record['model_id'], self.runs_dir)
        for _ in range(2):
            before = status_for_record(self.record, self.runs_dir)
            if before['state'] != 'ON' or before['remaining_seconds'] <= 0:
                raise ValueError('Session authorization is unavailable.')
            if self.session_id is not None and self.session_id != before['session_id']:
                raise ValueError('Session was replaced; launch a new client.')
            self.session_id = before['session_id']
            if self._watch is None:
                self._watch = _ProcessWatch(self.record['pid'])
            self._check_process()
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            try:
                st = os.fstat(fd)
                if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid()
                        or stat.S_IMODE(st.st_mode) != 0o600 or st.st_size > 2048):
                    raise ValueError('Untrusted credential envelope.')
                envelope = json.loads(os.read(fd, 2049))
            finally:
                os.close(fd)
            after = status_for_record(self.record, self.runs_dir)
            if after.get('state') != 'ON' or after.get('remaining_seconds', 0) <= 0:
                raise ValueError('Session authorization is unavailable.')
            if (after.get('session_id') != before['session_id']
                    or after.get('generation') != before['generation']):
                continue
            if (not isinstance(envelope, dict) or envelope.get('session_id') != before['session_id']
                    or envelope.get('generation') != before['generation']
                    or type(envelope.get('generation')) is not int
                    or not isinstance(envelope.get('token'), str)
                    or not re.fullmatch(r'se-session-[a-f0-9]{64}', envelope['token'])):
                raise ValueError('Credential envelope generation mismatch.')
            if self.session_id is not None and self.session_id != before['session_id']:
                raise ValueError('Session was replaced; launch a new client.')
            self.session_id = before['session_id']
            return dict(before, token=envelope['token'])
        raise ValueError('Session changed during credential read.')


def select_model(explicit: str | None, runs_dir: Path) -> str:
    def admitted(model_id: str) -> str:
        model = load_model(model_id)
        if resolve_endpoint(model, require_api_key=False).trust_tier not in ATTESTED_ENCLAVE_TIERS:
            raise OperatorError('Session windows apply only to attested models.')
        return model_id
    if explicit:
        return admitted(explicit)
    configured = os.environ.get('FREE_INFERENCE_DEFAULT_ATTESTED_MODEL', '').strip()
    if configured:
        return admitted(configured)
    from .launch import classify_pid_identity
    active = {r.get('model_id') for _, r in list_pid_records(runs_dir)
              if r.get('session_token_file') and classify_pid_identity(r.get('pid'), r.get('pid_lstart'))
              not in ('dead', 'reused')}
    if len(active) == 1:
        model_id = active.pop()
        if not isinstance(model_id, str) or not model_id.strip():
            raise OperatorError('Malformed session record; specify --model.')
        return admitted(model_id)
    if active:
        raise OperatorError('Multiple sessions; specify --model.')
    defaults = [m['id'] for m in load_models() if (m.get('routing') or {}).get('default_private_attested') is True]
    if len(defaults) != 1:
        raise OperatorError('Specify --model to select a session.')
    return admitted(defaults[0])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Manage operator-authorized attested session windows.')
    parser.add_argument('action', choices=['status', 'start', 'stop', 'renew', 'watch'])
    parser.add_argument('--model')
    parser.add_argument('--for', dest='window', type=parse_duration, default=DEFAULT_WINDOW_SECONDS)
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--notify', action='store_true', help='Send macOS notifications from foreground watch.')
    args = parser.parse_args(argv)
    runs = _effective_runs_dir()
    try:
        model_id = select_model(args.model, runs)
        record = read_pid_record_for_model(model_id, runs)
        info = status_for_record(record, runs) if record else {'state': 'OFF', 'model_id': model_id}
        if args.action == 'start':
            if info['state'] == 'UNKNOWN':
                raise OperatorError('Existing session state is unknown; refusing automatic replacement.')
            if info['state'] == 'ON':
                print('Existing session unchanged; use session renew to change its window.', file=sys.stderr)
            if info['state'] == 'OFF':
                model = load_model(model_id)
                ep = resolve_endpoint(model, require_api_key=False)
                from .launch import check_endpoint_lifecycle_status, check_uncontained_legacy_home
                check_endpoint_lifecycle_status(ep)
                if (ep.runtime != 'proxy' or not ep.is_local_host or not ep.attestation_method
                        or not ep.api_key_keychain_service or not ep.capabilities.get('tool_calling')):
                    raise OperatorError('Session start requires an attested loopback coding proxy with a sealed key.')
                home_override = os.environ.get('FREE_INFERENCE_OPENCODE_ATTESTED_HOME', '').strip()
                home = Path(home_override).expanduser().resolve() if home_override else ROOT / '.home/opencode-private-attested'
                if check_uncontained_legacy_home(home) is not None:
                    raise OperatorError('Legacy OpenCode state requires containment before session start.')
                if ep.routing_private_attested != 'cleared':
                    raise OperatorError('Model is not cleared for private attested use.')
                rc = subprocess.run([str(ROOT / 'scripts/serve-model'), model_id, '--interactive',
                                     '--ttl-seconds', str(args.window)], check=False,
                                    stdout=sys.stderr if args.json else None).returncode
                if rc:
                    return rc
                record = read_pid_record_for_model(model_id, runs)
                info = status_for_record(record, runs) if record else {'state': 'UNKNOWN', 'model_id': model_id}
        elif args.action == 'stop':
            # Existing stop code revalidates exact process identities before signaling.
            if record:
                rc = subprocess.run([str(ROOT / 'scripts/stop-model'), model_id], check=False,
                                    stdout=sys.stderr if args.json else None).returncode
                if rc:
                    return rc
                record = read_pid_record_for_model(model_id, runs)
                info = status_for_record(record, runs) if record else {'state': 'OFF', 'model_id': model_id}
        elif args.action == 'renew':
            if info['state'] != 'ON' or info['requests_remaining'] <= 0:
                raise OperatorError('Renewal requires a live session with remaining requests.')
            print(f"Authorize {model_id} for {args.window}s; request budget unchanged.", file=sys.stderr)
            raw = control_request(control_path(runs, model_id), dict(action='renew', seconds=args.window,
                                  session_id=info['session_id'], generation=info['generation']),
                                  expected_pid=record['pid'], timeout=180)
            info = dict(sanitize_status(raw, expected_model=record['repo'], expected_pid=record['pid']), model_id=model_id)
        elif args.action == 'watch':
            warned = set()
            while True:
                print(json.dumps(info) if args.json else format_status(info), flush=True)
                reason = warning_reason(info)
                key = (info.get('session_id'), info.get('generation'), reason)
                if reason and key not in warned:
                    warned.add(key)
                    advice = ('Run session renew to authorize more time.' if reason == 'expires soon'
                              and info['requests_remaining'] > 0 else
                              'Renewal does not refill requests; a fresh budget needs an explicit stop/start.')
                    message = f'{model_id}: {reason}. {advice}'
                    print(message, file=sys.stderr, flush=True)
                    if args.notify and sys.platform == 'darwin':
                        try:
                            subprocess.run(['/usr/bin/osascript', '-e', 'on run argv\n display notification (item 1 of argv) with title "Inference session"\nend run', message], check=False, timeout=5, capture_output=True)
                        except (subprocess.TimeoutExpired, OSError):
                            print('Desktop notification unavailable; continuing to watch.', file=sys.stderr)
                if info['state'] != 'ON':
                    return 0 if info['state'] == 'OFF' else 1
                time.sleep(min(5, max(1, info['remaining_seconds'])))
                record = read_pid_record_for_model(model_id, runs)
                info = status_for_record(record, runs) if record else {'state': 'OFF', 'model_id': model_id}
        print(json.dumps(info) if args.json else format_status(info))
        return 0 if info['state'] != 'UNKNOWN' else 1
    except KeyboardInterrupt:
        return 130
    except OperatorError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception:
        # Never echo exception values: they may contain credential-store content.
        print('Session operation failed. Check model selection and session status; no automatic renewal or restart was attempted.', file=sys.stderr)
        return 1
