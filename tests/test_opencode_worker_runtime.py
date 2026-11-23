from __future__ import annotations

import base64
import contextlib
import errno
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import secrets
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _load_script_module(name: str, rel_path: str) -> Any:
    path = ROOT / rel_path
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _probe_can_run_sandbox_exec() -> bool:
    if sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").is_file():
        return False
    try:
        proc = subprocess.run(
            ["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)", "/usr/bin/true"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return proc.returncode == 0
    except OSError:
        return False


def _probe_can_bind_loopback_tcp() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.bind(("127.0.0.1", 0))
            return True
    except OSError:
        return False


def _probe_can_connect_loopback_tcp() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            port = srv.getsockname()[1]
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return True
    except OSError:
        return False


def _probe_can_bind_unix_socket() -> bool:
    base = "/private/tmp" if Path("/private/tmp").is_dir() and os.access("/private/tmp", os.W_OK) else None
    tmp = Path(tempfile.mkdtemp(prefix="fi-ubind-", dir=base))
    sock_p = tmp / "b.sock"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
            srv.bind(str(sock_p))
            return True
    except OSError:
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _probe_can_connect_unix_socket() -> bool:
    base = "/private/tmp" if Path("/private/tmp").is_dir() and os.access("/private/tmp", os.W_OK) else None
    tmp = Path(tempfile.mkdtemp(prefix="fi-uprobe-", dir=base))
    sock_p = tmp / "p.sock"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
            srv.bind(str(sock_p))
            srv.listen(1)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as cli:
                cli.settimeout(1.0)
                cli.connect(str(sock_p))
                return True
    except OSError:
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


CAN_RUN_SANDBOX_EXEC = _probe_can_run_sandbox_exec()
CAN_BIND_LOOPBACK_TCP = _probe_can_bind_loopback_tcp()
CAN_CONNECT_LOOPBACK_TCP = _probe_can_connect_loopback_tcp()
CAN_BIND_UNIX_SOCKET = _probe_can_bind_unix_socket()
CAN_CONNECT_UNIX_SOCKET = _probe_can_connect_unix_socket()
SHORT_TMP_DIR: str | None = "/tmp" if os.access("/tmp", os.W_OK) else None


def _probe_can_run_ps() -> bool:
    ps_bin = shutil.which("ps") or "/bin/ps"
    try:
        proc = subprocess.run(
            [ps_bin, "-p", str(os.getpid()), "-o", "lstart="],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        return proc.returncode == 0 and bool((proc.stdout or "").strip())
    except OSError:
        return False


CAN_RUN_PS = _probe_can_run_ps()
OPENCODE_BIN = shutil.which("opencode") or (
    "/opt/homebrew/bin/opencode" if Path("/opt/homebrew/bin/opencode").is_file() else None
)


def _format_bsdinfo_lstart(pid: Any) -> str | None:
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return None
    from datetime import datetime, timezone
    from local_assist.proc_identity import read_proc_bsdinfo

    st, info = read_proc_bsdinfo(pid)
    if st != "alive" or info is None:
        if sys.platform != "darwin" and not CAN_RUN_PS:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return None
            except PermissionError:
                pass
            # Distinct per-PID synthetic UTC lstart scoped solely to non-Darwin
            # mocked-ps fixtures when /bin/ps is absent (e.g., minimal slim containers).
            return datetime.fromtimestamp(1700000000 + (pid % 86400), timezone.utc).strftime(
                "%a %b %e %H:%M:%S %Y"
            )
        return None
    return datetime.fromtimestamp(int(info["start_tvsec"]), timezone.utc).strftime(
        "%a %b %e %H:%M:%S %Y"
    )


def _bsdinfo_is_zombie(pid: Any) -> bool:
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    from local_assist.proc_identity import read_proc_bsdinfo

    st, _ = read_proc_bsdinfo(pid)
    return st == "zombie"


def _install_outer_sandbox_ps_fixture_if_blocked(test_case: unittest.TestCase) -> None:
    """Only active when the outer test runner itself blocks /bin/ps; no-op on unrestricted hosts and CI."""
    if CAN_RUN_PS:
        return
    for target, fn in (
        ("local_assist.registry.get_process_lstart", _format_bsdinfo_lstart),
        ("local_assist.launch.get_process_lstart", _format_bsdinfo_lstart),
        ("local_assist.security_profile.get_process_lstart", _format_bsdinfo_lstart),
        ("local_assist.registry.pid_is_zombie", _bsdinfo_is_zombie),
        ("local_assist.launch.pid_is_zombie", _bsdinfo_is_zombie),
        ("local_assist.security_profile._scan_worker_pids", lambda **_: ({}, True)),
        ("local_assist.launch._cleanup_scope_opencode_service", lambda *a, **k: True),
    ):
        p = patch(target, side_effect=fn)
        p.start()
        test_case.addCleanup(p.stop)


def _canonical_tree_sha256(root: Path) -> str:
    """Compute canonical tree digest matching agent-comms Section 9.1."""
    h = hashlib.sha256()

    def _feed_bytes(b: bytes) -> None:
        h.update(len(b).to_bytes(8, "big"))
        h.update(b)

    root_st = os.lstat(root)
    if not stat.S_ISDIR(root_st.st_mode) or stat.S_ISLNK(root_st.st_mode):
        raise ValueError(f"Tree root is not a real directory: {root}")
    _feed_bytes(b"dir")
    _feed_bytes(f"{stat.S_IMODE(root_st.st_mode):04o}".encode("ascii"))

    entries: list[tuple[bytes, Path, os.stat_result]] = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dp = Path(dirpath)
        for name in [*dirnames, *filenames]:
            full = dp / name
            rel_bytes = full.relative_to(root).as_posix().encode("utf-8")
            st = os.lstat(full)
            entries.append((rel_bytes, full, st))
        dirnames[:] = [d for d in dirnames if not (dp / d).is_symlink()]

    entries.sort(key=lambda item: item[0])
    root_real = root.resolve()
    for rel_bytes, full, st in entries:
        _feed_bytes(rel_bytes)
        mode_bytes = f"{stat.S_IMODE(st.st_mode):04o}".encode("ascii")
        if stat.S_ISLNK(st.st_mode):
            target = os.readlink(full)
            if os.path.isabs(target):
                raise ValueError(f"Absolute symlink forbidden in custody tree: {full} -> {target}")
            resolved = (full.parent / target).resolve()
            if not (resolved == root_real or root_real in resolved.parents):
                raise ValueError(f"Escaping symlink forbidden in custody tree: {full} -> {target}")
            _feed_bytes(b"symlink")
            _feed_bytes(mode_bytes)
            _feed_bytes(os.fsencode(target))
        elif stat.S_ISDIR(st.st_mode):
            _feed_bytes(b"dir")
            _feed_bytes(mode_bytes)
        elif stat.S_ISREG(st.st_mode):
            _feed_bytes(b"file")
            _feed_bytes(mode_bytes)
            _feed_bytes(hashlib.sha256(full.read_bytes()).digest())
        else:
            raise ValueError(f"Unsupported file type in custody tree: {full}")
    return h.hexdigest()


_FAKE_CONTROL_SERVERS: dict[str, "_FakeControlSocketServer"] = {}


def _sandbox_fallback_control_request(path: Path, request: dict[str, Any], *, expected_pid: int, timeout: float = 3.0) -> dict[str, Any]:
    from local_assist.session import _validate_store

    del timeout
    _validate_store(path.parent.parent)
    parent = path.parent.lstat()
    node = path.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
        or path.parent.is_symlink()
        or node.st_uid != os.geteuid()
        or stat.S_IMODE(node.st_mode) != 0o600
    ):
        raise ValueError("Untrusted session control socket.")
    srv = _FAKE_CONTROL_SERVERS.get(str(path)) or _FAKE_CONTROL_SERVERS.get(str(path.parent.resolve() / path.name))
    if srv is None:
        raise ConnectionRefusedError(errno.ECONNREFUSED, "No fake control server registered")
    if expected_pid != os.getpid():
        raise ValueError("Control-server process identity changed.")
    result = srv.response_fn(request)
    if not isinstance(result, dict) or "error" in result:
        raise ValueError("Session control refused the operation; check status before retrying.")
    return dict(result)


def _sandbox_fallback_control_node_present(path: Path) -> bool:
    key = str(path)
    if key in _FAKE_CONTROL_SERVERS:
        return True
    try:
        if str(path.parent.resolve() / path.name) in _FAKE_CONTROL_SERVERS:
            return True
    except OSError:
        pass
    try:
        return stat.S_ISSOCK(path.lstat().st_mode)
    except OSError:
        return False


class _FakeControlSocketServer:
    """Hermetic AF_UNIX session control socket responder matching local_assist.session."""

    def __init__(self, sock_path: Path, response_fn: Any) -> None:
        self.sock_path = sock_path
        self.response_fn = response_fn
        self._stop = threading.Event()
        self._srv: socket.socket | None = None
        self._thread: threading.Thread | None = None
        sock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(sock_path.parent, 0o700)
        if sock_path.exists():
            sock_path.unlink()
        _FAKE_CONTROL_SERVERS[str(sock_path)] = self
        _FAKE_CONTROL_SERVERS[str(sock_path.parent.resolve() / sock_path.name)] = self
        self._patchers: list[Any] = []
        if CAN_BIND_UNIX_SOCKET:
            self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            old_umask = os.umask(0o177)
            try:
                self._srv.bind(str(sock_path))
            finally:
                os.umask(old_umask)
            os.chmod(sock_path, 0o600)
            self._srv.listen(8)
            self._srv.settimeout(0.1)
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()
        else:
            sock_path.write_text("", encoding="utf-8")
            os.chmod(sock_path, 0o600)
            p_node = patch(
                "local_assist.session.control_node_present",
                side_effect=_sandbox_fallback_control_node_present,
            )
            p_node.start()
            self._patchers.append(p_node)
        if not CAN_CONNECT_UNIX_SOCKET:
            p_req = patch(
                "local_assist.session.control_request",
                side_effect=_sandbox_fallback_control_request,
            )
            p_req.start()
            self._patchers.append(p_req)

    def _serve(self) -> None:
        assert self._srv is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                try:
                    raw = conn.recv(4096)
                    req = json.loads(raw.decode("utf-8").splitlines()[0])
                    payload = self.response_fn(req)
                    conn.sendall((json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8"))
                except Exception:
                    pass

    def close(self) -> None:
        self._stop.set()
        _FAKE_CONTROL_SERVERS.pop(str(self.sock_path), None)
        _FAKE_CONTROL_SERVERS.pop(str(self.sock_path.parent.resolve() / self.sock_path.name), None)
        for p in reversed(self._patchers):
            try:
                p.stop()
            except RuntimeError:
                pass
        self._patchers.clear()
        if self._srv is not None:
            try:
                self._srv.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        try:
            self.sock_path.unlink(missing_ok=True)
        except OSError:
            pass


class ProcIdentityAndReapProtocolTests(unittest.TestCase):
    def test_proc_bsdinfo_four_states_and_linux_fail_closed(self) -> None:
        from local_assist import proc_identity

        if sys.platform == "darwin":
            st_self, info_self = proc_identity.read_proc_bsdinfo(os.getpid())
            self.assertEqual(st_self, "alive")
            assert info_self is not None
            self.assertIs(type(info_self["start_tvsec"]), int)
            self.assertIs(type(info_self["start_tvusec"]), int)
            self.assertGreater(info_self["start_tvsec"], 0)
            self.assertEqual(info_self["uid"], os.geteuid())

            st_abs, info_abs = proc_identity.read_proc_bsdinfo(999_999_991)
            self.assertEqual(st_abs, "absent")
            self.assertIsNone(info_abs)

            # Spawn a quick child that exits without wait() so it enters SZOMB on Darwin.
            zproc = subprocess.Popen([sys.executable, "-I", "-B", "-c", "raise SystemExit(0)"])
            try:
                deadline = time.monotonic() + 3.0
                observed_zombie = False
                while time.monotonic() < deadline:
                    st_z, _ = proc_identity.read_proc_bsdinfo(zproc.pid)
                    if st_z == "zombie":
                        observed_zombie = True
                        break
                    time.sleep(0.01)
                self.assertTrue(observed_zombie, "Expected unwaited exited child to report 'zombie'")
            finally:
                zproc.wait(timeout=3.0)

        # Simulated non-ESRCH kernel error must return 'error', never 'absent' (r9 Section 5.2).
        with patch.object(proc_identity, "_raw_proc_pidinfo", return_value=(0, errno.EPERM)):
            st_err, info_err = proc_identity.read_proc_bsdinfo(os.getpid())
            self.assertEqual(st_err, "error")
            self.assertIsNone(info_err)

        # Simulated Linux / unsupported platform fails closed.
        with patch.object(proc_identity, "_DARWIN_LIB", None):
            st_lin, _ = proc_identity.read_proc_bsdinfo(os.getpid())
            self.assertEqual(st_lin, "error")
            pids_lin, ok_lin = proc_identity.list_all_pids()
            self.assertEqual(pids_lin, [])
            self.assertFalse(ok_lin)
            matched_lin, q_ok_lin = proc_identity.pid_matches_worker_tag(os.getpid(), "a" * 32)
            self.assertFalse(matched_lin)
            self.assertFalse(q_ok_lin)

    def test_sandbox_check_three_way_discriminator_and_query_errors(self) -> None:
        from local_assist import proc_identity

        tag = "0123456789abcdef0123456789abcdef"

        with patch.object(proc_identity, "_DARWIN_LIB", proc_identity._DARWIN_LIB or object()):
            # 1. Unsandboxed process (r0 == 0) -> (False, True)
            with patch.object(proc_identity, "_sandbox_check_none", return_value=(0, 0)):
                self.assertEqual(proc_identity.pid_matches_worker_tag(1234, tag), (False, True))

            # 2. Other worker / restrictive sandbox (r0 == 1, allow == 1) -> (False, True)
            with (
                patch.object(proc_identity, "_sandbox_check_none", return_value=(1, 0)),
                patch.object(proc_identity, "_sandbox_check_mach_lookup", side_effect=[(1, 0)]),
            ):
                self.assertEqual(proc_identity.pid_matches_worker_tag(1234, tag), (False, True))

            # 3. Permissive sandbox allowing all mach-lookup (r0 == 1, allow == 0, deny == 0) -> (False, True)
            with (
                patch.object(proc_identity, "_sandbox_check_none", return_value=(1, 0)),
                patch.object(proc_identity, "_sandbox_check_mach_lookup", side_effect=[(0, 0), (0, 0)]),
            ):
                self.assertEqual(proc_identity.pid_matches_worker_tag(1234, tag), (False, True))

            # 4. Exact worker match (r0 == 1, allow == 0, deny == 1) -> (True, True)
            with (
                patch.object(proc_identity, "_sandbox_check_none", return_value=(1, 0)),
                patch.object(proc_identity, "_sandbox_check_mach_lookup", side_effect=[(0, 0), (1, 0)]),
            ):
                self.assertEqual(proc_identity.pid_matches_worker_tag(1234, tag), (True, True))

            # 5. Kernel error (-1) when PID is still alive or zombie -> (False, False); when absent -> (False, True)
            for alive_state in ("alive", "zombie"):
                with (
                    patch.object(proc_identity, "_sandbox_check_none", return_value=(-1, errno.EINVAL)),
                    patch.object(proc_identity, "read_proc_bsdinfo", return_value=(alive_state, {"uid": 501})),
                ):
                    self.assertEqual(proc_identity.pid_matches_worker_tag(1234, tag), (False, False))

            with (
                patch.object(proc_identity, "_sandbox_check_none", return_value=(-1, errno.ESRCH)),
                patch.object(proc_identity, "read_proc_bsdinfo", return_value=("absent", None)),
            ):
                self.assertEqual(proc_identity.pid_matches_worker_tag(1234, tag), (False, True))

    def test_reap_manifest_validation_and_microsecond_mismatch(self) -> None:
        from local_assist.proc_identity import reap_worker_from_manifest

        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            tmp_dir = Path(tmp)
            os.chmod(tmp_dir, 0o700)
            valid_base = {
                "schema_version": 1,
                "run_token": "tok-123",
                "launcher_pid": 5000,
                "launcher_pgid": 5000,
                "launcher_start_tvsec": 1700000000,
                "launcher_start_tvusec": 123456,
                "worker_id": "worker-test",
                "isolated_home": "/tmp/iso",
                "worker_tag": "a" * 32,
                "children": [
                    {"role": "opencode_serve", "pid": 5001, "start_tvsec": 1700000000, "start_tvusec": 500}
                ],
            }

            bad_variants = [
                {**valid_base, "schema_version": 2},
                {**valid_base, "schema_version": True},
                {**valid_base, "run_token": ""},
                {**valid_base, "launcher_pgid": 5001},
                {**valid_base, "launcher_start_tvsec": "1700000000"},
                {**valid_base, "launcher_start_tvusec": False},
                {k: v for k, v in valid_base.items() if k != "launcher_start_tvusec"},
                {**valid_base, "worker_tag": "not-32-hex"},
                {
                    **valid_base,
                    "children": [{"role": "opencode_run", "pid": 5002, "start_tvsec": 1700000000}],
                },
                {
                    **valid_base,
                    "children": [
                        {
                            "role": "opencode_run",
                            "pid": 5002,
                            "start_tvsec": 1700000000,
                            "start_tvusec": "500",
                        }
                    ],
                },
            ]
            for idx, bad_obj in enumerate(bad_variants):
                mp = tmp_dir / f"bad-{idx}.json"
                mp.write_text(json.dumps(bad_obj), encoding="utf-8")
                os.chmod(mp, 0o600)
                err_buf = io.StringIO()
                with redirect_stderr(err_buf):
                    rc = reap_worker_from_manifest(mp)
                self.assertEqual(rc, 1, f"Variant {idx} must fail with 1 (never 4)")

            # World-readable 0644 manifest or symlink manifest is rejected with 1.
            mp_perm = tmp_dir / "perm.json"
            mp_perm.write_text(json.dumps(valid_base), encoding="utf-8")
            os.chmod(mp_perm, 0o644)
            with redirect_stderr(io.StringIO()):
                self.assertEqual(reap_worker_from_manifest(mp_perm), 1)

            mp_good = tmp_dir / "good.json"
            mp_good.write_text(json.dumps(valid_base), encoding="utf-8")
            os.chmod(mp_good, 0o600)
            mp_sym = tmp_dir / "sym.json"
            mp_sym.symlink_to(mp_good)
            with redirect_stderr(io.StringIO()):
                self.assertEqual(reap_worker_from_manifest(mp_sym), 1)

            # Equal tvsec (1700000000) with different tvusec (501 != 500) is a DIFFERENT process and receives ZERO signals!
            signals_sent: list[tuple[int, int]] = []

            def _fake_bsdinfo(pid: int) -> tuple[str, dict[str, Any] | None]:
                if pid in (5000, 5001):
                    return (
                        "alive",
                        {
                            "uid": os.geteuid(),
                            "pgid": pid,
                            "status": 2,
                            "start_tvsec": 1700000000,
                            "start_tvusec": 999999 if pid == 5000 else 501,
                        },
                    )
                return ("absent", None)

            with (
                patch("local_assist.proc_identity.read_proc_bsdinfo", side_effect=_fake_bsdinfo),
                patch("local_assist.proc_identity.list_all_pids", return_value=([5000, 5001], True)),
                patch("local_assist.proc_identity.pid_matches_worker_tag", return_value=(False, True)),
                patch("local_assist.proc_identity._send_signal", side_effect=lambda p, s: signals_sent.append((p, s))),
            ):
                rc_ok = reap_worker_from_manifest(mp_good)
            self.assertEqual(rc_ok, 0)
            self.assertEqual(signals_sent, [])

    def _write_test_manifest(self, tmp_dir: Path, *, tag: str = "b" * 32) -> Path:
        mp = tmp_dir / "manifest.json"
        mp.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "run_token": "tok-reap",
                    "launcher_pid": 4000,
                    "launcher_pgid": 4000,
                    "launcher_start_tvsec": 100,
                    "launcher_start_tvusec": 200,
                    "worker_id": "w-1",
                    "isolated_home": "/tmp/iso",
                    "worker_tag": tag,
                    "children": [],
                }
            ),
            encoding="utf-8",
        )
        os.chmod(mp, 0o600)
        return mp

    def test_r9_scenario_1_delayed_sstop_withholds_sigkill_until_stopped(self) -> None:
        from local_assist import proc_identity

        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            mp = self._write_test_manifest(Path(tmp))
            uid = os.geteuid()
            state = {"killed": False, "stop_sent": False, "polls_after_stop": 0}
            signals: list[tuple[int, int]] = []

            def _bsd(pid: int) -> tuple[str, dict[str, Any] | None]:
                if pid != 6001 or state["killed"]:
                    return ("absent", None)
                if not state["stop_sent"]:
                    st_code = proc_identity.SRUN
                else:
                    state["polls_after_stop"] += 1
                    st_code = proc_identity.SRUN if state["polls_after_stop"] < 4 else proc_identity.SSTOP
                return (
                    "alive",
                    {"uid": uid, "pgid": 6001, "status": st_code, "start_tvsec": 555, "start_tvusec": 777},
                )

            def _sig(pid: int, sig: int) -> None:
                signals.append((pid, sig))
                if sig == signal.SIGSTOP:
                    state["stop_sent"] = True
                elif sig == signal.SIGKILL:
                    self.assertGreaterEqual(
                        state["polls_after_stop"],
                        4,
                        "SIGKILL must not be sent before SSTOP is observed",
                    )
                    state["killed"] = True

            with (
                patch.object(proc_identity, "list_all_pids", side_effect=lambda: ([6001] if not state["killed"] else [], True)),
                patch.object(proc_identity, "read_proc_bsdinfo", side_effect=_bsd),
                patch.object(proc_identity, "pid_matches_worker_tag", return_value=(True, True)),
                patch.object(proc_identity, "_send_signal", side_effect=_sig),
            ):
                rc = proc_identity.reap_worker_from_manifest(mp)

            self.assertEqual(rc, 0)
            self.assertEqual(signals, [(6001, signal.SIGSTOP), (6001, signal.SIGKILL)])

    def test_r9_scenario_2_match_never_observed_stopped_exits_nonzero_without_sigkill(self) -> None:
        from local_assist import proc_identity

        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            mp = self._write_test_manifest(Path(tmp))
            uid = os.geteuid()
            signals: list[tuple[int, int]] = []

            def _bsd(pid: int) -> tuple[str, dict[str, Any] | None]:
                if pid != 6002:
                    return ("absent", None)
                return (
                    "alive",
                    {"uid": uid, "pgid": 6002, "status": proc_identity.SRUN, "start_tvsec": 555, "start_tvusec": 777},
                )

            err_buf = io.StringIO()
            with (
                redirect_stderr(err_buf),
                patch.object(proc_identity, "list_all_pids", return_value=([6002], True)),
                patch.object(proc_identity, "read_proc_bsdinfo", side_effect=_bsd),
                patch.object(proc_identity, "pid_matches_worker_tag", return_value=(True, True)),
                patch.object(proc_identity, "_send_signal", side_effect=lambda p, s: signals.append((p, s))),
            ):
                rc = proc_identity.reap_worker_from_manifest(mp, stop_timeout_sec=0.03, reap_timeout_sec=0.2)

            self.assertEqual(rc, 1)
            self.assertEqual(signals, [(6002, signal.SIGSTOP)])

    def test_r9_scenario_3_changed_hands_observed_stopped_unchanged_reread_sends_one_sigcont_and_exits_1(self) -> None:
        from local_assist import proc_identity

        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            mp = self._write_test_manifest(Path(tmp))
            uid = os.geteuid()
            state = {"6003_stopped": False, "6004_killed": False}
            signals: list[tuple[int, int]] = []

            def _bsd(pid: int) -> tuple[str, dict[str, Any] | None]:
                if pid == 6003:
                    # Before SIGSTOP: worker start (500, 100); after SIGSTOP: bystander replacement (500, 999) in SSTOP!
                    if not state["6003_stopped"]:
                        return ("alive", {"uid": uid, "pgid": 6003, "status": proc_identity.SRUN, "start_tvsec": 500, "start_tvusec": 100})
                    return ("alive", {"uid": uid, "pgid": 9999, "status": proc_identity.SSTOP, "start_tvsec": 500, "start_tvusec": 999})
                if pid == 6004 and not state["6004_killed"]:
                    return ("alive", {"uid": uid, "pgid": 6004, "status": proc_identity.SSTOP, "start_tvsec": 600, "start_tvusec": 200})
                return ("absent", None)

            def _match(pid: int, _tag: str) -> tuple[bool, bool]:
                if pid == 6003 and state["6003_stopped"]:
                    return (False, True)
                if pid in (6003, 6004):
                    return (True, True)
                return (False, True)

            def _sig(pid: int, sig: int) -> None:
                signals.append((pid, sig))
                if pid == 6003 and sig == signal.SIGSTOP:
                    state["6003_stopped"] = True
                if pid == 6004 and sig == signal.SIGKILL:
                    state["6004_killed"] = True

            err_buf = io.StringIO()
            with (
                redirect_stderr(err_buf),
                patch.object(proc_identity, "list_all_pids", side_effect=lambda: ([6003, 6004] if not state["6004_killed"] else [6003], True)),
                patch.object(proc_identity, "read_proc_bsdinfo", side_effect=_bsd),
                patch.object(proc_identity, "pid_matches_worker_tag", side_effect=_match),
                patch.object(proc_identity, "_send_signal", side_effect=_sig),
            ):
                rc = proc_identity.reap_worker_from_manifest(mp, stop_timeout_sec=0.05)

            self.assertEqual(rc, 1)
            # 6003 got SIGSTOP and ONE compensating SIGCONT (never SIGKILL/SIGTERM); 6004 was still swept and killed!
            sig_6003 = [s for p, s in signals if p == 6003]
            sig_6004 = [s for p, s in signals if p == 6004]
            self.assertEqual(sig_6003, [signal.SIGSTOP, signal.SIGCONT])
            self.assertEqual(sig_6004, [signal.SIGSTOP, signal.SIGKILL])
            self.assertIn("changed_hands pid=6003", err_buf.getvalue())

    def test_r9_scenario_4_changed_hands_reread_mismatch_disappeared_or_zombie_sends_nothing_and_logs(self) -> None:
        from local_assist import proc_identity

        uid = os.geteuid()
        subcases = [
            # (label, expected_reason, sequence_after_sigstop)
            (
                "reread_changed_again",
                "reason=reread_mismatch_or_gone",
                [
                    ("alive", {"uid": uid, "pgid": 1, "status": proc_identity.SSTOP, "start_tvsec": 500, "start_tvusec": 222}),
                    ("alive", {"uid": uid, "pgid": 1, "status": proc_identity.SSTOP, "start_tvsec": 500, "start_tvusec": 333}),
                ],
            ),
            (
                "poll_disappeared",
                "reason=disappeared",
                [
                    ("alive", {"uid": uid, "pgid": 1, "status": proc_identity.SRUN, "start_tvsec": 500, "start_tvusec": 222}),
                    ("absent", None),
                ],
            ),
            (
                "poll_zombie",
                "reason=zombie",
                [
                    ("alive", {"uid": uid, "pgid": 1, "status": proc_identity.SRUN, "start_tvsec": 500, "start_tvusec": 222}),
                    ("zombie", {"uid": uid, "pgid": 1, "status": proc_identity.SZOMB, "start_tvsec": 500, "start_tvusec": 222}),
                ],
            ),
            (
                "direct_zombie_replacement_on_first_post_stop_read",
                "reason=zombie",
                [
                    ("zombie", {"uid": uid, "pgid": 1, "status": proc_identity.SZOMB, "start_tvsec": 500, "start_tvusec": 222}),
                ],
            ),
            (
                "direct_zombie_replacement_on_post_sstop_reverify_read",
                "reason=zombie",
                [
                    ("alive", {"uid": uid, "pgid": 6010, "status": proc_identity.SSTOP, "start_tvsec": 500, "start_tvusec": 111}),
                    ("zombie", {"uid": uid, "pgid": 1, "status": proc_identity.SZOMB, "start_tvsec": 500, "start_tvusec": 222}),
                ],
            ),
            (
                "poll_changed_again",
                "reason=changed_again",
                [
                    ("alive", {"uid": uid, "pgid": 1, "status": proc_identity.SRUN, "start_tvsec": 500, "start_tvusec": 222}),
                    ("alive", {"uid": uid, "pgid": 1, "status": proc_identity.SRUN, "start_tvsec": 500, "start_tvusec": 444}),
                ],
            ),
        ]

        for label, expected_reason, post_stop_seq in subcases:
            with self.subTest(subcase=label), tempfile.TemporaryDirectory() as tmp:
                mp = self._write_test_manifest(Path(tmp))
                stop_sent_6010 = {"v": False}
                state_6011 = {"status": proc_identity.SRUN, "killed": False}
                seq_iter = iter(post_stop_seq)
                signals: list[tuple[int, int]] = []

                def _bsd(pid: int) -> tuple[str, dict[str, Any] | None]:
                    if pid == 6010:
                        if not stop_sent_6010["v"]:
                            return ("alive", {"uid": uid, "pgid": 6010, "status": proc_identity.SRUN, "start_tvsec": 500, "start_tvusec": 111})
                        return next(seq_iter, ("absent", None))
                    if pid == 6011 and not state_6011["killed"]:
                        return ("alive", {"uid": uid, "pgid": 6011, "status": state_6011["status"], "start_tvsec": 500, "start_tvusec": 999})
                    return ("absent", None)

                def _match(pid: int, _tag: str) -> tuple[bool, bool]:
                    if pid == 6010:
                        return (not stop_sent_6010["v"], True)
                    if pid == 6011:
                        return (not state_6011["killed"], True)
                    return (False, True)

                def _sig(pid: int, sig: int) -> None:
                    signals.append((pid, sig))
                    if pid == 6010 and sig == signal.SIGSTOP:
                        stop_sent_6010["v"] = True
                    elif pid == 6011 and sig == signal.SIGSTOP:
                        state_6011["status"] = proc_identity.SSTOP
                    elif pid == 6011 and sig == signal.SIGKILL:
                        state_6011["killed"] = True

                err_buf = io.StringIO()
                with (
                    redirect_stderr(err_buf),
                    patch.object(
                        proc_identity,
                        "list_all_pids",
                        side_effect=lambda: (
                            ([6010] if not stop_sent_6010["v"] else []) + ([6011] if not state_6011["killed"] else []),
                            True,
                        ),
                    ),
                    patch.object(proc_identity, "read_proc_bsdinfo", side_effect=_bsd),
                    patch.object(proc_identity, "pid_matches_worker_tag", side_effect=_match),
                    patch.object(proc_identity, "_send_signal", side_effect=_sig),
                ):
                    rc = proc_identity.reap_worker_from_manifest(mp, stop_timeout_sec=0.05)

                self.assertEqual(rc, 1)
                self.assertEqual(
                    signals,
                    [(6010, signal.SIGSTOP), (6011, signal.SIGSTOP), (6011, signal.SIGKILL)],
                    f"{label}: 6010 must get only SIGSTOP while later matched PID 6011 is still swept and killed",
                )
                self.assertIn("changed_hands pid=6010", err_buf.getvalue(), f"{label}: missing per-event stderr diagnostic")
                self.assertIn(expected_reason, err_buf.getvalue(), f"{label}: missing expected {expected_reason}")

    def test_r9_scenario_5_changed_hands_never_observed_stopped_sends_nothing_and_logs(self) -> None:
        from local_assist import proc_identity

        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            mp = self._write_test_manifest(Path(tmp))
            uid = os.geteuid()
            stop_sent = {"v": False}
            signals: list[tuple[int, int]] = []

            def _bsd(pid: int) -> tuple[str, dict[str, Any] | None]:
                if pid != 6015:
                    return ("absent", None)
                if not stop_sent["v"]:
                    return ("alive", {"uid": uid, "pgid": 6015, "status": proc_identity.SRUN, "start_tvsec": 500, "start_tvusec": 111})
                return ("alive", {"uid": uid, "pgid": 9999, "status": proc_identity.SRUN, "start_tvsec": 500, "start_tvusec": 222})

            def _sig(pid: int, sig: int) -> None:
                signals.append((pid, sig))
                if sig == signal.SIGSTOP:
                    stop_sent["v"] = True

            err_buf = io.StringIO()
            with (
                redirect_stderr(err_buf),
                patch.object(proc_identity, "list_all_pids", side_effect=lambda: ([6015] if not stop_sent["v"] else [], True)),
                patch.object(proc_identity, "read_proc_bsdinfo", side_effect=_bsd),
                patch.object(proc_identity, "pid_matches_worker_tag", side_effect=lambda p, _t: (not stop_sent["v"], True)),
                patch.object(proc_identity, "_send_signal", side_effect=_sig),
            ):
                rc = proc_identity.reap_worker_from_manifest(mp, stop_timeout_sec=0.03)

            self.assertEqual(rc, 1)
            self.assertEqual(signals, [(6015, signal.SIGSTOP)])
            self.assertIn("changed_hands pid=6015", err_buf.getvalue())

    def test_r9_scenario_6_injected_third_party_sigcont_between_reverify_and_sigkill_residual(self) -> None:
        """r9 Section 6.4 / Section 13: third-party SIGCONT between post-stop re-verification and SIGKILL is the documented residual."""
        from local_assist import proc_identity

        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            mp = self._write_test_manifest(Path(tmp))
            uid = os.geteuid()
            state = {"status": proc_identity.SRUN, "killed": False, "third_party_continued": False}
            signals: list[tuple[int, int]] = []

            def _bsd(pid: int) -> tuple[str, dict[str, Any] | None]:
                if pid != 6020 or state["killed"]:
                    return ("absent", None)
                return ("alive", {"uid": uid, "pgid": 6020, "status": state["status"], "start_tvsec": 700, "start_tvusec": 800})

            def _third_party_hook(pid: int) -> None:
                # Simulate another same-UID actor sending SIGCONT right after post-stop re-verification!
                self.assertEqual(pid, 6020)
                self.assertEqual(state["status"], proc_identity.SSTOP)
                state["status"] = proc_identity.SRUN
                state["third_party_continued"] = True

            def _sig(pid: int, sig: int) -> None:
                signals.append((pid, sig))
                if sig == signal.SIGSTOP:
                    state["status"] = proc_identity.SSTOP
                elif sig == signal.SIGKILL:
                    # Documented residual: SIGKILL still proceeds immediately after re-verification despite third-party SIGCONT.
                    self.assertTrue(state["third_party_continued"])
                    state["killed"] = True

            with (
                patch.object(proc_identity, "list_all_pids", side_effect=lambda: ([6020] if not state["killed"] else [], True)),
                patch.object(proc_identity, "read_proc_bsdinfo", side_effect=_bsd),
                patch.object(proc_identity, "pid_matches_worker_tag", return_value=(True, True)),
                patch.object(proc_identity, "_send_signal", side_effect=_sig),
                patch.object(proc_identity, "_after_stopped_reverify_hook", side_effect=_third_party_hook),
            ):
                rc = proc_identity.reap_worker_from_manifest(mp, stop_timeout_sec=0.05)

            self.assertEqual(rc, 0)
            self.assertTrue(state["third_party_continued"])
            self.assertEqual(signals, [(6020, signal.SIGSTOP), (6020, signal.SIGKILL)])

    def test_r9_scenario_7_each_kernel_query_failure_on_live_and_zombie_exits_1(self) -> None:
        from local_assist import proc_identity

        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            mp = self._write_test_manifest(Path(tmp))
            uid = os.geteuid()

            # 1. list_all_pids failure -> 1
            with redirect_stderr(io.StringIO()), patch.object(proc_identity, "list_all_pids", return_value=([], False)):
                self.assertEqual(proc_identity.reap_worker_from_manifest(mp), 1)

            # 2. read_proc_bsdinfo returning "error" -> 1
            with (
                redirect_stderr(io.StringIO()),
                patch.object(proc_identity, "list_all_pids", return_value=([7001], True)),
                patch.object(proc_identity, "read_proc_bsdinfo", return_value=("error", None)),
            ):
                self.assertEqual(proc_identity.reap_worker_from_manifest(mp), 1)

            # 3. pid_matches_worker_tag failing on live and zombie processes across all 3 sandbox_check calls -> 1
            for proc_state in ("alive", "zombie"):
                for sb_side_effect in (
                    [(-1, errno.EINVAL)],
                    [(1, 0), (-1, errno.EINVAL)],
                    [(1, 0), (0, 0), (-1, errno.EINVAL)],
                ):
                    with self.subTest(proc_state=proc_state, sb=sb_side_effect):
                        info = (
                            {"uid": uid, "pgid": 7002, "status": proc_identity.SRUN, "start_tvsec": 10, "start_tvusec": 20}
                            if proc_state == "alive"
                            else {"uid": uid, "pgid": 7002, "status": proc_identity.SZOMB, "start_tvsec": 10, "start_tvusec": 20}
                        )
                        calls = list(sb_side_effect)
                        with (
                            redirect_stderr(io.StringIO()),
                            patch.object(proc_identity, "list_all_pids", return_value=([7002], True)),
                            patch.object(proc_identity, "read_proc_bsdinfo", return_value=(proc_state, info)),
                            patch.object(proc_identity, "_sandbox_check_none", return_value=calls[0]),
                            patch.object(proc_identity, "_sandbox_check_mach_lookup", side_effect=calls[1:] or [(0, 0)]),
                        ):
                            self.assertEqual(proc_identity.reap_worker_from_manifest(mp), 1)

    @unittest.skipUnless(CAN_RUN_SANDBOX_EXEC, "Requires outer environment permitting /usr/bin/sandbox-exec")
    def test_live_darwin_seatbelt_detached_grandchild_and_bystander_isolation(self) -> None:
        from local_assist import proc_identity
        from local_assist.security_profile import (
            allocate_worker_home,
            cleanup_worker_home,
            compile_seatbelt_profile,
            default_unattended_worker_profile,
        )

        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            tmp_path = Path(tmp)
            ws_dir = tmp_path / "ws"
            ws_dir.mkdir(mode=0o700)
            tag_a = secrets.token_hex(16)
            tag_b = secrets.token_hex(16)
            wid_a, iso_a = allocate_worker_home(worker_homes_dir=tmp_path / "workers")
            wid_b, iso_b = allocate_worker_home(worker_homes_dir=tmp_path / "workers")
            py_bin = Path(sys.executable)
            try:
                sb_a = tmp_path / "worker_a.sb"
                sb_b = tmp_path / "worker_b.sb"
                prof = default_unattended_worker_profile()
                sb_a.write_text(
                    compile_seatbelt_profile(
                        prof,
                        workspace_dir=ws_dir,
                        isolated_home=iso_a,
                        opencode_bin=py_bin,
                        worker_tag=tag_a,
                    ),
                    encoding="utf-8",
                )
                sb_b.write_text(
                    compile_seatbelt_profile(
                        prof,
                        workspace_dir=ws_dir,
                        isolated_home=iso_b,
                        opencode_bin=py_bin,
                        worker_tag=tag_b,
                    ),
                    encoding="utf-8",
                )

                pid_file = ws_dir / "grandchild.json"
                detach_code = textwrap.dedent(
                    f"""
                    import ctypes, json, os, signal, time
                    os.setsid()
                    p1 = os.fork()
                    if p1 > 0:
                        os._exit(0)
                    os.setsid()
                    p2 = os.fork()
                    if p2 > 0:
                        os._exit(0)
                    devnull = os.open("/dev/null", os.O_RDWR)
                    for fd_num in (0, 1, 2):
                        os.dup2(devnull, fd_num)
                    if devnull > 2:
                        os.close(devnull)
                    os.chdir("/")
                    os.environ.clear()
                    signal.signal(signal.SIGTERM, signal.SIG_IGN)
                    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
                    errbuf = ctypes.c_char_p()
                    sb_rc = lib.sandbox_init(b"(version 1)(deny default)", 0, ctypes.byref(errbuf))
                    sb_errno = ctypes.get_errno()
                    with open({str(pid_file)!r}, "w") as fh:
                        json.dump({{"pid": os.getpid(), "sb_rc": sb_rc, "sb_errno": sb_errno}}, fh)
                    for _ in range(100):
                        time.sleep(0.2)
                    """
                )
                proc_a = subprocess.run(
                    ["/usr/bin/sandbox-exec", "-f", str(sb_a), str(py_bin), "-I", "-B", "-c", detach_code],
                    cwd=str(ws_dir),
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=True,
                )
                self.assertEqual(proc_a.returncode, 0)

                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline and not pid_file.is_file():
                    time.sleep(0.02)
                gc_meta = json.loads(pid_file.read_text(encoding="utf-8"))
                gc_pid = int(gc_meta["pid"])
                self.assertEqual(gc_meta["sb_rc"], -1)

                dummy_launcher = subprocess.Popen([str(py_bin), "-I", "-B", "-c", "import time; time.sleep(0.05)"], start_new_session=True)
                st_dl, info_dl = proc_identity.read_proc_bsdinfo(dummy_launcher.pid)
                assert st_dl == "alive" and info_dl is not None
                dummy_launcher.wait(timeout=5)

                bystander = subprocess.Popen([str(py_bin), "-I", "-B", "-c", "import time; time.sleep(30)"])
                worker_b = subprocess.Popen(
                    ["/usr/bin/sandbox-exec", "-f", str(sb_b), str(py_bin), "-I", "-B", "-c", "import time; time.sleep(30)"]
                )
                try:
                    manifest_path = tmp_path / "manifest_a.json"
                    manifest_path.write_text(
                        json.dumps(
                            {
                                "schema_version": 1,
                                "run_token": "live-reap-tok",
                                "launcher_pid": dummy_launcher.pid,
                                "launcher_pgid": dummy_launcher.pid,
                                "launcher_start_tvsec": info_dl["start_tvsec"],
                                "launcher_start_tvusec": info_dl["start_tvusec"],
                                "worker_id": wid_a,
                                "isolated_home": str(iso_a),
                                "worker_tag": tag_a,
                                "children": [],
                            }
                        ),
                        encoding="utf-8",
                    )
                    os.chmod(manifest_path, 0o600)

                    reap_cp = subprocess.run(
                        [str(py_bin), "-I", "-B", str(ROOT / "scripts" / "opencode-attested"), "--reap-worker", str(manifest_path)],
                        capture_output=True,
                        text=True,
                        timeout=15,
                        check=False,
                    )
                    self.assertEqual(reap_cp.returncode, 0, reap_cp.stderr)
                    st_gc, _ = proc_identity.read_proc_bsdinfo(gc_pid)
                    self.assertEqual(st_gc, "absent")
                    self.assertIsNone(bystander.poll())
                    self.assertIsNone(worker_b.poll())
                finally:
                    for p in (bystander, worker_b):
                        p.kill()
                        p.wait(timeout=5)
            finally:
                cleanup_worker_home(iso_a, worker_id=wid_a, harvest_logs=False)
                cleanup_worker_home(iso_b, worker_id=wid_b, harvest_logs=False)


class SeatbeltUnixSocketAndCustodyTests(unittest.TestCase):
    def test_rejects_local_mcp_combined_with_allowed_shell_localhost_ports(self) -> None:
        from local_assist.security_profile import (
            SecurityProfileError,
            apply_cli_overrides,
            parse_security_profile_dict,
        )

        base_dict = {
            "schema_version": 1,
            "mode": "unattended_worker",
            "mcp": {
                "servers": {
                    "agent_comms": {
                        "type": "local",
                        "command": ["/usr/bin/python3", "/tmp/opencode_relay.py"],
                    }
                },
                "allowed_servers": ["agent_comms"],
            },
        }
        with self.assertRaisesRegex(SecurityProfileError, "Cannot combine enabled local MCP servers"):
            parse_security_profile_dict(
                {
                    **base_dict,
                    "network": {"allowed_shell_localhost_ports": [5432]},
                }
            )

        prof_ok = parse_security_profile_dict(base_dict)
        with self.assertRaisesRegex(SecurityProfileError, "Cannot combine enabled local MCP servers"):
            apply_cli_overrides(prof_ok, allowed_localhost_ports=[5432])

        # Rejects Unix socket paths exceeding SUN_PATH_MAX_BYTES (103 bytes on Darwin)
        overlong_sock = "/tmp/" + ("a" * 100) + ".sock"
        with self.assertRaisesRegex(SecurityProfileError, "exceeds 103 bytes"):
            parse_security_profile_dict(
                {
                    "schema_version": 1,
                    "mode": "unattended_worker",
                    "network": {"allowed_unix_sockets": [overlong_sock]},
                }
            )

        # Rejects user-created symlink in Unix socket ancestor chain
        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as sym_tmp:
            real_sub = Path(sym_tmp).resolve() / "real_b"
            real_sub.mkdir(mode=0o700)
            sym_sub = Path(sym_tmp).resolve() / "sym_b"
            sym_sub.symlink_to(real_sub)
            with self.assertRaisesRegex(SecurityProfileError, "real non-symlink directory"):
                parse_security_profile_dict(
                    {
                        "schema_version": 1,
                        "mode": "unattended_worker",
                        "network": {"allowed_unix_sockets": [str(sym_sub / "ledger.sock")]},
                    }
                )

    def test_compiled_seatbelt_unix_socket_precedence_ip_denial_and_bridge_custody_rules(self) -> None:
        from local_assist.security_profile import (
            allocate_worker_home,
            apply_cli_overrides,
            cleanup_worker_home,
            compile_seatbelt_profile,
            parse_security_profile_dict,
        )

        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            tmp_path = Path(tmp)
            ws_dir = tmp_path / "project"
            ws_dir.mkdir(mode=0o700)
            bridge_dir = tmp_path / "agent-comms-bridge" / "0123456789ab"
            bridge_dir.mkdir(parents=True, mode=0o700)
            ledger_sock = bridge_dir / "ledger.sock"
            custody_opencode = tmp_path / "custody" / "opencode"
            custody_opencode.mkdir(parents=True, mode=0o700)
            relay_script = custody_opencode / "opencode_relay.py"
            relay_script.write_text("# relay\n", encoding="utf-8")
            site_pkgs = tmp_path / "custody" / "env"
            site_pkgs.mkdir(parents=True, mode=0o700)

            noncustody_dir = tmp_path / "noncustody_mcp"
            noncustody_dir.mkdir(mode=0o700)
            noncustody_bin = noncustody_dir / "mcp_exec"
            noncustody_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(noncustody_bin, 0o700)
            sibling_secret = noncustody_dir / "secret.txt"
            sibling_secret.write_text("TOP_SECRET\n", encoding="utf-8")

            tag = "fedcba9876543210fedcba9876543210"
            prof = parse_security_profile_dict(
                {
                    "schema_version": 1,
                    "mode": "unattended_worker",
                    "spend": {"inherit_attached_session_caps": True},
                    "mcp": {
                        "enable_local_assist": False,
                        "servers": {
                            "agent_comms": {
                                "type": "local",
                                "command": [str(noncustody_bin), str(relay_script), str(ledger_sock)],
                            }
                        },
                        "allowed_servers": ["agent_comms"],
                    },
                    "network": {
                        "allowed_unix_sockets": [str(ledger_sock)],
                        "denied_localhost_ports": [19999],
                    },
                }
            )
            self.assertTrue(prof.spend_inherit_attached_session_caps)
            self.assertEqual(prof.network_allowed_unix_sockets, (str(ledger_sock),))

            prof_cli = apply_cli_overrides(prof, allowed_unix_sockets=[str(ledger_sock)])
            self.assertEqual(prof_cli.network_allowed_unix_sockets, (str(ledger_sock),))

            wid, iso = allocate_worker_home(worker_homes_dir=tmp_path / "workers")
            fake_sb = tmp_path / "sandbox-exec"
            fake_sb.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(fake_sb, 0o755)
            try:
                sb_text = compile_seatbelt_profile(
                    prof,
                    workspace_dir=ws_dir,
                    isolated_home=iso,
                    opencode_bin=Path("/usr/bin/true"),
                    sandbox_exec_bin=Path("/usr/bin/sandbox-exec") if Path("/usr/bin/sandbox-exec").is_file() else fake_sb,
                    service_port=43111,
                    upstream_port=9081,
                    endpoint_port=8081,
                    use_token_relay=True,
                    worker_tag=tag,
                    launcher_site_packages=site_pkgs,
                    custody_opencode_root=custody_opencode,
                    worker_manifest_path=bridge_dir / "manifest.json",
                    launcher_exit_path=bridge_dir / "launcher_exit.json",
                )

                # 1. Section 1 worker_tag rules
                self.assertIn(f'(allow mach-lookup (global-name "org.free-inference.worker-allow.{tag}"))', sb_text)
                self.assertIn(f'(deny mach-lookup (global-name "org.free-inference.worker-deny.{tag}"))', sb_text)

                # 2. Precedence: AF_UNIX allow rules appear after default (deny network-outbound)
                # and before (remote ip "localhost:...") clauses so macOS libsandbox preserves both
                # AF_UNIX relay sockets and dedicated local-assist-python loopback TCP access.
                default_net_deny_idx = sb_text.find("(deny network-outbound)")
                first_remote_ip_idx = sb_text.find('(remote ip "localhost:')
                sock_real_str = str(bridge_dir.resolve() / "ledger.sock")
                sock_allow_rule = f'(allow network-outbound (remote unix-socket (path-literal "{sock_real_str}")))'
                self.assertIn(sock_allow_rule, sb_text)
                self.assertGreater(sb_text.find(sock_allow_rule), default_net_deny_idx)
                self.assertLess(sb_text.find(sock_allow_rule), first_remote_ip_idx)

                # 3. Zero non-opencode IP outbound rules exist
                self.assertNotIn('(remote ip "localhost:5432")', sb_text)

                # 4. Custody opencode + site-packages get subpath read-allow AND unconditional file-write* deny
                cust_real = str(custody_opencode.resolve())
                site_real = str(site_pkgs.resolve())
                self.assertIn(f'(subpath "{cust_real}")', sb_text)
                self.assertIn(f'(subpath "{site_real}")', sb_text)

                # 5. Non-custody MCP command[0] gets ONLY literal read-allow, NEVER parent subpath!
                noncust_dir_real = str(noncustody_dir.resolve())
                noncust_bin_real = str(noncustody_bin.resolve())
                self.assertIn(f'(literal "{noncust_bin_real}")', sb_text)
                self.assertNotIn(f'(subpath "{noncust_dir_real}")', sb_text)

                # 6. Bridge dir metadata read/write deny and ~/.config/free-inference protection
                bridge_real = str(bridge_dir.resolve())
                for meta_name in ("owner.json", "profile.yaml", "manifest.json", "launcher_exit.json"):
                    self.assertIn(f'(literal "{bridge_real}/{meta_name}")', sb_text)
                self.assertIn(".config/free-inference", sb_text)
            finally:
                cleanup_worker_home(iso, worker_id=wid, harvest_logs=False)

    @unittest.skipUnless(CAN_RUN_SANDBOX_EXEC, "Requires outer environment permitting /usr/bin/sandbox-exec")
    def test_live_seatbelt_mcp_unix_socket_relay_tcp_deny_and_sibling_secret_protection(self) -> None:
        from local_assist.security_profile import (
            allocate_worker_home,
            cleanup_worker_home,
            compile_seatbelt_profile,
            parse_security_profile_dict,
        )

        # Use a short /tmp root so SUN_PATH_MAX_BYTES <= 103 holds comfortably.
        short_root = Path(tempfile.mkdtemp(prefix="fi-sb-", dir=SHORT_TMP_DIR))
        wid, iso = allocate_worker_home(worker_homes_dir=short_root / "workers")
        try:
            ws_dir = short_root / "ws"
            ws_dir.mkdir(mode=0o700)
            bridge_dir = short_root / "b"
            bridge_dir.mkdir(mode=0o700)
            sock_path = bridge_dir / "ledger.sock"
            for mname in ("owner.json", "profile.yaml", "manifest.json", "launcher_exit.json"):
                mp = bridge_dir / mname
                mp.write_text('{"secret":1}\n', encoding="utf-8")
                os.chmod(mp, 0o600)

            custody_opencode = short_root / "custody" / "opencode"
            custody_opencode.mkdir(parents=True, mode=0o700)
            relay_py = custody_opencode / "opencode_relay.py"
            relay_py.write_text("RELAY_OK = True\n", encoding="utf-8")
            os.chmod(relay_py, 0o400)

            noncust_dir = short_root / "mcp_bin"
            noncust_dir.mkdir(mode=0o700)
            mcp_exec = noncust_dir / "run_mcp"
            mcp_exec.write_text("#!/bin/sh\necho MCP_EXEC_OK\n", encoding="utf-8")
            os.chmod(mcp_exec, 0o500)
            sibling_secret = noncust_dir / "secret.txt"
            sibling_secret.write_text("SIBLING_SECRET\n", encoding="utf-8")
            os.chmod(sibling_secret, 0o600)

            # Start AF_UNIX echo server and loopback TCP listener on host
            unix_srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.addCleanup(unix_srv.close)
            unix_srv.bind(str(sock_path))
            os.chmod(sock_path, 0o600)
            unix_srv.listen(4)

            def _accept_once() -> None:
                try:
                    c, _ = unix_srv.accept()
                    with c:
                        data = c.recv(1024)
                        c.sendall(b"PONG:" + data)
                except OSError:
                    pass

            t_unix = threading.Thread(target=_accept_once, daemon=True)
            t_unix.start()

            tcp_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.addCleanup(tcp_srv.close)
            tcp_srv.bind(("127.0.0.1", 0))
            tcp_srv.listen(2)
            tcp_port = tcp_srv.getsockname()[1]

            prof = parse_security_profile_dict(
                {
                    "schema_version": 1,
                    "mode": "unattended_worker",
                    "mcp": {
                        "servers": {
                            "agent_comms": {
                                "type": "local",
                                "command": [str(mcp_exec)],
                            }
                        },
                        "allowed_servers": ["agent_comms"],
                    },
                    "network": {"allowed_unix_sockets": [str(sock_path)]},
                }
            )
            sb_path = short_root / "worker.sb"
            sb_path.write_text(
                compile_seatbelt_profile(
                    prof,
                    workspace_dir=ws_dir,
                    isolated_home=iso,
                    opencode_bin=Path("/usr/bin/true"),
                    worker_tag=secrets.token_hex(16),
                    custody_opencode_root=custody_opencode,
                    worker_manifest_path=bridge_dir / "manifest.json",
                    launcher_exit_path=bridge_dir / "launcher_exit.json",
                ),
                encoding="utf-8",
            )

            probe_code = textwrap.dedent(
                f"""
                import errno, json, os, socket, subprocess
                res = {{}}
                # 1. Unix socket connect succeeds
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.connect({str(sock_path)!r})
                    s.sendall(b"PING")
                    res["unix_reply"] = s.recv(64).decode("utf-8")

                # 2. Loopback TCP connect from shared Python is denied (EPERM)
                try:
                    with socket.create_connection(("127.0.0.1", {tcp_port}), timeout=1.0):
                        res["tcp_blocked"] = False
                except OSError as exc:
                    res["tcp_blocked"] = exc.errno in (errno.EPERM, errno.EACCES)

                # 3. Bridge dir readdir, metadata read, metadata write, and socket unlink are denied
                for name, fn in [
                    ("readdir_bridge", lambda: os.listdir({str(bridge_dir)!r})),
                    ("read_owner", lambda: open({str(bridge_dir / "owner.json")!r}).read()),
                    ("read_manifest", lambda: open({str(bridge_dir / "manifest.json")!r}).read()),
                    ("write_exit", lambda: open({str(bridge_dir / "launcher_exit.json")!r}, "w").write("x")),
                    ("unlink_sock", lambda: os.unlink({str(sock_path)!r})),
                    ("read_sibling_secret", lambda: open({str(sibling_secret)!r}).read()),
                    ("write_custody", lambda: open({str(relay_py)!r}, "w").write("x")),
                ]:
                    try:
                        fn()
                        res[name] = "ALLOWED"
                    except OSError:
                        res[name] = "DENIED"

                res["read_custody"] = open({str(relay_py)!r}).read().strip()
                cp = subprocess.run([{str(mcp_exec)!r}], capture_output=True, text=True, check=False)
                res["exec_mcp"] = cp.stdout.strip()
                print(json.dumps(res))
                """
            )
            try:
                cp = subprocess.run(
                    ["/usr/bin/sandbox-exec", "-f", str(sb_path), sys.executable, "-I", "-B", "-c", probe_code],
                    cwd=str(ws_dir),
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=True,
                )
                out = json.loads(cp.stdout.strip())
                self.assertEqual(out["unix_reply"], "PONG:PING")
                self.assertTrue(out["tcp_blocked"])
                for denied_key in (
                    "readdir_bridge",
                    "read_owner",
                    "read_manifest",
                    "write_exit",
                    "unlink_sock",
                    "read_sibling_secret",
                    "write_custody",
                ):
                    self.assertEqual(out[denied_key], "DENIED", f"Expected {denied_key} to be DENIED")
                self.assertEqual(out["read_custody"], "RELAY_OK = True")
                self.assertEqual(out["exec_mcp"], "MCP_EXEC_OK")
            finally:
                unix_srv.close()
                tcp_srv.close()
                t_unix.join(timeout=2.0)
        finally:
            cleanup_worker_home(iso, worker_id=wid, harvest_logs=False)
            shutil.rmtree(short_root, ignore_errors=True)


class SessionInheritanceAndExitCodeTests(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        _install_outer_sandbox_ps_fixture_if_blocked(self)
        self.mod = _load_script_module("opencode_attested_p3", "scripts/opencode-attested")
        self._tmp_root = Path(tempfile.mkdtemp(prefix="fi-p3-", dir=SHORT_TMP_DIR))
        self.runs_dir = self._tmp_root / "runs"
        self.runs_dir.mkdir(mode=0o700)
        self.workers_dir = self._tmp_root / "workers"
        self.workers_dir.mkdir(mode=0o700)
        wh_p = patch("local_assist.security_profile._active_worker_homes_dir", return_value=self.workers_dir)
        wh_p.start()
        self.addCleanup(wh_p.stop)
        if not CAN_BIND_LOOPBACK_TCP:
            port_p = patch("local_assist.launch._allocate_loopback_ephemeral_port", return_value=43218)
            port_p.start()
            self.addCleanup(port_p.stop)
        self.ws_dir = self._tmp_root / "ws"
        self.ws_dir.mkdir(mode=0o700)
        self.bridge_dir = self._tmp_root / "bridge"
        self.bridge_dir.mkdir(mode=0o700)
        self.fake_opencode = self._tmp_root / "fake-opencode"
        self.fake_opencode.write_text(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo '2.3.2'; exit 0; fi\nexit 0\n",
            encoding="utf-8",
        )
        os.chmod(self.fake_opencode, 0o700)
        self.fake_sb = self._tmp_root / "fake-sandbox-exec"
        self.fake_sb.write_text("#!/bin/sh\nshift 2\nexec \"$@\"\n", encoding="utf-8")
        os.chmod(self.fake_sb, 0o700)
        self.profile_path = self.bridge_dir / "profile.yaml"
        self.profile_path.write_text(
            "schema_version: 1\n"
            "mode: unattended_worker\n"
            "spend:\n"
            "  inherit_attached_session_caps: true\n",
            encoding="utf-8",
        )
        os.chmod(self.profile_path, 0o600)

    def tearDown(self) -> None:
        from local_assist.security_profile import _safe_rmtree_nofollow

        _safe_rmtree_nofollow(self._tmp_root)
        shutil.rmtree(self._tmp_root, ignore_errors=True)

    def _write_ready_session(
        self,
        *,
        model_id: str = "tinfoil-deepseek-v4-1-flash",
        repo: str = "deepseek-r1-0528",
        port: int = 18081,
        pid: int | None = None,
        pid_lstart: str | None = None,
        status: str = "ready",
        max_chat_requests: int = 2500,
        max_tokens_cap: int = 32768,
        max_request_bytes: int = 16777216,
        ttl_seconds: int = 43200,
        generation: int = 1,
    ) -> tuple[dict[str, Any], Path]:
        from local_assist.registry import get_process_lstart, pid_file_for_model, session_token_file_for_model

        eff_pid = os.getpid() if pid is None and status != "starting_null" else pid
        eff_lstart = (
            (get_process_lstart(eff_pid) if eff_pid else None)
            if pid_lstart is None
            else pid_lstart
        )
        tok = "se-session-" + ("a" * 64)
        tok_path = session_token_file_for_model(model_id, self.runs_dir)
        envelope = {"session_id": "sess-1", "generation": generation, "token": tok}
        tok_path.write_text(json.dumps(envelope), encoding="utf-8")
        os.chmod(tok_path, 0o600)
        rec = {
            "model_id": model_id,
            "repo": repo,
            "runtime": "proxy",
            "api_base_url": f"http://127.0.0.1:{port}/v1",
            "port": port,
            "upstream_port": port + 1000,
            "pid": eff_pid,
            "pid_lstart": eff_lstart,
            "session_token_file": str(tok_path),
            "max_chat_requests": max_chat_requests,
            "max_tokens_cap": max_tokens_cap,
            "max_request_bytes": max_request_bytes,
            "ttl_seconds": ttl_seconds,
            "status": "starting" if status == "starting_null" else status,
            "startup_nonce": "nonce-1",
        }
        pf = pid_file_for_model(model_id, self.runs_dir)
        pf.write_text(json.dumps(rec), encoding="utf-8")
        os.chmod(pf, 0o600)
        return rec, tok_path

    def test_inherit_attached_session_caps_above_defaults_and_explicit_conflict(self) -> None:
        from local_assist.session import control_path

        model_id = "tinfoil-deepseek-v4-1-flash"
        from local_assist.registry import load_model

        repo = str(load_model(model_id)["repo"])
        rec, _ = self._write_ready_session(
            model_id=model_id,
            repo=repo,
            max_chat_requests=2500,
            max_tokens_cap=32768,
            max_request_bytes=16777216,
            ttl_seconds=3600,
        )
        ctl = _FakeControlSocketServer(
            control_path(self.runs_dir, model_id),
            lambda _req: {
                "protocol": 1,
                "session_id": "sess-1",
                "pid": rec["pid"],
                "model": repo,
                "state": "ON",
                "generation": 1,
                "remaining_seconds": 50000,
                "remaining_milliseconds": 49999500,
                "expires_at": int(time.time()) + 50000,
                "requests_used": 10,
                "request_limit": 2500,
                "requests_remaining": 2490,
                "window_seconds": 54000,
            },
        )
        self.addCleanup(ctl.close)

        captured_relay_kwargs: dict[str, Any] = {}
        exit_file = self.bridge_dir / "launcher_exit.json"

        class _DummyRelay:
            api_base_url = "http://127.0.0.1:45123/v1"
            relay_token = "worker-relay-" + ("b" * 64)
            port = 45123
            local_request_cap_exhausted = False
            upstream_session_cap_exhausted = False
            _extra_canary_secrets: tuple[str, ...] = ()

            def __init__(self, **kwargs: Any) -> None:
                captured_relay_kwargs.update(kwargs)

            def start(self) -> "_DummyRelay":
                return self

            def close(self) -> None:
                return None

        real_subproc_run = subprocess.run

        def _selective_run(cmd: Any, *a: Any, **kw: Any) -> Any:
            if isinstance(cmd, (list, tuple)) and any("verify-served-model" in str(tok) for tok in cmd):
                return subprocess.CompletedProcess(cmd, 0, stdout=repo, stderr="")
            return real_subproc_run(cmd, *a, **kw)

        err_buf = io.StringIO()
        with (
            patch.object(self.mod, "_WorkerTokenRelay", _DummyRelay),
            patch("subprocess.run", side_effect=_selective_run),
            patch.dict(os.environ, {"FREE_INFERENCE_SANDBOX_EXEC_BIN": str(self.fake_sb)}, clear=False),
            redirect_stderr(err_buf),
        ):
            out_buf = io.StringIO()
            with patch("sys.stdout", out_buf):
                rc = self.mod.main(
                    [
                        "opencode-attested",
                        "--model",
                        model_id,
                        "--security-profile",
                        str(self.profile_path),
                        "--opencode-bin",
                        str(self.fake_opencode),
                        "--runs-dir",
                        str(self.runs_dir),
                        "--run-token",
                        "run-tok-caps",
                        "--launcher-exit-file",
                        str(exit_file),
                        "--print-config",
                    ]
                )

        self.assertEqual(rc, 0, err_buf.getvalue())
        self.assertFalse(exit_file.exists())
        # Inherited all 4 session bounds (including live window_seconds=54000 / remaining=50000 and 2490 remaining requests)!
        self.assertEqual(captured_relay_kwargs["max_chat_requests"], 2490)
        self.assertEqual(captured_relay_kwargs["max_tokens_cap"], 32768)
        self.assertEqual(captured_relay_kwargs["max_request_bytes"], 16777216)
        self.assertEqual(captured_relay_kwargs["ttl_seconds"], 50000.0)

        # Explicit CLI cap conflict (--max-chat-requests 500 against 2500) must exit 1 (not 4) with NO launcher_exit.json!
        with (
            patch("subprocess.run", side_effect=_selective_run),
            patch.dict(os.environ, {"FREE_INFERENCE_SANDBOX_EXEC_BIN": str(self.fake_sb)}, clear=False),
            redirect_stderr(io.StringIO()),
        ):
            rc_conflict = self.mod.main(
                [
                    "opencode-attested",
                    "--model",
                    model_id,
                    "--security-profile",
                    str(self.profile_path),
                    "--opencode-bin",
                    str(self.fake_opencode),
                    "--runs-dir",
                    str(self.runs_dir),
                    "--max-chat-requests",
                    "500",
                    "--run-token",
                    "run-tok-conflict",
                    "--launcher-exit-file",
                    str(exit_file),
                    "--",
                    "run",
                    "hello",
                ]
            )
        self.assertEqual(rc_conflict, 1)
        self.assertFalse(exit_file.exists())

    def test_exit_4_strict_reservation_and_all_session_classifications(self) -> None:
        from local_assist.registry import load_model, pid_file_for_model
        from local_assist.session import control_path

        model_id = "tinfoil-deepseek-v4-1-flash"
        repo = str(load_model(model_id)["repo"])
        exit_file = self.bridge_dir / "launcher_exit.json"

        def _invoke(run_tok: str = "tok-xyz", extra_args: list[str] | None = None) -> int:
            exit_file.unlink(missing_ok=True)
            with (
                patch.dict(os.environ, {"FREE_INFERENCE_SANDBOX_EXEC_BIN": str(self.fake_sb)}, clear=False),
                redirect_stderr(io.StringIO()),
            ):
                return self.mod.main(
                    [
                        "opencode-attested",
                        "--model",
                        model_id,
                        "--security-profile",
                        str(self.profile_path),
                        "--opencode-bin",
                        str(self.fake_opencode),
                        "--runs-dir",
                        str(self.runs_dir),
                        "--run-token",
                        run_tok,
                        "--launcher-exit-file",
                        str(exit_file),
                        *(extra_args or []),
                        "--",
                        "run",
                        "hello",
                    ]
                )

        # 1. Missing PID record -> exit 4 + opencode_session_unavailable
        self.assertEqual(_invoke("tok-missing"), 4)
        diag = json.loads(exit_file.read_text(encoding="utf-8"))
        self.assertEqual(stat.S_IMODE(exit_file.lstat().st_mode), 0o600)
        self.assertEqual(
            diag,
            {
                "schema_version": 1,
                "run_token": "tok-missing",
                "launcher_pid": os.getpid(),
                "reason": "opencode_session_unavailable",
            },
        )

        # 2. Dead PID record -> exit 4 + opencode_session_unavailable
        self._write_ready_session(model_id=model_id, repo=repo, pid=999_999_992, pid_lstart="Mon Jan 1 00:00:00 2026")
        self.assertEqual(_invoke("tok-dead"), 4)
        self.assertEqual(json.loads(exit_file.read_text())["reason"], "opencode_session_unavailable")

        # 3. Reused PID record -> exit 4 + opencode_session_unavailable
        self._write_ready_session(model_id=model_id, repo=repo, pid=os.getpid(), pid_lstart="Thu Jan  1 00:00:01 1970")
        self.assertEqual(_invoke("tok-reused"), 4)
        self.assertEqual(json.loads(exit_file.read_text())["reason"], "opencode_session_unavailable")

        # 4. Provisional status == "starting" (pid is None or live matched) -> ordinary exit 1, NO launcher_exit.json!
        self._write_ready_session(model_id=model_id, repo=repo, status="starting_null")
        self.assertEqual(_invoke("tok-starting-null"), 1)
        self.assertFalse(exit_file.exists())

        self._write_ready_session(model_id=model_id, repo=repo, status="starting")
        self.assertEqual(_invoke("tok-starting-live"), 1)
        self.assertFalse(exit_file.exists())

        # 5. state == "UNKNOWN" (missing/unverifiable control socket on matched PID) -> ordinary exit 1, NO launcher_exit.json!
        rec, _ = self._write_ready_session(model_id=model_id, repo=repo, status="ready")
        self.assertEqual(_invoke("tok-unknown"), 1)
        self.assertFalse(exit_file.exists())

        # 6. state == "OFF" -> exit 4 + opencode_session_unavailable
        state_holder: dict[str, Any] = {
            "protocol": 1,
            "session_id": "sess-1",
            "pid": rec["pid"],
            "model": repo,
            "state": "OFF",
            "generation": 1,
            "remaining_seconds": 0,
            "expires_at": int(time.time()),
            "requests_used": 10,
            "request_limit": 100,
            "requests_remaining": 90,
            "window_seconds": 3600,
        }
        ctl = _FakeControlSocketServer(control_path(self.runs_dir, model_id), lambda _r: state_holder)
        self.addCleanup(ctl.close)
        self.assertEqual(_invoke("tok-off"), 4)
        self.assertEqual(json.loads(exit_file.read_text())["reason"], "opencode_session_unavailable")

        # 7. state == "ON" with requests_remaining == 0 -> exit 4 + opencode_session_caps_exhausted
        state_holder.update({"state": "ON", "remaining_seconds": 1800, "requests_used": 100, "requests_remaining": 0})
        self.assertEqual(_invoke("tok-exhausted-pre"), 4)
        self.assertEqual(json.loads(exit_file.read_text())["reason"], "opencode_session_caps_exhausted")

        # 8. Diagnostic write failure (OSError) -> must return 1, NEVER 4!
        with patch.object(self.mod, "_write_launcher_exit_diagnostic", return_value=False):
            self.assertEqual(_invoke("tok-write-fail"), 1)

        # 9. Child OpenCode exiting with code 4 on unrelated error + requests_remaining > 0 -> normalized to 1, NO launcher_exit.json!
        state_holder.update({"state": "ON", "remaining_seconds": 1800, "requests_used": 1, "requests_remaining": 99})
        with (
            patch.object(self.mod, "ensure_model_served", return_value=(True, None, {
                "model_id": model_id,
                "max_chat_requests": 100,
                "max_request_bytes": 1048576,
                "max_tokens_cap": 8192,
                "ttl_seconds": 1800,
                "input_price_per_m": 0.6,
                "output_price_per_m": 1.45,
                "worst_total_usd": 1.0,
                "attached": True,
                "allocated_port": rec["port"],
            })),
            patch.object(self.mod, "execute_worker_profile_session", return_value=4),
        ):
            self.assertEqual(_invoke("tok-child-4"), 1)
            self.assertFalse(exit_file.exists())

        # 10. Mid-run relay cap exhaustion (local_request_cap_exhausted or upstream_session_cap_exhausted) -> exit 4 + opencode_session_caps_exhausted
        def _fake_exec_cap_hit(**kwargs: Any) -> int:
            relay = kwargs["relay_factory"]()
            try:
                relay.local_request_cap_exhausted = True
            finally:
                relay.close()
            return 1

        with (
            patch.object(self.mod, "ensure_model_served", return_value=(True, None, {
                "model_id": model_id,
                "max_chat_requests": 100,
                "max_request_bytes": 1048576,
                "max_tokens_cap": 8192,
                "ttl_seconds": 1800,
                "input_price_per_m": 0.6,
                "output_price_per_m": 1.45,
                "worst_total_usd": 1.0,
                "attached": True,
                "allocated_port": rec["port"],
            })),
            patch.object(self.mod, "execute_worker_profile_session", side_effect=_fake_exec_cap_hit),
        ):
            self.assertEqual(_invoke("tok-midrun-cap"), 4)
            self.assertEqual(json.loads(exit_file.read_text())["reason"], "opencode_session_caps_exhausted")

        # 11. Port owned by a different active model -> EXIT_MODEL_MISMATCH (3), NO launcher_exit.json!
        pid_file_for_model(model_id, self.runs_dir).unlink(missing_ok=True)
        self._write_ready_session(
            model_id="privatemode-glm-5-3-flash",
            repo="zai-org/GLM-4.7-Flash",
            port=8081,
        )
        with patch.object(
            self.mod,
            "ensure_model_served",
            return_value=(False, "Refusing to launch private-attested: another model is already serving at http://127.0.0.1:8081/v1", None),
        ):
            self.assertEqual(_invoke("tok-mismatch"), 3)
            self.assertFalse(exit_file.exists())


class CustodyImmutabilityAndPointerTests(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        _install_outer_sandbox_ps_fixture_if_blocked(self)
    def test_requirements_launcher_lock_and_release_hygiene(self) -> None:
        lock_file = ROOT / "requirements-launcher.txt"
        self.assertTrue(lock_file.is_file(), "requirements-launcher.txt must exist")
        text = lock_file.read_text(encoding="utf-8")
        self.assertIn("PyYAML==6.0.3", text)
        hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", text)
        self.assertGreaterEqual(len(hashes), 10, "Expected multi-platform wheels + sdist sha256 hashes")

        rh_path = ROOT / "release-hygiene.json"
        if rh_path.is_file():
            rh = json.loads(rh_path.read_text(encoding="utf-8"))
            self.assertIn("requirements-launcher.txt", rh.get("exact", []))

    def test_active_runs_pointer_exact_0700_0600_modes_and_malformed_rejection(self) -> None:
        from local_assist import custody

        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            fake_home = Path(tmp) / "userhome"
            fake_home.mkdir(mode=0o700)
            runs_dir = Path(tmp) / "live_runs"
            runs_dir.mkdir(mode=0o700)

            with patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home):
                # Missing pointer -> None
                self.assertIsNone(custody.read_active_runs_pointer())

                ptr_path = custody.write_active_runs_pointer(runs_dir)
                self.assertEqual(ptr_path, fake_home / ".config" / "free-inference" / "active-runs.json")
                self.assertEqual(stat.S_IMODE(ptr_path.parent.lstat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(ptr_path.lstat().st_mode), 0o600)
                self.assertEqual(custody.read_active_runs_pointer(), runs_dir.resolve())

                # Non-exact directory modes (0500 and 0755) must be rejected!
                for bad_dir_mode in (0o500, 0o755):
                    os.chmod(ptr_path.parent, bad_dir_mode)
                    try:
                        self.assertIsNone(custody.read_active_runs_pointer())
                    finally:
                        os.chmod(ptr_path.parent, 0o700)

                # Non-exact file modes (0400 and 0644) must be rejected!
                for bad_file_mode in (0o400, 0o644):
                    os.chmod(ptr_path, bad_file_mode)
                    try:
                        self.assertIsNone(custody.read_active_runs_pointer())
                    finally:
                        os.chmod(ptr_path, 0o600)

                # Malformed JSON or boolean schema_version -> None
                ptr_path.write_text('{"schema_version": true, "runs_dir": "/tmp"}\n', encoding="utf-8")
                os.chmod(ptr_path, 0o600)
                self.assertIsNone(custody.read_active_runs_pointer())

                # Symlink pointer file -> None
                custody.write_active_runs_pointer(runs_dir)
                real_copy = Path(tmp) / "copy.json"
                shutil.copy2(ptr_path, real_copy)
                os.chmod(real_copy, 0o600)
                ptr_path.unlink()
                ptr_path.symlink_to(real_copy)
                self.assertIsNone(custody.read_active_runs_pointer())

                # Staged read-only <isolated_home>/runtime snapshot outside custody_root returns False,
                # whereas explicit_site_packages, a read-only exported launcher tree (with scripts/opencode-attested),
                # or a runtime-shaped directory inside ~/.local/share/agent-comms/custody returns True,
                # and a writable tree outside custody_root returns False!
                fake_iso = Path(tmp) / "iso_home"
                (fake_iso / "bin").mkdir(parents=True, mode=0o700)
                (fake_iso / "bin" / "local-assist-python").write_text("#!/bin/sh\n", encoding="utf-8")
                (fake_iso / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
                staged_rt = fake_iso / "runtime"
                (staged_rt / "scripts").mkdir(parents=True, mode=0o700)
                (staged_rt / "scripts" / "verify-served-model").write_text("#!/usr/bin/env python3\n", encoding="utf-8")
                os.chmod(staged_rt, 0o500)
                custody_collision_iso = fake_home / ".local" / "share" / "agent-comms" / "custody" / "collision"
                (custody_collision_iso / "bin").mkdir(parents=True, mode=0o700)
                (custody_collision_iso / "bin" / "local-assist-python").write_text("#!/bin/sh\n", encoding="utf-8")
                (custody_collision_iso / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
                custody_collision_rt = custody_collision_iso / "runtime"
                (custody_collision_rt / "scripts").mkdir(parents=True, mode=0o700)
                (custody_collision_rt / "scripts" / "verify-served-model").write_text("#!/usr/bin/env python3\n", encoding="utf-8")
                os.chmod(custody_collision_rt, 0o500)
                try:
                    self.assertFalse(custody.is_custody_tree(staged_rt))
                    self.assertTrue(custody.is_custody_tree(staged_rt, explicit_site_packages="/tmp/site"))
                    # Collision inside ~/.local/share/agent-comms/custody always returns True!
                    self.assertTrue(custody.is_custody_tree(custody_collision_rt))
                    # Read-only exported launcher tree (with scripts/opencode-attested) returns True, while writable tree returns False!
                    os.chmod(staged_rt, 0o700)
                    (staged_rt / "scripts" / "opencode-attested").write_text("#!/usr/bin/env python3\n", encoding="utf-8")
                    self.assertFalse(custody.is_custody_tree(staged_rt))
                    os.chmod(staged_rt, 0o500)
                    self.assertTrue(custody.is_custody_tree(staged_rt))
                finally:
                    os.chmod(staged_rt, 0o700)
                    os.chmod(custody_collision_rt, 0o700)

    def test_readonly_custody_export_zero_bytecode_hostile_runs_env_and_tree_sha256(self) -> None:
        short_root = Path(tempfile.mkdtemp(prefix="fi-cust-", dir=SHORT_TMP_DIR))
        try:
            custody_base = short_root / "custody" / "launcher"
            launcher_tree = custody_base / "v0.3.0-deadbeefcafe"
            env_tree = custody_base / "env"
            fake_home = short_root / "home"
            fake_home.mkdir(mode=0o700)
            live_runs = short_root / "live_runs"
            live_runs.mkdir(mode=0o700)
            hostile_runs = short_root / "hostile_runs"
            hostile_runs.mkdir(mode=0o700)

            # Copy minimal tracked runtime tree without .git or .venv (matching git archive export)
            launcher_tree.mkdir(parents=True, mode=0o700)
            for sub in ("local_assist", "scripts", "config", "docs"):
                shutil.copytree(
                    ROOT / sub,
                    launcher_tree / sub,
                    symlinks=False,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
                )
            for fname in ("models.yaml", "requirements-launcher.txt"):
                shutil.copy2(ROOT / fname, launcher_tree / fname)

            # Populate target env directory with a pure-Python helper module (no symlinks, no .pyc)
            env_tree.mkdir(parents=True, mode=0o700)
            (env_tree / "custody_marker.py").write_text("CUSTODY_ENV_LOADED = True\n", encoding="utf-8")

            # Make both launcher_tree and env_tree strictly read-only (0500 dirs / 0500 scripts / 0400 files)
            for tree in (launcher_tree, env_tree):
                for dp_str, _dirs, files in os.walk(tree, topdown=False):
                    dp = Path(dp_str)
                    for fn in files:
                        fp = dp / fn
                        is_exec = (dp.name == "scripts")
                        os.chmod(fp, 0o500 if is_exec else 0o400)
                    os.chmod(dp, 0o500)

            tree_sha_before = _canonical_tree_sha256(launcher_tree)
            env_sha_before = _canonical_tree_sha256(env_tree)

            # Write active-runs pointer to live_runs and a poisoned OFF session in hostile_runs vs ON in live_runs
            from local_assist import custody, proc_identity
            from local_assist.registry import get_process_lstart, load_model, pid_file_for_model, session_token_file_for_model
            from local_assist.session import control_path

            with patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home):
                custody.write_active_runs_pointer(live_runs)

            model_id = "tinfoil-deepseek-v4-1-flash"
            repo = str(load_model(model_id)["repo"])
            tok = "se-session-" + ("c" * 64)
            tok_file = session_token_file_for_model(model_id, live_runs)
            tok_file.write_text(json.dumps({"session_id": "s-live", "generation": 1, "token": tok}), encoding="utf-8")
            os.chmod(tok_file, 0o600)
            rec = {
                "model_id": model_id,
                "repo": repo,
                "runtime": "proxy",
                "api_base_url": "http://127.0.0.1:18089/v1",
                "port": 18089,
                "upstream_port": 19089,
                "pid": os.getpid(),
                "pid_lstart": get_process_lstart(os.getpid()),
                "session_token_file": str(tok_file),
                "max_chat_requests": 500,
                "max_tokens_cap": 8192,
                "max_request_bytes": 1048576,
                "ttl_seconds": 3600,
                "status": "ready",
                "startup_nonce": "n-live",
            }
            pid_file_for_model(model_id, live_runs).write_text(json.dumps(rec), encoding="utf-8")

            ctl = _FakeControlSocketServer(
                control_path(live_runs, model_id),
                lambda _r: {
                    "protocol": 1,
                    "session_id": "s-live",
                    "pid": os.getpid(),
                    "model": repo,
                    "state": "ON",
                    "generation": 1,
                    "remaining_seconds": 3500,
                    "expires_at": int(time.time()) + 3500,
                    "requests_used": 2,
                    "request_limit": 500,
                    "requests_remaining": 498,
                    "window_seconds": 3600,
                },
            )
            self.addCleanup(ctl.close)

            sub_env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": str(fake_home),
                # Hostile FREE_INFERENCE_RUNS_DIR pointing at empty/poisoned hostile_runs (must be ignored in custody!)
                "FREE_INFERENCE_RUNS_DIR": str(hostile_runs),
            }

            # 1a. Direct script invocation without -B flag on read-only custody (proves sys.dont_write_bytecode=True in prologue)
            for extra_flags in (["--launcher-site-packages", str(env_tree)], []):
                cp_direct = subprocess.run(
                    [
                        sys.executable,
                        str(launcher_tree / "scripts" / "session"),
                        *extra_flags,
                        "status",
                        "--model",
                        model_id,
                        "--json",
                    ],
                    env=sub_env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertIn(cp_direct.returncode, (0, 1), cp_direct.stderr)
                direct_json = json.loads(cp_direct.stdout.strip())
                self.assertIn(direct_json["state"], ("ON", "OFF", "UNKNOWN"))

            # 1b. Subprocess with pwd.getpwuid directed at fake_home (proves active-runs.json resolves live_runs while stripping FREE_INFERENCE_RUNS_DIR)
            for extra_flags in (["--launcher-site-packages", str(env_tree)], []):
                ps_patch_code = (
                    ""
                    if CAN_RUN_PS
                    else (
                        "import local_assist.registry as _reg, local_assist.launch as _lch\n"
                        f"_reg.get_process_lstart = lambda p: {rec['pid_lstart']!r} if p == {os.getpid()} else None\n"
                        f"_lch.get_process_lstart = _reg.get_process_lstart\n"
                        "_reg.pid_is_zombie = lambda _p: False\n"
                        "_lch.pid_is_zombie = _reg.pid_is_zombie\n"
                    )
                )
                ctl_resp_dict = ctl.response_fn({"action": "status"})
                ctl_patch_code = (
                    ""
                    if CAN_CONNECT_UNIX_SOCKET
                    else (
                        "import os, stat, local_assist.session as _sess\n"
                        "def _val_ctl_req(p, _req, *, expected_pid, timeout=3.0):\n"
                        "    _sess._validate_store(p.parent.parent)\n"
                        "    par, nod = p.parent.lstat(), p.lstat()\n"
                        "    assert stat.S_ISDIR(par.st_mode) and par.st_uid == os.geteuid() and stat.S_IMODE(par.st_mode) == 0o700 and not p.parent.is_symlink()\n"
                        f"    assert nod.st_uid == os.geteuid() and stat.S_IMODE(nod.st_mode) == 0o600 and expected_pid == {rec['pid']!r}\n"
                        f"    return {ctl_resp_dict!r}\n"
                        "def _val_ctl_present(p):\n"
                        "    try:\n"
                        "        return stat.S_IMODE(p.lstat().st_mode) == 0o600\n"
                        "    except OSError:\n"
                        "        return False\n"
                        "_sess.control_node_present = _val_ctl_present\n"
                        "_sess.control_request = _val_ctl_req\n"
                    )
                )
                shim = textwrap.dedent(
                    f"""
                    import collections, pwd, runpy, sys
                    sys.path.insert(0, {str(launcher_tree)!r})
                    _Orig = collections.namedtuple("pw", ["pw_dir"])
                    pwd.getpwuid = lambda _uid: _Orig({str(fake_home)!r})
                    """
                ) + ps_patch_code + ctl_patch_code + textwrap.dedent(
                    f"""
                    sys.argv = [{str(launcher_tree / "scripts" / "session")!r}, *{extra_flags!r}, "status", "--model", {model_id!r}, "--json"]
                    try:
                        runpy.run_path(sys.argv[0], run_name="__main__")
                    except SystemExit as exc:
                        raise SystemExit(exc.code)
                    """
                )
                cp_sess = subprocess.run(
                    [sys.executable, "-c", shim],
                    env=sub_env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(cp_sess.returncode, 0, cp_sess.stderr)
                sess_json = json.loads(cp_sess.stdout.strip())
                self.assertEqual(sess_json["state"], "ON")
                self.assertEqual(sess_json["requests_remaining"], 498)
                # Also verify sibling/explicit env_tree was added to sys.path!
                shim_env_imp = textwrap.dedent(
                    f"""
                    import runpy, sys
                    sys.argv = [{str(launcher_tree / "scripts" / "session")!r}, *{extra_flags!r}, "status", "--model", {model_id!r}, "--json"]
                    try:
                        runpy.run_path(sys.argv[0], run_name="__main__")
                    except SystemExit:
                        pass
                    import custody_marker
                    assert custody_marker.CUSTODY_ENV_LOADED is True
                    """
                )
                cp_imp = subprocess.run(
                    [sys.executable, "-c", shim_env_imp],
                    env=sub_env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(cp_imp.returncode, 0, cp_imp.stderr)

            # 2. --runs-dir must be REFUSED in custody mode with exit 1 (never 4)!
            cp_refuse = subprocess.run(
                [
                    sys.executable,
                    str(launcher_tree / "scripts" / "opencode-attested"),
                    "--launcher-site-packages",
                    str(env_tree),
                    "--runs-dir",
                    str(hostile_runs),
                    "--print-config",
                ],
                env=sub_env,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(cp_refuse.returncode, 1)

            # 3. --reap-worker on Darwin from read-only custody (both with --launcher-site-packages and sibling ../env)
            if sys.platform == "darwin":
                sleeper = subprocess.Popen(
                    [sys.executable, "-I", "-B", "-c", "import time; time.sleep(60)"],
                    start_new_session=True,
                )
                self.addCleanup(lambda: (sleeper.kill(), sleeper.wait()) if sleeper.poll() is None else None)
                st_slp, info_slp = proc_identity.read_proc_bsdinfo(sleeper.pid)
                assert st_slp == "alive" and info_slp is not None
                manifest_p = short_root / "reap_manifest.json"
                manifest_p.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "run_token": "cust-reap",
                            "launcher_pid": sleeper.pid,
                            "launcher_pgid": sleeper.pid,
                            "launcher_start_tvsec": info_slp["start_tvsec"],
                            "launcher_start_tvusec": info_slp["start_tvusec"],
                            "worker_id": "w-cust",
                            "isolated_home": str(short_root / "iso"),
                            "worker_tag": "f" * 32,
                            "children": [],
                        }
                    ),
                    encoding="utf-8",
                )
                os.chmod(manifest_p, 0o600)
                for extra_flags in (["--launcher-site-packages", str(env_tree)], []):
                    cp_reap = subprocess.run(
                        [
                            sys.executable,
                            str(launcher_tree / "scripts" / "opencode-attested"),
                            *extra_flags,
                            "--reap-worker",
                            str(manifest_p),
                        ],
                        env=sub_env,
                        capture_output=True,
                        text=True,
                        timeout=15,
                        check=False,
                    )
                    self.assertEqual(cp_reap.returncode, 0, cp_reap.stderr)
                    self.assertEqual(sleeper.wait(timeout=3), -signal.SIGKILL)

            # 4. Zero bytecode / zero pin drift across both launcher_tree and env_tree!
            self.assertEqual(_canonical_tree_sha256(launcher_tree), tree_sha_before)
            self.assertEqual(_canonical_tree_sha256(env_tree), env_sha_before)
        finally:
            for dp_str, _dirs, files in os.walk(short_root, topdown=False):
                dp = Path(dp_str)
                for fn in files:
                    try:
                        os.chmod(dp / fn, 0o700)
                    except OSError:
                        pass
                try:
                    os.chmod(dp, 0o700)
                except OSError:
                    pass
            shutil.rmtree(short_root, ignore_errors=True)

    def test_non_custody_worker_cli_strips_runs_env_and_accepts_explicit_runs_dir(self) -> None:
        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            tmp_path = Path(tmp).resolve()
            hostile_runs = tmp_path / "hostile_runs"
            hostile_runs.mkdir(mode=0o700)
            explicit_runs = tmp_path / "explicit_runs"
            explicit_runs.mkdir(mode=0o700)

            check_code = textwrap.dedent(
                f"""
                import json, os, sys
                from pathlib import Path
                sys.path.insert(0, {str(ROOT)!r})
                from local_assist.custody import bootstrap_entrypoint
                from local_assist.registry import _effective_runs_dir
                st = bootstrap_entrypoint(Path({str(ROOT)!r}), sys.argv)
                print(json.dumps({{
                    "custody_mode": st.custody_mode,
                    "worker_or_reap_cli": st.worker_or_reap_cli,
                    "env_has_runs": "FREE_INFERENCE_RUNS_DIR" in os.environ,
                    "resolved_runs": str(_effective_runs_dir()),
                }}))
                """
            )
            sub_env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": os.environ.get("HOME", "/tmp"),
                "FREE_INFERENCE_RUNS_DIR": str(hostile_runs),
            }

            # 1. Non-custody unattended worker CLI strips inherited FREE_INFERENCE_RUNS_DIR
            cp_strip = subprocess.run(
                [sys.executable, "-c", check_code, "--unattended-worker"],
                env=sub_env,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(cp_strip.returncode, 0, cp_strip.stderr)
            out_strip = json.loads(cp_strip.stdout.strip())
            self.assertFalse(out_strip["custody_mode"])
            self.assertTrue(out_strip["worker_or_reap_cli"])
            self.assertFalse(out_strip["env_has_runs"])
            self.assertNotEqual(Path(out_strip["resolved_runs"]).resolve(), hostile_runs)

            # 2. Non-custody unattended worker CLI honors explicit --runs-dir <dir>
            cp_opt = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    check_code,
                    "--unattended-worker",
                    "--runs-dir",
                    str(explicit_runs),
                ],
                env=sub_env,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(cp_opt.returncode, 0, cp_opt.stderr)
            out_opt = json.loads(cp_opt.stdout.strip())
            self.assertFalse(out_opt["custody_mode"])
            self.assertFalse(out_opt["env_has_runs"])
            self.assertEqual(Path(out_opt["resolved_runs"]).resolve(), explicit_runs)

    @unittest.skipUnless(sys.platform == "darwin", "In-group proc_pidinfo manifest test requires Darwin")
    def test_in_group_worker_manifest_and_lifecycle_deterministic(self) -> None:
        from local_assist.launch import execute_worker_profile_session
        from local_assist.security_profile import parse_security_profile_dict

        short_root = Path(tempfile.mkdtemp(prefix="fi-ingrp-", dir=SHORT_TMP_DIR))
        try:
            ws_dir = short_root / "ws"
            ws_dir.mkdir(mode=0o700)
            bridge_dir = short_root / "bridge"
            bridge_dir.mkdir(mode=0o700)
            manifest_path = bridge_dir / "manifest.json"

            # Fake sandbox-exec + fake opencode binary recording PGIDs of both 'serve --service' and 'run'
            pgid_log = short_root / "pgids.jsonl"
            fake_sb = short_root / "fake-sb"
            fake_sb.write_text("#!/bin/sh\nshift 2\nexec \"$@\"\n", encoding="utf-8")
            os.chmod(fake_sb, 0o700)

            fake_oc = short_root / "fake-oc"
            fake_oc.write_text(
                f"#!{sys.executable} -I -B\n"
                + textwrap.dedent(
                    f"""
                    import json, os, signal, sys, time
                    from pathlib import Path
                    args = sys.argv[1:]
                    if args == ["--version"]:
                        print("2.3.2")
                        raise SystemExit(0)
                    with open({str(pgid_log)!r}, "a") as fh:
                        fh.write(json.dumps({{"args": args, "pid": os.getpid(), "pgid": os.getpgrp()}}) + "\\n")
                    if args[:2] == ["serve", "--service"]:
                        cfg = json.loads((Path(os.environ["XDG_CONFIG_HOME"]) / "opencode" / "service.json").read_text())
                        st_dir = Path(os.environ["XDG_STATE_HOME"]) / "opencode"
                        st_dir.mkdir(parents=True, exist_ok=True)
                        (st_dir / "service.json").write_text(json.dumps({{
                            "pid": os.getpid(),
                            "hostname": "127.0.0.1",
                            "port": cfg["port"],
                        }}))
                        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
                        while True:
                            time.sleep(0.05)
                    if args[0] == "run":
                        raise SystemExit(0)
                    raise SystemExit(2)
                    """
                ),
                encoding="utf-8",
            )
            os.chmod(fake_oc, 0o700)

            # Run inside a child process started with start_new_session=True so launcher_pgid == launcher_pid holds!
            ps_sub_patch = (
                ""
                if CAN_RUN_PS
                else (
                    "import local_assist.security_profile as _sp, local_assist.launch as _lch\n"
                    "_sp._scan_worker_pids = lambda **_: ({}, True)\n"
                    "_lch._cleanup_scope_opencode_service = lambda *a, **k: True\n"
                )
            )
            port_sub_patch = (
                ""
                if CAN_BIND_LOOPBACK_TCP
                else (
                    "import local_assist.launch as _lch_p\n"
                    "_lch_p._allocate_loopback_ephemeral_port = lambda: 43219\n"
                )
            )
            runner_code = textwrap.dedent(
                f"""
                import argparse, json, sys
                from pathlib import Path
                sys.path.insert(0, {str(ROOT)!r})
                from local_assist.launch import execute_worker_profile_session
                from local_assist.security_profile import allocate_worker_home, parse_security_profile_dict
                """
            ) + ps_sub_patch + port_sub_patch + textwrap.dedent(
                f"""
                prof = parse_security_profile_dict({{"schema_version": 1, "mode": "unattended_worker"}})
                ns = argparse.Namespace(
                    keep_worker_home=False,
                    print_config=False,
                    inherit_process_group=True,
                    worker_manifest={str(manifest_path)!r},
                    run_token="tok-ingroup-1",
                )
                rc = execute_worker_profile_session(
                    active_profile=prof,
                    args=ns,
                    caller_cwd=Path({str(ws_dir)!r}),
                    opencode_bin={str(fake_oc)!r},
                    sandbox_exec_bin=Path({str(fake_sb)!r}),
                    validated_worker_args=["run", "--format", "json", "ping"],
                    build_base_config_fn=lambda _r: {{"provider": {{}}}},
                    build_print_config_payload_fn=lambda *a: {{}},
                    allocate_worker_home_fn=lambda: allocate_worker_home(worker_homes_dir=Path({str(short_root / "workers")!r})),
                    skip_http_service_probe=True,
                )
                raise SystemExit(rc)
                """
            )
            cp = subprocess.run(
                [sys.executable, "-I", "-B", "-c", runner_code],
                capture_output=True,
                text=True,
                start_new_session=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertTrue(manifest_path.is_file())
            self.assertEqual(stat.S_IMODE(manifest_path.lstat().st_mode), 0o600)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema_version"], 1)
            self.assertEqual(manifest["run_token"], "tok-ingroup-1")
            self.assertEqual(manifest["launcher_pid"], manifest["launcher_pgid"])
            self.assertIs(type(manifest["launcher_start_tvsec"]), int)
            self.assertIs(type(manifest["launcher_start_tvusec"]), int)
            self.assertEqual(len(manifest["worker_tag"]), 32)
            roles = [c["role"] for c in manifest["children"]]
            self.assertEqual(roles, ["opencode_serve", "opencode_run"])
            for c in manifest["children"]:
                self.assertEqual(c["pgid"], manifest["launcher_pgid"])
                self.assertIs(type(c["start_tvsec"]), int)
                self.assertIs(type(c["start_tvusec"]), int)

            rows = [json.loads(ln) for ln in pgid_log.read_text(encoding="utf-8").splitlines() if ln.strip()]
            self.assertEqual(len(rows), 2)
            for row in rows:
                self.assertEqual(row["pgid"], manifest["launcher_pgid"])
        finally:
            shutil.rmtree(short_root, ignore_errors=True)

    @unittest.skipUnless(
        CAN_RUN_SANDBOX_EXEC and CAN_CONNECT_LOOPBACK_TCP and bool(OPENCODE_BIN),
        "Requires live sandbox-exec, loopback TCP connect, and installed opencode binary",
    )
    def test_real_opencode_2_0_32_in_group_serve_and_run_against_mock_model(self) -> None:
        assert OPENCODE_BIN is not None
        from local_assist.registry import get_process_lstart, load_model, pid_file_for_model

        served_repo = str(load_model("qwen3-30b-a3b-2507-mlx-4bit")["repo"])

        class _MockModelHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                body = json.dumps({"object": "list", "data": [{"id": served_repo}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                raw_req = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                req_obj = json.loads(raw_req.decode("utf-8")) if raw_req else {}
                if req_obj.get("stream"):
                    chunk1 = {
                        "id": "chatcmpl-1",
                        "object": "chat.completion.chunk",
                        "created": int(time.time()),
                        "model": served_repo,
                        "choices": [
                            {
                                "index": 0,
                                "delta": {"role": "assistant", "content": "IN_GROUP_REAL_OPENCODE_OK"},
                                "finish_reason": None,
                            }
                        ],
                    }
                    chunk2 = {
                        "id": "chatcmpl-1",
                        "object": "chat.completion.chunk",
                        "created": int(time.time()),
                        "model": served_repo,
                        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                        "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
                    }
                    sse = (
                        f"data: {json.dumps(chunk1)}\n\n"
                        f"data: {json.dumps(chunk2)}\n\n"
                        "data: [DONE]\n\n"
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Content-Length", str(len(sse)))
                    self.end_headers()
                    self.wfile.write(sse)
                    return
                resp = {
                    "id": "chatcmpl-1",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": served_repo,
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "IN_GROUP_REAL_OPENCODE_OK"},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
                }
                raw = json.dumps(resp).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        httpd: ThreadingHTTPServer | None = None
        for cand_port in range(34100, 34900):
            try:
                httpd = ThreadingHTTPServer(("127.0.0.1", cand_port), _MockModelHandler)
                break
            except OSError:
                continue
        assert httpd is not None
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        short_root = Path(tempfile.mkdtemp(prefix="fi-real-oc-", dir=SHORT_TMP_DIR))
        try:
            ws_dir = short_root / "ws"
            ws_dir.mkdir(mode=0o700)
            runs_dir = short_root / "runs"
            runs_dir.mkdir(mode=0o700)
            bridge_dir = short_root / "bridge"
            bridge_dir.mkdir(mode=0o700)
            manifest_path = bridge_dir / "manifest.json"
            prof_path = bridge_dir / "profile.yaml"
            prof_path.write_text("schema_version: 1\nmode: unattended_worker\n", encoding="utf-8")
            os.chmod(prof_path, 0o600)

            rec = {
                "model_id": "qwen3-30b-a3b-2507-mlx-4bit",
                "repo": served_repo,
                "runtime": "mlx-lm",
                "api_base_url": f"http://127.0.0.1:{port}/v1",
                "port": port,
                "pid": os.getpid(),
                "pid_lstart": get_process_lstart(os.getpid()),
                "hf_offline": True,
                "status": "ready",
                "startup_nonce": "n-oc",
            }
            pid_file_for_model("qwen3-30b-a3b-2507-mlx-4bit", runs_dir).write_text(json.dumps(rec), encoding="utf-8")
            workers_dir = short_root / "workers"
            workers_dir.mkdir(mode=0o700)
            oc_env = dict(os.environ)
            oc_env["FREE_INFERENCE_WORKER_HOMES_DIR"] = str(workers_dir)

            # Use opencode-local with --inherit-process-group --worker-manifest against our mock loopback model
            runner = textwrap.dedent(
                f"""
                import subprocess, sys
                import importlib.machinery, importlib.util
                path = {str(ROOT / "scripts" / "opencode-local")!r}
                loader = importlib.machinery.SourceFileLoader("oc_loc", path)
                spec = importlib.util.spec_from_loader("oc_loc", loader)
                mod = importlib.util.module_from_spec(spec)
                loader.exec_module(mod)
                mod.ensure_model_served = lambda *a, **k: (True, None)
                raise SystemExit(mod.main([
                    path,
                    "--model", "qwen3-30b-a3b-2507-mlx-4bit",
                    "--port", "{port}",
                    "--no-serve",
                    "--security-profile", {str(prof_path)!r},
                    "--opencode-bin", {str(OPENCODE_BIN)!r},
                    "--runs-dir", {str(runs_dir)!r},
                    "--inherit-process-group",
                    "--worker-manifest", {str(manifest_path)!r},
                    "--run-token", "real-oc-tok",
                    "--", "run", "--format", "json", "Reply IN_GROUP_REAL_OPENCODE_OK",
                ]))
                """
            )
            cp = subprocess.run(
                [sys.executable, "-I", "-B", "-c", runner],
                cwd=str(ws_dir),
                env=oc_env,
                capture_output=True,
                text=True,
                start_new_session=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertIn("IN_GROUP_REAL_OPENCODE_OK", cp.stdout)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual([c["role"] for c in manifest["children"]], ["opencode_serve", "opencode_run"])
            for c in manifest["children"]:
                self.assertEqual(c["pgid"], manifest["launcher_pgid"])
        finally:
            httpd.shutdown()
            httpd.server_close()
            t.join(timeout=2.0)
            shutil.rmtree(short_root, ignore_errors=True)


class LookoutRound2RegressionTests(unittest.TestCase):
    """Tests-first regression coverage for FREE-INFERENCE-OPENCODE-001 R1..R8 and kinfo_proc Q3."""

    @unittest.skipUnless(sys.platform == "darwin", "Early manifest + reap barrier test requires Darwin")
    def test_r1_early_manifest_published_on_session_exit4_and_premain_errors(self) -> None:
        from local_assist import proc_identity
        from local_assist.security_profile import _safe_rmtree_nofollow

        short_root = Path(tempfile.mkdtemp(prefix="fi-r1-", dir=SHORT_TMP_DIR))
        try:
            ws_dir = short_root / "ws"
            ws_dir.mkdir(mode=0o700)
            bridge_dir = short_root / "bridge"
            bridge_dir.mkdir(mode=0o700)
            runs_dir = short_root / "empty_runs"
            runs_dir.mkdir(mode=0o700)
            workers_dir = short_root / "workers"
            workers_dir.mkdir(mode=0o700)
            fake_oc = short_root / "fake-oc"
            fake_oc.write_text("#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 2.3.2; exit 0; fi\nexit 0\n", encoding="utf-8")
            os.chmod(fake_oc, 0o700)
            fake_sb = short_root / "fake-sb"
            fake_sb.write_text("#!/bin/sh\nshift 2\nexec \"$@\"\n", encoding="utf-8")
            os.chmod(fake_sb, 0o700)
            prof_path = bridge_dir / "profile.yaml"
            prof_path.write_text(
                "schema_version: 1\nmode: unattended_worker\nspend:\n  inherit_attached_session_caps: true\n",
                encoding="utf-8",
            )
            os.chmod(prof_path, 0o600)

            base_env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": os.environ.get("HOME", "/tmp"),
                "FREE_INFERENCE_SANDBOX_EXEC_BIN": str(fake_sb),
                "FREE_INFERENCE_WORKER_HOMES_DIR": str(workers_dir),
            }

            # 1. Session missing -> exit 4 with BOTH 0600 manifest.json (children: []) AND 0600 launcher_exit.json,
            #    isolated_home cleaned up, and --reap-worker <manifest> exits 0!
            manifest_1 = bridge_dir / "manifest_s4.json"
            exit_1 = bridge_dir / "exit_s4.json"
            cp_s4 = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(ROOT / "scripts" / "opencode-attested"),
                    "--model",
                    "tinfoil-deepseek-v4-1-flash",
                    "--security-profile",
                    str(prof_path),
                    "--opencode-bin",
                    str(fake_oc),
                    "--runs-dir",
                    str(runs_dir),
                    "--inherit-process-group",
                    "--worker-manifest",
                    str(manifest_1),
                    "--run-token",
                    "r1-tok-exit4",
                    "--launcher-exit-file",
                    str(exit_1),
                    "--",
                    "run",
                    "hello",
                ],
                cwd=str(ws_dir),
                env=base_env,
                capture_output=True,
                text=True,
                start_new_session=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(cp_s4.returncode, 4, cp_s4.stderr)
            self.assertTrue(manifest_1.is_file(), "Expected 0600 manifest.json on session exit 4")
            self.assertTrue(exit_1.is_file(), "Expected 0600 launcher_exit.json on session exit 4")
            self.assertEqual(stat.S_IMODE(manifest_1.lstat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(exit_1.lstat().st_mode), 0o600)
            m_doc = json.loads(manifest_1.read_text(encoding="utf-8"))
            e_doc = json.loads(exit_1.read_text(encoding="utf-8"))
            self.assertEqual(m_doc["run_token"], "r1-tok-exit4")
            self.assertEqual(m_doc["children"], [])
            self.assertEqual(m_doc["launcher_pid"], e_doc["launcher_pid"])
            self.assertEqual(e_doc["reason"], "opencode_session_unavailable")
            self.assertFalse(Path(m_doc["isolated_home"]).exists(), "Expected early-exit isolated_home to be cleaned up")
            self.assertEqual(proc_identity.reap_worker_from_manifest(manifest_1), 0)

            # 2. Malformed pre-separator bootstrap arg (--runs-dir missing value / nonexistent) in BOTH launchers
            for idx, script_rel in enumerate(("scripts/opencode-attested", "scripts/opencode-local")):
                m_boot = bridge_dir / f"manifest_boot_{idx}.json"
                e_boot = bridge_dir / f"exit_boot_{idx}.json"
                cp_boot = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-B",
                        str(ROOT / script_rel),
                        "--inherit-process-group",
                        "--worker-manifest",
                        str(m_boot),
                        "--run-token",
                        f"r1-boot-{idx}",
                        "--launcher-exit-file",
                        str(e_boot),
                        "--runs-dir",
                        str(short_root / "does_not_exist"),
                        "--",
                        "run",
                        "hello",
                    ],
                    cwd=str(ws_dir),
                    env=base_env,
                    capture_output=True,
                    text=True,
                    start_new_session=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(cp_boot.returncode, 1, cp_boot.stderr)
                self.assertTrue(m_boot.is_file(), f"{script_rel}: expected manifest on bootstrap --runs-dir error")
                self.assertFalse(e_boot.exists(), f"{script_rel}: non-session error must not write launcher_exit.json")
                mb_doc = json.loads(m_boot.read_text(encoding="utf-8"))
                self.assertEqual(mb_doc["children"], [])
                self.assertFalse(Path(mb_doc["isolated_home"]).exists())

            # 3. Malformed pre-separator flag (--launcher-site-packages missing value) in BOTH launchers
            for idx, script_rel in enumerate(("scripts/opencode-attested", "scripts/opencode-local")):
                m_mal = bridge_dir / f"manifest_mal_{idx}.json"
                cp_mal = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-B",
                        str(ROOT / script_rel),
                        "--inherit-process-group",
                        "--worker-manifest",
                        str(m_mal),
                        "--run-token",
                        f"r1-mal-{idx}",
                        "--runs-dir",
                        "--",
                        "run",
                        "hello",
                    ],
                    cwd=str(ws_dir),
                    env=base_env,
                    capture_output=True,
                    text=True,
                    start_new_session=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(cp_mal.returncode, 1, cp_mal.stderr)
                self.assertTrue(m_mal.is_file(), f"{script_rel}: expected manifest on malformed pre-separator arg")
                mm_doc = json.loads(m_mal.read_text(encoding="utf-8"))
                self.assertEqual(mm_doc["children"], [])
                self.assertFalse(Path(mm_doc["isolated_home"]).exists())

            # 4. Oversized LOCAL_ASSIST_SESSION_TOKEN (>512 bytes) in opencode-attested:
            #    scrubbed across execve, exits 1, publishes 0600 empty-children manifest, cleans up isolated_home!
            m_tok = bridge_dir / "manifest_oversize_tok.json"
            oversized_secret = "se-session-" + ("z" * 600)
            tok_env = {**base_env, "LOCAL_ASSIST_SESSION_TOKEN": oversized_secret}
            cp_tok = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts" / "opencode-attested"),
                    "--inherit-process-group",
                    "--worker-manifest",
                    str(m_tok),
                    "--run-token",
                    "r1-tok-oversize",
                    "--",
                    "run",
                    "hello",
                ],
                cwd=str(ws_dir),
                env=tok_env,
                capture_output=True,
                text=True,
                start_new_session=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(cp_tok.returncode, 1, cp_tok.stderr)
            self.assertIn("exceeding 512 bytes", cp_tok.stderr)
            self.assertNotIn(oversized_secret, cp_tok.stderr)
            self.assertNotIn(oversized_secret, cp_tok.stdout)
            self.assertTrue(m_tok.is_file(), "Expected manifest even when oversized token was scrubbed across execve")
            mt_doc = json.loads(m_tok.read_text(encoding="utf-8"))
            self.assertEqual(mt_doc["children"], [])
            self.assertFalse(Path(mt_doc["isolated_home"]).exists())
            self.assertEqual(list(workers_dir.iterdir()), [])

            # 5. Unknown pre-separator CLI flag (argparse SystemExit(2)) -> non-session exit != 4,
            #    publishes 0600 manifest.json (children: []), cleans up isolated_home!
            for idx, script_rel in enumerate(("scripts/opencode-attested", "scripts/opencode-local")):
                m_unk = bridge_dir / f"manifest_unk_{idx}.json"
                e_unk = bridge_dir / f"exit_unk_{idx}.json"
                cp_unk = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-B",
                        str(ROOT / script_rel),
                        "--inherit-process-group",
                        "--worker-manifest",
                        str(m_unk),
                        "--run-token",
                        f"r1-unk-{idx}",
                        "--launcher-exit-file",
                        str(e_unk),
                        "--unknown-bogus-flag",
                        "--",
                        "run",
                        "hello",
                    ],
                    cwd=str(ws_dir),
                    env=base_env,
                    capture_output=True,
                    text=True,
                    start_new_session=True,
                    timeout=15,
                    check=False,
                )
                self.assertNotEqual(cp_unk.returncode, 0)
                self.assertNotEqual(cp_unk.returncode, 4)
                self.assertTrue(m_unk.is_file(), f"{script_rel}: expected manifest on unknown CLI flag")
                self.assertFalse(e_unk.exists(), f"{script_rel}: unknown CLI flag must not write launcher_exit.json")
                mu_doc = json.loads(m_unk.read_text(encoding="utf-8"))
                self.assertEqual(mu_doc["children"], [])
                self.assertFalse(Path(mu_doc["isolated_home"]).exists())

            # 6. Bounded residual: invalid --worker-manifest parent or PGID != PID -> fails closed with exit 1,
            #    writes neither manifest nor launcher_exit.json, and leaves zero worker homes behind!
            bad_manifest = short_root / "missing_parent" / "manifest.json"
            cp_badm = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(ROOT / "scripts" / "opencode-attested"),
                    "--inherit-process-group",
                    "--worker-manifest",
                    str(bad_manifest),
                    "--run-token",
                    "r1-bad-parent",
                    "--",
                    "run",
                    "hello",
                ],
                cwd=str(ws_dir),
                env=base_env,
                capture_output=True,
                text=True,
                start_new_session=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(cp_badm.returncode, 1)
            self.assertFalse(bad_manifest.exists())
            self.assertEqual(list(workers_dir.iterdir()), [])

            m_pgid = bridge_dir / "manifest_pgid_mismatch.json"
            cp_pgid = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(ROOT / "scripts" / "opencode-local"),
                    "--inherit-process-group",
                    "--worker-manifest",
                    str(m_pgid),
                    "--run-token",
                    "r1-pgid-mismatch",
                    "--",
                    "run",
                    "hello",
                ],
                cwd=str(ws_dir),
                env=base_env,
                capture_output=True,
                text=True,
                start_new_session=False,
                timeout=15,
                check=False,
            )
            self.assertEqual(cp_pgid.returncode, 1)
            self.assertFalse(m_pgid.exists())
            self.assertEqual(list(workers_dir.iterdir()), [])
        finally:
            _safe_rmtree_nofollow(short_root)
            shutil.rmtree(short_root, ignore_errors=True)

    @unittest.skipUnless(sys.platform == "darwin", "In-group stderr pipe drain test requires Darwin")
    def test_r2_service_stderr_continuous_drain_and_nonblocking_eof_on_failure(self) -> None:
        short_root = Path(tempfile.mkdtemp(prefix="fi-r2-", dir=SHORT_TMP_DIR))
        try:
            ws_dir = short_root / "ws"
            ws_dir.mkdir(mode=0o700)
            workers_dir = short_root / "workers"
            workers_dir.mkdir(mode=0o700)
            fake_sb = short_root / "fake-sb"
            fake_sb.write_text("#!/bin/sh\nshift 2\nexec \"$@\"\n", encoding="utf-8")
            os.chmod(fake_sb, 0o700)

            # Case A: opencode serve --service binds 127.0.0.1:<cfg["port"]>, writes >512 KiB (>8x pipe buffer)
            # before and during run, and serves a live post-flood TCP request/ack round-trip (with file fallback only
            # when an outer test sandbox blocks loopback connect() with EPERM).
            flood_req = short_root / "flood_req.txt"
            flood_ack = short_root / "flood_ack.txt"
            tcp_proof = short_root / "tcp_proof.txt"
            use_live_tcp = bool(CAN_CONNECT_LOOPBACK_TCP)
            can_bind_tcp = bool(CAN_BIND_LOOPBACK_TCP)
            fake_oc_flood = short_root / "fake-oc-flood"
            fake_oc_flood.write_text(
                f"#!{sys.executable} -I -B\n"
                + textwrap.dedent(
                    f"""
                    import json, os, select, signal, socket, sys, time
                    from pathlib import Path
                    args = sys.argv[1:]
                    if args == ["--version"]:
                        print("2.3.2")
                        raise SystemExit(0)
                    if args[:2] == ["serve", "--service"]:
                        cfg = json.loads((Path(os.environ["XDG_CONFIG_HOME"]) / "opencode" / "service.json").read_text())
                        st_dir = Path(os.environ["XDG_STATE_HOME"]) / "opencode"
                        st_dir.mkdir(parents=True, exist_ok=True)
                        srv = None
                        if {can_bind_tcp!r}:
                            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                            srv.bind(("127.0.0.1", int(cfg["port"])))
                            srv.listen(5)
                            srv.setblocking(False)
                        def _bye(*_):
                            if srv is not None:
                                try:
                                    srv.close()
                                except OSError:
                                    pass
                            sys.exit(0)
                        signal.signal(signal.SIGTERM, _bye)
                        chunk = b"S" * 8192 + b"\\n"
                        for _ in range(72):
                            os.write(2, chunk)
                        (st_dir / "service.json").write_text(json.dumps({{"pid": os.getpid(), "hostname": "127.0.0.1", "port": cfg["port"]}}))
                        req_p = Path({str(flood_req)!r})
                        ack_p = Path({str(flood_ack)!r})
                        proof_p = Path({str(tcp_proof)!r})
                        while True:
                            os.write(2, chunk)
                            if {use_live_tcp!r} and srv is not None:
                                rlist, _, _ = select.select([srv], [], [], 0.01)
                                if rlist:
                                    conn, _ = srv.accept()
                                    try:
                                        conn.settimeout(2.0)
                                        data = b""
                                        while b"\\n" not in data and len(data) < 256:
                                            part = conn.recv(256)
                                            if not part:
                                                break
                                            data += part
                                        msg = data.decode("utf-8", errors="replace").strip()
                                        if msg == "PING_AFTER_576K":
                                            for _ in range(16):
                                                os.write(2, chunk)
                                            conn.sendall(b"POST_FLOOD_TCP_ACK:PING_AFTER_576K\\n")
                                            proof_p.write_text("TCP_ROUNDTRIP_OK")
                                    finally:
                                        conn.close()
                            else:
                                if req_p.is_file() and not ack_p.is_file():
                                    for _ in range(16):
                                        os.write(2, chunk)
                                    ack_p.write_text("POST_FLOOD_PROGRESS_OK:" + req_p.read_text())
                                time.sleep(0.01)
                    if args[0] == "run":
                        cfg = json.loads((Path(os.environ["XDG_CONFIG_HOME"]) / "opencode" / "service.json").read_text())
                        if {use_live_tcp!r}:
                            with socket.create_connection(("127.0.0.1", int(cfg["port"])), timeout=3.0) as cli:
                                cli.settimeout(3.0)
                                cli.sendall(b"PING_AFTER_576K\\n")
                                resp = b""
                                while b"\\n" not in resp and len(resp) < 256:
                                    part = cli.recv(256)
                                    if not part:
                                        break
                                    resp += part
                                if resp.decode("utf-8", errors="replace").strip() == "POST_FLOOD_TCP_ACK:PING_AFTER_576K":
                                    raise SystemExit(0)
                            sys.stderr.write("serve failed post-flood TCP round-trip\\n")
                            raise SystemExit(9)
                        req_p = Path({str(flood_req)!r})
                        ack_p = Path({str(flood_ack)!r})
                        req_p.write_text("PING_AFTER_576K")
                        deadline = time.monotonic() + 3.0
                        while time.monotonic() < deadline:
                            if ack_p.is_file() and ack_p.read_text() == "POST_FLOOD_PROGRESS_OK:PING_AFTER_576K":
                                raise SystemExit(0)
                            time.sleep(0.02)
                        sys.stderr.write("serve stalled on stderr backpressure before answering post-flood request\\n")
                        raise SystemExit(9)
                    raise SystemExit(2)
                    """
                ),
                encoding="utf-8",
            )
            os.chmod(fake_oc_flood, 0o700)

            ps_patch = (
                ""
                if CAN_RUN_PS
                else (
                    "import local_assist.security_profile as _sp, local_assist.launch as _lch\n"
                    "_sp._scan_worker_pids = lambda **_: ({}, True)\n"
                    "_lch._cleanup_scope_opencode_service = lambda *a, **k: True\n"
                )
            )
            port_patch = (
                ""
                if CAN_BIND_LOOPBACK_TCP
                else "import local_assist.launch as _lp\n_lp._allocate_loopback_ephemeral_port = lambda: 43220\n"
            )
            run_flood_code = (
                textwrap.dedent(
                    f"""
                    import argparse, sys
                    from pathlib import Path
                    sys.path.insert(0, {str(ROOT)!r})
                    from local_assist.launch import execute_worker_profile_session
                    from local_assist.security_profile import allocate_worker_home, parse_security_profile_dict
                    """
                )
                + ps_patch
                + port_patch
                + textwrap.dedent(
                    f"""
                    prof = parse_security_profile_dict({{"schema_version": 1, "mode": "unattended_worker"}})
                    ns = argparse.Namespace(keep_worker_home=False, print_config=False, inherit_process_group=True, worker_manifest={str(short_root / 'm_flood.json')!r}, run_token="r2-flood")
                    rc = execute_worker_profile_session(
                        active_profile=prof,
                        args=ns,
                        caller_cwd=Path({str(ws_dir)!r}),
                        opencode_bin={str(fake_oc_flood)!r},
                        sandbox_exec_bin=Path({str(fake_sb)!r}),
                        validated_worker_args=["run", "ping"],
                        build_base_config_fn=lambda _r: {{"provider": {{}}}},
                        build_print_config_payload_fn=lambda *a: {{}},
                        allocate_worker_home_fn=lambda: allocate_worker_home(worker_homes_dir=Path({str(workers_dir)!r})),
                        skip_http_service_probe=True,
                    )
                    raise SystemExit(rc)
                    """
                )
            )
            cp_flood = subprocess.run(
                [sys.executable, "-I", "-B", "-c", run_flood_code],
                capture_output=True,
                text=True,
                start_new_session=True,
                timeout=8,
                check=False,
            )
            self.assertEqual(cp_flood.returncode, 0, cp_flood.stderr)
            if use_live_tcp:
                self.assertTrue(tcp_proof.is_file(), "Expected live TCP round-trip proof after 576 KiB flood")
                self.assertEqual(tcp_proof.read_text(encoding="utf-8"), "TCP_ROUNDTRIP_OK")

            # Case B: serve --service fails readiness after forking a child that keeps stderr fd open -> must NOT hang on EOF!
            holder_pid_file = short_root / "holder.pid"
            fake_oc_fail = short_root / "fake-oc-fail"
            fake_oc_fail.write_text(
                f"#!{sys.executable} -I -B\n"
                + textwrap.dedent(
                    f"""
                    import os, sys, time
                    if sys.argv[1:] == ["--version"]:
                        print("2.3.2")
                        raise SystemExit(0)
                    os.write(2, b"FATAL_SERVE_BIND_ERROR\\n")
                    pid = os.fork()
                    if pid == 0:
                        os.setsid()
                        with open({str(holder_pid_file)!r}, "w") as fh:
                            fh.write(str(os.getpid()))
                        time.sleep(10)
                        os._exit(0)
                    os._exit(1)
                    """
                ),
                encoding="utf-8",
            )
            os.chmod(fake_oc_fail, 0o700)
            run_fail_code = run_flood_code.replace(str(fake_oc_flood), str(fake_oc_fail)).replace("m_flood.json", "m_fail.json")
            t0 = time.monotonic()
            cp_fail = subprocess.run(
                [sys.executable, "-I", "-B", "-c", run_fail_code],
                capture_output=True,
                text=True,
                start_new_session=True,
                timeout=5,
                check=False,
            )
            elapsed = time.monotonic() - t0
            try:
                if holder_pid_file.is_file():
                    os.kill(int(holder_pid_file.read_text().strip()), signal.SIGKILL)
            except OSError:
                pass
            self.assertEqual(cp_fail.returncode, 1)
            self.assertLess(elapsed, 4.0, "Startup error read must not block waiting for inherited stderr EOF")
            self.assertIn("FATAL_SERVE_BIND_ERROR", cp_fail.stderr)
        finally:
            shutil.rmtree(short_root, ignore_errors=True)

    def test_r3_session_store_propagation_pointer_publication_and_bystander_isolation(self) -> None:
        from local_assist import session as sess_mod
        from local_assist.custody import read_active_runs_pointer, write_active_runs_pointer
        from local_assist.registry import load_model, pid_file_for_model

        short_root = Path(tempfile.mkdtemp(prefix="fi-r3-", dir=SHORT_TMP_DIR))
        try:
            fake_home = short_root / "home"
            fake_home.mkdir(mode=0o700)
            default_runs = short_root / "default_runs"
            default_runs.mkdir(mode=0o700)
            custom_runs = short_root / "custom_runs"
            custom_runs.mkdir(mode=0o700)
            stale_runs = short_root / "stale_runs"
            stale_runs.mkdir(mode=0o700)
            pointer_runs = short_root / "pointer_runs"
            pointer_runs.mkdir(mode=0o700)

            model_id = "tinfoil-deepseek-v4-1-flash"
            repo = str(load_model(model_id)["repo"])
            FakePW = type("pw", (), {"pw_dir": str(fake_home)})

            def _seed_store(store: Path, port: int) -> dict[str, Any]:
                tok_p = store / f".se-session-{model_id}.token"
                tok_p.write_text('{"session_id":"s1","generation":1,"token":"' + ("se-session-" + "d" * 64) + '"}', encoding="utf-8")
                os.chmod(tok_p, 0o600)
                rec = {
                    "model_id": model_id,
                    "repo": repo,
                    "runtime": "proxy",
                    "api_base_url": f"http://127.0.0.1:{port}/v1",
                    "port": port,
                    "upstream_port": port + 1000,
                    "pid": os.getpid(),
                    "pid_lstart": _format_bsdinfo_lstart(os.getpid()) if not CAN_RUN_PS else sess_mod.read_pid_record_for_model.__globals__["get_process_lstart"](os.getpid()),
                    "session_token_file": str(tok_p),
                    "max_chat_requests": 200,
                    "max_tokens_cap": 8192,
                    "max_request_bytes": 1048576,
                    "ttl_seconds": 3600,
                    "status": "ready",
                }
                pf = pid_file_for_model(model_id, store)
                pf.write_text(json.dumps(rec), encoding="utf-8")
                os.chmod(pf, 0o600)
                return rec

            _install_outer_sandbox_ps_fixture_if_blocked(self)
            seen_subproc_cmds: list[list[str]] = []

            def _fake_sess_subproc(cmd: list[str], *a: Any, **kw: Any) -> Any:
                seen_subproc_cmds.append([str(x) for x in cmd])
                if any("serve-model" in str(x) for x in cmd):
                    assert "--runs-dir" in cmd, f"Expected --runs-dir in serve-model cmd: {cmd}"
                    r_idx = cmd.index("--runs-dir")
                    target_store = Path(cmd[r_idx + 1])
                    _seed_store(target_store, 18090)
                if any("stop-model" in str(x) for x in cmd):
                    # Verify --runs-dir was passed and remove only from that target store!
                    assert "--runs-dir" in cmd, f"Expected --runs-dir in stop-model cmd: {cmd}"
                    r_idx = cmd.index("--runs-dir")
                    target_store = Path(cmd[r_idx + 1])
                    pid_file_for_model(model_id, target_store).unlink(missing_ok=True)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            def _fake_status(rec: dict[str, Any] | None, rdir: Path) -> dict[str, Any]:
                if not rec:
                    return {"state": "OFF", "model_id": model_id}
                return {
                    "state": "ON",
                    "model_id": model_id,
                    "session_id": "s1",
                    "generation": 1,
                    "remaining_seconds": 3600,
                    "window_seconds": 3600,
                    "requests_remaining": 200,
                    "request_limit": 200,
                }

            with (
                patch("local_assist.custody.pwd.getpwuid", return_value=FakePW()),
                patch("local_assist.registry.DEFAULT_RUNS_DIR", default_runs),
                patch("local_assist.session.subprocess.run", side_effect=_fake_sess_subproc),
                patch("local_assist.session.status_for_record", side_effect=_fake_status),
            ):
                # 1. Seed a stale pointer first, then run implicit `session start` -> must pass --runs-dir <default_runs> AND --publish-active-runs!
                self.assertTrue(write_active_runs_pointer(stale_runs))
                self.assertEqual(read_active_runs_pointer(), stale_runs.resolve())
                seen_subproc_cmds.clear()
                with patch.dict(os.environ, {}, clear=False):
                    os.environ.pop("FREE_INFERENCE_RUNS_DIR", None)
                    rc_start_imp = sess_mod.main(["start", "--model", model_id, "--for", "1h"])
                self.assertEqual(rc_start_imp, 0)
                serve_cmds = [c for c in seen_subproc_cmds if any("serve-model" in x for x in c)]
                self.assertEqual(len(serve_cmds), 1)
                self.assertIn("--runs-dir", serve_cmds[0])
                self.assertEqual(Path(serve_cmds[0][serve_cmds[0].index("--runs-dir") + 1]).resolve(), default_runs.resolve())
                self.assertIn("--publish-active-runs", serve_cmds[0])
                pid_file_for_model(model_id, default_runs).unlink(missing_ok=True)

                # 2. `FREE_INFERENCE_RUNS_DIR=<custom> session start` -> selects <custom> AND omits --publish-active-runs!
                seen_subproc_cmds.clear()
                with patch.dict(os.environ, {"FREE_INFERENCE_RUNS_DIR": str(custom_runs)}, clear=False):
                    rc_start_env = sess_mod.main(["start", "--model", model_id, "--for", "1h"])
                self.assertEqual(rc_start_env, 0)
                serve_env_cmds = [c for c in seen_subproc_cmds if any("serve-model" in x for x in c)]
                self.assertEqual(len(serve_env_cmds), 1)
                self.assertEqual(Path(serve_env_cmds[0][serve_env_cmds[0].index("--runs-dir") + 1]).resolve(), custom_runs.resolve())
                self.assertNotIn("--publish-active-runs", serve_env_cmds[0])
                pid_file_for_model(model_id, custom_runs).unlink(missing_ok=True)

                # 3. Bystander isolation on `session --runs-dir <custom> stop`:
                #    Seed BOTH default_runs (bystander) AND custom_runs; stopping custom_runs must leave default_runs intact!
                _seed_store(default_runs, 18081)
                _seed_store(custom_runs, 18082)
                seen_subproc_cmds.clear()
                rc_stop_cust = sess_mod.main(["--runs-dir", str(custom_runs), "stop", "--model", model_id])
                self.assertEqual(rc_stop_cust, 0)
                self.assertFalse(pid_file_for_model(model_id, custom_runs).exists(), "Expected custom_runs session stopped")
                self.assertTrue(pid_file_for_model(model_id, default_runs).exists(), "Bystander default_runs session must remain untouched!")

                # 4. Real `scripts/stop-model --runs-dir <custom>` CLI test with live bystander record in default_runs:
                _seed_store(custom_runs, 18083)
                stop_mod = _load_script_module("stop_model_r3", "scripts/stop-model")
                with patch.object(stop_mod, "_terminate_verified_pid", return_value=True):
                    rc_real_stop = stop_mod.main(["stop-model", "--runs-dir", str(custom_runs), model_id])
                self.assertEqual(rc_real_stop, 0)
                self.assertFalse(pid_file_for_model(model_id, custom_runs).exists())
                self.assertTrue(pid_file_for_model(model_id, default_runs).exists())

                # 5. Writable non-custody worker checkout with empty default_runs + live pointer_runs via active-runs.json:
                #    ensure_model_served in opencode-attested passes --runs-dir <pointer_runs> to verify-served-model!
                pid_file_for_model(model_id, default_runs).unlink(missing_ok=True)
                _seed_store(pointer_runs, 18084)
                self.assertTrue(write_active_runs_pointer(pointer_runs))
                from local_assist.custody import CustodyBootstrapState

                att_mod = _load_script_module("oc_att_r3", "scripts/opencode-attested")
                ep = att_mod.resolve_endpoint(load_model(model_id), pid_record=att_mod.read_pid_record_for_model(model_id, pointer_runs), require_api_key=False)
                verify_invocations: list[list[str]] = []

                def _spy_run(cmd: Any, *a: Any, **kw: Any) -> Any:
                    if isinstance(cmd, list) and any("verify-served-model" in str(x) for x in cmd):
                        verify_invocations.append([str(x) for x in cmd])
                        return subprocess.CompletedProcess(cmd, 0, stdout=repo, stderr="")
                    return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

                worker_boot = CustodyBootstrapState(
                    custody_mode=False,
                    worker_or_reap_cli=True,
                    launcher_site_packages=None,
                    cli_runs_dir=None,
                )
                with (
                    patch("local_assist.custody._ACTIVE_BOOTSTRAP_STATE", worker_boot),
                    patch("subprocess.run", side_effect=_spy_run),
                    redirect_stderr(io.StringIO()),
                ):
                    ok_ens, err_ens, _ = att_mod.ensure_model_served(ep, no_serve=True, inherit_attached_session_caps=True)
                self.assertTrue(ok_ens, err_ens)
                self.assertEqual(len(verify_invocations), 1)
                self.assertIn("--runs-dir", verify_invocations[0])
                v_idx = verify_invocations[0].index("--runs-dir")
                self.assertEqual(Path(verify_invocations[0][v_idx + 1]).resolve(), pointer_runs.resolve())

                # 5b. Stale record in default_runs (dead PID or mismatched pid_lstart) must NOT mask live pointer_runs!
                from local_assist.registry import _effective_runs_dir as _eff_runs_fn

                for stale_rec in (
                    {"model_id": model_id, "pid": 99999999, "pid_lstart": "Mon Jan  1 00:00:00 2001", "status": "ready"},
                    {"model_id": model_id, "pid": os.getpid(), "pid_lstart": "Mon Jan  1 00:00:00 2001", "status": "ready"},
                ):
                    pid_file_for_model(model_id, default_runs).write_text(json.dumps(stale_rec), encoding="utf-8")
                    with patch("local_assist.custody._ACTIVE_BOOTSTRAP_STATE", worker_boot):
                        self.assertEqual(_eff_runs_fn().resolve(), pointer_runs.resolve())
                pid_file_for_model(model_id, default_runs).unlink(missing_ok=True)

                # 6. Refresh in writable non-custody worker checkout keeps verify-served-model, stop-model, and serve-model
                #    all locked to pointer_runs (and passes --publish-active-runs)!
                refresh_cmds: list[list[str]] = []

                def _spy_refresh(cmd: Any, *a: Any, **kw: Any) -> Any:
                    c_list = [str(x) for x in cmd]
                    refresh_cmds.append(c_list)
                    if any("serve-model" in x for x in c_list):
                        _seed_store(pointer_runs, 18084)
                        return subprocess.CompletedProcess(cmd, 0, stdout="started", stderr="")
                    if any("verify-served-model" in x for x in c_list):
                        return subprocess.CompletedProcess(cmd, 0, stdout=repo, stderr="")
                    return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

                with (
                    patch("local_assist.custody._ACTIVE_BOOTSTRAP_STATE", worker_boot),
                    patch("subprocess.run", side_effect=_spy_refresh),
                    redirect_stderr(io.StringIO()),
                ):
                    ok_ref, err_ref, _ = att_mod.ensure_model_served(
                        ep,
                        no_serve=False,
                        refresh_session=True,
                        max_chat_requests=25,
                        max_tokens_cap=2048,
                        max_request_bytes=131072,
                        max_session_usd=100.0,
                    )
                self.assertTrue(ok_ref, err_ref)
                self.assertEqual(len(refresh_cmds), 4)
                for sub_c in refresh_cmds:
                    self.assertIn("--runs-dir", sub_c, f"Expected --runs-dir in child cmd: {sub_c}")
                    self.assertEqual(Path(sub_c[sub_c.index("--runs-dir") + 1]).resolve(), pointer_runs.resolve())
                self.assertIn("--publish-active-runs", refresh_cmds[2])

                # 7. Dead/empty or stale-record pointer_runs in active-runs.json falls back to default_runs on cold start
                #    and passes --runs-dir <default_runs> --publish-active-runs to serve-model!
                pid_file_for_model(model_id, pointer_runs).write_text(
                    json.dumps({"model_id": model_id, "pid": os.getpid(), "pid_lstart": "Mon Jan  1 00:00:00 2001", "status": "ready"}),
                    encoding="utf-8",
                )
                with patch("local_assist.custody._ACTIVE_BOOTSTRAP_STATE", worker_boot):
                    self.assertEqual(_eff_runs_fn().resolve(), default_runs.resolve())
                pid_file_for_model(model_id, pointer_runs).unlink(missing_ok=True)
                cold_worker_cmds: list[list[str]] = []

                def _spy_cold_worker(cmd: Any, *a: Any, **kw: Any) -> Any:
                    c_list = [str(x) for x in cmd]
                    cold_worker_cmds.append(c_list)
                    if len(cold_worker_cmds) == 1:
                        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="down")
                    if any("serve-model" in x for x in c_list):
                        _seed_store(default_runs, 18085)
                        return subprocess.CompletedProcess(cmd, 0, stdout="started", stderr="")
                    return subprocess.CompletedProcess(cmd, 0, stdout=repo, stderr="")

                with (
                    patch("local_assist.custody._ACTIVE_BOOTSTRAP_STATE", worker_boot),
                    patch("subprocess.run", side_effect=_spy_cold_worker),
                    redirect_stderr(io.StringIO()),
                ):
                    ok_cw, err_cw, _ = att_mod.ensure_model_served(
                        ep,
                        no_serve=False,
                        max_chat_requests=25,
                        max_tokens_cap=2048,
                        max_request_bytes=131072,
                        max_session_usd=100.0,
                    )
                self.assertTrue(ok_cw, err_cw)
                for sub_c in cold_worker_cmds:
                    self.assertIn("--runs-dir", sub_c)
                    self.assertEqual(Path(sub_c[sub_c.index("--runs-dir") + 1]).resolve(), default_runs.resolve())
                serve_cw = [c for c in cold_worker_cmds if any("serve-model" in x for x in c)][0]
                self.assertIn("--publish-active-runs", serve_cw)

                # 8. Real scripts/serve-model local Rung 1 model path (both fresh start and already-active)
                #    publishes active-runs.json iff --publish-active-runs (or implicit default), and preserves
                #    bystander pointer when --runs-dir <custom> is passed without --publish-active-runs!
                serve_mod = _load_script_module("serve_model_r3_local", "scripts/serve-model")
                local_model_id = "qwen3-30b-a3b-2507-mlx-4bit"
                my_ls = _format_bsdinfo_lstart(os.getpid()) if not CAN_RUN_PS else sess_mod.read_pid_record_for_model.__globals__["get_process_lstart"](os.getpid())

                class _FakeLocalPopen:
                    pid = os.getpid()

                    def poll(self) -> None:
                        return None

                    def wait(self, timeout: float | None = None) -> int:
                        return 0

                self.assertTrue(write_active_runs_pointer(stale_runs))
                with (
                    patch.object(serve_mod, "VENV_PYTHON", Path(sys.executable)),
                    patch.object(serve_mod, "_port_is_bound", return_value=False),
                    patch.object(serve_mod, "_require_process_lstart", return_value=my_ls),
                    patch.object(serve_mod.subprocess, "Popen", return_value=_FakeLocalPopen()),
                    redirect_stderr(io.StringIO()),
                ):
                    # 8a. Explicit --runs-dir <custom> WITHOUT --publish-active-runs -> starts into custom_runs, leaves stale_runs pointer untouched
                    rc_loc_nopub = serve_mod.main(
                        ["serve-model", "--runs-dir", str(custom_runs), "--port", "18095", local_model_id]
                    )
                    self.assertEqual(rc_loc_nopub, 0)
                    self.assertTrue(pid_file_for_model(local_model_id, custom_runs).is_file())
                    self.assertEqual(read_active_runs_pointer(), stale_runs.resolve())

                    # 8b. Fresh start into default_runs WITH --publish-active-runs -> replaces stale_runs pointer with default_runs!
                    rc_loc_fresh = serve_mod.main(
                        [
                            "serve-model",
                            "--runs-dir",
                            str(default_runs),
                            "--publish-active-runs",
                            "--port",
                            "18096",
                            local_model_id,
                        ]
                    )
                    self.assertEqual(rc_loc_fresh, 0)
                    self.assertEqual(read_active_runs_pointer(), default_runs.resolve())

                # 8c. Already-active local server in default_runs WITH --publish-active-runs -> refreshes stale_runs pointer to default_runs!
                self.assertTrue(write_active_runs_pointer(stale_runs))
                with (
                    patch.object(serve_mod, "pid_is_alive", return_value=True),
                    patch.object(serve_mod, "get_process_lstart", return_value=my_ls),
                    redirect_stderr(io.StringIO()),
                ):
                    rc_loc_active = serve_mod.main(
                        [
                            "serve-model",
                            "--runs-dir",
                            str(default_runs),
                            "--publish-active-runs",
                            "--port",
                            "18096",
                            local_model_id,
                        ]
                    )
                self.assertEqual(rc_loc_active, 0)
                self.assertEqual(read_active_runs_pointer(), default_runs.resolve())

                # 8d. Failure to update active-runs.json on the already-active path emits a clear WARNING on stderr!
                warn_buf = io.StringIO()
                with (
                    patch.object(serve_mod, "pid_is_alive", return_value=True),
                    patch.object(serve_mod, "get_process_lstart", return_value=my_ls),
                    patch.object(serve_mod, "write_active_runs_pointer", return_value=False),
                    redirect_stderr(warn_buf),
                ):
                    rc_loc_warn = serve_mod.main(
                        [
                            "serve-model",
                            "--runs-dir",
                            str(default_runs),
                            "--publish-active-runs",
                            "--port",
                            "18096",
                            local_model_id,
                        ]
                    )
                self.assertEqual(rc_loc_warn, 0)
                self.assertIn("WARNING: failed to update ~/.config/free-inference/active-runs.json", warn_buf.getvalue())

                # 8e. Both opencode-attested and opencode-local forward serve-model pointer WARNINGs on returncode == 0!
                loc_mod = _load_script_module("oc_loc_r3_warn", "scripts/opencode-local")
                ep_loc = loc_mod.resolve_endpoint(load_model(local_model_id), require_api_key=False)
                warn_msg = "WARNING: failed to update ~/.config/free-inference/active-runs.json for mock.\n"

                def _serve_warn_att(cmd: Any, *a: Any, **kw: Any) -> Any:
                    c_list = [str(x) for x in cmd]
                    if any("serve-model" in x for x in c_list):
                        _seed_store(default_runs, 18085)
                        return subprocess.CompletedProcess(cmd, 0, stdout="started", stderr=warn_msg)
                    if any("verify-served-model" in x for x in c_list):
                        if "--wait" in c_list:
                            return subprocess.CompletedProcess(cmd, 0, stdout=repo, stderr="")
                        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="down")
                    return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

                att_warn_err = io.StringIO()
                with redirect_stderr(att_warn_err):
                    ok_aw, err_aw, _ = att_mod.ensure_model_served(
                        ep,
                        no_serve=False,
                        runs_dir=default_runs,
                        publish_pointer=True,
                        max_chat_requests=25,
                        max_tokens_cap=2048,
                        max_request_bytes=131072,
                        max_session_usd=100.0,
                        run_cmd=_serve_warn_att,
                    )
                self.assertTrue(ok_aw, err_aw)
                self.assertIn("WARNING: failed to update ~/.config/free-inference/active-runs.json", att_warn_err.getvalue())

                def _serve_warn_loc(cmd: Any, *a: Any, **kw: Any) -> Any:
                    c_list = [str(x) for x in cmd]
                    if any("serve-model" in x for x in c_list):
                        return subprocess.CompletedProcess(cmd, 0, stdout="started", stderr=warn_msg)
                    if any("verify-served-model" in x for x in c_list):
                        if "--wait" in c_list:
                            return subprocess.CompletedProcess(cmd, 0, stdout=str(load_model(local_model_id)["repo"]), stderr="")
                        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="down")
                    return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

                loc_warn_err = io.StringIO()
                with redirect_stderr(loc_warn_err):
                    ok_lw, err_lw = loc_mod.ensure_model_served(
                        ep_loc,
                        no_serve=False,
                        runs_dir=default_runs,
                        publish_pointer=True,
                        run_cmd=_serve_warn_loc,
                    )
                self.assertTrue(ok_lw, err_lw)
                self.assertIn("WARNING: failed to update ~/.config/free-inference/active-runs.json", loc_warn_err.getvalue())

                # 9. Mid-flight concurrent session appearing in default_runs during refresh/start on pointer_runs
                #    must NOT flip post-start read_pid_record_for_model, _extract_attached_session_caps, or launcher
                #    endpoint/lease resolution away from the pinned pointer_runs store!
                for stale_pf in list(default_runs.glob(".serve*.pid")):
                    stale_pf.unlink(missing_ok=True)
                _seed_store(pointer_runs, 18084)
                self.assertTrue(write_active_runs_pointer(pointer_runs))

                def _spy_midflight_race(cmd: Any, *a: Any, **kw: Any) -> Any:
                    c_list = [str(x) for x in cmd]
                    if any("serve-model" in x for x in c_list):
                        _seed_store(pointer_runs, 18084)
                        # Simulate another operator session concurrently starting in default_runs on port 18099!
                        _seed_store(default_runs, 18099)
                        return subprocess.CompletedProcess(cmd, 0, stdout="started", stderr="")
                    if any("verify-served-model" in x for x in c_list):
                        return subprocess.CompletedProcess(cmd, 0, stdout=repo, stderr="")
                    return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

                from contextlib import redirect_stdout

                lease_seen_stores: list[Path] = []

                def _fake_lease_supplier(rec: dict[str, Any], rdir: Path) -> Any:
                    lease_seen_stores.append(Path(rdir).resolve())
                    return lambda: {"token": "se-session-" + ("d" * 64)}

                out_race = io.StringIO()
                err_race = io.StringIO()
                with (
                    patch.dict(os.environ, {"FREE_INFERENCE_OPENCODE_ATTESTED_HOME": str(short_root / "att_home")}, clear=False),
                    patch("local_assist.custody._ACTIVE_BOOTSTRAP_STATE", worker_boot),
                    patch("subprocess.run", side_effect=_spy_midflight_race),
                    patch("local_assist.session.SessionLeaseSupplier", side_effect=_fake_lease_supplier),
                    patch.object(att_mod, "resolve_opencode_binary", return_value=("/usr/bin/true", None)),
                    redirect_stdout(out_race),
                    redirect_stderr(err_race),
                ):
                    rc_race = att_mod._main_inner_attested(
                        att_mod.parse_args(
                            [
                                "scripts/opencode-attested",
                                "--model",
                                model_id,
                                "--refresh-session",
                                "--max-chat-requests",
                                "25",
                                "--max-tokens-cap",
                                "2048",
                                "--max-request-bytes",
                                "131072",
                                "--max-session-usd",
                                "100",
                                "--print-config",
                            ]
                        )[0],
                        [],
                        short_root,
                        None,
                    )
                self.assertEqual(rc_race, 0, err_race.getvalue())
                race_cfg = json.loads(out_race.getvalue())
                self.assertEqual(
                    race_cfg["api_base_url"],
                    "http://127.0.0.1:18084/v1",
                    "Post-verification launcher setup must stay pinned to pointer_runs (18084), not flip to concurrent default_runs (18099)!",
                )
                self.assertEqual(lease_seen_stores, [pointer_runs.resolve()])
        finally:
            shutil.rmtree(short_root, ignore_errors=True)

    def test_r4_standalone_metadata_and_mcp_ancestor_relocation_denied(self) -> None:
        from local_assist.security_profile import (
            allocate_worker_home,
            cleanup_worker_home,
            compile_seatbelt_profile,
            parse_security_profile_dict,
        )

        short_root = Path(tempfile.mkdtemp(prefix="fi-r4-", dir=SHORT_TMP_DIR))
        wid, iso = allocate_worker_home(worker_homes_dir=short_root / "workers")
        try:
            ws_dir = short_root / "ws"
            ws_dir.mkdir(mode=0o700)
            meta_dir = ws_dir / "nested" / "meta"
            meta_dir.mkdir(parents=True, mode=0o700)
            manifest_p = meta_dir / "manifest.json"
            manifest_p.write_text("{}\n", encoding="utf-8")
            exit_p = meta_dir / "launcher_exit.json"
            prof_p = meta_dir / "profile.yaml"
            prof_p.write_text("schema_version: 1\nmode: unattended_worker\n", encoding="utf-8")

            mcp_dir = ws_dir / "tools" / "mcp_bin"
            mcp_dir.mkdir(parents=True, mode=0o700)
            mcp_exec = mcp_dir / "run_mcp"
            mcp_exec.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(mcp_exec, 0o500)

            prof = parse_security_profile_dict(
                {
                    "schema_version": 1,
                    "mode": "unattended_worker",
                    "mcp": {
                        "servers": {"custom_local": {"type": "local", "command": [str(mcp_exec)]}},
                        "allowed_servers": ["custom_local"],
                    },
                }
            )
            fake_sb = short_root / "sandbox-exec"
            fake_sb.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(fake_sb, 0o755)
            sb_text = compile_seatbelt_profile(
                prof,
                workspace_dir=ws_dir,
                isolated_home=iso,
                opencode_bin=Path("/usr/bin/true"),
                sandbox_exec_bin=Path("/usr/bin/sandbox-exec") if Path("/usr/bin/sandbox-exec").is_file() else fake_sb,
                worker_tag="a" * 32,
                worker_manifest_path=manifest_p,
                launcher_exit_path=exit_p,
                security_profile_path=prof_p,
            )

            # Verify intermediate ancestor directories inside write_root are emitted under final (deny file-write*)
            final_write_deny = sb_text.split("(deny file-write*")[-1]
            for anc in (meta_dir.resolve(), meta_dir.parent.resolve(), mcp_dir.resolve(), mcp_dir.parent.resolve()):
                self.assertIn(f'(literal "{anc}")', final_write_deny)

            if CAN_RUN_SANDBOX_EXEC:
                sb_file = short_root / "r4.sb"
                sb_file.write_text(sb_text, encoding="utf-8")
                probe = textwrap.dedent(
                    f"""
                    import errno, json, os
                    out = {{}}
                    for key, src, dst in [
                        ("rename_meta", {str(meta_dir)!r}, {str(ws_dir / "nested" / "meta_bak")!r}),
                        ("rename_nested", {str(meta_dir.parent)!r}, {str(ws_dir / "nested_bak")!r}),
                        ("rename_mcp_dir", {str(mcp_dir)!r}, {str(ws_dir / "tools" / "mcp_bak")!r}),
                    ]:
                        try:
                            os.rename(src, dst)
                            out[key] = "ALLOWED"
                        except OSError as exc:
                            out[key] = exc.errno in (errno.EPERM, errno.EACCES)
                    # Sibling file inside meta_dir remains creatable while meta_dir itself cannot be renamed!
                    sib = {str(meta_dir / "sibling.txt")!r}
                    with open(sib, "w") as fh:
                        fh.write("ok")
                    out["sibling_ok"] = open(sib).read() == "ok"
                    print(json.dumps(out))
                    """
                )
                cp = subprocess.run(
                    ["/usr/bin/sandbox-exec", "-f", str(sb_file), sys.executable, "-I", "-B", "-c", probe],
                    cwd=str(ws_dir),
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=True,
                )
                res = json.loads(cp.stdout.strip())
                self.assertIs(res["rename_meta"], True)
                self.assertIs(res["rename_nested"], True)
                self.assertIs(res["rename_mcp_dir"], True)
                self.assertIs(res["sibling_ok"], True)
        finally:
            cleanup_worker_home(iso, worker_id=wid, harvest_logs=False)
            shutil.rmtree(short_root, ignore_errors=True)

    def test_r5_external_worker_homes_validated_before_stale_sweep(self) -> None:
        from local_assist.custody import CustodyBootstrapState
        from local_assist.security_profile import sweep_stale_worker_homes_detailed

        _install_outer_sandbox_ps_fixture_if_blocked(self)
        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            tmp_path = Path(tmp).resolve()
            victim = tmp_path / "victim"
            victim_worker = victim / "worker-999999991-1000-deadbeef"
            victim_worker.mkdir(parents=True, mode=0o700)
            (victim_worker / ".worker-owner.json").write_text(
                json.dumps({"worker_id": victim_worker.name, "owner_pid": 999999991, "created_at": 1.0}),
                encoding="utf-8",
            )

            # Subcase 1: symlinked workers leaf
            home_sym = tmp_path / "home_sym"
            fi_dir = home_sym / ".local" / "state" / "free-inference"
            fi_dir.mkdir(parents=True, mode=0o700)
            os.chmod(home_sym, 0o700)
            os.chmod(home_sym / ".local", 0o700)
            os.chmod(home_sym / ".local" / "state", 0o700)
            os.chmod(fi_dir, 0o700)
            (fi_dir / "workers").symlink_to(victim)

            # Subcase 2: 0777 world-writable workers dir
            home_perm = tmp_path / "home_perm"
            perm_workers = home_perm / ".local" / "state" / "free-inference" / "workers"
            perm_workers.mkdir(parents=True, mode=0o700)
            perm_child = perm_workers / "worker-999999991-1000-cafebabe"
            perm_child.mkdir(mode=0o700)
            (perm_child / ".worker-owner.json").write_text(
                json.dumps({"worker_id": perm_child.name, "owner_pid": 999999991, "created_at": 1.0}),
                encoding="utf-8",
            )
            os.chmod(home_perm, 0o700)
            os.chmod(home_perm / ".local", 0o700)
            os.chmod(home_perm / ".local" / "state", 0o700)
            os.chmod(home_perm / ".local" / "state" / "free-inference", 0o700)
            os.chmod(perm_workers, 0o777)

            cust_state = CustodyBootstrapState(
                custody_mode=True,
                worker_or_reap_cli=True,
                launcher_site_packages=None,
                cli_runs_dir=None,
            )
            for hdir in (home_sym, home_perm):
                FakePW = type("pw", (), {"pw_dir": str(hdir)})
                with (
                    patch("local_assist.custody._ACTIVE_BOOTSTRAP_STATE", cust_state),
                    patch("local_assist.custody.pwd.getpwuid", return_value=FakePW()),
                ):
                    res = sweep_stale_worker_homes_detailed(max_age_seconds=0)
                    self.assertEqual(res["removed"], [])
            self.assertTrue(victim_worker.is_dir(), "Symlinked external root must never sweep victim worker-* dir")
            self.assertTrue(perm_child.is_dir(), "0777 external root must never be swept")
            os.chmod(perm_workers, 0o700)

    def test_r6_duplicate_slashes_and_case_variants_cannot_bypass_mdnsresponder_refusal(self) -> None:
        from local_assist.security_profile import SecurityProfileError, parse_security_profile_dict

        for bad_sock in (
            "/var//run/mDNSResponder",
            "/private//var/run/mDNSResponder",
            "/VAR/run/mDNSResponder",
            "/private/var/run/mdnsresponder",
            "/tmp//double_slash.sock",
        ):
            with self.subTest(sock=bad_sock), self.assertRaises(SecurityProfileError):
                parse_security_profile_dict(
                    {
                        "schema_version": 1,
                        "mode": "unattended_worker",
                        "network": {"allowed_unix_sockets": [bad_sock]},
                    }
                )

    def test_r7_verified_gone_stopped_process_during_tag_recheck_is_exited_not_error(self) -> None:
        from local_assist import proc_identity

        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            mp = Path(tmp) / "m.json"
            mp.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "run_token": "r7-tok",
                        "launcher_pid": os.getpid(),
                        "launcher_pgid": os.getpid(),
                        "launcher_start_tvsec": 1,
                        "launcher_start_tvusec": 2,
                        "worker_id": "w-r7",
                        "isolated_home": "/tmp/w-r7",
                        "worker_tag": "b" * 32,
                        "children": [],
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(mp, 0o600)
            uid = os.geteuid()
            st = {"stopped": False, "vanished_in_recheck": False}
            signals: list[tuple[int, int]] = []

            def _bsd(pid: int) -> tuple[str, dict[str, Any] | None]:
                if pid != 6090 or st["vanished_in_recheck"]:
                    return ("absent", None)
                return (
                    "alive",
                    {
                        "uid": uid,
                        "pgid": 6090,
                        "status": proc_identity.SSTOP if st["stopped"] else proc_identity.SRUN,
                        "start_tvsec": 800,
                        "start_tvusec": 900,
                    },
                )

            def _match(pid: int, _tag: str) -> tuple[bool, bool]:
                if pid == 6090 and st["stopped"]:
                    # Stopped process disappears mid-query -> pid_matches_worker_tag returns (False, True)
                    st["vanished_in_recheck"] = True
                    return (False, True)
                return (pid == 6090 and not st["vanished_in_recheck"], True)

            def _sig(pid: int, sig: int) -> None:
                signals.append((pid, sig))
                if sig == signal.SIGSTOP:
                    st["stopped"] = True

            with (
                patch.object(proc_identity, "list_all_pids", side_effect=lambda: ([6090] if not st["vanished_in_recheck"] else [], True)),
                patch.object(proc_identity, "read_proc_bsdinfo", side_effect=_bsd),
                patch.object(proc_identity, "pid_matches_worker_tag", side_effect=_match),
                patch.object(proc_identity, "_send_signal", side_effect=_sig),
            ):
                rc = proc_identity.reap_worker_from_manifest(mp, stop_timeout_sec=0.05)

            self.assertEqual(rc, 0, "Verified disappearance during post-SSTOP tag recheck must succeed as exited")
            self.assertEqual(signals, [(6090, signal.SIGSTOP)])

            # Contrast: live tag loss on unchanged alive start time MUST still fail closed with exit 1!
            st_loss = {"stopped": False, "calls": 0}
            with (
                redirect_stderr(io.StringIO()),
                patch.object(proc_identity, "list_all_pids", return_value=([6091], True)),
                patch.object(
                    proc_identity,
                    "read_proc_bsdinfo",
                    side_effect=lambda p: (
                        "alive",
                        {"uid": uid, "pgid": 6091, "status": proc_identity.SSTOP if st_loss["stopped"] else proc_identity.SRUN, "start_tvsec": 10, "start_tvusec": 20},
                    ),
                ),
                patch.object(
                    proc_identity,
                    "pid_matches_worker_tag",
                    side_effect=lambda _p, _t: (not st_loss["stopped"], True),
                ),
                patch.object(
                    proc_identity,
                    "_send_signal",
                    side_effect=lambda _p, s: st_loss.__setitem__("stopped", True) if s == signal.SIGSTOP else None,
                ),
            ):
                self.assertEqual(proc_identity.reap_worker_from_manifest(mp, stop_timeout_sec=0.05), 1)

    def test_r8_prespawn_ingroup_refusal_closes_relay_and_removes_isolated_home(self) -> None:
        from local_assist.launch import execute_worker_profile_session
        from local_assist.security_profile import allocate_worker_home, parse_security_profile_dict

        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            tmp_path = Path(tmp).resolve()
            ws_dir = tmp_path / "ws"
            ws_dir.mkdir(mode=0o700)
            workers_dir = tmp_path / "workers"
            workers_dir.mkdir(mode=0o700)
            prof = parse_security_profile_dict({"schema_version": 1, "mode": "unattended_worker"})
            allocated_homes: list[Path] = []
            relay_state = {"started": False, "closed": False}

            class _TrackedRelay:
                api_base_url = "http://127.0.0.1:45199/v1"
                relay_token = "worker-relay-" + ("e" * 64)
                port = 45199
                _extra_canary_secrets: tuple[str, ...] = ()

                def start(self) -> "_TrackedRelay":
                    relay_state["started"] = True
                    return self

                def close(self) -> None:
                    relay_state["closed"] = True

            def _alloc() -> tuple[str, Path]:
                wid, iso = allocate_worker_home(worker_homes_dir=workers_dir)
                allocated_homes.append(iso)
                return wid, iso

            import argparse
            import contextlib

            _install_outer_sandbox_ps_fixture_if_blocked(self)
            port_ctx = (
                contextlib.nullcontext()
                if CAN_BIND_LOOPBACK_TCP
                else patch("local_assist.launch._allocate_loopback_ephemeral_port", return_value=43299)
            )

            ns = argparse.Namespace(
                keep_worker_home=False,
                print_config=False,
                inherit_process_group=True,
                worker_manifest=str(tmp_path / "manifest.json"),
                run_token="r8-tok",
            )
            # Force pre-spawn PGID mismatch (launcher_pgid != launcher_pid)
            with (
                port_ctx,
                patch("local_assist.launch.os.getpgrp", return_value=os.getpid() + 1),
                redirect_stderr(io.StringIO()),
            ):
                rc = execute_worker_profile_session(
                    active_profile=prof,
                    args=ns,
                    caller_cwd=ws_dir,
                    opencode_bin="/usr/bin/true",
                    sandbox_exec_bin=Path("/usr/bin/true"),
                    validated_worker_args=["run", "hi"],
                    build_base_config_fn=lambda _r: {"provider": {}},
                    build_print_config_payload_fn=lambda *a: {},
                    relay_factory=_TrackedRelay,
                    allocate_worker_home_fn=_alloc,
                )

            self.assertEqual(rc, 1)
            self.assertTrue(relay_state["started"])
            self.assertTrue(relay_state["closed"], "Expected started relay to be closed on pre-spawn refusal")
            self.assertEqual(len(allocated_homes), 1)
            self.assertFalse(allocated_homes[0].exists(), "Expected allocated worker home to be removed on pre-spawn refusal")

            # Also verify port allocation failure immediately after prepared_identity ownership transfer cleans up isolated_home!
            from local_assist.launch import PreparedWorkerIdentity

            wid_prep, iso_prep = allocate_worker_home(worker_homes_dir=workers_dir)
            prep_id = PreparedWorkerIdentity(
                worker_id=wid_prep,
                isolated_home=iso_prep,
                worker_tag="f" * 32,
                manifest_path=tmp_path / "manifest_prep.json",
                run_token="r8-prep-tok",
                retain_home=False,
                launcher_pid=os.getpid(),
                launcher_pgid=os.getpid(),
                launcher_start_tvsec=1700000000,
                launcher_start_tvusec=0,
                launcher_lstart="",
            )
            owned_flag = {"v": False}
            with (
                patch("local_assist.launch._allocate_loopback_ephemeral_port", side_effect=OSError("bind failed")),
                redirect_stderr(io.StringIO()),
            ):
                rc_port_err = execute_worker_profile_session(
                    active_profile=prof,
                    args=ns,
                    caller_cwd=ws_dir,
                    opencode_bin="/usr/bin/true",
                    sandbox_exec_bin=Path("/usr/bin/true"),
                    validated_worker_args=["run", "hi"],
                    build_base_config_fn=lambda _r: {"provider": {}},
                    build_print_config_payload_fn=lambda *a: {},
                    prepared_identity=prep_id,
                    ownership_callback=lambda: owned_flag.__setitem__("v", True),
                )
            self.assertEqual(rc_port_err, 1)
            self.assertTrue(owned_flag["v"])
            self.assertFalse(iso_prep.exists(), "Expected prepared isolated_home to be cleaned up when port allocation fails after ownership transfer")

    @unittest.skipUnless(sys.platform == "darwin", "kinfo_proc calibration test requires Darwin")
    def test_q3_sysctl_kinfo_proc_structural_invariants_and_self_calibration(self) -> None:
        import ctypes
        from local_assist import proc_identity

        # 1. Self-calibration succeeded on Darwin
        self.assertTrue(proc_identity._SYSCTL_KINFO_CALIBRATED)
        self.assertTrue(proc_identity._calibrate_darwin_sysctl_kinfo_proc())

        # 2. Self-query proc_pidinfo failure -> calibration returns False
        with patch.object(proc_identity, "_raw_proc_pidinfo", return_value=(0, errno.EPERM, proc_identity.ProcBsdInfo())):
            self.assertFalse(proc_identity._calibrate_darwin_sysctl_kinfo_proc())

        # 3. Each mismatched field between proc_pidinfo and sysctl -> calibration returns False
        st_real, k_real = proc_identity._read_sysctl_kinfo_proc_64_unchecked(os.getpid())
        self.assertEqual(st_real, "alive")
        assert k_real is not None
        for field_name, bad_val in (
            ("pid", os.getpid() + 1),
            ("uid", k_real["uid"] + 1),
            ("pgid", k_real["pgid"] + 1),
            ("start_tvsec", k_real["start_tvsec"] + 1),
            ("start_tvusec", (k_real["start_tvusec"] + 1) % 1_000_000),
        ):
            tampered = {**k_real, field_name: bad_val}
            with (
                self.subTest(field=field_name),
                patch.object(proc_identity, "_read_sysctl_kinfo_proc_64_unchecked", return_value=("alive", tampered)),
            ):
                self.assertFalse(proc_identity._calibrate_darwin_sysctl_kinfo_proc())

        # 4. Guarded _sysctl_kinfo_proc_64 fails closed when _SYSCTL_KINFO_CALIBRATED is False
        with patch.object(proc_identity, "_SYSCTL_KINFO_CALIBRATED", False):
            self.assertEqual(proc_identity._sysctl_kinfo_proc_64(os.getpid()), ("error", None))

        # 5. Structural corruption in raw 648-byte buffer (wrong pid, invalid p_stat, negative tv_sec, out-of-range tv_usec) -> ("error", None)
        def _run_with_mutated_buf(mutator: Any) -> tuple[str, dict[str, Any] | None]:
            orig_sysctl = proc_identity._DARWIN_LIB.sysctl

            def _fake_sysctl(mib: Any, miblen: Any, buf: Any, sz_ptr: Any, newp: Any, newlen: Any) -> int:
                rc = orig_sysctl(mib, miblen, buf, sz_ptr, newp, newlen)
                if rc == 0:
                    raw_ba = bytearray(buf.raw)
                    mutator(raw_ba)
                    ctypes.memmove(buf, bytes(raw_ba), len(raw_ba))
                return rc

            with patch.object(proc_identity._DARWIN_LIB, "sysctl", side_effect=_fake_sysctl):
                return proc_identity._read_sysctl_kinfo_proc_64_unchecked(os.getpid())

        self.assertEqual(
            _run_with_mutated_buf(lambda ba: struct.pack_into("<i", ba, 40, os.getpid() + 7)),
            ("error", None),
        )
        self.assertEqual(
            _run_with_mutated_buf(lambda ba: ba.__setitem__(36, 99)),
            ("error", None),
        )
        self.assertEqual(
            _run_with_mutated_buf(lambda ba: struct.pack_into("<qi", ba, 0, 0, 0)),
            ("error", None),
        )
        self.assertEqual(
            _run_with_mutated_buf(lambda ba: struct.pack_into("<qi", ba, 0, 1700000000, 1_500_000)),
            ("error", None),
        )

    @unittest.skipUnless(CAN_RUN_SANDBOX_EXEC, "Requires outer environment permitting /usr/bin/sandbox-exec")
    def test_seatbelt_af_unix_coexists_with_local_assist_python_loopback_tcp(self) -> None:
        from local_assist.security_profile import (
            allocate_worker_home,
            build_worker_environment,
            cleanup_worker_home,
            compile_seatbelt_profile,
            parse_security_profile_dict,
            write_worker_runtime_artifacts,
        )

        short_root = Path(tempfile.mkdtemp(prefix="fi-af-", dir=SHORT_TMP_DIR))
        wid, iso = allocate_worker_home(worker_homes_dir=short_root / "workers")
        try:
            ws_dir = short_root / "ws"
            ws_dir.mkdir(mode=0o700)
            bridge_dir = short_root / "b"
            bridge_dir.mkdir(mode=0o700)
            sock_path = bridge_dir / "ledger.sock"

            unix_srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.addCleanup(unix_srv.close)
            unix_srv.bind(str(sock_path))
            os.chmod(sock_path, 0o600)
            unix_srv.listen(4)

            def _accept_unix() -> None:
                for _ in range(2):
                    try:
                        c, _ = unix_srv.accept()
                        with c:
                            data = c.recv(64)
                            c.sendall(b"ACK:" + data)
                    except OSError:
                        break

            threading.Thread(target=_accept_unix, daemon=True).start()

            tcp_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.addCleanup(tcp_srv.close)
            tcp_srv.bind(("127.0.0.1", 0))
            tcp_srv.listen(4)
            la_port = int(tcp_srv.getsockname()[1])

            def _accept_tcp() -> None:
                try:
                    c, _ = tcp_srv.accept()
                    with c:
                        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                except OSError:
                    pass

            threading.Thread(target=_accept_tcp, daemon=True).start()

            fake_oc = short_root / "fake-oc"
            fake_c = short_root / "fake_oc.c"
            fake_c.write_text(
                "#include <string.h>\n#include <unistd.h>\n#include <wordexp.h>\n"
                "int main(int argc, char **argv) {\n"
                "  if (argc >= 3 && strcmp(argv[1], \"-c\") == 0) {\n"
                "    const char *cmd = argv[2];\n"
                "    if (strncmp(cmd, \"exec \", 5) == 0) cmd += 5;\n"
                "    wordexp_t we;\n"
                "    if (wordexp(cmd, &we, WRDE_NOCMD) == 0 && we.we_wordc > 0) execv(we.we_wordv[0], we.we_wordv);\n"
                "  }\n  return 127;\n}\n",
                encoding="utf-8",
            )
            subprocess.run(["/usr/bin/cc", "-O2", str(fake_c), "-o", str(fake_oc)], check=True)
            os.chmod(fake_oc, 0o755)

            prof = parse_security_profile_dict(
                {
                    "schema_version": 1,
                    "mode": "unattended_worker",
                    "mcp": {"enable_local_assist": True, "servers": {}},
                    "network": {"allowed_unix_sockets": [str(sock_path)]},
                }
            )
            sb_text = compile_seatbelt_profile(
                prof,
                workspace_dir=ws_dir,
                isolated_home=iso,
                opencode_bin=fake_oc,
                local_assist_port=la_port,
            )
            _, sb_path, worker_shell = write_worker_runtime_artifacts(
                isolated_home=iso,
                worker_id=wid,
                profile=prof,
                opencode_config={},
                seatbelt_text=sb_text,
            )
            la_py = iso / "bin" / "local-assist-python"
            env = build_worker_environment(prof, isolated_home=iso, worker_id=wid, host_env=os.environ)

            # 1. General worker-shell Python CAN connect to allowed AF_UNIX socket, CANNOT connect TCP to la_port
            shell_probe = iso / ".tmp" / "shell_probe.py"
            shell_probe.write_text(
                "import errno, json, socket\n"
                "out = {}\n"
                f"with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as u:\n"
                f"    u.connect({str(sock_path)!r}); u.sendall(b'SH'); out['unix'] = u.recv(32).decode()\n"
                "try:\n"
                f"    with socket.create_connection(('127.0.0.1', {la_port}), timeout=1.0): out['tcp_blocked'] = False\n"
                "except OSError as exc:\n"
                "    out['tcp_blocked'] = exc.errno in (errno.EPERM, errno.EACCES)\n"
                "print(json.dumps(out))\n",
                encoding="utf-8",
            )
            cp_sh = subprocess.run(
                ["/usr/bin/sandbox-exec", "-f", str(sb_path), str(worker_shell), "-c", f"{sys.executable} -I -B {shell_probe}"],
                cwd=str(ws_dir),
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            sh_res = json.loads(cp_sh.stdout.strip())
            self.assertEqual(sh_res["unix"], "ACK:SH")
            self.assertTrue(sh_res["tcp_blocked"])

            # 2. Dedicated local-assist-python CAN connect TCP to la_port AND remains blocked on denied port 9081
            la_probe = iso / ".tmp" / "la_probe.py"
            la_probe.write_text(
                "import errno, json, socket\n"
                "out = {}\n"
                f"with socket.create_connection(('127.0.0.1', {la_port}), timeout=2.0) as s:\n"
                "    out['la_tcp'] = s.recv(64).decode('utf-8', 'replace').splitlines()[0]\n"
                "try:\n"
                "    with socket.create_connection(('127.0.0.1', 9081), timeout=1.0): out['denied_9081'] = False\n"
                "except OSError as exc:\n"
                "    out['denied_9081'] = exc.errno in (errno.EPERM, errno.EACCES)\n"
                "print(json.dumps(out))\n",
                encoding="utf-8",
            )
            cp_la = subprocess.run(
                ["/usr/bin/sandbox-exec", "-f", str(sb_path), str(fake_oc), "-c", f"exec {la_py} -I -B {la_probe}"],
                cwd=str(ws_dir),
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            la_res = json.loads(cp_la.stdout.strip())
            self.assertEqual(la_res["la_tcp"], "HTTP/1.1 200 OK")
            self.assertTrue(la_res["denied_9081"])
        finally:
            cleanup_worker_home(iso, worker_id=wid, harvest_logs=False)
            shutil.rmtree(short_root, ignore_errors=True)


class LookoutRound3RegressionTests(unittest.TestCase):
    """Regression suite for Lookout Round 2 findings R2-1 through R2-4 and Round 3 R3-1/R3-2."""

    def _build_isolated_clone_fixture(self, short_root: Path) -> tuple[Path, Path]:
        """Create a self-contained lab_clone with no .venv or runs/, isolating passwd-home lookups to fake_home."""
        short_root = short_root.resolve()
        fake_home = short_root / "home"
        fake_home.mkdir(mode=0o700, exist_ok=True)
        clone_root = short_root / "lab_clone"
        clone_root.mkdir(mode=0o700)
        shutil.copytree(
            ROOT / "local_assist",
            clone_root / "local_assist",
            symlinks=False,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )
        (clone_root / "scripts").mkdir(mode=0o700)
        for sc_name in ("opencode-attested", "opencode-local", "serve-model", "stop-model", "verify-served-model", "session"):
            shutil.copy2(ROOT / "scripts" / sc_name, clone_root / "scripts" / sc_name)
            os.chmod(clone_root / "scripts" / sc_name, 0o700)
        shutil.copytree(ROOT / "config", clone_root / "config", symlinks=False)
        for doc_sub in ("evals", "attestations"):
            if (ROOT / "docs" / doc_sub).is_dir():
                shutil.copytree(ROOT / "docs" / doc_sub, clone_root / "docs" / doc_sub, symlinks=False)

        self.assertFalse((clone_root / ".venv").exists(), "clone_root must have no .venv so _USE_VENV is False")
        self.assertFalse((clone_root / "runs").exists(), "clone_root must start without runs/")

        target_expr = "pwd.getpwuid(os.geteuid()).pw_dir"
        for rel_patch in ("local_assist/custody.py", "scripts/opencode-attested"):
            patch_file = clone_root / rel_patch
            src_txt = patch_file.read_text(encoding="utf-8")
            self.assertEqual(src_txt.count(target_expr), 1, f"Expected single {target_expr} in {rel_patch}")
            patch_file.write_text(src_txt.replace(target_expr, repr(str(fake_home)), 1), encoding="utf-8")
        os.chmod(clone_root / "scripts" / "opencode-attested", 0o700)

        # Verify in an isolated -I -B child subprocess before running any CLI that passwd home resolves to fake_home.
        cp_iso = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                (
                    f"import sys; from pathlib import Path; sys.path.insert(0, {str(clone_root)!r}); "
                    "import local_assist.custody as c; "
                    f"assert Path(c.__file__).resolve() == Path({str(clone_root / 'local_assist' / 'custody.py')!r}).resolve(); "
                    f"assert c._resolve_passwd_home_dir() == Path({str(fake_home)!r}), c._resolve_passwd_home_dir()"
                ),
            ],
            cwd=str(clone_root),
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(fake_home), "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(cp_iso.returncode, 0, f"Fixture passwd-home isolation preflight failed: {cp_iso.stderr}")
        return clone_root, fake_home

    def test_r2_1_cold_start_absent_stores_lexical_validation_and_descriptor_swap_protection(self) -> None:
        from local_assist import custody
        from local_assist.registry import get_process_lstart, pid_file_for_model

        short_root = Path(tempfile.mkdtemp(prefix="fi-r21-", dir=SHORT_TMP_DIR)).resolve()
        try:
            clone_root, fake_home = self._build_isolated_clone_fixture(short_root)
            mock_model_id = "qwen3-30b-a3b-2507-mlx-4bit"
            mock_port = 18099

            # Configure clone_root/models.yaml with a harmless fake local server command
            fake_daemon_py = short_root / "fake_daemon.py"
            fake_daemon_py.write_text(
                "import signal, sys, time\nsignal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\ntime.sleep(30)\n",
                encoding="utf-8",
            )
            models_text = (ROOT / "models.yaml").read_text(encoding="utf-8")
            old_block = (
                "  - id: qwen3-30b-a3b-2507-mlx-4bit\n"
                "    status: runnable\n"
                "    repo: mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit\n"
                "    upstream: Qwen/Qwen3-30B-A3B-Instruct-2507\n"
                "    converter: mlx-community\n"
                "    conversion_runtime_version: mlx-lm 0.26.3\n"
                "    runtime: mlx-lm\n"
                "    serve_command: null\n"
            )
            new_block = (
                "  - id: qwen3-30b-a3b-2507-mlx-4bit\n"
                "    status: runnable\n"
                "    repo: mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit\n"
                "    upstream: Qwen/Qwen3-30B-A3B-Instruct-2507\n"
                "    converter: mlx-community\n"
                "    conversion_runtime_version: mlx-lm 0.26.3\n"
                "    runtime: llama.cpp\n"
                f"    serve_command: \"{sys.executable} -I -B {fake_daemon_py} --host {{host}} --port {{port}} --model {{repo}}\"\n"
            )
            self.assertIn(old_block, models_text)
            (clone_root / "models.yaml").write_text(
                models_text.replace(old_block, new_block, 1).replace(
                    "http://127.0.0.1:8080/v1", f"http://127.0.0.1:{mock_port}/v1"
                ),
                encoding="utf-8",
            )

            stub_bin = short_root / "stub_bin"
            stub_bin.mkdir(mode=0o700)
            stub_oc = stub_bin / "opencode"
            stub_oc.write_text("#!/bin/sh\necho 2.3.2\n", encoding="utf-8")
            os.chmod(stub_oc, 0o700)
            stub_sb = stub_bin / "sandbox-exec"
            stub_sb.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(stub_sb, 0o700)
            base_env = {
                "PATH": f"{stub_bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
                "HOME": str(fake_home),
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            if not Path("/usr/bin/sandbox-exec").is_file():
                base_env["FREE_INFERENCE_SANDBOX_EXEC_BIN"] = str(stub_sb)
            default_runs = clone_root / "runs"
            self.assertFalse(default_runs.exists())

            # 1. Read-only / --no-serve probes against ABSENT default clone_root/runs:
            #    - `session status` exits 0 ("OFF") and does NOT create clone_root/runs
            cp_stat = subprocess.run(
                [sys.executable, "-I", "-B", str(clone_root / "scripts" / "session"), "status", "--model", "tinfoil-deepseek-v4-1-flash"],
                cwd=str(clone_root),
                env=base_env,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(cp_stat.returncode, 0, cp_stat.stderr)
            self.assertIn("OFF", cp_stat.stdout)
            self.assertFalse(default_runs.exists(), "session status must not create absent runs/")

            #    - `opencode-local --no-serve` reports unreachable (NOT invalid --runs-dir!) and does NOT create clone_root/runs
            cp_noserve = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(clone_root / "scripts" / "opencode-local"),
                    "--no-serve",
                    "--port",
                    "18098",
                    "--",
                    "run",
                    "hi",
                ],
                cwd=str(clone_root),
                env=base_env,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertNotEqual(cp_noserve.returncode, 0)
            self.assertIn("--no-serve was set", cp_noserve.stderr)
            self.assertNotIn("Invalid --runs-dir", cp_noserve.stderr)
            self.assertNotIn("must be an existing, non-symlink directory", cp_noserve.stderr)
            self.assertFalse(default_runs.exists(), "--no-serve must not create absent runs/")

            # 2. Explicit external `--runs-dir <absent>` MUST STILL fail closed across CLIs!
            absent_explicit = short_root / "explicit_absent"
            for sc_rel, extra_args in (
                ("serve-model", [mock_model_id]),
                ("verify-served-model", [mock_model_id]),
                ("session", ["status"]),
                ("opencode-local", ["--print-config", "--no-serve"]),
                ("opencode-attested", ["--print-config", "--no-serve", "--model", "tinfoil-deepseek-v4-1-flash"]),
            ):
                cp_exp = subprocess.run(
                    [sys.executable, "-I", "-B", str(clone_root / "scripts" / sc_rel), "--runs-dir", str(absent_explicit), *extra_args],
                    cwd=str(clone_root),
                    env=base_env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(cp_exp.returncode, 1, f"{sc_rel} must reject explicit absent --runs-dir: {cp_exp.stderr}")
                self.assertFalse(absent_explicit.exists())

            # 3. Lexical & ancestor validation of FREE_INFERENCE_RUNS_DIR BEFORE resolve():
            #    relative path, dot segment, symlink ancestor, symlink leaf, regular file, and unsticky 0777 ancestor MUST all fail closed!
            real_target = short_root / "real_t"
            real_target.mkdir(mode=0o700)
            sym_anc = short_root / "sym_anc"
            sym_anc.symlink_to(real_target)
            sym_leaf = short_root / "sym_leaf"
            sym_leaf.symlink_to(real_target)
            reg_file = short_root / "reg_file"
            reg_file.write_text("x\n", encoding="utf-8")
            unsticky_777 = short_root / "unsticky_777"
            unsticky_777.mkdir(mode=0o700)
            os.chmod(unsticky_777, 0o777)

            for bad_label, bad_env_val in (
                ("relative", "relative/runs_store"),
                ("dot_seg", f"{short_root}/./runs_store"),
                ("dotdot_seg", f"{short_root}/a/../runs_store"),
                ("symlink_ancestor", f"{sym_anc}/fresh_runs"),
                ("symlink_leaf", str(sym_leaf)),
                ("regular_file", str(reg_file)),
                ("unsticky_777_ancestor", f"{unsticky_777}/fresh_runs"),
            ):
                bad_env = {**base_env, "FREE_INFERENCE_RUNS_DIR": bad_env_val}
                for sc_rel, sc_args in (
                    ("session", ["status", "--model", "tinfoil-deepseek-v4-1-flash"]),
                    ("verify-served-model", [mock_model_id]),
                    ("serve-model", [mock_model_id]),
                    ("opencode-local", ["--print-config", "--no-serve"]),
                ):
                    cp_bad = subprocess.run(
                        [sys.executable, "-I", "-B", str(clone_root / "scripts" / sc_rel), *sc_args],
                        cwd=str(clone_root),
                        env=bad_env,
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertNotEqual(
                        cp_bad.returncode,
                        0,
                        f"Expected non-zero exit on {bad_label} ({bad_env_val}) for {sc_rel}",
                    )

            # 4. Deterministic descriptor/inode swap tests:
            #    5a. Symlink substitution on FileExistsError during ensure_creatable_runs_dir -> rejected with ELOOP/ENOTDIR, decoy untouched!
            decoy_dir = short_root / "decoy_swap"
            decoy_dir.mkdir(mode=0o700)
            race_parent = short_root / "race_parent"
            race_parent.mkdir(mode=0o700)
            race_target = race_parent / "runs"
            orig_mkdir = os.mkdir

            def _raced_mkdir(path_arg: Any, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
                if path_arg == "runs" and dir_fd is not None:
                    os.symlink(str(decoy_dir), str(race_target))
                    raise FileExistsError(errno.EEXIST, "File exists", "runs")
                return orig_mkdir(path_arg, mode, dir_fd=dir_fd) if dir_fd is not None else orig_mkdir(path_arg, mode)

            self.assertTrue(hasattr(custody, "ensure_creatable_runs_dir"), "ensure_creatable_runs_dir missing")
            with patch("local_assist.custody.os.mkdir", side_effect=_raced_mkdir):
                res_swap, err_swap = custody.ensure_creatable_runs_dir(race_target)
            self.assertIsNone(res_swap)
            self.assertIsNotNone(err_swap)
            self.assertEqual(list(decoy_dir.iterdir()), [])

            #    5b. Post-coherence ancestor replacement BEFORE child CLI startup (`_FREE_INFERENCE_PINNED_RUNS_STAT` mismatch):
            #        swap owned ancestor with a fresh real 0700 directory (different inode!) -> serve-model, stop-model, and verify-served-model ALL refuse!
            anc_parent = short_root / "anc_swap"
            anc_parent.mkdir(mode=0o700)
            res_orig, err_orig = custody.ensure_creatable_runs_dir(anc_parent / "runs")
            self.assertIsNone(err_orig)
            assert res_orig is not None and res_orig.stat_id is not None
            orig_stat_str = f"{res_orig.stat_id[0]}:{res_orig.stat_id[1]}"

            # Replace anc_parent with a brand-new real 0700 directory containing a brand-new 0700 runs/
            os.rename(anc_parent, short_root / "anc_swap_old")
            anc_parent.mkdir(mode=0o700)
            replacement_runs = anc_parent / "runs"
            replacement_runs.mkdir(mode=0o700)
            pinned_env = {**base_env, "_FREE_INFERENCE_PINNED_RUNS_STAT": orig_stat_str}

            for sc_rel, sc_args in (
                ("serve-model", ["--runs-dir", str(replacement_runs), mock_model_id]),
                ("stop-model", ["--runs-dir", str(replacement_runs), mock_model_id]),
                ("verify-served-model", ["--runs-dir", str(replacement_runs), mock_model_id]),
            ):
                cp_pin = subprocess.run(
                    [sys.executable, "-I", "-B", str(clone_root / "scripts" / sc_rel), *sc_args],
                    cwd=str(clone_root),
                    env=pinned_env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertNotEqual(cp_pin.returncode, 0, f"{sc_rel} must reject swapped inode under _FREE_INFERENCE_PINNED_RUNS_STAT")
                self.assertEqual(list(replacement_runs.iterdir()), [], f"{sc_rel} must not touch replacement_runs")

            #        Also without --runs-dir (via FREE_INFERENCE_RUNS_DIR on both swapped existing store and absent store):
            absent_pinned_runs = short_root / "absent_pinned_runs"
            for env_runs_cand, check_empty_dir in (
                (replacement_runs, True),
                (absent_pinned_runs, False),
            ):
                pinned_no_flag_env = {
                    **base_env,
                    "FREE_INFERENCE_RUNS_DIR": str(env_runs_cand),
                    "_FREE_INFERENCE_PINNED_RUNS_STAT": orig_stat_str,
                }
                for sc_rel in ("serve-model", "stop-model", "verify-served-model"):
                    cp_nf = subprocess.run(
                        [sys.executable, "-I", "-B", str(clone_root / "scripts" / sc_rel), mock_model_id],
                        cwd=str(clone_root),
                        env=pinned_no_flag_env,
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertNotEqual(
                        cp_nf.returncode,
                        0,
                        f"{sc_rel} without --runs-dir must reject mismatched or absent store when _FREE_INFERENCE_PINNED_RUNS_STAT is set",
                    )
                if check_empty_dir:
                    self.assertEqual(list(env_runs_cand.iterdir()), [])
                else:
                    self.assertFalse(env_runs_cand.exists(), "Absent pinned store must not be created")

            #    5c. Intra-child swap AFTER open_existing_runs_dir / bind_pinned_runs_dir and BEFORE read/write/unlink/pointer publication:
            #        retained dir_fd keeps operations strictly on the original directory and refuses stale-path pointer publication!
            intra_anc = short_root / "intra_anc"
            intra_anc.mkdir(mode=0o700)
            res_intra, err_intra = custody.ensure_creatable_runs_dir(intra_anc / "runs")
            self.assertIsNone(err_intra)
            assert res_intra is not None and res_intra.stat_id is not None

            with custody.bind_pinned_runs_dir(res_intra.path, expected_stat=res_intra.stat_id) as pinned_view:
                # Now swap intra_anc on the filesystem AFTER bind_pinned_runs_dir succeeded!
                moved_anc = short_root / "intra_anc_moved"
                os.rename(intra_anc, moved_anc)
                intra_anc.mkdir(mode=0o700)
                decoy_intra_runs = intra_anc / "runs"
                decoy_intra_runs.mkdir(mode=0o700)
                (decoy_intra_runs / ".serve.pid").write_text('{"model_id": "poison"}\n', encoding="utf-8")

                # Write, read, list, and unlink via runs_store_* helpers -> must hit moved_anc/runs, NEVER decoy_intra_runs!
                custody.runs_store_write_atomic(pinned_view.path, ".serve-test.pid", '{"model_id": "legit"}\n')
                probe_fd_before = os.open("/dev/null", os.O_RDONLY)
                os.close(probe_fd_before)
                for _ in range(20):
                    self.assertEqual(
                        custody.runs_store_list_names(pinned_view.path, prefix=".serve", suffix=".pid"),
                        [".serve-test.pid"],
                    )
                probe_fd_after = os.open("/dev/null", os.O_RDONLY)
                os.close(probe_fd_after)
                self.assertEqual(probe_fd_after, probe_fd_before, "runs_store_list_names must not leak duplicated dir_fd")
                self.assertIn("legit", custody.runs_store_read_text(pinned_view.path, ".serve-test.pid") or "")
                self.assertFalse((decoy_intra_runs / ".serve-test.pid").exists())
                custody.runs_store_unlink(pinned_view.path, ".serve-test.pid")
                self.assertTrue((decoy_intra_runs / ".serve.pid").is_file(), "decoy file must remain untouched")

                # Pointer publication must refuse because os.lstat(pinned_view.path) no longer matches pinned_view.stat_id!
                # Isolate passwd home so even a regression in expected_stat cannot touch the real operator pointer (R4-1).
                swap_ptr_home = short_root / "swap_ptr_home"
                swap_ptr_home.mkdir(mode=0o700)
                with patch.object(custody, "_resolve_passwd_home_dir", return_value=swap_ptr_home):
                    with self.assertRaises(ValueError):
                        custody.write_active_runs_pointer(pinned_view.path, expected_stat=pinned_view.stat_id)
                self.assertFalse((swap_ptr_home / ".config" / "free-inference" / "active-runs.json").exists())

            #    5c-bis. Mid-write swap AFTER initial inspect_existing_runs_dir inside write_active_runs_pointer and BEFORE os.replace,
            #            plus post-write swap detection via runs_dev/runs_ino in read_active_runs_pointer:
            ptr_home = short_root / "ptr_home"
            ptr_home.mkdir(mode=0o700)
            ptr_anc = short_root / "ptr_anc"
            ptr_anc.mkdir(mode=0o700)
            res_ptr_orig, _ = custody.ensure_creatable_runs_dir(ptr_anc / "runs")
            assert res_ptr_orig is not None and res_ptr_orig.stat_id is not None
            prior_good = short_root / "prior_good_runs"
            prior_good.mkdir(mode=0o700)

            with patch.object(custody, "_resolve_passwd_home_dir", return_value=ptr_home):
                custody.write_active_runs_pointer(prior_good)
                self.assertEqual(custody.read_active_runs_pointer(), prior_good.resolve())

                def _swap_mid_pointer_write() -> None:
                    os.rename(ptr_anc, short_root / "ptr_anc_moved")
                    ptr_anc.mkdir(mode=0o700)
                    (ptr_anc / "runs").mkdir(mode=0o700)

                with patch.object(custody, "_before_pointer_replace_hook", side_effect=_swap_mid_pointer_write):
                    with self.assertRaises(ValueError):
                        custody.write_active_runs_pointer(res_ptr_orig.path, expected_stat=res_ptr_orig.stat_id)
                # Prior valid pointer must remain intact!
                self.assertEqual(custody.read_active_runs_pointer(), prior_good.resolve())

                # Post-publication replacement of prior_good with a new real 0700 directory -> read_active_runs_pointer rejects inode mismatch!
                os.rename(prior_good, short_root / "prior_good_moved")
                prior_good.mkdir(mode=0o700)
                self.assertIsNone(
                    custody.read_active_runs_pointer(),
                    "read_active_runs_pointer must reject directory replaced after pointer publication via runs_dev/runs_ino",
                )

                # 5c-ter. Swap AFTER pointer validation (via _after_pointer_read_hook) and BEFORE the first registry store access:
                #         retained _PINNED_POINTER_FD_STATE descriptor serves the original verified store and never reads poisoned replacement!
                ptr_reg_anc = short_root / "ptr_reg_anc"
                ptr_reg_anc.mkdir(mode=0o700)
                res_ptr_reg, _ = custody.ensure_creatable_runs_dir(ptr_reg_anc / "runs")
                assert res_ptr_reg is not None and res_ptr_reg.stat_id is not None
                from local_assist.registry import get_process_lstart, list_pid_records, read_pid_record_for_model

                ls_ptr_reg = (
                    _format_bsdinfo_lstart(os.getpid())
                    if not CAN_RUN_PS
                    else get_process_lstart(os.getpid())
                )
                pid_file_for_model("qwen3-30b-a3b-2507-mlx-4bit", res_ptr_reg.path).write_text(
                    json.dumps(
                        {
                            "model_id": "qwen3-30b-a3b-2507-mlx-4bit",
                            "repo": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
                            "port": 18399,
                            "pid": os.getpid(),
                            "pid_lstart": ls_ptr_reg,
                            "status": "ready",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                custody.write_active_runs_pointer(res_ptr_reg.path)

                swapped_once = {"done": False}

                def _swap_after_ptr_validate() -> None:
                    if swapped_once["done"]:
                        return
                    swapped_once["done"] = True
                    os.rename(ptr_reg_anc, short_root / "ptr_reg_anc_moved")
                    ptr_reg_anc.mkdir(mode=0o700)
                    decoy_reg = ptr_reg_anc / "runs"
                    decoy_reg.mkdir(mode=0o700)
                    pid_file_for_model("qwen3-30b-a3b-2507-mlx-4bit", decoy_reg).write_text(
                        json.dumps(
                            {
                                "model_id": "qwen3-30b-a3b-2507-mlx-4bit",
                                "repo": "poison/substituted",
                                "port": 65530,
                                "pid": os.getpid(),
                                "pid_lstart": ls_ptr_reg,
                                "status": "ready",
                            }
                        )
                        + "\n",
                        encoding="utf-8",
                    )

                custody_boot_st = custody.CustodyBootstrapState(
                    custody_mode=True,
                    worker_or_reap_cli=True,
                    launcher_site_packages=None,
                    cli_runs_dir=None,
                )

                try:
                    with (
                        patch("local_assist.custody._ACTIVE_BOOTSTRAP_STATE", custody_boot_st),
                        patch.object(custody, "_after_pointer_read_hook", side_effect=_swap_after_ptr_validate),
                    ):
                        rec_got = read_pid_record_for_model("qwen3-30b-a3b-2507-mlx-4bit")
                        assert rec_got is not None
                        self.assertEqual(rec_got["port"], 18399)
                        self.assertNotEqual(rec_got["repo"], "poison/substituted")
                        listed_recs = list_pid_records(res_ptr_reg.path)
                        self.assertEqual(len(listed_recs), 1)
                        self.assertEqual(listed_recs[0][1]["port"], 18399)
                finally:
                    custody.clear_pinned_pointer_fd()

            #    5d. Direct intra-child post-bind ancestor swaps inside verify-served-model, stop-model, and serve-model:
            local_mid = "qwen3-30b-a3b-2507-mlx-4bit"
            verify_mod_r21 = _load_script_module("verify_model_r21_intra", "scripts/verify-served-model")
            stop_mod_r21 = _load_script_module("stop_model_r21_intra", "scripts/stop-model")
            serve_mod_r21 = _load_script_module("serve_model_r21_intra", "scripts/serve-model")
            real_bind = custody.bind_pinned_runs_dir

            #      (i) verify-served-model: swap ancestor right after bind_pinned_runs_dir yields -> reads legit PID from moved dir, ignores poisoned replacement!
            v_anc = short_root / "v_intra"
            v_anc.mkdir(mode=0o700)
            res_v_in, _ = custody.ensure_creatable_runs_dir(v_anc / "runs")
            assert res_v_in is not None and res_v_in.stat_id is not None
            from local_assist.registry import get_process_lstart

            my_ls_r21 = (
                _format_bsdinfo_lstart(os.getpid())
                if not CAN_RUN_PS
                else get_process_lstart(os.getpid())
            )
            pid_file_for_model(local_mid, res_v_in.path).write_text(
                json.dumps(
                    {
                        "model_id": local_mid,
                        "repo": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
                        "port": 18291,
                        "pid": os.getpid(),
                        "pid_lstart": my_ls_r21,
                        "hf_offline": True,
                        "status": "ready",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            @contextlib.contextmanager
            def _swapping_bind_verify(*b_args: Any, **b_kw: Any):
                with real_bind(*b_args, **b_kw) as v_obj:
                    os.rename(v_anc, short_root / "v_intra_moved")
                    v_anc.mkdir(mode=0o700)
                    decoy_v = v_anc / "runs"
                    decoy_v.mkdir(mode=0o700)
                    pid_file_for_model(local_mid, decoy_v).write_text(
                        json.dumps(
                            {
                                "model_id": "other-poisoned-model",
                                "repo": "poison/model",
                                "port": 18291,
                                "pid": os.getpid(),
                                "pid_lstart": my_ls_r21,
                                "hf_offline": False,
                                "status": "ready",
                            }
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    yield v_obj

            with (
                patch("local_assist.custody.bind_pinned_runs_dir", side_effect=_swapping_bind_verify),
                patch.object(verify_mod_r21, "check_once_detailed", return_value=(True, "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit", False)),
                patch.object(verify_mod_r21, "pid_is_alive", return_value=True),
                patch.object(verify_mod_r21, "pid_matches_record", return_value=True),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                rc_v_in = verify_mod_r21.main(
                    ["verify-served-model", "--runs-dir", str(res_v_in.path), "--require-offline", local_mid]
                )
            self.assertEqual(rc_v_in, 0, "verify-served-model must read pinned dir_fd rather than poisoned replacement")

            #      (ii) stop-model: swap ancestor right after bind_pinned_runs_dir yields -> unlinks dead PID in moved dir, leaves decoy PID file untouched!
            st_anc = short_root / "st_intra"
            st_anc.mkdir(mode=0o700)
            res_st_in, _ = custody.ensure_creatable_runs_dir(st_anc / "runs")
            assert res_st_in is not None and res_st_in.stat_id is not None
            pid_file_for_model(local_mid, res_st_in.path).write_text(
                json.dumps(
                    {
                        "model_id": local_mid,
                        "pid": 99999991,
                        "pid_lstart": "Mon Jan  1 00:00:00 2001",
                        "status": "ready",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            @contextlib.contextmanager
            def _swapping_bind_stop(*b_args: Any, **b_kw: Any):
                with real_bind(*b_args, **b_kw) as v_obj:
                    os.rename(st_anc, short_root / "st_intra_moved")
                    st_anc.mkdir(mode=0o700)
                    decoy_st = st_anc / "runs"
                    decoy_st.mkdir(mode=0o700)
                    pid_file_for_model(local_mid, decoy_st).write_text(
                        json.dumps({"model_id": local_mid, "pid": 99999992, "pid_lstart": "Mon Jan  1 00:00:00 2001"}) + "\n",
                        encoding="utf-8",
                    )
                    yield v_obj

            with (
                patch.object(stop_mod_r21, "bind_pinned_runs_dir", side_effect=_swapping_bind_stop),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                rc_st_in = stop_mod_r21.main(["stop-model", "--runs-dir", str(res_st_in.path), local_mid])
            self.assertEqual(rc_st_in, 0)
            self.assertFalse(pid_file_for_model(local_mid, short_root / "st_intra_moved" / "runs").exists(), "Legit dead PID must be unlinked via dir_fd")
            self.assertTrue(pid_file_for_model(local_mid, st_anc / "runs").is_file(), "Decoy replacement PID file must NOT be unlinked")
            self.assertFalse((st_anc / "runs" / ".pid.lock").exists(), "Lock file must NOT be created in decoy replacement")

            #      (ii-b) remove_stale_control_socket probes via ctl_fd (os.fchdir(ctl_fd)), protecting a live original socket
            #             even if runs_dir/.control is swapped with a stale decoy socket before the probe, and unlinking once dead:
            from local_assist import session as session_mod
            from local_assist.session import control_path, remove_stale_control_socket

            ctl_anc = short_root / "ctl_swap_anc"
            ctl_anc.mkdir(mode=0o700)
            ctl_runs = ctl_anc / "runs"
            ctl_runs.mkdir(mode=0o700)
            ctl_sock = control_path(ctl_runs, local_mid)
            ctl_sock.parent.mkdir(mode=0o700)
            if CAN_BIND_UNIX_SOCKET:
                live_srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.addCleanup(live_srv.close)
                live_srv.bind(str(ctl_sock))
                os.chmod(ctl_sock, 0o600)
                live_srv.listen(2)
                orig_ctl_ino = os.lstat(ctl_sock.parent).st_ino

                def _swap_with_stale_decoy_before_probe() -> None:
                    if (short_root / "ctl_swap_anc_moved").exists():
                        return
                    os.rename(ctl_anc, short_root / "ctl_swap_anc_moved")
                    ctl_anc.mkdir(mode=0o700)
                    decoy_ctl_dir = control_path(ctl_anc / "runs", local_mid).parent
                    decoy_ctl_dir.mkdir(parents=True, mode=0o700)
                    os.chmod(ctl_anc / "runs", 0o700)
                    decoy_sock = control_path(ctl_anc / "runs", local_mid)
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as dead_s:
                        dead_s.bind(str(decoy_sock))
                        os.chmod(decoy_sock, 0o600)

                moved_sock = control_path(short_root / "ctl_swap_anc_moved" / "runs", local_mid)
                decoy_sock_after = control_path(ctl_anc / "runs", local_mid)
                if CAN_CONNECT_UNIX_SOCKET:
                    # 1. Live original listener + swapped stale decoy -> returns False and preserves live moved_sock!
                    with (
                        custody.bind_pinned_runs_dir(ctl_runs) as v_ctl,
                        patch.object(
                            session_mod,
                            "_before_stale_socket_probe_hook",
                            side_effect=_swap_with_stale_decoy_before_probe,
                        ),
                    ):
                        self.assertFalse(remove_stale_control_socket(v_ctl.path, local_mid, os.getpid()))
                        self.assertTrue(moved_sock.exists(), "Live original socket must NEVER be unlinked due to stale decoy")
                        self.assertTrue(decoy_sock_after.exists())

                        # 2. Close live_srv so original socket inside ctl_fd becomes genuinely stale (ECONNREFUSED) -> unlinks moved_sock only!
                        live_srv.close()
                        self.assertTrue(remove_stale_control_socket(v_ctl.path, local_mid, os.getpid()))
                        self.assertFalse(moved_sock.exists(), "Dead original socket must be unlinked via ctl_fd")
                        self.assertTrue(decoy_sock_after.exists(), "Decoy replacement socket must remain untouched")
                else:
                    # Outer sandbox blocks AF_UNIX connect() with EPERM: verify _probe_control_socket_via_ctl_fd receives orig_ctl_ino!
                    seen_probe_inos: list[int] = []
                    probe_mode = {"state": "live"}

                    def _spy_probe_ctl_fd(passed_ctl_fd: int, sock_name: str, *, expected_pid: int, timeout: float = 0.25) -> dict[str, Any]:
                        seen_probe_inos.append(os.fstat(passed_ctl_fd).st_ino)
                        if probe_mode["state"] == "live":
                            return {"state": "ON"}
                        raise ConnectionRefusedError(errno.ECONNREFUSED, "dead")

                    with (
                        custody.bind_pinned_runs_dir(ctl_runs) as v_ctl,
                        patch.object(
                            session_mod,
                            "_before_stale_socket_probe_hook",
                            side_effect=_swap_with_stale_decoy_before_probe,
                        ),
                        patch.object(session_mod, "_probe_control_socket_via_ctl_fd", side_effect=_spy_probe_ctl_fd),
                    ):
                        self.assertFalse(remove_stale_control_socket(v_ctl.path, local_mid, os.getpid()))
                        self.assertEqual(seen_probe_inos[-1], orig_ctl_ino)
                        self.assertTrue(moved_sock.exists())
                        probe_mode["state"] = "dead"
                        self.assertTrue(remove_stale_control_socket(v_ctl.path, local_mid, os.getpid()))
                        self.assertEqual(seen_probe_inos[-1], orig_ctl_ino)
                        self.assertFalse(moved_sock.exists())
                        self.assertTrue(decoy_sock_after.exists())

            #      (iii) serve-model: swap ancestor right after bind_pinned_runs_dir yields on cold start -> refuses before spawn and leaves decoy untouched,
            #            and on already-active --publish-active-runs -> refuses stale-path pointer publication!
            sv_anc = short_root / "sv_intra"
            sv_anc.mkdir(mode=0o700)
            res_sv_in, _ = custody.ensure_creatable_runs_dir(sv_anc / "runs")
            assert res_sv_in is not None and res_sv_in.stat_id is not None

            @contextlib.contextmanager
            def _swapping_bind_serve(*b_args: Any, **b_kw: Any):
                with real_bind(*b_args, **b_kw) as v_obj:
                    if b_kw.get("create"):
                        os.rename(sv_anc, short_root / "sv_intra_moved")
                        sv_anc.mkdir(mode=0o700)
                        (sv_anc / "runs").mkdir(mode=0o700)
                    yield v_obj

            sv_err_buf = io.StringIO()
            with (
                patch.object(serve_mod_r21, "bind_pinned_runs_dir", side_effect=_swapping_bind_serve),
                patch.object(serve_mod_r21, "_port_is_bound", return_value=False),
                redirect_stdout(io.StringIO()),
                redirect_stderr(sv_err_buf),
            ):
                rc_sv_in = serve_mod_r21.main(["serve-model", "--runs-dir", str(res_sv_in.path), "--port", "18292", local_mid])
            self.assertNotEqual(rc_sv_in, 0, "serve-model must abort before spawn when RUNS path was swapped post-bind")
            self.assertIn("replaced concurrently", sv_err_buf.getvalue())
            self.assertEqual(list((sv_anc / "runs").iterdir()), [], "serve-model must create zero files in decoy replacement")
        finally:
            try:
                if (short_root / "unsticky_777").exists():
                    os.chmod(short_root / "unsticky_777", 0o700)
            except OSError:
                pass
            shutil.rmtree(short_root, ignore_errors=True)

    @unittest.skipUnless(
        CAN_RUN_PS and CAN_BIND_LOOPBACK_TCP and CAN_CONNECT_LOOPBACK_TCP,
        "Real-child cold-start regression requires /bin/ps and loopback TCP bind/connect",
    )
    def test_r3_1_and_r3_2_isolated_real_child_cold_start_pointer_and_bystander(self) -> None:
        from local_assist.registry import pid_file_for_model

        short_root = Path(tempfile.mkdtemp(prefix="fi-r31-", dir=SHORT_TMP_DIR)).resolve()
        mock_model_id = "qwen3-30b-a3b-2507-mlx-4bit"
        mock_repo = "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit"
        clone_root: Path | None = None
        default_runs: Path | None = None
        nested_env_runs: Path | None = None
        bystander_runs: Path | None = None
        env_with_oc: dict[str, str] = {}
        try:
            clone_root, fake_home = self._build_isolated_clone_fixture(short_root)
            fake_ptr_path = fake_home / ".config" / "free-inference" / "active-runs.json"
            workers_dir = short_root / "workers"
            workers_dir.mkdir(mode=0o700)

            fake_oc_ver = short_root / "fake-oc-ver"
            fake_oc_ver.write_text(
                "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 2.3.2; exit 0; fi\nexit 0\n",
                encoding="utf-8",
            )
            os.chmod(fake_oc_ver, 0o700)
            (short_root / "opencode").symlink_to(fake_oc_ver)

            fake_sb = short_root / "fake-sandbox-exec"
            fake_sb.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(fake_sb, 0o700)

            env_with_oc = {
                "PATH": f"{short_root}:{os.environ.get('PATH', '/usr/bin:/bin')}",
                "HOME": str(fake_home),
                "FREE_INFERENCE_WORKER_HOMES_DIR": str(workers_dir),
                "FREE_INFERENCE_SANDBOX_EXEC_BIN": str(fake_sb),
                "PYTHONDONTWRITEBYTECODE": "1",
            }

            http_daemon_py = short_root / "http_daemon.py"
            http_daemon_py.write_text(
                textwrap.dedent(
                    f"""
                    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
                    import json, signal, socketserver, sys
                    port = int(sys.argv[sys.argv.index("--port") + 1])
                    class H(BaseHTTPRequestHandler):
                        def do_GET(self):
                            raw = json.dumps({{"object": "list", "data": [{{"id": {mock_repo!r}, "object": "model"}}]}}).encode()
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.send_header("Content-Length", str(len(raw)))
                            self.end_headers()
                            self.wfile.write(raw)
                        def log_message(self, *a):
                            pass
                    class FastHTTPServer(ThreadingHTTPServer):
                        allow_reuse_address = True
                        def server_bind(self):
                            socketserver.TCPServer.server_bind(self)
                            self.server_name = "127.0.0.1"
                            self.server_port = self.server_address[1]
                    srv = FastHTTPServer(("127.0.0.1", port), H)
                    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
                    srv.serve_forever()
                    """
                ),
                encoding="utf-8",
            )

            def _alloc_bounded_port(start_p: int) -> int:
                for cand_p in range(start_p, start_p + 600):
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sp:
                        try:
                            sp.bind(("127.0.0.1", cand_p))
                            return cand_p
                        except OSError:
                            continue
                raise RuntimeError("Could not bind bounded test port")

            cold_port_default = _alloc_bounded_port(29100)
            cold_port_env = _alloc_bounded_port(cold_port_default + 1)
            bystander_port = _alloc_bounded_port(cold_port_env + 1)

            models_text = (ROOT / "models.yaml").read_text(encoding="utf-8")
            old_block = (
                "  - id: qwen3-30b-a3b-2507-mlx-4bit\n"
                "    status: runnable\n"
                "    repo: mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit\n"
                "    upstream: Qwen/Qwen3-30B-A3B-Instruct-2507\n"
                "    converter: mlx-community\n"
                "    conversion_runtime_version: mlx-lm 0.26.3\n"
                "    runtime: mlx-lm\n"
                "    serve_command: null\n"
            )
            self.assertIn(old_block, models_text)
            (clone_root / "models.yaml").write_text(
                models_text.replace(
                    old_block,
                    old_block.replace(
                        "runtime: mlx-lm\n    serve_command: null\n",
                        f"runtime: llama.cpp\n    serve_command: \"{sys.executable} -I -B {http_daemon_py} --host {{host}} --port {{port}} --model {{repo}}\"\n",
                    ),
                    1,
                ).replace("http://127.0.0.1:8080/v1", f"http://127.0.0.1:{cold_port_default}/v1"),
                encoding="utf-8",
            )

            default_runs = clone_root / "runs"
            bystander_runs = short_root / "bystander_runs"
            bystander_runs.mkdir(mode=0o700)
            nested_env_runs = short_root / "nested_a" / "nested_b" / "fresh_runs"

            # Step A: Start live fake bystander with explicit --runs-dir (must NOT publish active-runs.json),
            # then seed fake_home/.config/free-inference/active-runs.json pointing to bystander_runs.
            cp_by_start = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(clone_root / "scripts" / "serve-model"),
                    "--runs-dir",
                    str(bystander_runs),
                    "--port",
                    str(bystander_port),
                    mock_model_id,
                ],
                cwd=str(clone_root),
                env=env_with_oc,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(cp_by_start.returncode, 0, cp_by_start.stderr)
            self.assertFalse(fake_ptr_path.exists(), "Explicit --runs-dir without --publish-active-runs must not create fake pointer")

            cp_by_ver = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(clone_root / "scripts" / "verify-served-model"),
                    "--runs-dir",
                    str(bystander_runs),
                    "--port",
                    str(bystander_port),
                    "--wait",
                    "15",
                    mock_model_id,
                ],
                cwd=str(clone_root),
                env=env_with_oc,
                capture_output=True,
                text=True,
                timeout=25,
                check=False,
            )
            self.assertEqual(cp_by_ver.returncode, 0, cp_by_ver.stderr)
            bystander_pid = int(json.loads(pid_file_for_model(mock_model_id, bystander_runs).read_text(encoding="utf-8"))["pid"])

            cp_seed_ptr = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    (
                        f"import sys; from pathlib import Path; sys.path.insert(0, {str(clone_root)!r}); "
                        "from local_assist.custody import write_active_runs_pointer; "
                        f"write_active_runs_pointer(Path({str(bystander_runs)!r}))"
                    ),
                ],
                cwd=str(clone_root),
                env=env_with_oc,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(cp_seed_ptr.returncode, 0, cp_seed_ptr.stderr)
            self.assertTrue(fake_ptr_path.is_file())
            self.assertEqual(stat.S_IMODE(fake_ptr_path.parent.lstat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(fake_ptr_path.lstat().st_mode), 0o600)
            self.assertEqual(json.loads(fake_ptr_path.read_text(encoding="utf-8"))["runs_dir"], str(bystander_runs))

            # Step B: Worker-mode CLI with absent clone_root/runs consults fake_ptr_path and attaches to live bystander_runs!
            self.assertFalse(default_runs.exists())
            cp_att_by = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(clone_root / "scripts" / "opencode-local"),
                    "--unattended-worker",
                    "--print-config",
                ],
                cwd=str(clone_root),
                env=env_with_oc,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(cp_att_by.returncode, 0, cp_att_by.stderr)
            self.assertFalse(default_runs.exists(), "Worker attach via live fake pointer must not create absent default runs/")
            att_payload = json.loads(cp_att_by.stdout)
            self.assertEqual(att_payload["api_base_url"], f"http://127.0.0.1:{bystander_port}/v1")
            self.assertEqual(
                att_payload["config"]["provider"]["private-local"]["options"]["baseURL"],
                f"http://127.0.0.1:{bystander_port}/v1",
            )

            # Step C: Absent nested FREE_INFERENCE_RUNS_DIR:
            #   - --no-serve leaves nested_a uncreated and preserves fake_ptr_path -> bystander_runs
            #   - cold start creates 0700 nested_env_runs, preserves fake_ptr_path -> bystander_runs, and stopping nested_env_runs spares bystander!
            env_nested = {**env_with_oc, "FREE_INFERENCE_RUNS_DIR": str(nested_env_runs)}
            cp_env_noserve = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(clone_root / "scripts" / "opencode-local"),
                    "--no-serve",
                    "--port",
                    str(cold_port_env),
                    "--",
                    "run",
                    "hi",
                ],
                cwd=str(clone_root),
                env=env_nested,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertNotEqual(cp_env_noserve.returncode, 0)
            self.assertIn("--no-serve was set", cp_env_noserve.stderr)
            self.assertFalse((short_root / "nested_a").exists(), "--no-serve must not create nested env runs dir")
            self.assertEqual(json.loads(fake_ptr_path.read_text(encoding="utf-8"))["runs_dir"], str(bystander_runs))

            cp_cold_env = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(clone_root / "scripts" / "opencode-local"),
                    "--port",
                    str(cold_port_env),
                    "--print-config",
                    "--",
                    "run",
                    "hi",
                ],
                cwd=str(clone_root),
                env=env_nested,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(cp_cold_env.returncode, 0, cp_cold_env.stderr)
            self.assertTrue(nested_env_runs.is_dir())
            self.assertEqual(stat.S_IMODE(os.lstat(nested_env_runs).st_mode), 0o700)
            self.assertTrue(pid_file_for_model(mock_model_id, nested_env_runs).is_file())
            self.assertEqual(
                json.loads(fake_ptr_path.read_text(encoding="utf-8"))["runs_dir"],
                str(bystander_runs),
                "FREE_INFERENCE_RUNS_DIR cold start must not overwrite bystander fake pointer",
            )

            cp_stop_nested = subprocess.run(
                [sys.executable, "-I", "-B", str(clone_root / "scripts" / "stop-model"), "--runs-dir", str(nested_env_runs), mock_model_id],
                cwd=str(clone_root),
                env=env_with_oc,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(cp_stop_nested.returncode, 0, cp_stop_nested.stderr)
            self.assertFalse(pid_file_for_model(mock_model_id, nested_env_runs).exists())
            os.kill(bystander_pid, 0)
            self.assertTrue(pid_file_for_model(mock_model_id, bystander_runs).is_file(), "Bystander PID record must remain intact")

            # Step D: Stop bystander and leave a stale record in bystander_runs; with clone_root/runs still absent,
            # cold-starting opencode-local --unattended-worker --print-config creates 0700 clone_root/runs and updates fake_ptr_path!
            cp_stop_by = subprocess.run(
                [sys.executable, "-I", "-B", str(clone_root / "scripts" / "stop-model"), "--runs-dir", str(bystander_runs), mock_model_id],
                cwd=str(clone_root),
                env=env_with_oc,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(cp_stop_by.returncode, 0, cp_stop_by.stderr)
            pid_file_for_model(mock_model_id, bystander_runs).write_text(
                json.dumps({"model_id": mock_model_id, "pid": 99999994, "pid_lstart": "Mon Jan  1 00:00:00 2001", "status": "ready"}) + "\n",
                encoding="utf-8",
            )
            self.assertEqual(json.loads(fake_ptr_path.read_text(encoding="utf-8"))["runs_dir"], str(bystander_runs))
            self.assertFalse(default_runs.exists())

            cp_cold_def = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(clone_root / "scripts" / "opencode-local"),
                    "--unattended-worker",
                    "--print-config",
                ],
                cwd=str(clone_root),
                env=env_with_oc,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(cp_cold_def.returncode, 0, cp_cold_def.stderr)
            self.assertTrue(default_runs.is_dir())
            st_def = os.lstat(default_runs)
            self.assertEqual(stat.S_IMODE(st_def.st_mode), 0o700)
            self.assertTrue(pid_file_for_model(mock_model_id, default_runs).is_file())
            self.assertEqual(stat.S_IMODE(fake_ptr_path.parent.lstat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(fake_ptr_path.lstat().st_mode), 0o600)
            updated_ptr = json.loads(fake_ptr_path.read_text(encoding="utf-8"))
            self.assertEqual(updated_ptr["runs_dir"], str(default_runs))
            self.assertEqual(updated_ptr["runs_dev"], int(st_def.st_dev))
            self.assertEqual(updated_ptr["runs_ino"], int(st_def.st_ino))
        finally:
            if clone_root is not None:
                for cleanup_runs in (default_runs, nested_env_runs, bystander_runs):
                    if cleanup_runs is not None and cleanup_runs.is_dir():
                        subprocess.run(
                            [sys.executable, "-I", "-B", str(clone_root / "scripts" / "stop-model"), "--runs-dir", str(cleanup_runs), mock_model_id],
                            cwd=str(clone_root),
                            env=env_with_oc or dict(os.environ),
                            capture_output=True,
                            timeout=10,
                            check=False,
                        )
            shutil.rmtree(short_root, ignore_errors=True)

    def test_r2_2_argparse_disables_abbreviations_across_launchers_and_helpers(self) -> None:
        short_root = Path(tempfile.mkdtemp(prefix="fi-r22-", dir=SHORT_TMP_DIR))
        try:
            workers_dir = short_root / "workers"
            workers_dir.mkdir(mode=0o700)
            fake_home = short_root / "home"
            fake_home.mkdir(mode=0o700)
            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": str(fake_home),
                "FREE_INFERENCE_WORKER_HOMES_DIR": str(workers_dir),
                "PYTHONDONTWRITEBYTECODE": "1",
            }

            for script_rel in ("scripts/opencode-attested", "scripts/opencode-local"):
                # 1. Abbreviated `--worker-manif` is rejected by argparse (exit != 0) and never treated as valid --worker-manifest
                m_abbrev = short_root / f"m-abbrev-{Path(script_rel).name}.json"
                cp_m = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-B",
                        str(ROOT / script_rel),
                        "--inherit-process-group",
                        "--worker-manif",
                        str(m_abbrev),
                        "--run-token",
                        "tok-r22",
                        "--",
                        "run",
                        "hi",
                    ],
                    cwd=str(ROOT),
                    env=env,
                    start_new_session=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertNotEqual(cp_m.returncode, 0)
                self.assertIn("unrecognized arguments", cp_m.stderr)
                self.assertFalse(m_abbrev.exists())

                # 2a. Portable abbreviated `--keep-worker` rejection without `--worker-manifest` (all platforms)
                cp_k_port = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-B",
                        str(ROOT / script_rel),
                        "--keep-worker",
                        "--",
                        "run",
                        "hi",
                    ],
                    cwd=str(ROOT),
                    env=env,
                    start_new_session=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertNotEqual(cp_k_port.returncode, 0)
                self.assertIn("unrecognized arguments: --keep-worker", cp_k_port.stderr)

                if sys.platform == "darwin":
                    # 2b. Exact `--worker-manifest` + abbreviated `--keep-worker`: rejected by argparse, early manifest remains intact!
                    m_exact = short_root / f"m-exact-{Path(script_rel).name}.json"
                    cp_k = subprocess.run(
                        [
                            sys.executable,
                            "-I",
                            "-B",
                            str(ROOT / script_rel),
                            "--inherit-process-group",
                            "--worker-manifest",
                            str(m_exact),
                            "--run-token",
                            "tok-r22-k",
                            "--keep-worker",
                            "--",
                            "run",
                            "hi",
                        ],
                        cwd=str(ROOT),
                        env=env,
                        start_new_session=True,
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertNotEqual(cp_k.returncode, 0)
                    self.assertIn("unrecognized arguments: --keep-worker", cp_k.stderr)
                    self.assertTrue(m_exact.is_file(), "Early manifest must remain published on abbreviated --keep-worker parse error")

                    # 3. Exact `--worker-manifest` + exact `--keep-worker-home` on early failure: retains isolated_home AND manifest!
                    m_retain = short_root / f"m-retain-{Path(script_rel).name}.json"
                    cp_ret = subprocess.run(
                        [
                            sys.executable,
                            "-I",
                            "-B",
                            str(ROOT / script_rel),
                            "--inherit-process-group",
                            "--worker-manifest",
                            str(m_retain),
                            "--run-token",
                            "tok-r22-ret",
                            "--keep-worker-home",
                            "--model",
                            "nonexistent-model-r22",
                            "--",
                            "run",
                            "hi",
                        ],
                        cwd=str(ROOT),
                        env=env,
                        start_new_session=True,
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertNotEqual(cp_ret.returncode, 0)
                    self.assertTrue(m_retain.is_file())
                    retain_obj = json.loads(m_retain.read_text(encoding="utf-8"))
                    self.assertTrue(Path(retain_obj["isolated_home"]).is_dir(), "Exact --keep-worker-home must retain isolated_home on early failure")

            # 4. Sibling CLIs (`session`, `verify-served-model`, `serve-model`) also reject abbreviated `--runs-d`
            existing_runs = short_root / "existing_runs"
            existing_runs.mkdir(mode=0o700)
            for sc_rel, sc_args, expect_unrec in (
                ("scripts/session", ["--runs-d", str(existing_runs), "status"], False),
                ("scripts/session", [f"--runs-d={existing_runs}", "status"], True),
                ("scripts/verify-served-model", ["--runs-d", str(existing_runs), "qwen3-30b-a3b-2507-mlx-4bit"], False),
                ("scripts/verify-served-model", [f"--runs-d={existing_runs}", "qwen3-30b-a3b-2507-mlx-4bit"], True),
                ("scripts/serve-model", ["--runs-d", str(existing_runs), "qwen3-30b-a3b-2507-mlx-4bit"], False),
                ("scripts/serve-model", [f"--runs-d={existing_runs}", "qwen3-30b-a3b-2507-mlx-4bit"], True),
            ):
                cp_sib = subprocess.run(
                    [sys.executable, "-I", "-B", str(ROOT / sc_rel), *sc_args],
                    cwd=str(ROOT),
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertNotEqual(cp_sib.returncode, 0, f"{sc_rel} must reject abbreviated --runs-d")
                if expect_unrec:
                    self.assertIn("unrecognized arguments", cp_sib.stderr)
        finally:
            for root_p, dirs_p, files_p in os.walk(short_root, topdown=False):
                for fn in files_p:
                    try:
                        os.chmod(Path(root_p) / fn, 0o600)
                    except OSError:
                        pass
                for dn in dirs_p:
                    try:
                        os.chmod(Path(root_p) / dn, 0o700)
                    except OSError:
                        pass
            shutil.rmtree(short_root, ignore_errors=True)

    def test_r2_3_bounded_pipe_drain_exclusive_fd_ownership_across_delayed_reader(self) -> None:
        from local_assist.launch import _BoundedPipeDrain

        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            meta_file = Path(tmp) / "service-identity.json"
            meta_payload = '{"pid": 4242, "intact": true}\n'
            meta_file.write_text(meta_payload, encoding="utf-8")

            rfd, wfd = os.pipe()
            stream = os.fdopen(rfd, "rb")
            paused_between_reads = threading.Event()
            resume_reader = threading.Event()

            # Subclass/hook _after_chunk_hook to deterministically pause _drain_loop after reading chunk 1
            class _InstrumentedDrain(_BoundedPipeDrain):
                def _after_chunk_hook(self) -> None:
                    if not paused_between_reads.is_set():
                        paused_between_reads.set()
                        resume_reader.wait(timeout=5.0)

            drain = _InstrumentedDrain(stream, max_bytes=1024)
            owned_fd = getattr(drain, "_owned_fd", None)
            wake_rfd = getattr(drain, "_wake_rfd", None)
            self.assertIsInstance(owned_fd, int)
            self.assertIsInstance(wake_rfd, int)
            assert isinstance(owned_fd, int) and isinstance(wake_rfd, int)

            try:
                os.write(wfd, b"first-stderr-line\n")
                self.assertTrue(paused_between_reads.wait(timeout=2.0), "Reader did not reach between-reads barrier")

                # Call close() with a short join timeout while the reader thread is paused between reads!
                drain.close(_join_timeout=0.02)
                self.assertTrue(drain._thread.is_alive(), "Reader should still be paused at barrier")

                # Crucial invariant: BOTH owned_fd and wake_rfd MUST STILL BE OPEN (not closed by main thread!),
                # so opening metadata files on the main thread CANNOT recycle either reader descriptor!
                st_still_open = os.fstat(owned_fd)
                st_wake_still_open = os.fstat(wake_rfd)
                self.assertTrue(stat.S_ISFIFO(st_still_open.st_mode))
                self.assertTrue(stat.S_ISFIFO(st_wake_still_open.st_mode))

                with meta_file.open("rb") as mf:
                    self.assertNotIn(mf.fileno(), (owned_fd, wake_rfd), "Metadata file must not receive recycled reader fds")
                    # Release reader while metadata file is open and verify zero bytes of metadata file are stolen!
                    resume_reader.set()
                    drain._thread.join(timeout=2.0)
                    self.assertFalse(drain._thread.is_alive(), "Reader thread must exit promptly once resumed")
                    self.assertEqual(mf.read().decode("utf-8"), meta_payload)

                # Once _drain_loop has exited, BOTH owned_fd and wake_rfd MUST be closed (EBADF)!
                for closed_fd in (owned_fd, wake_rfd):
                    with self.assertRaises(OSError) as ctx:
                        os.fstat(closed_fd)
                    self.assertEqual(ctx.exception.errno, errno.EBADF)
                self.assertIn("first-stderr-line", drain.tail_text())
            finally:
                resume_reader.set()
                try:
                    os.close(wfd)
                except OSError:
                    pass
                drain.close()

    def test_r2_4_data_volume_firmlink_and_inode_alias_mdnsresponder_rejected(self) -> None:
        from local_assist.security_profile import SecurityProfileError, parse_security_profile_dict

        for bad_sock in (
            "/System/Volumes/Data/private/var/run/mDNSResponder",
            "/System/Volumes/Data/var/run/mDNSResponder",
            "/system/volumes/data/Private/Var/Run/MDNSRESPONDER",
        ):
            with self.subTest(sock=bad_sock), self.assertRaisesRegex(SecurityProfileError, "mDNSResponder"):
                parse_security_profile_dict(
                    {
                        "schema_version": 1,
                        "mode": "unattended_worker",
                        "network": {"allowed_unix_sockets": [bad_sock]},
                    }
                )

        # Also verify read-only (st_dev, st_ino) identity rejection even under an unrelated lexical path!
        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            alias_sock = Path(tmp).resolve() / "innocent.sock"
            orig_lstat = os.lstat
            if CAN_BIND_UNIX_SOCKET:
                srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.addCleanup(srv.close)
                srv.bind(str(alias_sock))
                alias_st = orig_lstat(alias_sock)
                match_paths = {"/private/var/run/mDNSResponder"}
            else:
                alias_st = os.stat_result(
                    (stat.S_IFSOCK | 0o600, 987654321, 16777234, 1, os.geteuid(), os.getegid(), 0, 0, 0, 0)
                )
                match_paths = {
                    "/private/var/run/mDNSResponder",
                    str(alias_sock),
                    str(Path(tmp) / "innocent.sock"),
                }

            def _fake_lstat(p: Any, *a: Any, **kw: Any) -> os.stat_result:
                if str(p) in match_paths:
                    return alias_st
                return orig_lstat(p, *a, **kw)

            with (
                patch("local_assist.security_profile.os.lstat", side_effect=_fake_lstat),
                self.assertRaisesRegex(SecurityProfileError, "mDNSResponder"),
            ):
                parse_security_profile_dict(
                    {
                        "schema_version": 1,
                        "mode": "unattended_worker",
                        "network": {"allowed_unix_sockets": [str(alias_sock)]},
                    }
                )

    def test_session_start_on_state_pointer_self_heal_and_swap_protection(self) -> None:
        from local_assist import custody, session as sess_mod

        short_root = Path(tempfile.mkdtemp(prefix="fi-onptr-", dir=SHORT_TMP_DIR)).resolve()
        try:
            fake_home = short_root / "home"
            fake_home.mkdir(mode=0o700)
            runs_dir = short_root / "live_runs"
            runs_dir.mkdir(mode=0o700)
            other_live = short_root / "other_live_runs"
            other_live.mkdir(mode=0o700)
            dead_store = short_root / "dead_runs"
            dead_store.mkdir(mode=0o700)
            fake_ptr = fake_home / ".config" / "free-inference" / "active-runs.json"

            on_info = {
                "state": "ON",
                "model_id": "tinfoil-deepseek-v4-1-flash",
                "remaining_seconds": 3600,
                "requests_used": 0,
                "requests_remaining": 100,
                "request_limit": 100,
                "generation": 1,
                "session_id": "sess-on-ptr",
            }
            fake_record = {"model_id": "tinfoil-deepseek-v4-1-flash", "pid": os.getpid(), "status": "ready"}
            clean_env = {k: v for k, v in os.environ.items() if k != "FREE_INFERENCE_RUNS_DIR"}

            def _run_start(argv: list[str], env_map: dict[str, str], *, target_runs: Path = runs_dir) -> int:
                with (
                    patch.dict(os.environ, env_map, clear=True),
                    patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home),
                    patch.object(sess_mod, "resolve_effective_runs_dir_details", return_value=(target_runs, None)),
                    patch.object(sess_mod, "select_model", return_value="tinfoil-deepseek-v4-1-flash"),
                    patch.object(sess_mod, "read_pid_record_for_model", return_value=fake_record),
                    patch.object(sess_mod, "status_for_record", return_value=dict(on_info)),
                    patch.object(custody, "is_custody_tree", return_value=False),
                ):
                    return sess_mod.main(argv)

            # 1. Missing pointer -> created pointing to runs_dir
            self.assertFalse(fake_ptr.exists())
            self.assertEqual(_run_start(["start"], clean_env), 0)
            self.assertTrue(fake_ptr.is_file())
            self.assertEqual(json.loads(fake_ptr.read_text(encoding="utf-8"))["runs_dir"], str(runs_dir))

            # 2. Dead/stale pointer -> repaired to runs_dir
            with patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home):
                custody.write_active_runs_pointer(dead_store)
            shutil.rmtree(dead_store)
            self.assertEqual(json.loads(fake_ptr.read_text(encoding="utf-8"))["runs_dir"], str(dead_store))
            self.assertEqual(_run_start(["start"], clean_env), 0)
            self.assertEqual(json.loads(fake_ptr.read_text(encoding="utf-8"))["runs_dir"], str(runs_dir))

            # 3. Valid pointer to a different live store -> intentionally repointed to runs_dir
            with patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home):
                custody.write_active_runs_pointer(other_live)
            self.assertEqual(json.loads(fake_ptr.read_text(encoding="utf-8"))["runs_dir"], str(other_live))
            self.assertEqual(_run_start(["start"], clean_env), 0)
            st_runs = os.lstat(runs_dir)
            ptr_doc = json.loads(fake_ptr.read_text(encoding="utf-8"))
            self.assertEqual(ptr_doc["runs_dir"], str(runs_dir))
            self.assertEqual(ptr_doc["runs_dev"], int(st_runs.st_dev))
            self.assertEqual(ptr_doc["runs_ino"], int(st_runs.st_ino))

            # 4. Explicit --runs-dir and FREE_INFERENCE_RUNS_DIR leave existing pointer untouched
            with patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home):
                custody.write_active_runs_pointer(other_live)
            self.assertEqual(_run_start(["start", "--runs-dir", str(runs_dir)], clean_env), 0)
            self.assertEqual(json.loads(fake_ptr.read_text(encoding="utf-8"))["runs_dir"], str(other_live))
            env_override = {**clean_env, "FREE_INFERENCE_RUNS_DIR": str(runs_dir)}
            self.assertEqual(_run_start(["start"], env_override), 0)
            self.assertEqual(json.loads(fake_ptr.read_text(encoding="utf-8"))["runs_dir"], str(other_live))

            # 5. Publication failure raises OperatorError -> exit 1
            with (
                patch.dict(os.environ, clean_env, clear=True),
                patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home),
                patch.object(sess_mod, "resolve_effective_runs_dir_details", return_value=(runs_dir, None)),
                patch.object(sess_mod, "select_model", return_value="tinfoil-deepseek-v4-1-flash"),
                patch.object(sess_mod, "read_pid_record_for_model", return_value=fake_record),
                patch.object(sess_mod, "status_for_record", return_value=dict(on_info)),
                patch.object(custody, "is_custody_tree", return_value=False),
                patch.object(custody, "write_active_runs_pointer", side_effect=OSError("disk full")),
            ):
                self.assertEqual(sess_mod.main(["start"]), 1)

            # 6. Runs-directory identity swap between initial validation and ON-path pointer write fails closed
            swap_parent = short_root / "swap_parent"
            swap_parent.mkdir(mode=0o700)
            swap_runs = swap_parent / "runs"
            swap_runs.mkdir(mode=0o700)
            with patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home):
                custody.write_active_runs_pointer(swap_runs)
            orig_swap_st = os.lstat(swap_runs)

            def _swap_during_status(_rec: Any, _rdir: Path) -> dict[str, Any]:
                os.rename(swap_runs, swap_parent / "runs_old")
                swap_runs.mkdir(mode=0o700)
                return dict(on_info)

            with (
                patch.dict(os.environ, clean_env, clear=True),
                patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home),
                patch.object(sess_mod, "resolve_effective_runs_dir_details", return_value=(swap_runs, None)),
                patch.object(sess_mod, "select_model", return_value="tinfoil-deepseek-v4-1-flash"),
                patch.object(sess_mod, "read_pid_record_for_model", return_value=fake_record),
                patch.object(sess_mod, "status_for_record", side_effect=_swap_during_status),
                patch.object(custody, "is_custody_tree", return_value=False),
            ):
                self.assertEqual(sess_mod.main(["start"]), 1)
            # Pointer must NOT have been updated to the replacement directory's inode
            ptr_after_swap = json.loads(fake_ptr.read_text(encoding="utf-8"))
            self.assertEqual(ptr_after_swap["runs_ino"], int(orig_swap_st.st_ino))
        finally:
            shutil.rmtree(short_root, ignore_errors=True)

    def test_inspect_active_runs_pointer_refusal_fifo_swaps_legacy_v1_and_pin_preservation(self) -> None:
        from local_assist import custody

        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            tmp_path = Path(tmp)
            fake_home = tmp_path / "home"
            fake_home.mkdir(mode=0o700)
            live_runs = tmp_path / "live_runs"
            live_runs.mkdir(mode=0o700)
            fi_dir = fake_home / ".config" / "free-inference"
            ptr_path = fi_dir / "active-runs.json"

            with patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home):
                # 1. Strictly absent when .config, free-inference, or active-runs.json is missing
                self.assertEqual(custody.inspect_active_runs_pointer(pin_fd=False).status, "absent")
                (fake_home / ".config").mkdir(mode=0o700)
                self.assertEqual(custody.inspect_active_runs_pointer(pin_fd=False).status, "absent")
                fi_dir.mkdir(mode=0o700)
                os.chmod(fi_dir, 0o700)
                self.assertEqual(custody.inspect_active_runs_pointer(pin_fd=False).status, "absent")

                # 2. Schema-v1 compatibility when BOTH runs_dev and runs_ino are omitted (derives stat from descriptor)
                ptr_path.write_text(json.dumps({"schema_version": 1, "runs_dir": str(live_runs)}) + "\n", encoding="utf-8")
                os.chmod(ptr_path, 0o600)
                res_legacy = custody.inspect_active_runs_pointer(pin_fd=True)
                self.assertEqual(res_legacy.status, "ok")
                self.assertEqual(res_legacy.path, live_runs.resolve())
                self.assertEqual(res_legacy.stat_id, (live_runs.lstat().st_dev, live_runs.lstat().st_ino))

                # Save pinned fd state to prove pin_fd=False leaves it completely untouched!
                orig_pin_state = custody._PINNED_POINTER_FD_STATE
                self.assertIsNotNone(orig_pin_state)

                # Partial runs_dev/runs_ino pairs rejected without echoing raw content
                for bad_obj in (
                    {"schema_version": 1, "runs_dir": str(live_runs), "runs_dev": 1},
                    {"schema_version": 1, "runs_dir": str(live_runs), "runs_ino": 1},
                    {"schema_version": 1, "runs_dir": str(live_runs), "runs_dev": True, "runs_ino": 1},
                ):
                    ptr_path.write_text(json.dumps(bad_obj) + "\n", encoding="utf-8")
                    os.chmod(ptr_path, 0o600)
                    r_bad = custody.inspect_active_runs_pointer(pin_fd=False)
                    self.assertEqual(r_bad.status, "refused")
                    self.assertEqual(r_bad.reason_code, "pointer_malformed")
                    # Existing pin untouched!
                    self.assertEqual(custody._PINNED_POINTER_FD_STATE, orig_pin_state)

                # 3. Token / control-character / embedded-NUL / deep-recursion / 0777-ancestor redaction
                for hostile_raw in (
                    json.dumps({"schema_version": 1, "runs_dir": "/tmp/se-session-0123456789abcdef0123456789abcdef\x1b[31m"}) + "\n",
                    json.dumps({"schema_version": 1, "runs_dir": "/tmp/has\x00nul"}) + "\n",
                    ("[" * 500) + ("]" * 500),
                ):
                    ptr_path.write_text(hostile_raw, encoding="utf-8")
                    os.chmod(ptr_path, 0o600)
                    r_hostile = custody.inspect_active_runs_pointer(pin_fd=False)
                    self.assertEqual(r_hostile.status, "refused")
                    self.assertNotIn("se-session-", r_hostile.message or "")
                    self.assertNotIn("\x1b", r_hostile.message or "")
                    self.assertNotIn("\x00", r_hostile.message or "")
                    self.assertNotIn("se-session-", r_hostile.remediation or "")

                # Sentinel-bearing 0777 ancestor must NOT leak ancestor name in refusal message!
                world_parent = tmp_path / "SENTINEL_WORLD_ANCESTOR_777"
                world_parent.mkdir(mode=0o700)
                os.chmod(world_parent, 0o777)
                world_runs = world_parent / "runs"
                world_runs.mkdir(mode=0o700)
                try:
                    ptr_path.write_text(json.dumps({"schema_version": 1, "runs_dir": str(world_runs)}) + "\n", encoding="utf-8")
                    os.chmod(ptr_path, 0o600)
                    r_world = custody.inspect_active_runs_pointer(pin_fd=False, allow_code_root_ancestors=False)
                    self.assertEqual(r_world.status, "refused")
                    self.assertEqual(r_world.reason_code, "target_untrusted_ancestor")
                    self.assertFalse(r_world.ancestor_owned_group_writable)
                    self.assertNotIn("SENTINEL_WORLD_ANCESTOR_777", r_world.message or "")
                    self.assertNotIn("SENTINEL_WORLD_ANCESTOR_777", r_world.remediation or "")
                    self.assertIsNone(r_world.untrusted_ancestor)
                finally:
                    os.chmod(world_parent, 0o700)

                # Owned 0770 ancestor with spaces emits shell-quoted chmod whose operand round-trips to the exact path!
                import shlex as _shlex

                space_parent = tmp_path / "gw dev dir"
                space_parent.mkdir(mode=0o700)
                os.chmod(space_parent, 0o770)
                space_runs = space_parent / "runs"
                space_runs.mkdir(mode=0o700)
                try:
                    ptr_path.write_text(json.dumps({"schema_version": 1, "runs_dir": str(space_runs)}) + "\n", encoding="utf-8")
                    os.chmod(ptr_path, 0o600)
                    r_space = custody.inspect_active_runs_pointer(pin_fd=False, allow_code_root_ancestors=False)
                    self.assertEqual(r_space.status, "refused")
                    self.assertTrue(r_space.ancestor_owned_group_writable)
                    self.assertTrue(r_space.ancestor_path_shell_safe)
                    rem_text = r_space.remediation or ""
                    self.assertIn("chmod 0750 ", rem_text)
                    cmd_inner = rem_text.split("(", 1)[1].split(")", 1)[0]
                    parsed_argv = _shlex.split(cmd_inner)
                    self.assertEqual(parsed_argv[:2], ["chmod", "0750"])
                    self.assertEqual(Path(parsed_argv[2]).resolve(), space_parent.resolve())
                finally:
                    os.chmod(space_parent, 0o700)

                # Owned 0770 ancestor with Unicode line-separator escapes display text AND omits bogus chmod command!
                sp_parent = tmp_path / "gw dev\u2028dir"
                sp_parent.mkdir(mode=0o700)
                os.chmod(sp_parent, 0o770)
                sp_runs = sp_parent / "runs"
                sp_runs.mkdir(mode=0o700)
                try:
                    ptr_path.write_text(json.dumps({"schema_version": 1, "runs_dir": str(sp_runs)}) + "\n", encoding="utf-8")
                    os.chmod(ptr_path, 0o600)
                    r_sp = custody.inspect_active_runs_pointer(pin_fd=False, allow_code_root_ancestors=False)
                    self.assertEqual(r_sp.status, "refused")
                    self.assertTrue(r_sp.ancestor_owned_group_writable)
                    self.assertFalse(r_sp.ancestor_path_shell_safe)
                    self.assertNotIn("\u2028", r_sp.message or "")
                    self.assertIn("\\u2028", r_sp.message or "")
                    self.assertNotIn("chmod 0750", r_sp.remediation or "")
                    # write_active_runs_pointer warning also omits bogus chmod operand for escaped path!
                    fake_sp_anc = frozenset({str(sp_parent.resolve()), str(sp_runs.resolve())})
                    w_err = io.StringIO()
                    with (
                        patch.object(custody, "_CODE_ROOT_ANCESTORS", fake_sp_anc),
                        redirect_stderr(w_err),
                    ):
                        custody.write_active_runs_pointer(sp_runs)
                    self.assertIn("\\u2028", w_err.getvalue())
                    self.assertNotIn("chmod 0750", w_err.getvalue())
                finally:
                    os.chmod(sp_parent, 0o700)

                # 4. Non-blocking FIFO refusal (must never hang!)
                ptr_path.unlink()
                os.mkfifo(ptr_path, 0o600)
                try:
                    r_fifo = custody.inspect_active_runs_pointer(pin_fd=False)
                    self.assertEqual(r_fifo.status, "refused")
                    self.assertEqual(r_fifo.reason_code, "pointer_mode_invalid")
                finally:
                    ptr_path.unlink()

                # 5. 0770 group-writable ancestor refused when allow_code_root_ancestors=False
                gw_parent = tmp_path / "gw_dev"
                gw_parent.mkdir(mode=0o700)
                os.chmod(gw_parent, 0o770)
                gw_runs = gw_parent / "runs"
                gw_runs.mkdir(mode=0o700)
                try:
                    ptr_path.write_text(json.dumps({"schema_version": 1, "runs_dir": str(gw_runs)}) + "\n", encoding="utf-8")
                    os.chmod(ptr_path, 0o600)
                    r_gw = custody.inspect_active_runs_pointer(pin_fd=False, allow_code_root_ancestors=False)
                    self.assertEqual(r_gw.status, "refused")
                    self.assertEqual(r_gw.reason_code, "target_untrusted_ancestor")
                    self.assertTrue(r_gw.ancestor_owned_group_writable)
                    self.assertIn("chmod 0750", r_gw.remediation or "")
                finally:
                    os.chmod(gw_parent, 0o700)

                # 6. Parent-chain swaps on BOTH post-read AND ENOENT for both .config and free-inference
                for swap_target in ("free-inference", ".config"):
                    for mode_kind in ("post_read", "enoent"):
                        h_sw = tmp_path / f"h_{swap_target.strip('.')}_{mode_kind}"
                        h_sw.mkdir(mode=0o700)
                        c_sw = h_sw / ".config"
                        c_sw.mkdir(mode=0o700)
                        f_sw = c_sw / "free-inference"
                        f_sw.mkdir(mode=0o700)
                        os.chmod(f_sw, 0o700)
                        p_sw = f_sw / "active-runs.json"
                        if mode_kind == "post_read":
                            p_sw.write_text(json.dumps({"schema_version": 1, "runs_dir": str(live_runs)}) + "\n", encoding="utf-8")
                            os.chmod(p_sw, 0o600)

                        def _do_swap(_t=swap_target, _c=c_sw, _f=f_sw) -> None:
                            if _t == "free-inference":
                                _f.rename(_c / "free-inference.old")
                                _f.mkdir(mode=0o700)
                                os.chmod(_f, 0o700)
                            else:
                                _c.rename(_c.parent / ".config.old")
                                _c.mkdir(mode=0o700)

                        with (
                            patch.object(custody, "_resolve_passwd_home_dir", return_value=h_sw),
                            patch.object(custody, "_before_pointer_chain_recheck_hook", side_effect=_do_swap),
                        ):
                            r_sw = custody.inspect_active_runs_pointer(pin_fd=False)
                        self.assertEqual(r_sw.status, "refused", f"{swap_target}/{mode_kind}")
                        self.assertEqual(r_sw.reason_code, "config_dir_untrusted", f"{swap_target}/{mode_kind}")

                custody.clear_pinned_pointer_fd()

    def test_write_active_runs_pointer_advisory_portability_warning_and_io_safety(self) -> None:
        from local_assist import custody

        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            tmp_path = Path(tmp)
            fake_home = tmp_path / "home"
            fake_home.mkdir(mode=0o700)
            gw_parent = tmp_path / "gw_dev"
            gw_parent.mkdir(mode=0o700)
            os.chmod(gw_parent, 0o770)
            gw_runs = gw_parent / "runs"
            gw_runs.mkdir(mode=0o700)
            try:
                fake_ancestors = frozenset({str(gw_parent.resolve()), str(gw_runs.resolve())})
                out_buf = io.StringIO()
                err_buf = io.StringIO()
                with (
                    patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home),
                    patch.object(custody, "_CODE_ROOT_ANCESTORS", fake_ancestors),
                    redirect_stdout(out_buf),
                    redirect_stderr(err_buf),
                ):
                    ptr = custody.write_active_runs_pointer(gw_runs)
                self.assertTrue(ptr.is_file())
                self.assertEqual(out_buf.getvalue(), "")
                err_lines = [ln for ln in err_buf.getvalue().splitlines() if ln.strip()]
                self.assertEqual(len(err_lines), 1)
                self.assertIn("WARNING:", err_lines[0])
                self.assertIn("chmod 0750", err_lines[0])

                # Non-chmod portability failure (e.g. target_identity_changed) must NOT suggest chmod
                fake_non_chmod = custody._build_pointer_refusal("target_identity_changed")
                err_buf2 = io.StringIO()
                with (
                    patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home),
                    patch.object(custody, "_CODE_ROOT_ANCESTORS", fake_ancestors),
                    patch.object(custody, "check_runs_dir_custody_portability", return_value=fake_non_chmod),
                    redirect_stderr(err_buf2),
                ):
                    ptr2 = custody.write_active_runs_pointer(gw_runs)
                self.assertTrue(ptr2.is_file())
                self.assertIn("WARNING:", err_buf2.getvalue())
                self.assertNotIn("chmod", err_buf2.getvalue())

                # Broken stderr write must NEVER fail an already-committed publication!
                class _BrokenStderr:
                    def write(self, _s: str) -> int:
                        raise OSError("broken pipe")

                with (
                    patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home),
                    patch.object(custody, "_CODE_ROOT_ANCESTORS", fake_ancestors),
                    patch.object(sys, "stderr", _BrokenStderr()),
                ):
                    ptr3 = custody.write_active_runs_pointer(gw_runs)
                self.assertTrue(ptr3.is_file())
            finally:
                os.chmod(gw_parent, 0o700)

    def test_custody_refused_pointer_cli_and_resolver_precedence(self) -> None:
        from local_assist import custody, registry, session as sess_mod

        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            tmp_path = Path(tmp)
            fake_home = tmp_path / "home"
            fake_home.mkdir(mode=0o700)
            fi_dir = fake_home / ".config" / "free-inference"
            fi_dir.mkdir(parents=True, mode=0o700)
            os.chmod(fake_home / ".config", 0o700)
            os.chmod(fi_dir, 0o700)

            gw_parent = tmp_path / "gw_dev"
            gw_parent.mkdir(mode=0o700)
            os.chmod(gw_parent, 0o770)
            gw_runs = gw_parent / "runs"
            gw_runs.mkdir(mode=0o700)
            ptr_path = fi_dir / "active-runs.json"
            ptr_path.write_text(json.dumps({"schema_version": 1, "runs_dir": str(gw_runs)}) + "\n", encoding="utf-8")
            os.chmod(ptr_path, 0o600)

            try:
                # 1. Resolver precedence: worker_or_reap_cli with live DEFAULT_RUNS_DIR skips pointer even if is_custody_tree returns True!
                boot_worker = custody.CustodyBootstrapState(
                    custody_mode=False,
                    worker_or_reap_cli=True,
                    launcher_site_packages=None,
                    cli_runs_dir=None,
                )
                with (
                    patch.object(custody, "get_active_bootstrap_state", return_value=boot_worker),
                    patch.object(registry, "_store_has_live_pid_record", return_value=True),
                    patch.object(custody, "is_custody_tree", return_value=True),
                    patch.object(custody, "inspect_active_runs_pointer") as mock_ptr,
                ):
                    resolved_dir, resolved_ptr = registry.resolve_effective_runs_dir_details()
                self.assertEqual(resolved_dir, registry.DEFAULT_RUNS_DIR)
                self.assertIsNone(resolved_ptr)
                mock_ptr.assert_not_called()

                # 2. Custody session status/watch/start/stop/renew on refused pointer WITH real fallback PID records on disk!
                fallback_runs = tmp_path / "fallback_custody_runs"
                fallback_runs.mkdir(mode=0o700)
                (fallback_runs / ".serve-tinfoil-deepseek-v4-1-flash-b41fc330.pid").write_text(
                    json.dumps({
                        "model_id": "tinfoil-deepseek-v4-1-flash",
                        "repo": "deepseek-v4-1-flash",
                        "pid": os.getpid(),
                        "pid_lstart": "Sat Nov 21 07:00:00 2026",
                        "session_token_file": str(fallback_runs / ".se-session-fake.token"),
                        "status": "ready",
                    }),
                    encoding="utf-8",
                )
                (fallback_runs / ".serve-qwen3-30b-a3b-2507-mlx-4bit-2aee4a3e.pid").write_text(
                    json.dumps({
                        "model_id": "qwen3-30b-a3b-2507-mlx-4bit",
                        "repo": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
                        "pid": os.getpid(),
                        "pid_lstart": "Sat Nov 21 07:00:00 2026",
                        "status": "ready",
                    }),
                    encoding="utf-8",
                )
                boot_custody = custody.CustodyBootstrapState(
                    custody_mode=True,
                    worker_or_reap_cli=False,
                    launcher_site_packages=None,
                    cli_runs_dir=None,
                )
                with (
                    patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home),
                    patch.object(custody, "get_active_bootstrap_state", return_value=boot_custody),
                    patch.object(custody, "is_custody_tree", return_value=True),
                    patch.object(registry, "DEFAULT_RUNS_DIR", fallback_runs),
                ):
                    for action in ("status", "watch"):
                        out_b = io.StringIO()
                        err_b = io.StringIO()
                        with redirect_stdout(out_b), redirect_stderr(err_b):
                            rc = sess_mod.main([action, "--model", "tinfoil-deepseek-v4-1-flash", "--json"])
                        self.assertEqual(rc, 1)
                        payload = json.loads(out_b.getvalue())
                        self.assertEqual(payload["state"], "UNKNOWN")
                        self.assertEqual(payload["pointer_status"], "refused")
                        self.assertEqual(payload["pointer_reason"], "target_untrusted_ancestor")
                        self.assertIn("chmod 0750", err_b.getvalue())

                    for action in ("start", "stop", "renew"):
                        err_b = io.StringIO()
                        with redirect_stderr(err_b):
                            rc = sess_mod.main([action, "--model", "tinfoil-deepseek-v4-1-flash"])
                        self.assertEqual(rc, 1)
                        self.assertIn("refused", err_b.getvalue().lower())

                # 3. Real CLI scripts/opencode-attested and scripts/opencode-local in custody mode WITH real fallback PID records:
                #    - Refused pointer -> exit 1 (NOT exit 4 opencode_session_unavailable, zero launcher_exit.json)
                #    - Absent pointer + no live session -> opencode-attested worker mode exits 4 + launcher_exit.json;
                #      opencode-local --print-config preserves existing behavior (exit 0)
                att_mod = _load_script_module("opencode_attested_ptr_refusal", "scripts/opencode-attested")
                loc_mod = _load_script_module("opencode_local_ptr_refusal", "scripts/opencode-local")
                exit_file = tmp_path / "launcher_exit.json"
                with (
                    patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home),
                    patch.object(custody, "get_active_bootstrap_state", return_value=boot_custody),
                    patch.object(custody, "is_custody_tree", return_value=True),
                    patch.object(registry, "DEFAULT_RUNS_DIR", fallback_runs),
                ):
                    err_att = io.StringIO()
                    with redirect_stderr(err_att):
                        rc_att = att_mod.main([
                            "--unattended-worker",
                            "--model", "tinfoil-deepseek-v4-1-flash",
                            "--run-token", "run-token-ptr-refused-1",
                            "--launcher-exit-file", str(exit_file),
                            "--", "run", "hi",
                        ])
                    self.assertEqual(rc_att, 1)
                    self.assertFalse(exit_file.exists(), "Refused pointer must not emit exit-4 launcher_exit.json")
                    self.assertIn("refused", err_att.getvalue().lower())

                    err_loc = io.StringIO()
                    with redirect_stderr(err_loc):
                        rc_loc = loc_mod.main(["opencode-local", "--print-config"])
                    self.assertEqual(rc_loc, 1)
                    self.assertIn("refused", err_loc.getvalue().lower())

                # Absent pointer + no live session -> attested worker mode preserves exit 4 + launcher_exit.json;
                # opencode-local --print-config preserves existing exit 0 behavior!
                ptr_path.unlink()
                fake_oc = tmp_path / "fake-opencode"
                fake_oc.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                os.chmod(fake_oc, 0o755)
                fake_sb = tmp_path / "fake-sandbox-exec"
                fake_sb.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                os.chmod(fake_sb, 0o755)
                empty_runs = tmp_path / "empty_custody_runs"
                empty_runs.mkdir(mode=0o700)
                loc_iso_home = tmp_path / "loc_iso_home"
                with (
                    patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home),
                    patch.object(custody, "get_active_bootstrap_state", return_value=boot_custody),
                    patch.object(custody, "is_custody_tree", return_value=True),
                    patch.object(registry, "DEFAULT_RUNS_DIR", empty_runs),
                    patch.object(att_mod, "resolve_opencode_binary", return_value=(str(fake_oc), None)),
                    patch.dict(os.environ, {"FREE_INFERENCE_SANDBOX_EXEC_BIN": str(fake_sb)}, clear=False),
                    redirect_stderr(io.StringIO()),
                ):
                    rc_abs = att_mod.main([
                        "--unattended-worker",
                        "--model", "tinfoil-deepseek-v4-1-flash",
                        "--run-token", "run-token-ptr-absent-1",
                        "--launcher-exit-file", str(exit_file),
                        "--", "run", "hi",
                    ])
                    out_loc_abs = io.StringIO()
                    with (
                        patch.object(loc_mod, "_resolve_isolated_home", return_value=loc_iso_home),
                        patch.object(loc_mod, "ensure_model_served", return_value=(True, "")) as mock_loc_serve,
                        redirect_stdout(out_loc_abs),
                    ):
                        rc_loc_abs = loc_mod.main(["opencode-local", "--print-config"])
                    mock_loc_serve.assert_called_once()
                self.assertEqual(rc_abs, 4)
                self.assertTrue(exit_file.is_file())
                ex_doc = json.loads(exit_file.read_text(encoding="utf-8"))
                self.assertEqual(ex_doc["reason"], "opencode_session_unavailable")
                self.assertEqual(rc_loc_abs, 0)
                self.assertIn("private-local", out_loc_abs.getvalue())
            finally:
                os.chmod(gw_parent, 0o700)


if __name__ == "__main__":
    unittest.main()
