from __future__ import annotations

import errno
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from local_assist import custody, doctor, se_key  # noqa: E402
from local_assist.session import control_path  # noqa: E402

SHORT_TMP_DIR = "/tmp" if Path("/tmp").is_dir() else tempfile.gettempdir()


def _can_connect_unix_socket() -> bool:
    try:
        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            sp = Path(tmp) / "probe.sock"
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                srv.bind(str(sp))
                srv.listen(1)
                cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    cli.connect(str(sp))
                    return True
                finally:
                    cli.close()
            finally:
                srv.close()
    except OSError:
        return False


CAN_CONNECT_UNIX_SOCKET = _can_connect_unix_socket()


def _make_fake_root(base: Path) -> Path:
    root = base / "repo"
    root.mkdir(mode=0o700)
    shutil.copy2(ROOT / "models.yaml", root / "models.yaml")
    shutil.copy2(ROOT / "promptfooconfig.yaml", root / "promptfooconfig.yaml")
    shutil.copytree(ROOT / "docs", root / "docs")
    shutil.copytree(ROOT / "evals", root / "evals")
    shutil.copytree(ROOT / "config", root / "config")
    (root / "scripts").mkdir(mode=0o700)
    shutil.copy2(ROOT / "scripts" / "generate-eval-manifest", root / "scripts" / "generate-eval-manifest")
    shutil.copy2(ROOT / "scripts" / "render-suite", root / "scripts" / "render-suite")
    (root / "tools" / "se_key_proxy").mkdir(parents=True, mode=0o700)
    shutil.copy2(ROOT / "tools" / "se_key_proxy" / "main.swift", root / "tools" / "se_key_proxy" / "main.swift")
    return root


def _start_fake_control_server(sock_path: Path, payload: dict) -> tuple[socket.socket, threading.Thread, threading.Event]:
    sock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(sock_path.parent, 0o700)
    if sock_path.exists():
        sock_path.unlink()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(sock_path))
    os.chmod(sock_path, 0o600)
    srv.listen(4)
    srv.settimeout(0.2)
    stop_ev = threading.Event()
    wire = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")

    def _serve() -> None:
        while not stop_ev.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                try:
                    conn.recv(4096)
                    conn.sendall(wire)
                except OSError:
                    pass

    th = threading.Thread(target=_serve, daemon=True)
    th.start()
    return srv, th, stop_ev


class DoctorTests(unittest.TestCase):
    def test_exit_code_matrix_default_vs_strict(self) -> None:
        for overall, expected_default, expected_strict in (
            ("pass", 0, 0),
            ("warn", 0, 1),
            ("fail", 1, 1),
        ):
            fake_report = {
                "schema_version": 1,
                "platform": {"system": "Linux", "machine": "x86_64", "python": "3.13.0"},
                "overall": overall,
                "counts": {"pass": 1, "warn": int(overall == "warn"), "fail": int(overall == "fail"), "skip": 0},
                "checks": [
                    {
                        "id": "synthetic",
                        "status": overall,
                        "summary": f"synthetic {overall}",
                        "details": {},
                        "remediation": None,
                    }
                ],
            }
            with patch.object(doctor, "run_doctor", return_value=fake_report):
                out_def = io.StringIO()
                with redirect_stdout(out_def):
                    rc_def = doctor.main(["--json"])
                self.assertEqual(rc_def, expected_default)
                parsed = json.loads(out_def.getvalue())
                self.assertEqual(parsed["overall"], overall)

                out_strict = io.StringIO()
                with redirect_stdout(out_strict):
                    rc_strict = doctor.main(["--json", "--strict"])
                self.assertEqual(rc_strict, expected_strict)

    def test_bootstrap_error_and_cli_parse_errors_use_safe_static_exit_1(self) -> None:
        secret_sentinel = "SECRET-PINNED-STAT-TOKEN-987654"
        env = dict(os.environ)
        env[custody.PINNED_RUNS_STAT_ENV_VAR] = secret_sentinel
        cp = subprocess.run(
            [sys.executable, "-I", "-B", str(ROOT / "scripts" / "doctor"), "--json"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        self.assertEqual(cp.returncode, 1)
        self.assertNotIn(secret_sentinel, cp.stderr)
        self.assertNotIn(secret_sentinel, cp.stdout)
        self.assertIn("pinned session store identity", cp.stderr.lower())

        # CLI parse errors emit static stderr and exit 1 (never echoing raw unknown flag), while --help exits 0
        bogus_flag = "--bogus-secret-flag-12345"
        err_cli = io.StringIO()
        with redirect_stderr(err_cli):
            rc_bad = doctor.main([bogus_flag])
        self.assertEqual(rc_bad, 1)
        self.assertNotIn(bogus_flag, err_cli.getvalue())
        self.assertIn("invalid cli arguments", err_cli.getvalue().lower())

        cp_help = subprocess.run(
            [sys.executable, "-I", "-B", str(ROOT / "scripts" / "doctor"), "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(cp_help.returncode, 0)

    def test_zero_write_offline_and_never_executes_opencode_or_hostile_path_shims(self) -> None:
        def _tree_snapshot(base: Path) -> list[tuple[str, int, int, str | None]]:
            rows: list[tuple[str, int, int, str | None]] = []
            for dirpath, dirnames, filenames in os.walk(base):
                dirnames.sort()
                filenames.sort()
                for name in [*dirnames, *filenames]:
                    full = Path(dirpath) / name
                    st = os.lstat(full)
                    digest = (
                        hashlib.sha256(full.read_bytes()).hexdigest()
                        if stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode)
                        else None
                    )
                    rows.append((str(full.relative_to(base)), st.st_mode, st.st_size, digest))
            return rows

        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            tmp_path = Path(tmp)
            fake_home = tmp_path / "home"
            fake_home.mkdir(mode=0o700)
            host_oc_cfg = fake_home / ".config" / "opencode"
            host_oc_share = fake_home / ".local" / "share" / "opencode"
            host_oc_cfg.mkdir(parents=True, mode=0o700)
            os.chmod(fake_home / ".config", 0o700)
            host_oc_share.mkdir(parents=True, mode=0o700)
            sentinel_cfg = host_oc_cfg / "sentinel.txt"
            sentinel_cfg.write_text("unchanged-cfg", encoding="utf-8")

            shim_dir = tmp_path / "hostile_bin"
            shim_dir.mkdir(mode=0o700)
            marker_file = tmp_path / "shim_executed.marker"
            for bin_name in ("opencode", "swiftc", "codesign", "ps"):
                shim = shim_dir / bin_name
                shim.write_text(
                    f"#!/bin/sh\necho {bin_name} >> {marker_file}\nexit 99\n",
                    encoding="utf-8",
                )
                os.chmod(shim, 0o755)

            fake_root = _make_fake_root(tmp_path)
            # Copy local_assist + scripts/doctor into fake_root so we can run the real CLI subprocess
            # against a read-only 0500 tree and prove zero bytecode / zero scratch writes!
            shutil.copytree(
                ROOT / "local_assist",
                fake_root / "local_assist",
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
            shutil.copy2(ROOT / "scripts" / "doctor", fake_root / "scripts" / "doctor")
            os.chmod(fake_root / "scripts" / "doctor", 0o755)

            # Populate se-key-proxy stamp + binary with matching pinned swiftc version (when on Darwin)
            # AND a live PID record so swiftc, codesign, and ps are ALL challenged!
            (fake_root / "bin").mkdir(mode=0o700)
            fake_se_bin = fake_root / "bin" / "se-key-proxy"
            fake_se_bin.write_bytes(b"fake-bin")
            os.chmod(fake_se_bin, 0o755)
            swiftc_ver_str = "Apple Swift version 6.0"
            if sys.platform == "darwin":
                _, sp_sw = doctor._run_pinned_system_cmd(
                    (doctor.DARWIN_SWIFTC_BIN,),
                    ["--version"],
                    env=doctor.FIXED_SYSTEM_ENV,
                )
                if sp_sw is not None and sp_sw.returncode == 0 and (sp_sw.stdout or "").strip():
                    swiftc_ver_str = sp_sw.stdout.strip().splitlines()[0].strip()
            (fake_root / "bin" / ".se-key-proxy.stamp").write_text(
                json.dumps({
                    "source_sha256": se_key.EXPECTED_SWIFT_SOURCE_SHA256,
                    "swiftc_version": swiftc_ver_str,
                    "binary_sha256": hashlib.sha256(b"fake-bin").hexdigest(),
                }),
                encoding="utf-8",
            )
            live_runs = tmp_path / "live_runs"
            live_runs.mkdir(mode=0o700)
            (live_runs / ".serve-loc.pid").write_text(
                json.dumps({
                    "model_id": "qwen3-30b-a3b-2507-mlx-4bit",
                    "pid": os.getpid(),
                    "pid_lstart": "Sat Nov 21 00:00:00 2026",
                    "status": "ready",
                }),
                encoding="utf-8",
            )
            st_lr = live_runs.lstat()

            # Mark fake_root and fake_root/local_assist read-only to prove zero writes (no __pycache__!)
            os.chmod(fake_root / "local_assist", 0o500)
            os.chmod(fake_root, 0o500)
            try:
                snap_root_before = _tree_snapshot(fake_root)
                snap_home_before = _tree_snapshot(fake_home)
                env = {
                    "HOME": str(fake_home),
                    "PATH": f"{shim_dir}:/usr/bin:/bin",
                    "OPENCODE_CONFIG": str(tmp_path / "hostile-opencode.json"),
                    "OPENCODE_TEST_HOME": str(tmp_path / "hostile-test-home"),
                }
                seen_pinned_cmds: list[str] = []
                real_sub_run = subprocess.run

                def _spy_pinned(cmd, *a, **kw):
                    seen_pinned_cmds.append(str(cmd[0]))
                    return real_sub_run(cmd, *a, **kw)

                with (
                    patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home),
                    patch.object(doctor, "_resolve_passwd_home_dir", return_value=fake_home),
                    patch.object(doctor.subprocess, "run", side_effect=_spy_pinned),
                    patch.dict(os.environ, env, clear=False),
                ):
                    rep = doctor.run_doctor(
                        root=fake_root,
                        cli_runs_dir=live_runs.resolve(),
                        cli_runs_stat=(st_lr.st_dev, st_lr.st_ino),
                        in_custody=False,
                        env=env,
                    )
                    # Also verify a trusted 0500 read-only custody checkout with NO runs/ and absent pointer passes!
                    rep_ro_custody = doctor.run_doctor(root=fake_root, in_custody=True, env=env)

                # Run the real scripts/doctor executable directly as shipped (fixed-prefix /bin/sh wrapper
                # invoking trusted python3 with -I -B, ignoring caller PATH and PYTHONPATH!) with hostile shims
                # for BOTH python3 and non-python tools plus a poisoned PYTHONPATH, and verify valid JSON,
                # exact exit code, zero hostile shim execution, and ZERO writes to fake_root or fake_home!
                hostile_py = shim_dir / "python3"
                hostile_py.write_text(f"#!/bin/sh\necho poisoned-python3 >> {marker_file}\nexit 99\n", encoding="utf-8")
                os.chmod(hostile_py, 0o755)
                poison_pypath = tmp_path / "poison_pypath"
                poison_pypath.mkdir(mode=0o700)
                (poison_pypath / "local_assist.py").write_text(
                    f"import pathlib; pathlib.Path({str(marker_file)!r}).write_text('poisoned-pythonpath')\n",
                    encoding="utf-8",
                )
                cli_env = dict(env)
                cli_env["PATH"] = f"{shim_dir}:/usr/bin:/bin"
                cli_env["PYTHONPATH"] = str(poison_pypath)
                cli_env["SHELLOPTS"] = "xtrace:verbose"
                cli_cp = subprocess.run(
                    [str(fake_root / "scripts" / "doctor"), "--json"],
                    capture_output=True,
                    text=True,
                    env=cli_env,
                    check=False,
                )
                self.assertNotIn("exec /", cli_cp.stderr)
                cli_rep = json.loads(cli_cp.stdout)
                self.assertEqual(cli_rep["schema_version"], 1)
                self.assertEqual(cli_cp.returncode, 1 if cli_rep["overall"] == "fail" else 0)
                self.assertTrue(any(c["id"] == "platform_runtime" for c in cli_rep["checks"]))
                self.assertFalse((fake_root / "local_assist" / "__pycache__").exists())

                # On macOS where Apple /usr/bin/python3 (<3.11) exists, also verify invoking the shipped
                # polyglot directly via /usr/bin/python3 -I -B produces valid JSON and ZERO home/cache writes!
                if sys.platform == "darwin" and os.path.isfile("/usr/bin/python3") and os.access("/usr/bin/python3", os.X_OK):
                    apple_env = dict(env)
                    apple_env["PATH"] = "/usr/bin:/bin"
                    apple_cp = subprocess.run(
                        ["/usr/bin/python3", "-I", "-B", str(fake_root / "scripts" / "doctor"), "--json"],
                        capture_output=True,
                        text=True,
                        env=apple_env,
                        check=False,
                    )
                    apple_rep = json.loads(apple_cp.stdout)
                    self.assertEqual(apple_rep["schema_version"], 1)
                    self.assertEqual(apple_rep["overall"], "fail")
                    self.assertEqual(apple_cp.returncode, 1)
                    self.assertTrue(any(c["id"] == "platform_runtime" and c["status"] == "fail" for c in apple_rep["checks"]))

                self.assertEqual(rep["schema_version"], 1)
                self.assertFalse(marker_file.exists(), "Hostile PATH shims (python3/opencode/swiftc/codesign/ps) and PYTHONPATH must never execute")
                if sys.platform == "darwin":
                    self.assertIn(doctor.DARWIN_SWIFTC_BIN, seen_pinned_cmds)
                    self.assertIn(doctor.DARWIN_CODESIGN_BIN, seen_pinned_cmds)
                    self.assertIn("/bin/ps", seen_pinned_cmds)
                self.assertEqual(_tree_snapshot(fake_root), snap_root_before)
                self.assertEqual(_tree_snapshot(fake_home), snap_home_before)
                plat_chk = next(c for c in rep["checks"] if c["id"] == "platform_runtime")
                self.assertTrue(plat_chk["details"]["opencode_discovered"])
                self.assertFalse(plat_chk["details"]["opencode_executed"])
                cat_chk = next(c for c in rep["checks"] if c["id"] == "catalog_drift")
                self.assertEqual(cat_chk["status"], "skip")

                ro_store_chk = next(c for c in rep_ro_custody["checks"] if c["id"] == "runs_store_and_pointer")
                ro_live_chk = next(c for c in rep_ro_custody["checks"] if c["id"] == "live_sessions")
                self.assertEqual(ro_store_chk["status"], "pass")
                self.assertEqual(ro_store_chk["details"]["store_status"], "absent")
                self.assertEqual(ro_live_chk["status"], "pass")
            finally:
                os.chmod(fake_root, 0o700)
                os.chmod(fake_root / "local_assist", 0o700)

    def test_unified_store_resolution_env_override_dangling_default_and_0770_portability(self) -> None:
        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            tmp_path = Path(tmp)
            fake_home = tmp_path / "home"
            fake_home.mkdir(mode=0o700)
            fake_root = _make_fake_root(tmp_path)

            # 1. Explicit FREE_INFERENCE_RUNS_DIR env override is audited directly (and leaves global pin untouched)
            env_store = tmp_path / "env_runs"
            env_store.mkdir(mode=0o700)
            st_env = env_store.lstat()
            with patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home):
                store = doctor._resolve_doctor_store(
                    fake_root,
                    cli_runs_dir=None,
                    cli_runs_stat=None,
                    env_runs_dir=env_store.resolve(),
                    env_runs_stat=(st_env.st_dev, st_env.st_ino),
                    in_custody=False,
                )
            self.assertEqual(store.source, "env_override")
            self.assertEqual(store.status, "ok")
            self.assertEqual(store.runs_dir, env_store.resolve())
            self.assertTrue(store.custody_portable)

            # 2. Dangling symlink at default runs dir fails (never passes as absent!)
            dangling = fake_root / "runs"
            dangling.symlink_to(tmp_path / "does-not-exist")
            try:
                with patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home):
                    store_dang = doctor._resolve_doctor_store(
                        fake_root,
                        cli_runs_dir=None,
                        cli_runs_stat=None,
                        env_runs_dir=None,
                        env_runs_stat=None,
                        in_custody=False,
                    )
                self.assertEqual(store_dang.status, "refused")
                chk_dang = doctor.check_runs_store_and_pointer(store_dang, in_custody=False)
                self.assertEqual(chk_dang.status, "fail")
            finally:
                dangling.unlink()

            # 3. Group-writable 0770 ancestor triggers warn in checkout and fail in custody
            gw_parent = tmp_path / "gw_dev"
            gw_parent.mkdir(mode=0o700)
            os.chmod(gw_parent, 0o770)
            gw_runs = gw_parent / "runs"
            gw_runs.mkdir(mode=0o700)
            try:
                fake_ancestors = frozenset({str(gw_parent.resolve()), str(gw_runs.resolve())})
                with (
                    patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home),
                    patch.object(custody, "_CODE_ROOT_ANCESTORS", fake_ancestors),
                ):
                    with redirect_stderr(io.StringIO()):
                        custody.write_active_runs_pointer(gw_runs)
                    store_co = doctor._resolve_doctor_store(
                        fake_root,
                        cli_runs_dir=None,
                        cli_runs_stat=None,
                        env_runs_dir=None,
                        env_runs_stat=None,
                        in_custody=False,
                    )
                    self.assertEqual(store_co.status, "ok")
                    self.assertFalse(store_co.custody_portable)
                    chk_co = doctor.check_runs_store_and_pointer(store_co, in_custody=False)
                    self.assertEqual(chk_co.status, "warn")
                    self.assertIn("chmod 0750", chk_co.remediation or "")

                    store_cus = doctor._resolve_doctor_store(
                        fake_root,
                        cli_runs_dir=None,
                        cli_runs_stat=None,
                        env_runs_dir=None,
                        env_runs_stat=None,
                        in_custody=True,
                    )
                    self.assertEqual(store_cus.status, "refused")
                    self.assertEqual(store_cus.reason_code, "target_untrusted_ancestor")
                    chk_cus = doctor.check_runs_store_and_pointer(store_cus, in_custody=True)
                    self.assertEqual(chk_cus.status, "fail")
            finally:
                os.chmod(gw_parent, 0o700)

    def test_metadata_only_se_envelopes_never_opens_payloads_and_catches_bad_modes(self) -> None:
        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            tmp_path = Path(tmp)
            fake_home = tmp_path / "home"
            fake_home.mkdir(mode=0o700)
            env_dir = fake_home / ".config" / "free-inference" / "se-envelopes"
            env_dir.mkdir(parents=True, mode=0o700)
            os.chmod(fake_home / ".config", 0o700)
            os.chmod(fake_home / ".config" / "free-inference", 0o700)
            os.chmod(env_dir, 0o700)

            stem = doctor._envelope_stem("free-inference.tinfoil")
            env_file = env_dir / f"{stem}.json"
            secret_payload = "TOP-SECRET-CIPHERTEXT-DO-NOT-OPEN-999999"
            env_file.write_text(secret_payload, encoding="utf-8")
            os.chmod(env_file, 0o600)

            opened_names: list[str] = []
            real_os_open = os.open

            def _tracking_open(path, *args, **kwargs):
                p_str = str(path)
                opened_names.append(p_str)
                return real_os_open(path, *args, **kwargs)

            with (
                patch.object(sys, "platform", "darwin"),
                patch.object(custody, "_resolve_passwd_home_dir", return_value=fake_home),
                patch.object(doctor, "_resolve_passwd_home_dir", return_value=fake_home),
                patch.object(os, "open", side_effect=_tracking_open),
            ):
                chk_ok = doctor.check_se_envelopes(ROOT)
            self.assertEqual(chk_ok.status, "pass")
            self.assertFalse(chk_ok.details["integrity_checked"])
            self.assertIn("free-inference.tinfoil", chk_ok.details["present_services"])
            self.assertFalse(any(stem in name for name in opened_names), "Envelope payload file must never be opened")
            self.assertNotIn(secret_payload, json.dumps(chk_ok.to_dict()))

            # Loose file mode 0644 -> fail without leaking payload
            os.chmod(env_file, 0o644)
            try:
                with (
                    patch.object(sys, "platform", "darwin"),
                    patch.object(doctor, "_resolve_passwd_home_dir", return_value=fake_home),
                ):
                    chk_bad = doctor.check_se_envelopes(ROOT)
                self.assertEqual(chk_bad.status, "fail")
                self.assertIn("free-inference.tinfoil", chk_bad.details["invalid_metadata_services"])
                self.assertNotIn(secret_payload, json.dumps(chk_bad.to_dict()))
            finally:
                os.chmod(env_file, 0o600)

    def test_model_registry_full_offline_ci_equivalence_catches_routing_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            fake_root = _make_fake_root(Path(tmp))
            chk_clean = doctor.check_model_registry(fake_root)
            self.assertEqual(chk_clean.status, "pass")
            self.assertTrue(chk_clean.details["offline_manifest_check_passed"])

            # Mutate a structurally valid manifest's routing metadata -> offline CI validator must reject it!
            ev_path = fake_root / "docs" / "evals" / "tinfoil-deepseek-v4-1-flash.json"
            data = json.loads(ev_path.read_text(encoding="utf-8"))
            data["routing_status"]["private_attested"] = "blocked"
            ev_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

            chk_bad = doctor.check_model_registry(fake_root)
            self.assertEqual(chk_bad.status, "fail")
            self.assertFalse(chk_bad.details["offline_manifest_check_passed"])
            self.assertGreater(chk_bad.details["offline_manifest_error_count"], 0)

    def test_linux_ps_usr_merged_candidate_fallback_with_zero_path_lookup(self) -> None:
        checked_paths: list[str] = []
        executed_cmds: list[list[str]] = []

        def _fake_verify(path_str: str) -> None:
            checked_paths.append(str(path_str))
            if str(path_str) == "/bin/ps":
                raise se_key.SEKeyIntegrityError("symlink ancestor /bin")

        def _fake_run(cmd, **kwargs):
            executed_cmds.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, stdout="Sat Nov 21 07:00:00 2026\n", stderr="")

        with (
            patch.object(sys, "platform", "linux"),
            patch.object(doctor, "verify_root_owned_binary_and_ancestors", side_effect=_fake_verify),
            patch.object(doctor.subprocess, "run", side_effect=_fake_run),
        ):
            out = doctor._doctor_ps_query(1234, "lstart")
        self.assertEqual(out, "Sat Nov 21 07:00:00 2026")
        self.assertEqual(checked_paths, ["/usr/bin/ps"])
        self.assertEqual(executed_cmds[0][0], "/usr/bin/ps")

    @unittest.skipUnless(CAN_CONNECT_UNIX_SOCKET, "Requires outer environment permitting AF_UNIX connect")
    def test_live_sessions_real_unix_control_socket_and_subprocess_allowlist(self) -> None:
        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            tmp_path = Path(tmp)
            runs = tmp_path / "runs"
            runs.mkdir(mode=0o700)
            st_runs = runs.lstat()
            store = doctor._DoctorStoreDecision(
                source="cli_override",
                status="ok",
                runs_dir=runs.resolve(),
                stat_id=(st_runs.st_dev, st_runs.st_ino),
                custody_portable=True,
            )

            my_pid = os.getpid()
            real_lstart = doctor._doctor_ps_query(my_pid, "lstart")
            if not real_lstart:
                self.skipTest("Requires pinned ps query on current process")
            model_att = "tinfoil-deepseek-v4-1-flash"
            sock_p = control_path(runs.resolve(), model_att)
            on_payload = {
                "protocol": 1,
                "session_id": "sess-test-1",
                "pid": my_pid,
                "model": "deepseek-v4-1-flash",
                "state": "ON",
                "generation": 1,
                "remaining_seconds": 3600,
                "expires_at": 2000000000,
                "requests_used": 5,
                "request_limit": 1000,
                "requests_remaining": 995,
                "window_seconds": 7200,
            }
            srv, th, stop_ev = _start_fake_control_server(sock_p, on_payload)
            try:
                (runs / ".serve-tinfoil-deepseek-v4-1-flash-0001.pid").write_text(
                    json.dumps({
                        "model_id": model_att,
                        "repo": "deepseek-v4-1-flash",
                        "pid": my_pid,
                        "pid_lstart": real_lstart,
                        "upstream_pid": my_pid,
                        "upstream_pid_lstart": real_lstart,
                        "session_token_file": str(runs / ".se-session-dummy.token"),
                        "status": "ready",
                    }),
                    encoding="utf-8",
                )
                (runs / ".serve-qwen3-30b-a3b-2507-mlx-4bit-0002.pid").write_text(
                    json.dumps({
                        "model_id": "qwen3-30b-a3b-2507-mlx-4bit",
                        "repo": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
                        "pid": my_pid,
                        "pid_lstart": real_lstart,
                        "status": "ready",
                    }),
                    encoding="utf-8",
                )

                seen_subprocs: list[str] = []
                real_sub_run = subprocess.run

                def _spy_run(cmd, *a, **kw):
                    seen_subprocs.append(str(cmd[0]))
                    return real_sub_run(cmd, *a, **kw)

                allowed_exes = {sys.executable, "/bin/ps", "/usr/bin/ps"}
                with patch.object(subprocess, "run", side_effect=_spy_run):
                    chk = doctor.check_live_sessions(ROOT, store)
                self.assertEqual(chk.status, "pass")
                self.assertEqual(chk.details["active_count"], 2)
                by_id = {s["model_id"]: s for s in chk.details["sessions"]}
                self.assertEqual(by_id[model_att]["category"], "active_attested")
                self.assertEqual(by_id["qwen3-30b-a3b-2507-mlx-4bit"]["category"], "active_local")
                self.assertTrue(by_id["qwen3-30b-a3b-2507-mlx-4bit"]["process_identity_only"])
                self.assertIn(sys.executable, seen_subprocs)
                self.assertTrue(any(e in ("/bin/ps", "/usr/bin/ps") for e in seen_subprocs))
                for exe in seen_subprocs:
                    self.assertIn(exe, allowed_exes)
            finally:
                stop_ev.set()
                srv.close()
                th.join(timeout=2)

    def test_live_sessions_complete_disjoint_dual_proxy_matrix_and_store_swap_guards(self) -> None:
        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            tmp_path = Path(tmp)
            runs = tmp_path / "runs"
            runs.mkdir(mode=0o700)
            st_runs = runs.lstat()
            store = doctor._DoctorStoreDecision(
                source="cli_override",
                status="ok",
                runs_dir=runs.resolve(),
                stat_id=(st_runs.st_dev, st_runs.st_ino),
                custody_portable=True,
            )

            my_pid = os.getpid()
            model_att = "tinfoil-deepseek-v4-1-flash"
            on_payload = {
                "protocol": 1,
                "session_id": "sess-test-1",
                "pid": my_pid,
                "model": "deepseek-v4-1-flash",
                "state": "ON",
                "generation": 1,
                "remaining_seconds": 3600,
                "expires_at": 2000000000,
                "requests_used": 5,
                "request_limit": 1000,
                "requests_remaining": 995,
                "window_seconds": 7200,
            }

            # 1. Active attested + active_local (process_identity_only) with descriptor-bound ctl_fd probe
            #    Simulate socket metadata on the placeholder file so this mocked test never requires AF_UNIX bind!
            ctl_d0 = runs / ".control"
            ctl_d0.mkdir(mode=0o700)
            os.chmod(ctl_d0, 0o700)
            sp0 = control_path(runs.resolve(), model_att)
            sp0.write_text("", encoding="utf-8")
            os.chmod(sp0, 0o600)
            real_os_stat = os.stat
            euid_now = os.geteuid() if hasattr(os, "geteuid") else 0

            def _mock_sock_stat(path, *a, **kw):
                st_r = real_os_stat(path, *a, **kw)
                if kw.get("dir_fd") is not None and str(path) == sp0.name:
                    return os.stat_result((
                        stat.S_IFSOCK | 0o600,
                        st_r.st_ino,
                        st_r.st_dev,
                        st_r.st_nlink,
                        euid_now,
                        st_r.st_gid,
                        st_r.st_size,
                        st_r.st_atime,
                        st_r.st_mtime,
                        st_r.st_ctime,
                    ))
                return st_r

            (runs / ".serve-tinfoil-deepseek-v4-1-flash-0001.pid").write_text(
                json.dumps({
                    "model_id": model_att,
                    "repo": "deepseek-v4-1-flash",
                    "pid": my_pid,
                    "pid_lstart": "LSTART-PRI",
                    "upstream_pid": my_pid + 1,
                    "upstream_pid_lstart": "LSTART-UP",
                    "session_token_file": str(runs / ".se-session-dummy.token"),
                    "status": "ready",
                }),
                encoding="utf-8",
            )
            (runs / ".serve-qwen3-30b-a3b-2507-mlx-4bit-0002.pid").write_text(
                json.dumps({
                    "model_id": "qwen3-30b-a3b-2507-mlx-4bit",
                    "repo": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
                    "pid": my_pid + 2,
                    "pid_lstart": "LSTART-LOC",
                    "status": "ready",
                }),
                encoding="utf-8",
            )
            with (
                patch.object(os, "stat", side_effect=_mock_sock_stat),
                patch.object(doctor, "_doctor_classify_pid_identity", return_value="matched"),
                patch.object(doctor, "_probe_control_socket_via_ctl_fd", return_value=on_payload),
            ):
                chk = doctor.check_live_sessions(ROOT, store)
            self.assertEqual(chk.status, "pass")
            self.assertEqual(chk.details["active_count"], 2)
            by_id = {s["model_id"]: s for s in chk.details["sessions"]}
            self.assertEqual(by_id[model_att]["category"], "active_attested")
            self.assertEqual(by_id["qwen3-30b-a3b-2507-mlx-4bit"]["category"], "active_local")
            self.assertTrue(by_id["qwen3-30b-a3b-2507-mlx-4bit"]["process_identity_only"])

            # 1b. Control-socket RecursionError on deeply nested JSON reply:
            #     stable store -> warn/unverifiable; replaced store -> fail/store_identity_changed!
            with (
                patch.object(os, "stat", side_effect=_mock_sock_stat),
                patch.object(doctor, "_doctor_classify_pid_identity", return_value="matched"),
                patch.object(doctor, "_probe_control_socket_via_ctl_fd", side_effect=RecursionError("deep json")),
            ):
                chk_rec_stable = doctor.check_live_sessions(ROOT, store)
            self.assertEqual(chk_rec_stable.status, "warn")
            by_id_rec = {s["model_id"]: s for s in chk_rec_stable.details["sessions"]}
            self.assertEqual(by_id_rec[model_att]["category"], "unverifiable")
            self.assertEqual(by_id_rec[model_att]["control_state"], "UNKNOWN")

            # 2. Disjoint dual-proxy matrix: degraded_attested wins over ON, OFF, and UNKNOWN for each unhealthy upstream
            for bad_up in ("dead", "reused", "unavailable"):
                for sock_state in ("ON", "OFF", "UNKNOWN"):
                    for f in runs.glob(".serve*.pid"):
                        f.unlink()
                    (runs / ".serve-att.pid").write_text(
                        json.dumps({
                            "model_id": model_att,
                            "repo": "deepseek-v4-1-flash",
                            "pid": 111,
                            "pid_lstart": "L1",
                            "upstream_pid": 222,
                            "upstream_pid_lstart": "L2",
                            "session_token_file": "tok",
                            "status": "ready",
                        }),
                        encoding="utf-8",
                    )

                    def _cls(pid, ls, _bad=bad_up):
                        return "matched" if pid == 111 else _bad

                    with (
                        patch.object(doctor, "_doctor_classify_pid_identity", side_effect=_cls),
                        patch.object(doctor, "_probe_attested_socket_via_runs_fd", return_value=(sock_state, None, True)),
                    ):
                        chk_deg = doctor.check_live_sessions(ROOT, store)
                    self.assertEqual(chk_deg.status, "warn")
                    self.assertEqual(
                        chk_deg.details["sessions"][0]["category"],
                        "degraded_attested",
                        f"Expected degraded_attested for upstream={bad_up}, socket={sock_state}",
                    )

            # 3. Expired authenticated OFF vs orphaned_upstream vs provisional starting null/null vs non-starting null/null vs asymmetric missing/null
            cases = [
                (
                    "expired_attested",
                    {
                        "model_id": model_att,
                        "repo": "deepseek-v4-1-flash",
                        "pid": 111,
                        "pid_lstart": "L1",
                        "upstream_pid": 222,
                        "upstream_pid_lstart": "L2",
                        "session_token_file": "tok",
                        "status": "ready",
                    },
                    {111: "matched", 222: "matched"},
                    ("OFF", None, True),
                    "expired_attested",
                ),
                (
                    "orphaned_upstream",
                    {
                        "model_id": model_att,
                        "repo": "deepseek-v4-1-flash",
                        "pid": 111,
                        "pid_lstart": "L1",
                        "upstream_pid": 222,
                        "upstream_pid_lstart": "L2",
                        "session_token_file": "tok",
                        "status": "ready",
                    },
                    {111: "dead", 222: "matched"},
                    ("UNKNOWN", None, True),
                    "orphaned_upstream",
                ),
                (
                    "starting_null_null_dead_is_stale",
                    {
                        "model_id": model_att,
                        "repo": "deepseek-v4-1-flash",
                        "pid": 111,
                        "pid_lstart": "L1",
                        "upstream_pid": None,
                        "upstream_pid_lstart": None,
                        "session_token_file": "tok",
                        "status": "starting",
                    },
                    {111: "dead"},
                    ("UNKNOWN", None, True),
                    "stale",
                ),
                (
                    "non_starting_null_null_matched_is_degraded",
                    {
                        "model_id": model_att,
                        "repo": "deepseek-v4-1-flash",
                        "pid": 111,
                        "pid_lstart": "L1",
                        "upstream_pid": None,
                        "upstream_pid_lstart": None,
                        "session_token_file": "tok",
                        "status": "ready",
                    },
                    {111: "matched"},
                    ("ON", None, True),
                    "degraded_attested",
                ),
                (
                    "asymmetric_missing_null_is_degraded",
                    {
                        "model_id": model_att,
                        "repo": "deepseek-v4-1-flash",
                        "pid": 111,
                        "pid_lstart": "L1",
                        "upstream_pid": None,
                        "session_token_file": "tok",
                        "status": "ready",
                    },
                    {111: "matched"},
                    ("ON", None, True),
                    "degraded_attested",
                ),
            ]
            for label, rec_obj, pid_map, sock_res, expected_cat in cases:
                for f in runs.glob(".serve*.pid"):
                    f.unlink()
                (runs / ".serve-case.pid").write_text(json.dumps(rec_obj), encoding="utf-8")
                with (
                    patch.object(doctor, "_doctor_classify_pid_identity", side_effect=lambda p, _l, m=pid_map: m.get(p, "unavailable")),
                    patch.object(doctor, "_probe_attested_socket_via_runs_fd", return_value=sock_res),
                ):
                    chk_case = doctor.check_live_sessions(ROOT, store)
                self.assertEqual(chk_case.status, "warn", label)
                self.assertEqual(chk_case.details["sessions"][0]["category"], expected_cat, label)

            # 4. Store replacement guards across:
            #    (a) empty scan (pre_aggregate_publish),
            #    (b) non-socket local record (pre_commit_record),
            #    (c) missing socket (post_socket_stat_error),
            #    (d) failed control exchange (post_socket_exchange_error),
            #    (e) successful control exchange (post_socket_exchange).
            for stage_name, setup_kind in (
                ("pre_aggregate_publish", "empty"),
                ("pre_commit_record", "local"),
                ("post_control_open_error", "attested_no_ctrl"),
                ("post_socket_stat_error", "attested_missing_sock"),
                ("post_socket_exchange_error", "attested_failed_exchange"),
                ("post_socket_exchange_error", "attested_recursion_exchange"),
                ("post_socket_exchange", "attested_ok_exchange"),
            ):
                swap_dir = tmp_path / f"swap_{stage_name}_{setup_kind}"
                swap_dir.mkdir(mode=0o700)
                st_sw = swap_dir.lstat()
                sw_store = doctor._DoctorStoreDecision(
                    source="cli_override",
                    status="ok",
                    runs_dir=swap_dir.resolve(),
                    stat_id=(st_sw.st_dev, st_sw.st_ino),
                    custody_portable=True,
                )
                if setup_kind == "local":
                    (swap_dir / ".serve-loc.pid").write_text(
                        json.dumps({"model_id": "qwen3-30b-a3b-2507-mlx-4bit", "pid": 100, "pid_lstart": "L", "status": "ready"}),
                        encoding="utf-8",
                    )
                elif setup_kind.startswith("attested"):
                    (swap_dir / ".serve-att.pid").write_text(
                        json.dumps({
                            "model_id": model_att,
                            "repo": "deepseek-v4-1-flash",
                            "pid": my_pid,
                            "pid_lstart": "L",
                            "session_token_file": "tok",
                            "status": "ready",
                        }),
                        encoding="utf-8",
                    )
                    if setup_kind != "attested_no_ctrl":
                        ctl_d = swap_dir / ".control"
                        ctl_d.mkdir(mode=0o700)
                        os.chmod(ctl_d, 0o700)
                        if setup_kind != "attested_missing_sock":
                            sp = control_path(swap_dir.resolve(), model_att)
                            sp.write_text("", encoding="utf-8")
                            os.chmod(sp, 0o600)

                swapped = [False]

                def _swap_hook(st_name: str, _target=stage_name, _dir=swap_dir, _flag=swapped) -> None:
                    if st_name == _target and not _flag[0]:
                        _flag[0] = True
                        moved = _dir.parent / f"{_dir.name}_moved"
                        _dir.rename(moved)
                        _dir.mkdir(mode=0o700)

                if setup_kind == "attested_ok_exchange":
                    probe_patch = patch.object(doctor, "_probe_control_socket_via_ctl_fd", return_value=on_payload)
                elif setup_kind == "attested_recursion_exchange":
                    probe_patch = patch.object(doctor, "_probe_control_socket_via_ctl_fd", side_effect=RecursionError("deep json"))
                else:
                    probe_patch = patch.object(doctor, "_probe_control_socket_via_ctl_fd", side_effect=OSError(errno.ECONNREFUSED, "refused"))
                with (
                    patch.object(os, "stat", side_effect=_mock_sock_stat),
                    patch.object(doctor, "_before_live_sessions_store_check_hook", side_effect=_swap_hook),
                    patch.object(doctor, "_doctor_classify_pid_identity", return_value="matched"),
                    probe_patch,
                ):
                    chk_sw = doctor.check_live_sessions(ROOT, sw_store)
                self.assertEqual(chk_sw.status, "fail", f"stage={stage_name}/{setup_kind}")
                self.assertEqual(chk_sw.details.get("reason_code"), "store_identity_changed", f"stage={stage_name}/{setup_kind}")

    def test_remaining_checks_se_key_proxy_attested_proxies_bpf_legacy_and_catalog(self) -> None:
        with tempfile.TemporaryDirectory(dir=SHORT_TMP_DIR) as tmp:
            tmp_path = Path(tmp)
            fake_root = _make_fake_root(tmp_path)

            # 1. se_key_proxy: non-Darwin skip; Darwin warn on missing stamp; Darwin fail on bad stamp without echoing secret stamp text
            with patch.object(sys, "platform", "linux"):
                self.assertEqual(doctor.check_se_key_proxy(fake_root).status, "skip")
            with patch.object(sys, "platform", "darwin"):
                self.assertEqual(doctor.check_se_key_proxy(fake_root).status, "warn")
                (fake_root / "bin").mkdir(mode=0o700)
                stamp_secret = "SECRET-STAMP-PAYLOAD-XYZ"
                (fake_root / "bin" / ".se-key-proxy.stamp").write_text(f"{{bad {stamp_secret}", encoding="utf-8")
                chk_bad_stamp = doctor.check_se_key_proxy(fake_root)
                self.assertEqual(chk_bad_stamp.status, "fail")
                self.assertEqual(chk_bad_stamp.details.get("reason_code"), "stamp_invalid")
                self.assertNotIn(stamp_secret, json.dumps(chk_bad_stamp.to_dict()))

                # Full pass path with mocked pinned /usr/bin/swiftc and /usr/bin/codesign
                fake_bin = fake_root / "bin" / "se-key-proxy"
                fake_bin.write_bytes(b"fake-se-key-proxy-binary")
                os.chmod(fake_bin, 0o755)
                bin_sha = hashlib.sha256(b"fake-se-key-proxy-binary").hexdigest()
                (fake_root / "bin" / ".se-key-proxy.stamp").write_text(
                    json.dumps({
                        "source_sha256": se_key.EXPECTED_SWIFT_SOURCE_SHA256,
                        "swiftc_version": "Apple Swift version 6.0",
                        "binary_sha256": bin_sha,
                    }),
                    encoding="utf-8",
                )

                def _fake_pinned(cands, args, *, env, timeout=10.0):
                    if cands == (doctor.DARWIN_SWIFTC_BIN,):
                        return doctor.DARWIN_SWIFTC_BIN, subprocess.CompletedProcess([], 0, stdout="Apple Swift version 6.0\n", stderr="")
                    return doctor.DARWIN_CODESIGN_BIN, subprocess.CompletedProcess([], 0, stdout="", stderr="")

                with patch.object(doctor, "_run_pinned_system_cmd", side_effect=_fake_pinned):
                    chk_se_ok = doctor.check_se_key_proxy(fake_root)
                self.assertEqual(chk_se_ok.status, "pass")

            # 2. attested_proxies: non-Darwin pass on valid manifest; fail on tampered manifest; Darwin warn on missing tinfoil-proxy;
            #    non-regular tinfoil-proxy, privatemode-proxy, and .privatemode-proxy.stamp all FAIL (never reported as missing!)
            with patch.object(sys, "platform", "linux"):
                self.assertEqual(doctor.check_attested_proxies(fake_root).status, "pass")
            with patch.object(sys, "platform", "darwin"):
                self.assertEqual(doctor.check_attested_proxies(fake_root).status, "warn")
                (fake_root / "bin" / "tinfoil-proxy").mkdir(mode=0o700)
                chk_tf_dir = doctor.check_attested_proxies(fake_root)
                self.assertEqual(chk_tf_dir.status, "fail")
                self.assertEqual(chk_tf_dir.details.get("tinfoil_proxy_reason"), "tinfoil_nonregular")
                (fake_root / "bin" / "tinfoil-proxy").rmdir()

                (fake_root / "bin" / "privatemode-proxy").mkdir(mode=0o700)
                chk_pm_dir = doctor.check_attested_proxies(fake_root)
                self.assertEqual(chk_pm_dir.status, "fail")
                self.assertEqual(chk_pm_dir.details.get("privatemode_proxy_reason"), "privatemode_nonregular")
                (fake_root / "bin" / "privatemode-proxy").rmdir()

                pm_bin_file = fake_root / "bin" / "privatemode-proxy"
                pm_bin_file.write_bytes(b"pm-bin")
                os.chmod(pm_bin_file, 0o755)
                (fake_root / "bin" / ".privatemode-proxy.stamp").mkdir(mode=0o700)
                chk_pms_dir = doctor.check_attested_proxies(fake_root)
                self.assertEqual(chk_pms_dir.status, "fail")
                self.assertEqual(chk_pms_dir.details.get("privatemode_proxy_reason"), "privatemode_stamp_nonregular")
                (fake_root / "bin" / ".privatemode-proxy.stamp").rmdir()
                pm_bin_file.unlink()

            # 2b. Oversized PID integer, deeply nested JSON PID file, and malformed .serve*.pid never abort or disappear!
            bad_runs = tmp_path / "bad_pid_runs"
            bad_runs.mkdir(mode=0o700)
            st_br = bad_runs.lstat()
            bad_store = doctor._DoctorStoreDecision(
                source="cli_override",
                status="ok",
                runs_dir=bad_runs.resolve(),
                stat_id=(st_br.st_dev, st_br.st_ino),
                custody_portable=True,
            )
            (bad_runs / ".serve-oversized.pid").write_text(
                json.dumps({"model_id": "qwen3-30b-a3b-2507-mlx-4bit", "pid": 10**100, "pid_lstart": "L", "status": "ready"}),
                encoding="utf-8",
            )
            (bad_runs / ".serve-nested.pid").write_text(("[" * 1200) + ("]" * 1200), encoding="utf-8")
            (bad_runs / ".serve-corrupt.pid").write_text("{not-json", encoding="utf-8")
            chk_bad_pids = doctor.check_live_sessions(ROOT, bad_store)
            self.assertEqual(chk_bad_pids.status, "warn")
            self.assertEqual(chk_bad_pids.details["warn_count"], 3)
            self.assertEqual(len(chk_bad_pids.details["sessions"]), 3)
            cats = [s["category"] for s in chk_bad_pids.details["sessions"]]
            self.assertEqual(cats, ["unverifiable", "unverifiable", "unverifiable"])
            manifest_p = fake_root / doctor.PRIVATEMODE_MANIFEST_REL
            orig_manifest = manifest_p.read_bytes()
            manifest_p.write_bytes(b'{"tampered": true}\n')
            self.assertEqual(doctor.check_attested_proxies(fake_root).status, "fail")
            manifest_p.write_bytes(orig_manifest)

            # 3. bpf_permissions: non-Darwin skip; Darwin root 0600 pass vs group-readable 0640 fail
            with patch.object(sys, "platform", "linux"):
                self.assertEqual(doctor.check_bpf_permissions().status, "skip")
            fake_bpf_ok = os.stat_result((stat.S_IFCHR | 0o600, 1, 1, 1, 0, 0, 0, 0, 0, 0))
            fake_bpf_bad = os.stat_result((stat.S_IFCHR | 0o640, 1, 1, 1, 0, 20, 0, 0, 0, 0))
            with patch.object(sys, "platform", "darwin"), patch.object(os, "lstat", return_value=fake_bpf_ok):
                self.assertEqual(doctor.check_bpf_permissions().status, "pass")
            with patch.object(sys, "platform", "darwin"), patch.object(os, "lstat", return_value=fake_bpf_bad):
                self.assertEqual(doctor.check_bpf_permissions().status, "fail")

            # 4. legacy_containment: clean pass vs uncontained fail
            self.assertEqual(doctor.check_legacy_containment(fake_root, in_custody=False, env={}).status, "pass")
            legacy_cfg = fake_root / ".home" / "opencode-private-attested" / ".config" / "opencode"
            legacy_cfg.mkdir(parents=True, mode=0o700)
            (legacy_cfg / "service.json").write_text('{"port": 1234}\n', encoding="utf-8")
            self.assertEqual(doctor.check_legacy_containment(fake_root, in_custody=False, env={}).status, "fail")

            # 5. catalog_drift: offline skip, mocked clean pass, mocked drift warn, mocked error fail
            self.assertEqual(doctor.check_catalog_drift(fake_root, enabled=False).status, "skip")
            from local_assist import catalog_sync

            clean_rep = type("_Rep", (), {"items": [], "disagreements": []})()
            drift_rep = type("_Rep", (), {"items": [object()], "disagreements": []})()
            with (
                patch.object(catalog_sync, "fetch_tinfoil_router_manifest", return_value={}),
                patch.object(catalog_sync, "fetch_tinfoil_openai_models", return_value={}),
                patch.object(catalog_sync, "compute_catalog_drift", return_value=clean_rep),
            ):
                self.assertEqual(doctor.check_catalog_drift(fake_root, enabled=True).status, "pass")
            with (
                patch.object(catalog_sync, "fetch_tinfoil_router_manifest", return_value={}),
                patch.object(catalog_sync, "fetch_tinfoil_openai_models", return_value={}),
                patch.object(catalog_sync, "compute_catalog_drift", return_value=drift_rep),
            ):
                self.assertEqual(doctor.check_catalog_drift(fake_root, enabled=True).status, "warn")
            with patch.object(catalog_sync, "fetch_tinfoil_router_manifest", side_effect=OSError("offline")):
                self.assertEqual(doctor.check_catalog_drift(fake_root, enabled=True).status, "fail")


if __name__ == "__main__":
    unittest.main()
