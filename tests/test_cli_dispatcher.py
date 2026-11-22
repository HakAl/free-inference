"""Offline unit and subprocess tests for scripts/free-inference and local_assist/cli.py."""

from __future__ import annotations

import errno
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from local_assist import __version__
from local_assist.cli import (
    COMMAND_SPECS,
    DispatchError,
    dispatch,
    format_usage,
    resolve_target_script,
)

SHIPPED_ENTRYPOINT = ROOT / "scripts" / "free-inference"
# Shell- and interpreter-owned variables subject to platform /bin/sh (e.g. bash-as-sh,
# dash) or CPython / macOS CoreFoundation startup normalization or removal prior to
# dispatcher code execution.
RUNTIME_MANAGED_ENV_KEYS = frozenset(
    {
        "PWD",
        "SHLVL",
        "_",
        "IFS",
        "OPTIND",
        "SHELLOPTS",
        "LC_CTYPE",
        "__CF_USER_TEXT_ENCODING",
        "__PYVENV_LAUNCHER__",
    }
)


def _make_executable(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)
    return path


def _materialize_temp_checkout(dest: Path) -> Path:
    """Copy shipped scripts/free-inference and local_assist/ without bytecode."""
    scripts_dir = dest / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    entrypoint = scripts_dir / "free-inference"
    shutil.copy2(SHIPPED_ENTRYPOINT, entrypoint)
    entrypoint.chmod(0o755)
    shutil.copytree(
        ROOT / "local_assist",
        dest / "local_assist",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    return entrypoint


def _find_bytecode_artifacts(root: Path) -> list[Path]:
    hits: list[Path] = []
    for path in root.rglob("*"):
        if path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}:
            hits.append(path)
    return hits


def _write_probe_fixture(path: Path, out_json: Path, exit_code: int) -> Path:
    """Write a standalone executable script that records argv, cwd, and env."""
    py_code = (
        "import json, os, sys\n"
        f"open({str(out_json)!r}, 'w', encoding='utf-8').write("
        "json.dumps({'argv': sys.argv, 'cwd': os.getcwd(), 'env': dict(os.environ)}))\n"
        f"raise SystemExit({exit_code})\n"
    )
    shebang = f"#!{sys.executable}\n"
    if len(shebang.encode("utf-8")) <= 100:
        content = shebang + py_code
    else:
        content = (
            "#!/bin/sh\n"
            f"exec {shlex.quote(sys.executable)} -I -B -c {shlex.quote(py_code)} \"$0\" \"$@\"\n"
        )
    return _make_executable(path, content)


class CliDispatcherUnitTests(unittest.TestCase):
    def test_dispatch_table_and_verbatim_forwarding(self) -> None:
        expected_targets = {
            "status": ("session", ("status",)),
            "doctor": ("doctor", ()),
            "models": ("models", ()),
            "session": ("session", ()),
            "local": ("opencode-local", ()),
            "attested": ("opencode-attested", ()),
            "delegate": ("delegate-local", ()),
            "sync": ("sync-model-catalog", ()),
            "setup": ("setup", ()),
            "se-key": ("se-key", ()),
            "serve": ("serve-model", ()),
            "stop": ("stop-model", ()),
            "verify": ("verify-served-model", ()),
        }
        self.assertEqual(set(COMMAND_SPECS.keys()), set(expected_targets.keys()))
        # Exported dispatch table itself must be immutable (MappingProxyType).
        with self.assertRaises(TypeError):
            COMMAND_SPECS["evil"] = COMMAND_SPECS["models"]  # type: ignore[index]

        with tempfile.TemporaryDirectory() as td:
            scripts_dir = Path(td) / "scripts"
            scripts_dir.mkdir()
            for script_name, _ in set(expected_targets.values()):
                _make_executable(scripts_dir / script_name, "#!/bin/sh\nexit 0\n")

            env_before = dict(os.environ)
            cwd_before = os.getcwd()

            for subcmd, (script_name, prefix_args) in expected_targets.items():
                calls: list[tuple[str, list[str]]] = []
                out = io.StringIO()
                err = io.StringIO()
                trailing = [
                    "--help",
                    "--version",
                    "--json",
                    "--runs-dir",
                    "/tmp/example",
                    "--",
                    "positional-arg",
                    "--raw-flag=1",
                ]
                rc = dispatch(
                    [subcmd, *trailing],
                    scripts_dir=scripts_dir,
                    exec_fn=lambda exe, argv: calls.append((exe, list(argv))),
                    stdout=out,
                    stderr=err,
                )
                self.assertEqual(rc, 0, msg=subcmd)
                self.assertEqual(out.getvalue(), "")
                self.assertEqual(err.getvalue(), "")
                expected_exe = str((scripts_dir / script_name).resolve())
                self.assertEqual(
                    calls,
                    [(expected_exe, [expected_exe, *prefix_args, *trailing])],
                )

            # Explicit help stop contract: prints built-in usage directly without executing stop-model.
            stop_calls: list[tuple[str, list[str]]] = []
            stop_out = io.StringIO()
            stop_err = io.StringIO()
            rc = dispatch(
                ["help", "stop"],
                scripts_dir=scripts_dir,
                exec_fn=lambda exe, argv: stop_calls.append((exe, list(argv))),
                stdout=stop_out,
                stderr=stop_err,
            )
            self.assertEqual(rc, 0)
            self.assertEqual(stop_calls, [])
            self.assertEqual(stop_err.getvalue(), "")
            self.assertIn("Usage: free-inference stop", stop_out.getvalue())
            self.assertIn("scripts/stop-model", stop_out.getvalue())

            # Python dispatcher must never mutate os.environ or cwd.
            self.assertEqual(dict(os.environ), env_before)
            self.assertEqual(os.getcwd(), cwd_before)

    def test_top_level_help_version_and_usage_errors(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            scripts_dir = Path(td) / "scripts"
            scripts_dir.mkdir()
            for spec in COMMAND_SPECS.values():
                _make_executable(scripts_dir / spec.script_name, "#!/bin/sh\nexit 0\n")

            # Help invocations list all 13 commands and never exec.
            for args in ([], ["-h"], ["--help"], ["help"]):
                calls: list[tuple[str, list[str]]] = []
                out = io.StringIO()
                err = io.StringIO()
                rc = dispatch(
                    args,
                    scripts_dir=scripts_dir,
                    exec_fn=lambda exe, argv: calls.append((exe, list(argv))),
                    stdout=out,
                    stderr=err,
                )
                self.assertEqual(rc, 0, msg=args)
                self.assertEqual(calls, [])
                self.assertEqual(err.getvalue(), "")
                self.assertEqual(out.getvalue(), format_usage())
                self.assertIn("to show help for a subcommand.", out.getvalue())
                self.assertNotIn("to forward '--help' to a subcommand.", out.getvalue())
                for name in COMMAND_SPECS:
                    self.assertIn(f"  {name} ", out.getvalue())

            # Version flags print exact package version and never exec.
            for args in (["--version"], ["-V"]):
                calls = []
                out = io.StringIO()
                err = io.StringIO()
                rc = dispatch(
                    args,
                    scripts_dir=scripts_dir,
                    exec_fn=lambda exe, argv: calls.append((exe, list(argv))),
                    stdout=out,
                    stderr=err,
                )
                self.assertEqual(rc, 0, msg=args)
                self.assertEqual(calls, [])
                self.assertEqual(err.getvalue(), "")
                self.assertEqual(out.getvalue(), f"free-inference {__version__}\n")

            # help <subcmd> forwards prefix_args + --help.
            for subcmd, expected_suffix in (
                ("models", ["--help"]),
                ("status", ["status", "--help"]),
            ):
                calls = []
                rc = dispatch(
                    ["help", subcmd],
                    scripts_dir=scripts_dir,
                    exec_fn=lambda exe, argv: calls.append((exe, list(argv))),
                    stdout=io.StringIO(),
                    stderr=io.StringIO(),
                )
                self.assertEqual(rc, 0, msg=subcmd)
                expected_exe = str(
                    (scripts_dir / COMMAND_SPECS[subcmd].script_name).resolve()
                )
                self.assertEqual(
                    calls, [(expected_exe, [expected_exe, *expected_suffix])]
                )

            # Invalid top-level invocations exit 2 on stderr with zero exec calls.
            for bad_args in (
                ["bogus"],
                ["--unknown"],
                ["help", "bogus"],
                ["help", "models", "extra"],
                ["--version", "extra"],
                ["-V", "extra"],
                ["--help", "extra"],
                ["-h", "extra"],
            ):
                calls = []
                out = io.StringIO()
                err = io.StringIO()
                rc = dispatch(
                    bad_args,
                    scripts_dir=scripts_dir,
                    exec_fn=lambda exe, argv: calls.append((exe, list(argv))),
                    stdout=out,
                    stderr=err,
                )
                self.assertEqual(rc, 2, msg=bad_args)
                self.assertEqual(calls, [])
                self.assertEqual(out.getvalue(), "")
                self.assertIn("Error:", err.getvalue())

    def test_confinement_missing_target_and_exec_oserror_translation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scripts_dir = root / "scripts"
            scripts_dir.mkdir()
            outside = _make_executable(root / "outside.sh", "#!/bin/sh\nexit 0\n")

            # Missing target script (including doctor on pre-Track-1 checkout).
            out = io.StringIO()
            err = io.StringIO()
            calls: list[tuple[str, list[str]]] = []
            rc = dispatch(
                ["doctor", "--json"],
                scripts_dir=scripts_dir,
                exec_fn=lambda exe, argv: calls.append((exe, list(argv))),
                stdout=out,
                stderr=err,
            )
            self.assertEqual(rc, 1)
            self.assertEqual(calls, [])
            self.assertIn("scripts/doctor", err.getvalue())
            self.assertNotIn("Traceback", err.getvalue())

            # If scripts/doctor is absent in the real checkout (pre-Track-1), verify real checkout too.
            if not (ROOT / "scripts" / "doctor").exists():
                real_err = io.StringIO()
                real_rc = dispatch(
                    ["doctor"],
                    scripts_dir=ROOT / "scripts",
                    exec_fn=lambda exe, argv: calls.append((exe, list(argv))),
                    stdout=io.StringIO(),
                    stderr=real_err,
                )
                self.assertEqual(real_rc, 1)
                self.assertEqual(calls, [])
                self.assertIn("scripts/doctor", real_err.getvalue())
                self.assertNotIn("Traceback", real_err.getvalue())

            # Synthetic executable doctor dispatches cleanly.
            doctor_path = _make_executable(
                scripts_dir / "doctor", "#!/bin/sh\nexit 0\n"
            )
            rc = dispatch(
                ["doctor", "--json"],
                scripts_dir=scripts_dir,
                exec_fn=lambda exe, argv: calls.append((exe, list(argv))),
                stdout=io.StringIO(),
                stderr=io.StringIO(),
            )
            self.assertEqual(rc, 0)
            self.assertEqual(
                calls,
                [(str(doctor_path.resolve()), [str(doctor_path.resolve()), "--json"])],
            )

            # Symlinked target rejected even if pointing inside or outside scripts_dir.
            (scripts_dir / "models").symlink_to(outside)
            err = io.StringIO()
            calls.clear()
            rc = dispatch(
                ["models"],
                scripts_dir=scripts_dir,
                exec_fn=lambda exe, argv: calls.append((exe, list(argv))),
                stdout=io.StringIO(),
                stderr=err,
            )
            self.assertEqual(rc, 1)
            self.assertEqual(calls, [])
            self.assertIn("symlinked", err.getvalue())
            self.assertNotIn("Traceback", err.getvalue())

            # Non-executable regular file rejected.
            non_exec = scripts_dir / "session"
            non_exec.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            non_exec.chmod(0o644)
            err = io.StringIO()
            rc = dispatch(
                ["status"],
                scripts_dir=scripts_dir,
                exec_fn=lambda exe, argv: calls.append((exe, list(argv))),
                stdout=io.StringIO(),
                stderr=err,
            )
            self.assertEqual(rc, 1)
            self.assertEqual(calls, [])
            self.assertIn("not executable", err.getvalue())
            self.assertNotIn("Traceback", err.getvalue())

            # Directory masquerading as target script rejected.
            (scripts_dir / "setup").mkdir()
            err = io.StringIO()
            rc = dispatch(
                ["setup"],
                scripts_dir=scripts_dir,
                exec_fn=lambda exe, argv: calls.append((exe, list(argv))),
                stdout=io.StringIO(),
                stderr=err,
            )
            self.assertEqual(rc, 1)
            self.assertIn("not a regular file", err.getvalue())

            # Path traversal / invalid script names rejected directly.
            for bad_name in ("", ".", "..", "../outside.sh", "sub/script", "a\\b", "a\x00b"):
                with self.assertRaises(DispatchError, msg=bad_name):
                    resolve_target_script(scripts_dir, bad_name)

            # Target lookup OSError (injected PermissionError during is_symlink) translated cleanly.
            err = io.StringIO()
            calls.clear()
            with patch.object(Path, "is_symlink", side_effect=PermissionError(errno.EACCES, "Permission denied")):
                rc = dispatch(
                    ["doctor"],
                    scripts_dir=scripts_dir,
                    exec_fn=lambda exe, argv: calls.append((exe, list(argv))),
                    stdout=io.StringIO(),
                    stderr=err,
                )
            self.assertEqual(rc, 1)
            self.assertEqual(calls, [])
            self.assertIn("cannot inspect target script scripts/doctor", err.getvalue())
            self.assertNotIn("Traceback", err.getvalue())

            # Real unsearchable scripts/ directory (chmod 0o000) when non-root translates cleanly.
            if hasattr(os, "geteuid") and os.geteuid() != 0:
                locked_dir = root / "locked_scripts"
                locked_dir.mkdir()
                _make_executable(locked_dir / "doctor", "#!/bin/sh\nexit 0\n")
                locked_dir.chmod(0o000)
                try:
                    err = io.StringIO()
                    calls.clear()
                    rc = dispatch(
                        ["doctor"],
                        scripts_dir=locked_dir,
                        exec_fn=lambda exe, argv: calls.append((exe, list(argv))),
                        stdout=io.StringIO(),
                        stderr=err,
                    )
                    self.assertEqual(rc, 1)
                    self.assertEqual(calls, [])
                    self.assertIn("scripts/doctor", err.getvalue())
                    self.assertNotIn("Traceback", err.getvalue())
                finally:
                    locked_dir.chmod(0o755)

            # Injected OSError from exec_fn translated to concise stderr + exit 1.
            def _raise_enoent(_exe: str, _argv: list[str]) -> None:
                raise OSError(errno.ENOENT, "No such file or directory")

            err = io.StringIO()
            rc = dispatch(
                ["doctor"],
                scripts_dir=scripts_dir,
                exec_fn=_raise_enoent,
                stdout=io.StringIO(),
                stderr=err,
            )
            self.assertEqual(rc, 1)
            self.assertIn("failed to execute scripts/doctor", err.getvalue())
            self.assertNotIn("Traceback", err.getvalue())


class CliDispatcherSubprocessTests(unittest.TestCase):
    def test_shipped_entrypoint_hostile_path_pythonpath_and_zero_bytecode(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            checkout = root / "checkout"
            entrypoint = _materialize_temp_checkout(checkout)
            caller_cwd = root / "caller_cwd"
            caller_cwd.mkdir()

            hostile_bin = root / "hostile_bin"
            hostile_bin.mkdir()
            hostile_marker = root / "hostile_py_invoked"
            _make_executable(
                hostile_bin / "python3",
                f"#!/bin/sh\ntouch {shlex.quote(str(hostile_marker))}\nexit 99\n",
            )

            poison_py = root / "poison_py"
            poison_py.mkdir()
            poison_marker = root / "poison_import_invoked"
            (poison_py / "local_assist.py").write_text(
                f"open({str(poison_marker)!r}, 'w').write('poisoned')\n"
                "raise RuntimeError('poisoned local_assist imported')\n",
                encoding="utf-8",
            )

            env = {
                "PATH": f"{hostile_bin}:/usr/bin:/bin",
                "PYTHONPATH": str(poison_py),
                "HOME": str(root / "empty_home"),
            }
            (root / "empty_home").mkdir()

            for args, expected_rc, expected_substr in (
                (["--help"], 0, "Commands:"),
                (["--version"], 0, f"free-inference {__version__}\n"),
                (["unknown-subcommand"], 2, "unknown subcommand"),
            ):
                proc = subprocess.run(
                    [str(entrypoint), *args],
                    cwd=str(caller_cwd),
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(
                    proc.returncode,
                    expected_rc,
                    msg=f"args={args} stdout={proc.stdout!r} stderr={proc.stderr!r}",
                )
                combined = proc.stdout if expected_rc == 0 else proc.stderr
                self.assertIn(expected_substr, combined)

            self.assertFalse(hostile_marker.exists(), "hostile PATH python3 was invoked")
            self.assertFalse(poison_marker.exists(), "poison PYTHONPATH was imported")
            self.assertEqual(_find_bytecode_artifacts(checkout), [])

    def test_shipped_entrypoint_end_to_end_handoff_env_cwd_argv_exit_and_zero_pyc(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            checkout = root / "checkout"
            entrypoint = _materialize_temp_checkout(checkout)
            caller_cwd = root / "caller_workdir"
            caller_cwd.mkdir()

            hostile_bin = root / "hostile_bin"
            hostile_bin.mkdir()
            hostile_marker = root / "hostile_py_invoked"
            _make_executable(
                hostile_bin / "python3",
                f"#!/bin/sh\ntouch {shlex.quote(str(hostile_marker))}\nexit 99\n",
            )

            poison_py = root / "poison_py"
            poison_py.mkdir()
            poison_marker = root / "poison_import_invoked"
            (poison_py / "local_assist.py").write_text(
                f"open({str(poison_marker)!r}, 'w').write('poisoned')\n"
                "raise RuntimeError('poisoned local_assist imported')\n",
                encoding="utf-8",
            )

            doctor_out = root / "doctor_probe.json"
            doctor_script = _write_probe_fixture(
                checkout / "scripts" / "doctor", doctor_out, exit_code=42
            )

            caller_env = {
                "PATH": f"{hostile_bin}:/usr/bin:/bin",
                "PYTHONPATH": str(poison_py),
                "FREE_INFERENCE_SENTINEL": "keep-exact-value",
                "EMPTY_SENTINEL": "",
            }
            self.assertNotIn("PYTHONDONTWRITEBYTECODE", caller_env)
            self.assertNotIn("LC_CTYPE", caller_env)
            self.assertNotIn("__CF_USER_TEXT_ENCODING", caller_env)

            proc = subprocess.run(
                [str(entrypoint), "doctor", "--json", "--", "--flag", "a b"],
                cwd=str(caller_cwd),
                env=caller_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                proc.returncode,
                42,
                msg=f"stdout={proc.stdout!r} stderr={proc.stderr!r}",
            )
            self.assertFalse(hostile_marker.exists())
            self.assertFalse(poison_marker.exists())

            payload = json.loads(doctor_out.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["argv"],
                [str(doctor_script.resolve()), "--json", "--", "--flag", "a b"],
            )
            self.assertEqual(
                os.path.realpath(payload["cwd"]),
                os.path.realpath(str(caller_cwd)),
            )
            self.assertNotIn("PYTHONDONTWRITEBYTECODE", payload["env"])
            received_filtered = {
                k: v
                for k, v in payload["env"].items()
                if k not in RUNTIME_MANAGED_ENV_KEYS
            }
            expected_filtered = {
                k: v
                for k, v in caller_env.items()
                if k not in RUNTIME_MANAGED_ENV_KEYS
            }
            self.assertEqual(received_filtered, expected_filtered)

            # Exact zero-delta comparison against the bare /bin/sh + trusted python3 -I -B
            # bootstrap executing the same fixture directly via os.execv.
            baseline_out = root / "baseline_probe.json"
            baseline_script = _write_probe_fixture(
                root / "baseline_fixture", baseline_out, exit_code=42
            )
            baseline_sh = (
                "for _py in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do "
                'if [ -f "$_py" ] && [ -x "$_py" ]; then '
                'exec "$_py" -I -B -c "import os, sys; os.execv(sys.argv[1], sys.argv[1:])" '
                f"{shlex.quote(str(baseline_script.resolve()))}; "
                "fi; done; exit 1"
            )
            baseline_proc = subprocess.run(
                ["/bin/sh", "-c", baseline_sh],
                cwd=str(caller_cwd),
                env=caller_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(baseline_proc.returncode, 42, msg=baseline_proc.stderr)
            baseline_payload = json.loads(baseline_out.read_text(encoding="utf-8"))
            self.assertEqual(payload["env"], baseline_payload["env"])

            # Verify status prefix-arg injection and nonzero exit propagation end-to-end.
            session_out = root / "session_probe.json"
            session_script = _write_probe_fixture(
                checkout / "scripts" / "session", session_out, exit_code=17
            )
            status_proc = subprocess.run(
                [str(entrypoint), "status", "--json"],
                cwd=str(caller_cwd),
                env=caller_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(status_proc.returncode, 17)
            status_payload = json.loads(session_out.read_text(encoding="utf-8"))
            self.assertEqual(
                status_payload["argv"],
                [str(session_script.resolve()), "status", "--json"],
            )

            # Verify bad-shebang executable produces clean exit 1 without traceback.
            _make_executable(
                checkout / "scripts" / "verify-served-model",
                "#!/nonexistent/free-inference/missing-interpreter\n",
            )
            bad_proc = subprocess.run(
                [str(entrypoint), "verify"],
                cwd=str(caller_cwd),
                env=caller_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(bad_proc.returncode, 1)
            self.assertIn("failed to execute scripts/verify-served-model", bad_proc.stderr)
            self.assertNotIn("Traceback", bad_proc.stderr)

            # Zero bytecode artifacts written anywhere inside the temporary checkout.
            self.assertEqual(_find_bytecode_artifacts(checkout), [])

    def test_real_target_smoke_under_controlled_path_and_apple_python3_9(self) -> None:
        self.assertTrue(SHIPPED_ENTRYPOINT.is_file())
        mode = SHIPPED_ENTRYPOINT.stat().st_mode
        self.assertTrue(bool(mode & stat.S_IXUSR), "scripts/free-inference must be executable")

        controlled_path_parts = [
            str(Path(sys.executable).resolve().parent),
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
        ]
        controlled_env = {
            "PATH": ":".join(dict.fromkeys(controlled_path_parts)),
            "HOME": os.environ.get("HOME", "/tmp"),
        }

        with tempfile.TemporaryDirectory() as other_cwd:
            # Real target: models --version reaches scripts/models (not intercepted by dispatcher).
            direct_ver = subprocess.run(
                [str(ROOT / "scripts" / "models"), "--version"],
                cwd=other_cwd,
                env=controlled_env,
                capture_output=True,
                text=True,
                check=False,
            )
            dispatched_ver = subprocess.run(
                [str(SHIPPED_ENTRYPOINT), "models", "--version"],
                cwd=other_cwd,
                env=controlled_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(direct_ver.returncode, 0, msg=direct_ver.stderr)
            self.assertEqual(dispatched_ver.returncode, 0, msg=dispatched_ver.stderr)
            self.assertEqual(dispatched_ver.stdout, direct_ver.stdout)
            self.assertNotEqual(
                dispatched_ver.stdout,
                f"free-inference {__version__}\n",
                msg="models --version should be handled by scripts/models, not top-level dispatcher",
            )

            # Real target: help models forwards --help to scripts/models.
            direct_help = subprocess.run(
                [str(ROOT / "scripts" / "models"), "--help"],
                cwd=other_cwd,
                env=controlled_env,
                capture_output=True,
                text=True,
                check=False,
            )
            dispatched_help = subprocess.run(
                [str(SHIPPED_ENTRYPOINT), "help", "models"],
                cwd=other_cwd,
                env=controlled_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(direct_help.returncode, 0, msg=direct_help.stderr)
            self.assertEqual(dispatched_help.returncode, 0, msg=dispatched_help.stderr)
            self.assertEqual(dispatched_help.stdout, direct_help.stdout)

            # Real target: help stop prints usage directly without invoking scripts/stop-model or creating .pid.lock.
            fresh_runs = Path(other_cwd) / "fresh_runs"
            fresh_runs.mkdir()
            stop_help_env = dict(controlled_env)
            stop_help_env["FREE_INFERENCE_RUNS_DIR"] = str(fresh_runs)
            stop_help_proc = subprocess.run(
                [str(SHIPPED_ENTRYPOINT), "help", "stop"],
                cwd=other_cwd,
                env=stop_help_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(stop_help_proc.returncode, 0, msg=stop_help_proc.stderr)
            self.assertIn("Usage: free-inference stop", stop_help_proc.stdout)
            self.assertEqual(list(fresh_runs.iterdir()), [], "help stop must not create .pid.lock or any files")

            # Apple /usr/bin/python3 (3.9) compatibility check on macOS.
            apple_py = Path("/usr/bin/python3")
            if sys.platform == "darwin" and apple_py.is_file() and os.access(apple_py, os.X_OK):
                apple_proc = subprocess.run(
                    [str(apple_py), "-I", "-B", str(SHIPPED_ENTRYPOINT), "--version"],
                    cwd=other_cwd,
                    env=controlled_env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(
                    apple_proc.returncode,
                    0,
                    msg=f"stdout={apple_proc.stdout!r} stderr={apple_proc.stderr!r}",
                )
                self.assertEqual(apple_proc.stdout, f"free-inference {__version__}\n")

    def test_direct_vs_dispatched_non_python_env_and_sigpipe_contract(self) -> None:
        """Distinguish direct execution from bootstrap on non-Python receivers (env + SIGPIPE)."""
        awk_path = Path("/usr/bin/awk")
        self.assertTrue(
            awk_path.is_file() and os.access(awk_path, os.X_OK),
            "/usr/bin/awk is required to probe raw execv environment without shell/Python startup",
        )

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            checkout = root / "checkout"
            entrypoint = _materialize_temp_checkout(checkout)
            caller_cwd = root / "caller_workdir"
            caller_cwd.mkdir()

            hostile_bin = root / "hostile_bin"
            hostile_bin.mkdir()
            hostile_marker = root / "hostile_py_invoked"
            _make_executable(
                hostile_bin / "python3",
                f"#!/bin/sh\ntouch {shlex.quote(str(hostile_marker))}\nexit 99\n",
            )

            poison_py = root / "poison_py"
            poison_py.mkdir()
            poison_marker = root / "poison_import_invoked"
            (poison_py / "local_assist.py").write_text(
                f"open({str(poison_marker)!r}, 'w').write('poisoned')\n"
                "raise RuntimeError('poisoned local_assist imported')\n",
                encoding="utf-8",
            )

            # 1) Non-shell, non-Python awk receiver capturing exact execv environment.
            awk_receiver = _make_executable(
                checkout / "scripts" / "doctor",
                '#!/usr/bin/awk -f\nBEGIN { for (k in ENVIRON) printf "%s=%s%c", k, ENVIRON[k], 0; exit 0 }\n',
            )

            caller_env = {
                "PATH": f"{hostile_bin}:/usr/bin:/bin",
                "PYTHONPATH": str(poison_py),
                "FREE_INFERENCE_SENTINEL": "keep-exact-value",
                "EMPTY_SENTINEL": "",
                "_py": "keep-user-py-value",
                "IFS": ":",
                "OPTIND": "7",
                "SHELLOPTS": "braceexpand",
                "__PYVENV_LAUNCHER__": "/sentinel/launcher",
            }
            self.assertNotIn("PYTHONDONTWRITEBYTECODE", caller_env)
            self.assertNotIn("LC_CTYPE", caller_env)
            self.assertNotIn("__CF_USER_TEXT_ENCODING", caller_env)

            def _parse_nul_env(raw: bytes) -> dict[str, str]:
                out_map: dict[str, str] = {}
                for rec in raw.split(b"\x00"):
                    if not rec:
                        continue
                    k_b, v_b = rec.split(b"=", 1)
                    out_map[k_b.decode("utf-8")] = v_b.decode("utf-8")
                return out_map

            direct_proc = subprocess.run(
                [str(awk_receiver)],
                cwd=str(caller_cwd),
                env=caller_env,
                capture_output=True,
                check=False,
            )
            self.assertEqual(direct_proc.returncode, 0, msg=direct_proc.stderr)
            direct_env = _parse_nul_env(direct_proc.stdout)
            # Direct execution preserves the shell/Python bootstrap keys and caller _py untouched.
            self.assertEqual(direct_env.get("IFS"), ":")
            self.assertEqual(direct_env.get("OPTIND"), "7")
            self.assertEqual(direct_env.get("SHELLOPTS"), "braceexpand")
            self.assertEqual(direct_env.get("__PYVENV_LAUNCHER__"), "/sentinel/launcher")
            self.assertEqual(direct_env.get("_py"), "keep-user-py-value")
            self.assertEqual(direct_env.get("FREE_INFERENCE_SENTINEL"), "keep-exact-value")
            self.assertEqual(direct_env.get("EMPTY_SENTINEL"), "")

            dispatched_proc = subprocess.run(
                [str(entrypoint), "doctor"],
                cwd=str(caller_cwd),
                env=caller_env,
                capture_output=True,
                check=False,
            )
            self.assertEqual(dispatched_proc.returncode, 0, msg=dispatched_proc.stderr)
            self.assertFalse(hostile_marker.exists())
            self.assertFalse(poison_marker.exists())
            dispatched_env = _parse_nul_env(dispatched_proc.stdout)

            # PYTHONDONTWRITEBYTECODE is never injected; caller _py and all supported vars match direct execution.
            self.assertNotIn("PYTHONDONTWRITEBYTECODE", dispatched_env)
            self.assertEqual(dispatched_env.get("_py"), "keep-user-py-value")
            differing_keys = {
                k
                for k in (set(direct_env) | set(dispatched_env))
                if direct_env.get(k) != dispatched_env.get(k)
            }
            self.assertTrue(
                differing_keys.issubset(RUNTIME_MANAGED_ENV_KEYS),
                msg=f"Unexpected env deltas outside documented bootstrap keys: {differing_keys - RUNTIME_MANAGED_ENV_KEYS}",
            )
            self.assertEqual(
                {k: v for k, v in dispatched_env.items() if k not in RUNTIME_MANAGED_ENV_KEYS},
                {k: v for k, v in direct_env.items() if k not in RUNTIME_MANAGED_ENV_KEYS},
            )

            # Exact zero-delta equality against bare unrolled /bin/sh -> trusted python3 -I -B os.execv baseline.
            baseline_sh = (
                "set +x +v 2>/dev/null; "
                "if [ -f /opt/homebrew/bin/python3 ] && [ -x /opt/homebrew/bin/python3 ]; then "
                'exec /opt/homebrew/bin/python3 -I -B -c "import os, sys; os.execv(sys.argv[1], sys.argv[1:])" '
                f"{shlex.quote(str(awk_receiver.resolve()))}; "
                "elif [ -f /usr/local/bin/python3 ] && [ -x /usr/local/bin/python3 ]; then "
                'exec /usr/local/bin/python3 -I -B -c "import os, sys; os.execv(sys.argv[1], sys.argv[1:])" '
                f"{shlex.quote(str(awk_receiver.resolve()))}; "
                "elif [ -f /usr/bin/python3 ] && [ -x /usr/bin/python3 ]; then "
                'exec /usr/bin/python3 -I -B -c "import os, sys; os.execv(sys.argv[1], sys.argv[1:])" '
                f"{shlex.quote(str(awk_receiver.resolve()))}; "
                "fi; exit 1"
            )
            baseline_proc = subprocess.run(
                ["/bin/sh", "-c", baseline_sh],
                cwd=str(caller_cwd),
                env=caller_env,
                capture_output=True,
                check=False,
            )
            self.assertEqual(baseline_proc.returncode, 0, msg=baseline_proc.stderr)
            baseline_env = _parse_nul_env(baseline_proc.stdout)
            self.assertEqual(dispatched_env, baseline_env)

            # 1b) Inherited shell tracing (SHELLOPTS=xtrace:verbose) must never print caller args to stderr.
            trace_out = root / "trace_probe.json"
            _write_probe_fixture(checkout / "scripts" / "session", trace_out, exit_code=0)
            trace_env = dict(caller_env)
            trace_env["SHELLOPTS"] = "xtrace:verbose"
            prompt_marker = "SYNTHETIC_PRIVATE_PROMPT_MARKER_987654"
            trace_proc = subprocess.run(
                [str(entrypoint), "session", prompt_marker],
                cwd=str(caller_cwd),
                env=trace_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(trace_proc.returncode, 0, msg=trace_proc.stderr)
            self.assertNotIn(prompt_marker, trace_proc.stderr)
            trace_payload = json.loads(trace_out.read_text(encoding="utf-8"))
            self.assertIn(prompt_marker, trace_payload["argv"])
            self.assertEqual(trace_payload["env"].get("_py"), "keep-user-py-value")

            # 2) Non-Python SIGPIPE contract: dispatcher restores SIGPIPE to SIG_DFL before os.execv
            # so non-Python targets (such as scripts/setup) terminate on SIGPIPE like direct exec.
            sigpipe_receiver = _make_executable(
                checkout / "scripts" / "setup",
                "#!/bin/sh\nkill -PIPE $$\nexit 42\n",
            )
            direct_pipe = subprocess.run(
                [str(sigpipe_receiver)],
                cwd=str(caller_cwd),
                env=caller_env,
                capture_output=True,
                check=False,
            )
            dispatched_pipe = subprocess.run(
                [str(entrypoint), "setup"],
                cwd=str(caller_cwd),
                env=caller_env,
                capture_output=True,
                check=False,
            )
            self.assertEqual(direct_pipe.returncode, -signal.SIGPIPE)
            self.assertEqual(dispatched_pipe.returncode, -signal.SIGPIPE)
            self.assertEqual(_find_bytecode_artifacts(checkout), [])


if __name__ == "__main__":
    unittest.main()
