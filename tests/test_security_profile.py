from __future__ import annotations

import ctypes
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from local_assist.errors import ModelMismatch, ModelUnavailable
from local_assist.lifecycle import ensure_local_model_served
from local_assist.registry import get_process_lstart
from local_assist.security_profile import (
    TESTED_OPENCODE_VERSION,
    SecurityProfileError,
    WorkerSecurityProfile,
    _WorkerTokenRelay,
    _read_regular_file_nofollow,
    _safe_rmtree_nofollow,
    allocate_worker_home,
    apply_cli_overrides,
    build_worker_environment,
    check_pid_identity_state,
    check_tracked_protected_files,
    cleanup_worker_home,
    compile_opencode_security_config,
    compile_seatbelt_profile,
    default_unattended_worker_profile,
    harvest_worker_local_assist_logs,
    load_security_profile,
    parse_security_profile_dict,
    reap_worker_processes,
    reap_worker_processes_detailed,
    run_worker_sandbox_lifecycle,
    sweep_stale_worker_homes,
    sweep_stale_worker_homes_detailed,
    teardown_worker_home,
    validate_worker_opencode_args,
    verify_opencode_version,
    write_verified_local_models_handoff,
    write_worker_runtime_artifacts,
)


HAS_SANDBOX_EXEC = sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").is_file()
OPENCODE_BIN = shutil.which("opencode")


def _install_portable_lsof_fixture_if_absent(test_case: unittest.TestCase) -> None:
    from unittest.mock import patch
    import local_assist.security_profile as sp_mod

    orig_resolve = sp_mod._resolve_lsof_bin
    true_bin = shutil.which("true") or "/usr/bin/true"

    def _portable_resolve() -> str | None:
        found = orig_resolve()
        return found if found is not None else true_bin

    patcher = patch(
        "local_assist.security_profile._resolve_lsof_bin",
        side_effect=_portable_resolve,
    )
    patcher.start()
    test_case.addCleanup(patcher.stop)


class SecurityProfileSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        _install_portable_lsof_fixture_if_absent(self)

    def test_default_profile_and_yaml_json_loading(self) -> None:
        default_prof = default_unattended_worker_profile()
        self.assertEqual(default_prof.schema_version, 1)
        self.assertEqual(default_prof.mode, "unattended_worker")
        self.assertTrue(default_prof.enforce_os_sandbox)
        self.assertFalse(default_prof.allow_subagents)
        self.assertFalse(default_prof.mcp_enable_local_assist)
        self.assertFalse(default_prof.allow_ssh_agent)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            yaml_file = tmp_path / "profile.yaml"
            yaml_file.write_text(
                "schema_version: 1\n"
                "mode: unattended_worker\n"
                "enforce_os_sandbox: true\n"
                "spend:\n"
                "  max_session_usd: 1.25\n"
                "filesystem:\n"
                "  read_roots:\n"
                "    - .\n"
                "  write_roots:\n"
                "    - src\n"
                "  protected_paths:\n"
                "    - src/locked.py\n"
                "tools:\n"
                "  allowed_tools:\n"
                "    - read\n"
                "    - edit\n"
                "    - shell\n"
                "  denied_tools:\n"
                "    - write\n"
                "  allow_subagents: false\n"
                "mcp:\n"
                "  enable_local_assist: false\n"
                "  servers:\n"
                "    agent_comms:\n"
                "      type: local\n"
                "      command:\n"
                "        - python3\n"
                "        - -m\n"
                "        - agent_comms\n"
                "  allowed_servers:\n"
                "    - agent_comms\n"
                "  allowed_tools:\n"
                "    - agent_comms_whoami\n"
                "  denied_tools:\n"
                "    - agent_comms_dispatch_agent\n",
                encoding="utf-8",
            )
            loaded = load_security_profile(yaml_file)
            self.assertEqual(loaded.spend_max_session_usd, 1.25)
            self.assertEqual(loaded.write_roots, ("src",))
            self.assertEqual(loaded.protected_paths, ("src/locked.py",))
            self.assertEqual(loaded.denied_tools, ("write",))
            self.assertIn("agent_comms", loaded.mcp_servers)
            self.assertEqual(loaded.mcp_allowed_tools, ("agent_comms_whoami",))
            self.assertEqual(loaded.mcp_denied_tools, ("agent_comms_dispatch_agent",))

            json_file = tmp_path / "profile.json"
            json_file.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "mode": "unattended_worker",
                        "enforce_os_sandbox": True,
                        "tools": {"allowed_tools": ["read", "grep"]},
                    }
                ),
                encoding="utf-8",
            )
            loaded_json = load_security_profile(json_file)
            self.assertEqual(loaded_json.allowed_tools, ("read", "grep"))

    def test_rejects_invalid_schema_fields(self) -> None:
        with self.assertRaisesRegex(SecurityProfileError, "Unknown keys"):
            parse_security_profile_dict({"unknown_top_key": True})

        with self.assertRaisesRegex(SecurityProfileError, "enforce_os_sandbox: false is refused"):
            parse_security_profile_dict({"enforce_os_sandbox": False})

        with self.assertRaisesRegex(SecurityProfileError, "Unknown built-in tool"):
            parse_security_profile_dict({"tools": {"allowed_tools": ["not_a_tool"]}})

        with self.assertRaisesRegex(SecurityProfileError, "non-loopback host"):
            parse_security_profile_dict(
                {"network": {"allowed_endpoints": ["http://example.com:8080"]}}
            )

        with self.assertRaisesRegex(SecurityProfileError, "only http://"):
            parse_security_profile_dict(
                {"network": {"allowed_endpoints": ["https://127.0.0.1:8080"]}}
            )

        with self.assertRaisesRegex(SecurityProfileError, "reserved inference/proxy port"):
            parse_security_profile_dict(
                {"network": {"allowed_shell_localhost_ports": [8081]}}
            )

        with self.assertRaisesRegex(SecurityProfileError, "reserved worker runtime variable"):
            parse_security_profile_dict({"environment": {"set": {"PATH": "/tmp"}}})

        with self.assertRaisesRegex(SecurityProfileError, "reserved worker runtime variable"):
            parse_security_profile_dict(
                {"environment": {"set": {"OPENCODE_CONFIG_CONTENT": "{}"}}}
            )

        with self.assertRaisesRegex(SecurityProfileError, "stripped secret/credential prefix"):
            parse_security_profile_dict(
                {"environment": {"allowlist": ["AWS_SECRET_ACCESS_KEY"]}}
            )

        with self.assertRaisesRegex(SecurityProfileError, "stripped secret/credential prefix"):
            parse_security_profile_dict(
                {"environment": {"set": {"GITHUB_TOKEN": "ghp_123"}}}
            )

        with self.assertRaisesRegex(SecurityProfileError, "stripped credential/runtime variable"):
            parse_security_profile_dict(
                {"environment": {"set": {"GIT_DIR": "/tmp/evil"}}}
            )

        with self.assertRaisesRegex(SecurityProfileError, "Ambiguous MCP server names"):
            parse_security_profile_dict(
                {
                    "mcp": {
                        "servers": {
                            "foo": {"type": "local", "command": ["echo"]},
                            "foo_bar": {"type": "local", "command": ["echo"]},
                        }
                    }
                }
            )

        with self.assertRaisesRegex(SecurityProfileError, "must be qualified as '<server>_<tool>'"):
            parse_security_profile_dict(
                {
                    "mcp": {
                        "servers": {"foo": {"type": "local", "command": ["echo"]}},
                        "allowed_tools": ["unqualified"],
                    }
                }
            )

    def test_validate_worker_opencode_args(self) -> None:
        with self.assertRaisesRegex(SecurityProfileError, "requires the 'run' subcommand"):
            validate_worker_opencode_args([])

        with self.assertRaisesRegex(SecurityProfileError, "only allows the 'run' subcommand"):
            validate_worker_opencode_args(["serve"])

        for bad_flag in (
            "--server",
            "--auto",
            "--dangerously-skip-permissions",
            "--yolo",
            "--file",
            "--model",
            "-m",
            "--attach",
            "--command",
            "--continue",
            "--fork",
        ):
            with self.assertRaisesRegex(SecurityProfileError, "Disallowed opencode flag"):
                validate_worker_opencode_args(["run", bad_flag, "prompt"])

        with self.assertRaisesRegex(SecurityProfileError, "Inline '--flag=value' syntax"):
            validate_worker_opencode_args(["run", "--format=json", "prompt"])

        with self.assertRaisesRegex(SecurityProfileError, "requires a non-empty prompt"):
            validate_worker_opencode_args(["run", "--format", "json"])

        validated = validate_worker_opencode_args(["run", "--format", "json", "Say OK"])
        self.assertEqual(validated, ["run", "--standalone", "--format", "json", "Say OK"])

    def test_compile_opencode_security_config_and_env(self) -> None:
        prof = parse_security_profile_dict(
            {
                "tools": {
                    "allowed_tools": ["read", "edit", "shell"],
                    "denied_tools": ["write"],
                    "allow_subagents": False,
                },
                "mcp": {
                    "enable_local_assist": False,
                    "servers": {
                        "agent_comms": {
                            "type": "local",
                            "command": ["python3", "-m", "agent_comms"],
                        },
                        "unlisted_srv": {
                            "type": "local",
                            "command": ["python3", "-m", "unlisted"],
                        },
                    },
                    "allowed_servers": ["agent_comms"],
                    "allowed_tools": [
                        "agent_comms_whoami",
                        "agent_comms_send_message",
                        "agent_comms_dispatch_agent",
                    ],
                    "denied_tools": ["agent_comms_dispatch_agent"],
                },
            }
        )
        base_cfg = {
            "provider": {"private_local": {"options": {"baseURL": "http://127.0.0.1:8080/v1"}}},
            "mcp": {
                "local_assist": {
                    "type": "local",
                    "command": ["python3", "-m", "local_assist.mcp_server"],
                    "enabled": True,
                }
            },
        }
        compiled = compile_opencode_security_config(base_cfg, prof)
        self.assertEqual(compiled["permission"]["*"], "deny")
        self.assertEqual(compiled["permission"]["read"], "allow")
        self.assertEqual(compiled["permission"]["edit"], "deny")
        self.assertEqual(compiled["permission"]["write"], "deny")
        self.assertFalse(compiled["tools"]["write"])
        self.assertEqual(compiled["permission"]["bash"], "allow")
        self.assertEqual(compiled["permission"]["shell"], "allow")
        self.assertEqual(compiled["permission"]["task"], "deny")
        self.assertEqual(compiled["permission"]["subagent"], "deny")
        self.assertEqual(compiled["permission"]["webfetch"], "deny")
        self.assertTrue(compiled["agent"]["general"]["disable"])
        self.assertNotIn("local_assist", compiled["mcp"]["servers"])
        self.assertFalse(compiled["mcp"]["servers"]["agent_comms"]["disabled"])
        self.assertTrue(compiled["mcp"]["servers"]["unlisted_srv"]["disabled"])
        self.assertEqual(compiled["permission"]["agent_comms_*"], "deny")
        self.assertEqual(compiled["permission"]["agent_comms_whoami"], "allow")
        self.assertEqual(compiled["permission"]["agent_comms_send_message"], "allow")
        self.assertEqual(compiled["permission"]["agent_comms_dispatch_agent"], "deny")
        self.assertFalse(compiled["tools"]["agent_comms_dispatch_agent"])

        with tempfile.TemporaryDirectory() as tmp:
            iso_home = Path(tmp)
            fake_host_env = {
                "PATH": "/usr/bin:/bin",
                "USER": "alice",
                "AWS_SECRET_ACCESS_KEY": "secret",
                "SSH_AUTH_SOCK": "/tmp/ssh.sock",
                "OPENCODE_CONFIG_CONTENT": "{}",
            }
            worker_env = build_worker_environment(
                prof,
                isolated_home=iso_home,
                worker_id="worker-test-1",
                host_env=fake_host_env,
            )
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", worker_env)
            self.assertNotIn("SSH_AUTH_SOCK", worker_env)
            self.assertNotIn("OPENCODE_CONFIG_CONTENT", worker_env)
            self.assertEqual(worker_env["GIT_AUTHOR_NAME"], "worker")
            self.assertEqual(worker_env["GIT_AUTHOR_EMAIL"], "worker@local")
            self.assertEqual(worker_env["LOCAL_ASSIST_WORKER_ID"], "worker-test-1")
            self.assertEqual(worker_env["OPENCODE_DISABLE_PROJECT_CONFIG"], "true")

    def test_rejects_broad_roots(self) -> None:
        prof_root = parse_security_profile_dict({"filesystem": {"read_roots": ["/"]}})
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            iso = Path(tmp) / "iso"
            ws.mkdir()
            iso.mkdir()
            with self.assertRaisesRegex(SecurityProfileError, "overly broad root directory"):
                compile_seatbelt_profile(
                    prof_root,
                    workspace_dir=ws,
                    isolated_home=iso,
                    opencode_bin=Path("/usr/bin/true"),
                    sandbox_exec_bin=Path("/usr/bin/true"),
                )

            prof_home = parse_security_profile_dict(
                {"filesystem": {"write_roots": [str(Path.home())]}}
            )
            with self.assertRaisesRegex(SecurityProfileError, "overly broad root directory"):
                compile_seatbelt_profile(
                    prof_home,
                    workspace_dir=ws,
                    isolated_home=iso,
                    opencode_bin=Path("/usr/bin/true"),
                    sandbox_exec_bin=Path("/usr/bin/true"),
                )

    def test_opencode_binary_under_home_bin_does_not_reopen_host_home_reads(self) -> None:
        # WORK-MAJOR-5 & R2-MINOR-2: an opencode binary installed at ~/bin/opencode must not grant
        # (subpath "<host_home>") when allow_default_toolchains=False, tested in a synthetic home
        # without mutating the operator's real ~/bin.
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            fake_home = (Path(tmp) / "fake_home").resolve()
            home_bin_dir = fake_home / "bin"
            home_bin_dir.mkdir(parents=True, exist_ok=True)
            dummy_bin = home_bin_dir / "opencode"
            dummy_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(dummy_bin, 0o700)

            ws = Path(tmp) / "ws"
            iso = Path(tmp) / "iso"
            ws.mkdir()
            iso.mkdir()
            with patch.object(Path, "home", return_value=fake_home):
                prof = parse_security_profile_dict(
                    {"filesystem": {"allow_default_toolchains": False}}
                )
                sb_text = compile_seatbelt_profile(
                    prof,
                    workspace_dir=ws,
                    isolated_home=iso,
                    opencode_bin=dummy_bin,
                    sandbox_exec_bin=Path("/usr/bin/true"),
                )
            self.assertIn(f'(literal "{dummy_bin.resolve()}")', sb_text)
            self.assertNotIn(f'(subpath "{fake_home}")', sb_text)
            self.assertNotIn(f'(subpath "/System/Volumes/Data{fake_home}")', sb_text)

    def test_worker_sandbox_local_assist_handoff_enforcement(self) -> None:
        # WORK-MAJOR-4, R2-MAJOR-1, R3-MAJOR-1, R3-MAJOR-2:
        # Portable producer + consumer verification:
        # 1. write_verified_local_models_handoff unpacks (Path, dict) tuples from list_pid_records,
        #    populating verified-models.json for valid offline local servers and excluding invalid ones.
        # 2. Consumer accepts valid handoff when verify-served-model fails due to sandbox-unavailable
        #    inspection (rc=1 or rc=3 with missing PID/lsof inspection), but raises ModelMismatch when
        #    verify-served-model reports a confirmed model or offline mismatch (rc=3).
        from unittest.mock import patch
        from local_assist.registry import pid_file_for_model

        class _FailedVerifyProc:
            returncode = 1
            stdout = ""
            stderr = "runs/ unreadable inside worker sandbox"

        class _SandboxUnverifiableRc3Proc:
            returncode = 3
            stdout = ""
            stderr = (
                "served model on port 8080 for 'qwen3-30b-a3b-2507-mlx-4bit' has no active PID record "
                "confirming offline startup (hf_offline=True)"
            )

        class _ConfirmedMismatchRc3Proc:
            returncode = 3
            stdout = ""
            stderr = (
                "served model mismatch on port 8080: listener pid 12345 was started with "
                "--model mlx-community/Qwen3-1.7B-4bit; expected mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit"
            )

        class _OnlineMismatchRc3Proc:
            returncode = 3
            stdout = ""
            stderr = (
                "served model on port 8080 for 'qwen3-30b-a3b-2507-mlx-4bit' (pid=12345) "
                "was started with --allow-hf-online or lacks verified offline state"
            )

        class _PassedVerifyProc:
            returncode = 0
            stdout = "qwen3-30b-a3b-2507-mlx-4bit\n"
            stderr = ""

        model_id = "qwen3-30b-a3b-2507-mlx-4bit"
        served_repo = "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit"
        live_pid = os.getpid()
        live_lstart = get_process_lstart(live_pid)
        self.assertTrue(live_lstart)

        wid, iso_home = allocate_worker_home()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                fake_runs = Path(tmp) / "runs"
                fake_runs.mkdir(parents=True, exist_ok=True)
                # Valid offline cleared record
                valid_pid_path = pid_file_for_model(model_id, fake_runs)
                valid_pid_path.write_text(
                    json.dumps(
                        {
                            "model_id": model_id,
                            "repo": served_repo,
                            "status": "ready",
                            "pid": live_pid,
                            "pid_lstart": live_lstart,
                            "port": 8080,
                            "hf_offline": True,
                        }
                    ),
                    encoding="utf-8",
                )
                # Invalid online record (hf_offline=False) -> must be excluded by producer
                invalid_id = "qwen3-1.7b-mlx-4bit"
                invalid_pid_path = pid_file_for_model(invalid_id, fake_runs)
                invalid_pid_path.write_text(
                    json.dumps(
                        {
                            "model_id": invalid_id,
                            "repo": "mlx-community/Qwen3-1.7B-4bit",
                            "status": "ready",
                            "pid": live_pid,
                            "pid_lstart": live_lstart,
                            "port": 8080,
                            "hf_offline": False,
                        }
                    ),
                    encoding="utf-8",
                )

                handoff_file = write_verified_local_models_handoff(
                    isolated_home=iso_home,
                    worker_id=wid,
                    runs_dir=fake_runs,
                    verify_runner=lambda *a, **k: _PassedVerifyProc(),
                )
                produced = json.loads(handoff_file.read_text(encoding="utf-8"))
                self.assertIn(model_id, produced["models"])
                self.assertNotIn(invalid_id, produced["models"])
                self.assertEqual(produced["models"][model_id]["pid"], live_pid)
                self.assertEqual(produced["models"][model_id]["pid_lstart"], live_lstart)

                base_env = {
                    "LOCAL_ASSIST_WORKER_SANDBOX": "1",
                    "LOCAL_ASSIST_WORKER_ID": wid,
                    "LOCAL_ASSIST_AUTO_SERVE": "0",
                }
                with patch("local_assist.lifecycle.get_models", return_value=[served_repo]):
                    # 1. Missing handoff file -> fails closed
                    with patch.dict(os.environ, base_env, clear=False):
                        os.environ.pop("LOCAL_ASSIST_VERIFIED_MODELS_FILE", None)
                        with self.assertRaises(ModelUnavailable):
                            ensure_local_model_served(
                                model_id, auto_serve=False, run_cmd=lambda *a, **k: _FailedVerifyProc()
                            )

                    # 2. Valid produced handoff succeeds when verify-served-model fails due to
                    #    sandbox-unavailable inspection (both rc=1 and rc=3 missing PID/lsof inspection)
                    with patch.dict(
                        os.environ,
                        {**base_env, "LOCAL_ASSIST_VERIFIED_MODELS_FILE": str(handoff_file)},
                        clear=False,
                    ):
                        ensure_local_model_served(
                            model_id, auto_serve=False, run_cmd=lambda *a, **k: _FailedVerifyProc()
                        )
                        ensure_local_model_served(
                            model_id,
                            auto_serve=False,
                            run_cmd=lambda *a, **k: _SandboxUnverifiableRc3Proc(),
                        )

                        # 3. Confirmed model or offline mismatch (rc=3) MUST raise ModelMismatch
                        #    even when a valid handoff, live PID, and matching /models are present (R3-MAJOR-2)
                        with self.assertRaises(ModelMismatch):
                            ensure_local_model_served(
                                model_id,
                                auto_serve=False,
                                run_cmd=lambda *a, **k: _ConfirmedMismatchRc3Proc(),
                            )
                        with self.assertRaises(ModelMismatch):
                            ensure_local_model_served(
                                model_id,
                                auto_serve=False,
                                run_cmd=lambda *a, **k: _OnlineMismatchRc3Proc(),
                            )

                    # 4. Handoff file with hf_offline=False -> fails closed
                    mut_handoff = Path(tmp) / "mut-verified-models.json"
                    mut_handoff.write_text(
                        json.dumps(
                            {
                                "schema_version": 1,
                                "worker_id": wid,
                                "issued_at": time.time(),
                                "expires_at": time.time() + 600,
                                "models": {
                                    model_id: {
                                        "model_id": model_id,
                                        "served_model_id": served_repo,
                                        "api_base_url": "http://127.0.0.1:8080/v1",
                                        "pid": live_pid,
                                        "pid_lstart": live_lstart,
                                        "hf_offline": False,
                                    }
                                },
                            }
                        ),
                        encoding="utf-8",
                    )
                    with patch.dict(
                        os.environ,
                        {**base_env, "LOCAL_ASSIST_VERIFIED_MODELS_FILE": str(mut_handoff)},
                        clear=False,
                    ):
                        with self.assertRaises(ModelUnavailable):
                            ensure_local_model_served(
                                model_id, auto_serve=False, run_cmd=lambda *a, **k: _FailedVerifyProc()
                            )

                    # 5. Handoff file with mismatched pid_lstart -> fails closed
                    mut_handoff.write_text(
                        json.dumps(
                            {
                                "schema_version": 1,
                                "worker_id": wid,
                                "issued_at": time.time(),
                                "expires_at": time.time() + 600,
                                "models": {
                                    model_id: {
                                        "model_id": model_id,
                                        "served_model_id": served_repo,
                                        "api_base_url": "http://127.0.0.1:8080/v1",
                                        "pid": live_pid,
                                        "pid_lstart": "Mon Jan  1 00:00:00 1990",
                                        "hf_offline": True,
                                    }
                                },
                            }
                        ),
                        encoding="utf-8",
                    )
                    with patch.dict(
                        os.environ,
                        {**base_env, "LOCAL_ASSIST_VERIFIED_MODELS_FILE": str(mut_handoff)},
                        clear=False,
                    ):
                        with self.assertRaises(ModelUnavailable):
                            ensure_local_model_served(
                                model_id, auto_serve=False, run_cmd=lambda *a, **k: _FailedVerifyProc()
                            )

                    # 6. Expired handoff file -> fails closed
                    mut_handoff.write_text(
                        json.dumps(
                            {
                                "schema_version": 1,
                                "worker_id": wid,
                                "issued_at": time.time() - 7200,
                                "expires_at": time.time() - 10,
                                "models": {
                                    model_id: {
                                        "model_id": model_id,
                                        "served_model_id": served_repo,
                                        "api_base_url": "http://127.0.0.1:8080/v1",
                                        "pid": live_pid,
                                        "pid_lstart": live_lstart,
                                        "hf_offline": True,
                                    }
                                },
                            }
                        ),
                        encoding="utf-8",
                    )
                    with patch.dict(
                        os.environ,
                        {**base_env, "LOCAL_ASSIST_VERIFIED_MODELS_FILE": str(mut_handoff)},
                        clear=False,
                    ):
                        with self.assertRaises(ModelUnavailable):
                            ensure_local_model_served(
                                model_id, auto_serve=False, run_cmd=lambda *a, **k: _FailedVerifyProc()
                            )
        finally:
            cleanup_worker_home(iso_home, worker_id=wid, harvest_logs=False)

    def test_sweep_stale_worker_homes_preserves_live_owner_even_when_old(self) -> None:
        # WORK-MAJOR-8: a worker home whose verified owner process is still alive must
        # never be reaped or deleted by sweep_stale_worker_homes, even if mtime > max_age_seconds.
        live_wid, live_home = allocate_worker_home()
        dead_wid, dead_home = allocate_worker_home()
        try:
            old_ts = time.time() - 10800
            os.utime(live_home, (old_ts, old_ts))

            # Overwrite dead_home's .worker-owner.json with a mismatched owner_pid_lstart
            owner_meta = dead_home / ".worker-owner.json"
            os.chmod(owner_meta, 0o600)
            owner_meta.write_text(
                json.dumps(
                    {
                        "worker_id": dead_wid,
                        "owner_pid": os.getpid(),
                        "owner_pid_lstart": "Mon Jan  1 00:00:00 1990",
                        "created_at": old_ts,
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(owner_meta, 0o400)
            os.utime(dead_home, (old_ts, old_ts))

            removed = sweep_stale_worker_homes(max_age_seconds=3600)
            self.assertIn(dead_home, removed)
            self.assertFalse(dead_home.exists())
            self.assertNotIn(live_home, removed)
            self.assertTrue(live_home.exists())
        finally:
            cleanup_worker_home(live_home, worker_id=live_wid, harvest_logs=False)
            cleanup_worker_home(dead_home, worker_id=dead_wid, harvest_logs=False)


class WorkerTokenRelayTests(unittest.TestCase):
    def test_relay_auth_clamping_caps_and_sse_streaming(self) -> None:
        observed_requests: list[dict[str, Any]] = []
        secret_session_token = "se-session-supersecret1234567890"
        first_sse_chunk_received = threading.Event()
        second_sse_chunk_sent = threading.Event()

        class _MockUpstreamHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                observed_requests.append(
                    {
                        "method": "GET",
                        "path": self.path,
                        "auth": self.headers.get("Authorization"),
                    }
                )
                body = json.dumps({"data": [{"id": "mock-model"}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                cl = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(cl)
                parsed = json.loads(raw.decode("utf-8"))
                observed_requests.append(
                    {
                        "method": "POST",
                        "path": self.path,
                        "auth": self.headers.get("Authorization"),
                        "body": parsed,
                    }
                )
                if parsed.get("stream"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    # WORK-MAJOR-7: send first short SSE event (<100 bytes), flush, and wait
                    # until the downstream client has received it before sending the rest.
                    self.wfile.write(b'data: {"choices":[{"delta":{"content":"hel"}}]}\n\n')
                    self.wfile.flush()
                    if not first_sse_chunk_received.wait(timeout=5.0):
                        return
                    self.wfile.write(b'data: {"choices":[{"delta":{"content":"lo"}}]}\n\n')
                    self.wfile.write(b"data: [DONE]\n\n")
                    self.wfile.flush()
                    second_sse_chunk_sent.set()
                    return
                body = json.dumps(
                    {
                        "id": "chatcmpl-1",
                        "model": "mock-model",
                        "choices": [
                            {
                                "index": 0,
                                "message": {"role": "assistant", "content": "OK"},
                                "finish_reason": "stop",
                            }
                        ],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        upstream_srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockUpstreamHandler)
        upstream_thread = threading.Thread(target=upstream_srv.serve_forever, daemon=True)
        upstream_thread.start()
        upstream_url = f"http://127.0.0.1:{upstream_srv.server_address[1]}/v1"

        relay = _WorkerTokenRelay(
            upstream_base_url=upstream_url,
            upstream_session_token=secret_session_token,
            max_chat_requests=2,
            max_request_bytes=1024,
            max_tokens_cap=128,
        ).start()
        try:
            # 1. Unauthenticated request -> 401 without hitting upstream
            req_unauth = Request(f"{relay.api_base_url}/models", method="GET")
            with self.assertRaises(HTTPError) as ctx:
                urlopen(req_unauth, timeout=5)
            self.assertEqual(ctx.exception.code, 401)
            ctx.exception.close()
            self.assertEqual(len(observed_requests), 0)

            # 2. Wrong bearer token -> 401 without hitting upstream
            req_bad = Request(
                f"{relay.api_base_url}/models",
                headers={"Authorization": "Bearer wrong-token"},
                method="GET",
            )
            with self.assertRaises(HTTPError) as ctx:
                urlopen(req_bad, timeout=5)
            self.assertEqual(ctx.exception.code, 401)
            ctx.exception.close()
            self.assertEqual(len(observed_requests), 0)

            # 3. Disallowed path -> 404
            req_404 = Request(
                f"http://127.0.0.1:{relay.port}/metrics",
                headers={"Authorization": f"Bearer {relay.relay_token}"},
                method="GET",
            )
            with self.assertRaises(HTTPError) as ctx:
                urlopen(req_404, timeout=5)
            self.assertEqual(ctx.exception.code, 404)
            ctx.exception.close()

            # 4. Authenticated GET /v1/models replaces Authorization header with upstream session token
            req_models = Request(
                f"{relay.api_base_url}/models",
                headers={"Authorization": f"Bearer {relay.relay_token}"},
                method="GET",
            )
            with urlopen(req_models, timeout=5) as resp:
                models_data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(models_data["data"][0]["id"], "mock-model")
            self.assertEqual(observed_requests[-1]["auth"], f"Bearer {secret_session_token}")

            # 5. Oversized POST /v1/chat/completions -> 413 without consuming chat_requests_used
            big_payload = json.dumps({"messages": [{"role": "user", "content": "x" * 2000}]}).encode("utf-8")
            req_big = Request(
                f"{relay.api_base_url}/chat/completions",
                data=big_payload,
                headers={
                    "Authorization": f"Bearer {relay.relay_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with self.assertRaises(HTTPError) as ctx:
                urlopen(req_big, timeout=5)
            self.assertEqual(ctx.exception.code, 413)
            ctx.exception.close()
            self.assertEqual(relay.chat_requests_used, 0)

            # 6. First chat request clamps max_tokens, max_completion_tokens, n, best_of, and removes maxOutputTokens
            chat_payload = json.dumps(
                {
                    "model": "mock-model",
                    "messages": [{"role": "user", "content": "hi"}],
                    "max_tokens": 9999,
                    "max_completion_tokens": 4096,
                    "maxOutputTokens": 99999,
                    "n": 5,
                    "best_of": 5,
                }
            ).encode("utf-8")
            req_chat = Request(
                f"{relay.api_base_url}/chat/completions",
                data=chat_payload,
                headers={
                    "Authorization": f"Bearer {relay.relay_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urlopen(req_chat, timeout=5) as resp:
                chat_resp = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(chat_resp["choices"][0]["message"]["content"], "OK")
            self.assertEqual(observed_requests[-1]["auth"], f"Bearer {secret_session_token}")
            self.assertEqual(observed_requests[-1]["body"]["max_tokens"], 128)
            self.assertEqual(observed_requests[-1]["body"]["max_completion_tokens"], 128)
            self.assertEqual(observed_requests[-1]["body"]["n"], 1)
            self.assertEqual(observed_requests[-1]["body"]["best_of"], 1)
            self.assertNotIn("maxOutputTokens", observed_requests[-1]["body"])

            # 7. Second chat request streams SSE incrementally without 4 KiB buffering (WORK-MAJOR-7)
            sse_payload = json.dumps(
                {
                    "model": "mock-model",
                    "messages": [{"role": "user", "content": "stream"}],
                    "stream": True,
                }
            ).encode("utf-8")
            req_sse = Request(
                f"{relay.api_base_url}/chat/completions",
                data=sse_payload,
                headers={
                    "Authorization": f"Bearer {relay.relay_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urlopen(req_sse, timeout=5) as resp:
                first_line = resp.readline().decode("utf-8")
                self.assertIn('"hel"', first_line)
                self.assertFalse(second_sse_chunk_sent.is_set())
                first_sse_chunk_received.set()
                rest_body = resp.read().decode("utf-8")
            sse_body = first_line + rest_body
            self.assertIn("[DONE]", sse_body)
            self.assertNotIn("se-session-", sse_body)

            # 8. Third chat request exceeds max_chat_requests=2 -> 429
            with self.assertRaises(HTTPError) as ctx:
                urlopen(req_chat, timeout=5)
            self.assertEqual(ctx.exception.code, 429)
            ctx.exception.close()
        finally:
            relay.close()
            upstream_srv.shutdown()
            upstream_srv.server_close()


class LauncherSecurityCliGateTests(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        _install_portable_lsof_fixture_if_absent(self)

    def test_opencode_attested_worker_requires_spend_cap_and_blocks_uncleared_override(self) -> None:
        script = str(ROOT / "scripts" / "opencode-attested")
        # 1. Missing --max-session-usd in worker mode is refused immediately
        res_no_usd = subprocess.run(
            [sys.executable, script, "--unattended-worker", "--", "run", "hi"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(res_no_usd.returncode, 0)
        self.assertIn("requires an explicit spend ceiling", res_no_usd.stderr)

        # 2. --preserve-host-home is refused when a security profile is active
        res_preserve = subprocess.run(
            [
                sys.executable,
                script,
                "--unattended-worker",
                "--preserve-host-home",
                "--max-session-usd",
                "0.50",
                "--",
                "run",
                "hi",
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(res_preserve.returncode, 0)
        self.assertIn("Refusing --preserve-host-home", res_preserve.stderr)

        # 3. --allow-uncleared-model is refused when profile has allow_uncleared_model=false
        res_uncleared = subprocess.run(
            [
                sys.executable,
                script,
                "--unattended-worker",
                "--allow-uncleared-model",
                "--max-session-usd",
                "0.50",
                "--",
                "run",
                "hi",
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(res_uncleared.returncode, 0)
        self.assertIn("allow_uncleared_model=false", res_uncleared.stderr)

    @unittest.skipUnless(OPENCODE_BIN is not None, "opencode binary required")
    def test_opencode_local_launcher_worker_success_path_and_version_gate(self) -> None:
        # WORK-MAJOR-6: exercise scripts/opencode-local main() directly with --unattended-worker
        # (including verify_opencode_version without --allow-opencode-version-drift) and verify
        # version mismatch is rejected while the pinned version succeeds.
        import importlib.machinery
        import importlib.util
        import io
        from contextlib import redirect_stderr, redirect_stdout
        from unittest.mock import patch

        script_path = ROOT / "scripts" / "opencode-local"
        loader = importlib.machinery.SourceFileLoader("opencode_local_mod", str(script_path))
        spec = importlib.util.spec_from_loader("opencode_local_mod", loader)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        real_popen = subprocess.Popen
        recorded_sandbox_cmd: list[str] = []

        class _FakeSandboxPopen:
            pid = 1

            def poll(self) -> int:
                return 0

            def wait(self, timeout: float | None = None) -> int:
                return 0

        def _fake_popen(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
            if cmd and Path(str(cmd[0])).name == "sandbox-exec":
                recorded_sandbox_cmd.extend(str(c) for c in cmd)
                return _FakeSandboxPopen()
            return real_popen(cmd, *args, **kwargs)

        with patch.object(mod, "ensure_model_served", return_value=(True, None)), patch(
            "local_assist.security_profile.subprocess.Popen", side_effect=_fake_popen
        ):
            out_buf = io.StringIO()
            err_buf = io.StringIO()
            with redirect_stdout(out_buf), redirect_stderr(err_buf):
                rc = mod.main(
                    [
                        str(script_path),
                        "--unattended-worker",
                        "--no-serve",
                        "--",
                        "run",
                        "--format",
                        "json",
                        "Hello worker",
                    ]
                )
            self.assertEqual(rc, 0, err_buf.getvalue())
            self.assertTrue(recorded_sandbox_cmd)
            self.assertEqual(recorded_sandbox_cmd[0], "/usr/bin/sandbox-exec")
            self.assertIn("--standalone", recorded_sandbox_cmd)

        # Also verify that if TESTED_OPENCODE_VERSION differs, main() fails closed with rc=1.
        with patch("local_assist.security_profile.TESTED_OPENCODE_VERSION", "0.0.0-mismatch"):
            err_mismatch = io.StringIO()
            with redirect_stderr(err_mismatch):
                rc_bad = mod.main(
                    [
                        str(script_path),
                        "--unattended-worker",
                        "--no-serve",
                        "--",
                        "run",
                        "Hello worker",
                    ]
                )
            self.assertEqual(rc_bad, 1)
            self.assertIn("differs from security-verified version", err_mismatch.getvalue())


def _build_der_cert_with_aia_ocsp(port: int) -> bytes:
    """Build a minimal valid X.509 v3 DER certificate with AIA and OCSP URLs pointing to 127.0.0.1:<port>."""

    def _der_len(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(b)]) + b

    def _tlv(tag: int, content: bytes) -> bytes:
        return bytes([tag]) + _der_len(len(content)) + content

    def _seq(content: bytes) -> bytes:
        return _tlv(0x30, content)

    def _oid(arc_list: list[int]) -> bytes:
        out = bytearray([40 * arc_list[0] + arc_list[1]])
        for val in arc_list[2:]:
            if val == 0:
                out.append(0)
            else:
                chunks: list[int] = []
                v = val
                while v > 0:
                    chunks.append(v & 0x7F)
                    v >>= 7
                for c in reversed(chunks[1:]):
                    out.append(c | 0x80)
                out.append(chunks[0])
        return _tlv(0x06, bytes(out))

    # Version v3
    version = _tlv(0xA0, _tlv(0x02, b"\x02"))
    serial = _tlv(0x02, b"\x01\x01")
    # sha256WithRSAEncryption (1.2.840.113549.1.1.11)
    sig_alg = _seq(_oid([1, 2, 840, 113549, 1, 1, 11]) + b"\x05\x00")
    cn_attr = _seq(_oid([2, 5, 4, 3]) + _tlv(0x0C, b"worker-test.local"))
    name = _seq(_tlv(0x31, cn_attr))
    validity = _seq(_tlv(0x17, b"250101000000Z") + _tlv(0x17, b"350101000000Z"))
    # Minimal 512-bit RSA SubjectPublicKeyInfo
    modulus = b"\x00" + (b"\x99" * 63) + b"\x01"
    rsa_pub = _seq(_tlv(0x02, modulus) + _tlv(0x02, b"\x01\x00\x01"))
    spki = _seq(
        _seq(_oid([1, 2, 840, 113549, 1, 1, 1]) + b"\x05\x00")
        + _tlv(0x03, b"\x00" + rsa_pub)
    )
    # AIA extension (1.3.6.1.5.5.7.1.1) with OCSP (1.3.6.1.5.5.7.48.1) and caIssuers (1.3.6.1.5.5.7.48.2)
    ocsp_url = f"http://127.0.0.1:{port}/ocsp".encode("ascii")
    aia_url = f"http://127.0.0.1:{port}/aia".encode("ascii")
    acc_ocsp = _seq(_oid([1, 3, 6, 1, 5, 5, 7, 48, 1]) + _tlv(0x86, ocsp_url))
    acc_aia = _seq(_oid([1, 3, 6, 1, 5, 5, 7, 48, 2]) + _tlv(0x86, aia_url))
    aia_ext_val = _seq(acc_ocsp + acc_aia)
    aia_ext = _seq(_oid([1, 3, 6, 1, 5, 5, 7, 1, 1]) + _tlv(0x04, aia_ext_val))
    exts = _tlv(0xA3, _seq(aia_ext))
    tbs = _seq(version + serial + sig_alg + name + validity + name + spki + exts)
    sig_bits = _tlv(0x03, b"\x00" + (b"\x55" * 64))
    return _seq(tbs + sig_alg + sig_bits)


@unittest.skipUnless(HAS_SANDBOX_EXEC, "macOS /usr/bin/sandbox-exec required")
class LiveSeatbeltAttackTests(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        _install_portable_lsof_fixture_if_absent(self)
        self._tmp = tempfile.TemporaryDirectory()
        self.ws_dir = Path(self._tmp.name) / "workspace"
        self.ws_dir.mkdir(parents=True, exist_ok=True)
        (self.ws_dir / "protected_dir" / "nested").mkdir(parents=True, exist_ok=True)
        (self.ws_dir / "protected_dir" / "nested" / "locked.txt").write_text(
            "locked\n", encoding="utf-8"
        )
        self.worker_id, self.isolated_home = allocate_worker_home()
        self.profile = apply_cli_overrides(
            default_unattended_worker_profile(),
            protected_paths=["protected_dir/nested/locked.txt"],
        )
        self.fake_opencode_bin = Path(OPENCODE_BIN) if OPENCODE_BIN else Path("/usr/bin/true")
        self.seatbelt_text = compile_seatbelt_profile(
            self.profile,
            workspace_dir=self.ws_dir,
            isolated_home=self.isolated_home,
            opencode_bin=self.fake_opencode_bin,
            upstream_port=9181,
            use_token_relay=True,
        )
        self.config_path, self.seatbelt_path, self.worker_shell = write_worker_runtime_artifacts(
            isolated_home=self.isolated_home,
            worker_id=self.worker_id,
            profile=self.profile,
            opencode_config={"provider": {"private_attested": {"options": {"apiKey": "worker-relay-test"}}}},
            seatbelt_text=self.seatbelt_text,
        )
        self.worker_env = build_worker_environment(
            self.profile,
            isolated_home=self.isolated_home,
            worker_id=self.worker_id,
        )

    def tearDown(self) -> None:
        cleanup_worker_home(self.isolated_home, worker_id=self.worker_id, harvest_logs=False)
        self._tmp.cleanup()

    def _run_in_sandbox(self, cmd: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/usr/bin/sandbox-exec", "-f", str(self.seatbelt_path), *cmd],
            cwd=str(cwd or self.ws_dir),
            env=self.worker_env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )

    def test_r3_blocker1_trustd_certificate_aia_ocsp_triggers_zero_requests(self) -> None:
        hits: list[str] = []
        sub_der_payload: list[bytes] = [b""]

        class _HitHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                hits.append(self.path)
                self.send_response(200)
                if self.path == "/ca.cer" and sub_der_payload[0]:
                    self.send_header("Content-Type", "application/pkix-cert")
                    self.send_header("Content-Length", str(len(sub_der_payload[0])))
                    self.end_headers()
                    self.wfile.write(sub_der_payload[0])
                else:
                    self.end_headers()

            def do_POST(self) -> None:
                hits.append(self.path)
                self.send_response(200)
                self.end_headers()

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _HitHandler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        port = srv.server_address[1]
        ca_key = self.ws_dir / "ca.key"
        ca_crt = self.ws_dir / "ca.crt"
        sub_key = self.ws_dir / "sub.key"
        sub_csr = self.ws_dir / "sub.csr"
        sub_crt = self.ws_dir / "sub.crt"
        sub_der = self.ws_dir / "sub.der"
        leaf_key = self.ws_dir / "leaf.key"
        leaf_csr = self.ws_dir / "leaf.csr"
        leaf_crt = self.ws_dir / "leaf.crt"
        leaf_der = self.ws_dir / "leaf.der"
        ca_der = self.ws_dir / "ca.der"
        ca_ext = self.ws_dir / "ca_ext.cnf"
        ca_ext.write_text(
            "[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\n"
            "basicConstraints=critical,CA:TRUE\n"
            "keyUsage=critical,keyCertSign,cRLSign\n"
            "subjectKeyIdentifier=hash\n",
            encoding="utf-8",
        )
        ext = self.ws_dir / "ext.cnf"
        ext.write_text(
            "basicConstraints=CA:FALSE\n"
            "keyUsage=digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            "authorityKeyIdentifier=keyid,issuer\n"
            f"authorityInfoAccess = OCSP;URI:http://127.0.0.1:{port}/ocsp,"
            f"caIssuers;URI:http://127.0.0.1:{port}/ca.cer\n"
            f"crlDistributionPoints = URI:http://127.0.0.1:{port}/crl.pem\n",
            encoding="utf-8",
        )
        subprocess.run(
            [
                "/usr/bin/openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(ca_key),
                "-out",
                str(ca_crt),
                "-days",
                "1",
                "-subj",
                "/CN=TestRootCA",
                "-config",
                str(ca_ext),
                "-extensions",
                "v3_ca",
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "/usr/bin/openssl",
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(sub_key),
                "-out",
                str(sub_csr),
                "-subj",
                "/CN=TestSubCA",
                "-config",
                str(ca_ext),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "/usr/bin/openssl",
                "x509",
                "-req",
                "-in",
                str(sub_csr),
                "-CA",
                str(ca_crt),
                "-CAkey",
                str(ca_key),
                "-CAcreateserial",
                "-out",
                str(sub_crt),
                "-days",
                "1",
                "-extfile",
                str(ca_ext),
                "-extensions",
                "v3_ca",
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "/usr/bin/openssl",
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(leaf_key),
                "-out",
                str(leaf_csr),
                "-subj",
                "/CN=leaf.local",
                "-config",
                str(ca_ext),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "/usr/bin/openssl",
                "x509",
                "-req",
                "-in",
                str(leaf_csr),
                "-CA",
                str(sub_crt),
                "-CAkey",
                str(sub_key),
                "-CAcreateserial",
                "-out",
                str(leaf_crt),
                "-days",
                "1",
                "-extfile",
                str(ext),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "/usr/bin/openssl",
                "x509",
                "-in",
                str(leaf_crt),
                "-outform",
                "DER",
                "-out",
                str(leaf_der),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "/usr/bin/openssl",
                "x509",
                "-in",
                str(sub_crt),
                "-outform",
                "DER",
                "-out",
                str(sub_der),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "/usr/bin/openssl",
                "x509",
                "-in",
                str(ca_crt),
                "-outform",
                "DER",
                "-out",
                str(ca_der),
            ],
            check=True,
            capture_output=True,
        )
        sub_der_payload[0] = sub_der.read_bytes()
        probe_py = self.ws_dir / "trustd_probe.py"
        probe_py.write_text(
            "import ctypes, pathlib\n"
            "sec = ctypes.CDLL('/System/Library/Frameworks/Security.framework/Security')\n"
            "cf = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')\n"
            "libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib')\n"
            "bp = ctypes.c_uint32.in_dll(libc, 'bootstrap_port').value\n"
            "libc.bootstrap_look_up.argtypes = [ctypes.c_uint32, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32)]\n"
            "libc.bootstrap_look_up.restype = ctypes.c_int32\n"
            "sp1 = ctypes.c_uint32(0)\n"
            "rc_trustd = libc.bootstrap_look_up(bp, b'com.apple.trustd.agent', ctypes.byref(sp1))\n"
            "sp2 = ctypes.c_uint32(0)\n"
            "rc_sec = libc.bootstrap_look_up(bp, b'com.apple.SecurityServer', ctypes.byref(sp2))\n"
            "sp3 = ctypes.c_uint32(0)\n"
            "rc_trustd_sys = libc.bootstrap_look_up(bp, b'com.apple.trustd', ctypes.byref(sp3))\n"
            "cf.CFDataCreate.restype = ctypes.c_void_p\n"
            "cf.CFDataCreate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_long]\n"
            "sec.SecCertificateCreateWithData.restype = ctypes.c_void_p\n"
            "sec.SecCertificateCreateWithData.argtypes = [ctypes.c_void_p, ctypes.c_void_p]\n"
            "sec.SecPolicyCreateSSL.restype = ctypes.c_void_p\n"
            "sec.SecPolicyCreateSSL.argtypes = [ctypes.c_bool, ctypes.c_void_p]\n"
            "sec.SecPolicyCreateRevocation.restype = ctypes.c_void_p\n"
            "sec.SecPolicyCreateRevocation.argtypes = [ctypes.c_ulong]\n"
            "cf.CFArrayCreate.restype = ctypes.c_void_p\n"
            "cf.CFArrayCreate.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_long, ctypes.c_void_p]\n"
            "sec.SecTrustCreateWithCertificates.restype = ctypes.c_int32\n"
            "sec.SecTrustCreateWithCertificates.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]\n"
            "sec.SecTrustSetAnchorCertificates.restype = ctypes.c_int32\n"
            "sec.SecTrustSetAnchorCertificates.argtypes = [ctypes.c_void_p, ctypes.c_void_p]\n"
            "sec.SecTrustSetNetworkFetchAllowed.restype = ctypes.c_int32\n"
            "sec.SecTrustSetNetworkFetchAllowed.argtypes = [ctypes.c_void_p, ctypes.c_bool]\n"
            "sec.SecTrustEvaluateWithError.restype = ctypes.c_bool\n"
            "sec.SecTrustEvaluateWithError.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]\n"
            f"lb = pathlib.Path({str(leaf_der)!r}).read_bytes()\n"
            f"cb = pathlib.Path({str(ca_der)!r}).read_bytes()\n"
            "l_cert = sec.SecCertificateCreateWithData(None, cf.CFDataCreate(None, lb, len(lb)))\n"
            "c_cert = sec.SecCertificateCreateWithData(None, cf.CFDataCreate(None, cb, len(cb)))\n"
            "pol_ssl = sec.SecPolicyCreateSSL(True, None)\n"
            "pol_rev = sec.SecPolicyCreateRevocation((1 << 0) | (1 << 3))\n"
            "pol_arr = (ctypes.c_void_p * 2)(pol_ssl, pol_rev)\n"
            "policies = cf.CFArrayCreate(None, pol_arr, 2, None)\n"
            "trust = ctypes.c_void_p()\n"
            "st_create = sec.SecTrustCreateWithCertificates(l_cert, policies, ctypes.byref(trust))\n"
            "ca_arr = (ctypes.c_void_p * 1)(c_cert)\n"
            "anchors = cf.CFArrayCreate(None, ca_arr, 1, None)\n"
            "st_anc = sec.SecTrustSetAnchorCertificates(trust, anchors)\n"
            "st_net = sec.SecTrustSetNetworkFetchAllowed(trust, True)\n"
            "assert st_create == 0 and st_anc == 0 and st_net == 0, f'{st_create}/{st_anc}/{st_net}'\n"
            "err = ctypes.c_void_p()\n"
            "sec.SecTrustEvaluateWithError(trust, ctypes.byref(err))\n"
            "print(f'evaluated rc_trustd={rc_trustd} rc_trustd_sys={rc_trustd_sys} rc_sec={rc_sec}')\n",
            encoding="utf-8",
        )
        try:
            # 1. Inside worker sandbox: trustd & SecurityServer Mach lookups are denied and 0 AIA/OCSP HTTP hits occur
            res = self._run_in_sandbox([sys.executable, str(probe_py)])
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("evaluated", res.stdout)
            self.assertNotIn("rc_trustd=0", res.stdout)
            self.assertNotIn("rc_trustd_sys=0", res.stdout)
            self.assertNotIn("rc_sec=0", res.stdout)
            time.sleep(0.25)
            self.assertEqual(hits, [])

            # 2. Positive control (R2-MINOR-1): running the exact same probe script unsandboxed (where
            # com.apple.trustd.agent, com.apple.trustd, and com.apple.SecurityServer are reachable)
            # succeeds on all Mach lookups, and on interactive macOS hosts triggers AIA/OCSP HTTP requests.
            unsandboxed = subprocess.run(
                [sys.executable, str(probe_py)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(unsandboxed.returncode, 0, unsandboxed.stderr)
            self.assertIn("rc_trustd=0 rc_trustd_sys=0 rc_sec=0", unsandboxed.stdout)
            time.sleep(0.25)
            if os.environ.get("GITHUB_ACTIONS") != "true":
                self.assertGreaterEqual(
                    len(hits), 1, f"Expected unsandboxed trustd AIA/OCSP hits, got {hits}"
                )
        finally:
            srv.shutdown()
            srv.server_close()

    def test_containing_write_root_denies_writes_to_runs_and_sibling_worker_homes(self) -> None:
        # WORK-MAJOR-1, WORK-MAJOR-3, & R2-MAJOR-3: even when write_roots includes LAB_ROOT
        # (containing runs/ and .home/), writes and renames targeting runs/, sibling worker homes
        # (including sibling .git/HEAD and .git/objects/...), or the local-assist-runs directory
        # itself are kernel-denied while this worker's .tmp, normal workspace .git plumbing, and
        # files inside local-assist-runs remain writable.
        sibling_id, sibling_home = allocate_worker_home()
        dummy_audit = ROOT / "runs" / f".test-dummy-audit-{os.getpid()}.json"
        dummy_pid = ROOT / "runs" / f".serve-dummy-{os.getpid()}.pid"
        dummy_audit.parent.mkdir(parents=True, exist_ok=True)
        dummy_audit.write_text('{"status":"clean"}\n', encoding="utf-8")
        dummy_pid.write_text('{"pid":99999}\n', encoding="utf-8")
        sibling_shell = sibling_home / "bin" / "worker-shell"
        sibling_shell.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        sibling_agents = sibling_home / ".config" / "opencode" / "AGENTS.md"
        sibling_git_dir = sibling_home / ".tmp" / "repo" / ".git"
        (sibling_git_dir / "objects" / "aa").mkdir(parents=True, exist_ok=True)
        sibling_git_head = sibling_git_dir / "HEAD"
        sibling_git_head.write_text("ref: refs/heads/main\n", encoding="utf-8")
        sibling_git_obj = sibling_git_dir / "objects" / "aa" / "bb"
        sibling_git_obj.write_text("clean-obj\n", encoding="utf-8")

        own_git_dir = self.isolated_home / ".tmp" / "repo" / ".git"
        own_git_dir.mkdir(parents=True, exist_ok=True)
        own_git_head = own_git_dir / "HEAD"
        own_git_head.write_text("ref: refs/heads/main\n", encoding="utf-8")
        try:
            lab_write_profile = parse_security_profile_dict(
                {
                    "filesystem": {
                        "read_roots": [str(ROOT), str(self.ws_dir)],
                        "write_roots": [str(ROOT)],
                    },
                    "mcp": {"enable_local_assist": True},
                }
            )
            sb_text = compile_seatbelt_profile(
                lab_write_profile,
                workspace_dir=self.ws_dir,
                isolated_home=self.isolated_home,
                opencode_bin=self.fake_opencode_bin,
                upstream_port=9181,
                use_token_relay=True,
            )
            sb_file = self.isolated_home / "lab-write-worker.sb"
            sb_file.write_text(sb_text, encoding="utf-8")

            def _run_lab_sb(cmd: list[str]) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["/usr/bin/sandbox-exec", "-f", str(sb_file), *cmd],
                    cwd=str(self.ws_dir),
                    env=self.worker_env,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )

            for blocked_cmd in (
                f"echo overwrite > {dummy_audit}",
                f"echo overwrite > {dummy_pid}",
                f"echo pwn > {sibling_shell}",
                f"echo pwn > {sibling_agents}",
                f"echo pwn > {sibling_git_head}",
                f"echo pwn > {sibling_git_obj}",
                f"mv {ROOT / 'runs'} {ROOT / 'runs-renamed'}",
                f"mv {ROOT / '.home'} {ROOT / '.home-renamed'}",
                f"rmdir {self.isolated_home / '.local' / 'share' / 'local-assist-runs'}",
                f"mv {self.isolated_home / '.local' / 'share' / 'local-assist-runs'} {self.isolated_home / '.tmp' / 'moved-runs'}",
            ):
                res_blk = _run_lab_sb([str(self.worker_shell), "-c", blocked_cmd])
                self.assertNotEqual(
                    res_blk.returncode, 0, f"Unexpectedly succeeded: {blocked_cmd}"
                )

            self.assertEqual(dummy_audit.read_text(encoding="utf-8"), '{"status":"clean"}\n')
            self.assertEqual(dummy_pid.read_text(encoding="utf-8"), '{"pid":99999}\n')
            self.assertEqual(sibling_git_head.read_text(encoding="utf-8"), "ref: refs/heads/main\n")
            self.assertEqual(sibling_git_obj.read_text(encoding="utf-8"), "clean-obj\n")
            self.assertFalse(sibling_agents.exists())

            # Positive control: this worker's .tmp (including its own .git/HEAD) remains writable by general python,
            # whereas local-assist-runs is denied to general python (F2)
            res_ok = _run_lab_sb(
                [
                    sys.executable,
                    "-c",
                    (
                        f"import pathlib; "
                        f"pathlib.Path({str(self.isolated_home / '.tmp' / 'ok.txt')!r}).write_text('ok'); "
                        f"pathlib.Path({str(own_git_head)!r}).write_text('ref: refs/heads/dev\\n')"
                    ),
                ]
            )
            self.assertEqual(res_ok.returncode, 0, res_ok.stderr)
            res_denied_runs = _run_lab_sb(
                [
                    sys.executable,
                    "-c",
                    (
                        f"import pathlib; "
                        f"pathlib.Path({str(self.isolated_home / '.local' / 'share' / 'local-assist-runs' / 'ok.json')!r}).write_text('{{}}')"
                    ),
                ]
            )
            self.assertNotEqual(res_denied_runs.returncode, 0)
        finally:
            dummy_audit.unlink(missing_ok=True)
            dummy_pid.unlink(missing_ok=True)
            cleanup_worker_home(sibling_home, worker_id=sibling_id, harvest_logs=False)

    def test_worker_sandbox_local_assist_handoff_inside_seatbelt(self) -> None:
        # R2-MAJOR-2 & R3-MAJOR-1: macOS Seatbelt-specific test verifying that inside worker.sb
        # (where setuid /bin/ps fails), _verify_worker_sandbox_handoff verifies the outside server PID
        # and start time via libSystem proc_pidinfo(PROC_PIDTBSDINFO) and fails closed once the
        # outside server process terminates.
        from local_assist.registry import pid_file_for_model

        class _PassedVerifyProc:
            returncode = 0
            stdout = "qwen3-30b-a3b-2507-mlx-4bit\n"
            stderr = ""

        model_id = "qwen3-30b-a3b-2507-mlx-4bit"
        served_repo = "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit"

        outside_srv = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wid, iso_home = allocate_worker_home()
        try:
            live_pid = outside_srv.pid
            live_lstart = get_process_lstart(live_pid)
            self.assertTrue(live_lstart)

            with tempfile.TemporaryDirectory() as tmp:
                fake_runs = Path(tmp) / "runs"
                fake_runs.mkdir(parents=True, exist_ok=True)
                valid_pid_path = pid_file_for_model(model_id, fake_runs)
                valid_pid_path.write_text(
                    json.dumps(
                        {
                            "model_id": model_id,
                            "repo": served_repo,
                            "status": "ready",
                            "pid": live_pid,
                            "pid_lstart": live_lstart,
                            "port": 8080,
                            "hf_offline": True,
                        }
                    ),
                    encoding="utf-8",
                )
                handoff_file = write_verified_local_models_handoff(
                    isolated_home=iso_home,
                    worker_id=wid,
                    runs_dir=fake_runs,
                    verify_runner=lambda *a, **k: _PassedVerifyProc(),
                )
                prof = parse_security_profile_dict(
                    {
                        "filesystem": {
                            "read_roots": [str(self.ws_dir)],
                            "write_roots": [str(self.ws_dir)],
                        },
                        "mcp": {"enable_local_assist": True},
                    }
                )
                sb_path = iso_home / "worker.sb"
                sb_path.write_text(
                    compile_seatbelt_profile(
                        prof,
                        workspace_dir=self.ws_dir,
                        isolated_home=iso_home,
                        opencode_bin=self.fake_opencode_bin,
                    ),
                    encoding="utf-8",
                )
                sb_env = build_worker_environment(prof, isolated_home=iso_home, worker_id=wid)
                sb_env["LOCAL_ASSIST_WORKER_SANDBOX"] = "1"
                sb_env["LOCAL_ASSIST_AUTO_SERVE"] = "0"
                sb_env["LOCAL_ASSIST_VERIFIED_MODELS_FILE"] = str(handoff_file)

                sandbox_consumer_code = (
                    f"import sys; sys.path.insert(0, {str(ROOT)!r})\n"
                    "from unittest.mock import patch\n"
                    "from local_assist.registry import get_process_lstart\n"
                    "from local_assist.lifecycle import ensure_local_model_served\n"
                    f"assert get_process_lstart({live_pid}) is None, 'Expected setuid /bin/ps to fail in Seatbelt'\n"
                    f"with patch('local_assist.lifecycle.get_models', return_value=[{served_repo!r}]):\n"
                    f"    ensure_local_model_served({model_id!r}, auto_serve=False)\n"
                    "print('SANDBOX_HANDOFF_OK')\n"
                )
                cp_ok = subprocess.run(
                    ["/usr/bin/sandbox-exec", "-f", str(sb_path), sys.executable, "-c", sandbox_consumer_code],
                    cwd=str(self.ws_dir),
                    env=sb_env,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(cp_ok.returncode, 0, f"stdout={cp_ok.stdout}\nstderr={cp_ok.stderr}")
                self.assertIn("SANDBOX_HANDOFF_OK", cp_ok.stdout)

                outside_srv.terminate()
                outside_srv.wait(timeout=5)
                sandbox_dead_code = (
                    f"import sys; sys.path.insert(0, {str(ROOT)!r})\n"
                    "from unittest.mock import patch\n"
                    "from local_assist.errors import ModelUnavailable\n"
                    "from local_assist.lifecycle import ensure_local_model_served\n"
                    f"with patch('local_assist.lifecycle.get_models', return_value=[{served_repo!r}]):\n"
                    "    try:\n"
                    f"        ensure_local_model_served({model_id!r}, auto_serve=False)\n"
                    "    except ModelUnavailable:\n"
                    "        print('DEAD_PID_REJECTED')\n"
                    "        sys.exit(0)\n"
                    "sys.exit(1)\n"
                )
                cp_dead = subprocess.run(
                    ["/usr/bin/sandbox-exec", "-f", str(sb_path), sys.executable, "-c", sandbox_dead_code],
                    cwd=str(self.ws_dir),
                    env=sb_env,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(cp_dead.returncode, 0, f"stdout={cp_dead.stdout}\nstderr={cp_dead.stderr}")
                self.assertIn("DEAD_PID_REJECTED", cp_dead.stdout)
        finally:
            if outside_srv.poll() is None:
                outside_srv.kill()
                outside_srv.wait()
            cleanup_worker_home(iso_home, worker_id=wid, harvest_logs=False)

    def test_r2_blocker1_config_and_symlink_protection(self) -> None:
        # 1. Child shell cannot read opencode.json or .config
        res_read = self._run_in_sandbox(
            [str(self.worker_shell), "-c", f"cat {self.config_path}"]
        )
        self.assertNotEqual(res_read.returncode, 0)

        # 2. Child shell cannot write opencode.json, worker.sb, bin/worker-shell, or .config/opencode/AGENTS.md
        for target in (
            self.config_path,
            self.seatbelt_path,
            self.worker_shell,
            self.isolated_home / ".config" / "opencode" / "AGENTS.md",
        ):
            res_write = self._run_in_sandbox(
                [str(self.worker_shell), "-c", f"echo pwn > {target}"]
            )
            self.assertNotEqual(res_write.returncode, 0, f"Unexpectedly wrote to {target}")

        # 3. Symlink inside workspace pointing to <isolated_home>/.config/opencode/AGENTS.md is write-blocked
        sym_agents = self.ws_dir / "sym_agents.md"
        sym_agents.symlink_to(self.isolated_home / ".config" / "opencode" / "AGENTS.md")
        res_sym_write = self._run_in_sandbox(
            [
                sys.executable,
                "-c",
                f"import pathlib; pathlib.Path({str(sym_agents)!r}).write_text('evil')",
            ]
        )
        self.assertNotEqual(res_sym_write.returncode, 0)
        self.assertFalse((self.isolated_home / ".config" / "opencode" / "AGENTS.md").exists())

    def test_r2_blocker2_and_r3_major2_3_git_plumbing_and_attack_suite(self) -> None:
        # Initialize repository outside the sandbox with tracked .env.example and .gitattributes
        subprocess.run(["git", "init", "-b", "main"], cwd=str(self.ws_dir), check=True, capture_output=True)
        (self.ws_dir / ".env.example").write_text("EXAMPLE=1\n", encoding="utf-8")
        (self.ws_dir / ".gitattributes").write_text("* text=auto\n", encoding="utf-8")
        (self.ws_dir / "app.py").write_text("print('v1')\n", encoding="utf-8")
        subprocess.run(
            ["git", "add", ".env.example", ".gitattributes", "app.py"],
            cwd=str(self.ws_dir),
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=init",
                "-c",
                "user.email=init@local",
                "commit",
                "-m",
                "initial",
            ],
            cwd=str(self.ws_dir),
            check=True,
            capture_output=True,
        )

        # Tracked protected file check should NOT flag .env.example or .gitattributes,
        # but SHOULD flag protected_dir/nested/locked.txt if tracked.
        self.assertEqual(
            check_tracked_protected_files(
                self.ws_dir, protected_paths=self.profile.protected_paths
            ),
            [],
        )

        # 1. Verify 7-command git workflow inside the worker sandbox succeeds with neutral identity
        git_workflow_script = (
            "set -e\n"
            "echo 'print(\"v2\")' > app.py\n"
            "git add app.py\n"
            "git commit -m 'second commit'\n"
            "echo 'print(\"v3\")' > app.py\n"
            "git commit -m 'pathspec commit' app.py\n"
            "git checkout -b feature\n"
            "echo 'EXAMPLE=2' > .env.example\n"
            "git commit -m 'feature change' .env.example\n"
            "git checkout main\n"
            "git cherry-pick feature\n"
            "git revert --no-edit HEAD\n"
            "echo 'stash me' >> app.py\n"
            "git stash push -m 'test-stash'\n"
            "git stash pop\n"
            "git checkout -- app.py\n"
            "git gc --quiet\n"
            "git bisect start HEAD HEAD~2\n"
            "git bisect good\n"
            "git bisect reset\n"
        )
        res_git = self._run_in_sandbox([str(self.worker_shell), "-c", git_workflow_script])
        self.assertEqual(res_git.returncode, 0, f"git workflow failed:\n{res_git.stdout}\n{res_git.stderr}")

        # Verify neutral git author/committer metadata (R3-MINOR-4)
        log_out = subprocess.run(
            ["git", "log", "-1", "--format=%an <%ae> | %cn <%ce>"],
            cwd=str(self.ws_dir),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        self.assertEqual(log_out, "worker <worker@local> | worker <worker@local>")

        # 2. Verify all .git persistence / redirection / rebase-todo / container-relocation attacks are kernel-denied
        hook_marker = self.ws_dir / "hook_ran"
        (self.ws_dir / "sub" / ".git" / "hooks").mkdir(parents=True, exist_ok=True)
        (self.ws_dir / ".git" / "rebase-merge").mkdir(parents=True, exist_ok=True)
        # Recompile Seatbelt profile after creating sub/.git so existing nested repo ancestors are discovered (WORK-MAJOR-2).
        os.chmod(self.seatbelt_path, 0o600)
        self.seatbelt_path.write_text(
            compile_seatbelt_profile(
                self.profile,
                workspace_dir=self.ws_dir,
                isolated_home=self.isolated_home,
                opencode_bin=self.fake_opencode_bin,
                upstream_port=9181,
                use_token_relay=True,
            ),
            encoding="utf-8",
        )
        os.chmod(self.seatbelt_path, 0o400)

        for attack_cmd in (
            "echo ../evil > .git/commondir",
            "echo ../evil > .git/COMMONDIR",
            "echo ../evil > .git/gitdir",
            "echo '[core]' > .git/config.worktree",
            "echo 'exec touch hook_ran' > .git/rebase-merge/git-rebase-todo",
            "echo x > .git/arbitrary_file",
            f"echo '#!/bin/sh\ntouch {hook_marker}' > .git/hooks/pre-commit",
            "echo '[core]\nfsmonitor = touch pwn' >> .git/config",
            "mv .git .git2",
            "echo '#!/bin/sh' > sub/.git/hooks/pre-commit",
            "mv sub \"$TMPDIR/sub_relocated\"",
            "mkdir -p \"$TMPDIR/staged_sub/.git/hooks\" && echo '#!/bin/sh' > \"$TMPDIR/staged_sub/.git/hooks/pre-commit\"",
            "mkdir -p \"$TMPDIR/staged_sub\" && echo SECRET=1 > \"$TMPDIR/staged_sub/.env\"",
            "mkdir -p \"$TMPDIR/staged_sub\" && echo '{}' > \"$TMPDIR/staged_sub/opencode.json\"",
            "echo SECRET=1 > .env",
            "echo SECRET=1 > .env.local",
            "echo '{}' > opencode.json",
            "mv protected_dir protected_dir_renamed",
            "mv protected_dir/nested protected_dir/nested_renamed",
            "echo overwrite > protected_dir/nested/locked.txt",
        ):
            atk_res = self._run_in_sandbox([str(self.worker_shell), "-c", attack_cmd])
            self.assertNotEqual(atk_res.returncode, 0, f"Attack unexpectedly succeeded: {attack_cmd}")
        self.assertFalse((self.ws_dir / "sub" / ".git" / "hooks" / "pre-commit").exists())

        # Verify subsequent git commit outside the sandbox executes zero hooks
        (self.ws_dir / "app.py").write_text("print('host commit')\n", encoding="utf-8")
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=host",
                "-c",
                "user.email=host@local",
                "commit",
                "-am",
                "host commit",
            ],
            cwd=str(self.ws_dir),
            check=True,
            capture_output=True,
        )
        self.assertFalse(hook_marker.exists())

    def test_signals_windowserver_dns_ports_and_exec_lockdown(self) -> None:
        # 1. Signaling host parent PID is denied, while signaling a child inside the sandbox succeeds
        parent_pid = os.getpid()
        res_kill_host = self._run_in_sandbox(
            [sys.executable, "-c", f"import os; os.kill({parent_pid}, 0)"]
        )
        self.assertNotEqual(res_kill_host.returncode, 0)

        res_kill_child = self._run_in_sandbox(
            [
                sys.executable,
                "-c",
                "import os, signal, subprocess; p = subprocess.Popen(['/bin/sleep', '10']); os.kill(p.pid, signal.SIGTERM); p.wait()",
            ]
        )
        self.assertEqual(res_kill_child.returncode, 0, res_kill_child.stderr)

        # 2. CGWindowListCopyWindowInfo returns None / 0 windows (WindowServer mach-lookup denied)
        cg_code = (
            "import ctypes\n"
            "cg = ctypes.CDLL('/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics')\n"
            "cg.CGWindowListCopyWindowInfo.restype = ctypes.c_void_p\n"
            "cg.CGWindowListCopyWindowInfo.argtypes = [ctypes.c_uint32, ctypes.c_uint32]\n"
            "res = cg.CGWindowListCopyWindowInfo(0, 0)\n"
            "assert res is None or res == 0, f'Expected None, got {res}'\n"
        )
        res_cg = self._run_in_sandbox([sys.executable, "-c", cg_code])
        self.assertEqual(res_cg.returncode, 0, res_cg.stderr)

        # 3. DNS resolution (mDNSResponder) and loopback/external TCP connects fail from child processes
        res_dns = self._run_in_sandbox(
            [sys.executable, "-c", "import socket; socket.gethostbyname('example.com')"]
        )
        self.assertNotEqual(res_dns.returncode, 0)

        for host, port in (
            ("127.0.0.1", 8080),
            ("127.0.0.1", 8081),
            ("127.0.0.1", 9081),
            ("127.0.0.1", 49374),
            ("1.1.1.1", 80),
        ):
            res_net = self._run_in_sandbox(
                [
                    sys.executable,
                    "-c",
                    (
                        "import errno, socket, sys\n"
                        "s = socket.socket()\n"
                        "s.settimeout(1.0)\n"
                        "try:\n"
                        f"    s.connect(({host!r}, {port}))\n"
                        "    sys.exit(0)\n"
                        "except OSError as exc:\n"
                        "    assert exc.errno in (errno.EPERM, errno.EACCES), f'Expected EPERM/EACCES, got {exc!r}'\n"
                        "    sys.exit(42)\n"
                    ),
                ]
            )
            self.assertEqual(res_net.returncode, 42, f"Expected EPERM on {host}:{port}, got {res_net.stderr}")

        # Positive control with two live TCP listeners: allowed localhost port succeeds, denied localhost port returns EPERM.
        allow_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        deny_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        allow_sock.bind(("127.0.0.1", 0))
        deny_sock.bind(("127.0.0.1", 0))
        allow_sock.listen(4)
        deny_sock.listen(4)
        allow_port = allow_sock.getsockname()[1]
        deny_port = deny_sock.getsockname()[1]
        try:
            port_prof = parse_security_profile_dict(
                {
                    "network": {
                        "allowed_shell_localhost_ports": [allow_port],
                        "denied_localhost_ports": [deny_port],
                    }
                }
            )
            port_sb = self.isolated_home / "port-control.sb"
            port_sb.write_text(
                compile_seatbelt_profile(
                    port_prof,
                    workspace_dir=self.ws_dir,
                    isolated_home=self.isolated_home,
                    opencode_bin=self.fake_opencode_bin,
                ),
                encoding="utf-8",
            )
            res_allow_port = subprocess.run(
                [
                    "/usr/bin/sandbox-exec",
                    "-f",
                    str(port_sb),
                    sys.executable,
                    "-c",
                    f"import socket; s = socket.create_connection(('127.0.0.1', {allow_port}), timeout=2.0); s.close()",
                ],
                cwd=str(self.ws_dir),
                env=self.worker_env,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(res_allow_port.returncode, 0, res_allow_port.stderr)

            res_deny_port = subprocess.run(
                [
                    "/usr/bin/sandbox-exec",
                    "-f",
                    str(port_sb),
                    sys.executable,
                    "-c",
                    (
                        "import errno, socket, sys\n"
                        "try:\n"
                        f"    socket.create_connection(('127.0.0.1', {deny_port}), timeout=2.0)\n"
                        "    sys.exit(0)\n"
                        "except OSError as exc:\n"
                        "    assert exc.errno in (errno.EPERM, errno.EACCES), f'Expected EPERM, got {exc!r}'\n"
                        "    sys.exit(42)\n"
                    ),
                ],
                cwd=str(self.ws_dir),
                env=self.worker_env,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(res_deny_port.returncode, 42, res_deny_port.stderr)
        finally:
            allow_sock.close()
            deny_sock.close()

        # 4. Forbidden binaries cannot be executed by child shell processes
        denied_bins = [
            "/usr/bin/security",
            "/usr/bin/defaults",
            "/usr/bin/open",
            "/usr/bin/osascript",
            "/bin/launchctl",
            "/usr/bin/pbpaste",
        ]
        if OPENCODE_BIN:
            denied_bins.append(OPENCODE_BIN)
        for bin_path in denied_bins:
            res_exec = self._run_in_sandbox([str(self.worker_shell), "-c", f"{bin_path} --version"])
            self.assertNotEqual(res_exec.returncode, 0, f"Unexpectedly executed {bin_path}")


@unittest.skipUnless(
    HAS_SANDBOX_EXEC and OPENCODE_BIN is not None,
    "macOS /usr/bin/sandbox-exec and opencode binary required",
)
class LiveOpenCodeWorkerIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        _install_portable_lsof_fixture_if_absent(self)

    def test_opencode_run_standalone_symlink_mcp_and_process_reaping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws_dir = Path(tmp) / "ws"
            ws_dir.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", "-b", "main"], cwd=str(ws_dir), check=True, capture_output=True)

            # Write a tiny stdio MCP server mocking agent_comms with whoami and dispatch_agent tools
            mcp_script = ws_dir / "mock_agent_comms_mcp.py"
            mcp_script.write_text(
                f"import sys\nsys.path.insert(0, {str(ROOT)!r})\n"
                "from local_assist.server import read_message_with_framing, write_message, result\n"
                "framing = None\n"
                "while True:\n"
                "    msg, framing = read_message_with_framing(session_framing=framing)\n"
                "    if msg is None:\n"
                "        break\n"
                "    method = msg.get('method')\n"
                "    msg_id = msg.get('id')\n"
                "    if method == 'initialize':\n"
                "        write_message(result(msg_id, {\n"
                "            'protocolVersion': (msg.get('params') or {}).get('protocolVersion') or '2024-11-05',\n"
                "            'capabilities': {'tools': {}},\n"
                "            'serverInfo': {'name': 'agent_comms', 'version': '0.1.0'}\n"
                "        }), framing=framing)\n"
                "    elif method == 'tools/list':\n"
                "        write_message(result(msg_id, {'tools': [\n"
                "            {'name': 'whoami', 'description': 'Return identity', 'inputSchema': {'type': 'object', 'properties': {}, 'additionalProperties': False}},\n"
                "            {'name': 'dispatch_agent', 'description': 'Forbidden dispatch', 'inputSchema': {'type': 'object', 'properties': {}, 'additionalProperties': False}}\n"
                "        ]}), framing=framing)\n"
                "    elif method == 'tools/call':\n"
                "        name = (msg.get('params') or {}).get('name')\n"
                "        write_message(result(msg_id, {\n"
                "            'content': [{'type': 'text', 'text': f'MCP_CALL_OK:{name}'}],\n"
                "            'isError': False\n"
                "        }), framing=framing)\n"
                "    elif msg_id is not None:\n"
                "        write_message(result(msg_id, {}), framing=framing)\n",
                encoding="utf-8",
            )

            worker_id, isolated_home = allocate_worker_home()
            sleep_marker = f"WORKER_SLEEP_MARKER_{worker_id}"
            turn_counter = 0
            observed_tool_Outputs: list[str] = []
            observed_available_tools: list[list[str]] = []

            class _MockOpenAIPlanner(BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"

                def log_message(self, format: str, *args: Any) -> None:
                    return

                def do_GET(self) -> None:
                    body = json.dumps({"data": [{"id": "mock-worker-model"}]}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def do_POST(self) -> None:
                    nonlocal turn_counter
                    cl = int(self.headers.get("Content-Length", "0"))
                    req_json = json.loads(self.rfile.read(cl).decode("utf-8"))
                    req_tools = [
                        str((t.get("function") or {}).get("name"))
                        for t in (req_json.get("tools") or [])
                        if isinstance(t, dict)
                    ]
                    observed_available_tools.append(req_tools)
                    # Ignore parallel small_model title-generation requests that have no tools.
                    if not req_tools:
                        msg_obj: dict[str, Any] = {
                            "role": "assistant",
                            "content": "Worker probe",
                        }
                        finish_reason = "stop"
                    else:
                        messages = req_json.get("messages") or []
                        for m in messages:
                            if m.get("role") == "tool":
                                observed_tool_Outputs.append(str(m.get("content", "")))

                        turn_counter += 1
                        if turn_counter == 1:
                            shell_cmd = (
                                f"ln -sf {isolated_home}/opencode.json sym_cfg.json; "
                                f"ln -sf {isolated_home}/.config/opencode/AGENTS.md sym_agents.md; "
                                "echo ../evil > .git/commondir 2>/dev/null || true; "
                                f"python3 -c \"import time; time.sleep(120)\" {sleep_marker} >/dev/null 2>&1 & "
                                "echo SHELL_DONE"
                            )
                            tool_calls = [
                                {
                                    "id": "call_shell_1",
                                    "type": "function",
                                    "function": {
                                        "name": "shell",
                                        "arguments": json.dumps(
                                            {"command": shell_cmd, "description": "probe"}
                                        ),
                                    },
                                },
                            ]
                            msg_obj = {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": tool_calls,
                            }
                            finish_reason = "tool_calls"
                        elif turn_counter == 2:
                            tool_calls = [
                                {
                                    "id": "call_mcp_ok",
                                    "type": "function",
                                    "function": {
                                        "name": "agent_comms_whoami",
                                        "arguments": "{}",
                                    },
                                },
                                {
                                    "id": "call_mcp_denied",
                                    "type": "function",
                                    "function": {
                                        "name": "agent_comms_dispatch_agent",
                                        "arguments": "{}",
                                    },
                                },
                                {
                                    "id": "call_read_sym",
                                    "type": "function",
                                    "function": {
                                        "name": "read",
                                        "arguments": json.dumps(
                                            {"path": str(ws_dir / "sym_cfg.json")}
                                        ),
                                    },
                                },
                                {
                                    "id": "call_write_sym",
                                    "type": "function",
                                    "function": {
                                        "name": "write",
                                        "arguments": json.dumps(
                                            {
                                                "path": str(ws_dir / "sym_agents.md"),
                                                "content": "INJECTED_PROMPT",
                                            }
                                        ),
                                    },
                                },
                                {
                                    "id": "call_webfetch_denied",
                                    "type": "function",
                                    "function": {
                                        "name": "webfetch",
                                        "arguments": json.dumps(
                                            {"url": "http://127.0.0.1:1"}
                                        ),
                                    },
                                },
                            ]
                            msg_obj = {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": tool_calls,
                            }
                            finish_reason = "tool_calls"
                        else:
                            msg_obj = {
                                "role": "assistant",
                                "content": "WORKER_TRIAL_COMPLETE",
                            }
                            finish_reason = "stop"

                    if req_json.get("stream"):
                        self.send_response(200)
                        self.send_header("Content-Type", "text/event-stream")
                        self.end_headers()
                        delta: dict[str, Any] = {"role": "assistant"}
                        if msg_obj.get("content"):
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
                            "id": f"chatcmpl-{turn_counter}",
                            "object": "chat.completion.chunk",
                            "model": "mock-worker-model",
                            "choices": [
                                {"index": 0, "delta": delta, "finish_reason": finish_reason}
                            ],
                        }
                        self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode("utf-8"))
                        self.wfile.write(b"data: [DONE]\n\n")
                        self.wfile.flush()
                        return

                    resp_body = json.dumps(
                        {
                            "id": f"chatcmpl-{turn_counter}",
                            "object": "chat.completion",
                            "model": "mock-worker-model",
                            "choices": [
                                {
                                    "index": 0,
                                    "message": msg_obj,
                                    "finish_reason": finish_reason,
                                }
                            ],
                        }
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(resp_body)))
                    self.end_headers()
                    self.wfile.write(resp_body)

            planner_srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockOpenAIPlanner)
            planner_thread = threading.Thread(target=planner_srv.serve_forever, daemon=True)
            planner_thread.start()
            upstream_url = f"http://127.0.0.1:{planner_srv.server_address[1]}/v1"

            relay = _WorkerTokenRelay(
                upstream_base_url=upstream_url,
                upstream_session_token="se-session-live-integration-secret-token",
                max_chat_requests=10,
                max_request_bytes=262144,
                max_tokens_cap=2048,
            ).start()

            try:
                profile = parse_security_profile_dict(
                    {
                        "tools": {
                            "allowed_tools": ["read", "edit", "shell"],
                            "denied_tools": ["todowrite"],
                            "allow_subagents": False,
                        },
                        "mcp": {
                            "enable_local_assist": False,
                            "servers": {
                                "agent_comms": {
                                    "type": "local",
                                    "command": [sys.executable, str(mcp_script)],
                                }
                            },
                            "allowed_servers": ["agent_comms"],
                            "allowed_tools": ["agent_comms_whoami"],
                            "denied_tools": ["agent_comms_dispatch_agent"],
                        },
                    }
                )
                base_cfg = {
                    "autoupdate": False,
                    "share": "disabled",
                    "snapshot": False,
                    "lsp": False,
                    "formatter": False,
                    "enabled_providers": ["private-attested"],
                    "provider": {
                        "private-attested": {
                            "npm": "@opencode/ai/providers/openai-compatible",
                            "name": "Private Attested",
                            "options": {
                                "baseURL": relay.api_base_url,
                                "apiKey": relay.relay_token,
                                "timeout": 180000,
                            },
                            "models": {
                                "mock-worker-model": {
                                    "id": "mock-worker-model",
                                    "name": "mock-worker-model",
                                    "tool_call": True,
                                    "modalities": {
                                        "input": ["text"],
                                        "output": ["text"],
                                    },
                                    "limit": {"context": 32768, "output": 2048},
                                }
                            },
                        }
                    },
                    "model": "private-attested/mock-worker-model",
                    "small_model": "private-attested/mock-worker-model",
                }
                compiled_cfg = compile_opencode_security_config(
                    base_cfg, profile, isolated_home=isolated_home
                )
                assert OPENCODE_BIN is not None
                # WORK-MAJOR-6: verify_opencode_version succeeds without --allow-opencode-version-drift
                self.assertEqual(
                    verify_opencode_version(OPENCODE_BIN, allow_version_drift=False),
                    TESTED_OPENCODE_VERSION,
                )
                seatbelt_text = compile_seatbelt_profile(
                    profile,
                    workspace_dir=ws_dir,
                    isolated_home=isolated_home,
                    opencode_bin=Path(OPENCODE_BIN),
                    use_token_relay=True,
                )
                # Allow mock_agent_comms_mcp.py to import local_assist.server from ROOT
                seatbelt_text += f'\n(allow file-read-data (subpath "{ROOT}"))\n'
                _, seatbelt_path, _ = write_worker_runtime_artifacts(
                    isolated_home=isolated_home,
                    worker_id=worker_id,
                    profile=profile,
                    opencode_config=compiled_cfg,
                    seatbelt_text=seatbelt_text,
                )
                env = build_worker_environment(
                    profile,
                    isolated_home=isolated_home,
                    worker_id=worker_id,
                )
                validated_args = validate_worker_opencode_args(
                    ["run", "--format", "json", "Run integration probe"]
                )
                proc = subprocess.run(
                    [
                        "/usr/bin/sandbox-exec",
                        "-f",
                        str(seatbelt_path),
                        OPENCODE_BIN,
                        *validated_args,
                    ],
                    cwd=str(ws_dir),
                    env=env,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=45,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0, f"opencode run failed:\n{proc.stdout}\n{proc.stderr}")
                self.assertIn("WORKER_TRIAL_COMPLETE", proc.stdout)

                joined_tools = "\n".join(observed_tool_Outputs)
                # 1. No se-session-* token anywhere in tool outputs or stdout
                self.assertNotIn("se-session-", joined_tools)
                self.assertNotIn("se-session-", proc.stdout)
                # 2. Allowed MCP tool whoami succeeded
                self.assertIn(
                    "MCP_CALL_OK:whoami",
                    joined_tools,
                    f"available_tools={observed_available_tools}\nstdout={proc.stdout}\nstderr={proc.stderr}",
                )
                # 3. Denied MCP tool dispatch_agent did NOT execute
                self.assertNotIn("MCP_CALL_OK:dispatch_agent", joined_tools)
                # 4. Symlink write to .config/opencode/AGENTS.md was blocked
                self.assertFalse((isolated_home / ".config" / "opencode" / "AGENTS.md").exists())
                # 5. .git/commondir planting was blocked
                self.assertFalse((ws_dir / ".git" / "commondir").exists())
                # 6. Denied webfetch tool was refused by OpenCode
                self.assertIn('No tool named \\"webfetch\\"', joined_tools)
                self.assertIn('No tool named \\"agent_comms_dispatch_agent\\"', joined_tools)
            finally:
                relay.close()
                planner_srv.shutdown()
                planner_srv.server_close()
                cleanup_worker_home(isolated_home, worker_id=worker_id, harvest_logs=False)

            # Verify stray background sleep process was reaped by cleanup_worker_home (R3-MINOR-3)
            ps_out = subprocess.run(
                ["/bin/ps", "eww", "-U", str(os.getuid()), "-o", "pid=,command="],
                capture_output=True,
                text=True,
                check=False,
            ).stdout
            self.assertNotIn(sleep_marker, ps_out)

    def test_harvest_worker_local_assist_logs_marks_untrusted_source(self) -> None:
        worker_id, isolated_home = allocate_worker_home()
        dest_dir: Path | None = None
        try:
            staging = isolated_home / ".local" / "share" / "local-assist-runs"
            day_dir = staging / "2026-11-04"
            day_dir.mkdir(parents=True, exist_ok=True)
            payload_file = day_dir / "12-00-00-extract-fields-abcd.json"
            orig_rel_path = "runs/local-assist/2026-11-04/12-00-00-extract-fields-abcd.json"
            payload_file.write_text(
                json.dumps(
                    {
                        "tool": "extract_fields",
                        "parsed_output": {"extracted": {}},
                        "payload_path": orig_rel_path,
                    }
                ),
                encoding="utf-8",
            )
            index_file = staging / "2026-11-04.jsonl"
            index_file.write_text(
                json.dumps(
                    {
                        "tool": "extract_fields",
                        "finish_reason": "stop",
                        "payload_path": orig_rel_path,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            dest_dir = harvest_worker_local_assist_logs(
                isolated_home=isolated_home, worker_id=worker_id
            )
            self.assertIsNotNone(dest_dir)
            assert dest_dir is not None
            expected_harvested_rel = (
                f"runs/local-assist/worker-sandbox/{worker_id}/2026-11-04/12-00-00-extract-fields-abcd.json"
            )
            harvested_payload = json.loads(
                (dest_dir / "2026-11-04" / "12-00-00-extract-fields-abcd.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertTrue(harvested_payload["sandbox_untrusted_source"])
            self.assertTrue(harvested_payload["worker_sandbox_preverified"])
            self.assertEqual(harvested_payload["worker_id"], worker_id)
            self.assertEqual(harvested_payload["payload_path"], expected_harvested_rel)
            self.assertEqual(harvested_payload["original_sandbox_payload_path"], orig_rel_path)

            harvested_index_row = json.loads(
                (dest_dir / "2026-11-04.jsonl").read_text(encoding="utf-8").strip()
            )
            self.assertEqual(harvested_index_row["payload_path"], expected_harvested_rel)
            self.assertEqual(harvested_index_row["original_sandbox_payload_path"], orig_rel_path)
            self.assertTrue((ROOT / harvested_index_row["payload_path"]).is_file())

            # WORK-MAJOR-3: symlinked file, symlinked subdirectory, and symlinked staging root
            # pointing to an out-of-scope host directory must never be harvested.
            with tempfile.TemporaryDirectory() as out_of_scope_tmp:
                out_dir = Path(out_of_scope_tmp)
                sentinel_json = out_dir / "sentinel.json"
                sentinel_json.write_text(
                    json.dumps({"secret": "TOP_SECRET_HOST_JSON"}), encoding="utf-8"
                )
                sentinel_jsonl = out_dir / "sentinel.jsonl"
                sentinel_jsonl.write_text(
                    json.dumps({"secret": "TOP_SECRET_HOST_JSONL"}) + "\n", encoding="utf-8"
                )

                # (a) Symlinked file and symlinked subdirectory inside staging
                (day_dir / "sym-file.json").symlink_to(sentinel_json)
                (staging / "sym-subdir").symlink_to(out_dir, target_is_directory=True)
                shutil.rmtree(dest_dir, ignore_errors=True)
                dest_dir_a = harvest_worker_local_assist_logs(
                    isolated_home=isolated_home, worker_id=worker_id
                )
                self.assertIsNotNone(dest_dir_a)
                assert dest_dir_a is not None
                self.assertFalse((dest_dir_a / "2026-11-04" / "sym-file.json").exists())
                self.assertFalse((dest_dir_a / "sym-subdir" / "sentinel.json").exists())

                # (b) Synchronized parent-directory substitution at the os.open boundary AFTER
                #     containment check (R2-MAJOR-4, R3-MINOR-1, R4-MINOR-1)
                from unittest.mock import patch

                race_day = staging / "2026-11-05"
                race_day.mkdir(parents=True, exist_ok=True)
                race_file = race_day / "sentinel.json"
                race_file.write_text(
                    json.dumps({"tool": "extract_fields", "parsed_output": {"extracted": {}}}),
                    encoding="utf-8",
                )
                real_os_open = os.open
                open_hook_triggered = False

                def _substituting_os_open(target: Any, flags: int, *o_args: Any, **o_kwargs: Any) -> int:
                    nonlocal open_hook_triggered
                    if target in ("2026-11-05", race_file, str(race_file)) and not race_day.is_symlink():
                        open_hook_triggered = True
                        shutil.rmtree(race_day)
                        race_day.symlink_to(out_dir, target_is_directory=True)
                    return real_os_open(target, flags, *o_args, **o_kwargs)

                # Control 1: the earlier resolve -> is_relative_to -> pathname os.open(O_NOFOLLOW)
                # reader leaks the outside sentinel under this exact os.open-boundary hook.
                def _legacy_resolve_then_pathname_open(path: Path, *, root_real: Path) -> str | None:
                    if path.is_symlink():
                        return None
                    resolved = path.resolve(strict=True)
                    if not resolved.is_relative_to(root_real):
                        return None
                    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                    try:
                        with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as h:
                            return h.read()
                    finally:
                        os.close(fd)

                with patch("os.open", side_effect=_substituting_os_open):
                    leaked_text = _legacy_resolve_then_pathname_open(
                        race_file, root_real=staging.resolve(strict=True)
                    )
                self.assertTrue(open_hook_triggered)
                self.assertIsNotNone(leaked_text)
                assert leaked_text is not None
                self.assertIn("TOP_SECRET_HOST_JSON", leaked_text)

                # Control 2: reset race_day as a real directory and run the production harvester
                # under the same os.open-boundary hook; descriptor-relative O_NOFOLLOW rejects the swap.
                race_day.unlink()
                race_day.mkdir(parents=True, exist_ok=True)
                race_file.write_text(
                    json.dumps({"tool": "extract_fields", "parsed_output": {"extracted": {}}}),
                    encoding="utf-8",
                )
                open_hook_triggered = False
                shutil.rmtree(dest_dir_a, ignore_errors=True)
                with patch(
                    "local_assist.security_profile.os.open",
                    side_effect=_substituting_os_open,
                ):
                    dest_dir_race = harvest_worker_local_assist_logs(
                        isolated_home=isolated_home, worker_id=worker_id
                    )
                self.assertTrue(open_hook_triggered)
                self.assertIsNotNone(dest_dir_race)
                assert dest_dir_race is not None
                self.assertFalse((dest_dir_race / "2026-11-05" / "sentinel.json").exists())
                # Ordinary file from 2026-11-04 was still harvested (positive control)
                self.assertTrue(
                    (dest_dir_race / "2026-11-04" / "12-00-00-extract-fields-abcd.json").is_file()
                )

                # (c) Replace staging root itself with a symlink to out_dir
                shutil.rmtree(staging)
                staging.symlink_to(out_dir, target_is_directory=True)
                shutil.rmtree(dest_dir_race, ignore_errors=True)
                dest_dir_b = harvest_worker_local_assist_logs(
                    isolated_home=isolated_home, worker_id=worker_id
                )
                self.assertIsNone(dest_dir_b)
                self.assertFalse((dest_dir / "sentinel.json").exists())
        finally:
            cleanup_worker_home(isolated_home, worker_id=worker_id, harvest_logs=False)
            if dest_dir is not None and dest_dir.exists():
                shutil.rmtree(dest_dir, ignore_errors=True)


class Phase2LookoutRemediationTests(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        _install_portable_lsof_fixture_if_absent(self)

    def test_f1_safe_rmtree_nofollow_blocks_symlink_swap_and_removes_readonly_tree(self) -> None:
        # Positive control: _safe_rmtree_nofollow removes read-only 0400 files and 0500 directories
        worker_id, isolated_home = allocate_worker_home()
        try:
            ro_dir = isolated_home / "ro_subdir"
            ro_dir.mkdir(parents=True, exist_ok=True)
            ro_file = ro_dir / "locked.txt"
            ro_file.write_text("readonly-content\n", encoding="utf-8")
            os.chmod(ro_file, 0o400)
            os.chmod(ro_dir, 0o500)
            self.assertTrue(cleanup_worker_home(isolated_home, worker_id=worker_id, harvest_logs=False))
            self.assertFalse(isolated_home.exists())
        finally:
            if isolated_home.exists():
                _safe_rmtree_nofollow(isolated_home)

        # Negative & race control: symlink substitution at cleanup boundary must never chmod or
        # unlink outside host files.
        with tempfile.TemporaryDirectory() as out_tmp:
            out_dir = Path(out_tmp)
            outside_sentinel = out_dir / "outside_readonly.txt"
            outside_sentinel.write_text("immutable-host-file\n", encoding="utf-8")
            os.chmod(outside_sentinel, 0o444)

            outside_subdir = out_dir / "outside_dir"
            outside_subdir.mkdir(parents=True, exist_ok=True)
            outside_nested = outside_subdir / "keep.txt"
            outside_nested.write_text("keep-me\n", encoding="utf-8")
            os.chmod(outside_nested, 0o444)

            # Control 1: legacy pathname chmod after is_symlink() mutates the outside 0444 file
            # when swapped right after the check.
            legacy_victim = out_dir / "legacy_victim.txt"
            legacy_victim.write_text("v\n", encoding="utf-8")
            if not legacy_victim.is_symlink():
                legacy_victim.unlink()
                legacy_victim.symlink_to(outside_sentinel)
                os.chmod(legacy_victim, 0o700)
            self.assertEqual(outside_sentinel.stat().st_mode & 0o777, 0o700)
            # Restore outside_sentinel to 0444
            os.chmod(outside_sentinel, 0o444)
            legacy_victim.unlink()

            # Control 2: production _safe_rmtree_nofollow under both static symlinks and a
            # synchronized scandir/unlink-boundary symlink swap leaves outside_sentinel at 0444
            # and outside_nested intact.
            worker_id2, isolated_home2 = allocate_worker_home()
            try:
                (isolated_home2 / "static_sym_file").symlink_to(outside_sentinel)
                (isolated_home2 / "static_sym_dir").symlink_to(
                    outside_subdir, target_is_directory=True
                )
                race_dir = isolated_home2 / "race_subdir"
                race_dir.mkdir(parents=True, exist_ok=True)
                race_child = race_dir / "child.txt"
                race_child.write_text("inside\n", encoding="utf-8")
                os.chmod(race_child, 0o400)
                os.chmod(race_dir, 0o500)

                real_os_open = os.open
                swap_triggered = False

                def _swap_on_race_dir_open(target: Any, flags: int, *args: Any, **kwargs: Any) -> int:
                    nonlocal swap_triggered
                    if target == "race_subdir" and not swap_triggered:
                        swap_triggered = True
                        os.chmod(race_dir, 0o700)
                        race_child.unlink()
                        race_dir.rmdir()
                        race_dir.symlink_to(outside_subdir, target_is_directory=True)
                    return real_os_open(target, flags, *args, **kwargs)

                from unittest.mock import patch

                with patch("local_assist.security_profile.os.open", side_effect=_swap_on_race_dir_open):
                    ok = cleanup_worker_home(
                        isolated_home2, worker_id=worker_id2, harvest_logs=False
                    )
                self.assertTrue(swap_triggered)
                self.assertTrue(ok)
                self.assertFalse(isolated_home2.exists())
                self.assertEqual(outside_sentinel.stat().st_mode & 0o777, 0o444)
                self.assertEqual(outside_sentinel.read_text(encoding="utf-8"), "immutable-host-file\n")
                self.assertTrue(outside_nested.is_file())
                self.assertEqual(outside_nested.stat().st_mode & 0o777, 0o444)
                self.assertEqual(outside_nested.read_text(encoding="utf-8"), "keep-me\n")
            finally:
                if isolated_home2.exists():
                    _safe_rmtree_nofollow(isolated_home2)
                os.chmod(outside_sentinel, 0o600)
                os.chmod(outside_nested, 0o600)

    @unittest.skipUnless(HAS_SANDBOX_EXEC, "macOS sandbox-exec required")
    def test_f2_dedicated_local_assist_python_and_lineage_isolation_inside_seatbelt(self) -> None:
        from local_assist.registry import pid_file_for_model

        model_id = "qwen3-30b-a3b-2507-mlx-4bit"
        served_repo = "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit"

        class _MockChatHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                raw = json.dumps(
                    {"object": "list", "data": [{"id": served_repo, "object": "model"}]}
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                _ = self.rfile.read(length) if length > 0 else b""
                resp = {
                    "id": "chatcmpl-f2-test",
                    "object": "chat.completion",
                    "model": served_repo,
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": json.dumps(
                                    {
                                        "extracted": {"owner": "alice"},
                                    }
                                ),
                            },
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20},
                }
                raw = json.dumps(resp).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, format: str, *args: Any) -> None:
                return

        # Try binding port 8080 if free, otherwise bind an ephemeral loopback port and rewrite
        # localhost:8080 in worker.sb for the positive MCP round-trip while still testing 8080 deny.
        bound_8080 = False
        try:
            chat_srv = ThreadingHTTPServer(("127.0.0.1", 8080), _MockChatHandler)
            bound_8080 = True
        except OSError:
            chat_srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockChatHandler)
        chat_port = int(chat_srv.server_address[1])
        srv_thread = threading.Thread(target=chat_srv.serve_forever, daemon=True)
        srv_thread.start()

        outside_srv = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        worker_id, isolated_home = allocate_worker_home()
        dest_dir: Path | None = None
        try:
            srv_lstart = get_process_lstart(outside_srv.pid)
            self.assertIsNotNone(srv_lstart)

            with (
                tempfile.TemporaryDirectory() as ws_tmp,
                tempfile.TemporaryDirectory() as bin_tmp,
                tempfile.TemporaryDirectory() as runs_tmp,
            ):
                ws_dir = Path(ws_tmp)
                fake_runs = Path(runs_tmp)
                isolated_pid_file = pid_file_for_model(model_id, fake_runs)
                isolated_pid_file.write_text(
                    json.dumps(
                        {
                            "status": "ready",
                            "pid": outside_srv.pid,
                            "pid_lstart": srv_lstart,
                            "model_id": model_id,
                            "served_repo": served_repo,
                            "port": 8080,
                            "runtime": "mlx-lm",
                            "hf_offline": True,
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                # Create a dedicated mock opencode_real binary distinct from sys.executable
                fake_opencode = Path(bin_tmp) / "fake-opencode-bin"
                fake_src = Path(bin_tmp) / "fake_opencode.c"
                fake_src.write_text(
                    "#include <string.h>\n"
                    "#include <unistd.h>\n"
                    "#include <wordexp.h>\n"
                    "int main(int argc, char **argv) {\n"
                    "    if (argc >= 3 && strcmp(argv[1], \"-c\") == 0) {\n"
                    "        const char *cmd = argv[2];\n"
                    "        if (strncmp(cmd, \"exec \", 5) == 0) cmd += 5;\n"
                    "        wordexp_t we;\n"
                    "        if (wordexp(cmd, &we, WRDE_NOCMD) == 0 && we.we_wordc > 0) {\n"
                    "            execv(we.we_wordv[0], we.we_wordv);\n"
                    "        }\n"
                    "    }\n"
                    "    return 127;\n"
                    "}\n",
                    encoding="utf-8",
                )
                subprocess.run(
                    ["/usr/bin/cc", "-O2", str(fake_src), "-o", str(fake_opencode)],
                    capture_output=True,
                    check=True,
                )
                os.chmod(fake_opencode, 0o755)

                prof = parse_security_profile_dict(
                    {
                        "schema_version": 1,
                        "mode": "unattended_worker",
                        "enforce_os_sandbox": True,
                        "filesystem": {"read_roots": ["."], "write_roots": ["."]},
                        "tools": {
                            "allowed_tools": ["read", "shell"],
                            "denied_tools": [],
                            "allow_subagents": False,
                        },
                        "mcp": {"enable_local_assist": True, "servers": {}},
                    },
                )

                class _OkVerify:
                    returncode = 0
                    stdout = f"{model_id}\n"
                    stderr = ""

                handoff_path = write_verified_local_models_handoff(
                    isolated_home=isolated_home,
                    worker_id=worker_id,
                    runs_dir=fake_runs,
                    verify_runner=lambda *a, **k: _OkVerify(),
                )
                self.assertTrue(handoff_path.is_file())
                handoff_obj = json.loads(handoff_path.read_text(encoding="utf-8"))
                self.assertIn(model_id, handoff_obj["models"])

                sb_text = compile_seatbelt_profile(
                    prof,
                    workspace_dir=ws_dir,
                    isolated_home=isolated_home,
                    opencode_bin=fake_opencode,
                )
                _, sb_path, worker_shell = write_worker_runtime_artifacts(
                    isolated_home=isolated_home,
                    worker_id=worker_id,
                    profile=prof,
                    opencode_config={},
                    seatbelt_text=sb_text,
                )
                la_py = isolated_home / "bin" / "local-assist-python"
                self.assertTrue(la_py.is_file())
                self.assertFalse(la_py.is_symlink())
                self.assertEqual(la_py.stat().st_mode & 0o777, 0o500)

                self.assertIn(f'(process-path "{la_py.resolve(strict=True)}")', sb_text)
                self.assertNotIn(f'(process-path "{Path(sys.executable).resolve(strict=True)}")', sb_text)

                if not bound_8080:
                    os.chmod(sb_path, 0o600)
                    sb_path.write_text(
                        sb_text.replace("localhost:8080", f"localhost:{chat_port}"),
                        encoding="utf-8",
                    )
                    os.chmod(sb_path, 0o400)

                worker_env = build_worker_environment(
                    prof,
                    isolated_home=isolated_home,
                    worker_id=worker_id,
                    host_env=os.environ,
                )

                # 1. Negative control: general-purpose python3 from worker-shell is denied TCP connect to 8080/chat_port
                res_net = subprocess.run(
                    [
                        "/usr/bin/sandbox-exec",
                        "-f",
                        str(sb_path),
                        str(worker_shell),
                        "-c",
                        (
                            f"{sys.executable} -c '"
                            f"import socket; s = socket.socket(); s.settimeout(2.0); "
                            f"s.connect((\"127.0.0.1\", {chat_port}))'"
                        ),
                    ],
                    cwd=str(ws_dir),
                    env=worker_env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertNotEqual(res_net.returncode, 0)
                self.assertIn("Operation not permitted", res_net.stderr)

                # 2. Negative control: general-purpose python3 from worker-shell is denied writing local-assist-runs
                #    (with a positive control using the exact same quoted Python snippet writing to .tmp/probe_ok.json)
                import shlex

                def _build_write_probe_cmd(target_path: Path) -> str:
                    py_code = f"import pathlib; pathlib.Path({str(target_path)!r}).write_text('{{}}')"
                    return f"{shlex.quote(sys.executable)} -c {shlex.quote(py_code)}"

                allowed_probe_file = isolated_home / ".tmp" / "probe_ok.json"
                res_write_ctrl = subprocess.run(
                    [
                        "/usr/bin/sandbox-exec",
                        "-f",
                        str(sb_path),
                        str(worker_shell),
                        "-c",
                        _build_write_probe_cmd(allowed_probe_file),
                    ],
                    cwd=str(ws_dir),
                    env=worker_env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(res_write_ctrl.returncode, 0, res_write_ctrl.stderr)
                self.assertTrue(allowed_probe_file.is_file())

                forged_log = isolated_home / ".local" / "share" / "local-assist-runs" / "forged.json"
                res_write = subprocess.run(
                    [
                        "/usr/bin/sandbox-exec",
                        "-f",
                        str(sb_path),
                        str(worker_shell),
                        "-c",
                        _build_write_probe_cmd(forged_log),
                    ],
                    cwd=str(ws_dir),
                    env=worker_env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertNotEqual(res_write.returncode, 0)
                self.assertIn("PermissionError", res_write.stderr)
                self.assertIn("Operation not permitted", res_write.stderr)
                self.assertFalse(forged_log.exists())

                # 3. Negative control: worker-shell / general-purpose python3 cannot exec local-assist-python
                res_exec = subprocess.run(
                    [
                        "/usr/bin/sandbox-exec",
                        "-f",
                        str(sb_path),
                        str(worker_shell),
                        "-c",
                        f"{la_py} -c 'print(123)'",
                    ],
                    cwd=str(ws_dir),
                    env=worker_env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertNotEqual(res_exec.returncode, 0)

                # 4. Positive control: fake_opencode (standing in for opencode_real) CAN spawn
                # local-assist-python -m local_assist.server, complete an MCP extract_fields call
                # over loopback, and write audit logs to local-assist-runs.
                mcp_reqs = (
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "initialize",
                            "params": {},
                        }
                    )
                    + "\n"
                    + json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 2,
                            "method": "tools/call",
                            "params": {
                                "name": "extract_fields",
                                "arguments": {
                                    "text": "Owner: alice",
                                    "fields": {
                                        "owner": {
                                            "type": "string",
                                            "description": "Owner name",
                                            "required": True,
                                        }
                                    },
                                },
                            },
                        }
                    )
                    + "\n"
                )
                mcp_env = dict(worker_env)
                mcp_env["PYTHONPATH"] = str(ROOT)
                mcp_env["LOCAL_ASSIST_NO_AUTO_SERVE"] = "1"
                mcp_env["LOCAL_ASSIST_WORKER_SANDBOX"] = "1"
                mcp_env["LOCAL_ASSIST_WORKER_ID"] = worker_id
                mcp_env["LOCAL_ASSIST_VERIFIED_MODELS_FILE"] = str(handoff_path)
                mcp_env["LOCAL_ASSIST_LOG_DIR"] = str(
                    isolated_home / ".local" / "share" / "local-assist-runs"
                )
                mcp_env["LOCAL_ASSIST_BASE_URL"] = f"http://127.0.0.1:{chat_port}/v1"

                res_mcp = subprocess.run(
                    [
                        "/usr/bin/sandbox-exec",
                        "-f",
                        str(sb_path),
                        str(fake_opencode),
                        "-c",
                        f"exec {la_py} -I -m local_assist.server",
                    ],
                    input=mcp_reqs,
                    cwd=str(ws_dir),
                    env=mcp_env,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(res_mcp.returncode, 0, res_mcp.stderr)
                lines = [ln for ln in res_mcp.stdout.splitlines() if ln.strip()]
                self.assertEqual(len(lines), 2, res_mcp.stdout)
                call_resp = json.loads(lines[1])
                self.assertFalse(call_resp["result"].get("isError", False), call_resp)
                structured = call_resp["result"]["structuredContent"]
                self.assertEqual(structured["extracted"]["owner"], "alice")

                # Verify F10: harvest_worker_local_assist_logs rewrites payload_path to actual harvested path
                dest_dir = harvest_worker_local_assist_logs(
                    isolated_home=isolated_home, worker_id=worker_id
                )
                self.assertIsNotNone(dest_dir)
                assert dest_dir is not None
                jsonl_files = list(dest_dir.glob("*.jsonl"))
                self.assertEqual(len(jsonl_files), 1)
                index_row = json.loads(jsonl_files[0].read_text(encoding="utf-8").strip())
                self.assertTrue(
                    index_row["payload_path"].startswith(
                        f"runs/local-assist/worker-sandbox/{worker_id}/"
                    ),
                    index_row,
                )
                self.assertTrue(
                    index_row["original_sandbox_payload_path"].startswith("runs/local-assist/"),
                    index_row,
                )
                harvested_payload_path = ROOT / index_row["payload_path"]
                self.assertTrue(harvested_payload_path.is_file())
                payload_obj = json.loads(harvested_payload_path.read_text(encoding="utf-8"))
                self.assertEqual(payload_obj["payload_path"], index_row["payload_path"])
        finally:
            outside_srv.terminate()
            try:
                outside_srv.wait(timeout=5)
            except subprocess.TimeoutExpired:
                outside_srv.kill()
            chat_srv.shutdown()
            chat_srv.server_close()
            cleanup_worker_home(isolated_home, worker_id=worker_id, harvest_logs=False)
            if dest_dir is not None and dest_dir.exists():
                shutil.rmtree(dest_dir, ignore_errors=True)

    def test_f3_nan_infinity_and_nonpositive_spend_ceilings_rejected(self) -> None:
        import importlib.machinery
        import importlib.util
        import io
        from contextlib import redirect_stderr
        from unittest.mock import patch
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            for bad_val in (
                float("nan"),
                float("inf"),
                float("-inf"),
                0,
                0.0,
                -1.5,
                True,
                "nan",
                "inf",
                "-inf",
            ):
                with self.assertRaises(SecurityProfileError, msg=f"Accepted {bad_val!r}"):
                    parse_security_profile_dict(
                        {
                            "schema_version": 1,
                            "mode": "unattended_worker",
                            "spend": {"max_session_usd": bad_val},
                        },
                    )

            for bad_yaml in ("nan", ".nan", ".inf", "-.inf", "0", "-2.0"):
                prof_file = ws / "bad_spend.yaml"
                prof_file.write_text(
                    f"schema_version: 1\nmode: unattended_worker\nspend:\n  max_session_usd: {bad_yaml}\n",
                    encoding="utf-8",
                )
                with self.assertRaises(SecurityProfileError, msg=f"Accepted YAML {bad_yaml}"):
                    load_security_profile(prof_file)

        script_path = ROOT / "scripts" / "opencode-attested"
        loader = importlib.machinery.SourceFileLoader("opencode_attested_f3_mod", str(script_path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        assert spec is not None and spec.loader is not None
        oc_att = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(oc_att)

        from local_assist.errors import LocalAssistError

        endpoint = oc_att.resolve_endpoint(
            oc_att.load_model("tinfoil-deepseek-v4-1-flash"),
            require_api_key=False,
        )
        # Interactive mode (max_session_usd=None) returns full est dict for format_session_banner
        est_none = oc_att.check_session_spend_ceiling(
            endpoint,
            max_chat_requests=25,
            max_request_bytes=131072,
            max_tokens_cap=2048,
            max_session_usd=None,
        )
        self.assertIsInstance(est_none, dict)
        banner = oc_att.format_session_banner(
            endpoint,
            {**est_none, "attached": False, "ttl_seconds": 3600},
            max_session_usd=None,
        )
        self.assertIn("no pre-flight --max-session-usd cap set", banner)

        for bad_usd in (float("nan"), float("inf"), float("-inf"), 0.0, -1.0):
            with self.assertRaises(
                LocalAssistError,
                msg=f"check_session_spend_ceiling accepted {bad_usd!r}",
            ):
                oc_att.check_session_spend_ceiling(
                    endpoint,
                    max_chat_requests=25,
                    max_request_bytes=131072,
                    max_tokens_cap=2048,
                    max_session_usd=bad_usd,
                )

        for bad_cli_usd in ("nan", "inf", "-inf", "0", "-0.5"):
            err_buf = io.StringIO()
            with redirect_stderr(err_buf):
                rc = oc_att.main(
                    [
                        str(script_path),
                        "--unattended-worker",
                        "--no-serve",
                        f"--max-session-usd={bad_cli_usd}",
                        "--print-config",
                    ]
                )
            self.assertEqual(rc, 1, f"CLI accepted --max-session-usd={bad_cli_usd}")

        # Attached session with non-finite cap in PID record is refused
        for bad_rec_cap in ("nan", "inf", 0, -5, True):
            with self.assertRaises(LocalAssistError):
                oc_att._extract_attached_session_caps(
                    endpoint,
                    {
                        "max_chat_requests": bad_rec_cap,
                        "max_tokens_cap": 2048,
                        "max_request_bytes": 131072,
                        "ttl_seconds": 3600,
                    },
                )

    def test_f4_staged_fifo_does_not_block_harvester_cleanup_or_sweep(self) -> None:
        worker_id, isolated_home = allocate_worker_home()
        dest_dir: Path | None = None
        try:
            staging = isolated_home / ".local" / "share" / "local-assist-runs"
            day_dir = staging / "2026-11-04"
            day_dir.mkdir(parents=True, exist_ok=True)

            # Create blocking FIFOs with no writer at both .json and top-level .jsonl paths
            fifo_json = day_dir / "00-00-00-trap.json"
            os.mkfifo(fifo_json)
            fifo_jsonl = staging / "2026-11-04-trap.jsonl"
            os.mkfifo(fifo_jsonl)

            # Also create valid regular payload + index files alongside the FIFOs
            valid_rel = "runs/local-assist/2026-11-04/12-00-00-valid.json"
            valid_json = day_dir / "12-00-00-valid.json"
            valid_json.write_text(
                json.dumps({"tool": "extract_fields", "payload_path": valid_rel}),
                encoding="utf-8",
            )
            valid_jsonl = staging / "2026-11-04.jsonl"
            valid_jsonl.write_text(
                json.dumps({"tool": "extract_fields", "payload_path": valid_rel}) + "\n",
                encoding="utf-8",
            )

            t0 = time.monotonic()
            self.assertIsNone(
                _read_regular_file_nofollow(fifo_json, root_real=staging.resolve(strict=True))
            )
            self.assertIsNone(
                _read_regular_file_nofollow(fifo_jsonl, root_real=staging.resolve(strict=True))
            )
            dest_dir = harvest_worker_local_assist_logs(
                isolated_home=isolated_home, worker_id=worker_id
            )
            elapsed_harvest = time.monotonic() - t0
            self.assertLess(elapsed_harvest, 2.0)
            self.assertIsNotNone(dest_dir)
            assert dest_dir is not None
            self.assertFalse((dest_dir / "2026-11-04" / "00-00-00-trap.json").exists())
            self.assertFalse((dest_dir / "2026-11-04-trap.jsonl").exists())
            self.assertTrue((dest_dir / "2026-11-04" / "12-00-00-valid.json").is_file())
            self.assertTrue((dest_dir / "2026-11-04.jsonl").is_file())

            # Verify sweep_stale_worker_homes with dead owner harvests valid logs and removes FIFO home without blocking
            owner_meta = isolated_home / ".worker-owner.json"
            os.chmod(owner_meta, 0o600)
            owner_meta.write_text(
                json.dumps(
                    {
                        "worker_id": worker_id,
                        "owner_pid": 999999,
                        "owner_lstart": "Thu Jan  1 00:00:00 1970",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            os.chmod(owner_meta, 0o400)
            shutil.rmtree(dest_dir, ignore_errors=True)
            t1 = time.monotonic()
            swept = sweep_stale_worker_homes(max_age_seconds=0)
            elapsed_sweep = time.monotonic() - t1
            self.assertLess(elapsed_sweep, 2.0)
            self.assertIn(isolated_home, swept)
            self.assertFalse(isolated_home.exists())
            self.assertTrue((dest_dir / "2026-11-04" / "12-00-00-valid.json").is_file())
        finally:
            if isolated_home.exists():
                cleanup_worker_home(isolated_home, worker_id=worker_id, harvest_logs=False)
            if dest_dir is not None and dest_dir.exists():
                shutil.rmtree(dest_dir, ignore_errors=True)

    def test_f5_launcher_sigterm_sighup_process_group_and_teardown_lifecycle(self) -> None:
        import importlib.machinery
        import importlib.util
        import io
        from contextlib import redirect_stderr, redirect_stdout
        from unittest.mock import patch

        from local_assist.security_profile import pid_is_alive

        # 1. Leader exits on SIGTERM while a child in the same process group ignores SIGTERM
        #    AND clears its env markers and cwd="/" so fallback reaping cannot find it:
        #    run_worker_sandbox_lifecycle must escalate SIGKILL to the process group BEFORE
        #    teardown_worker_home runs (verified inside pre_teardown_hook).
        worker_id, isolated_home = allocate_worker_home()
        child_pid_file = isolated_home / "stubborn_child.pid"
        child_ready_file = isolated_home / "stubborn_child.ready"
        child_dead_before_fallback = False
        try:
            child_script = (
                "import pathlib, signal, time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "signal.signal(signal.SIGHUP, signal.SIG_IGN)\n"
                f"pathlib.Path({str(child_ready_file)!r}).write_text('1')\n"
                "time.sleep(60)\n"
            )
            leader_script = (
                "import os, pathlib, signal, subprocess, sys, time\n"
                "child = subprocess.Popen(\n"
                f"    [sys.executable, '-c', {child_script!r}],\n"
                "    cwd='/',\n"
                "    env={},\n"
                ")\n"
                f"pathlib.Path({str(child_pid_file)!r}).write_text(str(child.pid))\n"
                "signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))\n"
                "time.sleep(60)\n"
            )
            env = dict(os.environ)
            env["OPENCODE_WORKER_ID"] = worker_id

            def _send_sigterm_when_ready() -> None:
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline and not (
                    child_pid_file.exists() and child_ready_file.exists()
                ):
                    time.sleep(0.05)
                os.kill(os.getpid(), subprocess.signal.SIGTERM)

            def _verify_group_killed_before_fallback() -> None:
                nonlocal child_dead_before_fallback
                c_pid = int(child_pid_file.read_text(encoding="utf-8").strip())
                child_dead_before_fallback = not pid_is_alive(c_pid)

            killer = threading.Thread(target=_send_sigterm_when_ready, daemon=True)
            killer.start()

            rc, td = run_worker_sandbox_lifecycle(
                [sys.executable, "-c", leader_script],
                cwd=isolated_home,
                env=env,
                isolated_home=isolated_home,
                worker_id=worker_id,
                harvest_logs=False,
                remove_home=True,
                grace_seconds=0.25,
                pre_teardown_hook=_verify_group_killed_before_fallback,
            )
            killer.join(timeout=5)
            self.assertEqual(rc, 128 + int(subprocess.signal.SIGTERM))
            self.assertTrue(
                child_dead_before_fallback,
                "Expected process-group escalation to kill SIGTERM-ignoring child before fallback reaper",
            )
            self.assertTrue(td["clean"], td)
            self.assertFalse(isolated_home.exists())
        finally:
            if isolated_home.exists():
                cleanup_worker_home(isolated_home, worker_id=worker_id, harvest_logs=False)

        # 2. Spawn-window cancellation: signal arrives inside popen_factory just as the child spawns.
        worker_id_sp, isolated_home_sp = allocate_worker_home()
        spawned_proc_ref: list[subprocess.Popen[Any]] = []
        try:
            def _spawning_and_signaling_popen(cmd: list[str], *a: Any, **kw: Any) -> subprocess.Popen[Any]:
                p = subprocess.Popen(cmd, *a, **kw)
                spawned_proc_ref.append(p)
                os.kill(os.getpid(), subprocess.signal.SIGTERM)
                return p

            rc_sp, td_sp = run_worker_sandbox_lifecycle(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                cwd=isolated_home_sp,
                env={"OPENCODE_WORKER_ID": worker_id_sp},
                isolated_home=isolated_home_sp,
                worker_id=worker_id_sp,
                harvest_logs=False,
                remove_home=True,
                grace_seconds=0.2,
                popen_factory=_spawning_and_signaling_popen,
            )
            self.assertEqual(rc_sp, 128 + int(subprocess.signal.SIGTERM))
            self.assertEqual(len(spawned_proc_ref), 1)
            self.assertIsNotNone(spawned_proc_ref[0].poll())
            self.assertTrue(td_sp["clean"], td_sp)
            self.assertFalse(isolated_home_sp.exists())
        finally:
            if isolated_home_sp.exists():
                cleanup_worker_home(isolated_home_sp, worker_id=worker_id_sp, harvest_logs=False)

        # 3. Repeated signals (SIGHUP + SIGTERM) delivered at teardown entry do not abort teardown.
        worker_id2, isolated_home2 = allocate_worker_home()
        try:
            def _send_repeated_teardown_signals() -> None:
                os.kill(os.getpid(), subprocess.signal.SIGHUP)
                os.kill(os.getpid(), subprocess.signal.SIGTERM)

            rc2, td2 = run_worker_sandbox_lifecycle(
                [sys.executable, "-c", "pass"],
                cwd=isolated_home2,
                env={"OPENCODE_WORKER_ID": worker_id2},
                isolated_home=isolated_home2,
                worker_id=worker_id2,
                harvest_logs=False,
                remove_home=True,
                pre_teardown_hook=_send_repeated_teardown_signals,
            )
            self.assertEqual(rc2, 128 + int(subprocess.signal.SIGHUP))
            self.assertTrue(td2["clean"], td2)
            self.assertFalse(isolated_home2.exists())
        finally:
            if isolated_home2.exists():
                cleanup_worker_home(isolated_home2, worker_id=worker_id2, harvest_logs=False)

        # 4. Launcher entry-point SIGTERM and SIGHUP integration matrix across both
        #    scripts/opencode-local and scripts/opencode-attested.
        if OPENCODE_BIN is not None:
            attested_serve_ret = (
                True,
                None,
                {
                    "session_token": "tok-f5",
                    "attached": False,
                    "max_chat_requests": 25,
                    "max_tokens_cap": 2048,
                    "max_request_bytes": 131072,
                    "ttl_seconds": 3600,
                    "input_price_per_m": 0.10,
                    "output_price_per_m": 0.40,
                    "worst_total_usd": 0.13,
                },
            )
            with tempfile.TemporaryDirectory() as tok_dir:
                tok_file = Path(tok_dir) / "session.token"
                tok_file.write_text("se-session-0123456789abcdef0123456789", encoding="utf-8")
                pid_rec_stub = {
                    "status": "ready",
                    "pid": os.getpid(),
                    "session_token_file": str(tok_file),
                    "max_chat_requests": 25,
                    "max_tokens_cap": 2048,
                    "max_request_bytes": 131072,
                    "ttl_seconds": 3600,
                }
                for script_name, extra_cli, serve_ret in (
                    ("opencode-local", [], (True, None)),
                    ("opencode-attested", ["--max-session-usd", "0.50"], attested_serve_ret),
                ):
                    script_path = ROOT / "scripts" / script_name
                    loader = importlib.machinery.SourceFileLoader(
                        f"f5_{script_name.replace('-', '_')}", str(script_path)
                    )
                    spec = importlib.util.spec_from_loader(loader.name, loader)
                    assert spec is not None and spec.loader is not None
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)

                    for sig in (subprocess.signal.SIGTERM, subprocess.signal.SIGHUP):
                        captured_homes: list[Path] = []
                        spawned_children: list[subprocess.Popen[Any]] = []
                        real_alloc = mod.allocate_worker_home
                        real_popen = subprocess.Popen

                        def _tracking_alloc() -> tuple[str, Path]:
                            wid, ih = real_alloc()
                            captured_homes.append(ih)
                            return wid, ih

                        def _intercept_sandbox_popen(cmd: list[str], *a: Any, **kw: Any) -> Any:
                            if cmd and Path(str(cmd[0])).name == "sandbox-exec":
                                p = real_popen(
                                    [sys.executable, "-c", "import time; time.sleep(60)"],
                                    *a,
                                    **kw,
                                )
                                spawned_children.append(p)
                                os.kill(os.getpid(), sig)
                                return p
                            return real_popen(cmd, *a, **kw)

                        out_b = io.StringIO()
                        err_b = io.StringIO()
                        with (
                            patch.object(mod, "ensure_model_served", return_value=serve_ret),
                            patch.object(
                                mod,
                                "read_pid_record_for_model",
                                return_value=pid_rec_stub,
                                create=True,
                            ),
                            patch.object(mod, "allocate_worker_home", side_effect=_tracking_alloc),
                            patch(
                                "local_assist.security_profile.subprocess.Popen",
                                side_effect=_intercept_sandbox_popen,
                            ),
                            redirect_stdout(out_b),
                            redirect_stderr(err_b),
                        ):
                            rc_l = mod.main(
                                [
                                    str(script_path),
                                    "--unattended-worker",
                                    "--no-serve",
                                    *extra_cli,
                                    "--",
                                    "run",
                                    "hello",
                                ]
                            )
                        self.assertEqual(rc_l, 128 + int(sig), f"{script_name} {sig}: {err_b.getvalue()}")
                        self.assertEqual(len(spawned_children), 1)
                        self.assertIsNotNone(spawned_children[0].poll())
                        self.assertEqual(len(captured_homes), 1)
                        self.assertFalse(captured_homes[0].exists())

    def test_f6_f7_multi_pass_reaper_start_time_revalidation_and_unavailable_identity(self) -> None:
        import importlib.machinery
        import importlib.util
        import io
        from contextlib import redirect_stderr, redirect_stdout
        from unittest.mock import patch

        from local_assist.security_profile import _scan_worker_pids

        # 1. Multi-pass reaping catches a child forked inside a SIGTERM handler
        worker_id, isolated_home = allocate_worker_home()
        forked_pid_file = isolated_home / "forked_on_sigterm.pid"
        proc: subprocess.Popen[Any] | None = None
        try:
            trap_script = (
                "import os, pathlib, signal, subprocess, sys, time\n"
                "def _on_term(sig, frame):\n"
                "    c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                f"    pathlib.Path({str(forked_pid_file)!r}).write_text(str(c.pid))\n"
                "    sys.exit(0)\n"
                "signal.signal(signal.SIGTERM, _on_term)\n"
                f"pathlib.Path({str(isolated_home / 'ready')!r}).write_text('1')\n"
                "time.sleep(60)\n"
            )
            env = dict(os.environ)
            env["OPENCODE_WORKER_ID"] = worker_id
            proc = subprocess.Popen(
                [sys.executable, "-c", trap_script],
                cwd=str(isolated_home),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and not (isolated_home / "ready").exists():
                time.sleep(0.05)
            self.assertTrue((isolated_home / "ready").exists())

            reaped, clean = reap_worker_processes_detailed(
                worker_id=worker_id,
                isolated_home=isolated_home,
                grace_seconds=0.2,
            )
            self.assertTrue(clean)
            self.assertIn(proc.pid, reaped)
            self.assertTrue(forked_pid_file.exists())
            forked_pid = int(forked_pid_file.read_text(encoding="utf-8").strip())
            self.assertIn(forked_pid, reaped)
        finally:
            if proc is not None and proc.poll() is None:
                proc.kill()
            cleanup_worker_home(isolated_home, worker_id=worker_id, harvest_logs=False)

        # 2a. Pre-signal scanner-boundary PID reuse race (P2-WORK-MAJOR-2):
        #     When ps or lsof observes worker A's PID right before A exits and replacement process B
        #     reuses that PID with a newer lstart (and cwd="/tmp"), _scan_worker_pids and
        #     reap_worker_processes_detailed must NOT bind or signal B!
        worker_id_race, isolated_home_race = allocate_worker_home()
        pre_term_signals: list[tuple[int, int]] = []
        try:
            real_subproc_run = subprocess.run

            class _ProcRes:
                def __init__(self, returncode: int, stdout: str, stderr: str = "") -> None:
                    self.returncode = returncode
                    self.stdout = stdout
                    self.stderr = stderr

            def _race_subproc_run(cmd: list[str], *a: Any, **kw: Any) -> Any:
                if cmd and cmd[0] == "/bin/ps" and "pid=,lstart=,command=" in cmd:
                    return _ProcRes(
                        0,
                        f"654321 Mon Nov  4 12:00:00 2026 /usr/bin/python3 OPENCODE_WORKER_ID={worker_id_race}\n",
                    )
                if cmd and cmd[0] == "/usr/sbin/lsof":
                    if "-p" in cmd and "654322" in cmd:
                        # Replacement process B on 654322 has cwd=/tmp (outside isolated_home_race)
                        return _ProcRes(0, "p654322\nfcwd\nn/tmp\n")
                    return _ProcRes(0, f"p654322\nfcwd\nn{isolated_home_race}\n")
                return real_subproc_run(cmd, *a, **kw)

            with (
                patch("local_assist.security_profile._resolve_lsof_bin", return_value="/usr/sbin/lsof"),
                patch("local_assist.security_profile.subprocess.run", side_effect=_race_subproc_run),
                patch("local_assist.security_profile.pid_is_alive", return_value=True),
                patch(
                    "local_assist.security_profile.get_process_lstart",
                    side_effect=lambda pid: (
                        "Mon Nov  4 12:00:09 2026"
                        if pid in (654321, 654322)
                        else None
                    ),
                ),
                patch(
                    "local_assist.security_profile.os.kill",
                    side_effect=lambda pid, sig: pre_term_signals.append((pid, int(sig))),
                ),
            ):
                matched_race, obs_ok_race = _scan_worker_pids(
                    worker_id=worker_id_race,
                    isolated_home=isolated_home_race,
                )
                self.assertTrue(obs_ok_race)
                self.assertEqual(matched_race, {})
                reaped_race, clean_race = reap_worker_processes_detailed(
                    worker_id=worker_id_race,
                    isolated_home=isolated_home_race,
                    grace_seconds=0.05,
                )
                self.assertTrue(clean_race)
                self.assertEqual(reaped_race, [])
                self.assertEqual(pre_term_signals, [])
        finally:
            cleanup_worker_home(isolated_home_race, worker_id=worker_id_race, harvest_logs=False)

        # 2b. Start-time revalidation before SIGKILL prevents killing a PID reused after SIGTERM
        killed_signals: list[tuple[int, int]] = []

        def _fake_scan(*, worker_id: str | None = None, isolated_home: Path | None = None) -> tuple[dict[int, str], bool]:
            if not killed_signals:
                return {543210: "Mon Nov  4 12:00:00 2026"}, True
            return {}, True

        with patch("local_assist.security_profile._scan_worker_pids", side_effect=_fake_scan), patch(
            "local_assist.security_profile.pid_is_alive", return_value=True
        ), patch(
            "local_assist.security_profile.get_process_lstart",
            side_effect=lambda pid: (
                "Mon Nov  4 12:00:00 2026"
                if not killed_signals
                else "Mon Nov  4 12:00:05 2026"
            ),
        ), patch(
            "local_assist.security_profile.os.kill",
            side_effect=lambda pid, sig: killed_signals.append((pid, int(sig))),
        ):
            _, clean_reuse = reap_worker_processes_detailed(
                worker_id="w-reuse",
                isolated_home=None,
                grace_seconds=0.05,
            )
        self.assertTrue(clean_reuse)
        self.assertEqual(killed_signals, [(543210, int(subprocess.signal.SIGTERM))])

        # 3a. Real scanner boundary (P2-WORK-MAJOR-1):
        #     - Empty observation control: ps returns 0 (no matches) and lsof returns 0 (only self cwd) -> clean=True
        #     - Failing lsof status-1 with stderr diagnostic: ps returns 0 and lsof returns 1 with stderr ->
        #       _scan_worker_pids returns ({}, False), teardown_worker_home retains isolated_home, and both
        #       launchers return non-zero (1) in both normal and --keep-worker-home modes!
        worker_id_ctrl, isolated_home_ctrl = allocate_worker_home()
        try:
            def _empty_ok_subproc(cmd: list[str], *a: Any, **kw: Any) -> Any:
                if cmd and cmd[0] == "/bin/ps":
                    return _ProcRes(0, f"{os.getpid()} Mon Nov  4 12:00:00 2026 python3\n", "")
                if cmd and cmd[0] == "/usr/sbin/lsof":
                    return _ProcRes(0, f"p{os.getpid()}\nfcwd\nn/tmp\n", "")
                return real_subproc_run(cmd, *a, **kw)

            with (
                patch("local_assist.security_profile._resolve_lsof_bin", return_value="/usr/sbin/lsof"),
                patch("local_assist.security_profile.subprocess.run", side_effect=_empty_ok_subproc),
            ):
                m_ctrl, ok_ctrl = _scan_worker_pids(
                    worker_id=worker_id_ctrl,
                    isolated_home=isolated_home_ctrl,
                )
            self.assertTrue(ok_ctrl)
            self.assertEqual(m_ctrl, {})
        finally:
            cleanup_worker_home(isolated_home_ctrl, worker_id=worker_id_ctrl, harvest_logs=False)

        worker_id3, isolated_home3 = allocate_worker_home()
        try:
            def _lsof_err_subproc(cmd: list[str], *a: Any, **kw: Any) -> Any:
                if cmd and cmd[0] == "/bin/ps":
                    return _ProcRes(0, f"{os.getpid()} Mon Nov  4 12:00:00 2026 python3\n", "")
                if cmd and cmd[0] == "/usr/sbin/lsof":
                    return _ProcRes(1, "", "lsof: status error on cwd observer\n")
                return real_subproc_run(cmd, *a, **kw)

            with (
                patch("local_assist.security_profile._resolve_lsof_bin", return_value="/usr/sbin/lsof"),
                patch("local_assist.security_profile.subprocess.run", side_effect=_lsof_err_subproc),
            ):
                m_err, ok_err = _scan_worker_pids(
                    worker_id=worker_id3,
                    isolated_home=isolated_home3,
                )
                self.assertEqual(m_err, {})
                self.assertFalse(ok_err)
                td_fail = teardown_worker_home(
                    isolated_home3,
                    worker_id=worker_id3,
                    harvest_logs=False,
                    remove_home=True,
                )
            self.assertFalse(td_fail["reaper_clean"])
            self.assertFalse(td_fail["clean"])
            self.assertFalse(td_fail["removed"])
            self.assertTrue(isolated_home3.exists())
        finally:
            cleanup_worker_home(isolated_home3, worker_id=worker_id3, harvest_logs=False)

        # 3b. Identified survivor after max_passes AND failing lsof status-1 across both launchers
        #     in both normal and --keep-worker-home modes (plan line 409):
        worker_id_surv, isolated_home_surv = allocate_worker_home()
        try:
            def _survivor_subproc(cmd: list[str], *a: Any, **kw: Any) -> Any:
                if cmd and cmd[0] == "/bin/ps" and "pid=,lstart=,command=" in cmd:
                    return _ProcRes(
                        0,
                        f"765432 Mon Nov  4 12:00:00 2026 /usr/bin/python3 OPENCODE_WORKER_ID={worker_id_surv}\n",
                        "",
                    )
                if cmd and cmd[0] == "/usr/sbin/lsof":
                    return _ProcRes(0, f"p{os.getpid()}\nfcwd\nn/tmp\n", "")
                return real_subproc_run(cmd, *a, **kw)

            with (
                patch("local_assist.security_profile._resolve_lsof_bin", return_value="/usr/sbin/lsof"),
                patch("local_assist.security_profile.subprocess.run", side_effect=_survivor_subproc),
                patch("local_assist.security_profile.pid_is_alive", return_value=True),
                patch(
                    "local_assist.security_profile.get_process_lstart",
                    return_value="Mon Nov  4 12:00:00 2026",
                ),
                patch("local_assist.security_profile.os.kill", side_effect=lambda p, s: None),
            ):
                td_surv = teardown_worker_home(
                    isolated_home_surv,
                    worker_id=worker_id_surv,
                    harvest_logs=False,
                    remove_home=True,
                )
            self.assertFalse(td_surv["reaper_clean"])
            self.assertFalse(td_surv["clean"])
            self.assertFalse(td_surv["removed"])
            self.assertTrue(isolated_home_surv.exists())
        finally:
            cleanup_worker_home(isolated_home_surv, worker_id=worker_id_surv, harvest_logs=False)

        if OPENCODE_BIN is not None:
            attested_serve_ret = (
                True,
                None,
                {
                    "session_token": "tok-f6",
                    "attached": False,
                    "max_chat_requests": 25,
                    "max_tokens_cap": 2048,
                    "max_request_bytes": 131072,
                    "ttl_seconds": 3600,
                    "input_price_per_m": 0.10,
                    "output_price_per_m": 0.40,
                    "worst_total_usd": 0.13,
                },
            )

            class _FakeOkPopen:
                pid = 1

                def poll(self) -> int:
                    return 0

                def wait(self, timeout: float | None = None) -> int:
                    return 0

            for script_name, extra_cli, serve_ret in (
                ("opencode-local", [], (True, None)),
                ("opencode-attested", ["--max-session-usd", "0.50"], attested_serve_ret),
            ):
                script_path = ROOT / "scripts" / script_name
                loader = importlib.machinery.SourceFileLoader(
                    f"f6_{script_name.replace('-', '_')}", str(script_path)
                )
                spec = importlib.util.spec_from_loader(loader.name, loader)
                assert spec is not None and spec.loader is not None
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)

                for keep_flags in ([], ["--keep-worker-home"]):
                    for failure_mode in ("lsof_status_1", "survivor"):
                        tracked_homes: list[ tuple[str, Path] ] = []
                        real_alloc = mod.allocate_worker_home
                        real_popen = subprocess.Popen

                        def _track_alloc() -> tuple[str, Path]:
                            wid, ih = real_alloc()
                            tracked_homes.append((wid, ih))
                            return wid, ih

                        def _fake_popen_ok(cmd: list[str], *a: Any, **kw: Any) -> Any:
                            if cmd and Path(str(cmd[0])).name == "sandbox-exec":
                                return _FakeOkPopen()
                            return real_popen(cmd, *a, **kw)

                        def _mode_subproc_run(cmd: list[str], *a: Any, **kw: Any) -> Any:
                            if cmd and cmd[0] == "/bin/ps" and "pid=,lstart=,command=" in cmd:
                                if failure_mode == "survivor" and tracked_homes:
                                    wid_cur = tracked_homes[-1][0]
                                    return _ProcRes(
                                        0,
                                        f"876543 Mon Nov  4 12:00:00 2026 python3 OPENCODE_WORKER_ID={wid_cur}\n",
                                        "",
                                    )
                                return _ProcRes(0, f"{os.getpid()} Mon Nov  4 12:00:00 2026 python3\n", "")
                            if cmd and cmd[0] == "/usr/sbin/lsof":
                                if failure_mode == "lsof_status_1":
                                    return _ProcRes(1, "", "lsof: observer error\n")
                                return _ProcRes(0, f"p{os.getpid()}\nfcwd\nn/tmp\n", "")
                            return real_subproc_run(cmd, *a, **kw)

                        out_b = io.StringIO()
                        err_b = io.StringIO()
                        try:
                            with tempfile.TemporaryDirectory() as tok_dir_f6:
                                tok_file_f6 = Path(tok_dir_f6) / "session.token"
                                tok_file_f6.write_text("se-session-0123456789abcdef0123456789", encoding="utf-8")
                                pid_rec_stub = {
                                    "status": "ready",
                                    "pid": os.getpid(),
                                    "session_token_file": str(tok_file_f6),
                                    "max_chat_requests": 25,
                                    "max_tokens_cap": 2048,
                                    "max_request_bytes": 131072,
                                    "ttl_seconds": 3600,
                                }
                                with (
                                    patch.object(mod, "ensure_model_served", return_value=serve_ret),
                                    patch.object(
                                        mod,
                                        "read_pid_record_for_model",
                                        return_value=pid_rec_stub,
                                        create=True,
                                    ),
                                    patch.object(mod, "allocate_worker_home", side_effect=_track_alloc),
                                    patch(
                                        "local_assist.security_profile._resolve_lsof_bin",
                                        return_value="/usr/sbin/lsof",
                                    ),
                                    patch(
                                        "local_assist.security_profile.subprocess.Popen",
                                        side_effect=_fake_popen_ok,
                                    ),
                                    patch(
                                        "local_assist.security_profile.subprocess.run",
                                        side_effect=_mode_subproc_run,
                                    ),
                                    patch(
                                        "local_assist.security_profile.pid_is_alive",
                                        side_effect=lambda p: True if p == 876543 else (p == os.getpid()),
                                    ),
                                    patch(
                                        "local_assist.security_profile.get_process_lstart",
                                        side_effect=lambda p: (
                                            "Mon Nov  4 12:00:00 2026"
                                            if p in (876543, os.getpid())
                                            else None
                                        ),
                                    ),
                                    patch(
                                        "local_assist.security_profile.os.kill",
                                        side_effect=lambda p, s: None,
                                    ),
                                    redirect_stdout(out_b),
                                    redirect_stderr(err_b),
                                ):
                                    rc_fail = mod.main(
                                        [
                                            str(script_path),
                                            "--unattended-worker",
                                            "--no-serve",
                                            *extra_cli,
                                            *keep_flags,
                                            "--",
                                            "run",
                                            "hello",
                                        ]
                                    )
                            self.assertEqual(
                                rc_fail,
                                1,
                                f"{script_name} {keep_flags} {failure_mode} unexpectedly returned {rc_fail}",
                            )
                            self.assertIn("incomplete", err_b.getvalue().lower())
                            self.assertEqual(len(tracked_homes), 1)
                            self.assertTrue(
                                tracked_homes[0][1].exists(),
                                f"Expected isolated_home to be retained on {failure_mode}",
                            )
                        finally:
                            for wid_c, ih_c in tracked_homes:
                                if ih_c.exists():
                                    cleanup_worker_home(ih_c, worker_id=wid_c, harvest_logs=False)

        # 4. Unavailable owner identity (get_process_lstart returning None on live PID, or missing lstart)
        #    returns "unavailable" and sweep_stale_worker_homes_detailed preserves the active worker home!
        worker_id4, isolated_home4 = allocate_worker_home()
        try:
            with patch("local_assist.security_profile.get_process_lstart", return_value=None):
                state = check_pid_identity_state(os.getpid(), "Mon Nov  4 12:00:00 2026")
                self.assertEqual(state, "unavailable")
                sweep_res = sweep_stale_worker_homes_detailed(max_age_seconds=0)
                self.assertIn(isolated_home4, sweep_res["skipped_active"])
                self.assertNotIn(isolated_home4, sweep_res["removed"])
                self.assertTrue(isolated_home4.exists())

            self.assertEqual(check_pid_identity_state(os.getpid(), None), "unavailable")
            self.assertEqual(check_pid_identity_state(os.getpid(), ""), "unavailable")
        finally:
            cleanup_worker_home(isolated_home4, worker_id=worker_id4, harvest_logs=False)

    def test_f8_cli_flags_allow_ssh_agent_localhost_port_and_pass_env(self) -> None:
        import importlib.machinery
        import importlib.util
        import io
        from contextlib import redirect_stderr
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            base_prof = default_unattended_worker_profile()
            merged = apply_cli_overrides(
                base_prof,
                allow_ssh_agent=True,
                allowed_localhost_ports=[5432, 6379],
                pass_env=["CUSTOM_WORKER_FLAG", "CI_JOB_ID"],
            )
            self.assertTrue(merged.allow_ssh_agent)
            self.assertEqual(merged.network_allowed_shell_localhost_ports, (5432, 6379))
            self.assertIn("CUSTOM_WORKER_FLAG", merged.env_allowlist)
            self.assertIn("CI_JOB_ID", merged.env_allowlist)

            _, iso_home = allocate_worker_home()
            try:
                with patch.dict(
                    os.environ,
                    {"SSH_AUTH_SOCK": "/tmp/fake-ssh-agent.sock"},
                    clear=False,
                ):
                    sb_text = compile_seatbelt_profile(
                        merged,
                        isolated_home=iso_home,
                        workspace_dir=ws,
                        opencode_bin=Path(sys.executable),
                        sandbox_exec_bin=Path(sys.executable),
                    )
                self.assertIn("localhost:5432", sb_text)
                self.assertIn("localhost:6379", sb_text)
                self.assertIn("fake-ssh-agent.sock", sb_text)

                env = build_worker_environment(
                    merged,
                    isolated_home=iso_home,
                    worker_id="w-f8",
                    host_env={
                        "SSH_AUTH_SOCK": "/tmp/fake-ssh-agent.sock",
                        "CUSTOM_WORKER_FLAG": "enabled",
                        "OPENAI_API_KEY": "sk-secret",
                    },
                )
                self.assertEqual(env.get("SSH_AUTH_SOCK"), "/tmp/fake-ssh-agent.sock")
                self.assertEqual(env.get("CUSTOM_WORKER_FLAG"), "enabled")
                self.assertNotIn("OPENAI_API_KEY", env)
            finally:
                cleanup_worker_home(iso_home, harvest_logs=False)

            # Reserved ports and stripped secret env names are rejected by apply_cli_overrides
            for bad_port in (8080, 8081, 9081, 9181, 49374, 0, 70000):
                with self.assertRaises(SecurityProfileError, msg=f"Accepted port {bad_port}"):
                    apply_cli_overrides(
                        base_prof,
                        allowed_localhost_ports=[bad_port],
                    )
            for bad_env in ("OPENAI_API_KEY", "HF_TOKEN", "PATH", "HOME", "OPENCODE_CONFIG"):
                with self.assertRaises(SecurityProfileError, msg=f"Accepted env {bad_env}"):
                    apply_cli_overrides(
                        base_prof,
                        pass_env=[bad_env],
                    )

        # Verify both launcher scripts accept the flags in parse_args and reject invalid overrides in main()
        for script_name in ("opencode-local", "opencode-attested"):
            script_path = ROOT / "scripts" / script_name
            loader = importlib.machinery.SourceFileLoader(
                f"f8_{script_name.replace('-', '_')}", str(script_path)
            )
            spec = importlib.util.spec_from_loader(loader.name, loader)
            assert spec is not None and spec.loader is not None
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            parsed, _ = mod.parse_args(
                [
                    "--unattended-worker",
                    "--allow-ssh-agent",
                    "--allow-localhost-port",
                    "5432",
                    "--pass-env",
                    "CUSTOM_WORKER_FLAG",
                ]
            )
            self.assertTrue(parsed.allow_ssh_agent)
            self.assertEqual(parsed.allow_localhost_port, [5432])
            self.assertEqual(parsed.pass_env, ["CUSTOM_WORKER_FLAG"])

            err_buf = io.StringIO()
            with redirect_stderr(err_buf):
                rc_bad = mod.main(
                    [
                        str(script_path),
                        "--unattended-worker",
                        "--allow-localhost-port",
                        "8080",
                        "--print-config",
                    ]
                )
            self.assertEqual(rc_bad, 1)
            self.assertIn("8080", err_buf.getvalue())

    def test_f9_relay_mid_stream_upstream_error_does_not_corrupt_http_framing(self) -> None:
        # Start a raw TCP server that sends chunked 200 OK headers + partial chunk, then closes abruptly
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sock.bind(("127.0.0.1", 0))
        srv_sock.listen(5)
        upstream_port = int(srv_sock.getsockname()[1])

        def _broken_upstream() -> None:
            try:
                conn, _ = srv_sock.accept()
                with conn:
                    _ = conn.recv(4096)
                    # Send HTTP 200 with Transfer-Encoding: chunked and a truncated chunk
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: text/event-stream\r\n"
                        b"Transfer-Encoding: chunked\r\n"
                        b"\r\n"
                        b"10\r\n"
                        b"data: partial\r\n\r\n"
                        b"ff\r\ntruncated"
                    )
            except OSError:
                pass

        t = threading.Thread(target=_broken_upstream, daemon=True)
        t.start()

        relay = _WorkerTokenRelay(
            upstream_base_url=f"http://127.0.0.1:{upstream_port}/v1",
            upstream_session_token="secret",
            max_chat_requests=5,
            max_request_bytes=65536,
            max_tokens_cap=512,
        )
        relay.start()
        try:
            with socket.create_connection(("127.0.0.1", relay.port), timeout=5.0) as cli:
                body = b'{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true}'
                req = (
                    f"POST /v1/chat/completions HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{relay.port}\r\n"
                    f"Authorization: Bearer {relay.relay_token}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("utf-8") + body
                cli.sendall(req)
                chunks: list[bytes] = []
                while True:
                    data = cli.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
            raw_resp = b"".join(chunks).decode("utf-8", errors="replace")
            self.assertEqual(raw_resp.count("HTTP/1.1 "), 1, raw_resp)
            self.assertNotIn("HTTP/1.1 502", raw_resp)
            self.assertNotIn("upstream_unreachable", raw_resp)
        finally:
            relay.close()
            srv_sock.close()

    def test_f11_worker_print_config_retains_inspected_artifacts(self) -> None:
        import importlib.machinery
        import importlib.util
        import io
        from contextlib import redirect_stderr, redirect_stdout
        from unittest.mock import patch
        from unittest.mock import patch

        for script_name, extra_args, serve_ret in (
            ("opencode-local", [], (True, None)),
            (
                "opencode-attested",
                ["--max-session-usd", "0.50"],
                (
                    True,
                    None,
                    {
                        "session_token": "tok-123",
                        "attached": False,
                        "max_chat_requests": 25,
                        "max_tokens_cap": 2048,
                        "max_request_bytes": 131072,
                        "ttl_seconds": 3600,
                        "input_price_per_m": 0.10,
                        "output_price_per_m": 0.40,
                        "worst_total_usd": 0.13,
                    },
                ),
            ),
        ):
            script_path = ROOT / "scripts" / script_name
            loader = importlib.machinery.SourceFileLoader(
                f"f11_{script_name.replace('-', '_')}", str(script_path)
            )
            spec = importlib.util.spec_from_loader(loader.name, loader)
            assert spec is not None and spec.loader is not None
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            out_buf = io.StringIO()
            err_buf = io.StringIO()
            with tempfile.TemporaryDirectory() as tok_dir_f11:
                tok_file_f11 = Path(tok_dir_f11) / "session.token"
                tok_file_f11.write_text("se-session-0123456789abcdef0123456789", encoding="utf-8")
                pid_rec_stub = {
                    "status": "ready",
                    "pid": os.getpid(),
                    "session_token_file": str(tok_file_f11),
                    "max_chat_requests": 25,
                    "max_tokens_cap": 2048,
                    "max_request_bytes": 131072,
                    "ttl_seconds": 3600,
                }
                with (
                    patch.object(mod, "ensure_model_served", return_value=serve_ret),
                    patch.object(
                        mod,
                        "read_pid_record_for_model",
                        return_value=pid_rec_stub,
                        create=True,
                    ),
                ):
                    with redirect_stdout(out_buf), redirect_stderr(err_buf):
                        rc = mod.main(
                            [
                                str(script_path),
                                "--unattended-worker",
                                "--no-serve",
                                "--print-config",
                                *extra_args,
                            ]
                        )
            self.assertEqual(rc, 0, err_buf.getvalue())
            meta = json.loads(out_buf.getvalue())
            iso_home = Path(meta["isolated_home"])
            cfg_path = Path(meta["opencode_config_path"])
            sb_path = Path(meta["seatbelt_profile_path"])
            try:
                self.assertTrue(iso_home.is_dir(), f"Missing isolated_home for {script_name}")
                self.assertTrue(cfg_path.is_file(), f"Missing opencode_config_path for {script_name}")
                self.assertTrue(sb_path.is_file(), f"Missing seatbelt_profile_path for {script_name}")
            finally:
                cleanup_worker_home(
                    iso_home,
                    worker_id=meta.get("worker_id"),
                    harvest_logs=False,
                )

    def test_r2_f1_runtime_write_protection_and_staged_immutable_local_assist_runtime(self) -> None:
        from unittest.mock import patch
        from local_assist.registry import pid_file_for_model
        from local_assist.security_profile import run_worker_sandbox_process

        # Part A: Portable validation & compilation checks (runs on all platforms)
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            iso = Path(tmp) / "iso"
            ws.mkdir()
            iso.mkdir()

            for forbidden_wr in (
                ROOT / "local_assist",
                ROOT / "scripts",
                ROOT / "bin",
                ROOT / "config",
                ROOT / "tools",
                ROOT / ".venv",
            ):
                if not forbidden_wr.is_dir():
                    continue
                bad_prof = parse_security_profile_dict(
                    {"filesystem": {"write_roots": [str(forbidden_wr)]}}
                )
                with self.assertRaisesRegex(
                    SecurityProfileError,
                    "overlaps denied credential/runtime path",
                    msg=f"Expected write_root {forbidden_wr} to be rejected",
                ):
                    compile_seatbelt_profile(
                        bad_prof,
                        workspace_dir=ws,
                        isolated_home=iso,
                        opencode_bin=Path("/usr/bin/true"),
                        sandbox_exec_bin=Path("/usr/bin/true"),
                    )

            # Separate check for sys.base_prefix so system-Python hosts where base_prefix == /usr
            # are accepted whether rejected by the broad-root check or runtime-overlap check (P3-WORK-MINOR-1).
            base_pfx = Path(sys.base_prefix).resolve()
            if base_pfx.is_dir():
                bad_pfx_prof = parse_security_profile_dict(
                    {"filesystem": {"write_roots": [str(base_pfx)]}}
                )
                with self.assertRaisesRegex(
                    SecurityProfileError,
                    "(overlaps denied credential/runtime path|overly broad root directory)",
                ):
                    compile_seatbelt_profile(
                        bad_pfx_prof,
                        workspace_dir=ws,
                        isolated_home=iso,
                        opencode_bin=Path("/usr/bin/true"),
                        sandbox_exec_bin=Path("/usr/bin/true"),
                    )

            # Containing write_root (ROOT) is permitted as a write_root while runtime subpaths are kernel write-denied
            containing_prof = parse_security_profile_dict(
                {
                    "filesystem": {
                        "read_roots": [str(ROOT)],
                        "write_roots": [str(ROOT)],
                    },
                    "mcp": {"enable_local_assist": True},
                }
            )
            sb_containing = compile_seatbelt_profile(
                containing_prof,
                workspace_dir=ws,
                isolated_home=iso,
                opencode_bin=Path("/usr/bin/true"),
                sandbox_exec_bin=Path("/usr/bin/true"),
            )
            for protected_runtime_target in (
                ROOT / "local_assist",
                ROOT / "scripts",
                ROOT / "bin",
                ROOT / "config",
                ROOT / "tools",
                ROOT / "models.yaml",
                iso.resolve() / "runtime",
                iso.resolve() / "lib",
            ):
                self.assertIn(
                    f'(literal "{protected_runtime_target.resolve()}")',
                    sb_containing,
                )
                self.assertIn(
                    f'(subpath "{protected_runtime_target.resolve()}")',
                    sb_containing,
                )

            base_cfg = {
                "mcp": {
                    "servers": {
                        "local_assist": {
                            "type": "local",
                            "command": [sys.executable, "-m", "local_assist.server"],
                            "cwd": str(ROOT),
                            "environment": {},
                        }
                    }
                }
            }
            compiled_cfg = compile_opencode_security_config(
                base_cfg,
                containing_prof,
                isolated_home=iso,
            )
            la_cfg = compiled_cfg["mcp"]["servers"]["local_assist"]
            self.assertEqual(
                la_cfg["command"],
                [
                    str(iso.resolve() / "bin" / "local-assist-python"),
                    "-I",
                    "-m",
                    "local_assist.server",
                ],
            )
            self.assertEqual(la_cfg["cwd"], str(iso.resolve() / "runtime"))
            self.assertEqual(la_cfg["environment"]["PYTHONSAFEPATH"], "1")
            self.assertEqual(la_cfg["environment"]["PYTHONNOUSERSITE"], "1")

        if not HAS_SANDBOX_EXEC:
            return

        # Part B: Live macOS Seatbelt enforcement against a disposable workbench mirror
        # (P3-WORK-MINOR-4) so even if a kernel rule regressed, the operator's real checkout
        # is never mutated. Also records the exact verify-served-model subprocess path executed
        # during the MCP extract_fields call.
        model_id = "qwen3-30b-a3b-2507-mlx-4bit"
        served_repo = "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit"

        class _MockR2F1ChatHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                raw = json.dumps(
                    {"object": "list", "data": [{"id": served_repo, "object": "model"}]}
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                _ = self.rfile.read(length) if length > 0 else b""
                resp = {
                    "id": "chatcmpl-r2-f1",
                    "object": "chat.completion",
                    "model": served_repo,
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": json.dumps({"extracted": {"owner": "immutable-runtime"}}),
                            },
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 6, "total_tokens": 16},
                }
                raw = json.dumps(resp).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, format: str, *args: Any) -> None:
                return

        try:
            chat_srv = ThreadingHTTPServer(("127.0.0.1", 8080), _MockR2F1ChatHandler)
            bound_8080 = True
        except OSError:
            chat_srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockR2F1ChatHandler)
            bound_8080 = False
        chat_port = int(chat_srv.server_address[1])
        chat_thread = threading.Thread(target=chat_srv.serve_forever, daemon=True)
        chat_thread.start()

        outside_srv = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)", "--model", served_repo],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        worker_id, isolated_home = allocate_worker_home()
        try:
            srv_lstart = get_process_lstart(outside_srv.pid)
            self.assertTrue(srv_lstart)
            with tempfile.TemporaryDirectory() as tmp:
                mirror_root = (Path(tmp) / "lab_mirror").resolve()
                mirror_root.mkdir(parents=True, exist_ok=True)
                shutil.copytree(
                    ROOT / "local_assist",
                    mirror_root / "local_assist",
                    symlinks=False,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
                )
                for sub_d in ("scripts", "bin", "config", "tools", ".venv", "runs", ".home"):
                    (mirror_root / sub_d).mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / "models.yaml", mirror_root / "models.yaml")
                for doc_sub in ("evals", "attestations"):
                    if (ROOT / "docs" / doc_sub).is_dir():
                        shutil.copytree(
                            ROOT / "docs" / doc_sub,
                            mirror_root / "docs" / doc_sub,
                            symlinks=False,
                        )

                # Instrument mirror_root/scripts/verify-served-model before staging so that when
                # local_assist.lifecycle.ensure_local_model_served executes it from <isolated_home>/runtime,
                # it records its own resolved __file__ path to LOCAL_ASSIST_LOG_DIR/verifier-origin.json
                # and exits 1 (triggering the verified-models.json handoff path).
                mirror_verify = mirror_root / "scripts" / "verify-served-model"
                mirror_verify.write_text(
                    "#!/usr/bin/env python3\n"
                    "import json, os, pathlib, sys\n"
                    "log_dir = os.environ.get('LOCAL_ASSIST_LOG_DIR', '')\n"
                    "if log_dir:\n"
                    "    p = pathlib.Path(log_dir) / 'verifier-origin.json'\n"
                    "    p.parent.mkdir(parents=True, exist_ok=True)\n"
                    "    p.write_text(json.dumps({'verifier_file': str(pathlib.Path(__file__).resolve()), 'cwd': os.getcwd()}))\n"
                    "sys.stderr.write('runs/ unreadable inside worker sandbox\\n')\n"
                    "raise SystemExit(1)\n",
                    encoding="utf-8",
                )
                os.chmod(mirror_verify, 0o755)

                fake_runs = Path(tmp) / "runs"
                fake_runs.mkdir(parents=True, exist_ok=True)
                fake_opencode = Path(tmp) / "fake-opencode"
                fake_src = Path(tmp) / "fake_opencode.c"
                fake_src.write_text(
                    "#include <string.h>\n"
                    "#include <unistd.h>\n"
                    "#include <wordexp.h>\n"
                    "int main(int argc, char **argv) {\n"
                    "    if (argc >= 3 && strcmp(argv[1], \"-c\") == 0) {\n"
                    "        const char *cmd = argv[2];\n"
                    "        if (strncmp(cmd, \"exec \", 5) == 0) cmd += 5;\n"
                    "        wordexp_t we;\n"
                    "        if (wordexp(cmd, &we, WRDE_NOCMD) == 0 && we.we_wordc > 0) {\n"
                    "            execv(we.we_wordv[0], we.we_wordv);\n"
                    "        }\n"
                    "    }\n"
                    "    return 127;\n"
                    "}\n",
                    encoding="utf-8",
                )
                subprocess.run(
                    ["/usr/bin/cc", "-O2", str(fake_src), "-o", str(fake_opencode)],
                    capture_output=True,
                    check=True,
                )
                os.chmod(fake_opencode, 0o755)

                pid_path = pid_file_for_model(model_id, fake_runs)
                pid_path.write_text(
                    json.dumps(
                        {
                            "model_id": model_id,
                            "repo": served_repo,
                            "status": "ready",
                            "pid": outside_srv.pid,
                            "pid_lstart": srv_lstart,
                            "hf_offline": True,
                            "port": chat_port,
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )

                class _OkVerify:
                    returncode = 0
                    stdout = f"{model_id}\n"
                    stderr = ""

                handoff_path = write_verified_local_models_handoff(
                    isolated_home=isolated_home,
                    worker_id=worker_id,
                    runs_dir=fake_runs,
                    verify_runner=lambda *a, **k: _OkVerify(),
                )
                prof = parse_security_profile_dict(
                    {
                        "filesystem": {
                            "read_roots": [str(mirror_root)],
                            "write_roots": [str(mirror_root)],
                        },
                        "mcp": {"enable_local_assist": True},
                    }
                )
                with patch("local_assist.security_profile.ROOT", mirror_root):
                    sb_text = compile_seatbelt_profile(
                        prof,
                        workspace_dir=mirror_root,
                        isolated_home=isolated_home,
                        opencode_bin=fake_opencode,
                    )
                    _, sb_path, worker_shell = write_worker_runtime_artifacts(
                        isolated_home=isolated_home,
                        worker_id=worker_id,
                        profile=prof,
                        opencode_config={},
                        seatbelt_text=sb_text,
                    )
                if not bound_8080:
                    os.chmod(sb_path, 0o600)
                    sb_path.write_text(
                        sb_text.replace("localhost:8080", f"localhost:{chat_port}"),
                        encoding="utf-8",
                    )
                    os.chmod(sb_path, 0o400)

                runtime_dir = isolated_home / "runtime"
                self.assertTrue((runtime_dir / "local_assist" / "server.py").is_file())
                self.assertTrue((runtime_dir / "scripts" / "verify-served-model").is_file())
                self.assertTrue((runtime_dir / "models.yaml").is_file())
                self.assertEqual(
                    (runtime_dir / "local_assist" / "server.py").stat().st_mode & 0o777,
                    0o400,
                )
                self.assertEqual(
                    (runtime_dir / "scripts" / "verify-served-model").stat().st_mode & 0o777,
                    0o500,
                )

                worker_env = build_worker_environment(
                    prof,
                    isolated_home=isolated_home,
                    worker_id=worker_id,
                    host_env=os.environ,
                )

                orig_server_bytes = (mirror_root / "local_assist" / "server.py").read_bytes()
                orig_verify_bytes = (mirror_root / "scripts" / "verify-served-model").read_bytes()
                orig_models_bytes = (mirror_root / "models.yaml").read_bytes()

                # Positive control: writing an ordinary workspace file inside the containing write_root succeeds
                allowed_ws_file = mirror_root / "workspace_allowed.txt"
                res_ok = subprocess.run(
                    [
                        "/usr/bin/sandbox-exec",
                        "-f",
                        str(sb_path),
                        str(worker_shell),
                        "-c",
                        f"echo allowed > {allowed_ws_file}",
                    ],
                    cwd=str(mirror_root),
                    env=worker_env,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(res_ok.returncode, 0, res_ok.stderr)
                self.assertEqual(allowed_ws_file.read_text(encoding="utf-8"), "allowed\n")

                # 1. Negative controls: with write_roots=[str(mirror_root)], worker cannot modify or rename
                #    mirror_root/local_assist/*, mirror_root/scripts/*, mirror_root/models.yaml, or <isolated_home>/runtime/*.
                for blocked_cmd in (
                    f"echo '# pwn' >> {mirror_root / 'local_assist' / 'server.py'}",
                    f"echo '# pwn' >> {mirror_root / 'scripts' / 'verify-served-model'}",
                    f"echo '# pwn' >> {mirror_root / 'models.yaml'}",
                    f"mv {mirror_root / 'local_assist'} {mirror_root / 'local_assist.pwn'}",
                    f"mv {mirror_root / 'scripts'} {mirror_root / 'scripts.pwn'}",
                    f"echo '# pwn' >> {runtime_dir / 'local_assist' / 'server.py'}",
                    f"echo '# pwn' >> {runtime_dir / 'scripts' / 'verify-served-model'}",
                    f"mv {runtime_dir} {isolated_home / '.tmp' / 'runtime-moved'}",
                ):
                    res_blk = subprocess.run(
                        [
                            "/usr/bin/sandbox-exec",
                            "-f",
                            str(sb_path),
                            str(worker_shell),
                            "-c",
                            blocked_cmd,
                        ],
                        cwd=str(mirror_root),
                        env=worker_env,
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertNotEqual(
                        res_blk.returncode,
                        0,
                        f"Expected EPERM on {blocked_cmd}, got rc=0",
                    )

                self.assertEqual((mirror_root / "local_assist" / "server.py").read_bytes(), orig_server_bytes)
                self.assertEqual((mirror_root / "scripts" / "verify-served-model").read_bytes(), orig_verify_bytes)
                self.assertEqual((mirror_root / "models.yaml").read_bytes(), orig_models_bytes)

                # 2. Poison control: even if the worker plants a malicious local_assist package and
                #    scripts/verify-served-model in a writable directory (<isolated_home>/.tmp/poison)
                #    and sets cwd + PYTHONPATH to that directory, local-assist-python -I ignores both
                #    and loads exclusively from <isolated_home>/runtime!
                poison_dir = isolated_home / ".tmp" / "poison"
                (poison_dir / "local_assist").mkdir(parents=True, exist_ok=True)
                (poison_dir / "scripts").mkdir(parents=True, exist_ok=True)
                poison_marker = isolated_home / ".tmp" / "poison_executed.txt"
                (poison_dir / "local_assist" / "__init__.py").write_text(
                    f"import pathlib; pathlib.Path({str(poison_marker)!r}).write_text('pwned'); raise RuntimeError('poison imported')\n",
                    encoding="utf-8",
                )
                (poison_dir / "local_assist" / "server.py").write_text(
                    f"import pathlib; pathlib.Path({str(poison_marker)!r}).write_text('pwned'); raise SystemExit(99)\n",
                    encoding="utf-8",
                )
                poison_verify = poison_dir / "scripts" / "verify-served-model"
                poison_verify.write_text(
                    f"#!/usr/bin/env python3\nimport pathlib; pathlib.Path({str(poison_marker)!r}).write_text('pwned-verify'); raise SystemExit(99)\n",
                    encoding="utf-8",
                )
                os.chmod(poison_verify, 0o755)

                la_py = isolated_home / "bin" / "local-assist-python"
                mcp_env = dict(worker_env)
                mcp_env["PYTHONPATH"] = str(poison_dir)
                mcp_env["PYTHONSAFEPATH"] = "1"
                mcp_env["PYTHONNOUSERSITE"] = "1"
                mcp_env["LOCAL_ASSIST_AUTO_SERVE"] = "0"
                mcp_env["LOCAL_ASSIST_WORKER_SANDBOX"] = "1"
                mcp_env["LOCAL_ASSIST_WORKER_ID"] = worker_id
                mcp_env["LOCAL_ASSIST_VERIFIED_MODELS_FILE"] = str(handoff_path)
                mcp_env["LOCAL_ASSIST_LOG_DIR"] = str(
                    isolated_home / ".local" / "share" / "local-assist-runs"
                )
                mcp_env["LOCAL_ASSIST_BASE_URL"] = f"http://127.0.0.1:{chat_port}/v1"

                # Verify that local_assist.__file__ and local_assist.paths.ROOT resolve inside runtime_dir
                res_check_origin = subprocess.run(
                    [
                        "/usr/bin/sandbox-exec",
                        "-f",
                        str(sb_path),
                        str(fake_opencode),
                        "-c",
                        (
                            f"exec {la_py} -I -c "
                            "'import json, local_assist, local_assist.paths as p; "
                            "print(json.dumps({\"file\": str(local_assist.__file__), \"root\": str(p.ROOT)}))'"
                        ),
                    ],
                    cwd=str(poison_dir),
                    env=mcp_env,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(res_check_origin.returncode, 0, res_check_origin.stderr)
                origin_info = json.loads(res_check_origin.stdout.strip())
                self.assertEqual(
                    Path(origin_info["root"]).resolve(),
                    runtime_dir.resolve(),
                )
                self.assertTrue(
                    Path(origin_info["file"]).resolve().is_relative_to(runtime_dir.resolve()),
                    origin_info,
                )
                self.assertFalse(poison_marker.exists())

                # Verify end-to-end MCP tool call succeeds from the staged immutable runtime
                # AND executes <isolated_home>/runtime/scripts/verify-served-model!
                mcp_reqs = (
                    json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
                    + "\n"
                    + json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 2,
                            "method": "tools/call",
                            "params": {
                                "name": "extract_fields",
                                "arguments": {
                                    "text": "Owner: immutable-runtime",
                                    "fields": {
                                        "owner": {
                                            "type": "string",
                                            "description": "Owner name",
                                            "required": True,
                                        }
                                    },
                                },
                            },
                        }
                    )
                    + "\n"
                )
                res_mcp = subprocess.run(
                    [
                        "/usr/bin/sandbox-exec",
                        "-f",
                        str(sb_path),
                        str(fake_opencode),
                        "-c",
                        f"exec {la_py} -I -m local_assist.server",
                    ],
                    input=mcp_reqs,
                    cwd=str(poison_dir),
                    env=mcp_env,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(res_mcp.returncode, 0, res_mcp.stderr)
                self.assertFalse(poison_marker.exists())
                out_lines = [ln for ln in res_mcp.stdout.splitlines() if ln.strip()]
                self.assertEqual(len(out_lines), 2, res_mcp.stdout)
                call_resp = json.loads(out_lines[1])
                self.assertFalse(call_resp["result"].get("isError", False), call_resp)
                self.assertEqual(
                    call_resp["result"]["structuredContent"]["extracted"]["owner"],
                    "immutable-runtime",
                )
                verifier_origin_file = (
                    isolated_home / ".local" / "share" / "local-assist-runs" / "verifier-origin.json"
                )
                self.assertTrue(verifier_origin_file.is_file())
                verifier_origin = json.loads(verifier_origin_file.read_text(encoding="utf-8"))
                self.assertEqual(
                    Path(verifier_origin["verifier_file"]).resolve(),
                    (runtime_dir / "scripts" / "verify-served-model").resolve(),
                )
                self.assertEqual(
                    Path(verifier_origin["cwd"]).resolve(),
                    runtime_dir.resolve(),
                )
        finally:
            outside_srv.terminate()
            try:
                outside_srv.wait(timeout=5)
            except subprocess.TimeoutExpired:
                outside_srv.kill()
            chat_srv.shutdown()
            chat_srv.server_close()
            if isolated_home.exists():
                _safe_rmtree_nofollow(isolated_home)

    def test_r2_f2_missing_lsof_observer_fails_closed_and_retains_home(self) -> None:
        from unittest.mock import patch
        from local_assist.security_profile import (
            _pid_cwd_matches_variants,
            _scan_worker_pids,
        )

        worker_id, isolated_home = allocate_worker_home()
        try:
            # 1. When _resolve_lsof_bin returns None and isolated_home is provided,
            #    _pid_cwd_matches_variants and _scan_worker_pids must fail closed (observer_ok=False).
            with patch("local_assist.security_profile._resolve_lsof_bin", return_value=None):
                cwd_matched, cwd_obs_ok = _pid_cwd_matches_variants(
                    os.getpid(), (str(isolated_home),)
                )
                self.assertFalse(cwd_matched)
                self.assertFalse(cwd_obs_ok)

                matched, obs_ok = _scan_worker_pids(
                    worker_id=worker_id,
                    isolated_home=isolated_home,
                )
                self.assertEqual(matched, {})
                self.assertFalse(obs_ok)

                td_res = teardown_worker_home(
                    isolated_home,
                    worker_id=worker_id,
                    harvest_logs=False,
                    remove_home=True,
                    reap_processes=True,
                )
                self.assertFalse(td_res["reaper_clean"])
                self.assertFalse(td_res["clean"])
                self.assertFalse(td_res["removed"])
                self.assertTrue(isolated_home.exists())

                # Mark owner dead and verify sweep_stale_worker_homes_detailed puts it in incomplete
                owner_meta = isolated_home / ".worker-owner.json"
                os.chmod(owner_meta, 0o600)
                owner_meta.write_text(
                    json.dumps(
                        {
                            "worker_id": worker_id,
                            "owner_pid": 999999,
                            "owner_pid_lstart": "Thu Jan  1 00:00:00 1970",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                os.chmod(owner_meta, 0o400)

                sweep_res = sweep_stale_worker_homes_detailed(max_age_seconds=0)
                self.assertIn(isolated_home, sweep_res["incomplete"])
                self.assertNotIn(isolated_home, sweep_res["removed"])
                self.assertTrue(isolated_home.exists())

            # 2. Positive control: with a controlled working observer, teardown succeeds and removes home.
            true_bin = shutil.which("true") or "/usr/bin/true"
            with patch("local_assist.security_profile._resolve_lsof_bin", return_value=true_bin):
                td_ok = teardown_worker_home(
                    isolated_home,
                    worker_id=worker_id,
                    harvest_logs=False,
                    remove_home=True,
                    reap_processes=True,
                )
                self.assertTrue(td_ok["reaper_clean"])
                self.assertTrue(td_ok["clean"])
                self.assertTrue(td_ok["removed"])
                self.assertFalse(isolated_home.exists())
        finally:
            if isolated_home.exists():
                _safe_rmtree_nofollow(isolated_home)

    def test_r2_f3_unconfirmed_process_group_blocks_cleanup_and_persists_across_sweeps(self) -> None:
        from unittest.mock import patch

        worker_id, isolated_home = allocate_worker_home()
        dest_dir: Path | None = None
        try:
            # Stage two audit log entries to verify R1 (idempotent harvest across repeated sweeps)
            staging = isolated_home / ".local" / "share" / "local-assist-runs"
            day_dir = staging / "2026-11-05"
            day_dir.mkdir(parents=True, exist_ok=True)
            rel_1 = "runs/local-assist/2026-11-05/10-00-00-one.json"
            (day_dir / "10-00-00-one.json").write_text(
                json.dumps({"tool": "extract_fields", "payload_path": rel_1}),
                encoding="utf-8",
            )
            index_file = staging / "2026-11-05.jsonl"
            index_file.write_text(
                json.dumps({"tool": "extract_fields", "payload_path": rel_1}) + "\n",
                encoding="utf-8",
            )

            stubborn_group_alive = True

            def _fake_pg_alive(pgid: int) -> bool:
                return stubborn_group_alive

            # Run lifecycle where the leader exits 0, fallback _scan_worker_pids returns ({}, True),
            # but _process_group_alive remains True after _terminate_process_group (R2-F3).
            with (
                patch(
                    "local_assist.security_profile._process_group_alive",
                    side_effect=_fake_pg_alive,
                ),
                patch(
                    "local_assist.security_profile._scan_worker_pids",
                    return_value=({}, True),
                ),
            ):
                rc, td_res = run_worker_sandbox_lifecycle(
                    [sys.executable, "-c", "raise SystemExit(0)"],
                    cwd=isolated_home,
                    env=os.environ,
                    isolated_home=isolated_home,
                    worker_id=worker_id,
                    harvest_logs=True,
                    remove_home=True,
                    grace_seconds=0.05,
                )

            self.assertEqual(rc, 1)
            self.assertFalse(td_res["group_clean"])
            self.assertFalse(td_res["reaper_clean"])
            self.assertFalse(td_res["clean"])
            self.assertFalse(td_res["removed"])
            self.assertTrue(isolated_home.exists())
            unconfirmed_marker = isolated_home / ".unconfirmed-process-group.json"
            self.assertTrue(unconfirmed_marker.is_file())
            dest_dir = td_res["harvested_dir"]
            self.assertIsNotNone(dest_dir)
            assert dest_dir is not None
            harvested_index = dest_dir / "2026-11-05.jsonl"
            self.assertEqual(
                len([ln for ln in harvested_index.read_text(encoding="utf-8").splitlines() if ln.strip()]),
                1,
            )

            # Mark owner PID dead so sweep_stale_worker_homes_detailed inspects this home
            owner_meta = isolated_home / ".worker-owner.json"
            os.chmod(owner_meta, 0o600)
            owner_meta.write_text(
                json.dumps(
                    {
                        "worker_id": worker_id,
                        "owner_pid": 999999,
                        "owner_pid_lstart": "Thu Jan  1 00:00:00 1970",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            os.chmod(owner_meta, 0o400)

            # P3-PLAN-MINOR-1 & R1: While stubborn_group_alive is still True, a subsequent sweep
            # must NOT delete the home even when _scan_worker_pids returns ({}, True), and must NOT
            # duplicate existing harvested JSONL rows!
            with (
                patch(
                    "local_assist.security_profile._process_group_alive",
                    side_effect=_fake_pg_alive,
                ),
                patch(
                    "local_assist.security_profile._scan_worker_pids",
                    return_value=({}, True),
                ),
            ):
                sweep_1 = sweep_stale_worker_homes_detailed(max_age_seconds=0)
            self.assertIn(isolated_home, sweep_1["incomplete"])
            self.assertNotIn(isolated_home, sweep_1["removed"])
            self.assertTrue(isolated_home.exists())
            self.assertEqual(
                len([ln for ln in harvested_index.read_text(encoding="utf-8").splitlines() if ln.strip()]),
                1,
            )

            # Add a second distinct row to staged JSONL and resolve the stubborn process group:
            # the next sweep must harvest the new row without duplicating the first, clear the
            # unconfirmed group marker, and remove isolated_home!
            rel_2 = "runs/local-assist/2026-11-05/10-00-01-two.json"
            with index_file.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"tool": "delegate_task", "payload_path": rel_2}) + "\n")
            stubborn_group_alive = False

            with (
                patch(
                    "local_assist.security_profile._process_group_alive",
                    side_effect=_fake_pg_alive,
                ),
                patch(
                    "local_assist.security_profile._scan_worker_pids",
                    return_value=({}, True),
                ),
            ):
                sweep_2 = sweep_stale_worker_homes_detailed(max_age_seconds=0)
            self.assertIn(isolated_home, sweep_2["removed"])
            self.assertNotIn(isolated_home, sweep_2["incomplete"])
            self.assertFalse(isolated_home.exists())
            harvested_rows = [
                json.loads(ln)
                for ln in harvested_index.read_text(encoding="utf-8").splitlines()
                if ln.strip()
            ]
            self.assertEqual(len(harvested_rows), 2)
            self.assertEqual(
                [r["tool"] for r in harvested_rows],
                ["extract_fields", "delegate_task"],
            )

            # P3-WORK-MINOR-2 & P3-R2-WORK-MINOR-1: Keep the real _write_unconfirmed_group_marker
            # active and inject OSError at Path.write_text on the target marker after the initial
            # pre-spawn write succeeds, proving the real updater preserves the pending record
            # without unlinking it first, and that a subsequent sweep retains the home.
            wid_fault, home_fault = allocate_worker_home()
            try:
                stubborn_group_alive = True
                target_marker = home_fault / ".unconfirmed-process-group.json"
                spawn_sentinel = home_fault / ".tmp" / "worker-spawned.txt"
                real_path_write_text = Path.write_text
                marker_writes = 0
                injected_failures = 0

                def _faulty_write_text(
                    self_path: Path, data: str, *args: Any, **kwargs: Any
                ) -> int:
                    nonlocal marker_writes, injected_failures
                    if self_path == target_marker:
                        marker_writes += 1
                        if marker_writes > 1:
                            injected_failures += 1
                            raise OSError("Simulated ENOSPC during post-spawn/teardown marker update")
                    return real_path_write_text(self_path, data, *args, **kwargs)

                with (
                    patch(
                        "local_assist.security_profile._process_group_alive",
                        side_effect=_fake_pg_alive,
                    ),
                    patch(
                        "local_assist.security_profile._scan_worker_pids",
                        return_value=({}, True),
                    ),
                    patch.object(Path, "write_text", _faulty_write_text),
                ):
                    rc_f, td_f = run_worker_sandbox_lifecycle(
                        [
                            sys.executable,
                            "-c",
                            f"import pathlib; pathlib.Path({str(spawn_sentinel)!r}).write_text('ok')",
                        ],
                        cwd=home_fault,
                        env=os.environ,
                        isolated_home=home_fault,
                        worker_id=wid_fault,
                        harvest_logs=False,
                        remove_home=True,
                        grace_seconds=0.05,
                    )
                self.assertEqual(rc_f, 1)
                self.assertTrue(spawn_sentinel.is_file())
                self.assertGreaterEqual(injected_failures, 2)
                self.assertFalse(td_f["clean"])
                self.assertTrue(home_fault.exists())
                self.assertTrue(target_marker.is_file())

                owner_meta_f = home_fault / ".worker-owner.json"
                os.chmod(owner_meta_f, 0o600)
                owner_meta_f.write_text(
                    json.dumps(
                        {
                            "worker_id": wid_fault,
                            "owner_pid": 999999,
                            "owner_pid_lstart": "Thu Jan  1 00:00:00 1970",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                os.chmod(owner_meta_f, 0o400)

                with patch(
                    "local_assist.security_profile._scan_worker_pids",
                    return_value=({}, True),
                ):
                    sweep_f = sweep_stale_worker_homes_detailed(max_age_seconds=0)
                self.assertIn(home_fault, sweep_f["incomplete"])
                self.assertNotIn(home_fault, sweep_f["removed"])
                self.assertTrue(home_fault.exists())
            finally:
                if home_fault.exists():
                    _safe_rmtree_nofollow(home_fault)

            # P3-WORK-MINOR-3: run_worker_sandbox_process uses callback-only teardown and never
            # reads, mutates, or creates .unconfirmed-process-group.json or .keep-worker-home in cwd.
            from local_assist.security_profile import run_worker_sandbox_process

            with tempfile.TemporaryDirectory() as proj_tmp:
                proj_dir = Path(proj_tmp)
                unrelated_marker = proj_dir / ".unconfirmed-process-group.json"
                unrelated_marker.write_text("not-json-project-file\n", encoding="utf-8")
                cb_called = False

                def _on_cb() -> None:
                    nonlocal cb_called
                    cb_called = True

                rc_proc = run_worker_sandbox_process(
                    [sys.executable, "-c", "raise SystemExit(0)"],
                    cwd=proj_dir,
                    env=os.environ,
                    teardown_callback=_on_cb,
                )
                self.assertEqual(rc_proc, 0)
                self.assertTrue(cb_called)
                self.assertEqual(
                    unrelated_marker.read_text(encoding="utf-8"),
                    "not-json-project-file\n",
                )
                self.assertFalse((proj_dir / ".keep-worker-home").exists())

            # R3-F1: When popen_factory raises synchronously before spawning a child,
            # run_worker_sandbox_lifecycle clears the pre-child pending
            # .unconfirmed-process-group.json marker so teardown_worker_home removes isolated_home.
            wid_popen_err, home_popen_err = allocate_worker_home()
            try:
                def _raising_popen(*_a: Any, **_kw: Any) -> Any:
                    self.assertTrue((home_popen_err / ".unconfirmed-process-group.json").is_file())
                    raise OSError("simulated synchronous pre-child Popen failure")

                with patch(
                    "local_assist.security_profile._scan_worker_pids",
                    return_value=({}, True),
                ):
                    with self.assertRaises(OSError):
                        run_worker_sandbox_lifecycle(
                            [sys.executable, "-c", "raise SystemExit(0)"],
                            cwd=home_popen_err,
                            env=os.environ,
                            isolated_home=home_popen_err,
                            worker_id=wid_popen_err,
                            harvest_logs=False,
                            remove_home=True,
                            popen_factory=_raising_popen,
                        )
                self.assertFalse(home_popen_err.exists())
            finally:
                if home_popen_err.exists():
                    _safe_rmtree_nofollow(home_popen_err)
        finally:
            if isolated_home.exists():
                _safe_rmtree_nofollow(isolated_home)
            if dest_dir is not None and dest_dir.exists():
                shutil.rmtree(dest_dir, ignore_errors=True)

    def test_worker_relay_default_chat_params_and_subagent_flag_decoupling(self) -> None:
        import argparse
        from urllib.error import HTTPError
        from urllib.request import Request, urlopen
        from local_assist.launch import (
            add_common_launcher_arguments,
            resolve_active_security_profile,
        )
        from local_assist.security_profile import validate_default_chat_params

        # 1. Decouple --allow-subagents from implicitly activating the unattended worker Seatbelt sandbox:
        #    passing --allow-subagents alone returns None (interactive mode), while passing
        #    --unattended-worker --allow-subagents returns a WorkerSecurityProfile with allow_subagents=True.
        parser = argparse.ArgumentParser()
        parser.add_argument("--allow-uncleared-model", action="store_true", default=False)
        parser.add_argument("--max-session-usd", type=float, default=None)
        add_common_launcher_arguments(
            parser,
            default_output_limit=8192,
            default_wait_seconds=60.0,
            wait_help="wait",
            no_serve_help="no-serve",
            print_config_help="print-config",
            unattended_help="unattended",
        )
        interactive_args = parser.parse_args(["--allow-subagents"])
        self.assertIsNone(resolve_active_security_profile(interactive_args))

        worker_args = parser.parse_args(["--unattended-worker", "--allow-subagents"])
        prof = resolve_active_security_profile(worker_args)
        self.assertIsNotNone(prof)
        assert prof is not None
        self.assertTrue(prof.allow_subagents)

        # 2. validate_default_chat_params rejects reserved keys and >4096-byte payloads
        for bad_dict in (
            {"model": "evil"},
            {"messages": []},
            {"max_tokens": 999999},
            {"max_completion_tokens": 999999},
            {"maxOutputTokens": 999999},
            {"n": 3},
            {"best_of": 3},
            {"stream": True},
            {"pad": "x" * 4100},
        ):
            with self.assertRaises(SecurityProfileError):
                validate_default_chat_params(bad_dict)

        # 3. _WorkerTokenRelay merges default_chat_params non-overwritingly and enforces
        #    post-merge max_request_bytes BEFORE incrementing chat_requests_used.
        received_bodies: list[dict[str, Any]] = []

        class _RelayUpstreamHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                received_bodies.append(json.loads(raw.decode("utf-8")))
                resp = json.dumps(
                    {
                        "id": "chatcmpl-relay",
                        "object": "chat.completion",
                        "model": "kimi-k3-1-pro",
                        "choices": [
                            {
                                "index": 0,
                                "message": {"role": "assistant", "content": "ok"},
                                "finish_reason": "stop",
                            }
                        ],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

            def log_message(self, format: str, *args: Any) -> None:
                return

        up_srv = ThreadingHTTPServer(("127.0.0.1", 0), _RelayUpstreamHandler)
        up_port = int(up_srv.server_address[1])
        threading.Thread(target=up_srv.serve_forever, daemon=True).start()

        relay = _WorkerTokenRelay(
            upstream_base_url=f"http://127.0.0.1:{up_port}/v1",
            upstream_session_token="se-session-" + ("f" * 64),
            max_chat_requests=2,
            max_request_bytes=320,
            max_tokens_cap=512,
            default_chat_params={
                "chat_template_kwargs": {"thinking": False, "enable_thinking": False},
                "reasoning_effort": "none",
                "include_reasoning": False,
            },
        ).start()
        try:
            # (a) Borderline body <= 320B raw that exceeds 320B after merging defaults -> 413 without incrementing chat_requests_used
            borderline = json.dumps(
                {
                    "model": "kimi-k3-1-pro",
                    "messages": [{"role": "user", "content": "x" * 160}],
                }
            ).encode("utf-8")
            self.assertLessEqual(len(borderline), 320)
            req_413 = Request(
                f"{relay.api_base_url}/chat/completions",
                data=borderline,
                headers={
                    "Authorization": f"Bearer {relay.relay_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with self.assertRaises(HTTPError) as ctx_413:
                urlopen(req_413, timeout=3)
            self.assertEqual(ctx_413.exception.code, 413)
            err_payload = json.loads(ctx_413.exception.read().decode("utf-8"))
            ctx_413.exception.close()
            self.assertEqual(err_payload["error"]["type"], "request_too_large")
            self.assertEqual(relay.chat_requests_used, 0)
            self.assertEqual(len(received_bodies), 0)

            # (b) Compact request -> defaults merged
            body_1 = json.dumps(
                {
                    "model": "kimi-k3-1-pro",
                    "messages": [{"role": "user", "content": "hi"}],
                }
            ).encode("utf-8")
            req_1 = Request(
                f"{relay.api_base_url}/chat/completions",
                data=body_1,
                headers={
                    "Authorization": f"Bearer {relay.relay_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urlopen(req_1, timeout=3) as r1:
                self.assertEqual(r1.status, 200)
            self.assertEqual(relay.chat_requests_used, 1)
            self.assertEqual(received_bodies[0].get("reasoning_effort"), "none")
            self.assertIs(received_bodies[0].get("include_reasoning"), False)
            self.assertEqual(
                received_bodies[0].get("chat_template_kwargs"),
                {"thinking": False, "enable_thinking": False},
            )

            # (c) Client override preserved
            body_2 = json.dumps(
                {
                    "model": "kimi-k3-1-pro",
                    "messages": [{"role": "user", "content": "hi"}],
                    "include_reasoning": True,
                    "chat_template_kwargs": {"thinking": True},
                }
            ).encode("utf-8")
            req_2 = Request(
                f"{relay.api_base_url}/chat/completions",
                data=body_2,
                headers={
                    "Authorization": f"Bearer {relay.relay_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urlopen(req_2, timeout=3) as r2:
                self.assertEqual(r2.status, 200)
            self.assertEqual(relay.chat_requests_used, 2)
            self.assertIs(received_bodies[1].get("include_reasoning"), True)
            self.assertEqual(
                received_bodies[1].get("chat_template_kwargs"),
                {"thinking": True, "enable_thinking": False},
            )
        finally:
            relay.close()
            up_srv.shutdown()
            up_srv.server_close()


if __name__ == "__main__":
    unittest.main()
