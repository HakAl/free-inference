from __future__ import annotations

import contextlib
import http.server
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from local_assist.launch import (
    FORBIDDEN_INTERACTIVE_SUBCOMMANDS,
    MAX_CLI_CONFIG_BYTES,
    _normalize_interactive_opencode_args,
    _open_pinned_opencode_config_dir,
    _persist_interactive_cli_config,
    _read_cli_config_from_dirfd,
    _stage_interactive_cli_config,
    _wait_for_invocation_service_ready,
    _write_cli_config_to_dirfd,
    merge_cli_config_three_way,
    publish_and_run_opencode,
    sanitize_cli_config_dict,
)
from local_assist.registry import EndpointConfig
from local_assist.security_profile import (
    ALLOWED_RUN_VALUE_FLAGS,
    HARD_DENIED_WORKER_TOOLS,
    KNOWN_BUILTIN_TOOLS,
    RESERVED_WORKER_ENV_NAMES,
    TESTED_OPENCODE_VERSION,
    SecurityProfileError,
    _build_worker_shell_script,
    _dual_realpath_variants,
    _expand_tool_set,
    allocate_worker_home,
    apply_cli_overrides,
    build_worker_environment,
    compile_interactive_seatbelt_profile,
    compile_opencode_security_config,
    compile_seatbelt_profile,
    default_unattended_worker_profile,
    parse_security_profile_dict,
    validate_worker_opencode_args,
    verify_opencode_version,
    write_worker_runtime_artifacts,
)

OPENCODE_BIN = shutil.which("opencode") or (
    "/opt/homebrew/bin/opencode" if Path("/opt/homebrew/bin/opencode").is_file() else None
)
HAS_SANDBOX_EXEC = sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").is_file()


def _can_apply_seatbelt() -> bool:
    if not HAS_SANDBOX_EXEC:
        return False
    try:
        proc = subprocess.run(
            ["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)", "/usr/bin/true"],
            capture_output=True,
            timeout=5,
            check=False,
        )
        return proc.returncode == 0
    except OSError:
        return False


CAN_APPLY_SEATBELT = _can_apply_seatbelt()


def _load_smoke_module() -> Any:
    script_path = ROOT / "scripts" / "opencode-smoke"
    loader = importlib.machinery.SourceFileLoader("opencode_smoke_mod_test", str(script_path))
    spec = importlib.util.spec_from_loader("opencode_smoke_mod_test", loader)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _dummy_endpoint(port: int = 8081) -> EndpointConfig:
    return EndpointConfig(
        model_id="tinfoil-deepseek-v4-1-flash",
        served_model_id="deepseek-v4-1-flash",
        provider_id="tinfoil",
        api_base_url=f"http://127.0.0.1:{port}/v1",
        host="127.0.0.1",
        port=port,
        api_key="se-keychain-managed",
        api_key_envar=None,
        runtime="tinfoil_proxy",
        trust_tier="enclave_runtime_attested",
        attestation_method="tinfoil_proxy",
        is_local_host=True,
        usage_policy="private_coding_opt_in",
        routing_private_local="blocked",
        routing_private_attested="cleared",
        context_window=65536,
    )


class OpenCode23UnitTests(unittest.TestCase):
    def test_tested_version_and_templates_deny_browser_and_execute(self) -> None:
        self.assertEqual(TESTED_OPENCODE_VERSION, "2.3.2")
        self.assertIn("browser", KNOWN_BUILTIN_TOOLS)
        self.assertIn("execute", KNOWN_BUILTIN_TOOLS)
        self.assertEqual(HARD_DENIED_WORKER_TOOLS, frozenset({"browser", "execute"}))

        for rel in (
            "config/opencode-private-attested.json.tmpl",
            "config/opencode-private-local.json.tmpl",
        ):
            raw = (ROOT / rel).read_text(encoding="utf-8")
            rendered = (
                raw.replace("__PLUGINS_JSON__", "[]")
                .replace("__CONTEXT_LIMIT__", "32768")
                .replace("__OUTPUT_LIMIT__", "4096")
                .replace("__SUBAGENT_ENABLED__", "false")
            )
            cfg = json.loads(rendered)
            self.assertIs(cfg["tools"]["browser"], False, rel)
            self.assertIs(cfg["tools"]["execute"], False, rel)
            self.assertEqual(cfg["permission"]["browser"], "deny", rel)
            self.assertEqual(cfg["permission"]["execute"], "deny", rel)

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("v2.3.2", readme)
        self.assertNotIn("v2.0.32+", readme)
        self.assertIn("--allow-opencode-version-drift", readme)

    def test_cli_config_leaf_schema_allowlist_and_type_checks(self) -> None:
        raw = {
            "$schema": "https://opencode.ai/v2/cli.json",
            "animations": True,
            "highlights": False,
            "mouse": True,
            "plugins": ["evil-pkg", {"package": "/tmp/pwn.js"}],
            "plugin": ["evil"],
            "plugin_enabled": {"evil": True},
            "experimental": {"anything": True},
            "unknown_top": "drop",
            "theme": {"name": "catppuccin", "mode": "dark", "bad_mode": "neon"},
            "keybinds": {
                "leader": "ctrl+x",
                "submit": ["enter", "ctrl+m"],
                "disabled": False,
                "bad_dict": {"cmd": "sh"},
                "bad_list": ["ok", 123],
            },
            "leader": {"timeout": 1500},
            "scroll": {"speed": 2.5, "acceleration": True},
            "attention": {
                "notifications": True,
                "sound": False,
                "volume": 0.5,
                "sound_pack": "opencode.default",
                "sounds": {"done": "/etc/passwd"},
            },
            "diffs": {
                "source": "branch",
                "wrap": "word",
                "tree": True,
                "single": False,
                "fullscreen": False,
                "view": "split",
            },
            "terminal": {"title": True, "copy": "select"},
            "prompt": {"editor": True, "paste": "compact", "image_preview": False},
            "session": {
                "sidebar": "auto",
                "scrollbar": True,
                "submit_scroll": "bottom",
                "thinking": "hide",
                "grouping": "auto",
                "verbosity": "medium",
                "image_preview": False,
                "tps": True,
                "markdown": "rendered",
                "new_location": "launch",
                "permissions": "autoaccept",
                "bogus": "drop",
            },
            "tabs": {
                "mode": "auto",
                "enabled": True,
                "scope": "cwd",
                "layout": "horizontal",
                "indicators": "status",
            },
            "mini": {
                "thinking": "hide",
                "tools": "show",
                "shell_output": "hide",
                "turn_summary": "show",
                "footer": "show",
                "splash": "hide",
                "work_spinner": "block-soft-slide",
                "mono": False,
                "replay": True,
                "replay_limit": 50,
            },
            "debug": {"devtools": False, "timing": True, "turn_tokens": "verbose"},
            "cursor": {"style": "block", "blinking": True},
        }
        sanitized = sanitize_cli_config_dict(raw)
        for forbidden in ("plugins", "plugin", "plugin_enabled", "experimental", "unknown_top"):
            self.assertNotIn(forbidden, sanitized)
        self.assertNotIn("sounds", sanitized["attention"])
        self.assertNotIn("bad_mode", sanitized["theme"])
        self.assertNotIn("bad_dict", sanitized["keybinds"])
        self.assertNotIn("bad_list", sanitized["keybinds"])
        self.assertNotIn("bogus", sanitized["session"])
        self.assertEqual(sanitized["session"]["permissions"], "autoaccept")
        self.assertEqual(sanitized["keybinds"]["submit"], ["enter", "ctrl+m"])

        # Python bool must be rejected for numeric fields, and NaN/Inf/out-of-range rejected.
        bad_types = {
            "leader": {"timeout": True},
            "scroll": {"speed": True},
            "attention": {"volume": False},
            "mini": {"replay_limit": True},
            "session": {"permissions": "yolo"},
            "debug": {"turn_tokens": "all"},
        }
        self.assertEqual(sanitize_cli_config_dict(bad_types), {})
        self.assertEqual(
            sanitize_cli_config_dict({"scroll": {"speed": float("nan")}, "attention": {"volume": 1.5}}),
            {},
        )
        # Huge JSON integer (> float max) must not raise OverflowError
        self.assertEqual(
            sanitize_cli_config_dict({"scroll": {"speed": 10**400}, "attention": {"volume": 10**400}}),
            {},
        )
        self.assertEqual(sanitize_cli_config_dict(["not", "a", "dict"]), {})

    def test_three_way_merge_preserves_siblings_concurrent_updates_and_unmodified_noop(self) -> None:
        base = {"session": {"permissions": "prompt", "verbosity": "low"}}
        # Unmodified session -> None (zero writes)
        self.assertIsNone(merge_cli_config_three_way(base, base, base))

        # Sibling edits: A updates permissions, B already wrote verbosity="high"
        disk_after_b = {"session": {"permissions": "prompt", "verbosity": "high"}}
        final_a = {"session": {"permissions": "autoaccept", "verbosity": "low"}}
        merged = merge_cli_config_three_way(base, final_a, disk_after_b)
        self.assertEqual(
            merged,
            {"session": {"permissions": "autoaccept", "verbosity": "high"}},
        )

        # Parent deletion vs sibling leaf addition: B added session.thinking="hide", A deleted session
        disk_b_added = {
            "session": {"permissions": "prompt", "verbosity": "low", "thinking": "hide"}
        }
        merged_add = merge_cli_config_three_way(base, {}, disk_b_added)
        self.assertEqual(merged_add, {"session": {"thinking": "hide"}})

        # Parent deletion vs concurrent update to existing sibling leaf:
        # Both staged permissions+verbosity; B updated verbosity="high"; A deleted session.
        # B's updated verbosity (D != S) must be preserved while untouched permissions (D == S) is deleted.
        merged_upd = merge_cli_config_three_way(base, {}, disk_after_b)
        self.assertEqual(merged_upd, {"session": {"verbosity": "high"}})

        # Concurrent leaf update when B deleted parent: A's explicit update reconstructs parent.
        merged_recreate = merge_cli_config_three_way(base, final_a, {})
        self.assertEqual(merged_recreate, {"session": {"permissions": "autoaccept"}})

        # Same-leaf conflict: last-writer-wins
        disk_b_same = {"session": {"permissions": "autoaccept", "verbosity": "low"}}
        final_a_same = {"session": {"permissions": "prompt", "verbosity": "low"}}
        # A changed nothing relative to base -> None
        self.assertIsNone(merge_cli_config_three_way(base, final_a_same, disk_b_same))
        # Both changed permissions from prompt -> A's new value wins when A writes second
        base_v = {"session": {"verbosity": "low"}}
        self.assertEqual(
            merge_cli_config_three_way(
                base_v,
                {"session": {"verbosity": "high"}},
                {"session": {"verbosity": "medium"}},
            ),
            {"session": {"verbosity": "high"}},
        )

    def test_descriptor_pinned_toctou_symlinks_fifo_size_cap_and_merged_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            # 1. Absence vs invalid input distinction
            h_absent = root / "absent"
            h_absent.mkdir(mode=0o700)
            st_dir, fd = _open_pinned_opencode_config_dir(h_absent, create=False)
            self.assertEqual((st_dir, fd), ("absent", None))

            # 2. Symlinked .config directory rejected
            h_sym_cfg = root / "sym_cfg"
            h_sym_cfg.mkdir(mode=0o700)
            target_dir = root / "target_dir"
            target_dir.mkdir(mode=0o700)
            os.symlink(target_dir, h_sym_cfg / ".config")
            st_sym, fd_sym = _open_pinned_opencode_config_dir(h_sym_cfg, create=False)
            self.assertEqual((st_sym, fd_sym), ("invalid", None))

            # 3. Symlinked .config/opencode directory rejected
            h_sym_oc = root / "sym_oc"
            (h_sym_oc / ".config").mkdir(parents=True, mode=0o700)
            os.symlink(target_dir, h_sym_oc / ".config" / "opencode")
            self.assertEqual(
                _open_pinned_opencode_config_dir(h_sym_oc, create=False),
                ("invalid", None),
            )

            # 4. Group/world-writable parent rejected
            h_bad_mode = root / "bad_mode"
            (h_bad_mode / ".config" / "opencode").mkdir(parents=True, mode=0o700)
            os.chmod(h_bad_mode / ".config" / "opencode", 0o775)
            self.assertEqual(
                _open_pinned_opencode_config_dir(h_bad_mode, create=False),
                ("invalid", None),
            )
            os.chmod(h_bad_mode / ".config" / "opencode", 0o700)

            # 5. Symlinked cli.json rejected
            h_sym_file = root / "sym_file"
            oc_dir = h_sym_file / ".config" / "opencode"
            oc_dir.mkdir(parents=True, mode=0o700)
            real_json = root / "real.json"
            real_json.write_text('{"session":{"permissions":"autoaccept"}}\n', encoding="utf-8")
            os.symlink(real_json, oc_dir / "cli.json")
            st_d, dfd = _open_pinned_opencode_config_dir(h_sym_file, create=False)
            self.assertEqual(st_d, "ok")
            assert dfd is not None
            try:
                self.assertEqual(_read_cli_config_from_dirfd(dfd), ("invalid", None))
            finally:
                os.close(dfd)

            # 6. Non-regular file (FIFO) rejected without blocking
            h_fifo = root / "fifo_home"
            fifo_oc = h_fifo / ".config" / "opencode"
            fifo_oc.mkdir(parents=True, mode=0o700)
            os.mkfifo(fifo_oc / "cli.json")
            st_d, dfd = _open_pinned_opencode_config_dir(h_fifo, create=False)
            self.assertEqual(st_d, "ok")
            assert dfd is not None
            try:
                self.assertEqual(_read_cli_config_from_dirfd(dfd), ("invalid", None))
            finally:
                os.close(dfd)

            # 7. Oversized file (> 64 KiB) and invalid JSON rejected; staging refuses overwrite
            h_over = root / "oversized"
            over_oc = h_over / ".config" / "opencode"
            over_oc.mkdir(parents=True, mode=0o700)
            inv_over = root / "inv_over"
            (inv_over / ".config" / "opencode").mkdir(parents=True, mode=0o700)
            over_payload = '{"theme":{"name":"' + ("x" * (MAX_CLI_CONFIG_BYTES + 100)) + '"}}'
            (over_oc / "cli.json").write_text(over_payload, encoding="utf-8")
            err = io.StringIO()
            staged, writeback_ok = _stage_interactive_cli_config(h_over, inv_over, err_stream=err)
            self.assertEqual(staged, {})
            self.assertFalse(writeback_ok)
            self.assertFalse((inv_over / ".config" / "opencode" / "cli.json").exists())

            # 8. Merged overflow (> 64 KiB from two independently valid < 64 KiB configs)
            # preserves existing on-disk cli.json untouched.
            h_merge_over = root / "merge_over"
            mo_oc = h_merge_over / ".config" / "opencode"
            mo_oc.mkdir(parents=True, mode=0o700)
            inv_mo = root / "inv_mo"
            (inv_mo / ".config" / "opencode").mkdir(parents=True, mode=0o700)
            big_a = {"keybinds": {f"a{i}": "x" * 1000 for i in range(40)}}
            big_b = {"keybinds": {f"b{i}": "y" * 1000 for i in range(40)}}
            orig_bytes = (json.dumps(big_b, indent=2, sort_keys=True) + "\n").encode("utf-8")
            self.assertLess(len(orig_bytes), MAX_CLI_CONFIG_BYTES)
            (mo_oc / "cli.json").write_bytes(orig_bytes)
            (inv_mo / ".config" / "opencode" / "cli.json").write_text(
                json.dumps(big_a), encoding="utf-8"
            )
            err_mo = io.StringIO()
            persisted = _persist_interactive_cli_config(h_merge_over, inv_mo, {}, err_stream=err_mo)
            self.assertFalse(persisted)
            self.assertIn("exceeds", err_mo.getvalue())
            self.assertEqual((mo_oc / "cli.json").read_bytes(), orig_bytes)

            # 9. Parent swap before write-back refuses to write through symlink
            h_swap = root / "swap_home"
            (h_swap / ".config" / "opencode").mkdir(parents=True, mode=0o700)
            inv_swap = root / "inv_swap"
            (inv_swap / ".config" / "opencode").mkdir(parents=True, mode=0o700)
            (inv_swap / ".config" / "opencode" / "cli.json").write_text(
                json.dumps({"session": {"permissions": "autoaccept"}}), encoding="utf-8"
            )
            shutil.rmtree(h_swap / ".config")
            os.symlink(target_dir, h_swap / ".config")
            err_swap = io.StringIO()
            self.assertFalse(
                _persist_interactive_cli_config(h_swap, inv_swap, {}, err_stream=err_swap)
            )
            self.assertFalse((target_dir / "opencode" / "cli.json").exists())

            # 10. Deeply nested JSON (RecursionError) and huge JSON integer (> float max)
            # are handled gracefully without raising.
            h_deep = root / "deep_home"
            deep_oc = h_deep / ".config" / "opencode"
            deep_oc.mkdir(parents=True, mode=0o700)
            depth = 2000
            (deep_oc / "cli.json").write_text(("[" * depth) + ("]" * depth), encoding="utf-8")
            st_d, dfd = _open_pinned_opencode_config_dir(h_deep, create=False)
            self.assertEqual(st_d, "ok")
            assert dfd is not None
            try:
                self.assertEqual(_read_cli_config_from_dirfd(dfd), ("invalid", None))
            finally:
                os.close(dfd)

            # Huge JSON integer in scroll.speed does not abort read/staging
            (deep_oc / "cli.json").write_text(
                '{"scroll":{"speed":' + ("9" * 400) + '},"session":{"permissions":"autoaccept"}}',
                encoding="utf-8",
            )
            st_d2, dfd2 = _open_pinned_opencode_config_dir(h_deep, create=False)
            self.assertEqual(st_d2, "ok")
            assert dfd2 is not None
            try:
                fstat, parsed = _read_cli_config_from_dirfd(dfd2)
                self.assertEqual(fstat, "ok")
                self.assertEqual(parsed, {"session": {"permissions": "autoaccept"}})
            finally:
                os.close(dfd2)

    def test_publish_and_run_staging_writeback_gates_and_env_hygiene(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "ws"
            ws.mkdir(mode=0o700)
            iso_home = root / "home"
            (iso_home / ".config" / "opencode").mkdir(parents=True, mode=0o700)
            (iso_home / ".config" / "opencode" / "cli.json").write_text(
                json.dumps(
                    {
                        "$schema": "https://opencode.ai/v2/cli.json",
                        "session": {"permissions": "autoaccept"},
                        "plugins": ["evil-plugin"],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            fake_bin = root / "fake-opencode"
            fake_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(fake_bin, 0o700)

            observed: dict[str, Any] = {}

            class _FakeProc:
                def __init__(self, rc: int = 0, raise_on_wait: bool = False) -> None:
                    self._rc = rc
                    self._polled: int | None = None
                    self._raise_on_wait = raise_on_wait
                    self.pid = 999999

                def poll(self) -> int | None:
                    return self._polled

                def terminate(self) -> None:
                    self._polled = 143

                def wait(self, timeout: float | None = None) -> int:
                    if self._raise_on_wait:
                        self._raise_on_wait = False
                        raise RuntimeError("simulated wait interruption")
                    self._polled = self._rc
                    return self._rc

            def _popen_capture(cmd: list[str], cwd: str, env: dict[str, str]) -> Any:
                observed["cmd"] = cmd
                observed["env"] = dict(env)
                xdg_cfg = Path(env["XDG_CONFIG_HOME"])
                oc_cfg = xdg_cfg / "opencode"
                observed["cfg_mode"] = xdg_cfg.stat().st_mode & 0o777
                observed["oc_mode"] = oc_cfg.stat().st_mode & 0o777
                observed["svc_mode"] = (oc_cfg / "service.json").stat().st_mode & 0o777
                observed["staged_cli"] = json.loads((oc_cfg / "cli.json").read_text(encoding="utf-8"))
                # Simulate OpenCode updating cli.json + trying to sneak plugins
                (oc_cfg / "cli.json").write_text(
                    json.dumps(
                        {
                            "$schema": "https://opencode.ai/v2/cli.json",
                            "session": {"permissions": "prompt", "verbosity": "high"},
                            "plugins": ["injected-at-runtime"],
                        }
                    ),
                    encoding="utf-8",
                )
                return _FakeProc(rc=0)

            rc = publish_and_run_opencode(
                opencode_bin=str(fake_bin),
                opencode_args=["run", "hi"],
                caller_cwd=ws,
                isolated_home=iso_home,
                endpoint=_dummy_endpoint(),
                config_text=json.dumps({"model": "private-attested/m"}),
                build_env_fn=lambda _p: {
                    "OPENCODE_CLI_CONFIG_CONTENT": '{"plugins":["bad"]}',
                    "OPENCODE_PTY_HANDOFF": "bad",
                    "OPENCODE_PTY_SOCKET_DIR": "/tmp/bad",
                    "OPENCODE_DB": "/tmp/bad.db",
                },
                current_sync={},
                popen_fn=_popen_capture,
            )
            self.assertEqual(rc, 0)
            self.assertEqual(observed["cfg_mode"], 0o500)
            self.assertEqual(observed["oc_mode"], 0o700)
            self.assertEqual(observed["svc_mode"], 0o400)
            # plugins stripped on staging
            self.assertEqual(
                observed["staged_cli"],
                {
                    "$schema": "https://opencode.ai/v2/cli.json",
                    "session": {"permissions": "autoaccept"},
                },
            )
            # New 2.3.2 env vars stripped, OPENCODE_PTY_BIN set to immutable sentinel under 0500 .config
            env = observed["env"]
            for k in (
                "OPENCODE_CLI_CONFIG_CONTENT",
                "OPENCODE_PTY_HANDOFF",
                "OPENCODE_PTY_SOCKET_DIR",
                "OPENCODE_DB",
            ):
                self.assertNotIn(k, env)
            self.assertTrue(env["OPENCODE_PTY_BIN"].endswith("/.config/.disabled-opencode-pty"))
            self.assertFalse(Path(env["OPENCODE_PTY_BIN"]).exists())

            # Persisted cli.json updated cleanly and stripped injected plugins
            persisted = json.loads(
                (iso_home / ".config" / "opencode" / "cli.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                persisted,
                {
                    "$schema": "https://opencode.ai/v2/cli.json",
                    "session": {"permissions": "prompt", "verbosity": "high"},
                },
            )
            self.assertEqual(
                (iso_home / ".config" / "opencode" / "cli.json").stat().st_mode & 0o777,
                0o600,
            )

            # Unmodified session performs zero writes (preserve mtime_ns)
            cli_path = iso_home / ".config" / "opencode" / "cli.json"
            before_stat = cli_path.stat()

            def _popen_noop(cmd: list[str], cwd: str, env: dict[str, str]) -> Any:
                return _FakeProc(rc=0)

            rc_noop = publish_and_run_opencode(
                opencode_bin=str(fake_bin),
                opencode_args=["run", "hi"],
                caller_cwd=ws,
                isolated_home=iso_home,
                endpoint=_dummy_endpoint(),
                config_text=json.dumps({"model": "private-attested/m"}),
                build_env_fn=lambda _p: {},
                current_sync={},
                popen_fn=_popen_noop,
            )
            self.assertEqual(rc_noop, 0)
            after_stat = cli_path.stat()
            self.assertEqual((before_stat.st_ino, before_stat.st_mtime_ns), (after_stat.st_ino, after_stat.st_mtime_ns))

            # Exceptional exit (proc terminated + waited in finally) still persists cleanly
            def _popen_exc(cmd: list[str], cwd: str, env: dict[str, str]) -> Any:
                oc_cfg = Path(env["XDG_CONFIG_HOME"]) / "opencode"
                (oc_cfg / "cli.json").write_text(
                    json.dumps({"session": {"permissions": "autoaccept", "verbosity": "high"}}),
                    encoding="utf-8",
                )
                return _FakeProc(rc=0, raise_on_wait=True)

            with self.assertRaises(RuntimeError):
                publish_and_run_opencode(
                    opencode_bin=str(fake_bin),
                    opencode_args=["run", "hi"],
                    caller_cwd=ws,
                    isolated_home=iso_home,
                    endpoint=_dummy_endpoint(),
                    config_text=json.dumps({"model": "private-attested/m"}),
                    build_env_fn=lambda _p: {},
                    current_sync={},
                    popen_fn=_popen_exc,
                )
            persisted_exc = json.loads(cli_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted_exc["session"]["permissions"], "autoaccept")

    def test_writeback_skipped_when_reap_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "ws"
            ws.mkdir(mode=0o700)
            iso_home = root / "home"
            (iso_home / ".config" / "opencode").mkdir(parents=True, mode=0o700)
            cli_path = iso_home / ".config" / "opencode" / "cli.json"
            cli_path.write_text('{"session":{"permissions":"prompt"}}\n', encoding="utf-8")
            fake_bin = root / "fake-opencode"
            fake_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(fake_bin, 0o700)
            fake_sb = root / "fake-sb"
            fake_sb.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(fake_sb, 0o700)

            class _DoneProc:
                pid = 999998

                def poll(self) -> int:
                    return 0

                def wait(self, timeout: float | None = None) -> int:
                    return 0

            def _popen_mutate(cmd: list[str], cwd: str, env: dict[str, str]) -> Any:
                oc_cfg = Path(env["XDG_CONFIG_HOME"]) / "opencode"
                (oc_cfg / "cli.json").write_text(
                    '{"session":{"permissions":"autoaccept"}}\n', encoding="utf-8"
                )
                return _DoneProc()

            with patch("local_assist.launch.subprocess.Popen", new=_popen_mutate), patch(
                "local_assist.launch._reap_invocation_service_and_children", return_value=False
            ), patch(
                "local_assist.launch._sweep_dead_invocations", return_value=None
            ), patch(
                "local_assist.launch._try_bind_service_identity_sidecar", return_value=None
            ):
                rc = publish_and_run_opencode(
                    opencode_bin=str(fake_bin),
                    opencode_args=[],
                    caller_cwd=ws,
                    isolated_home=iso_home,
                    endpoint=_dummy_endpoint(),
                    config_text=json.dumps({"model": "private-attested/m"}),
                    build_env_fn=lambda _p: {},
                    current_sync={},
                    sandbox_exec_bin=fake_sb,
                    popen_fn=_popen_mutate,
                )
            self.assertEqual(rc, 1)
            self.assertEqual(
                json.loads(cli_path.read_text(encoding="utf-8")),
                {"session": {"permissions": "prompt"}},
            )

    def test_interactive_run_prestarts_service_and_fails_closed_if_service_unready(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "ws"
            ws.mkdir(mode=0o700)
            iso_home = root / "home"
            iso_home.mkdir(mode=0o700)
            fake_bin = root / "fake-opencode"
            fake_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(fake_bin, 0o700)
            fake_sb = root / "fake-sb"
            fake_sb.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(fake_sb, 0o700)

            spawned_cmds: list[list[str]] = []

            class _EarlyExitProc:
                pid = 999997

                def poll(self) -> int:
                    return 1

                def wait(self, timeout: float | None = None) -> int:
                    return 1

            def _popen_early_exit(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
                spawned_cmds.append(list(cmd))
                return _EarlyExitProc()

            err_buf = io.StringIO()
            with patch("local_assist.launch.subprocess.Popen", new=_popen_early_exit), patch(
                "local_assist.launch._reap_invocation_service_and_children", return_value=True
            ), patch(
                "local_assist.launch._sweep_dead_invocations", return_value=None
            ), patch(
                "local_assist.launch.sys.stderr", err_buf
            ):
                rc = publish_and_run_opencode(
                    opencode_bin=str(fake_bin),
                    opencode_args=["--log-level", "info", "run", "hello"],
                    caller_cwd=ws,
                    isolated_home=iso_home,
                    endpoint=_dummy_endpoint(),
                    config_text=json.dumps({"model": "private-attested/m"}),
                    build_env_fn=lambda _p: {},
                    current_sync={},
                    sandbox_exec_bin=fake_sb,
                    popen_fn=_popen_early_exit,
                )
            self.assertEqual(rc, 1)
            opencode_cmds = [c for c in spawned_cmds if str(fake_bin) in c]
            self.assertEqual(len(opencode_cmds), 1)
            self.assertEqual(opencode_cmds[0][-2:], ["serve", "--service"])
            self.assertIn("blocking standalone --stdio fallback", err_buf.getvalue())

            # Also verify sidecar bind failure fails closed (never spawns opencode run),
            # and write-back exception in finally does not skip inv_dir cleanup.
            spawned_cmds2: list[list[str]] = []

            class _AliveProc:
                pid = 999996

                def poll(self) -> int | None:
                    return None

                def terminate(self) -> None:
                    pass

                def wait(self, timeout: float | None = None) -> int:
                    return 0

            def _popen_alive(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
                spawned_cmds2.append(list(cmd))
                return _AliveProc()

            with patch("local_assist.launch.subprocess.Popen", new=_popen_alive), patch(
                "local_assist.launch._wait_for_invocation_service_ready", return_value=True
            ), patch(
                "local_assist.launch._try_bind_service_identity_sidecar", return_value=False
            ), patch(
                "local_assist.launch._reap_invocation_service_and_children", return_value=True
            ), patch(
                "local_assist.launch._sweep_dead_invocations", return_value=None
            ):
                rc2 = publish_and_run_opencode(
                    opencode_bin=str(fake_bin),
                    opencode_args=["run", "hello"],
                    caller_cwd=ws,
                    isolated_home=iso_home,
                    endpoint=_dummy_endpoint(),
                    config_text=json.dumps({"model": "private-attested/m"}),
                    build_env_fn=lambda _p: {},
                    current_sync={},
                    sandbox_exec_bin=fake_sb,
                    popen_fn=_popen_alive,
                )
            self.assertEqual(rc2, 1)
            oc_cmds2 = [c for c in spawned_cmds2 if str(fake_bin) in c]
            self.assertEqual(len(oc_cmds2), 1)
            self.assertEqual(oc_cmds2[0][-2:], ["serve", "--service"])
            # inv_dir cleaned up even if _persist_interactive_cli_config raises
            with patch(
                "local_assist.launch._persist_interactive_cli_config",
                side_effect=RuntimeError("boom writeback"),
            ):
                rc3 = publish_and_run_opencode(
                    opencode_bin=str(fake_bin),
                    opencode_args=["run", "hi"],
                    caller_cwd=ws,
                    isolated_home=iso_home,
                    endpoint=_dummy_endpoint(),
                    config_text=json.dumps({"model": "private-attested/m"}),
                    build_env_fn=lambda _p: {},
                    current_sync={},
                    popen_fn=lambda *a, **kw: type("P", (), {"pid": 999995, "poll": lambda s: 0, "wait": lambda s, timeout=None: 0})(),
                )
            self.assertEqual(rc3, 0)
            self.assertEqual(list((iso_home / ".invocations").iterdir()), [])

    def test_wait_for_invocation_service_ready_verifies_pid_port_and_authenticated_api_info(self) -> None:
        import base64

        expected_pw = "test-service-secret-123"
        expected_auth = "Basic " + base64.b64encode(f"opencode:{expected_pw}".encode("utf-8")).decode("ascii")
        resp_cfg: dict[str, Any] = {"pid": 424242, "version": "2.3.2"}

        class _InfoHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                return

            def do_GET(self) -> None:
                if self.path != "/api/info":
                    self.send_response(404)
                    self.end_headers()
                    return
                if self.headers.get("Authorization") != expected_auth:
                    self.send_response(401)
                    self.end_headers()
                    return
                body = json.dumps(resp_cfg).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        class _TCPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
            allow_reuse_address = True
            daemon_threads = True

        srv = _TCPServer(("127.0.0.1", 0), _InfoHandler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as td:
                svc_file = Path(td) / "service.json"

                class _Proc:
                    def __init__(self, pid: int) -> None:
                        self.pid = pid

                    def poll(self) -> int | None:
                        return None

                # 1. Wrong PID in service.json rejected
                svc_file.write_text(json.dumps({"pid": 111111, "url": f"http://127.0.0.1:{port}"}), encoding="utf-8")
                self.assertFalse(
                    _wait_for_invocation_service_ready(
                        serve_proc=_Proc(424242),
                        state_svc_file=svc_file,
                        service_port=port,
                        service_password=expected_pw,
                        timeout_seconds=0.5,
                    )
                )

                # 2. Wrong port in service.json url rejected
                svc_file.write_text(json.dumps({"pid": 424242, "url": f"http://127.0.0.1:{port + 1}"}), encoding="utf-8")
                self.assertFalse(
                    _wait_for_invocation_service_ready(
                        serve_proc=_Proc(424242),
                        state_svc_file=svc_file,
                        service_port=port,
                        service_password=expected_pw,
                        timeout_seconds=0.5,
                    )
                )

                # 2b. Malformed port in service.json url rejected cleanly (no ValueError)
                svc_file.write_text(json.dumps({"pid": 424242, "url": "http://127.0.0.1:notaport"}), encoding="utf-8")
                self.assertFalse(
                    _wait_for_invocation_service_ready(
                        serve_proc=_Proc(424242),
                        state_svc_file=svc_file,
                        service_port=port,
                        service_password=expected_pw,
                        timeout_seconds=0.5,
                    )
                )

                # 3. Wrong password (401 on /api/info) rejected
                svc_file.write_text(json.dumps({"pid": 424242, "url": f"http://127.0.0.1:{port}"}), encoding="utf-8")
                self.assertFalse(
                    _wait_for_invocation_service_ready(
                        serve_proc=_Proc(424242),
                        state_svc_file=svc_file,
                        service_port=port,
                        service_password="wrong-password",
                        timeout_seconds=0.5,
                    )
                )

                # 4. Mismatched /api/info pid rejected
                resp_cfg["pid"] = 999999
                self.assertFalse(
                    _wait_for_invocation_service_ready(
                        serve_proc=_Proc(424242),
                        state_svc_file=svc_file,
                        service_port=port,
                        service_password=expected_pw,
                        timeout_seconds=0.5,
                    )
                )

                # 5. Exact PID + exact port + valid auth + matching /api/info pid succeeds
                resp_cfg["pid"] = 424242
                self.assertTrue(
                    _wait_for_invocation_service_ready(
                        serve_proc=_Proc(424242),
                        state_svc_file=svc_file,
                        service_port=port,
                        service_password=expected_pw,
                        timeout_seconds=1.0,
                    )
                )
        finally:
            srv.shutdown()
            srv.server_close()

    def test_wait_for_invocation_service_ready_bounds_trickle_oversized_and_releases_launch_lock(self) -> None:
        import fcntl

        stop_ev = threading.Event()
        mode_box = {"mode": "trickle"}

        class _SlowHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                return

            def do_GET(self) -> None:
                if mode_box["mode"] == "chunked_eof_trailer":
                    body = json.dumps({"pid": 424242, "version": "2.3.2"}).encode("utf-8")
                    raw_http = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: application/json\r\n"
                        b"Transfer-Encoding: chunked\r\n"
                        b"Connection: close\r\n\r\n"
                        + f"{len(body):x}\r\n".encode("ascii")
                        + body
                        + b"\r\n0\r\n"
                        # Intentionally omit final terminating \r\n (EOF inside trailer section)
                    )
                    try:
                        self.wfile.write(raw_http)
                        self.wfile.flush()
                    except OSError:
                        pass
                    return
                if mode_box["mode"] == "chunked_valid":
                    body = json.dumps({"pid": 424242, "version": "2.3.2"}).encode("utf-8")
                    raw_http = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: application/json\r\n"
                        b"Transfer-Encoding: chunked\r\n"
                        b"Connection: close\r\n\r\n"
                        + f"{len(body):x}\r\n".encode("ascii")
                        + body
                        + b"\r\n0\r\n\r\n"
                    )
                    try:
                        self.wfile.write(raw_http)
                        self.wfile.flush()
                    except OSError:
                        pass
                    return
                if mode_box["mode"] == "truncated":
                    prefix = json.dumps({"pid": 424242, "version": "2.3.2"}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(prefix) + 50))
                    self.end_headers()
                    try:
                        self.wfile.write(prefix)
                        self.wfile.flush()
                    except OSError:
                        pass
                    return
                if mode_box["mode"] == "oversized":
                    payload = b"{" + (b" " * 70000) + b"}"
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    try:
                        self.wfile.write(payload)
                        self.wfile.flush()
                    except OSError:
                        pass
                    return
                # Trickling body: sends 1 byte every 0.1s (well under the 0.5s socket timeout)
                # so an unbounded resp.read() would hang far beyond the overall deadline.
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "200")
                self.end_headers()
                try:
                    self.wfile.write(b"{")
                    self.wfile.flush()
                    for _ in range(199):
                        if stop_ev.wait(0.1):
                            return
                        self.wfile.write(b" ")
                        self.wfile.flush()
                except OSError:
                    return

        class _TCPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
            allow_reuse_address = True
            daemon_threads = True

        srv = _TCPServer(("127.0.0.1", 0), _SlowHandler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                svc_file = root / "service.json"
                svc_file.write_text(
                    json.dumps({"pid": 424242, "url": f"http://127.0.0.1:{port}"}),
                    encoding="utf-8",
                )

                class _Proc:
                    def __init__(self, pid: int = 424242) -> None:
                        self.pid = pid
                        self.terminated = False

                    def poll(self) -> int | None:
                        return 0 if self.terminated else None

                    def terminate(self) -> None:
                        self.terminated = True

                    def wait(self, timeout: float | None = None) -> int:
                        return 0

                # 1. Trickling HTTP response must abort within the overall monotonic deadline
                t0 = time.monotonic()
                ok_trickle = _wait_for_invocation_service_ready(
                    serve_proc=_Proc(),
                    state_svc_file=svc_file,
                    service_port=port,
                    service_password="pw",
                    timeout_seconds=0.55,
                )
                elapsed_trickle = time.monotonic() - t0
                self.assertFalse(ok_trickle)
                self.assertLess(elapsed_trickle, 1.4)

                # 2. Oversized (> 64 KiB) response must be rejected within deadline
                mode_box["mode"] = "oversized"
                t1 = time.monotonic()
                ok_big = _wait_for_invocation_service_ready(
                    serve_proc=_Proc(),
                    state_svc_file=svc_file,
                    service_port=port,
                    service_password="pw",
                    timeout_seconds=0.4,
                )
                self.assertFalse(ok_big)
                self.assertLess(time.monotonic() - t1, 1.2)

                # 2b. Truncated fixed-length body (valid JSON prefix + early EOF < Content-Length) rejected
                mode_box["mode"] = "truncated"
                t1b = time.monotonic()
                ok_trunc = _wait_for_invocation_service_ready(
                    serve_proc=_Proc(),
                    state_svc_file=svc_file,
                    service_port=port,
                    service_password="pw",
                    timeout_seconds=0.3,
                )
                self.assertFalse(ok_trunc)
                self.assertLess(time.monotonic() - t1b, 1.0)

                # 2c. Chunked response with EOF in trailer section (0\r\n without final \r\n) rejected,
                # whereas complete chunked terminator (0\r\n\r\n) succeeds.
                mode_box["mode"] = "chunked_eof_trailer"
                t1c = time.monotonic()
                ok_chunk_eof = _wait_for_invocation_service_ready(
                    serve_proc=_Proc(),
                    state_svc_file=svc_file,
                    service_port=port,
                    service_password="pw",
                    timeout_seconds=0.3,
                )
                self.assertFalse(ok_chunk_eof)
                self.assertLess(time.monotonic() - t1c, 1.0)

                mode_box["mode"] = "chunked_valid"
                ok_chunk_ok = _wait_for_invocation_service_ready(
                    serve_proc=_Proc(),
                    state_svc_file=svc_file,
                    service_port=port,
                    service_password="pw",
                    timeout_seconds=0.5,
                )
                self.assertTrue(ok_chunk_ok)

                # Direct RFC 9112 §7.1 chunked wire framing checks:
                # reject signed '+2' chunk size and colonless trailer lines; accept interim 100 + valid 200.
                from local_assist.launch import _is_complete_chunked_wire

                self.assertFalse(
                    _is_complete_chunked_wire(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+2\r\n{}\r\n0\r\n\r\n"
                    )
                )
                self.assertFalse(
                    _is_complete_chunked_wire(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n 2\r\n{}\r\n0\r\n\r\n"
                    )
                )
                self.assertFalse(
                    _is_complete_chunked_wire(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2 \r\n{}\r\n0\r\n\r\n"
                    )
                )
                self.assertFalse(
                    _is_complete_chunked_wire(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n 2;ext=1\r\n{}\r\n0\r\n\r\n"
                    )
                )
                self.assertFalse(
                    _is_complete_chunked_wire(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\n\r\n{}\r\n0\r\n\r\n"
                    )
                )
                self.assertTrue(
                    _is_complete_chunked_wire(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2 ;ext=1\r\n{}\r\n0\r\n\r\n"
                    )
                )
                self.assertFalse(
                    _is_complete_chunked_wire(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\nnot-a-header\r\n\r\n"
                    )
                )
                self.assertTrue(
                    _is_complete_chunked_wire(
                        b"HTTP/1.1 100 Continue\r\n\r\n"
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                        b"2\r\n{}\r\n0\r\nX-Checksum: ok\r\n\r\n"
                    )
                )

                # 3. End-to-end publish_and_run_opencode: shared launch lock MUST NOT be held
                # during service readiness wait, and deadline refusal must terminate serve_proc
                # and clean up inv_dir.
                mode_box["mode"] = "trickle"
                ws = root / "ws"
                ws.mkdir(mode=0o700)
                iso_home = root / "home"
                iso_home.mkdir(mode=0o700)
                fake_bin = root / "fake-oc"
                fake_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                os.chmod(fake_bin, 0o700)
                fake_sb = root / "fake-sb"
                fake_sb.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                os.chmod(fake_sb, 0o700)

                serve_proc_holder: list[_Proc] = []
                lock_free_during_wait: list[bool] = []
                boot_lock_held_during_wait: list[bool] = []
                orig_wait = _wait_for_invocation_service_ready

                def _popen_trickle(cmd: list[str], *a: Any, **kw: Any) -> Any:
                    if str(fake_bin) not in cmd:
                        return type(
                            "OtherProc",
                            (),
                            {
                                "pid": 515152,
                                "returncode": 0,
                                "poll": lambda s: 0,
                                "wait": lambda s, timeout=None: 0,
                                "communicate": lambda s, input=None, timeout=None: ("", ""),
                                "__enter__": lambda s: s,
                                "__exit__": lambda s, *ex: False,
                            },
                        )()
                    p = _Proc(pid=515151)
                    serve_proc_holder.append(p)
                    # Publish service.json pointing at our trickling server on allocated port
                    env_arg = kw.get("env") or {}
                    st_dir = Path(env_arg["XDG_STATE_HOME"]) / "opencode"
                    st_dir.mkdir(parents=True, exist_ok=True)
                    (st_dir / "service.json").write_text(
                        json.dumps({"pid": 515151, "url": f"http://127.0.0.1:{port}"}),
                        encoding="utf-8",
                    )
                    return p

                def _bounded_wait_probe(**kwargs: Any) -> bool:
                    # Try non-blocking exclusive flock on shared launch lock WHILE waiting -> MUST be free
                    lock_path = iso_home / ".opencode-launch.lock"
                    lfd = os.open(str(lock_path), os.O_RDWR)
                    try:
                        try:
                            fcntl.flock(lfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            lock_free_during_wait.append(True)
                            fcntl.flock(lfd, fcntl.LOCK_UN)
                        except BlockingIOError:
                            lock_free_during_wait.append(False)
                    finally:
                        os.close(lfd)
                    # Dedicated service-boot lock MUST exist (no O_CREAT) and be HELD during wait
                    boot_lock_p = iso_home / ".opencode-service-boot.lock"
                    bfd = os.open(str(boot_lock_p), os.O_RDWR)
                    try:
                        try:
                            fcntl.flock(bfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            boot_lock_held_during_wait.append(False)
                            fcntl.flock(bfd, fcntl.LOCK_UN)
                        except BlockingIOError:
                            boot_lock_held_during_wait.append(True)
                    finally:
                        os.close(bfd)
                    kwargs["timeout_seconds"] = 0.5
                    return orig_wait(**kwargs)

                t2 = time.monotonic()
                with patch("local_assist.launch._allocate_loopback_ephemeral_port", return_value=port), patch(
                    "local_assist.launch.subprocess.Popen", new=_popen_trickle
                ), patch(
                    "local_assist.launch._wait_for_invocation_service_ready",
                    side_effect=_bounded_wait_probe,
                ), patch(
                    "local_assist.launch._reap_invocation_service_and_children", return_value=True
                ), patch(
                    "local_assist.launch._sweep_dead_invocations", return_value=None
                ):
                    rc_timeout = publish_and_run_opencode(
                        opencode_bin=str(fake_bin),
                        opencode_args=["run", "hello"],
                        caller_cwd=ws,
                        isolated_home=iso_home,
                        endpoint=_dummy_endpoint(),
                        config_text=json.dumps({"model": "private-attested/m"}),
                        build_env_fn=lambda _p: {},
                        current_sync={},
                        sandbox_exec_bin=fake_sb,
                        popen_fn=_popen_trickle,
                    )
                self.assertEqual(rc_timeout, 1)
                self.assertLess(time.monotonic() - t2, 2.5)
                self.assertEqual(lock_free_during_wait, [True])
                self.assertEqual(boot_lock_held_during_wait, [True])
                # Dedicated service-boot lock MUST exist (opened without O_CREAT) and be released cleanly after refusal.
                boot_lock_path = iso_home / ".opencode-service-boot.lock"
                blfd = os.open(str(boot_lock_path), os.O_RDWR)
                try:
                    fcntl.flock(blfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(blfd, fcntl.LOCK_UN)
                finally:
                    os.close(blfd)
                self.assertEqual(len(serve_proc_holder), 1)
                self.assertTrue(serve_proc_holder[0].terminated)
                self.assertEqual(list((iso_home / ".invocations").iterdir()), [])

                # 4. Two-launcher timeout handoff: Launcher 1's failed serve_proc MUST be terminated &
                # reaped WHILE .opencode-service-boot.lock is still held, BEFORE Launcher 2's serve_proc
                # is allowed to spawn under the boot lock.
                events: list[str] = []
                ev_lock = threading.Lock()
                l1_started = threading.Event()
                l1_reaped = threading.Event()
                boot_lock_held_at_reap: list[bool] = []
                proc_counter = {"n": 0}

                class _TrackedProc:
                    def __init__(self, tag: str, pid: int, auto_exit: bool = False) -> None:
                        self.tag = tag
                        self.pid = pid
                        self._done = auto_exit

                    def poll(self) -> int | None:
                        return 0 if self._done else None

                    def terminate(self) -> None:
                        with ev_lock:
                            events.append(f"{self.tag}:terminate")
                        self._done = True

                    def wait(self, timeout: float | None = None) -> int:
                        if self.tag == "L1_serve":
                            # Deterministically assert the boot lock is HELD at the exact moment of reap
                            bfd = os.open(str(boot_lock_path), os.O_RDWR)
                            try:
                                try:
                                    fcntl.flock(bfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                                    boot_lock_held_at_reap.append(False)
                                    fcntl.flock(bfd, fcntl.LOCK_UN)
                                except BlockingIOError:
                                    boot_lock_held_at_reap.append(True)
                            finally:
                                os.close(bfd)
                            l1_reaped.set()
                        with ev_lock:
                            events.append(f"{self.tag}:reaped")
                        return 0

                def _popen_handoff(cmd: list[str], *a: Any, **kw: Any) -> Any:
                    if str(fake_bin) not in cmd:
                        return type(
                            "OtherProc",
                            (),
                            {
                                "pid": 515199,
                                "returncode": 0,
                                "poll": lambda s: 0,
                                "wait": lambda s, timeout=None: 0,
                                "communicate": lambda s, input=None, timeout=None: ("", ""),
                                "__enter__": lambda s: s,
                                "__exit__": lambda s, *ex: False,
                            },
                        )()
                    is_serve = cmd[-2:] == ["serve", "--service"]
                    with ev_lock:
                        if is_serve:
                            proc_counter["n"] += 1
                            idx = proc_counter["n"]
                            tag = f"L{idx}_serve"
                            events.append(f"{tag}:spawn")
                            if idx == 1:
                                l1_started.set()
                            return _TrackedProc(tag, 515200 + idx)
                        events.append("L2_client:spawn")
                        return _TrackedProc("L2_client", 515300, auto_exit=True)

                def _wait_handoff(**kwargs: Any) -> bool:
                    sp = kwargs["serve_proc"]
                    if sp.tag == "L1_serve":
                        time.sleep(0.25)
                        return False
                    self.assertTrue(l1_reaped.is_set(), f"L2_serve started before L1_serve reaped: {events}")
                    return True

                rcs: dict[str, int] = {}

                def _run_launcher(name: str) -> None:
                    rcs[name] = publish_and_run_opencode(
                        opencode_bin=str(fake_bin),
                        opencode_args=["run", name],
                        caller_cwd=ws,
                        isolated_home=iso_home,
                        endpoint=_dummy_endpoint(),
                        config_text=json.dumps({"model": "private-attested/m"}),
                        build_env_fn=lambda _p: {},
                        current_sync={},
                        sandbox_exec_bin=fake_sb,
                        popen_fn=_popen_handoff,
                    )

                with patch("local_assist.launch.subprocess.Popen", new=_popen_handoff), patch(
                    "local_assist.launch._wait_for_invocation_service_ready",
                    side_effect=_wait_handoff,
                ), patch(
                    "local_assist.launch._try_bind_service_identity_sidecar", return_value=True
                ), patch(
                    "local_assist.launch._reap_invocation_service_and_children", return_value=True
                ), patch(
                    "local_assist.launch._sweep_dead_invocations", return_value=None
                ):
                    t_l1 = threading.Thread(target=_run_launcher, args=("L1",))
                    t_l2 = threading.Thread(target=_run_launcher, args=("L2",))
                    t_l1.start()
                    self.assertTrue(l1_started.wait(timeout=5.0))
                    t_l2.start()
                    t_l1.join(timeout=10.0)
                    t_l2.join(timeout=10.0)
                self.assertEqual(rcs.get("L1"), 1)
                self.assertEqual(rcs.get("L2"), 0)
                self.assertEqual(boot_lock_held_at_reap, [True])
                self.assertLess(events.index("L1_serve:reaped"), events.index("L2_serve:spawn"))

                # 5. Unverified reap (both SIGTERM wait and SIGKILL wait time out, poll() stays None):
                # records pending-reap marker so subsequent launches refuse to spawn until the prior
                # service PID is confirmed gone, then recover cleanly once dead.
                stuck_pid = 515901
                stuck_alive = {"alive": True}
                spawned_after_stuck: list[list[str]] = []

                class _UnreapableProc:
                    def __init__(self) -> None:
                        self.pid = stuck_pid

                    def poll(self) -> int | None:
                        return None

                    def terminate(self) -> None:
                        pass

                    def kill(self) -> None:
                        pass

                    def wait(self, timeout: float | None = None) -> int:
                        raise subprocess.TimeoutExpired(cmd="serve", timeout=timeout or 1.0)

                def _popen_stuck(cmd: list[str], *a: Any, **kw: Any) -> Any:
                    if str(fake_bin) not in cmd:
                        return type(
                            "OtherProc",
                            (),
                            {
                                "pid": 515902,
                                "returncode": 0,
                                "poll": lambda s: 0,
                                "wait": lambda s, timeout=None: 0,
                                "communicate": lambda s, input=None, timeout=None: ("", ""),
                                "__enter__": lambda s: s,
                                "__exit__": lambda s, *ex: False,
                            },
                        )()
                    spawned_after_stuck.append(list(cmd))
                    return _UnreapableProc()

                with patch("local_assist.launch.subprocess.Popen", new=_popen_stuck), patch(
                    "local_assist.launch._wait_for_invocation_service_ready", return_value=False
                ), patch(
                    "local_assist.launch.pid_is_alive", side_effect=lambda pid: stuck_alive["alive"] if pid == stuck_pid else False
                ), patch(
                    "local_assist.launch.get_process_lstart", return_value="Sun Nov 22 07:00:00 2026"
                ), patch(
                    "local_assist.launch._reap_invocation_service_and_children", return_value=True
                ), patch(
                    "local_assist.launch._sweep_dead_invocations", return_value=None
                ):
                    rc_stuck1 = publish_and_run_opencode(
                        opencode_bin=str(fake_bin),
                        opencode_args=["run", "stuck1"],
                        caller_cwd=ws,
                        isolated_home=iso_home,
                        endpoint=_dummy_endpoint(),
                        config_text=json.dumps({"model": "private-attested/m"}),
                        build_env_fn=lambda _p: {},
                        current_sync={},
                        sandbox_exec_bin=fake_sb,
                        popen_fn=_popen_stuck,
                    )
                    self.assertEqual(rc_stuck1, 1)
                    self.assertEqual(len(spawned_after_stuck), 1)
                    self.assertTrue((iso_home / ".opencode-service-boot.pending.json").is_file())

                    # Subsequent launch while stuck_pid is still alive MUST refuse WITHOUT spawning serve_proc
                    # and distinguish a known live PID from an unknown-PID interruption.
                    known_pid_err = io.StringIO()
                    with contextlib.redirect_stderr(known_pid_err):
                        rc_blocked = publish_and_run_opencode(
                            opencode_bin=str(fake_bin),
                            opencode_args=["run", "blocked2"],
                            caller_cwd=ws,
                            isolated_home=iso_home,
                            endpoint=_dummy_endpoint(),
                            config_text=json.dumps({"model": "private-attested/m"}),
                            build_env_fn=lambda _p: {},
                            current_sync={},
                            sandbox_exec_bin=fake_sb,
                            popen_fn=_popen_stuck,
                        )
                    self.assertEqual(rc_blocked, 1)
                    self.assertEqual(len(spawned_after_stuck), 1)
                    self.assertIn(f"pid={stuck_pid}", known_pid_err.getvalue())
                    self.assertIn(f"stop pid {stuck_pid}", known_pid_err.getvalue())
                    self.assertNotIn("interrupted before recording its child service PID", known_pid_err.getvalue())

                    # Once stuck_pid is confirmed gone, marker clears and next launch proceeds
                    stuck_alive["alive"] = False
                    with patch(
                        "local_assist.launch._wait_for_invocation_service_ready", return_value=True
                    ), patch(
                        "local_assist.launch._try_bind_service_identity_sidecar", return_value=True
                    ):
                        def _popen_recovered(cmd: list[str], *a: Any, **kw: Any) -> Any:
                            if str(fake_bin) not in cmd:
                                return type(
                                    "OtherProc",
                                    (),
                                    {
                                        "pid": 515909,
                                        "returncode": 0,
                                        "poll": lambda s: 0,
                                        "wait": lambda s, timeout=None: 0,
                                        "communicate": lambda s, input=None, timeout=None: ("", ""),
                                        "__enter__": lambda s: s,
                                        "__exit__": lambda s, *ex: False,
                                    },
                                )()
                            is_serve = cmd[-2:] == ["serve", "--service"]
                            return _TrackedProc("rec_serve" if is_serve else "rec_cli", 515910, auto_exit=not is_serve)

                        with patch("local_assist.launch.subprocess.Popen", new=_popen_recovered):
                            rc_rec = publish_and_run_opencode(
                                opencode_bin=str(fake_bin),
                                opencode_args=["run", "recovered"],
                                caller_cwd=ws,
                                isolated_home=iso_home,
                                endpoint=_dummy_endpoint(),
                                config_text=json.dumps({"model": "private-attested/m"}),
                                build_env_fn=lambda _p: {},
                                current_sync={},
                                sandbox_exec_bin=fake_sb,
                                popen_fn=_popen_recovered,
                            )
                    self.assertEqual(rc_rec, 0)
                    self.assertFalse((iso_home / ".opencode-service-boot.pending.json").exists())

                # 6. Persistence failure (ENOSPC) fault injection:
                # 6a. Pre-spawn ENOSPC refuses to spawn serve_proc at all (0 spawns).
                import errno as _errno_mod

                spawns_enospc: list[list[str]] = []

                def _popen_enospc(cmd: list[str], *a: Any, **kw: Any) -> Any:
                    if str(fake_bin) not in cmd:
                        return type(
                            "OtherProc",
                            (),
                            {
                                "pid": 515920,
                                "returncode": 0,
                                "poll": lambda s: 0,
                                "wait": lambda s, timeout=None: 0,
                                "communicate": lambda s, input=None, timeout=None: ("", ""),
                                "__enter__": lambda s: s,
                                "__exit__": lambda s, *ex: False,
                            },
                        )()
                    spawns_enospc.append(list(cmd))
                    return _UnreapableProc()

                with patch("local_assist.launch.subprocess.Popen", new=_popen_enospc), patch(
                    "local_assist.launch._atomic_write_text_0600",
                    side_effect=OSError(_errno_mod.ENOSPC, "No space left on device"),
                ), patch(
                    "local_assist.launch._reap_invocation_service_and_children", return_value=True
                ), patch(
                    "local_assist.launch._sweep_dead_invocations", return_value=None
                ):
                    rc_enospc_pre = publish_and_run_opencode(
                        opencode_bin=str(fake_bin),
                        opencode_args=["run", "enospc-pre"],
                        caller_cwd=ws,
                        isolated_home=iso_home,
                        endpoint=_dummy_endpoint(),
                        config_text=json.dumps({"model": "private-attested/m"}),
                        build_env_fn=lambda _p: {},
                        current_sync={},
                        sandbox_exec_bin=fake_sb,
                        popen_fn=_popen_enospc,
                    )
                self.assertEqual(rc_enospc_pre, 1)
                self.assertEqual(spawns_enospc, [])

                # 6b. Pre-spawn guard succeeds, then post-spawn PID updates fail with ENOSPC while
                # serve_proc cannot be reaped: durable pre-spawn guard (with boot_id, no child pid)
                # blocks subsequent launches on the SAME host boot with unknown-PID recovery guidance,
                # and automatically recovers to a successful launch after a host reboot (new boot_id).
                from local_assist.launch import _atomic_write_text_0600 as _real_atomic_write

                write_calls = {"n": 0}
                boot_before = "11111111-1111-4111-8111-111111111111"
                boot_after = "22222222-2222-4222-8222-222222222222"
                boot_box = {"boot_id": boot_before}

                def _enospc_after_first(target_path: Path, content: str) -> None:
                    write_calls["n"] += 1
                    if write_calls["n"] == 1:
                        return _real_atomic_write(target_path, content)
                    raise OSError(_errno_mod.ENOSPC, "No space left on device")

                with patch("local_assist.launch.subprocess.Popen", new=_popen_enospc), patch(
                    "local_assist.launch._get_host_boot_id",
                    side_effect=lambda: boot_box["boot_id"],
                ), patch(
                    "local_assist.launch._atomic_write_text_0600",
                    side_effect=_enospc_after_first,
                ), patch(
                    "local_assist.launch._wait_for_invocation_service_ready", return_value=False
                ), patch(
                    "local_assist.launch._reap_invocation_service_and_children", return_value=True
                ), patch(
                    "local_assist.launch._sweep_dead_invocations", return_value=None
                ):
                    rc_enospc_post = publish_and_run_opencode(
                        opencode_bin=str(fake_bin),
                        opencode_args=["run", "enospc-post"],
                        caller_cwd=ws,
                        isolated_home=iso_home,
                        endpoint=_dummy_endpoint(),
                        config_text=json.dumps({"model": "private-attested/m"}),
                        build_env_fn=lambda _p: {},
                        current_sync={},
                        sandbox_exec_bin=fake_sb,
                        popen_fn=_popen_enospc,
                    )
                    self.assertEqual(rc_enospc_post, 1)
                    self.assertEqual(len(spawns_enospc), 1)
                    marker_path = iso_home / ".opencode-service-boot.pending.json"
                    self.assertTrue(marker_path.is_file())
                    guard_data = json.loads(marker_path.read_text(encoding="utf-8"))
                    self.assertEqual(guard_data.get("boot_id"), boot_before)
                    self.assertNotIn("pid", guard_data)

                    # Next launcher on SAME boot MUST refuse fail-closed (no second spawn) and
                    # distinguish unknown child PID with explicit recovery steps.
                    unknown_pid_err = io.StringIO()
                    with contextlib.redirect_stderr(unknown_pid_err):
                        rc_enospc_next = publish_and_run_opencode(
                            opencode_bin=str(fake_bin),
                            opencode_args=["run", "enospc-next"],
                            caller_cwd=ws,
                            isolated_home=iso_home,
                            endpoint=_dummy_endpoint(),
                            config_text=json.dumps({"model": "private-attested/m"}),
                            build_env_fn=lambda _p: {},
                            current_sync={},
                            sandbox_exec_bin=fake_sb,
                            popen_fn=_popen_enospc,
                        )
                    self.assertEqual(rc_enospc_next, 1)
                    self.assertEqual(len(spawns_enospc), 1)
                    err_text = unknown_pid_err.getvalue()
                    self.assertIn("interrupted before recording its child service PID", err_text)
                    self.assertIn(str(marker_path), err_text)
                    self.assertIn("reboot", err_text)

                # After a host reboot (different canonical boot_id), the stale unknown-PID guard auto-clears
                # and the home returns to service with a successful interactive run launch!
                boot_box["boot_id"] = boot_after

                def _popen_post_reboot(cmd: list[str], *a: Any, **kw: Any) -> Any:
                    if str(fake_bin) not in cmd:
                        return type(
                            "OtherProc",
                            (),
                            {
                                "pid": 515930,
                                "returncode": 0,
                                "poll": lambda s: 0,
                                "wait": lambda s, timeout=None: 0,
                                "communicate": lambda s, input=None, timeout=None: ("", ""),
                                "__enter__": lambda s: s,
                                "__exit__": lambda s, *ex: False,
                            },
                        )()
                    is_serve = cmd[-2:] == ["serve", "--service"]
                    return _TrackedProc(
                        "reboot_serve" if is_serve else "reboot_cli",
                        515931 if is_serve else 515932,
                        auto_exit=not is_serve,
                    )

                with patch("local_assist.launch.subprocess.Popen", new=_popen_post_reboot), patch(
                    "local_assist.launch._get_host_boot_id",
                    side_effect=lambda: boot_box["boot_id"],
                ), patch(
                    "local_assist.launch._wait_for_invocation_service_ready", return_value=True
                ), patch(
                    "local_assist.launch._try_bind_service_identity_sidecar", return_value=True
                ), patch(
                    "local_assist.launch._reap_invocation_service_and_children", return_value=True
                ), patch(
                    "local_assist.launch._sweep_dead_invocations", return_value=None
                ):
                    rc_after_reboot = publish_and_run_opencode(
                        opencode_bin=str(fake_bin),
                        opencode_args=["run", "after-reboot"],
                        caller_cwd=ws,
                        isolated_home=iso_home,
                        endpoint=_dummy_endpoint(),
                        config_text=json.dumps({"model": "private-attested/m"}),
                        build_env_fn=lambda _p: {},
                        current_sync={},
                        sandbox_exec_bin=fake_sb,
                        popen_fn=_popen_post_reboot,
                    )
                self.assertEqual(rc_after_reboot, 0)
                self.assertFalse((iso_home / ".opencode-service-boot.pending.json").exists())

                # 6c. Guard with unavailable OR malformed ("corrupt") boot_id never falsely auto-clears,
                # qualifies manual removal (not reboot alone), and unverified start times (missing saved
                # or current pid_lstart) never tell the operator to blindly stop the PID.
                from local_assist.launch import _check_and_clear_pending_service_reap

                marker_p = iso_home / ".opencode-service-boot.pending.json"
                marker_p.write_text(
                    json.dumps({"invocation_id": "inv-unavail", "boot_id": "unavailable"}) + "\n",
                    encoding="utf-8",
                )
                with patch("local_assist.launch._get_host_boot_id", return_value=boot_after):
                    ok_unavail, reason_unavail = _check_and_clear_pending_service_reap(iso_home)
                self.assertFalse(ok_unavail)
                self.assertIn("interrupted before recording its child service PID", reason_unavail or "")
                self.assertIn("manually remove", reason_unavail or "")
                self.assertIn("reboot alone will not auto-clear", reason_unavail or "")
                self.assertNotIn("or reboot to recover", reason_unavail or "")
                self.assertTrue(marker_p.is_file())

                marker_p.write_text(
                    json.dumps(
                        {
                            "invocation_id": "inv-corrupt",
                            "boot_id": "corrupt",
                            "pid": stuck_pid,
                            "pid_lstart": "Sun Nov 22 07:00:00 2026",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                with patch("local_assist.launch._get_host_boot_id", return_value=boot_after), patch(
                    "local_assist.launch.pid_is_alive",
                    side_effect=lambda pid: pid == stuck_pid,
                ), patch(
                    "local_assist.launch.get_process_lstart",
                    return_value="Sun Nov 22 07:00:00 2026",
                ):
                    ok_corrupt, reason_corrupt = _check_and_clear_pending_service_reap(iso_home)
                self.assertFalse(ok_corrupt)
                self.assertIn(f"pid={stuck_pid}", reason_corrupt or "")
                self.assertIn("start time verified", reason_corrupt or "")
                self.assertIn("reboot alone will not auto-clear", reason_corrupt or "")
                self.assertTrue(marker_p.is_file())

                # Unverified PID identity: saved pid_lstart unavailable -> must require confirming
                # process belongs to opencode serve --service for this home before stopping.
                marker_p.write_text(
                    json.dumps(
                        {
                            "invocation_id": "inv-unverified-saved",
                            "boot_id": boot_after,
                            "pid": stuck_pid,
                            "pid_lstart": "unavailable",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                with patch("local_assist.launch._get_host_boot_id", return_value=boot_after), patch(
                    "local_assist.launch.pid_is_alive",
                    side_effect=lambda pid: pid == stuck_pid,
                ), patch(
                    "local_assist.launch.get_process_lstart",
                    return_value="Sun Nov 22 07:00:00 2026",
                ):
                    ok_unv_saved, reason_unv_saved = _check_and_clear_pending_service_reap(iso_home)
                self.assertFalse(ok_unv_saved)
                self.assertIn("identity is unverified", reason_unv_saved or "")
                self.assertIn("opencode serve --service", reason_unv_saved or "")
                self.assertIn("before stopping it", reason_unv_saved or "")
                self.assertNotIn(f"stop pid {stuck_pid}", reason_unv_saved or "")
                self.assertTrue(marker_p.is_file())

                # Unverified PID identity: current start-time query returns None -> same unverified refusal.
                marker_p.write_text(
                    json.dumps(
                        {
                            "invocation_id": "inv-unverified-cur",
                            "boot_id": boot_after,
                            "pid": stuck_pid,
                            "pid_lstart": "Sun Nov 22 07:00:00 2026",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                with patch("local_assist.launch._get_host_boot_id", return_value=boot_after), patch(
                    "local_assist.launch.pid_is_alive",
                    side_effect=lambda pid: pid == stuck_pid,
                ), patch(
                    "local_assist.launch.get_process_lstart",
                    return_value=None,
                ):
                    ok_unv_cur, reason_unv_cur = _check_and_clear_pending_service_reap(iso_home)
                self.assertFalse(ok_unv_cur)
                self.assertIn("identity is unverified", reason_unv_cur or "")
                self.assertIn("opencode serve --service", reason_unv_cur or "")
                self.assertIn("before stopping it", reason_unv_cur or "")
                self.assertNotIn(f"stop pid {stuck_pid}", reason_unv_cur or "")
                self.assertTrue(marker_p.is_file())

                # Valid saved boot UUID + unavailable current boot lookup must distinguish unavailable
                # current lookup from missing recorded UUID (does not falsely claim no valid UUID recorded).
                marker_p.write_text(
                    json.dumps({"invocation_id": "inv-cur-boot-none", "boot_id": boot_before}) + "\n",
                    encoding="utf-8",
                )
                with patch("local_assist.launch._get_host_boot_id", return_value=None):
                    ok_cur_none, reason_cur_none = _check_and_clear_pending_service_reap(iso_home)
                self.assertFalse(ok_cur_none)
                self.assertIn("current host boot UUID could not be read", reason_cur_none or "")
                self.assertNotIn("no valid boot UUID was recorded", reason_cur_none or "")
                self.assertTrue(marker_p.is_file())
                marker_p.unlink()
        finally:
            stop_ev.set()
            srv.shutdown()
            srv.server_close()

    def test_cli_config_fstat_and_read_io_errors_fall_back_and_still_launch(self) -> None:
        import errno as _errno

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "ws"
            ws.mkdir(mode=0o700)
            iso_home = root / "home"
            cfg_dir = iso_home / ".config" / "opencode"
            cfg_dir.mkdir(parents=True, mode=0o700)
            cli_path = cfg_dir / "cli.json"
            original_text = json.dumps({"session": {"permissions": "autoaccept"}}) + "\n"
            cli_path.write_text(original_text, encoding="utf-8")
            os.chmod(cli_path, 0o600)

            inv_dir = root / "inv"
            (inv_dir / ".config" / "opencode").mkdir(parents=True, mode=0o700)

            # 1. OSError from os.fstat on opened cli.json falls back cleanly
            real_fstat = os.fstat
            cli_ino = cli_path.stat().st_ino

            def _failing_fstat(fd: int) -> os.stat_result:
                st = real_fstat(fd)
                if st.st_ino == cli_ino:
                    raise OSError(_errno.EIO, "simulated fstat error")
                return st

            err_buf = io.StringIO()
            with patch("local_assist.launch.os.fstat", side_effect=_failing_fstat):
                staged, wb_allowed = _stage_interactive_cli_config(iso_home, inv_dir, err_stream=err_buf)
            self.assertEqual(staged, {})
            self.assertFalse(wb_allowed)
            self.assertIn("WARNING", err_buf.getvalue())

            # 2. OSError from os.read on opened cli.json falls back cleanly AND publish_and_run_opencode
            # still completes normally with write-back disabled and original file untouched.
            real_read = os.read

            def _failing_read(fd: int, n: int) -> bytes:
                try:
                    if real_fstat(fd).st_ino == cli_ino:
                        raise OSError(_errno.EIO, "simulated read error")
                except OSError as exc:
                    if exc.errno == _errno.EIO:
                        raise
                return real_read(fd, n)

            err_buf2 = io.StringIO()
            with patch("local_assist.launch.os.read", side_effect=_failing_read):
                staged2, wb_allowed2 = _stage_interactive_cli_config(iso_home, inv_dir, err_stream=err_buf2)
            self.assertEqual(staged2, {})
            self.assertFalse(wb_allowed2)
            self.assertIn("WARNING", err_buf2.getvalue())

            fake_bin = root / "fake-oc"
            fake_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(fake_bin, 0o700)
            ran = []

            def _fake_popen(cmd: list[str], *a: Any, **kw: Any) -> Any:
                ran.append(list(cmd))
                # Even if the invocation writes a cli.json, write-back must stay disabled
                inv_cli = Path(kw["env"]["OPENCODE_CONFIG_DIR"]) / "cli.json"
                inv_cli.write_text('{"theme":{"mode":"light"}}\n', encoding="utf-8")
                return type("P", (), {"pid": 999994, "poll": lambda s: 0, "wait": lambda s, timeout=None: 0})()

            with patch("local_assist.launch.os.read", side_effect=_failing_read):
                rc = publish_and_run_opencode(
                    opencode_bin=str(fake_bin),
                    opencode_args=["--auto"],
                    caller_cwd=ws,
                    isolated_home=iso_home,
                    endpoint=_dummy_endpoint(),
                    config_text=json.dumps({"model": "private-attested/m"}),
                    build_env_fn=lambda _p: {},
                    current_sync={},
                    popen_fn=_fake_popen,
                )
            self.assertEqual(rc, 0)
            self.assertEqual(len(ran), 1)
            self.assertEqual(cli_path.read_text(encoding="utf-8"), original_text)
            self.assertEqual(list((iso_home / ".invocations").iterdir()), [])

    def test_interactive_arg_normalization_flags_server_precedence_and_v23_subcommands(self) -> None:
        for forbidden in (
            "service",
            "serve",
            "acp",
            "pair",
            "auth",
            "upgrade",
            "update",
            "uninstall",
            "api",
            "plugin",
            "reload",
            "mcp",
        ):
            self.assertIn(forbidden, FORBIDDEN_INTERACTIVE_SUBCOMMANDS)
            ok, _, err = _normalize_interactive_opencode_args([forbidden])
            self.assertFalse(ok, forbidden)
            self.assertIn(forbidden, err or "")

        # Value-taking global flags (separated and = forms) must not hide forbidden subcommands
        for hidden in (
            ["--log-level", "info", "api"],
            ["--log-level=info", "plugin"],
            ["-s", "ses_123", "reload"],
            ["--session=ses_123", "mcp"],
            ["--prompt", "hello", "service"],
            ["--completions", "zsh", "auth"],
        ):
            ok, _, err = _normalize_interactive_opencode_args(hidden)
            self.assertFalse(ok, f"expected refusal for {hidden}")
            self.assertTrue(err)

        # Unconditional --server rejection takes precedence over operand consumption, '--', and on run/mini
        for bad_server in (
            ["--server", "http://127.0.0.1:9999"],
            ["--server=http://127.0.0.1:9999"],
            ["run", "--server", "http://127.0.0.1:9999", "hi"],
            ["run", "--server=http://127.0.0.1:9999", "hi"],
            ["mini", "--server=http://127.0.0.1:9999"],
            ["--prompt", "--server"],
            ["--prompt", "--server=http://127.0.0.1:9999"],
            ["--", "--server", "http://127.0.0.1:9999"],
            ["run", "--", "--server=http://127.0.0.1:9999"],
        ):
            ok, _, err = _normalize_interactive_opencode_args(bad_server)
            self.assertFalse(ok, f"expected --server refusal for {bad_server}")
            self.assertIn("--server", err or "")

        # Missing or flag-shaped operands for value-taking root flags are rejected consistently
        for bad_operand in (
            ["--log-level"],
            ["-s"],
            ["--log-level", "--standalone"],
            ["--log-level", "--"],
            ["-s", "-v"],
        ):
            ok, _, err = _normalize_interactive_opencode_args(bad_operand)
            self.assertFalse(ok, f"expected operand refusal for {bad_operand}")
            self.assertTrue(err)

        # Preserves --standalone stripping and allowed TUI / commands
        ok, cleaned, err = _normalize_interactive_opencode_args(
            ["--standalone", "--log-level", "info", "run", "--standalone=true", "hello"]
        )
        self.assertTrue(ok, err)
        self.assertEqual(cleaned, ["--log-level", "info", "run", "hello"])

        for allowed in (
            [],
            ["--auto"],
            ["--log-level", "warn", "/tmp/work"],
            ["mini", "--continue"],
            ["models"],
            ["session", "list"],
            ["stats"],
            ["debug", "config"],
        ):
            ok, out, err = _normalize_interactive_opencode_args(allowed)
            self.assertTrue(ok, f"expected allow for {allowed}, err={err}")
            self.assertEqual(out, allowed)

    def test_worker_flags_hard_denied_tools_and_v23_env_hardening(self) -> None:
        self.assertEqual(ALLOWED_RUN_VALUE_FLAGS, frozenset({"--format", "--title"}))
        self.assertEqual(
            validate_worker_opencode_args(
                ["run", "--standalone", "--format", "json", "--title", "t1", "--thinking", "Say OK"]
            ),
            ["run", "--format", "json", "--title", "t1", "--thinking", "Say OK"],
        )
        for bad in (
            ["run", "--variant", "high", "hi"],
            ["run", "--variant=high", "hi"],
            ["run", "--worktree", "wt1", "hi"],
            ["run", "--worktree=wt1", "hi"],
            ["run", "-w", "hi"],
            ["run", "--archived", "hi"],
            ["run", "--agent", "build", "hi"],
            ["run", "--agent=build", "hi"],
            ["run", "--auto", "hi"],
            ["run", "--server", "http://127.0.0.1:1", "hi"],
            ["run", "--server=http://127.0.0.1:1", "hi"],
            ["run", "--log-level", "debug", "hi"],
            ["run", "--log-level=debug", "hi"],
            ["run", "--wizard", "hi"],
            ["run", "--completions", "zsh", "hi"],
            ["run", "--print-logs", "hi"],
        ):
            with self.assertRaises(SecurityProfileError, msg=f"expected rejection for {bad}"):
                validate_worker_opencode_args(bad)

        # Hard-denied tools rejected in profile and CLI overrides, and always denied in compiled config
        for tool in ("browser", "execute"):
            with self.assertRaisesRegex(SecurityProfileError, "unconditionally denied"):
                parse_security_profile_dict({"tools": {"allowed_tools": ["read", tool]}})
            base_prof = default_unattended_worker_profile()
            with self.assertRaisesRegex(SecurityProfileError, "unconditionally denied"):
                apply_cli_overrides(base_prof, allowed_tools=[tool])
            self.assertNotIn(tool, _expand_tool_set(["read", tool], [], allow_subagents=False))

        compiled = compile_opencode_security_config({}, default_unattended_worker_profile())
        for tool in ("browser", "execute"):
            self.assertIs(compiled["tools"][tool], False)
            self.assertEqual(compiled["permission"][tool], "deny")

        # New 2.3.2 env vars reserved, stripped, unset in child shell, and OPENCODE_PTY_BIN set
        new_vars = (
            "OPENCODE_CLI_CONFIG_CONTENT",
            "OPENCODE_PTY_BIN",
            "OPENCODE_PTY_HANDOFF",
            "OPENCODE_PTY_SOCKET_DIR",
            "OPENCODE_DB",
        )
        for v in new_vars:
            self.assertIn(v, RESERVED_WORKER_ENV_NAMES)
            with self.assertRaises(SecurityProfileError):
                parse_security_profile_dict({"environment": {"allowlist": ["PATH", v]}})
            with self.assertRaises(SecurityProfileError):
                parse_security_profile_dict({"environment": {"set": {v: "x"}}})
            with self.assertRaises(SecurityProfileError):
                apply_cli_overrides(default_unattended_worker_profile(), pass_env=[v])

        with tempfile.TemporaryDirectory() as td:
            wid, wh = allocate_worker_home(worker_homes_dir=Path(td))
            prof = default_unattended_worker_profile()
            host_env = {
                "PATH": "/usr/bin:/bin",
                "OPENCODE_CLI_CONFIG_CONTENT": '{"session":{"permissions":"autoaccept"}}',
                "OPENCODE_PTY_BIN": "/tmp/evil-pty",
                "OPENCODE_PTY_HANDOFF": "1",
                "OPENCODE_PTY_SOCKET_DIR": "/tmp/sock",
                "OPENCODE_DB": "/tmp/evil.db",
            }
            w_env = build_worker_environment(prof, isolated_home=wh, worker_id=wid, host_env=host_env)
            for v in (
                "OPENCODE_CLI_CONFIG_CONTENT",
                "OPENCODE_PTY_HANDOFF",
                "OPENCODE_PTY_SOCKET_DIR",
                "OPENCODE_DB",
            ):
                self.assertNotIn(v, w_env)
            self.assertEqual(w_env["OPENCODE_PTY_BIN"], str(wh.resolve() / ".config" / ".disabled-opencode-pty"))

            shell_txt = _build_worker_shell_script(prof, isolated_home=wh, worker_id=wid)
            for v in new_vars:
                self.assertIn(v, shell_txt)

            # Worker Seatbelt has zero cli.json carveout and denies exec on OPENCODE_PTY_BIN sentinel
            ws = Path(td) / "ws"
            ws.mkdir(mode=0o700)
            fake_oc = Path(td) / "oc"
            fake_oc.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(fake_oc, 0o700)
            fake_sb = Path(td) / "fake-sandbox-exec"
            fake_sb.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(fake_sb, 0o700)
            sb = compile_seatbelt_profile(
                prof,
                workspace_dir=ws,
                isolated_home=wh,
                opencode_bin=fake_oc,
                sandbox_exec_bin=fake_sb,
            )
            self.assertNotIn("cli\\.json", sb)
            for iv in _dual_realpath_variants(wh.resolve()):
                self.assertIn(f'(literal "{iv}/.config/.disabled-opencode-pty")', sb)

            # write_worker_runtime_artifacts locks .config and .config/opencode to 0500 (no cli.json)
            write_worker_runtime_artifacts(
                isolated_home=wh,
                worker_id=wid,
                profile=prof,
                opencode_config=compiled,
                seatbelt_text=sb,
            )
            self.assertEqual((wh / ".config").stat().st_mode & 0o777, 0o500)
            self.assertEqual((wh / ".config" / "opencode").stat().st_mode & 0o777, 0o500)
            self.assertFalse((wh / ".config" / "opencode" / "cli.json").exists())

    def test_smoke_detect_opencode_version_truthful_and_unknown_fallback(self) -> None:
        smoke = _load_smoke_module()
        with tempfile.TemporaryDirectory() as td:
            good_bin = Path(td) / "good-oc"
            good_bin.write_text("#!/bin/sh\necho '2.3.2'\n", encoding="utf-8")
            os.chmod(good_bin, 0o700)
            self.assertEqual(smoke.detect_opencode_version(str(good_bin)), "v2.3.2")

            bad_rc = Path(td) / "bad-rc"
            bad_rc.write_text("#!/bin/sh\necho '2.3.2'\nexit 1\n", encoding="utf-8")
            os.chmod(bad_rc, 0o700)
            self.assertEqual(smoke.detect_opencode_version(str(bad_rc)), "unknown")

            garbage = Path(td) / "garbage"
            garbage.write_text("#!/bin/sh\necho 'not-a-version'\n", encoding="utf-8")
            os.chmod(garbage, 0o700)
            self.assertEqual(smoke.detect_opencode_version(str(garbage)), "unknown")

            bad_utf8 = Path(td) / "bad-utf8"
            bad_utf8.write_text("#!/bin/sh\nprintf '\\377\\n'\n", encoding="utf-8")
            os.chmod(bad_utf8, 0o700)
            self.assertEqual(smoke.detect_opencode_version(str(bad_utf8)), "unknown")

            self.assertEqual(smoke.detect_opencode_version(str(Path(td) / "missing")), "unknown")

            # Symlink identity attribution: resolving once pins the exact binary across symlink swaps,
            # while an identity change (symlink repointed or binary replaced/unlinked) returns "unknown".
            v232 = Path(td) / "opencode-2.3.2"
            v232.write_text("#!/bin/sh\necho '2.3.2'\n", encoding="utf-8")
            os.chmod(v232, 0o700)
            v240 = Path(td) / "opencode-2.4.0"
            v240.write_text("#!/bin/sh\necho '2.4.0'\n", encoding="utf-8")
            os.chmod(v240, 0o700)
            link = Path(td) / "opencode"
            link.symlink_to(v232)

            resolved_path, pinned_id = smoke.resolve_opencode_binary(str(link))
            self.assertEqual(resolved_path, os.path.realpath(str(v232)))
            self.assertIsNotNone(pinned_id)

            # Simulate concurrent Homebrew symlink upgrade during smoke run
            link.unlink()
            link.symlink_to(v240)
            # Probing the resolved binary with pinned identity still attributes v2.3.2 accurately
            self.assertEqual(
                smoke.detect_opencode_version(resolved_path, expected_identity=pinned_id),
                "v2.3.2",
            )
            # Probing the moved symlink against the pinned identity refuses misattribution -> "unknown"
            self.assertEqual(
                smoke.detect_opencode_version(str(link), expected_identity=pinned_id),
                "unknown",
            )
            # Replacing the resolved binary in-place (new content/inode) invalidates identity -> "unknown"
            tmp_rep = Path(td) / "opencode-2.3.2.new"
            tmp_rep.write_text("#!/bin/sh\necho '2.9.9'\n", encoding="utf-8")
            os.chmod(tmp_rep, 0o700)
            os.replace(tmp_rep, v232)
            self.assertEqual(
                smoke.detect_opencode_version(resolved_path, expected_identity=pinned_id),
                "unknown",
            )

            # Smoke execution sequence with pinned_opencode_binary: even if the original path is
            # replaced with 2.9.9 AND restored back to 2.3.2 INSIDE the sampled callback, the pinned
            # binary actually executed for help, run, and --version stays bound to 2.3.2.
            v_orig = Path(td) / "opencode-orig"
            v_orig.write_text("#!/bin/sh\necho '2.3.2'\n", encoding="utf-8")
            os.chmod(v_orig, 0o700)
            v_backup = Path(td) / "opencode-orig.bak"
            os.link(v_orig, v_backup)

            with smoke.pinned_opencode_binary(str(v_orig)) as (pinned_exec, pinned_seq_id):
                self.assertIsNotNone(pinned_seq_id)
                self.assertNotEqual(os.path.realpath(pinned_exec), os.path.realpath(str(v_orig)))

                help_out, help_ok = smoke.run_identity_checked_command(
                    pinned_exec,
                    pinned_seq_id,
                    lambda: subprocess.run([pinned_exec, "--version"], capture_output=True, text=True, check=True).stdout.strip(),
                )
                self.assertTrue(help_ok)
                self.assertEqual(help_out, "2.3.2")

                def _swap_and_restore_inside_callback() -> str:
                    tmp_swap = Path(td) / "opencode-swap"
                    tmp_swap.write_text("#!/bin/sh\necho '2.9.9'\n", encoding="utf-8")
                    os.chmod(tmp_swap, 0o700)
                    os.replace(tmp_swap, v_orig)
                    # Execute the pinned executable while v_orig on disk is 2.9.9
                    actual_ran = subprocess.run(
                        [pinned_exec, "--version"], capture_output=True, text=True, check=True
                    ).stdout.strip()
                    # Restore v_orig back to original inode BEFORE callback returns
                    os.replace(v_backup, v_orig)
                    return actual_ran

                run_out, run_ok = smoke.run_identity_checked_command(
                    pinned_exec,
                    pinned_seq_id,
                    _swap_and_restore_inside_callback,
                )
                self.assertTrue(run_ok)
                # The executable actually launched during run was the pinned 2.3.2 snapshot, NOT 2.9.9
                self.assertEqual(run_out, "2.3.2")
                self.assertEqual(
                    smoke.resolve_smoke_observed_version(
                        pinned_exec,
                        pinned_seq_id,
                        identity_intact=bool(help_ok and run_ok),
                    ),
                    "v2.3.2",
                )

            # When pinning fails / identity cannot be bound (expected_identity=None), report "unknown"
            self.assertEqual(
                smoke.resolve_smoke_observed_version(str(v_orig), None, identity_intact=True),
                "unknown",
            )
            _, unpinned_ok = smoke.run_identity_checked_command(str(v_orig), None, lambda: {"returncode": 0})
            self.assertFalse(unpinned_ok)

            # Verify pinning works cleanly on the real macOS OpenCode 2.3.2 binary when installed
            if OPENCODE_BIN is not None:
                with smoke.pinned_opencode_binary(OPENCODE_BIN) as (real_pinned, real_pinned_id):
                    self.assertIsNotNone(real_pinned_id)
                    self.assertEqual(
                        smoke.resolve_smoke_observed_version(
                            real_pinned,
                            real_pinned_id,
                            identity_intact=True,
                        ),
                        f"v{TESTED_OPENCODE_VERSION}",
                    )

            # Unlinking the resolved binary -> "unknown"
            v232.unlink()
            self.assertEqual(
                smoke.detect_opencode_version(resolved_path, expected_identity=pinned_id),
                "unknown",
            )


@unittest.skipUnless(CAN_APPLY_SEATBELT, "macOS sandbox-exec capability required")
class OpenCode23LiveSeatbeltTests(unittest.TestCase):
    def test_interactive_seatbelt_cli_json_carveout_both_aliases_and_child_denial(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "ws"
            ws.mkdir(mode=0o700)
            iso_home = root / "home"
            for sub in (".local/share/opencode", ".cache/opencode", ".invocations"):
                (iso_home / sub).mkdir(parents=True, mode=0o700)
            inv_dir = iso_home / ".invocations" / "inv-test-seatbelt"
            for sub in (".config/opencode", ".state/opencode", ".tmp", "bin"):
                (inv_dir / sub).mkdir(parents=True, mode=0o700)
            svc = inv_dir / ".config" / "opencode" / "service.json"
            svc.write_text('{"hostname":"127.0.0.1","port":49111,"password":"secret"}\n', encoding="utf-8")
            os.chmod(svc, 0o400)
            cli = inv_dir / ".config" / "opencode" / "cli.json"
            cli.write_text('{"session":{"permissions":"prompt"}}\n', encoding="utf-8")
            os.chmod(cli, 0o600)
            os.chmod(inv_dir / ".config" / "opencode", 0o700)
            os.chmod(inv_dir / ".config", 0o500)

            import ctypes

            buf = ctypes.create_string_buffer(4096)
            rc_pidpath = ctypes.CDLL("/usr/lib/libSystem.B.dylib").proc_pidpath(
                os.getpid(), buf, 4096
            )
            py_bin = Path(buf.value.decode("utf-8")) if rc_pidpath > 0 and buf.value else Path(sys.executable).resolve()
            sb_text = compile_interactive_seatbelt_profile(
                workspace_dir=ws,
                isolated_home=iso_home,
                invocation_dir=inv_dir,
                opencode_bin=py_bin,
                service_port=49111,
            )
            sb_path = inv_dir / "interactive.sb"
            sb_path.write_text(sb_text, encoding="utf-8")
            os.chmod(sb_path, 0o400)

            inv_aliases = _dual_realpath_variants(inv_dir.resolve())
            self.assertGreaterEqual(len(inv_aliases), 1)

            probe = f"""
import errno, os, subprocess
aliases = {inv_aliases!r}
results = {{}}
for idx, base in enumerate(aliases):
    oc = base + "/.config/opencode"
    # 1. Atomic write cli.json.tmp -> rename cli.json MUST SUCCEED
    tmp = oc + "/cli.json.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write('{{"session":{{"permissions":"autoaccept"}}}}\\n')
    os.replace(tmp, oc + "/cli.json")
    results[f"cli_update_{{idx}}"] = "ok"

    # 2. Write service.json MUST FAIL
    for name, fn in (
        ("svc_write", lambda: open(oc + "/service.json", "w").write("x")),
        ("svc_unlink", lambda: os.unlink(oc + "/service.json")),
        ("svc_rename_over", lambda: os.replace(oc + "/cli.json", oc + "/service.json")),
        ("svc_hardlink", lambda: os.link(oc + "/service.json", oc + "/cli.json.tmp")),
        ("svc_chmod", lambda: os.chmod(oc + "/service.json", 0o600)),
        ("opencode_json", lambda: open(oc + "/opencode.json", "w").write("x")),
        ("plugins_create", lambda: open(oc + "/AGENTS.md", "w").write("x")),
        ("pty_sentinel_create", lambda: open(base + "/.config/.disabled-opencode-pty", "w").write("x")),
    ):
        try:
            fn()
            results[f"{{name}}_{{idx}}"] = "UNEXPECTED_ALLOW"
        except OSError as exc:
            results[f"{{name}}_{{idx}}"] = f"blocked:{{exc.errno}}"

# 3. Child shell process (process-path != opencode_real) must be denied read AND write on cli.json & service.json
child_read = subprocess.run(["/bin/cat", aliases[0] + "/.config/opencode/cli.json"], capture_output=True, text=True)
results["child_read_cli_rc"] = child_read.returncode
child_read_svc = subprocess.run(["/bin/cat", aliases[0] + "/.config/opencode/service.json"], capture_output=True, text=True)
results["child_read_svc_rc"] = child_read_svc.returncode
child_write = subprocess.run(["/bin/sh", "-c", f'echo x > "{{aliases[0]}}/.config/opencode/cli.json.tmp"'], capture_output=True, text=True)
results["child_write_cli_rc"] = child_write.returncode
import json
print(json.dumps(results))
"""
            res = subprocess.run(
                ["/usr/bin/sandbox-exec", "-f", str(sb_path), str(py_bin), "-c", probe],
                cwd=str(ws),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(res.returncode, 0, f"stdout={res.stdout}\nstderr={res.stderr}")
            out = json.loads(res.stdout.strip().splitlines()[-1])
            for idx in range(len(inv_aliases)):
                self.assertEqual(out[f"cli_update_{idx}"], "ok")
                for name in (
                    "svc_write",
                    "svc_unlink",
                    "svc_rename_over",
                    "svc_hardlink",
                    "svc_chmod",
                    "opencode_json",
                    "plugins_create",
                    "pty_sentinel_create",
                ):
                    self.assertTrue(
                        str(out[f"{name}_{idx}"]).startswith("blocked:"),
                        f"{name}_{idx} -> {out[f'{name}_{idx}']}",
                    )
            self.assertNotEqual(out["child_read_cli_rc"], 0)
            self.assertNotEqual(out["child_read_svc_rc"], 0)
            self.assertNotEqual(out["child_write_cli_rc"], 0)

            # 4. Interactive run profile (allow_opencode_self_exec=False) kernel-blocks
            # opencode_real from re-executing itself (preventing standalone --stdio fallback).
            sb_no_self_exec = compile_interactive_seatbelt_profile(
                workspace_dir=ws,
                isolated_home=iso_home,
                invocation_dir=inv_dir,
                opencode_bin=py_bin,
                service_port=49111,
                allow_opencode_self_exec=False,
            )
            sb_no_self_path = inv_dir / "interactive_run.sb"
            sb_no_self_path.write_text(sb_no_self_exec, encoding="utf-8")
            os.chmod(sb_no_self_path, 0o400)
            self_exec_probe = (
                f"import subprocess; r = subprocess.run([{str(py_bin)!r}, '-c', 'print(1)']); "
                "raise SystemExit(r.returncode)"
            )
            res_self_exec = subprocess.run(
                ["/usr/bin/sandbox-exec", "-f", str(sb_no_self_path), str(py_bin), "-c", self_exec_probe],
                cwd=str(ws),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertNotEqual(res_self_exec.returncode, 0)
            os.chmod(inv_dir / ".config", 0o700)

    @unittest.skipUnless(OPENCODE_BIN is not None, "opencode binary required")
    def test_live_opencode_2_3_2_pty_fallback_and_hard_denial_in_interactive_and_worker_modes(self) -> None:
        assert OPENCODE_BIN is not None
        self.assertEqual(
            verify_opencode_version(OPENCODE_BIN, allow_version_drift=False),
            TESTED_OPENCODE_VERSION,
        )

        # Shared mock OpenAI chat server driving tool calls in two phases (interactive + worker).
        state_lock = threading.Lock()
        state: dict[str, Any] = {"mode": "interactive", "turn": 0, "tool_outputs": []}

        class _MockHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                if self.path.rstrip("/") == "/v1/models":
                    body = json.dumps(
                        {"object": "list", "data": [{"id": "mock-model", "object": "model"}]}
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                req = json.loads(raw.decode("utf-8"))
                msgs = req.get("messages") or []
                has_tools = bool(req.get("tools"))
                if not has_tools:
                    # Background title/summary requests carry no tools; respond cleanly without advancing turn state.
                    msg_out: dict[str, Any] = {"role": "assistant", "content": "Mock Session"}
                    finish = "stop"
                    turn_id = "title"
                else:
                    with state_lock:
                        for m in msgs:
                            if isinstance(m, dict) and m.get("role") == "tool":
                                state["tool_outputs"].append(str(m.get("content") or ""))
                        turn = state["turn"]
                        state["turn"] += 1
                        mode = state["mode"]
                    turn_id = str(turn)
                    if mode == "interactive":
                        if turn == 0:
                            msg_out = {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [
                                    {
                                        "id": "call_shell_int",
                                        "type": "function",
                                        "function": {
                                            "name": "shell",
                                            "arguments": json.dumps(
                                                {
                                                    "command": "echo PTY_FALLBACK_INTERACTIVE_OK",
                                                    "description": "test shell fallback",
                                                }
                                            ),
                                        },
                                    },
                                    {
                                        "id": "call_webfetch_int",
                                        "type": "function",
                                        "function": {
                                            "name": "webfetch",
                                            "arguments": json.dumps(
                                                {"url": "https://example.com", "format": "text"}
                                            ),
                                        },
                                    },
                                    {
                                        "id": "call_browser_int",
                                        "type": "function",
                                        "function": {
                                            "name": "browser",
                                            "arguments": json.dumps({"url": "https://example.com"}),
                                        },
                                    },
                                    {
                                        "id": "call_execute_int",
                                        "type": "function",
                                        "function": {
                                            "name": "execute",
                                            "arguments": json.dumps({"code": "console.log(1)"}),
                                        },
                                    },
                                ],
                            }
                            finish = "tool_calls"
                        else:
                            msg_out = {"role": "assistant", "content": "INTERACTIVE_232_OK"}
                            finish = "stop"
                    else:
                        if turn == 0:
                            msg_out = {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [
                                    {
                                        "id": "call_shell_wrk",
                                        "type": "function",
                                        "function": {
                                            "name": "shell",
                                            "arguments": json.dumps(
                                                {
                                                    "command": "echo PTY_FALLBACK_WORKER_OK PTY_VAR=${OPENCODE_PTY_BIN:-UNSET}",
                                                    "description": "test worker shell fallback",
                                                }
                                            ),
                                        },
                                    }
                                ],
                            }
                            finish = "tool_calls"
                        else:
                            msg_out = {"role": "assistant", "content": "WORKER_232_OK"}
                            finish = "stop"

                if req.get("stream"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                    self.end_headers()
                    delta: dict[str, Any] = {"role": "assistant"}
                    if msg_out.get("content") is not None:
                        delta["content"] = msg_out["content"]
                    if msg_out.get("tool_calls"):
                        delta["tool_calls"] = [
                            {
                                "index": idx,
                                "id": tc["id"],
                                "type": "function",
                                "function": tc["function"],
                            }
                            for idx, tc in enumerate(msg_out["tool_calls"])
                        ]
                    c1 = {
                        "id": f"chatcmpl-{turn_id}",
                        "object": "chat.completion.chunk",
                        "created": int(time.time()),
                        "model": "mock-model",
                        "choices": [{"index": 0, "delta": delta, "finish_reason": None}],
                    }
                    c2 = {
                        "id": f"chatcmpl-{turn_id}",
                        "object": "chat.completion.chunk",
                        "created": int(time.time()),
                        "model": "mock-model",
                        "choices": [{"index": 0, "delta": {}, "finish_reason": finish}],
                    }
                    self.wfile.write(f"data: {json.dumps(c1)}\n\n".encode("utf-8"))
                    self.wfile.write(f"data: {json.dumps(c2)}\n\n".encode("utf-8"))
                    self.wfile.write(b"data: [DONE]\n\n")
                    self.wfile.flush()
                    return

                body = json.dumps(
                    {
                        "id": f"chatcmpl-{turn_id}",
                        "object": "chat.completion",
                        "created": int(time.time()),
                        "model": "mock-model",
                        "choices": [{"index": 0, "message": msg_out, "finish_reason": finish}],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        class _TCPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
            allow_reuse_address = True
            daemon_threads = True

        server = _TCPServer(("127.0.0.1", 0), _MockHandler)
        port = server.server_address[1]
        srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
        srv_thread.start()

        try:
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                ws = root / "ws"
                ws.mkdir(mode=0o700)

                # --- Part A: Interactive Seatbelt mode with cli.json autoaccept + --auto ---
                iso_home = root / "int_home"
                (iso_home / ".config" / "opencode").mkdir(parents=True, mode=0o700)
                (iso_home / ".config" / "opencode" / "cli.json").write_text(
                    json.dumps(
                        {
                            "$schema": "https://opencode.ai/v2/cli.json",
                            "session": {"permissions": "autoaccept"},
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                int_cfg = {
                    "autoupdate": False,
                    "share": "disabled",
                    "snapshot": False,
                    "lsp": False,
                    "formatter": False,
                    "plugins": [],
                    "enabled_providers": ["private-attested"],
                    "model": "private-attested/mock-model",
                    "small_model": "private-attested/mock-model",
                    "provider": {
                        "private-attested": {
                            "name": "Mock",
                            "npm": "@opencode/ai/providers/openai-compatible",
                            "options": {
                                "baseURL": f"http://127.0.0.1:{port}/v1",
                                "apiKey": "dummy",
                                "timeout": 30000,
                            },
                            "models": {
                                "mock-model": {
                                    "id": "mock-model",
                                    "name": "mock-model",
                                    "tool_call": True,
                                    "modalities": {"input": ["text"], "output": ["text"]},
                                    "limit": {"context": 32768, "output": 2048},
                                }
                            },
                        }
                    },
                    "tools": {
                        "read": True,
                        "bash": True,
                        "webfetch": False,
                        "websearch": False,
                        "browser": False,
                        "execute": False,
                    },
                    "permission": {
                        "*": "ask",
                        "read": "allow",
                        "bash": "allow",
                        "webfetch": "deny",
                        "websearch": "deny",
                        "browser": "deny",
                        "execute": "deny",
                    },
                }
                ep = _dummy_endpoint(port=port)

                t0 = time.monotonic()
                rc_int = publish_and_run_opencode(
                    opencode_bin=OPENCODE_BIN,
                    opencode_args=["run", "--auto", "--format", "json", "probe"],
                    caller_cwd=ws,
                    isolated_home=iso_home,
                    endpoint=ep,
                    config_text=json.dumps(int_cfg),
                    build_env_fn=lambda _p: {
                        "PATH": "/opt/homebrew/bin:/usr/bin:/bin",
                        "HOME": str(iso_home),
                        "OPENCODE_TEST_HOME": str(iso_home),
                    },
                    current_sync={},
                    endpoint_port=port,
                )
                elapsed_int = time.monotonic() - t0
                self.assertEqual(rc_int, 0)
                # Must finish well under the 5-second PTY daemon polling timeout.
                self.assertLess(elapsed_int, 4.9)
                joined_int = "\n".join(state["tool_outputs"])
                self.assertIn("PTY_FALLBACK_INTERACTIVE_OK", joined_int)
                # Hard denials on webfetch, browser, and execute must produce explicit denial errors
                # even under session.permissions=autoaccept + --auto.
                self.assertNotIn("Example Domain", joined_int)
                for denied_tool in ("webfetch", "browser", "execute"):
                    self.assertTrue(
                        any(
                            denied_tool in out
                            and any(
                                marker in out.lower()
                                for marker in ("no tool named", "denied", "not available", "blocked", "permission")
                            )
                            for out in state["tool_outputs"]
                        ),
                        f"expected explicit denial for {denied_tool} in {state['tool_outputs']}",
                    )
                # Direct observation: no opencode-pty binary extracted, no retry in fresh runtime dir,
                # and direct fallback used instead of PTY daemon.
                self.assertFalse((iso_home / ".cache" / "opencode" / "bin" / "opencode-pty").exists())
                int_log_path = iso_home / ".local" / "share" / "opencode" / "log" / "opencode.log"
                self.assertTrue(int_log_path.is_file(), f"missing interactive opencode.log at {int_log_path}")
                int_log = int_log_path.read_text(encoding="utf-8", errors="replace")
                self.assertNotIn("Starting opencode-pty in a fresh runtime directory", int_log)
                self.assertIn("process daemon unavailable; spawning shell command instead", int_log)

                # --- Part B: Unattended worker Seatbelt mode ---
                with state_lock:
                    state["mode"] = "worker"
                    state["turn"] = 0
                    state["tool_outputs"] = []

                wid, wh = allocate_worker_home(worker_homes_dir=root / "workers")
                prof = default_unattended_worker_profile()
                compiled_cfg = compile_opencode_security_config(
                    int_cfg, prof, isolated_home=wh, workspace_dir=ws
                )
                sb_text = compile_seatbelt_profile(
                    prof,
                    workspace_dir=ws,
                    isolated_home=wh,
                    opencode_bin=Path(OPENCODE_BIN),
                    use_token_relay=False,
                )
                _, sb_path, _ = write_worker_runtime_artifacts(
                    isolated_home=wh,
                    worker_id=wid,
                    profile=prof,
                    opencode_config=compiled_cfg,
                    seatbelt_text=sb_text,
                )
                w_env = build_worker_environment(prof, isolated_home=wh, worker_id=wid)
                validated = validate_worker_opencode_args(["run", "--format", "json", "probe"])

                t1 = time.monotonic()
                proc_w = subprocess.run(
                    ["/usr/bin/sandbox-exec", "-f", str(sb_path), OPENCODE_BIN, *validated],
                    cwd=str(ws),
                    env=w_env,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                elapsed_w = time.monotonic() - t1
                self.assertEqual(proc_w.returncode, 0, f"stdout={proc_w.stdout}\nstderr={proc_w.stderr}")
                self.assertIn("WORKER_232_OK", proc_w.stdout)
                self.assertLess(elapsed_w, 4.9)
                # Direct observation of shell tool duration (< 2000ms) in JSON events
                shell_events = [
                    json.loads(line)
                    for line in proc_w.stdout.splitlines()
                    if line.strip().startswith("{") and '"tool":"shell"' in line
                ]
                self.assertTrue(shell_events, f"missing shell JSON event in {proc_w.stdout}")
                t_info = shell_events[0].get("part", {}).get("state", {}).get("time", {})
                start_ts = t_info.get("start")
                end_ts = t_info.get("end")
                self.assertIsInstance(start_ts, (int, float), f"missing numeric start timestamp in {t_info}")
                self.assertIsInstance(end_ts, (int, float), f"missing numeric end timestamp in {t_info}")
                self.assertNotIsInstance(start_ts, bool)
                self.assertNotIsInstance(end_ts, bool)
                self.assertGreaterEqual(end_ts, start_ts, f"unordered shell timestamps in {t_info}")
                self.assertLess(end_ts - start_ts, 2000, f"shell duration exceeded 2000ms in {t_info}")
                joined_w = "\n".join(state["tool_outputs"])
                self.assertIn("PTY_FALLBACK_WORKER_OK", joined_w)
                self.assertIn("PTY_VAR=UNSET", joined_w)
                self.assertFalse((wh / ".cache" / "opencode" / "bin" / "opencode-pty").exists())
                self.assertFalse((wh / ".local" / "state" / "opencode" / "pty").exists())
                w_log_path = wh / ".local" / "share" / "opencode" / "log" / "opencode.log"
                self.assertTrue(w_log_path.is_file(), f"missing worker opencode.log at {w_log_path}")
                w_log = w_log_path.read_text(encoding="utf-8", errors="replace")
                self.assertNotIn("Starting opencode-pty in a fresh runtime directory", w_log)
                self.assertIn("process daemon unavailable; spawning shell command instead", w_log)
        finally:
            server.shutdown()
            server.server_close()

    @unittest.skipUnless(OPENCODE_BIN is not None, "opencode binary required")
    def test_real_opencode_2_3_2_tui_cli_json_atomic_write_and_persistence(self) -> None:
        """Prove the real OpenCode 2.3.2 binary writes cli.json inside Seatbelt and persists back."""
        import pty
        import select
        import signal

        assert OPENCODE_BIN is not None
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "ws"
            ws.mkdir(mode=0o700)
            iso = root / "home"
            (iso / ".config" / "opencode").mkdir(parents=True, mode=0o700)
            cli_p = iso / ".config" / "opencode" / "cli.json"
            cli_p.write_text(
                json.dumps(
                    {
                        "$schema": "https://opencode.ai/v2/cli.json",
                        "keybinds": {"app_exit": "ctrl+q"},
                        "session": {"permissions": "autoaccept"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            master_fd, slave_fd = pty.openpty()
            driver = f"""
import json, sys
from pathlib import Path
sys.path.insert(0, {str(ROOT)!r})
from local_assist.launch import publish_and_run_opencode
from local_assist.registry import EndpointConfig
ep = EndpointConfig(
    model_id="m", served_model_id="m", provider_id="tinfoil",
    api_base_url="http://127.0.0.1:8081/v1", host="127.0.0.1", port=8081,
    api_key="dummy", api_key_envar=None, runtime="tinfoil_proxy",
    trust_tier="enclave_runtime_attested", attestation_method="tinfoil_proxy",
    is_local_host=True,
)
rc = publish_and_run_opencode(
    opencode_bin={str(OPENCODE_BIN)!r},
    opencode_args=["mini"],
    caller_cwd=Path({str(ws)!r}),
    isolated_home=Path({str(iso)!r}),
    endpoint=ep,
    config_text=json.dumps({{"autoupdate": False, "share": "disabled"}}),
    build_env_fn=lambda _p: {{
        "PATH": "/opt/homebrew/bin:/usr/bin:/bin",
        "TERM": "xterm-256color",
        "HOME": {str(iso)!r},
        "OPENCODE_TEST_HOME": {str(iso)!r},
    }},
    current_sync={{}},
)
raise SystemExit(rc)
"""
            proc = subprocess.Popen(
                [sys.executable, "-c", driver],
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )
            os.close(slave_fd)
            try:
                deadline = time.monotonic() + 3.0
                sent_exit = False
                while proc.poll() is None and time.monotonic() < deadline + 10.0:
                    r_ready, _, _ = select.select([master_fd], [], [], 0.1)
                    if r_ready:
                        try:
                            os.read(master_fd, 4096)
                        except OSError:
                            break
                    if not sent_exit and time.monotonic() >= deadline:
                        sent_exit = True
                        try:
                            os.write(master_fd, b"\x11")
                        except OSError:
                            pass
                        time.sleep(0.3)
                        if proc.poll() is None:
                            proc.send_signal(signal.SIGTERM)
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=5)
            finally:
                try:
                    os.close(master_fd)
                except OSError:
                    pass

            persisted = json.loads(cli_p.read_text(encoding="utf-8"))
            self.assertEqual(persisted.get("keybinds", {}).get("app.exit"), "ctrl+q")
            self.assertNotIn("app_exit", persisted.get("keybinds", {}))
            self.assertEqual(persisted.get("session", {}).get("permissions"), "autoaccept")
            self.assertEqual(cli_p.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
