from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from local_assist.client import DEFAULT_TIMEOUT_SECONDS, default_timeout_seconds, normalize_text
from local_assist.logging import summarize_args
from local_assist.tools.compress_context import (
    extract_diff_files,
    parse_and_validate as parse_compress_context,
    validate_inputs as validate_compress_inputs,
)
from local_assist.tools.delegate_task import (
    compute_ungrounded_identifiers,
    parse_and_validate as parse_delegate_task,
    stable_id as stable_delegate_id,
    validate_inputs as validate_delegate_inputs,
)
from local_assist.tools.extract_fields import (
    parse_and_validate as parse_extract_fields,
    validate_field_specs,
)
from local_assist.tools.propose_eval_prompts import (
    parse_and_validate as parse_eval_prompts,
    stable_id as stable_eval_prompt_id,
)


class LocalAssistTests(unittest.TestCase):
    def test_default_timeout_seconds_reads_env_override(self) -> None:
        import os
        saved = os.environ.pop("LOCAL_ASSIST_TIMEOUT_SECONDS", None)
        try:
            self.assertEqual(default_timeout_seconds(), DEFAULT_TIMEOUT_SECONDS)
            os.environ["LOCAL_ASSIST_TIMEOUT_SECONDS"] = "240"
            self.assertEqual(default_timeout_seconds(), 240)
            os.environ["LOCAL_ASSIST_TIMEOUT_SECONDS"] = "not-a-number"
            self.assertEqual(default_timeout_seconds(), DEFAULT_TIMEOUT_SECONDS)
            os.environ["LOCAL_ASSIST_TIMEOUT_SECONDS"] = "0"
            self.assertEqual(default_timeout_seconds(), 1)
        finally:
            if saved is not None:
                os.environ["LOCAL_ASSIST_TIMEOUT_SECONDS"] = saved
            else:
                os.environ.pop("LOCAL_ASSIST_TIMEOUT_SECONDS", None)

    def test_normalize_text_strips_known_artifacts(self) -> None:
        self.assertEqual(normalize_text("```json\n{\"a\":1}\n```"), '{"a":1}')
        self.assertEqual(normalize_text("<think>hidden</think>{\"a\":1}<|im_end|>"), '{"a":1}')

    def test_eval_prompt_parse_and_validate_computes_stable_ids(self) -> None:
        prompt_text = "Return only a JSON array of three integers. No prose, no markdown."
        assertion = "return output.trim().startsWith('[') && /^\\[[\\s\\d,]+\\]$/.test(output.trim());"
        result = parse_eval_prompts(
            json.dumps(
                {
                    "prompts": [
                        {
                            "prompt": prompt_text,
                            "expected_signal": "Strict raw JSON array output.",
                            "assertion": assertion,
                            "category": "structured_output",
                        }
                    ],
                    "coverage_note": None,
                }
            )
        )
        candidate = result["prompts"][0]
        self.assertEqual(candidate["id"], stable_eval_prompt_id(prompt_text))
        self.assertEqual(candidate["assertion"], assertion)

        suite = {
            "description": "generated candidate suite",
            "prompts": ["{{prompt}}"],
            "tests": [
                {
                    "description": f"candidate-{candidate['id']}",
                    "vars": {"prompt": candidate["prompt"]},
                    "assert": [{"type": "javascript", "value": candidate["assertion"]}],
                }
            ],
        }
        self.assertEqual(json.loads(json.dumps(suite)), suite)

    def test_extract_fields_parse_and_validate(self) -> None:
        fields = validate_field_specs(
            "Build 482 finished in 12.3 seconds. Logs: a.txt, b.txt.",
            {
                "build_id": {"type": "integer", "description": "Build number.", "required": True},
                "duration_seconds": {"type": "number", "description": "Total time."},
                "log_files": {"type": "string_list", "description": "Referenced log files."},
                "failed": {"type": "boolean", "description": "Whether the build failed."},
            },
        )
        result = parse_extract_fields(
            json.dumps(
                {
                    "extracted": {
                        "build_id": 482,
                        "duration_seconds": 12.3,
                        "log_files": ["a.txt", "b.txt"],
                        "failed": None,
                    },
                    "extraction_note": None,
                }
            ),
            fields,
        )
        self.assertEqual(result["extracted"]["build_id"], 482)
        self.assertEqual(result["extracted"]["log_files"], ["a.txt", "b.txt"])
        self.assertIsNone(result["extracted"]["failed"])
        self.assertEqual(result["missing_required"], [])

    def test_extract_fields_flags_missing_required(self) -> None:
        fields = validate_field_specs(
            "Some text without a build id.",
            {"build_id": {"type": "integer", "description": "Build number.", "required": True}},
        )
        result = parse_extract_fields(
            json.dumps({"extracted": {"build_id": None}, "extraction_note": None}),
            fields,
        )
        self.assertEqual(result["missing_required"], ["build_id"])

    def test_extract_fields_rejects_unexpected_keys(self) -> None:
        fields = validate_field_specs(
            "x",
            {"a": {"type": "string", "description": "first"}},
        )
        with self.assertRaises(Exception):
            parse_extract_fields(
                json.dumps({"extracted": {"a": "ok", "b": "extra"}, "extraction_note": None}),
                fields,
            )

    def test_extract_fields_rejects_unexpected_top_level_keys(self) -> None:
        fields = validate_field_specs(
            "x",
            {"a": {"type": "string", "description": "first"}},
        )
        with self.assertRaises(Exception):
            parse_extract_fields(
                json.dumps(
                    {"extracted": {"a": "ok"}, "extraction_note": None, "rationale": "extra"}
                ),
                fields,
            )

    def test_extract_fields_rejects_null_string_list(self) -> None:
        fields = validate_field_specs(
            "x",
            {"items": {"type": "string_list", "description": "items"}},
        )
        with self.assertRaises(Exception):
            parse_extract_fields(
                json.dumps({"extracted": {"items": None}, "extraction_note": None}),
                fields,
            )

    def test_extract_fields_rejects_non_string_text(self) -> None:
        with self.assertRaises(Exception):
            validate_field_specs(None, {"a": {"type": "string", "description": "first"}})
        with self.assertRaises(Exception):
            validate_field_specs(
                {"not": "a string"}, {"a": {"type": "string", "description": "first"}}
            )

    def test_extract_fields_rejects_type_mismatch(self) -> None:
        fields = validate_field_specs(
            "x",
            {"count": {"type": "integer", "description": "a count"}},
        )
        with self.assertRaises(Exception):
            parse_extract_fields(
                json.dumps({"extracted": {"count": "not a number"}, "extraction_note": None}),
                fields,
            )

    def test_extract_diff_files_parses_headers(self) -> None:
        diff = (
            "diff --git a/src/foo.py b/src/foo.py\n"
            "--- a/src/foo.py\n"
            "+++ b/src/foo.py\n"
            "@@ -1 +1 @@\n-old\n+new\n"
            "diff --git a/old_name.py b/new_name.py\n"
            "rename from old_name.py\n"
            "rename to new_name.py\n"
            "diff --git a/dropped.py b/dropped.py\n"
            "deleted file mode 100644\n"
            "--- a/dropped.py\n"
            "+++ /dev/null\n"
        )
        paths = extract_diff_files(diff)
        self.assertIn("src/foo.py", paths)
        self.assertIn("old_name.py", paths)
        self.assertIn("new_name.py", paths)
        self.assertIn("dropped.py", paths)
        self.assertNotIn("/dev/null", paths)

    def test_compress_context_rejects_invented_changed_file(self) -> None:
        diff = (
            "diff --git a/real.py b/real.py\n--- a/real.py\n+++ b/real.py\n@@ -1 +1 @@\n-a\n+b\n"
        )
        validated = validate_compress_inputs("diff", diff, None, 5)
        model_output = {
            "summary": "Edited real.py.",
            "key_points": [],
            "changed_files": ["real.py", "fictional.py"],
            "failures": [],
            "risks": [],
            "commands": [],
            "followups": [],
            "omitted": [],
        }
        with self.assertRaises(Exception):
            parse_compress_context(json.dumps(model_output), validated)

    def test_compress_context_accepts_well_formed_output(self) -> None:
        diff = (
            "diff --git a/real.py b/real.py\n--- a/real.py\n+++ b/real.py\n@@ -1 +1 @@\n-a\n+b\n"
        )
        validated = validate_compress_inputs("diff", diff, None, 5)
        model_output = {
            "summary": "Edited real.py.",
            "key_points": ["replaced a with b"],
            "changed_files": ["real.py"],
            "failures": [],
            "risks": [],
            "commands": [],
            "followups": [],
            "omitted": ["raw diff bodies"],
        }
        result = parse_compress_context(json.dumps(model_output), validated)
        self.assertEqual(result["changed_files"], ["real.py"])
        self.assertEqual(result["summary"], "Edited real.py.")

    def test_compress_context_rejects_missing_top_level_key(self) -> None:
        validated = validate_compress_inputs("logs", "anything", None, 5)
        model_output = {
            "summary": "ok",
            "key_points": [],
            "changed_files": [],
            "failures": [],
            "risks": [],
            "commands": [],
            "followups": [],
        }
        with self.assertRaises(Exception):
            parse_compress_context(json.dumps(model_output), validated)

    def test_compress_context_rejects_oversize_list(self) -> None:
        validated = validate_compress_inputs("logs", "anything", None, 2)
        model_output = {
            "summary": "ok",
            "key_points": ["a", "b", "c"],
            "changed_files": [],
            "failures": [],
            "risks": [],
            "commands": [],
            "followups": [],
            "omitted": [],
        }
        with self.assertRaises(Exception):
            parse_compress_context(json.dumps(model_output), validated)

    def test_compress_context_rejects_invalid_kind(self) -> None:
        with self.assertRaises(Exception):
            validate_compress_inputs("transcript", "some text", None, 5)

    def test_delegate_task_validation_and_ungrounded_identifiers(self) -> None:
        import os
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside_tmp:
            ws_root = Path(tmp).resolve()
            outside_root = Path(outside_tmp).resolve()
            ctx_file = ws_root / "sample.py"
            ctx_file.write_text("import os\ndef known_helper(input_value: int) -> int:\n    return input_value + 1\n")
            outside_file = outside_root / "secret.txt"
            outside_file.write_text("outside workspace secret")

            saved_ws = os.environ.get("LOCAL_ASSIST_WORKSPACE_ROOT")
            os.environ["LOCAL_ASSIST_WORKSPACE_ROOT"] = str(ws_root)
            try:
                validated = validate_delegate_inputs(
                    "draft_code",
                    "Write a wrapper around known_helper.",
                    None,
                    "sample.py",
                    ["Use type hints."],
                    1024,
                )
                self.assertEqual(validated["kind"], "draft_code")
                self.assertEqual(validated["max_tokens"], 1024)
                self.assertIn("known_helper", validated["context"])
                self.assertEqual(validated["constraints"], ["Use type hints."])

                # V3: Absolute path outside LOCAL_ASSIST_WORKSPACE_ROOT is rejected
                with self.assertRaises(Exception):
                    validate_delegate_inputs(
                        "focused_qa",
                        "Read outside file.",
                        None,
                        str(outside_file),
                        None,
                        512,
                    )

                # V3: Symlink inside workspace pointing outside is rejected
                sym_file = ws_root / "link.txt"
                sym_file.symlink_to(outside_file)
                with self.assertRaises(Exception):
                    validate_delegate_inputs(
                        "focused_qa",
                        "Read symlink.",
                        None,
                        "link.txt",
                        None,
                        512,
                    )

                # V3: Non-UTF8 binary file raises ModelOutputMalformed (invalid_arguments)
                bad_utf8 = ws_root / "binary.bin"
                bad_utf8.write_bytes(b"\xff\xfe\x00\x80invalid")
                with self.assertRaises(Exception):
                    validate_delegate_inputs(
                        "focused_qa",
                        "Read binary.",
                        None,
                        "binary.bin",
                        None,
                        512,
                    )

                # V3: Oversized file (> 128000 bytes) is rejected by stat() before read
                huge_file = ws_root / "huge.txt"
                huge_file.write_bytes(b"a" * 130_000)
                with self.assertRaises(Exception):
                    validate_delegate_inputs(
                        "focused_qa",
                        "Read huge file.",
                        None,
                        "huge.txt",
                        None,
                        512,
                    )

                # Providing both context and context_path is rejected
                with self.assertRaises(Exception):
                    validate_delegate_inputs(
                        "draft_code",
                        "Write a wrapper.",
                        "inline context",
                        str(ctx_file),
                        None,
                        1024,
                    )
            finally:
                if saved_ws is not None:
                    os.environ["LOCAL_ASSIST_WORKSPACE_ROOT"] = saved_ws
                else:
                    os.environ.pop("LOCAL_ASSIST_WORKSPACE_ROOT", None)

            parsed = parse_delegate_task(
                json.dumps(
                    {
                        "output": (
                            "import os\n"
                            "import mystery_pkg\n"
                            "def newly_drafted_wrapper(x):\n"
                            "    # Reference: https://unverified.example/spec by Dr. Invented Author\n"
                            "    return mystery_pkg.call(x)\n"
                        ),
                        "summary": "Wraps known_helper.",
                        "assumptions": ["x is an int"],
                        "unverified_claims": [],
                    }
                ),
                validated,
            )
            self.assertEqual(parsed["id"], stable_delegate_id(parsed["output"]))
            self.assertEqual(parsed["kind"], "draft_code")
            self.assertIn("mystery_pkg", parsed["ungrounded_identifiers"])
            self.assertIn("https://unverified.example/spec", parsed["ungrounded_identifiers"])
            self.assertIn("Dr. Invented Author", parsed["ungrounded_identifiers"])
            self.assertNotIn("os", parsed["ungrounded_identifiers"])
            self.assertNotIn("newly_drafted_wrapper", parsed["ungrounded_identifiers"])

            # V4: Whole-token grounding checks (short module names and '<pkg>-free' phrasing)
            self.assertEqual(
                compute_ungrounded_identifiers(
                    "import os\nimport re\nimport requests\n",
                    "Compute the positions and return results",
                ),
                ["os", "re", "requests"],
            )
            self.assertEqual(
                compute_ungrounded_identifiers(
                    "from numpy import clip\n",
                    "use numpy-free code",
                ),
                ["numpy"],
            )

            # Path traversal in context_path is rejected
            with self.assertRaises(Exception):
                validate_delegate_inputs(
                    "focused_qa",
                    "Summarize file.",
                    None,
                    "../outside.txt",
                    512,
                )

            # Invalid kind or out-of-range max_tokens is rejected
            with self.assertRaises(Exception):
                validate_delegate_inputs("unknown_kind", "hi", None, None, 512)
            with self.assertRaises(Exception):
                validate_delegate_inputs("focused_qa", "hi", None, None, 9999)

            # summarize_args redacts raw context and logs char counts + sha256
            summary = summarize_args(
                {
                    "kind": "focused_qa",
                    "instruction": "Explain this.",
                    "context": "super-secret-inline-context",
                    "context_path": str(ctx_file),
                }
            )
            self.assertEqual(summary["instruction_chars"], len("Explain this."))
            self.assertEqual(summary["context_chars"], len("super-secret-inline-context"))
            self.assertIsNotNone(summary["context_sha256"])
            self.assertNotIn("super-secret-inline-context", json.dumps(summary))

    def test_compress_context_and_extract_fields_redact_prompt_in_logs(self) -> None:
        import hashlib
        import tempfile
        from unittest.mock import patch
        import local_assist.logging as log_mod
        from local_assist.client import ChatResult
        from local_assist.tools import compress_context as cc_mod
        from local_assist.tools import extract_fields as ef_mod

        secret_diff = (
            "diff --git a/secret.py b/secret.py\n"
            "--- a/secret.py\n"
            "+++ b/secret.py\n"
            "@@ -1 +1 @@\n"
            "-PRIVATE_TOKEN_OLD_999\n"
            "+PRIVATE_TOKEN_NEW_888\n"
        )
        secret_text = "Confidential invoice #7721 for Project Chimera amount 42000"

        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            la_runs = tmp_root / "runs" / "local-assist"
            with (
                patch.object(log_mod, "ROOT", tmp_root),
                patch.object(log_mod, "LOCAL_ASSIST_RUNS", la_runs),
            ):
                with (
                    patch.object(cc_mod, "require_chat_succeeds"),
                    patch.object(
                        cc_mod,
                        "chat",
                        return_value=ChatResult(
                            raw_text="{}",
                            text=json.dumps(
                                {
                                    "summary": "Updated secret.py.",
                                    "key_points": ["rotated token"],
                                    "changed_files": ["secret.py"],
                                    "failures": [],
                                    "risks": [],
                                    "commands": [],
                                    "followups": [],
                                    "omitted": [],
                                }
                            ),
                            served_model="mock-local",
                            usage={"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
                            latency_ms=12,
                            finish_reason="stop",
                        ),
                    ),
                ):
                    cc_res = cc_mod.run("diff", secret_diff, "token rotation", 5)
                    self.assertEqual(cc_res["changed_files"], ["secret.py"])

                with (
                    patch.object(ef_mod, "require_chat_succeeds"),
                    patch.object(
                        ef_mod,
                        "chat",
                        return_value=ChatResult(
                            raw_text="{}",
                            text=json.dumps(
                                {
                                    "extracted": {"amount": 42000},
                                    "extraction_note": None,
                                }
                            ),
                            served_model="mock-local",
                            usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                            latency_ms=10,
                            finish_reason="stop",
                        ),
                    ),
                ):
                    ef_res = ef_mod.run(
                        secret_text,
                        {"amount": {"type": "integer", "description": "Invoice amount", "required": True}},
                    )
                    self.assertEqual(ef_res["extracted"]["amount"], 42000)

                log_files = sorted(la_runs.rglob("*.json"))
                self.assertEqual(len(log_files), 2)
                by_tool = {
                    json.loads(p.read_text(encoding="utf-8"))["tool"]: json.loads(p.read_text(encoding="utf-8"))
                    for p in log_files
                }

                cc_log = by_tool["compress_context"]
                self.assertNotIn("prompt", cc_log)
                self.assertIn("prompt_redacted", cc_log)
                self.assertGreater(cc_log["prompt_redacted"]["chars"], len(secret_diff))
                self.assertNotIn("text", cc_log["args"])
                self.assertEqual(cc_log["args"]["text_chars"], len(secret_diff))
                self.assertEqual(
                    cc_log["args"]["text_sha256"],
                    hashlib.sha256(secret_diff.encode("utf-8")).hexdigest(),
                )
                self.assertNotIn("PRIVATE_TOKEN_OLD_999", json.dumps(cc_log))

                ef_log = by_tool["extract_fields"]
                self.assertNotIn("prompt", ef_log)
                self.assertIn("prompt_redacted", ef_log)
                self.assertGreater(ef_log["prompt_redacted"]["chars"], len(secret_text))
                self.assertNotIn("text", ef_log["args"])
                self.assertEqual(ef_log["args"]["text_chars"], len(secret_text))
                self.assertEqual(
                    ef_log["args"]["text_sha256"],
                    hashlib.sha256(secret_text.encode("utf-8")).hexdigest(),
                )
                self.assertNotIn("Project Chimera", json.dumps(ef_log))

    def test_mcp_initialize_and_tools_list(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            env = self._build_isolated_cli_probe_env(Path(td))
            proc = subprocess.Popen(
                ["scripts/local-assist-server"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            assert proc.stdin is not None
            assert proc.stdout is not None

            try:
                self._send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
                init = self._recv(proc)
                self.assertEqual(init["result"]["serverInfo"]["name"], "local-assist-server")

                self._send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
                tools = self._recv(proc)
                names = [tool["name"] for tool in tools["result"]["tools"]]
                self.assertEqual(
                    names,
                    [
                        "propose_eval_prompts",
                        "extract_fields",
                        "compress_context",
                        "delegate_task",
                    ],
                )
            finally:
                proc.terminate()
                proc.wait(timeout=5)
                if proc.stdin:
                    proc.stdin.close()
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()

    @staticmethod
    def _build_isolated_cli_probe_env(
        isolated_root: Path,
        *,
        base_env: dict[str, str] | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> dict[str, str]:
        import os

        src = base_env if base_env is not None else dict(os.environ)
        home_dir = isolated_root / "home"
        tmp_dir = isolated_root / "tmp"
        codex_home = isolated_root / "codex_home"
        claude_cfg = home_dir / ".claude"
        xdg_config = home_dir / ".config"
        xdg_data = home_dir / ".local" / "share"
        xdg_state = home_dir / ".local" / "state"
        xdg_cache = home_dir / ".cache"
        for d in (home_dir, tmp_dir, codex_home, claude_cfg, xdg_config, xdg_data, xdg_state, xdg_cache):
            d.mkdir(parents=True, exist_ok=True)

        raw_path = src.get("PATH") or "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        local_bin = str(Path.home() / ".local" / "bin")
        path_parts = [p for p in raw_path.split(":") if p]
        if local_bin not in path_parts:
            path_parts.insert(0, local_bin)

        env: dict[str, str] = {
            "PATH": ":".join(path_parts),
            "HOME": str(home_dir),
            "TMPDIR": str(tmp_dir),
            "LANG": src.get("LANG", "en_US.UTF-8"),
            "LC_ALL": src.get("LC_ALL", "en_US.UTF-8"),
            "TERM": "dumb",
            "XDG_CONFIG_HOME": str(xdg_config),
            "XDG_DATA_HOME": str(xdg_data),
            "XDG_STATE_HOME": str(xdg_state),
            "XDG_CACHE_HOME": str(xdg_cache),
            "CODEX_HOME": str(codex_home),
            "CLAUDE_CONFIG_DIR": str(claude_cfg),
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "DISABLE_TELEMETRY": "1",
            "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
            "DO_NOT_TRACK": "1",
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "no_proxy": "127.0.0.1,localhost,::1",
        }
        if extra_env:
            env.update(extra_env)
        return env

    @staticmethod
    def _write_loopback_seatbelt_profile(
        profile_path: Path,
        *,
        isolated_root: Path,
        denied_read_roots: list[Path] | None = None,
    ) -> Path:
        import os

        real_isolated = os.path.realpath(str(isolated_root))
        real_user_home = os.path.realpath(os.path.expanduser("~"))
        deny_read_lines = [
            f'  (literal "{real_user_home}/.claude.json")',
            f'  (subpath "{real_user_home}/.claude")',
            f'  (subpath "{real_user_home}/.codex")',
            f'  (subpath "{real_user_home}/.gemini")',
            f'  (subpath "{real_user_home}/.config/opencode")',
        ]
        for extra_root in denied_read_roots or []:
            deny_read_lines.append(f'  (subpath "{os.path.realpath(str(extra_root))}")')
        deny_read_block = "\n".join(deny_read_lines)
        profile_text = (
            "(version 1)\n"
            "(allow default)\n"
            "(deny network*)\n"
            '(allow network* (local ip "localhost:*"))\n'
            '(allow network* (remote ip "localhost:*"))\n'
            "(allow network* (remote unix-socket))\n"
            "(deny file-write*)\n"
            f'(allow file-write* (subpath "{real_isolated}"))\n'
            '(allow file-write* (literal "/dev/null") (literal "/dev/dtracehelper") (literal "/dev/tty"))\n'
            "(deny file-read*\n"
            f"{deny_read_block})\n"
            f'(allow file-read* (subpath "{real_isolated}"))\n'
        )
        profile_path.write_text(profile_text, encoding="utf-8")
        return profile_path

    def _resolve_sandbox_and_cli_binary(
        self,
        cli_name: str,
        *,
        binary_map: dict[str, str | None] | None = None,
        sandbox_available: bool | None = None,
    ) -> str:
        import os
        import shutil

        has_sandbox = (
            os.access("/usr/bin/sandbox-exec", os.X_OK)
            if sandbox_available is None
            else sandbox_available
        )
        if not has_sandbox:
            self.skipTest("/usr/bin/sandbox-exec is required for hermetic CLI loopback probes")

        if binary_map is not None:
            resolved = binary_map.get(cli_name)
        elif cli_name == "codex":
            resolved = shutil.which("codex") or (
                "/opt/homebrew/bin/codex"
                if os.access("/opt/homebrew/bin/codex", os.X_OK)
                else None
            )
        elif cli_name == "claude":
            resolved = shutil.which("claude") or (
                str(Path.home() / ".local" / "bin" / "claude")
                if os.access(Path.home() / ".local" / "bin" / "claude", os.X_OK)
                else None
            )
        elif cli_name == "agy":
            resolved = shutil.which("agy") or (
                str(Path.home() / ".local" / "bin" / "agy")
                if os.access(Path.home() / ".local" / "bin" / "agy", os.X_OK)
                else None
            )
        else:
            resolved = shutil.which(cli_name)

        if not resolved:
            self.skipTest(f"{cli_name} binary not installed on host")
        return resolved

    def test_mcp_stdio_content_length_and_newline_roundtrip(self) -> None:
        import http.server
        import os
        import tempfile
        import threading

        expected_annotations = {
            "readOnlyHint": False,
            "openWorldHint": False,
        }
        fixture_token = "se-session-fixture-token"
        models_requests: list[str] = []
        chat_requests: list[dict[str, Any]] = []
        backend_auth_headers: list[str] = []
        sentinel_requests: list[str] = []

        class SentinelHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                sentinel_requests.append(f"GET {self.path}")
                self.send_response(500)
                self.end_headers()

            def do_POST(self) -> None:
                sentinel_requests.append(f"POST {self.path}")
                self.send_response(500)
                self.end_headers()

        class LoopbackBackendHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                backend_auth_headers.append(self.headers.get("Authorization", ""))
                if self.path.startswith("/v1/models"):
                    models_requests.append(self.path)
                    raw = json.dumps(
                        {
                            "object": "list",
                            "data": [{"id": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit"}],
                        }
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return
                self.send_response(404)
                self.end_headers()

            def do_POST(self) -> None:
                backend_auth_headers.append(self.headers.get("Authorization", ""))
                ln = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(ln).decode("utf-8"))
                chat_requests.append(body)
                msgs = body.get("messages") or []
                user_text = str(msgs[-1].get("content", "")) if msgs else ""
                if "Return exactly OK." in user_text:
                    reply_text = "OK"
                else:
                    reply_text = json.dumps(
                        {"extracted": {"amount": 42}, "extraction_note": None}
                    )
                resp = {
                    "id": "chatcmpl-mock",
                    "object": "chat.completion",
                    "model": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": reply_text},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                }
                raw = json.dumps(resp).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        sentinel_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SentinelHandler)
        sentinel_port = sentinel_srv.server_address[1]
        threading.Thread(target=sentinel_srv.serve_forever, daemon=True).start()

        backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), LoopbackBackendHandler)
        backend_port = backend.server_address[1]
        threading.Thread(target=backend.serve_forever, daemon=True).start()

        try:
            with tempfile.TemporaryDirectory() as td:
                td_path = Path(td)
                log_dir = td_path / "logs"
                log_dir.mkdir(parents=True, exist_ok=True)
                events_file = td_path / "lifecycle_events.jsonl"
                wrapper = td_path / "run_wrapped_mcp.py"
                wrapper.write_text(
                    f"""#!{sys.executable} -B
import dataclasses, json, os, subprocess, sys
from pathlib import Path

sys.path.insert(0, {str(ROOT)!r})
import local_assist.client as client_mod
import local_assist.lifecycle as lc_mod
import local_assist.registry as reg_mod
from local_assist.server import main

fixture_url = "http://127.0.0.1:{backend_port}/v1"
fixture_key = {fixture_token!r}

orig_load_models = reg_mod.load_models
def _patched_load_models(models_path=None):
    items = []
    for entry in orig_load_models(models_path):
        copied = dict(entry)
        if copied.get("id") == "qwen3-30b-a3b-2507-mlx-4bit":
            copied["apiBaseUrl"] = fixture_url
            copied["apiKey"] = fixture_key
            copied.pop("apiKeyEnvar", None)
            copied.pop("apiKeyKeychainService", None)
        items.append(copied)
    return items

reg_mod.load_models = _patched_load_models
client_mod.load_models = _patched_load_models

orig_resolve = reg_mod.resolve_endpoint
def _patched_resolve(entry, pid_record=None, require_api_key=False):
    ep = orig_resolve(entry, pid_record=pid_record, require_api_key=require_api_key)
    return dataclasses.replace(
        ep,
        api_base_url=fixture_url,
        api_key=fixture_key,
        api_key_envar=None,
        api_key_keychain_service=None,
    )

reg_mod.resolve_endpoint = _patched_resolve
client_mod.resolve_endpoint = _patched_resolve
lc_mod.resolve_endpoint = _patched_resolve

state = {{"served": os.environ.get("SIMULATE_INITIALLY_DOWN") != "1"}}
events_path = Path({str(events_file)!r})

def _fake_runner(cmd, **kwargs):
    cmd_strs = [str(x) for x in cmd]
    with events_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({{"cmd": cmd_strs, "auto_serve": os.environ.get("LOCAL_ASSIST_AUTO_SERVE")}}) + "\\n")
    if any("serve-model" in s and "verify-served-model" not in s for s in cmd_strs):
        state["served"] = True
        return subprocess.CompletedProcess(cmd, 0, stdout="started\\n", stderr="")
    if any("verify-served-model" in s for s in cmd_strs):
        if state["served"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="verified\\n", stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="port down")
    return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

orig_ensure = lc_mod.ensure_local_model_served
def _patched_ensure(model, **kwargs):
    kwargs["run_cmd"] = _fake_runner
    return orig_ensure(model, **kwargs)

lc_mod.ensure_local_model_served = _patched_ensure
raise SystemExit(main())
""",
                    encoding="utf-8",
                )
                wrapper.chmod(0o755)

                # Hostile ambient env with a sentinel LOCAL_ASSIST_BASE_URL, API key, and HTTP_PROXY (WORK-MAJOR-1)
                hostile_ambient = dict(os.environ)
                hostile_ambient.update(
                    {
                        "LOCAL_ASSIST_BASE_URL": f"http://127.0.0.1:{sentinel_port}/v1",
                        "LOCAL_ASSIST_API_KEY": "sk-sentinel-leak",
                        "LOCAL_ASSIST_ALLOW_ATTESTED_TEE": "1",
                        "LOCAL_ASSIST_ALLOW_UNCLEARED_TEE": "1",
                        "LOCAL_ASSIST_WORKER_SANDBOX": "1",
                        "HTTP_PROXY": f"http://127.0.0.1:{sentinel_port}",
                        "HTTPS_PROXY": f"http://127.0.0.1:{sentinel_port}",
                        "ALL_PROXY": f"http://127.0.0.1:{sentinel_port}",
                        "http_proxy": f"http://127.0.0.1:{sentinel_port}",
                        "https_proxy": f"http://127.0.0.1:{sentinel_port}",
                        "all_proxy": f"http://127.0.0.1:{sentinel_port}",
                    }
                )

                for framing, use_auto_serve in (("content-length", False), ("line", True)):
                    env = self._build_isolated_cli_probe_env(
                        td_path / f"child_env_{framing}",
                        base_env=hostile_ambient,
                        extra_env={
                            "LOCAL_ASSIST_BASE_URL": f"http://127.0.0.1:{backend_port}/v1",
                            "LOCAL_ASSIST_API_KEY": fixture_token,
                            "LOCAL_ASSIST_LOG_DIR": str(log_dir),
                            "SIMULATE_INITIALLY_DOWN": "1" if use_auto_serve else "0",
                        },
                    )
                    self.assertNotIn("HTTP_PROXY", env)
                    self.assertNotIn("LOCAL_ASSIST_ALLOW_ATTESTED_TEE", env)
                    self.assertNotIn("LOCAL_ASSIST_WORKER_SANDBOX", env)
                    self.assertEqual(
                        env["LOCAL_ASSIST_BASE_URL"], f"http://127.0.0.1:{backend_port}/v1"
                    )
                    self.assertEqual(env["LOCAL_ASSIST_API_KEY"], fixture_token)

                    cmd = [sys.executable, "-B", str(wrapper)]
                    if use_auto_serve:
                        cmd.append("--auto-serve")

                    proc = subprocess.Popen(
                        cmd,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env=env,
                    )
                    assert proc.stdin is not None
                    assert proc.stdout is not None
                    try:
                        init_req = {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "initialize",
                            "params": {"protocolVersion": "2024-11-05"},
                        }
                        notif_req = {"jsonrpc": "2.0", "method": "notifications/initialized"}
                        list_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
                        call_req = {
                            "jsonrpc": "2.0",
                            "id": 3,
                            "method": "tools/call",
                            "params": {
                                "name": "extract_fields",
                                "arguments": {
                                    "text": "Invoice 42",
                                    "fields": {
                                        "amount": {
                                            "type": "integer",
                                            "description": "Invoice total",
                                            "required": True,
                                        }
                                    },
                                },
                            },
                        }
                        if framing == "content-length":
                            self._send(proc, init_req)
                            init_resp = self._recv(proc)
                            self._send(proc, notif_req)
                            self._send(proc, list_req)
                            list_resp = self._recv(proc)
                            self._send(proc, call_req)
                            call_resp = self._recv(proc)
                        else:
                            for req in (init_req, notif_req, list_req, call_req):
                                proc.stdin.write(
                                    (json.dumps(req, separators=(",", ":")) + "\n").encode("utf-8")
                                )
                            proc.stdin.flush()
                            init_resp = json.loads(proc.stdout.readline().decode("utf-8"))
                            list_resp = json.loads(proc.stdout.readline().decode("utf-8"))
                            call_resp = json.loads(proc.stdout.readline().decode("utf-8"))

                        self.assertEqual(
                            init_resp["result"]["serverInfo"]["name"], "local-assist-server"
                        )
                        tools = list_resp["result"]["tools"]
                        self.assertEqual(
                            [t["name"] for t in tools],
                            [
                                "propose_eval_prompts",
                                "extract_fields",
                                "compress_context",
                                "delegate_task",
                            ],
                        )
                        for tool in tools:
                            self.assertEqual(tool.get("annotations"), expected_annotations)

                        self.assertFalse(call_resp["result"]["isError"])
                        self.assertEqual(
                            call_resp["result"]["structuredContent"],
                            {
                                "extracted": {"amount": 42},
                                "missing_required": [],
                                "extraction_note": None,
                            },
                        )
                    finally:
                        proc.terminate()
                        proc.wait(timeout=5)
                        if proc.stdin:
                            proc.stdin.close()
                        if proc.stdout:
                            proc.stdout.close()
                        if proc.stderr:
                            proc.stderr.close()

                # Verify zero requests leaked to the hostile ambient sentinel listener (WORK-MAJOR-1)
                self.assertEqual(sentinel_requests, [])
                # Verify all expected /v1/models and /v1/chat/completions requests hit the fixture backend
                self.assertEqual(len(models_requests), 2)
                self.assertEqual(len(chat_requests), 4)
                self.assertEqual(
                    backend_auth_headers,
                    [f"Bearer {fixture_token}"] * 6,
                )

                recorded_events = [
                    json.loads(line)
                    for line in events_file.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                self.assertTrue(
                    any(
                        ev.get("auto_serve") == "1"
                        and any("serve-model" in part for part in ev.get("cmd", []))
                        for ev in recorded_events
                    )
                )
                audit_files = list(log_dir.rglob("*.json"))
                self.assertEqual(len(audit_files), 2)
        finally:
            backend.shutdown()
            backend.server_close()
            sentinel_srv.shutdown()
            sentinel_srv.server_close()

    def test_cli_probe_env_isolation_strips_ambient_credentials_and_configs(self) -> None:
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            ambient_home = td_path / "ambient_home"
            (ambient_home / ".claude").mkdir(parents=True)
            (ambient_home / ".codex").mkdir(parents=True)
            (ambient_home / ".gemini" / "config").mkdir(parents=True)

            sentinel_claude_json = ambient_home / ".claude.json"
            sentinel_claude_dir = ambient_home / ".claude" / "settings.json"
            sentinel_codex_toml = ambient_home / ".codex" / "config.toml"
            sentinel_agy_json = ambient_home / ".gemini" / "config" / "mcp_config.json"

            sentinel_claude_json.write_text('{"sentinel":"CLAUDE_JSON_SECRET"}', encoding="utf-8")
            sentinel_claude_dir.write_text('{"sentinel":"CLAUDE_DIR_SECRET"}', encoding="utf-8")
            sentinel_codex_toml.write_text("# CODEX_TOML_SECRET\n", encoding="utf-8")
            sentinel_agy_json.write_text('{"sentinel":"AGY_JSON_SECRET"}', encoding="utf-8")

            before_contents = {
                p: p.read_text(encoding="utf-8")
                for p in (
                    sentinel_claude_json,
                    sentinel_claude_dir,
                    sentinel_codex_toml,
                    sentinel_agy_json,
                )
            }

            ambient_env = {
                "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
                "HOME": str(ambient_home),
                "USERPROFILE": str(ambient_home),
                "CODEX_HOME": str(ambient_home / ".codex"),
                "CLAUDE_CONFIG_DIR": str(ambient_home / ".claude"),
                "XDG_CONFIG_HOME": str(ambient_home / ".config"),
                "XDG_DATA_HOME": str(ambient_home / ".local" / "share"),
                "XDG_STATE_HOME": str(ambient_home / ".local" / "state"),
                "XDG_CACHE_HOME": str(ambient_home / ".cache"),
                "ANTHROPIC_API_KEY": "anthropic-ambient-sentinel",
                "ANTHROPIC_AUTH_TOKEN": "ant-oauth-ambient-sentinel",
                "ANTHROPIC_BASE_URL": "https://api.anthropic.com",
                "OPENAI_API_KEY": "openai-ambient-sentinel",
                "OPENAI_BASE_URL": "https://api.openai.com/v1",
                "CLAUDE_CODE_OAUTH_TOKEN": "claude-oauth-ambient-sentinel",
                "GOOGLE_API_KEY": "google-ambient-sentinel",
                "GEMINI_API_KEY": "gemini-ambient-sentinel",
                "LOCAL_ASSIST_BASE_URL": "http://127.0.0.1:8080/v1",
                "LOCAL_ASSIST_API_KEY": "local-assist-ambient-sentinel",
                "HTTP_PROXY": "http://127.0.0.1:9999",
            }

            isolated_root = td_path / "isolated"
            isolated_env = self._build_isolated_cli_probe_env(
                isolated_root, base_env=ambient_env
            )

            for forbidden in (
                "USERPROFILE",
                "ANTHROPIC_API_KEY",
                "ANTHROPIC_AUTH_TOKEN",
                "ANTHROPIC_BASE_URL",
                "OPENAI_API_KEY",
                "OPENAI_BASE_URL",
                "CLAUDE_CODE_OAUTH_TOKEN",
                "GOOGLE_API_KEY",
                "GEMINI_API_KEY",
                "LOCAL_ASSIST_BASE_URL",
                "LOCAL_ASSIST_API_KEY",
                "HTTP_PROXY",
            ):
                self.assertNotIn(forbidden, isolated_env)

            for redirected in (
                "HOME",
                "TMPDIR",
                "CODEX_HOME",
                "CLAUDE_CONFIG_DIR",
                "XDG_CONFIG_HOME",
                "XDG_DATA_HOME",
                "XDG_STATE_HOME",
                "XDG_CACHE_HOME",
            ):
                val = Path(isolated_env[redirected]).resolve()
                self.assertTrue(
                    str(val).startswith(str(isolated_root.resolve())),
                    f"{redirected}={val} is outside {isolated_root}",
                )

            if os.access("/usr/bin/sandbox-exec", os.X_OK):
                sb_profile = self._write_loopback_seatbelt_profile(
                    isolated_root / "probe.sb",
                    isolated_root=isolated_root,
                    denied_read_roots=[ambient_home],
                )
                for sentinel_path in before_contents:
                    read_proc = subprocess.run(
                        ["/usr/bin/sandbox-exec", "-f", str(sb_profile), "/bin/cat", str(sentinel_path)],
                        env=isolated_env,
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    self.assertNotEqual(read_proc.returncode, 0)
                    self.assertNotIn("SECRET", read_proc.stdout)

            for sentinel_path, expected in before_contents.items():
                self.assertEqual(sentinel_path.read_text(encoding="utf-8"), expected)

    def test_partial_cli_availability_skips_missing_clients_individually(self) -> None:
        # WORK-MINOR-1 & R2-WORK-MAJOR-1:
        # 1. When sandbox-exec is available and only agy is installed, Codex and Claude
        #    probes must raise SkipTest individually while agy resolves cleanly.
        agy_only_map: dict[str, str | None] = {
            "codex": None,
            "claude": None,
            "agy": "/usr/bin/true",
        }
        with self.assertRaises(unittest.SkipTest) as codex_skip:
            self._resolve_sandbox_and_cli_binary(
                "codex", binary_map=agy_only_map, sandbox_available=True
            )
        self.assertIn("codex binary not installed", str(codex_skip.exception))

        with self.assertRaises(unittest.SkipTest) as claude_skip:
            self._resolve_sandbox_and_cli_binary(
                "claude", binary_map=agy_only_map, sandbox_available=True
            )
        self.assertIn("claude binary not installed", str(claude_skip.exception))

        resolved_agy = self._resolve_sandbox_and_cli_binary(
            "agy", binary_map=agy_only_map, sandbox_available=True
        )
        self.assertEqual(resolved_agy, "/usr/bin/true")

        # 2. When /usr/bin/sandbox-exec is unavailable (e.g., Linux verify-linux-portable),
        #    every client probe raises SkipTest with the sandbox prerequisite reason even if
        #    a binary is present.
        all_present_map: dict[str, str | None] = {
            "codex": "/usr/bin/true",
            "claude": "/usr/bin/true",
            "agy": "/usr/bin/true",
        }
        for cli_name in ("codex", "claude", "agy"):
            with self.assertRaises(unittest.SkipTest) as sb_skip:
                self._resolve_sandbox_and_cli_binary(
                    cli_name, binary_map=all_present_map, sandbox_available=False
                )
            self.assertIn(
                "/usr/bin/sandbox-exec is required", str(sb_skip.exception)
            )

    @staticmethod
    def _prepare_mock_mcp_workspace(isolated_root: Path) -> tuple[Path, Path, Path]:
        ws = isolated_root / "ws"
        ws.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q"], cwd=ws, check=True)

        mock_mcp = isolated_root / "mock_local_assist_server.py"
        mock_mcp.write_text(
            f"""#!{sys.executable} -B
import sys
sys.path.insert(0, {str(ROOT)!r})
import local_assist.server as srv
srv.extract_fields = lambda text, fields: {{
    "extracted": {{k: 42 for k in fields}},
    "missing_required": [],
    "extraction_note": None,
}}
raise SystemExit(srv.main())
""",
            encoding="utf-8",
        )
        mock_mcp.chmod(0o755)
        sb_profile = LocalAssistTests._write_loopback_seatbelt_profile(
            isolated_root / "loopback.sb",
            isolated_root=isolated_root,
        )
        return ws, mock_mcp, sb_profile

    def test_sandboxed_codex_mcp_registration_and_two_turn_roundtrip(self) -> None:
        import http.server
        import tempfile
        import threading

        codex_bin = self._resolve_sandbox_and_cli_binary("codex")
        codex_turns: list[dict[str, Any]] = []
        codex_paths: list[str] = []
        codex_auth_headers: list[str] = []

        class CodexLoopbackHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_POST(self) -> None:
                codex_paths.append(self.path)
                codex_auth_headers.append(self.headers.get("Authorization", ""))
                ln = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(ln).decode("utf-8"))
                codex_turns.append(body)
                has_fc_out = any(
                    isinstance(item, dict) and item.get("type") == "function_call_output"
                    for item in body.get("input", [])
                )
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                if not has_fc_out:
                    fc_item = {
                        "id": "fc_1",
                        "type": "function_call",
                        "call_id": "call_01",
                        "namespace": "mcp__local_assist",
                        "name": "extract_fields",
                        "arguments": json.dumps(
                            {
                                "text": "Invoice 42",
                                "fields": {
                                    "amount": {
                                        "type": "integer",
                                        "description": "amt",
                                        "required": True,
                                    }
                                },
                            }
                        ),
                        "status": "completed",
                    }
                    events = [
                        (
                            "response.created",
                            {
                                "type": "response.created",
                                "response": {"id": "resp_1", "status": "in_progress", "output": []},
                            },
                        ),
                        (
                            "response.output_item.added",
                            {"type": "response.output_item.added", "output_index": 0, "item": fc_item},
                        ),
                        (
                            "response.output_item.done",
                            {"type": "response.output_item.done", "output_index": 0, "item": fc_item},
                        ),
                        (
                            "response.completed",
                            {
                                "type": "response.completed",
                                "response": {
                                    "id": "resp_1",
                                    "status": "completed",
                                    "output": [fc_item],
                                    "usage": {"input_tokens": 10, "output_tokens": 10, "total_tokens": 20},
                                },
                            },
                        ),
                    ]
                else:
                    msg_item = {
                        "id": "msg_2",
                        "type": "message",
                        "role": "assistant",
                        "status": "completed",
                        "content": [{"type": "output_text", "text": "CODEX_ROUNDTRIP_OK"}],
                    }
                    events = [
                        (
                            "response.created",
                            {
                                "type": "response.created",
                                "response": {"id": "resp_2", "status": "in_progress", "output": []},
                            },
                        ),
                        (
                            "response.output_item.done",
                            {"type": "response.output_item.done", "output_index": 0, "item": msg_item},
                        ),
                        (
                            "response.completed",
                            {
                                "type": "response.completed",
                                "response": {
                                    "id": "resp_2",
                                    "status": "completed",
                                    "output": [msg_item],
                                    "usage": {"input_tokens": 20, "output_tokens": 5, "total_tokens": 25},
                                },
                            },
                        ),
                    ]
                for ev, data in events:
                    self.wfile.write(f"event: {ev}\ndata: {json.dumps(data)}\n\n".encode("utf-8"))
                self.wfile.flush()

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CodexLoopbackHandler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        try:
            with tempfile.TemporaryDirectory() as td:
                isolated_root = Path(td)
                ws, mock_mcp, sb_profile = self._prepare_mock_mcp_workspace(isolated_root)
                env_codex = self._build_isolated_cli_probe_env(
                    isolated_root,
                    extra_env={"LOCAL_TEST_API_KEY": "se-session-test-token"},
                )
                codex_home = Path(env_codex["CODEX_HOME"])

                add_proc = subprocess.run(
                    [
                        "/usr/bin/sandbox-exec",
                        "-f",
                        str(sb_profile),
                        codex_bin,
                        "mcp",
                        "add",
                        "local_assist",
                        "--",
                        str(mock_mcp),
                    ],
                    cwd=ws,
                    env=env_codex,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(add_proc.returncode, 0, add_proc.stderr)

                list_proc = subprocess.run(
                    [
                        "/usr/bin/sandbox-exec",
                        "-f",
                        str(sb_profile),
                        codex_bin,
                        "mcp",
                        "list",
                    ],
                    cwd=ws,
                    env=env_codex,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(list_proc.returncode, 0, list_proc.stderr)
                self.assertIn("local_assist", list_proc.stdout)

                # Verify wire_api = "chat" is rejected at config load (WORK-MINOR-2)
                chat_wire_cfg = f"""model = "test-model"
model_provider = "local_test"

[model_providers.local_test]
name = "Local Test"
base_url = "http://127.0.0.1:{port}/v1"
env_key = "LOCAL_TEST_API_KEY"
wire_api = "chat"
"""
                (codex_home / "config.toml").write_text(chat_wire_cfg, encoding="utf-8")
                chat_reject_proc = subprocess.run(
                    [
                        "/usr/bin/sandbox-exec",
                        "-f",
                        str(sb_profile),
                        codex_bin,
                        "exec",
                        "--strict-config",
                        "-s",
                        "read-only",
                        "Extract amount",
                    ],
                    cwd=ws,
                    env=env_codex,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertNotEqual(chat_reject_proc.returncode, 0)
                self.assertIn(
                    '`wire_api = "chat"` is no longer supported.',
                    chat_reject_proc.stderr,
                )

                base_codex_cfg = f"""model = "test-model"
model_provider = "local_test"

[analytics]
enabled = false

[feedback]
enabled = false

[model_providers.local_test]
name = "Local Test"
base_url = "http://127.0.0.1:{port}/v1"
env_key = "LOCAL_TEST_API_KEY"
wire_api = "responses"

[mcp_servers.local_assist]
command = "{mock_mcp}"
tool_timeout_sec = 180
"""
                # 1. Unapproved non-interactive call is gated because readOnlyHint is False
                codex_turns.clear()
                codex_paths.clear()
                codex_auth_headers.clear()
                (codex_home / "config.toml").write_text(base_codex_cfg, encoding="utf-8")
                unapproved_proc = subprocess.run(
                    [
                        "/usr/bin/sandbox-exec",
                        "-f",
                        str(sb_profile),
                        codex_bin,
                        "exec",
                        "--strict-config",
                        "-s",
                        "read-only",
                        "Extract amount",
                    ],
                    cwd=ws,
                    env=env_codex,
                    capture_output=True,
                    text=True,
                    timeout=25,
                )
                self.assertEqual(unapproved_proc.returncode, 0, unapproved_proc.stderr)
                self.assertEqual(len(codex_turns), 2)
                self.assertEqual(codex_paths, ["/v1/responses", "/v1/responses"])
                self.assertEqual(
                    codex_auth_headers,
                    ["Bearer se-session-test-token", "Bearer se-session-test-token"],
                )
                ns_entries = [
                    t
                    for t in codex_turns[0].get("tools", [])
                    if isinstance(t, dict)
                    and t.get("type") == "namespace"
                    and t.get("name") == "mcp__local_assist"
                ]
                self.assertEqual(len(ns_entries), 1)
                self.assertEqual(
                    sorted(x.get("name") for x in ns_entries[0].get("tools", [])),
                    [
                        "compress_context",
                        "delegate_task",
                        "extract_fields",
                        "propose_eval_prompts",
                    ],
                )
                unapproved_fc_outs = [
                    i
                    for i in codex_turns[1].get("input", [])
                    if isinstance(i, dict) and i.get("type") == "function_call_output"
                ]
                self.assertEqual(len(unapproved_fc_outs), 1)
                self.assertIn(
                    "MCP tool call requires approval",
                    json.dumps(unapproved_fc_outs[0].get("output")),
                )

                # 2. Explicit per-tool approval_mode = "approve" succeeds end-to-end
                codex_turns.clear()
                codex_paths.clear()
                codex_auth_headers.clear()
                (codex_home / "config.toml").write_text(
                    base_codex_cfg
                    + '\n[mcp_servers.local_assist.tools.extract_fields]\napproval_mode = "approve"\n',
                    encoding="utf-8",
                )
                approved_proc = subprocess.run(
                    [
                        "/usr/bin/sandbox-exec",
                        "-f",
                        str(sb_profile),
                        codex_bin,
                        "exec",
                        "--strict-config",
                        "-s",
                        "read-only",
                        "Extract amount",
                    ],
                    cwd=ws,
                    env=env_codex,
                    capture_output=True,
                    text=True,
                    timeout=25,
                )
                self.assertEqual(approved_proc.returncode, 0, approved_proc.stderr)
                self.assertIn("CODEX_ROUNDTRIP_OK", approved_proc.stdout)
                self.assertEqual(len(codex_turns), 2)
                self.assertEqual(codex_paths, ["/v1/responses", "/v1/responses"])
                approved_fc_outs = [
                    i
                    for i in codex_turns[1].get("input", [])
                    if isinstance(i, dict) and i.get("type") == "function_call_output"
                ]
                self.assertEqual(len(approved_fc_outs), 1)
                self.assertIn(
                    '{"extracted":{"amount":42},"missing_required":[],"extraction_note":null}',
                    str(approved_fc_outs[0].get("output")),
                )
        finally:
            srv.shutdown()
            srv.server_close()

    def test_sandboxed_claude_mcp_registration_and_two_turn_roundtrip(self) -> None:
        import http.server
        import tempfile
        import threading

        claude_bin = self._resolve_sandbox_and_cli_binary("claude")
        claude_turns: list[dict[str, Any]] = []
        claude_paths: list[str] = []
        claude_headers: list[dict[str, str]] = []

        class ClaudeLoopbackHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_POST(self) -> None:
                claude_paths.append(self.path)
                claude_headers.append(
                    {
                        "x-api-key": self.headers.get("x-api-key", ""),
                        "anthropic-version": self.headers.get("anthropic-version", ""),
                        "anthropic-beta": self.headers.get("anthropic-beta", ""),
                    }
                )
                ln = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(ln).decode("utf-8"))
                claude_turns.append(body)
                has_tool_result = any(
                    isinstance(m.get("content"), list)
                    and any(
                        isinstance(b, dict) and b.get("type") == "tool_result"
                        for b in m["content"]
                    )
                    for m in body.get("messages", [])
                )
                if not has_tool_result:
                    resp_obj = {
                        "id": "msg_t1",
                        "type": "message",
                        "role": "assistant",
                        "model": "test-model",
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "toolu_01",
                                "name": "mcp__local_assist__extract_fields",
                                "input": {
                                    "text": "Invoice 42",
                                    "fields": {
                                        "amount": {
                                            "type": "integer",
                                            "description": "amt",
                                            "required": True,
                                        }
                                    },
                                },
                            }
                        ],
                        "stop_reason": "tool_use",
                        "stop_sequence": None,
                        "usage": {"input_tokens": 10, "output_tokens": 10},
                    }
                else:
                    resp_obj = {
                        "id": "msg_t2",
                        "type": "message",
                        "role": "assistant",
                        "model": "test-model",
                        "content": [{"type": "text", "text": "CLAUDE_ROUNDTRIP_OK"}],
                        "stop_reason": "end_turn",
                        "stop_sequence": None,
                        "usage": {"input_tokens": 20, "output_tokens": 5},
                    }
                raw = json.dumps(resp_obj).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ClaudeLoopbackHandler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        try:
            with tempfile.TemporaryDirectory() as td:
                isolated_root = Path(td)
                ws, mock_mcp, sb_profile = self._prepare_mock_mcp_workspace(isolated_root)
                env_claude = self._build_isolated_cli_probe_env(
                    isolated_root,
                    extra_env={
                        "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{port}",
                        "ANTHROPIC_API_KEY": "se-session-test-token",
                    },
                )
                c_add = subprocess.run(
                    [
                        "/usr/bin/sandbox-exec",
                        "-f",
                        str(sb_profile),
                        claude_bin,
                        "mcp",
                        "add",
                        "local_assist",
                        "--",
                        str(mock_mcp),
                    ],
                    cwd=ws,
                    env=env_claude,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(c_add.returncode, 0, c_add.stderr)

                c_get = subprocess.run(
                    [
                        "/usr/bin/sandbox-exec",
                        "-f",
                        str(sb_profile),
                        claude_bin,
                        "mcp",
                        "get",
                        "local_assist",
                    ],
                    cwd=ws,
                    env=env_claude,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(c_get.returncode, 0, c_get.stderr)
                self.assertIn("local_assist", c_get.stdout)

                mcp_cfg = isolated_root / "claude_mcp.json"
                mcp_cfg.write_text(
                    json.dumps(
                        {
                            "mcpServers": {
                                "local_assist": {
                                    "type": "stdio",
                                    "command": str(mock_mcp),
                                }
                            }
                        }
                    ),
                    encoding="utf-8",
                )
                claude_turns.clear()
                claude_paths.clear()
                claude_headers.clear()
                c_run = subprocess.run(
                    [
                        "/usr/bin/sandbox-exec",
                        "-f",
                        str(sb_profile),
                        claude_bin,
                        "--bare",
                        "--no-session-persistence",
                        "--mcp-config",
                        str(mcp_cfg),
                        "--allowedTools",
                        "mcp__local_assist__extract_fields",
                        "-p",
                        "Extract amount",
                    ],
                    cwd=ws,
                    env=env_claude,
                    capture_output=True,
                    text=True,
                    timeout=25,
                )
                self.assertEqual(c_run.returncode, 0, c_run.stderr)
                self.assertIn("CLAUDE_ROUNDTRIP_OK", c_run.stdout)
                self.assertGreaterEqual(len(claude_turns), 2)
                self.assertTrue(all(p == "/v1/messages?beta=true" for p in claude_paths))
                self.assertEqual(claude_headers[0]["x-api-key"], "se-session-test-token")
                self.assertEqual(claude_headers[0]["anthropic-version"], "2023-06-01")
                self.assertIn("claude-code-20250219", claude_headers[0]["anthropic-beta"])
                c_tools = [
                    t.get("name")
                    for t in claude_turns[0].get("tools", [])
                    if isinstance(t, dict)
                    and str(t.get("name", "")).startswith("mcp__local_assist__")
                ]
                self.assertEqual(
                    sorted(c_tools),
                    [
                        "mcp__local_assist__compress_context",
                        "mcp__local_assist__delegate_task",
                        "mcp__local_assist__extract_fields",
                        "mcp__local_assist__propose_eval_prompts",
                    ],
                )
                last_user_msg = claude_turns[-1]["messages"][-1]
                tool_results = [
                    b
                    for b in last_user_msg.get("content", [])
                    if isinstance(b, dict) and b.get("type") == "tool_result"
                ]
                self.assertEqual(len(tool_results), 1)
                self.assertEqual(
                    json.loads(tool_results[0]["content"]),
                    {
                        "extracted": {"amount": 42},
                        "missing_required": [],
                        "extraction_note": None,
                    },
                )
        finally:
            srv.shutdown()
            srv.server_close()

    def test_sandboxed_agy_mcp_registration(self) -> None:
        import tempfile

        agy_bin = self._resolve_sandbox_and_cli_binary("agy")
        with tempfile.TemporaryDirectory() as td:
            isolated_root = Path(td)
            ws, mock_mcp, sb_profile = self._prepare_mock_mcp_workspace(isolated_root)
            env_agy = self._build_isolated_cli_probe_env(isolated_root)
            agy_add = subprocess.run(
                [
                    "/usr/bin/sandbox-exec",
                    "-f",
                    str(sb_profile),
                    agy_bin,
                    "mcp",
                    "add",
                    "local_assist",
                    "--",
                    str(mock_mcp),
                ],
                cwd=ws,
                env=env_agy,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(agy_add.returncode, 0, agy_add.stderr)

            agy_list = subprocess.run(
                [
                    "/usr/bin/sandbox-exec",
                    "-f",
                    str(sb_profile),
                    agy_bin,
                    "mcp",
                    "list",
                ],
                cwd=ws,
                env=env_agy,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(agy_list.returncode, 0, agy_list.stderr)
            self.assertIn("local_assist", agy_list.stdout)
            agy_cfg_path = (
                Path(env_agy["HOME"]) / ".gemini" / "config" / "mcp_config.json"
            )
            self.assertTrue(agy_cfg_path.is_file())
            agy_cfg = json.loads(agy_cfg_path.read_text(encoding="utf-8"))
            self.assertEqual(
                agy_cfg["mcpServers"]["local_assist"]["command"], str(mock_mcp)
            )
            self.assertFalse(agy_cfg["mcpServers"]["local_assist"]["disabled"])

    def test_open_loopback_http_bypasses_env_and_system_proxies_and_redirects(self) -> None:
        import http.server
        import tempfile
        import threading
        import unittest.mock
        from urllib.error import HTTPError, URLError
        from urllib.request import Request

        import local_assist.client as client_mod
        from local_assist.errors import LocalAssistError

        backend_requests: list[str] = []
        proxy_requests: list[str] = []
        redirect_sentinel_requests: list[str] = []

        class BackendHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                backend_requests.append(f"GET {self.path}")
                raw = json.dumps(
                    {
                        "object": "list",
                        "data": [{"id": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit"}],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self) -> None:
                ln = int(self.headers.get("Content-Length", "0"))
                _ = self.rfile.read(ln) if ln > 0 else b""
                backend_requests.append(f"POST {self.path}")
                raw = json.dumps(
                    {
                        "id": "chatcmpl-loopback",
                        "object": "chat.completion",
                        "model": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
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
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        class HostileProxyHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                proxy_requests.append(f"GET {self.path}")
                raw = json.dumps(
                    {"object": "list", "data": [{"id": "PROXY_INTERCEPTED"}]}
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self) -> None:
                ln = int(self.headers.get("Content-Length", "0"))
                _ = self.rfile.read(ln) if ln > 0 else b""
                proxy_requests.append(f"POST {self.path}")
                raw = json.dumps(
                    {
                        "id": "chatcmpl-proxy",
                        "object": "chat.completion",
                        "model": "PROXY_INTERCEPTED",
                        "choices": [
                            {
                                "index": 0,
                                "message": {"role": "assistant", "content": "PROXY"},
                                "finish_reason": "stop",
                            }
                        ],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_CONNECT(self) -> None:
                proxy_requests.append(f"CONNECT {self.path}")
                self.send_response(502)
                self.end_headers()

        backend_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), BackendHandler)
        backend_port = backend_srv.server_address[1]
        threading.Thread(target=backend_srv.serve_forever, daemon=True).start()

        proxy_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HostileProxyHandler)
        proxy_port = proxy_srv.server_address[1]
        threading.Thread(target=proxy_srv.serve_forever, daemon=True).start()

        class RedirectSentinelHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                redirect_sentinel_requests.append(self.path)
                self.send_response(200)
                self.end_headers()

        sentinel_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectSentinelHandler)
        sentinel_port = sentinel_srv.server_address[1]
        threading.Thread(target=sentinel_srv.serve_forever, daemon=True).start()

        class RedirectHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{sentinel_port}/leak")
                self.end_headers()

        redirect_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        redirect_port = redirect_srv.server_address[1]
        threading.Thread(target=redirect_srv.serve_forever, daemon=True).start()

        try:
            with tempfile.TemporaryDirectory() as td:
                td_path = Path(td)
                models_yaml = td_path / "models.yaml"
                models_yaml.write_text(
                    (ROOT / "models.yaml")
                    .read_text(encoding="utf-8")
                    .replace("http://127.0.0.1:8080/v1", f"http://127.0.0.1:{backend_port}/v1"),
                    encoding="utf-8",
                )
                clean_no_proxy_env = {
                    "PATH": str(Path(sys.executable).parent) + ":/usr/bin:/bin",
                    "HOME": str(td_path),
                    "TMPDIR": str(td_path),
                    "LANG": "C",
                }

                # 1. Control check (PLAN-MINOR-1): confirm simulated OS proxy discovery
                # routes default urllib requests to proxy_srv when proxy env vars are absent.
                ctrl_proc = subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        "-c",
                        (
                            "import urllib.request; "
                            f"urllib.request.getproxies = lambda: {{'http': 'http://127.0.0.1:{proxy_port}'}}; "
                            "urllib.request.proxy_bypass = lambda h: False; "
                            f"urllib.request.build_opener().open('http://127.0.0.1:{backend_port}/v1/models', timeout=5).read()"
                        ),
                    ],
                    env=clean_no_proxy_env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(ctrl_proc.returncode, 0, ctrl_proc.stderr)
                self.assertEqual(len(proxy_requests), 1)
                self.assertEqual(backend_requests, [])

                # 2. System-proxy bypass check (proxy env vars absent, getproxies patched BEFORE import):
                proxy_requests.clear()
                backend_requests.clear()
                sys_proxy_script = f"""
import sys, urllib.request
from pathlib import Path
urllib.request.getproxies = lambda: {{"http": "http://127.0.0.1:{proxy_port}", "https": "http://127.0.0.1:{proxy_port}"}}
urllib.request.proxy_bypass = lambda h: False
sys.path.insert(0, {str(ROOT)!r})
import local_assist.registry as reg
reg.DEFAULT_MODELS_PATH = Path({str(models_yaml)!r})
import local_assist.client as client
models = client.get_models(model="mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit")
assert models == ["mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit"], models
res = client.chat("mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit", "sys", "Return OK.")
assert res.text == "OK", res
"""
                sys_proc = subprocess.run(
                    [sys.executable, "-B", "-c", sys_proxy_script],
                    env=clean_no_proxy_env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(sys_proc.returncode, 0, sys_proc.stderr)
                self.assertEqual(proxy_requests, [])
                self.assertEqual(
                    backend_requests,
                    ["GET /v1/models", "POST /v1/chat/completions"],
                )

                # 3. Environment-proxy bypass check (HTTP_PROXY/ALL_PROXY set, NO_PROXY absent):
                proxy_requests.clear()
                backend_requests.clear()
                env_with_hostile_proxy = dict(clean_no_proxy_env)
                for pvar in (
                    "HTTP_PROXY",
                    "http_proxy",
                    "HTTPS_PROXY",
                    "https_proxy",
                    "ALL_PROXY",
                    "all_proxy",
                ):
                    env_with_hostile_proxy[pvar] = f"http://127.0.0.1:{proxy_port}"
                self.assertNotIn("NO_PROXY", env_with_hostile_proxy)
                self.assertNotIn("no_proxy", env_with_hostile_proxy)

                env_proxy_script = f"""
import sys
from pathlib import Path
sys.path.insert(0, {str(ROOT)!r})
import local_assist.registry as reg
reg.DEFAULT_MODELS_PATH = Path({str(models_yaml)!r})
import local_assist.client as client
models = client.get_models(model="mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit")
assert models == ["mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit"], models
res = client.chat("mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit", "sys", "Return OK.")
assert res.text == "OK", res
"""
                env_proc = subprocess.run(
                    [sys.executable, "-B", "-c", env_proxy_script],
                    env=env_with_hostile_proxy,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(env_proc.returncode, 0, env_proc.stderr)
                self.assertEqual(proxy_requests, [])
                self.assertEqual(
                    backend_requests,
                    ["GET /v1/models", "POST /v1/chat/completions"],
                )

                # 4. Redirects and non-HTTP / non-loopback / userinfo URLs are refused:
                open_fn = getattr(client_mod, "open_loopback_http", None)
                self.assertIsNotNone(open_fn, "open_loopback_http must be defined on local_assist.client")
                assert open_fn is not None
                with self.assertRaises(HTTPError) as redir_ctx:
                    open_fn(Request(f"http://127.0.0.1:{redirect_port}/v1/models"), timeout=5)
                self.assertEqual(redir_ctx.exception.code, 302)
                redir_ctx.exception.close()
                self.assertEqual(redirect_sentinel_requests, [])

                for bad_url in (
                    "file:///etc/hosts",
                    "ftp://127.0.0.1:8080/v1/models",
                    "http://192.0.2.1:8080/v1/models",
                    f"http://user:pass@127.0.0.1:{backend_port}/v1/models",
                ):
                    with self.assertRaises(URLError):
                        open_fn(Request(bad_url), timeout=5)

                for bad_env_url in (
                    "ftp://127.0.0.1:8080/v1",
                    "http://user:pass@127.0.0.1:8080/v1",
                ):
                    with unittest.mock.patch.dict("os.environ", {"LOCAL_ASSIST_BASE_URL": bad_env_url}):
                        with self.assertRaises(LocalAssistError) as bad_env_ctx:
                            client_mod.base_url()
                        self.assertEqual(bad_env_ctx.exception.code, "trust_tier_blocked")
        finally:
            backend_srv.shutdown()
            backend_srv.server_close()
            proxy_srv.shutdown()
            proxy_srv.server_close()
            redirect_srv.shutdown()
            redirect_srv.server_close()
            sentinel_srv.shutdown()
            sentinel_srv.server_close()

    def test_registered_entrypoint_bypasses_hostile_proxy_and_resolves_workspace_root(self) -> None:
        import http.server
        import os
        import shutil
        import tempfile
        import threading

        from local_assist.registry import get_process_lstart, pid_file_for_model

        proxy_requests: list[str] = []

        class HostileProxyHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                proxy_requests.append(f"GET {self.path}")
                raw = json.dumps(
                    {
                        "object": "list",
                        "data": [{"id": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit"}],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self) -> None:
                ln = int(self.headers.get("Content-Length", "0"))
                _ = self.rfile.read(ln) if ln > 0 else b""
                proxy_requests.append(f"POST {self.path}")
                raw = json.dumps(
                    {
                        "id": "chatcmpl-proxy-impersonation",
                        "object": "chat.completion",
                        "model": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
                        "choices": [
                            {
                                "index": 0,
                                "message": {
                                    "role": "assistant",
                                    "content": json.dumps(
                                        {
                                            "summary": "PROXY_LEAK",
                                            "output": "PROXY_LEAK",
                                            "assumptions": [],
                                            "unverified_claims": [],
                                        }
                                    ),
                                },
                                "finish_reason": "stop",
                            }
                        ],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_CONNECT(self) -> None:
                proxy_requests.append(f"CONNECT {self.path}")
                self.send_response(502)
                self.end_headers()

        proxy_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HostileProxyHandler)
        proxy_port = proxy_srv.server_address[1]
        threading.Thread(target=proxy_srv.serve_forever, daemon=True).start()

        backend_proc: subprocess.Popen[str] | None = None
        try:
            with tempfile.TemporaryDirectory() as td:
                td_path = Path(td)
                mirror_root = (td_path / "lab_mirror").resolve()
                shutil.copytree(
                    ROOT / "local_assist",
                    mirror_root / "local_assist",
                    symlinks=False,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
                )
                (mirror_root / "scripts").mkdir(parents=True, exist_ok=True)
                for script_name in (
                    "local-assist-server",
                    "verify-served-model",
                    "serve-model",
                    "delegate-local",
                ):
                    dst = mirror_root / "scripts" / script_name
                    shutil.copy2(ROOT / "scripts" / script_name, dst)
                    dst.chmod(0o755)
                shutil.copytree(
                    ROOT / "docs" / "evals",
                    mirror_root / "docs" / "evals",
                    symlinks=False,
                )
                (mirror_root / "runs").mkdir(parents=True, exist_ok=True)

                backend_log_file = td_path / "backend_requests.jsonl"
                backend_script = td_path / "mock_mlx_backend.py"
                backend_script.write_text(
                    f"""#!{sys.executable} -B
import http.server, json, sys
from pathlib import Path

log_path = Path({str(backend_log_file)!r})
served_repo = "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit"

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_GET(self):
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({{"method": "GET", "path": self.path}}) + "\\n")
        raw = json.dumps({{"object": "list", "data": [{{"id": served_repo}}]}}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def do_POST(self):
        ln = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(ln).decode("utf-8")) if ln > 0 else {{}}
        msgs = body.get("messages") or []
        user_text = str(msgs[-1].get("content", "")) if msgs else ""
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({{"method": "POST", "path": self.path, "has_invoice_secret": "CONFIDENTIAL_INVOICE_TOTAL=42" in user_text}}) + "\\n")
        if "Return exactly OK." in user_text:
            reply = "OK"
        elif "CONFIDENTIAL_INVOICE_TOTAL=42" in user_text:
            reply = json.dumps({{
                "summary": "Read invoice total from local workspace file.",
                "output": "42",
                "assumptions": [],
                "unverified_claims": [],
            }})
        else:
            reply = json.dumps({{"extracted": {{"amount": 42}}, "extraction_note": None}})
        raw = json.dumps({{
            "id": "chatcmpl-mirror",
            "object": "chat.completion",
            "model": served_repo,
            "choices": [{{"index": 0, "message": {{"role": "assistant", "content": reply}}, "finish_reason": "stop"}}],
            "usage": {{"prompt_tokens": 12, "completion_tokens": 6, "total_tokens": 18}},
        }}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
print(json.dumps({{"port": srv.server_address[1]}}), flush=True)
srv.serve_forever()
""",
                    encoding="utf-8",
                )
                backend_proc = subprocess.Popen(
                    [
                        sys.executable,
                        "-B",
                        str(backend_script),
                        "--model",
                        "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                assert backend_proc.stdout is not None
                ready_line = backend_proc.stdout.readline().strip()
                self.assertTrue(ready_line, "mock_mlx_backend did not announce port")
                backend_port = int(json.loads(ready_line)["port"])
                srv_lstart = get_process_lstart(backend_proc.pid)
                self.assertTrue(srv_lstart)

                (mirror_root / "models.yaml").write_text(
                    (ROOT / "models.yaml")
                    .read_text(encoding="utf-8")
                    .replace("http://127.0.0.1:8080/v1", f"http://127.0.0.1:{backend_port}/v1"),
                    encoding="utf-8",
                )
                pid_path = pid_file_for_model(
                    "qwen3-30b-a3b-2507-mlx-4bit", mirror_root / "runs"
                )
                pid_path.write_text(
                    json.dumps(
                        {
                            "model_id": "qwen3-30b-a3b-2507-mlx-4bit",
                            "repo": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
                            "port": backend_port,
                            "pid": backend_proc.pid,
                            "pid_lstart": srv_lstart,
                            "hf_offline": True,
                            "status": "ready",
                        }
                    ),
                    encoding="utf-8",
                )

                # Omit /usr/sbin and /sbin from PATH to also test verify-served-model's
                # /usr/sbin/lsof fallback when an MCP host passes a minimal PATH.
                py_bin_dir = str(Path(sys.executable).parent)
                path_entries = [py_bin_dir, "/usr/local/bin", "/usr/bin", "/bin"]
                has_host_lsof = bool(
                    shutil.which("lsof")
                    or os.access("/usr/sbin/lsof", os.X_OK)
                    or os.access("/usr/bin/lsof", os.X_OK)
                )
                if not has_host_lsof:
                    shim_bin = td_path / "shim_bin"
                    shim_bin.mkdir(parents=True, exist_ok=True)
                    lsof_shim = shim_bin / "lsof"
                    lsof_shim.write_text(
                        f"#!/bin/sh\necho 'p{backend_proc.pid}'\n",
                        encoding="utf-8",
                    )
                    lsof_shim.chmod(0o755)
                    path_entries.insert(0, str(shim_bin))

                # Ensure python3 exists in py_bin_dir or /usr/bin; if sys.executable is named
                # python only, expose a python3 symlink in a temp bin dir for the no-.venv branch.
                if not shutil.which("python3", path=":".join(path_entries)):
                    py3_bin = td_path / "py3_bin"
                    py3_bin.mkdir(parents=True, exist_ok=True)
                    (py3_bin / "python3").symlink_to(sys.executable)
                    path_entries.insert(0, str(py3_bin))

                caller_ws = td_path / "caller_workspace"
                (caller_ws / "notes").mkdir(parents=True, exist_ok=True)
                (caller_ws / "notes" / "invoice.txt").write_text(
                    "CONFIDENTIAL_INVOICE_TOTAL=42\n",
                    encoding="utf-8",
                )

                # Hostile proxy env passed UNCHANGED into the registered entry points (FREE-INFERENCE-MCP-001 F1):
                hostile_env = {
                    "PATH": ":".join(path_entries),
                    "HOME": str(td_path / "home"),
                    "TMPDIR": str(td_path / "tmp"),
                    "LANG": "en_US.UTF-8",
                    "HTTP_PROXY": f"http://127.0.0.1:{proxy_port}",
                    "http_proxy": f"http://127.0.0.1:{proxy_port}",
                    "HTTPS_PROXY": f"http://127.0.0.1:{proxy_port}",
                    "https_proxy": f"http://127.0.0.1:{proxy_port}",
                    "ALL_PROXY": f"http://127.0.0.1:{proxy_port}",
                    "all_proxy": f"http://127.0.0.1:{proxy_port}",
                }
                (td_path / "home").mkdir(parents=True, exist_ok=True)
                (td_path / "tmp").mkdir(parents=True, exist_ok=True)
                self.assertNotIn("NO_PROXY", hostile_env)
                self.assertNotIn("no_proxy", hostile_env)
                self.assertNotIn("LOCAL_ASSIST_WORKSPACE_ROOT", hostile_env)
                self.assertNotIn("LOCAL_ASSIST_BASE_URL", hostile_env)

                entrypoint = mirror_root / "scripts" / "local-assist-server"
                for use_venv in (False, True):
                    if use_venv:
                        import venv

                        venv.EnvBuilder(symlinks=True, with_pip=False).create(
                            mirror_root / ".venv"
                        )

                    proc = subprocess.Popen(
                        [str(entrypoint)],
                        cwd=caller_ws,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env=hostile_env,
                    )
                    assert proc.stdin is not None
                    assert proc.stdout is not None
                    try:
                        self._send(
                            proc,
                            {
                                "jsonrpc": "2.0",
                                "id": 1,
                                "method": "initialize",
                                "params": {"protocolVersion": "2024-11-05"},
                            },
                        )
                        init_resp = self._recv(proc)
                        self.assertEqual(
                            init_resp["result"]["serverInfo"]["name"], "local-assist-server"
                        )

                        self._send(
                            proc,
                            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                        )
                        list_resp = self._recv(proc)
                        for tool in list_resp["result"]["tools"]:
                            self.assertEqual(
                                tool.get("annotations"),
                                {"readOnlyHint": False, "openWorldHint": False},
                            )

                        self._send(
                            proc,
                            {
                                "jsonrpc": "2.0",
                                "id": 3,
                                "method": "tools/call",
                                "params": {
                                    "name": "delegate_task",
                                    "arguments": {
                                        "kind": "focused_qa",
                                        "instruction": "Return invoice total.",
                                        "context_path": "notes/invoice.txt",
                                    },
                                },
                            },
                        )
                        del_resp = self._recv(proc)
                        self.assertFalse(del_resp["result"]["isError"], del_resp)
                        self.assertEqual(del_resp["result"]["structuredContent"]["output"], "42")

                        self._send(
                            proc,
                            {
                                "jsonrpc": "2.0",
                                "id": 4,
                                "method": "tools/call",
                                "params": {
                                    "name": "extract_fields",
                                    "arguments": {
                                        "text": "Invoice 42",
                                        "fields": {
                                            "amount": {
                                                "type": "integer",
                                                "description": "Invoice total",
                                                "required": True,
                                            }
                                        },
                                    },
                                },
                            },
                        )
                        ext_resp = self._recv(proc)
                        self.assertFalse(ext_resp["result"]["isError"], ext_resp)
                        self.assertEqual(
                            ext_resp["result"]["structuredContent"]["extracted"],
                            {"amount": 42},
                        )
                    finally:
                        proc.terminate()
                        proc.wait(timeout=5)
                        if proc.stdin:
                            proc.stdin.close()
                        if proc.stdout:
                            proc.stdout.close()
                        if proc.stderr:
                            proc.stderr.close()

                # Also exercise scripts/delegate-local under the same hostile proxy environment
                del_cli = subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        str(mirror_root / "scripts" / "delegate-local"),
                        "extract_fields",
                        "--text",
                        "Invoice 42",
                        "--fields-json",
                        '{"amount":{"type":"integer","description":"Invoice total","required":true}}',
                    ],
                    cwd=caller_ws,
                    env=hostile_env,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(del_cli.returncode, 0, del_cli.stderr)
                self.assertEqual(json.loads(del_cli.stdout)["extracted"], {"amount": 42})

                self.assertEqual(proxy_requests, [])
                backend_records = [
                    json.loads(line)
                    for line in backend_log_file.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                self.assertGreaterEqual(
                    sum(1 for r in backend_records if r.get("method") == "GET"), 5
                )
                self.assertGreaterEqual(
                    sum(1 for r in backend_records if r.get("has_invoice_secret") is True), 2
                )

                audit_root = mirror_root / "runs" / "local-assist"
                audit_files = list(audit_root.rglob("*.json"))
                self.assertGreaterEqual(len(audit_files), 5)
                for af in audit_root.rglob("*"):
                    if af.is_file():
                        self.assertNotIn(
                            "CONFIDENTIAL_INVOICE_TOTAL",
                            af.read_text(encoding="utf-8"),
                        )
        finally:
            if backend_proc is not None:
                backend_proc.terminate()
                try:
                    backend_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    backend_proc.kill()
                    backend_proc.wait(timeout=5)
                if backend_proc.stdout:
                    backend_proc.stdout.close()
                if backend_proc.stderr:
                    backend_proc.stderr.close()
            proxy_srv.shutdown()
            proxy_srv.server_close()

    def _send(self, proc: subprocess.Popen[bytes], payload: dict) -> None:
        assert proc.stdin is not None
        body = json.dumps(payload).encode("utf-8")
        proc.stdin.write(b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body)
        proc.stdin.flush()

    def _recv(self, proc: subprocess.Popen[bytes]) -> dict:
        assert proc.stdout is not None
        headers: dict[str, str] = {}
        while True:
            line = proc.stdout.readline()
            if line in (b"\r\n", b"\n"):
                break
            key, _, value = line.decode("ascii").partition(":")
            headers[key.lower()] = value.strip()
        body = proc.stdout.read(int(headers["content-length"]))
        return json.loads(body.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
