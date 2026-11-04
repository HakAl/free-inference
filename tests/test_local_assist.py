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
        proc = subprocess.Popen(
            ["scripts/local-assist-server"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
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
