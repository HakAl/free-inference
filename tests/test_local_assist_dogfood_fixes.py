from __future__ import annotations

import hashlib
import http.server
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
from pathlib import Path
from typing import Any
from unittest import mock
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from local_assist.client import ChatResult
from local_assist.errors import LocalAssistError, ModelOutputMalformed
from local_assist.server import handle_request


class LocalAssistDogfoodFixesTests(unittest.TestCase):
    def test_malformed_model_output_preserves_completion_telemetry_and_stats_tokens(self) -> None:
        from local_assist.tools import compress_context

        with tempfile.TemporaryDirectory() as td:
            log_dir = Path(td) / "logs"
            fake_result = ChatResult(
                text="this is definitely not valid json",
                raw_text="this is definitely not valid json",
                served_model="mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
                finish_reason="stop",
                usage={"prompt_tokens": 120, "completion_tokens": 45, "total_tokens": 165},
                latency_ms=834,
            )
            with (
                patch.dict(os.environ, {"LOCAL_ASSIST_LOG_DIR": str(log_dir)}, clear=False),
                patch.object(
                    compress_context,
                    "require_chat_succeeds",
                    return_value="mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
                ),
                patch.object(compress_context, "chat", return_value=fake_result),
            ):
                with self.assertRaises(ModelOutputMalformed):
                    compress_context.run(kind="logs", text="ERROR line 1\nERROR line 2", max_items=2)

            jsonl_files = list(log_dir.glob("*.jsonl"))
            self.assertEqual(len(jsonl_files), 1)
            row = json.loads(jsonl_files[0].read_text(encoding="utf-8").strip())
            self.assertEqual(row["finish_reason"], "error")
            self.assertEqual(row["served_model"], "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit")
            self.assertEqual(row["model_finish_reason"], "stop")
            self.assertEqual(row["latency_ms"], 834)
            self.assertEqual(
                row["usage"],
                {"prompt_tokens": 120, "completion_tokens": 45, "total_tokens": 165},
            )

            detail_files = list(log_dir.glob("*/*.json"))
            self.assertEqual(len(detail_files), 1)
            detail = json.loads(detail_files[0].read_text(encoding="utf-8"))
            self.assertEqual(detail["served_model"], "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit")
            self.assertEqual(detail["usage"]["total_tokens"], 165)
            self.assertEqual(detail["latency_ms"], 834)
            self.assertEqual(detail["model_finish_reason"], "stop")

            stats_proc = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "local-assist-stats"),
                    "--log-dir",
                    str(log_dir),
                    "--json",
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(stats_proc.returncode, 0, stats_proc.stderr)
            stats = json.loads(stats_proc.stdout)
            self.assertEqual(stats["error_calls"], 1)
            self.assertEqual(stats["succeeded_calls"], 0)
            self.assertEqual(stats["tokens"]["total_tokens"], 165)
            self.assertEqual(stats["error_tokens"]["total_tokens"], 165)
            self.assertEqual(stats["by_tool"]["compress_context"]["latency_ms"]["count"], 0)

    def test_compress_context_small_max_items_clamping_and_grounding(self) -> None:
        from local_assist.tools import compress_context

        src = (
            "Traceback in src/real.py line 44: KeyError 'user_id'\n"
            "Reproduce with: pytest tests/test_real.py -k user_id\n"
        )
        model_json = json.dumps(
            {
                "summary": "KeyError on user_id in src/real.py.",
                "key_points": ["first", "second", "third", "fourth"],
                "changed_files": ["invented/ghost.py", "src/real.py"],
                "failures": ["KeyError 'user_id'", "extra secondary error"],
                "risks": ["missing user_id guard"],
                "commands": ["rg user_id invented/ghost.py", "pytest tests/test_real.py -k user_id"],
                "followups": ["inspect caller"],
                "omitted": [],
            }
        )
        for cap in (1, 2, 3):
            validated = {"kind": "logs", "text": src, "focus": None, "max_items": cap}
            parsed, meta = compress_context.parse_and_validate_with_meta(model_json, validated)
            self.assertEqual(set(parsed.keys()), set(compress_context.OUTPUT_KEYS))
            self.assertEqual(len(parsed["key_points"]), cap)
            self.assertLessEqual(len(parsed["failures"]), cap)
            self.assertIn("key_points", meta["clamped_fields"])
            self.assertEqual(parsed["changed_files"], ["src/real.py"])
            self.assertEqual(parsed["commands"], ["pytest tests/test_real.py -k user_id"])
            self.assertGreaterEqual(meta["ungrounded_items_dropped"], 2)

        runaway = json.dumps(
            {
                "summary": "s",
                "key_points": [f"p{i}" for i in range(20)],
                "changed_files": [],
                "failures": [],
                "risks": [],
                "commands": [],
                "followups": [],
                "omitted": [],
            }
        )
        with self.assertRaises(ModelOutputMalformed):
            compress_context.parse_and_validate(
                runaway, {"kind": "logs", "text": src, "focus": None, "max_items": 1}
            )

    def test_workspace_confined_context_path_on_compress_and_extract(self) -> None:
        from local_assist.tools import compress_context, extract_fields

        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "workspace"
            outside = Path(td) / "outside"
            log_dir = Path(td) / "logs"
            ws.mkdir()
            outside.mkdir()
            (ws / "logs").mkdir()
            (ws / "logs" / "app.log").write_text("ERROR in worker.py\n", encoding="utf-8")
            (ws / "invoice.txt").write_text("Total: 99 USD\n", encoding="utf-8")
            (ws / ".env").write_text("CANARY_CFG=1\n", encoding="utf-8")
            (outside / "secret.txt").write_text("outside\n", encoding="utf-8")
            (ws / "escape_link.txt").symlink_to(outside / "secret.txt")

            fake_comp = ChatResult(
                text=json.dumps(
                    {
                        "summary": "Worker error.",
                        "key_points": ["ERROR in worker.py"],
                        "changed_files": ["worker.py"],
                        "failures": ["ERROR in worker.py"],
                        "risks": [],
                        "commands": [],
                        "followups": [],
                        "omitted": [],
                    }
                ),
                raw_text="{}",
                served_model="mock-qwen",
                finish_reason="stop",
                usage={"prompt_tokens": 20, "completion_tokens": 20, "total_tokens": 40},
                latency_ms=50,
            )
            fake_ext = ChatResult(
                text=json.dumps(
                    {
                        "extracted": {"total": 99},
                        "extraction_note": None,
                    }
                ),
                raw_text="{}",
                served_model="mock-qwen",
                finish_reason="stop",
                usage={"prompt_tokens": 20, "completion_tokens": 15, "total_tokens": 35},
                latency_ms=40,
            )

            env = {
                "LOCAL_ASSIST_WORKSPACE_ROOT": str(ws),
                "LOCAL_ASSIST_LOG_DIR": str(log_dir),
            }
            with (
                patch.dict(os.environ, env, clear=False),
                patch.object(compress_context, "require_chat_succeeds", return_value="mock-qwen"),
                patch.object(compress_context, "chat", return_value=fake_comp),
                patch.object(extract_fields, "require_chat_succeeds", return_value="mock-qwen"),
                patch.object(extract_fields, "chat", return_value=fake_ext),
            ):
                comp_out = compress_context.run(kind="logs", context_path="logs/app.log", max_items=2)
                self.assertEqual(comp_out["summary"], "Worker error.")
                self.assertEqual(comp_out["changed_files"], ["worker.py"])

                ext_out = extract_fields.run(
                    context_path="invoice.txt",
                    fields={"total": {"type": "integer", "description": "invoice total", "required": True}},
                )
                self.assertEqual(ext_out["extracted"]["total"], 99)

                jsonl_files = list(log_dir.glob("*.jsonl"))
                self.assertEqual(len(jsonl_files), 1)
                logged_rows = [
                    json.loads(line)
                    for line in jsonl_files[0].read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                by_tool = {r["tool"]: r for r in logged_rows}
                self.assertEqual(by_tool["compress_context"]["observed"]["source_path"], "logs/app.log")
                self.assertEqual(by_tool["extract_fields"]["observed"]["source_path"], "invoice.txt")

                for bad_kwargs in (
                    {"kind": "logs", "text": "x", "context_path": "logs/app.log"},
                    {"kind": "logs"},
                    {"kind": "logs", "context_path": "../outside/secret.txt"},
                    {"kind": "logs", "context_path": str(outside / "secret.txt")},
                    {"kind": "logs", "context_path": "escape_link.txt"},
                    {"kind": "logs", "context_path": ".env"},
                ):
                    with self.assertRaises(LocalAssistError) as ctx:
                        compress_context.run(**bad_kwargs)
                    self.assertEqual(ctx.exception.code, "invalid_arguments")

    def test_delegate_task_coerces_structured_output_and_rejects_empty(self) -> None:
        from local_assist.tools import delegate_task

        validated = {
            "kind": "generate_test_cases",
            "instruction": "Generate boundary cases for check_limit(limit).",
            "context": "def check_limit(limit): return 0 < limit <= 5",
            "constraints": [],
        }
        structured = json.dumps(
            {
                "summary": "Two boundary cases around 0 and 5.",
                "output": [
                    {"name": "zero_budget", "input": {"limit": 0}, "expected": False},
                    {"name": "exact_cap", "input": {"limit": 5}, "expected": True},
                ],
                "assumptions": ["limit is non-negative"],
                "unverified_claims": [],
            }
        )
        parsed, meta = delegate_task.parse_and_validate_with_meta(structured, validated)
        self.assertIsInstance(parsed["output"], str)
        self.assertEqual(len(json.loads(parsed["output"])), 2)
        self.assertTrue(meta["coerced_structured_output"])

        for empty_val in ([], {}):
            with self.assertRaises(ModelOutputMalformed):
                delegate_task.parse_and_validate(
                    json.dumps(
                        {
                            "summary": "empty",
                            "output": empty_val,
                            "assumptions": [],
                            "unverified_claims": [],
                        }
                    ),
                    validated,
                )

    def test_propose_eval_prompts_normalizes_coverage_note_and_rejects_bad_js_syntax(self) -> None:
        from local_assist.tools import propose_eval_prompts

        raw_ok = json.dumps(
            {
                "prompts": [
                    {
                        "prompt": 'Return JSON {"count": 6}.',
                        "expected_signal": "Exact count field in JSON output.",
                        "assertion": "JSON.parse(output).count === 6",
                        "category": "structured_output",
                    }
                ],
                "coverage_note": "   ",
            }
        )
        full = propose_eval_prompts.parse_and_validate(raw_ok, n=1)
        self.assertIsNone(full["coverage_note"])

        partial = propose_eval_prompts.parse_and_validate(raw_ok, n=3)
        self.assertEqual(partial["coverage_note"], "Model returned 1 of 3 requested prompts.")

        bad_js = json.dumps(
            {
                "prompts": [
                    {
                        "prompt": "Prompt",
                        "expected_signal": "Broken JS assertion.",
                        "assertion": "output === (",
                        "category": "format",
                    }
                ],
                "coverage_note": None,
            }
        )
        with self.assertRaises(ModelOutputMalformed):
            propose_eval_prompts.parse_and_validate(bad_js, n=1)

    def test_check_eval_assertion_accuracy_and_os_sandbox_resource_bounds(self) -> None:
        from local_assist.tools import check_eval_assertion

        with tempfile.TemporaryDirectory() as td:
            log_dir = Path(td) / "logs"
            sentinel = Path(td) / "sentinel.txt"
            sentinel.write_text("TOP_SECRET_SENTINEL_VALUE", encoding="utf-8")

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(2)
                probe_port = listener.getsockname()[1]
                accepted: list[bool] = []

                def _accept_once() -> None:
                    listener.settimeout(1.0)
                    try:
                        conn, _ = listener.accept()
                        accepted.append(True)
                        conn.close()
                    except OSError:
                        pass

                t = threading.Thread(target=_accept_once, daemon=True)
                t.start()

                with patch.dict(os.environ, {"LOCAL_ASSIST_LOG_DIR": str(log_dir)}, clear=False):
                    # 1. Detects false rejects (overconstrained string vs number)
                    r1 = check_eval_assertion.run(
                        assertion={"type": "javascript", "value": 'JSON.parse(output).age === "30"'},
                        passing_outputs=['{"age": 30}', '{"age": "30"}'],
                        failing_outputs=['{"age": 25}'],
                    )
                    self.assertFalse(r1["passed"])
                    self.assertEqual(len(r1["false_rejects"]), 1)
                    self.assertEqual(r1["false_rejects"][0]["index"], 0)

                    # 2. Detects false accepts (unanchored numeric regex)
                    r2 = check_eval_assertion.run(
                        assertion={"type": "regex", "value": "6"},
                        passing_outputs=["6 hours"],
                        failing_outputs=["16 hours"],
                    )
                    self.assertFalse(r2["passed"])
                    self.assertEqual(len(r2["false_accepts"]), 1)

                    # 3. Synchronous infinite loop bounded
                    t0 = time.monotonic()
                    r3 = check_eval_assertion.run(
                        assertion={"type": "javascript", "value": "while (true) {}"},
                        passing_outputs=["ok"],
                        failing_outputs=["bad"],
                    )
                    self.assertLess(time.monotonic() - t0, 4.0)
                    self.assertFalse(r3["passed"])
                    self.assertGreaterEqual(len(r3["runtime_errors"]), 1)

                    # 4. Async hang / timer / Promise rejected without hanging exit
                    t0 = time.monotonic()
                    r4 = check_eval_assertion.run(
                        assertion={
                            "type": "javascript",
                            "value": "new Promise(() => {})",
                        },
                        passing_outputs=["ok"],
                        failing_outputs=["bad"],
                    )
                    self.assertLess(time.monotonic() - t0, 4.0)
                    self.assertFalse(r4["passed"])
                    self.assertGreaterEqual(len(r4["runtime_errors"]), 1)

                    # 5. Catastrophic backtracking regex bounded
                    t0 = time.monotonic()
                    r5 = check_eval_assertion.run(
                        assertion={"type": "regex", "value": "^(a+)+$"},
                        passing_outputs=["aaaa"],
                        failing_outputs=[("a" * 4096) + "!"],
                    )
                    self.assertLess(time.monotonic() - t0, 4.0)
                    self.assertFalse(r5["passed"])
                    self.assertGreaterEqual(len(r5["runtime_errors"]), 1)

                    # 6. Oversized heap allocation bounded under --max-old-space-size=64
                    r6 = check_eval_assertion.run(
                        assertion={
                            "type": "javascript",
                            "value": "(() => { const a = []; for (let i = 0; i < 10_000_000; i++) a.push({i}); return a.length > 0; })()",
                        },
                        passing_outputs=["ok"],
                        failing_outputs=["bad"],
                    )
                    self.assertFalse(r6["passed"])
                    self.assertGreaterEqual(len(r6["runtime_errors"]), 1)

                    # 7. Sentinel read/write & loopback escape blocked by Seatbelt + Node --permission + VM
                    escape_js = (
                        "(() => {"
                        f" const p = {json.dumps(str(sentinel))};"
                        " try { const req = this.constructor.constructor('return process')();"
                        "   req.mainModule.require('fs').writeFileSync(p, 'PWNED'); return true; } catch (e) {}"
                        f" try {{ fetch('http://127.0.0.1:{probe_port}'); }} catch (e) {{}}"
                        " return output === 'ok';"
                        "})()"
                    )
                    r7 = check_eval_assertion.run(
                        assertion={"type": "javascript", "value": escape_js},
                        passing_outputs=["ok"],
                        failing_outputs=["no"],
                    )
                    t.join(timeout=1.5)
                    self.assertEqual(sentinel.read_text(encoding="utf-8"), "TOP_SECRET_SENTINEL_VALUE")
                    self.assertNotIn("TOP_SECRET_SENTINEL_VALUE", json.dumps(r7))
                    self.assertEqual(accepted, [])

    def test_select_context_verbatim_slicing_and_bounds(self) -> None:
        from local_assist.tools import select_context

        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            f1 = ws / "alpha.py"
            lines = [f"line_{i}: value={i * 10}" for i in range(1, 26)]
            f1_text = "\n".join(lines) + "\n"
            f1.write_text(f1_text, encoding="utf-8")
            expected_sha = hashlib.sha256(f1_text.encode("utf-8")).hexdigest()

            fake_sel = ChatResult(
                text=json.dumps(
                    {
                        "selections": [
                            {
                                "path": "alpha.py",
                                "start_line": 3,
                                "end_line": 20,
                                "reason": "Defines key values.",
                            },
                            {
                                "path": "nonexistent.py",
                                "start_line": 1,
                                "end_line": 2,
                                "reason": "Hallucinated path.",
                            },
                        ],
                        "unanswered_aspects": ["deployment topology"],
                    }
                ),
                raw_text="{}",
                served_model="mock-qwen",
                finish_reason="stop",
                usage={"prompt_tokens": 80, "completion_tokens": 30, "total_tokens": 110},
                latency_ms=95,
            )
            env = {
                "LOCAL_ASSIST_WORKSPACE_ROOT": str(ws),
                "LOCAL_ASSIST_LOG_DIR": str(Path(td) / "logs"),
            }
            with (
                patch.dict(os.environ, env, clear=False),
                patch.object(select_context, "require_chat_succeeds", return_value="mock-qwen"),
                patch.object(select_context, "chat", return_value=fake_sel),
            ):
                out = select_context.run(
                    query="Where are values defined?",
                    paths=["alpha.py"],
                    max_excerpts=3,
                    max_lines_per_excerpt=6,
                )
            self.assertEqual(len(out["excerpts"]), 1)
            ex = out["excerpts"][0]
            self.assertEqual(ex["path"], "alpha.py")
            self.assertEqual(ex["start_line"], 3)
            self.assertEqual(ex["end_line"], 8)
            self.assertEqual(ex["excerpt"], "\n".join(lines[2:8]) + "\n")
            self.assertIn(ex["excerpt"], f1_text)
            self.assertEqual(ex["source_sha256"], expected_sha)
            self.assertEqual(out["unanswered_aspects"], ["deployment topology"])

    def test_assist_status_side_effect_free_annotations_and_codex_approval_gate(self) -> None:
        # 1. Verify exact MCP ToolAnnotations (LDF2)
        list_resp = handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        assert list_resp is not None
        tools_by_name = {t["name"]: t for t in list_resp["result"]["tools"]}
        self.assertEqual(
            sorted(tools_by_name),
            [
                "assist_status",
                "check_eval_assertion",
                "compress_context",
                "delegate_task",
                "extract_fields",
                "propose_eval_prompts",
                "select_context",
            ],
        )
        self.assertEqual(
            tools_by_name["assist_status"]["annotations"],
            {"readOnlyHint": True, "openWorldHint": False},
        )
        for logged_tool in (
            "check_eval_assertion",
            "compress_context",
            "delegate_task",
            "extract_fields",
            "propose_eval_prompts",
            "select_context",
        ):
            ann = tools_by_name[logged_tool]["annotations"]
            self.assertEqual(ann, {"readOnlyHint": False, "openWorldHint": False})
            self.assertNotIn("destructiveHint", ann)

        # 2. Verify assist_status performs zero LogCall writes, zero auto-serve, and leaks zero secrets
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            log_dir = tmp_path / "logs"
            runs_dir = tmp_path / "runs"
            runs_dir.mkdir()
            canary_val = "se-session-supersecretcanary99887766"
            tok_file = runs_dir / ".se-session-test.token"
            tok_file.write_text(canary_val, encoding="utf-8")
            (runs_dir / ".serve-tinfoil-deepseek-v4-1-flash-test.pid").write_text(
                json.dumps(
                    {
                        "model_id": "tinfoil-deepseek-v4-1-flash",
                        "pid": os.getpid(),
                        "port": 18081,
                        "started_at": "2026-11-14T06:00:00-0500",
                        "session_token_file": str(tok_file),
                        "ttl_seconds": 3600,
                        "max_chat_requests": 200,
                    }
                ),
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {
                    "LOCAL_ASSIST_LOG_DIR": str(log_dir),
                    "LOCAL_ASSIST_AUTO_SERVE": "1",
                    "LOCAL_ASSIST_WORKSPACE_ROOT": str(tmp_path),
                    "LOCAL_ASSIST_RUNS_DIR": str(runs_dir),
                    "SYNTHETIC_CANARY_ENV": canary_val,
                },
                clear=False,
            ):
                status_resp = handle_request(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "assist_status", "arguments": {}},
                    }
                )
            assert status_resp is not None
            self.assertFalse(status_resp["result"].get("isError", False))
            raw_status = json.dumps(status_resp)
            self.assertNotIn(canary_val, raw_status)
            self.assertFalse(log_dir.exists() and any(log_dir.iterdir()))

        # 3. Synthetic loopback codex exec -s read-only approval-gate test on new tool (LDF2 Round 3)
        codex_bin = shutil.which("codex")
        if not codex_bin or not Path("/usr/bin/sandbox-exec").is_file():
            self.skipTest("codex and /usr/bin/sandbox-exec required for live CLI approval-gate check")

        codex_turns: list[dict[str, Any]] = []

        class CodexApprovalHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_POST(self) -> None:
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
                        "id": "fc_chk",
                        "type": "function_call",
                        "call_id": "call_chk_01",
                        "namespace": "mcp__local_assist",
                        "name": "check_eval_assertion",
                        "arguments": json.dumps(
                            {
                                "assertion": {"type": "icontains", "value": "hello"},
                                "passing_outputs": ["hello world"],
                                "failing_outputs": ["goodbye"],
                            }
                        ),
                        "status": "completed",
                    }
                    events = [
                        (
                            "response.created",
                            {"type": "response.created", "response": {"id": "r1", "status": "in_progress", "output": []}},
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
                                    "id": "r1",
                                    "status": "completed",
                                    "output": [fc_item],
                                    "usage": {"input_tokens": 10, "output_tokens": 10, "total_tokens": 20},
                                },
                            },
                        ),
                    ]
                else:
                    msg_item = {
                        "id": "m2",
                        "type": "message",
                        "role": "assistant",
                        "status": "completed",
                        "content": [{"type": "output_text", "text": "APPROVAL_CHECK_DONE"}],
                    }
                    events = [
                        (
                            "response.created",
                            {"type": "response.created", "response": {"id": "r2", "status": "in_progress", "output": []}},
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
                                    "id": "r2",
                                    "status": "completed",
                                    "output": [msg_item],
                                    "usage": {"input_tokens": 15, "output_tokens": 5, "total_tokens": 20},
                                },
                            },
                        ),
                    ]
                for ev, data in events:
                    self.wfile.write(f"event: {ev}\ndata: {json.dumps(data)}\n\n".encode("utf-8"))
                self.wfile.flush()

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CodexApprovalHandler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as td:
                iso = Path(td)
                ws = iso / "ws"
                ws.mkdir()
                subprocess.run(["git", "init", "-q"], cwd=ws, check=True)
                audit_dir = iso / "audit"
                audit_dir.mkdir()
                codex_home = iso / "codex_home"
                codex_home.mkdir()
                mcp_wrapper = iso / "run_mcp.py"
                mcp_wrapper.write_text(
                    f"""#!{sys.executable} -B
import os, sys
os.environ["LOCAL_ASSIST_LOG_DIR"] = {str(audit_dir)!r}
os.environ["LOCAL_ASSIST_WORKSPACE_ROOT"] = {str(ws)!r}
sys.path.insert(0, {str(ROOT)!r})
import local_assist.server as srv
raise SystemExit(srv.main([]))
""",
                    encoding="utf-8",
                )
                mcp_wrapper.chmod(0o755)
                base_cfg = f"""model = "test-model"
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
command = "{mcp_wrapper}"
tool_timeout_sec = 60
"""
                env_codex = {
                    "PATH": os.environ.get("PATH", "/opt/homebrew/bin:/usr/bin:/bin"),
                    "HOME": str(iso),
                    "CODEX_HOME": str(codex_home),
                    "LOCAL_TEST_API_KEY": "synthetic-key",
                }
                # Unapproved: must block AND write 0 audit records
                (codex_home / "config.toml").write_text(base_cfg, encoding="utf-8")
                codex_turns.clear()
                p_unapproved = subprocess.run(
                    [codex_bin, "exec", "--strict-config", "-s", "read-only", "Check assertion"],
                    cwd=ws,
                    env=env_codex,
                    capture_output=True,
                    text=True,
                    timeout=25,
                )
                self.assertEqual(p_unapproved.returncode, 0, p_unapproved.stderr)
                fc_outs_1 = [
                    i
                    for i in codex_turns[-1].get("input", [])
                    if isinstance(i, dict) and i.get("type") == "function_call_output"
                ]
                self.assertIn("requires approval", json.dumps(fc_outs_1))
                self.assertEqual(list(audit_dir.glob("*.jsonl")), [])

                # Approved: must execute check_eval_assertion AND write 1 audit JSONL file
                (codex_home / "config.toml").write_text(
                    base_cfg
                    + '\n[mcp_servers.local_assist.tools.check_eval_assertion]\napproval_mode = "approve"\n',
                    encoding="utf-8",
                )
                codex_turns.clear()
                p_approved = subprocess.run(
                    [codex_bin, "exec", "--strict-config", "-s", "read-only", "Check assertion"],
                    cwd=ws,
                    env=env_codex,
                    capture_output=True,
                    text=True,
                    timeout=25,
                )
                self.assertEqual(p_approved.returncode, 0, p_approved.stderr)
                fc_outs_2 = [
                    i
                    for i in codex_turns[-1].get("input", [])
                    if isinstance(i, dict) and i.get("type") == "function_call_output"
                ]
                self.assertEqual(len(fc_outs_2), 1)
                self.assertIn('"passed":true', str(fc_outs_2[0].get("output", "")).replace(" ", "").replace("\n", ""))
                self.assertEqual(len(list(audit_dir.glob("*.jsonl"))), 1)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_eval_local_assist_dogfood_validate_fixtures(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "eval-local-assist-dogfood"), "--validate-fixtures"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        summary = json.loads(proc.stdout)
        self.assertTrue(summary["fixtures_valid"])
        self.assertTrue(summary.get("oracle_selftests_passed"))
        self.assertGreaterEqual(summary["seen_count"], 4)
        self.assertGreaterEqual(summary["unseen_count"], 3)

    def test_workspace_confinement_blocks_directory_swap_toctou_race(self) -> None:
        from local_assist.workspace import read_confined_workspace_file

        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            ws = base / "ws"
            sub = ws / "sub"
            outside = base / "outside"
            sub.mkdir(parents=True)
            outside.mkdir(parents=True)
            (sub / "note.txt").write_text("INSIDE_SAFE_TEXT", encoding="utf-8")
            (outside / "note.txt").write_text("OUTSIDE_SENTINEL_TEXT", encoding="utf-8")

            # Race 1: intermediate directory replaced with outside symlink right before step open.
            def _swap_before_dir(stage: str, seg: str) -> None:
                if stage == "dir" and seg == "sub":
                    os.rename(sub, base / "sub_parked")
                    os.symlink(outside, sub)

            with self.assertRaises(ModelOutputMalformed):
                read_confined_workspace_file(
                    "sub/note.txt",
                    workspace_root=ws,
                    max_bytes=4096,
                    _step_hook=_swap_before_dir,
                )
            self.assertTrue(sub.is_symlink())
            sub.unlink()
            os.rename(base / "sub_parked", sub)

            # Race 2: intermediate directory swapped on pathname AFTER descriptor pin, before leaf open.
            # Pinned cur_fd stays on original directory (never follows pathname swap to outside).
            def _swap_before_leaf(stage: str, seg: str) -> None:
                if stage == "leaf" and seg == "note.txt":
                    os.rename(sub, base / "sub_moved_outside_ws")
                    os.symlink(outside, sub)

            with self.assertRaises(ModelOutputMalformed):
                read_confined_workspace_file(
                    "sub/note.txt",
                    workspace_root=ws,
                    max_bytes=4096,
                    _step_hook=_swap_before_leaf,
                )
            sub.unlink()
            os.rename(base / "sub_moved_outside_ws", sub)

            # Race 3: pathname swapped to outside symlink while original directory stays inside ws:
            # descriptor-pinned open reads INSIDE_SAFE_TEXT (never OUTSIDE_SENTINEL_TEXT).
            sub_backup = ws / "sub_pinned_inside"

            def _swap_inside_ws(stage: str, seg: str) -> None:
                if stage == "leaf" and seg == "note.txt":
                    os.rename(sub, sub_backup)
                    os.symlink(outside, sub)

            _, content, _ = read_confined_workspace_file(
                "sub/note.txt",
                workspace_root=ws,
                max_bytes=4096,
                _step_hook=_swap_inside_ws,
            )
            self.assertEqual(content, "INSIDE_SAFE_TEXT")
            self.assertNotIn("OUTSIDE_SENTINEL_TEXT", content)

            # Simulated Linux /proc/self/fd/<fd> confinement checks
            from local_assist import workspace as ws_mod

            with (
                patch.object(ws_mod.sys, "platform", "linux"),
                patch.object(ws_mod.os, "readlink", return_value=str(sub)),
            ):
                self.assertTrue(ws_mod._descriptor_within_workspace(42, ws))

            with (
                patch.object(ws_mod.sys, "platform", "linux"),
                patch.object(ws_mod.os, "readlink", return_value=str(outside)),
            ):
                self.assertFalse(ws_mod._descriptor_within_workspace(42, ws))

            with (
                patch.object(ws_mod.sys, "platform", "linux"),
                patch.object(ws_mod.os, "readlink", return_value=str(sub) + " (deleted)"),
            ):
                self.assertFalse(ws_mod._descriptor_within_workspace(42, ws))

            with (
                patch.object(ws_mod.sys, "platform", "linux"),
                patch.object(ws_mod.os, "readlink", side_effect=OSError("procfs unavailable")),
            ):
                self.assertFalse(ws_mod._descriptor_within_workspace(42, ws))

    def test_assertion_executor_enforces_seatbelt_on_ordinary_node_and_inherited_policy(self) -> None:
        from local_assist.launch import _locate_host_node_binary, _provision_dedicated_local_assist_python
        from local_assist.security_profile import compile_interactive_seatbelt_profile
        from local_assist.tools import check_eval_assertion

        host_node = _locate_host_node_binary()
        self.assertIsNotNone(host_node)
        assert host_node is not None
        sandbox_exec = Path("/usr/bin/sandbox-exec")
        if not sandbox_exec.is_file():
            self.skipTest("/usr/bin/sandbox-exec unavailable")

        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            sentinel = base / "sentinel_secret.txt"
            sentinel.write_text("ORDINARY_NODE_SENTINEL", encoding="utf-8")
            pwned = base / "pwned_write.txt"

            # Stage an ordinary writable (0755) Node copy under base / "ordinary" / "bin" / "node"
            ord_root = base / "ordinary"
            (ord_root / "bin").mkdir(parents=True)
            ord_node = ord_root / "bin" / "node"
            shutil.copy2(host_node, ord_node)
            os.chmod(ord_node, 0o755)
            for cand_lib in (host_node.parent.parent / "lib", Path("/opt/homebrew/opt/node/lib")):
                if cand_lib.is_dir():
                    dylibs = list(cand_lib.glob("libnode*.dylib"))
                    if dylibs:
                        (ord_root / "lib").mkdir(exist_ok=True)
                        for dy in dylibs:
                            shutil.copy2(dy, ord_root / "lib" / dy.name)
                        break

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(2)
                probe_port = listener.getsockname()[1]
                accepted: list[bool] = []

                def _accept_loop() -> None:
                    listener.settimeout(0.8)
                    try:
                        conn, _ = listener.accept()
                        accepted.append(True)
                        conn.close()
                    except OSError:
                        pass

                t_srv = threading.Thread(target=_accept_loop, daemon=True)
                t_srv.start()

                with mock.patch.dict(
                    os.environ,
                    {
                        "LOCAL_ASSIST_ASSERTION_NODE_BIN": str(ord_node),
                        "LOCAL_ASSIST_WORKER_SANDBOX": "1",
                        "LOCAL_ASSIST_LOG_DIR": str(base / "logs"),
                    },
                    clear=False,
                ):
                    cmd = check_eval_assertion._resolve_sandboxed_node_command()
                    self.assertEqual(cmd[0], "/usr/bin/sandbox-exec")

                    res_ok = check_eval_assertion.run(
                        assertion={"type": "javascript", "value": "JSON.parse(output).ok === true"},
                        passing_outputs=['{"ok": true}'],
                        failing_outputs=['{"ok": false}'],
                    )
                    self.assertTrue(res_ok["passed"])

                    attack_js = (
                        f"(() => {{"
                        f" try {{ const fs = process.mainModule ? process.mainModule.require('fs') : require('fs');"
                        f"   if (fs.readFileSync({json.dumps(str(sentinel))}, 'utf8').includes('SENTINEL')) return true;"
                        f" }} catch (e) {{}}"
                        f" try {{ const fs = require('fs'); fs.writeFileSync({json.dumps(str(pwned))}, 'x'); return true; }} catch (e) {{}}"
                        f" try {{ const cp = require('child_process'); const r = cp.spawnSync('/bin/echo', ['hi']);"
                        f"   if (r && r.status === 0) return true; }} catch (e) {{}}"
                        f" try {{ const net = require('net'); const s = net.connect({probe_port}, '127.0.0.1'); }} catch (e) {{}}"
                        f" return output === 'expected';"
                        f"}})()"
                    )
                    res_attack = check_eval_assertion.run(
                        assertion={"type": "javascript", "value": attack_js},
                        passing_outputs=["expected"],
                        failing_outputs=["other"],
                    )
                    t_srv.join(timeout=1.5)
                    self.assertTrue(res_attack["passed"])
                    self.assertFalse(pwned.exists())
                    self.assertEqual(accepted, [])

            # Part 2: positive + negative verification inside generated compile_interactive_seatbelt_profile
            ws_dir = base / "ws"
            iso_home = base / "iso-home"
            inv_dir = iso_home / ".invocations" / "inv-test"
            runs_dir = base / "runs"
            (runs_dir / "local-assist").mkdir(parents=True)
            ws_dir.mkdir(parents=True)
            (inv_dir / "bin").mkdir(parents=True)
            (inv_dir / ".tmp").mkdir(parents=True)
            fake_opencode = base / "fake-opencode"
            fake_opencode.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(fake_opencode, 0o755)

            _provision_dedicated_local_assist_python(inv_dir)
            (inv_dir / "opencode.json").write_text('{"secret":"REDACTED"}\n', encoding="utf-8")
            os.chmod(inv_dir / "opencode.json", 0o400)
            os.chmod(inv_dir, 0o700)

            with mock.patch.dict(
                os.environ, {"FREE_INFERENCE_RUNS_DIR": str(runs_dir.resolve())}, clear=False
            ):
                sb_text = compile_interactive_seatbelt_profile(
                    workspace_dir=ws_dir,
                    isolated_home=iso_home,
                    invocation_dir=inv_dir,
                    opencode_bin=fake_opencode,
                    sandbox_exec_bin=sandbox_exec,
                    service_port=54321,
                )
            # Compile an identical profile allowing sandbox-exec -> local-assist-python directly for test launch
            la_py = inv_dir.resolve() / "bin" / "local-assist-python"
            sb_test = (
                sb_text
                + f'\n(allow process-exec (require-all (process-path "{sandbox_exec.resolve()}") (literal "{la_py}")))\n'
            )
            sb_file = base / "inherited_test.sb"
            sb_file.write_text(sb_test, encoding="utf-8")

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener2:
                listener2.bind(("127.0.0.1", 0))
                listener2.listen(2)
                probe_port2 = listener2.getsockname()[1]
                accepted2: list[bool] = []

                def _accept_loop2() -> None:
                    listener2.settimeout(1.2)
                    try:
                        conn, _ = listener2.accept()
                        accepted2.append(True)
                        conn.close()
                    except OSError:
                        pass

                t_srv2 = threading.Thread(target=_accept_loop2, daemon=True)
                t_srv2.start()

                py_snippet = """
import json, os, sys
from local_assist.tools import check_eval_assertion
cmd = check_eval_assertion._resolve_sandboxed_node_command()
ok_res = check_eval_assertion.run(
    assertion={"type": "javascript", "value": "JSON.parse(output).n === 7"},
    passing_outputs=['{"n": 7}'],
    failing_outputs=['{"n": 8}'],
)
sentinel_js = json.dumps(os.environ["TEST_SENTINEL_PATH"])
pwned_js = json.dumps(os.environ["TEST_PWNED_PATH"])
probe_port = int(os.environ["TEST_PROBE_PORT"])
atk_js = (
    "(() => {"
    f" try {{ const fs = require('fs'); if (fs.readFileSync({sentinel_js}, 'utf8')) return true; }} catch (e) {{}}"
    f" try {{ const fs = require('fs'); fs.writeFileSync({pwned_js}, 'y'); return true; }} catch (e) {{}}"
    " try { const cp = require('child_process'); const r = cp.spawnSync('/bin/echo', ['x']); if (r && r.status === 0) return true; } catch (e) {}"
    f" try {{ const net = require('net'); net.connect({probe_port}, '127.0.0.1'); }} catch (e) {{}}"
    " return output === 'good';"
    "})()"
)
atk_res = check_eval_assertion.run(
    assertion={"type": "javascript", "value": atk_js},
    passing_outputs=["good"],
    failing_outputs=["bad"],
)
print(json.dumps({"cmd0": cmd[0], "ok": ok_res["passed"], "atk": atk_res["passed"]}))
"""
                env_inh = {
                    "PATH": "/usr/bin:/bin",
                    "HOME": str(iso_home),
                    "TMPDIR": str(inv_dir.resolve() / ".tmp"),
                    "PYTHONSAFEPATH": "1",
                    "PYTHONNOUSERSITE": "1",
                    "LOCAL_ASSIST_WORKER_SANDBOX": "1",
                    "LOCAL_ASSIST_ASSERTION_NODE_BIN": str(inv_dir.resolve() / "bin" / "local-assist-node"),
                    "LOCAL_ASSIST_LOG_DIR": str(runs_dir.resolve() / "local-assist"),
                    "FREE_INFERENCE_RUNS_DIR": str(runs_dir.resolve()),
                    "TEST_SENTINEL_PATH": str(sentinel),
                    "TEST_PWNED_PATH": str(pwned),
                    "TEST_PROBE_PORT": str(probe_port2),
                }
                proc_inh = subprocess.run(
                    [str(sandbox_exec), "-f", str(sb_file), str(la_py), "-I", "-c", py_snippet],
                    cwd=str(inv_dir.resolve() / "runtime"),
                    env=env_inh,
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
                t_srv2.join(timeout=1.5)
                self.assertEqual(proc_inh.returncode, 0, proc_inh.stderr)
                parsed_inh = json.loads(proc_inh.stdout.strip())
                self.assertEqual(
                    Path(parsed_inh["cmd0"]).resolve(),
                    (inv_dir.resolve() / "bin" / "local-assist-node").resolve(),
                )
                self.assertTrue(parsed_inh["ok"])
                self.assertTrue(parsed_inh["atk"])
                self.assertFalse(pwned.exists())
                self.assertEqual(accepted2, [])

    def test_eval_local_assist_dogfood_behavioral_oracles_and_live_gate(self) -> None:
        import importlib.machinery
        import importlib.util

        harness_path = ROOT / "scripts" / "eval-local-assist-dogfood"
        loader = importlib.machinery.SourceFileLoader("eval_local_assist_dogfood_mod", str(harness_path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        assert spec is not None
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)

        # Seen generated-test oracle rejects plausible prose or wrong boundary expectations
        self.assertFalse(
            mod.grade_sliding_counter_test_cases(
                {"output": "Here are 5 thorough unit test cases covering SlidingCounter."}
            )
        )
        self.assertFalse(
            mod.grade_sliding_counter_test_cases(
                {
                    "output": json.dumps(
                        [
                            {"calls": [[1.0], [2.0], [3.0], [4.0]], "expected": [True, True, True, True]},
                            {"calls": [[1.0], [2.0], [3.0], [4.1]], "expected": [True, True, True, True]},
                        ]
                    )
                }
            )
        )

        # Held-out parse_window oracle rejects stub ValueError raiser and empty assumptions
        self.assertFalse(
            mod.grade_parse_window_implementation(
                {
                    "output": "def parse_window(spec: str) -> int:\n    raise ValueError('bad')\n",
                    "assumptions": ["Raises on everything"],
                }
            )
        )
        self.assertFalse(
            mod.grade_parse_window_implementation(
                {
                    "output": (
                        "def parse_window(spec: str) -> int:\n"
                        "    if not isinstance(spec, str): raise ValueError('type')\n"
                        "    s = spec.strip()\n"
                        "    if len(s) < 2 or s[-1] not in ('s', 'm', 'h') or not s[:-1].isdigit(): raise ValueError('bad')\n"
                        "    v = int(s[:-1])\n"
                        "    if v <= 0: raise ValueError('zero')\n"
                        "    return v * {'s': 1, 'm': 60, 'h': 3600}[s[-1]]\n"
                    ),
                    "assumptions": [],
                }
            )
        )

        # Prompt-generation oracle accepts prompt-consistent assertions and rejects tautological,
        # brittle, contradictory-value, wrong-key, wrong-type, and ungrounded candidates (LDF-W3).
        self.assertTrue(
            mod.grade_proposed_eval_prompts(
                {
                    "prompts": [
                        {
                            "id": "good1",
                            "prompt": 'Return JSON {"status": "ok", "count": 6}.',
                            "expected_signal": "Exact JSON fields",
                            "assertion": '(() => { const d = JSON.parse(output); return d.status === "ok" && d.count === 6; })()',
                            "category": "structured_output",
                        }
                    ],
                    "coverage_note": "1 of 2",
                }
            )
        )
        for bad_id, bad_assertion in (
            ("tautology", "output.includes('status')"),
            ("wrong_value", "JSON.parse(output).count === 7"),
            ("wrong_value_multi", '(() => { const d = JSON.parse(output); return d.status === "ok" && d.count === 7; })()'),
            ("wrong_key", "JSON.parse(output).total === 6"),
            ("wrong_type", "typeof JSON.parse(output).count === 'string'"),
            ("wrong_type_eq", 'JSON.parse(output).count === "6"'),
            ("loose_eq", '(() => { const d = JSON.parse(output); return d.status === "ok" && d.count == 6; })()'),
        ):
            self.assertFalse(
                mod.grade_proposed_eval_prompts(
                    {
                        "prompts": [
                            {
                                "id": bad_id,
                                "prompt": 'Return JSON {"status": "ok", "count": 6}.',
                                "expected_signal": f"Negative case {bad_id}",
                                "assertion": bad_assertion,
                                "category": "structured_output",
                            }
                        ],
                        "coverage_note": "1 of 2",
                    }
                ),
                f"Expected contradictory/weak assertion {bad_id} to fail",
            )

        # Prompts without an anchored constant-output specification (open-ended wording, input
        # transformation examples, illustrative examples, negations, or trailing modifiers) are
        # classified as ungraded and never counted as automatic semantic passes (LDF-W3).
        for ug_id, ug_prompt, ug_assert in (
            (
                "open1",
                "Return a JSON summary with fields status and count.",
                "JSON.parse(output).count === 7",
            ),
            (
                "input_transform",
                'Given {"count": 6}, return JSON with count increased by one.',
                "JSON.parse(output).count === 6",
            ),
            (
                "example_clause",
                'For example, {"count": 6} shows the schema. Return JSON for zero items.',
                "JSON.parse(output).count === 6",
            ),
            (
                "negation_do_not",
                'Do not return JSON {"count": 6}.',
                "JSON.parse(output).count === 6",
            ),
            (
                "negation_other_than",
                'Return JSON other than {"count": 6}.',
                "JSON.parse(output).count === 6",
            ),
            (
                "trailing_transform",
                'Return JSON {"count": 6} with count increased by one.',
                "JSON.parse(output).count === 6",
            ),
            (
                "two_json_objects",
                'Return JSON {"count": 6} instead of {"count": 7}.',
                "JSON.parse(output).count === 6",
            ),
            (
                "nested_non_scalar",
                'Return JSON {"nested": {"count": 6}}.',
                'typeof JSON.parse(output).nested.count === "number"',
            ),
        ):
            payload = {
                "prompts": [
                    {
                        "id": ug_id,
                        "prompt": ug_prompt,
                        "expected_signal": f"Ambiguous/non-constant case {ug_id}",
                        "assertion": ug_assert,
                        "category": "structured_output",
                    }
                ],
                "coverage_note": "1 of 2",
            }
            ungraded_res = mod.evaluate_proposed_eval_prompts(payload)
            self.assertFalse(ungraded_res["passed"], ug_id)
            self.assertEqual(ungraded_res["ungraded_count"], 1, ug_id)
            self.assertFalse(mod.grade_proposed_eval_prompts(payload), ug_id)

        # --live without --operator-approved must exit 2 immediately without contacting :8080
        proc_blocked = subprocess.run(
            [sys.executable, str(harness_path), "--live", "--repeats", "1"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(proc_blocked.returncode, 2)
        self.assertIn("--operator-approved", proc_blocked.stderr)

    def test_cli_assist_status_json_delegate_local_aliases_and_contract_guards(self) -> None:
        from local_assist.client import ChatResult
        from local_assist.tools import delegate_task, propose_eval_prompts

        p_as = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "assist-status"), "--json"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(p_as.returncode, 0, p_as.stderr)
        as_json = json.loads(p_as.stdout)
        self.assertIn("active_sessions", as_json)
        seen_keys = [
            (s.get("model_id"), s.get("pid"), s.get("port")) for s in as_json["active_sessions"]
        ]
        self.assertEqual(len(seen_keys), len(set(seen_keys)))

        p_dl = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "delegate-local"), "status"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(p_dl.returncode, 0, p_dl.stderr)
        self.assertEqual(json.loads(p_dl.stdout)["server"]["name"], "local-assist-server")

        # Partial batch retention when n >= 2 and one candidate has fenced JS or syntax error
        mixed_batch = json.dumps(
            {
                "prompts": [
                    {
                        "prompt": 'Return JSON {"count": 6}.',
                        "expected_signal": "Valid candidate 1",
                        "assertion": "JSON.parse(output).count === 6",
                        "category": "structured_output",
                    },
                    {
                        "prompt": "Broken fenced assertion",
                        "expected_signal": "Invalid fenced assertion",
                        "assertion": "```javascript\nreturn true;\n```",
                        "category": "format",
                    },
                    {
                        "prompt": 'Return JSON {"ok": true}.',
                        "expected_signal": "Valid candidate 2",
                        "assertion": "JSON.parse(output).ok === true",
                        "category": "structured_output",
                    },
                ],
                "coverage_note": None,
            }
        )
        retained = propose_eval_prompts.parse_and_validate(mixed_batch, n=3)
        self.assertEqual(len(retained["prompts"]), 2)
        self.assertIsNotNone(retained["coverage_note"])
        self.assertIn("Retained 2 of 3", str(retained["coverage_note"]))

        # delegate_task rejects finish_reason == "length" with output_truncated
        with tempfile.TemporaryDirectory() as td:
            with (
                mock.patch.dict(os.environ, {"LOCAL_ASSIST_LOG_DIR": td}, clear=False),
                mock.patch("local_assist.tools.delegate_task.require_chat_succeeds"),
                mock.patch(
                    "local_assist.tools.delegate_task.chat",
                    return_value=ChatResult(
                        text='{"summary":"s","output":"cut","assumptions":[],"unverified_claims":[]}',
                        raw_text='{"summary":"s","output":"cut","assumptions":[],"unverified_claims":[]}',
                        served_model="mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
                        usage={"prompt_tokens": 20, "completion_tokens": 256},
                        latency_ms=50,
                        finish_reason="length",
                    ),
                ),
            ):
                with self.assertRaises(ModelOutputMalformed) as ctx:
                    delegate_task.run(kind="focused_qa", instruction="Explain why.", max_tokens=256)
                self.assertEqual(ctx.exception.code, "output_truncated")

    def test_f2_assist_status_zero_credential_reads_and_unauthenticated_probe(self) -> None:
        from local_assist.tools import assist_status

        captured_headers: list[dict[str, str]] = []

        class UnauthModelsHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                captured_headers.append({k.lower(): v for k, v in self.headers.items()})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {
                            "object": "list",
                            "data": [{"id": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit"}],
                        }
                    ).encode("utf-8")
                )

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), UnauthModelsHandler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as td:
                tmp_path = Path(td)
                runs_dir = tmp_path / "runs"
                runs_dir.mkdir()
                tok_file = runs_dir / ".se-session-secret.token"
                tok_file.write_text("se-session-neverreadthis998877665544", encoding="utf-8")
                (runs_dir / ".serve-qwen3-30b-a3b-2507-mlx-4bit.pid").write_text(
                    json.dumps(
                        {
                            "model_id": "qwen3-30b-a3b-2507-mlx-4bit",
                            "pid": os.getpid(),
                            "port": port,
                            "status": "ready",
                            "hf_offline": True,
                            "session_token_file": str(tok_file),
                        }
                    ),
                    encoding="utf-8",
                )
                (runs_dir / ".serve-tinfoil-deepseek-v4-1-flash.pid").write_text(
                    json.dumps(
                        {
                            "model_id": "tinfoil-deepseek-v4-1-flash",
                            "pid": os.getpid(),
                            "port": 18081,
                            "session_token_file": str(tok_file),
                        }
                    ),
                    encoding="utf-8",
                )

                env_reads: list[str] = []
                real_env = dict(os.environ)
                real_env.update(
                    {
                        "LOCAL_ASSIST_RUNS_DIR": str(runs_dir),
                        "LOCAL_ASSIST_WORKSPACE_ROOT": str(tmp_path),
                        "LOCAL_ASSIST_API_KEY": "sk-inherited-secret-never-touch",
                        "OPENAI_API_KEY": "sk-openai-secret-never-touch",
                        "LOCAL_ASSIST_SESSION_TOKEN": "se-session-env-never-touch-11223344",
                    }
                )

                class AuditedEnv(dict):  # type: ignore[type-arg]
                    def get(self, key: str, default: Any = None) -> Any:
                        env_reads.append(str(key))
                        return super().get(key, default)

                    def __getitem__(self, key: str) -> Any:
                        env_reads.append(str(key))
                        return super().__getitem__(key)

                opened_paths: list[str] = []
                orig_read_text = Path.read_text

                def _spy_read_text(self_path: Path, *a: Any, **kw: Any) -> str:
                    opened_paths.append(str(self_path))
                    return orig_read_text(self_path, *a, **kw)

                with (
                    mock.patch.object(os, "environ", AuditedEnv(real_env)),
                    mock.patch.object(Path, "read_text", _spy_read_text),
                ):
                    res = assist_status.run()

                self.assertTrue(res["rung1_local"]["live_served"])
                self.assertEqual(len(captured_headers), 1)
                self.assertNotIn("authorization", captured_headers[0])
                forbidden_env = {
                    k
                    for k in env_reads
                    if any(s in k.upper() for s in ("API_KEY", "TOKEN", "PASSWORD", "SECRET"))
                }
                self.assertEqual(forbidden_env, set())
                self.assertFalse(
                    any(".token" in p for p in opened_paths),
                    f"assist_status must never open token files, opened: {opened_paths}",
                )
        finally:
            srv.shutdown()
            srv.server_close()

    def test_f8_select_context_preserves_crlf_and_ascii_line_coordinates(self) -> None:
        from local_assist.tools import select_context

        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            crlf_file = ws / "crlf_unicode.txt"
            raw_bytes = b"alpha\r\nbeta\xe2\x80\xa8same_line\r\ngamma\r\ndelta_no_nl"
            crlf_file.write_bytes(raw_bytes)
            raw_text = raw_bytes.decode("utf-8")

            fake_sel = ChatResult(
                text=json.dumps(
                    {
                        "selections": [
                            {
                                "path": "crlf_unicode.txt",
                                "start_line": 1,
                                "end_line": 3,
                                "reason": "CRLF and Unicode line-separator span.",
                            },
                            {
                                "path": "crlf_unicode.txt",
                                "start_line": 4,
                                "end_line": 4,
                                "reason": "Final line without newline.",
                            },
                        ],
                        "unanswered_aspects": [],
                    }
                ),
                raw_text="{}",
                served_model="mock-qwen",
                finish_reason="stop",
                usage={"prompt_tokens": 40, "completion_tokens": 20, "total_tokens": 60},
                latency_ms=30,
            )
            env = {
                "LOCAL_ASSIST_WORKSPACE_ROOT": str(ws),
                "LOCAL_ASSIST_LOG_DIR": str(Path(td) / "logs"),
            }
            with (
                patch.dict(os.environ, env, clear=False),
                patch.object(select_context, "require_chat_succeeds", return_value="mock-qwen"),
                patch.object(select_context, "chat", return_value=fake_sel),
            ):
                out = select_context.run(query="Check CRLF and u2028", paths=["crlf_unicode.txt"])

            self.assertEqual(len(out["excerpts"]), 2)
            ex1, ex2 = out["excerpts"]
            self.assertEqual(ex1["excerpt"], "alpha\r\nbeta\u2028same_line\r\ngamma\r\n")
            self.assertIn(ex1["excerpt"], raw_text)
            self.assertEqual(ex2["start_line"], 4)
            self.assertEqual(ex2["end_line"], 4)
            self.assertEqual(ex2["excerpt"], "delta_no_nl")
            self.assertIn(ex2["excerpt"], raw_text)

    def test_f9_iso_p4_evaluate_proposed_eval_prompts_batches_count_and_executor_bytes(self) -> None:
        import importlib.machinery
        import importlib.util
        from local_assist.tools import check_eval_assertion

        harness_path = ROOT / "scripts" / "eval-local-assist-dogfood"
        loader = importlib.machinery.SourceFileLoader("eval_local_assist_dogfood_f9", str(harness_path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        assert spec is not None
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)

        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"LOCAL_ASSIST_LOG_DIR": td}, clear=False):
                # 1. 4-field flat JSON (26 failing mutations > 20 per-side limit): valid passes, weak fails
                good_4 = {
                    "prompts": [
                        {
                            "prompt": 'Return JSON {"a":1,"b":2,"c":3,"d":4}.',
                            "assertion": (
                                "const o = JSON.parse(output); "
                                "o !== null && typeof o === 'object' && !Array.isArray(o) && "
                                "Object.keys(o).length === 4 && o.a === 1 && o.b === 2 && o.c === 3 && o.d === 4"
                            ),
                        }
                    ],
                    "coverage_note": None,
                }
                res_good = mod.evaluate_proposed_eval_prompts(good_4)
                self.assertTrue(res_good["passed"], res_good)
                self.assertEqual(res_good["passed_count"], 1)

                weak_4 = {
                    "prompts": [
                        {
                            "prompt": 'Return JSON {"a":1,"b":2,"c":3,"d":4}.',
                            "assertion": "const o = JSON.parse(output); o.a === 1 && o.b === 2 && o.c === 3",
                        }
                    ],
                    "coverage_note": None,
                }
                res_weak = mod.evaluate_proposed_eval_prompts(weak_4)
                self.assertFalse(res_weak["passed"], res_weak)
                self.assertEqual(res_weak["failed_count"], 1)

                # 2. Aggregate byte-budget batching (ISO-P4): 3 numeric fields + 15,900-char string
                # produces <= 20 failing candidates individually < 16,384 bytes, but > 262,144 bytes aggregate!
                big_str = "x" * 15900
                big_obj = {"n1": 1, "n2": 2, "n3": 3, "blob": big_str}
                big_prompt = f"Return JSON {json.dumps(big_obj)}."
                big_payload = {
                    "prompts": [
                        {
                            "prompt": big_prompt,
                            "assertion": (
                                "const o = JSON.parse(output); "
                                "o !== null && typeof o === 'object' && !Array.isArray(o) && "
                                "Object.keys(o).length === 4 && o.n1 === 1 && o.n2 === 2 && o.n3 === 3 && "
                                "o.blob === 'x'.repeat(15900)"
                            ),
                        }
                    ],
                    "coverage_note": None,
                }
                res_big = mod.evaluate_proposed_eval_prompts(big_payload)
                self.assertTrue(res_big["passed"], res_big)

                # 3. JSON-escaping overhead control (ISO-P4): raw candidates sum to ~245 KB (< 262,144),
                # each candidate is ~14.4 KB (< 16,384), and <= 20 candidates per side, yet JSON string
                # escaping inside the executor payload expands aggregate size above 400 KB (> 262,144).
                esc_str = ('"\\\n\t' * 1800)
                esc_obj = {"n1": 1, "n2": 2, "n3": 3, "s": esc_str}
                esc_payload = {
                    "prompts": [
                        {
                            "prompt": f"Return JSON {json.dumps(esc_obj)}.",
                            "assertion": (
                                "const o = JSON.parse(output); "
                                "o !== null && typeof o === 'object' && !Array.isArray(o) && "
                                "Object.keys(o).length === 4 && o.n1 === 1 && o.n2 === 2 && o.n3 === 3 && "
                                "o.s === '\"\\\\\\n\\t'.repeat(1800)"
                            ),
                        }
                    ],
                    "coverage_note": None,
                }
                res_esc = mod.evaluate_proposed_eval_prompts(esc_payload)
                self.assertTrue(res_esc["passed"], res_esc)

                # 4. Impossible minimum 1+1 batch -> classified ungraded before check_eval_assertion.run
                with patch.object(check_eval_assertion, "MAX_STDIN_PAYLOAD_BYTES", 20000):
                    with patch.object(check_eval_assertion, "run") as spy_run:
                        res_impossible = mod.evaluate_proposed_eval_prompts(big_payload)
                        self.assertFalse(res_impossible["passed"])
                        self.assertEqual(res_impossible["ungraded_count"], 1)
                        spy_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
