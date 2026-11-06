from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from contextlib import AbstractContextManager
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from .paths import LOCAL_ASSIST_RUNS, ROOT


LOCAL_TZ = ZoneInfo("America/New_York")


def now_local() -> datetime:
    return datetime.now(tz=LOCAL_TZ)


def summarize_args(args: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    if "seed" in args and isinstance(args["seed"], str):
        summary["seed_chars"] = len(args["seed"])
    if "n" in args:
        summary["n_requested"] = args["n"]
    if "language" in args:
        summary["language"] = args["language"]
    if "category" in args and isinstance(args["category"], str):
        summary["category"] = args["category"]
    if "text_chars" in args and isinstance(args["text_chars"], int):
        summary["text_chars"] = args["text_chars"]
    elif "text" in args and isinstance(args["text"], str):
        summary["text_chars"] = len(args["text"])
    if "text_sha256" in args and isinstance(args["text_sha256"], str):
        summary["text_sha256"] = args["text_sha256"]
    elif "text" in args and isinstance(args["text"], str) and args["text"]:
        summary["text_sha256"] = hashlib.sha256(args["text"].encode("utf-8")).hexdigest()
    if "fields" in args and isinstance(args["fields"], dict):
        summary["n_fields"] = len(args["fields"])
    if "kind" in args and isinstance(args["kind"], str):
        summary["kind"] = args["kind"]
    if "max_items" in args and isinstance(args["max_items"], int):
        summary["max_items"] = args["max_items"]
    if "length_bin" in args and isinstance(args["length_bin"], str):
        summary["length_bin"] = args["length_bin"]
    if "instruction" in args and isinstance(args["instruction"], str):
        summary["instruction_chars"] = len(args["instruction"])
    if "context_chars" in args and isinstance(args["context_chars"], int):
        summary["context_chars"] = args["context_chars"]
    elif "context" in args and isinstance(args["context"], str):
        summary["context_chars"] = len(args["context"])
    if "context_sha256" in args and isinstance(args["context_sha256"], str):
        summary["context_sha256"] = args["context_sha256"]
    elif "context" in args and isinstance(args["context"], str) and args["context"]:
        summary["context_sha256"] = hashlib.sha256(args["context"].encode("utf-8")).hexdigest()
    if "context_path" in args and isinstance(args["context_path"], str):
        summary["context_path"] = args["context_path"]
    return summary


class LogCall(AbstractContextManager["LogCall"]):
    def __init__(
        self,
        tool: str,
        requested_model: str,
        args: dict[str, Any],
        *,
        redact_prompt: bool = False,
    ) -> None:
        self.tool = tool
        self.requested_model = requested_model
        self.args = args
        self.redact_prompt = redact_prompt
        self.started = time.perf_counter()
        self.ts = now_local()
        self.date = self.ts.strftime("%Y-%m-%d")
        self.slug = f"{self.ts.strftime('%H-%M-%S')}-{tool.replace('_', '-')}-{secrets.token_hex(2)}"
        self.payload_rel = Path("runs") / "local-assist" / self.date / f"{self.slug}.json"
        custom_log_dir = os.environ.get("LOCAL_ASSIST_LOG_DIR", "").strip()
        if custom_log_dir:
            base_dir = Path(custom_log_dir)
            self.payload_path = base_dir / self.date / f"{self.slug}.json"
            self.index_path = base_dir / f"{self.date}.jsonl"
        else:
            self.payload_path = ROOT / self.payload_rel
            self.index_path = LOCAL_ASSIST_RUNS / f"{self.date}.jsonl"
        self.worker_sandbox_preverified = os.environ.get("LOCAL_ASSIST_WORKER_SANDBOX") == "1"
        self.payload: dict[str, Any] = {
            "ts": self.ts.isoformat(timespec="seconds"),
            "tool": tool,
            "requested_model": requested_model,
            "args": args,
        }
        if self.worker_sandbox_preverified:
            self.payload["worker_sandbox_preverified"] = True

    def __enter__(self) -> "LogCall":
        self.payload_path.parent.mkdir(parents=True, exist_ok=True)
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        return False

    def record_prompt(self, *, system: str, prompt: str) -> None:
        self.payload["system"] = system
        if self.redact_prompt:
            prompt_sha = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
            self.payload["prompt_redacted"] = {
                "chars": len(prompt),
                "sha256": prompt_sha,
            }
        else:
            self.payload["prompt"] = prompt

    def record_raw_response(self, *, raw_response: str, normalized_response: str) -> None:
        self.payload["raw_response"] = raw_response
        self.payload["normalized_response"] = normalized_response

    def record_result(
        self,
        result: dict[str, Any],
        *,
        observed: dict[str, Any],
        served_model: str | None,
        usage: dict[str, Any] | None,
        latency_ms: int,
        finish_reason: str | None,
    ) -> None:
        elapsed_ms = int(round((time.perf_counter() - self.started) * 1000))
        self.payload.update(
            {
                "parsed_output": result,
                "observed": observed,
                "served_model": served_model,
                "usage": usage,
                "latency_ms": latency_ms,
                "elapsed_ms": elapsed_ms,
                "finish_reason": finish_reason,
            }
        )
        self._write_payload()
        index_row: dict[str, Any] = {
            "ts": self.ts.isoformat(timespec="seconds"),
            "tool": self.tool,
            "requested_model": self.requested_model,
            "served_model": served_model,
            "args_summary": summarize_args(self.args),
            "observed": observed,
            "usage": usage,
            "latency_ms": latency_ms,
            "finish_reason": finish_reason,
            "payload_path": self.payload_rel.as_posix(),
        }
        if self.worker_sandbox_preverified:
            index_row["worker_sandbox_preverified"] = True
        self._append_index(index_row)

    def record_error(self, error: dict[str, Any]) -> None:
        elapsed_ms = int(round((time.perf_counter() - self.started) * 1000))
        self.payload.update({"error": error, "elapsed_ms": elapsed_ms})
        self._write_payload()
        index_row: dict[str, Any] = {
            "ts": self.ts.isoformat(timespec="seconds"),
            "tool": self.tool,
            "requested_model": self.requested_model,
            "args_summary": summarize_args(self.args),
            "observed": {"error": error.get("code", "unknown")},
            "latency_ms": elapsed_ms,
            "finish_reason": "error",
            "payload_path": self.payload_rel.as_posix(),
        }
        if self.worker_sandbox_preverified:
            index_row["worker_sandbox_preverified"] = True
        self._append_index(index_row)

    def _write_payload(self) -> None:
        self.payload_path.write_text(json.dumps(self.payload, indent=2, ensure_ascii=False) + "\n")

    def _append_index(self, row: dict[str, Any]) -> None:
        with self.index_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def log_call(
    tool: str,
    requested_model: str,
    args: dict[str, Any],
    *,
    redact_prompt: bool = False,
) -> LogCall:
    return LogCall(tool, requested_model, args, redact_prompt=redact_prompt)
