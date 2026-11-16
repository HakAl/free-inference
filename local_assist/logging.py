from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from contextvars import ContextVar, Token
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from .paths import LOCAL_ASSIST_RUNS, ROOT


LOCAL_TZ = ZoneInfo("America/New_York")
VALID_TRANSPORTS = frozenset({"mcp", "cli", "direct"})
VALID_STARTUP_STATES = frozenset(
    {
        "warm",
        "worker_handoff",
        "auto_served",
        "auto_serve_reused",
        "auto_serve_failed",
        "not_served",
    }
)
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]+")
_CALLER_CONTEXT: ContextVar[dict[str, str] | None] = ContextVar("_CALLER_CONTEXT", default=None)
_ACTIVE_LOG_CALL: ContextVar["LogCall | None"] = ContextVar("_ACTIVE_LOG_CALL", default=None)


def now_local() -> datetime:
    return datetime.now(tz=LOCAL_TZ)


def sanitize_caller_field(value: Any, *, max_len: int = 128) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = _CONTROL_CHARS_RE.sub(" ", value)
    normalized = " ".join(cleaned.split())
    if not normalized:
        return None
    return normalized[:max_len]


@contextmanager
def caller_context(
    *,
    transport: str,
    client_name: str | None = None,
    client_version: str | None = None,
    protocol_version: str | None = None,
    label: str | None = None,
) -> Iterator[dict[str, str]]:
    effective_transport = transport if transport in VALID_TRANSPORTS else "direct"
    info: dict[str, str] = {"transport": effective_transport}
    for key, raw in (
        ("client_name", client_name),
        ("client_version", client_version),
        ("protocol_version", protocol_version),
        ("label", label if label is not None else os.environ.get("LOCAL_ASSIST_CALLER")),
    ):
        clean = sanitize_caller_field(raw)
        if clean is not None:
            info[key] = clean
    ctx_handle = _CALLER_CONTEXT.set(info)
    try:
        yield dict(info)
    finally:
        _CALLER_CONTEXT.reset(ctx_handle)


def resolve_caller() -> dict[str, str]:
    ctx = _CALLER_CONTEXT.get()
    if ctx is not None:
        resolved = dict(ctx)
        if "label" not in resolved:
            env_label = sanitize_caller_field(os.environ.get("LOCAL_ASSIST_CALLER"))
            if env_label is not None:
                resolved["label"] = env_label
        return resolved
    resolved = {"transport": "direct"}
    env_label = sanitize_caller_field(os.environ.get("LOCAL_ASSIST_CALLER"))
    if env_label is not None:
        resolved["label"] = env_label
    return resolved


def record_active_startup_state(state: str) -> None:
    if state not in VALID_STARTUP_STATES:
        raise ValueError(f"Unsupported startup_state: {state!r}")
    active = _ACTIVE_LOG_CALL.get()
    if active is not None:
        active.startup_state = state


def get_active_startup_state() -> str | None:
    active = _ACTIVE_LOG_CALL.get()
    return active.startup_state if active is not None else None


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
    if "query" in args and isinstance(args["query"], str):
        summary["query_chars"] = len(args["query"])
    if "paths" in args and isinstance(args["paths"], list):
        summary["n_paths"] = len(args["paths"])
    if "assertion_type" in args and isinstance(args["assertion_type"], str):
        summary["assertion_type"] = args["assertion_type"]
    if "n_passing" in args and isinstance(args["n_passing"], int):
        summary["n_passing"] = args["n_passing"]
    if "n_failing" in args and isinstance(args["n_failing"], int):
        summary["n_failing"] = args["n_failing"]
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
        self.caller = resolve_caller()
        self.startup_state: str | None = None
        self.readiness_ok: bool | None = None
        self.ready_ms: int | None = None
        self._served_model: str | None = None
        self._usage: dict[str, Any] | None = None
        self._model_latency_ms: int | None = None
        self._model_finish_reason: str | None = None
        self._recorded = False
        self._active_handle: Token[LogCall | None] | None = None
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
            "caller": dict(self.caller),
            "requested_model": requested_model,
            "args": args,
        }
        if self.worker_sandbox_preverified:
            self.payload["worker_sandbox_preverified"] = True

    def __enter__(self) -> "LogCall":
        self.payload_path.parent.mkdir(parents=True, exist_ok=True)
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        self._active_handle = _ACTIVE_LOG_CALL.set(self)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        try:
            if (
                exc_type is not None
                and not self._recorded
                and isinstance(exc_type, type)
                and issubclass(exc_type, Exception)
            ):
                self.record_error(
                    {
                        "code": "internal_error",
                        "message": str(exc),
                        "details": {"exception_type": exc_type.__name__},
                    }
                )
        finally:
            if self._active_handle is not None:
                _ACTIVE_LOG_CALL.reset(self._active_handle)
                self._active_handle = None
        return False

    @contextmanager
    def measure_readiness(self) -> Iterator[None]:
        t0 = time.perf_counter()
        self.readiness_ok = False
        try:
            yield
            self.readiness_ok = True
        finally:
            self.ready_ms = int(round((time.perf_counter() - t0) * 1000))

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

    def record_completion(self, result: Any) -> None:
        served = getattr(result, "served_model", None)
        if isinstance(served, str) and served:
            self._served_model = served
        fin = getattr(result, "finish_reason", None)
        if isinstance(fin, str) and fin:
            self._model_finish_reason = fin
        lat = getattr(result, "latency_ms", None)
        if isinstance(lat, int) and not isinstance(lat, bool) and lat >= 0:
            self._model_latency_ms = (self._model_latency_ms or 0) + lat
        usage = getattr(result, "usage", None)
        if isinstance(usage, dict):
            if self._usage is None:
                self._usage = dict(usage)
            else:
                merged = dict(self._usage)
                for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
                    old_v = merged.get(key)
                    new_v = usage.get(key)
                    if (
                        isinstance(old_v, int)
                        and not isinstance(old_v, bool)
                        and isinstance(new_v, int)
                        and not isinstance(new_v, bool)
                    ):
                        merged[key] = old_v + new_v
                    elif isinstance(new_v, int) and not isinstance(new_v, bool):
                        merged[key] = new_v
                self._usage = merged

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
        self._recorded = True
        elapsed_ms = int(round((time.perf_counter() - self.started) * 1000))
        self.payload.update(
            {
                "caller": dict(self.caller),
                "startup_state": self.startup_state,
                "readiness_ok": self.readiness_ok,
                "ready_ms": self.ready_ms,
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
            "caller": dict(self.caller),
            "requested_model": self.requested_model,
            "served_model": served_model,
            "startup_state": self.startup_state,
            "readiness_ok": self.readiness_ok,
            "ready_ms": self.ready_ms,
            "args_summary": summarize_args(self.args),
            "observed": observed,
            "usage": usage,
            "latency_ms": latency_ms,
            "elapsed_ms": elapsed_ms,
            "finish_reason": finish_reason,
            "payload_path": self.payload_rel.as_posix(),
        }
        if self.worker_sandbox_preverified:
            index_row["worker_sandbox_preverified"] = True
        self._append_index(index_row)

    def record_error(self, error: dict[str, Any]) -> None:
        self._recorded = True
        elapsed_ms = int(round((time.perf_counter() - self.started) * 1000))
        effective_latency_ms = (
            self._model_latency_ms if self._model_latency_ms is not None else elapsed_ms
        )
        self.payload.update(
            {
                "caller": dict(self.caller),
                "startup_state": self.startup_state,
                "readiness_ok": self.readiness_ok,
                "ready_ms": self.ready_ms,
                "served_model": self._served_model,
                "usage": self._usage,
                "latency_ms": effective_latency_ms,
                "model_finish_reason": self._model_finish_reason,
                "error": error,
                "elapsed_ms": elapsed_ms,
                "finish_reason": "error",
            }
        )
        self._write_payload()
        index_row: dict[str, Any] = {
            "ts": self.ts.isoformat(timespec="seconds"),
            "tool": self.tool,
            "caller": dict(self.caller),
            "requested_model": self.requested_model,
            "served_model": self._served_model,
            "startup_state": self.startup_state,
            "readiness_ok": self.readiness_ok,
            "ready_ms": self.ready_ms,
            "args_summary": summarize_args(self.args),
            "observed": {"error": error.get("code", "unknown")},
            "usage": self._usage,
            "latency_ms": effective_latency_ms,
            "model_finish_reason": self._model_finish_reason,
            "elapsed_ms": elapsed_ms,
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
