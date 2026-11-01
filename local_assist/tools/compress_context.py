from __future__ import annotations

import argparse
import json
import re
import sys
import time
from typing import Any, TypedDict

from ..client import chat, default_timeout_seconds
from ..errors import LocalAssistError, ModelOutputMalformed
from ..lifecycle import require_chat_succeeds
from ..logging import log_call
from ..routing import JOB_TO_MODEL


JOB = "compress_context"
ALLOWED_KINDS = {"diff", "test_output", "logs"}
MAX_TEXT_CHARS = 200_000
MAX_FOCUS_CHARS = 500
DEFAULT_MAX_ITEMS = 10
MIN_MAX_ITEMS = 1
MAX_MAX_ITEMS = 50
OUTPUT_KEYS = (
    "summary",
    "key_points",
    "changed_files",
    "failures",
    "risks",
    "commands",
    "followups",
    "omitted",
)
LIST_KEYS = tuple(k for k in OUTPUT_KEYS if k != "summary")


class CompressContextResult(TypedDict):
    summary: str
    key_points: list[str]
    changed_files: list[str]
    failures: list[str]
    risks: list[str]
    commands: list[str]
    followups: list[str]
    omitted: list[str]


SYSTEM = """You compress a block of noisy context into a structured summary
that preserves action-critical facts.

You are given:
- kind: diff, test_output, or logs
- text: the source content
- focus (optional): a short string describing what to emphasize
- max_items: maximum length for every list field

Output a JSON object with exactly these top-level keys, in any order:
summary, key_points, changed_files, failures, risks, commands, followups,
omitted. Do not add other top-level keys. Do not omit any of these keys.

Field semantics:
- summary: 1-3 sentence prose. Plain English. No bullet markers.
- key_points: the most important facts, as short strings.
- changed_files: file paths drawn from the input. For kind=diff every entry
  MUST be a path that appears in a diff header in the text (after a
  `diff --git`, `+++ b/`, `--- a/`, `rename to`, or similar marker). For
  other kinds, only include paths that appear verbatim in the text.
- failures: failure descriptions for kind=test_output or error spans in
  kind=logs. Each entry must reference a test name, error line, or other
  distinctive substring that appears verbatim in the input. Quote exact
  error strings when they are likely to be searched for.
- risks: short advisory notes about what could go wrong. Model judgment.
- commands: runnable shell commands the reader might invoke next. Each
  entry must look like a command (e.g. `pytest tests/foo.py -v`,
  `git log -p`, `cargo check`), not prose advice. If a command appears in
  the input verbatim, quote it. If nothing concrete fits, return [].
  Prose advice belongs in followups, not here.
- followups: short advisory next steps in plain English (not commands).
- omitted: categories of content present in this specific input that you
  compressed away. Each entry must describe content actually in the input.
  If you compressed nothing, return []. Do not pad this field with
  generic categories that don't apply to the input you were given.

Hard rules:
- DO NOT invent file paths. If a path isn't in the input, don't list it.
- DO NOT invent test names or error messages.
- DO NOT mark a passing run as a failure.
- Every list defaults to []. An empty list means "nothing to report"
  whether the input had nothing or you compressed it away.
- Keep every list at or below max_items entries. Pick the most important.

Output JSON only, no commentary, no markdown."""


def run(
    kind: Any,
    text: Any,
    focus: Any = None,
    max_items: Any = DEFAULT_MAX_ITEMS,
) -> CompressContextResult:
    model = JOB_TO_MODEL[JOB]

    with log_call(
        JOB,
        model,
        args={"kind": kind, "text": text, "focus": focus, "max_items": max_items},
    ) as call:
        try:
            validated = validate_inputs(kind, text, focus, max_items)
            deadline = time.monotonic() + float(default_timeout_seconds())
            require_chat_succeeds(model, deadline=deadline)
            prompt = build_prompt(validated)
            call.record_prompt(system=SYSTEM, prompt=prompt)
            result = chat(
                model,
                SYSTEM,
                prompt,
                response_format="json",
                temperature=0.1,
                timeout_seconds=max(1, int(deadline - time.monotonic())),
            )
            call.record_raw_response(raw_response=result.raw_text, normalized_response=result.text)
            parsed = parse_and_validate(result.text, validated)
            observed = {
                "kind": validated["kind"],
                "text_chars": len(validated["text"]),
                "summary_chars": len(parsed["summary"]),
                "n_key_points": len(parsed["key_points"]),
                "n_changed_files": len(parsed["changed_files"]),
                "n_failures": len(parsed["failures"]),
                "n_risks": len(parsed["risks"]),
                "n_commands": len(parsed["commands"]),
                "n_followups": len(parsed["followups"]),
                "n_omitted": len(parsed["omitted"]),
            }
            call.record_result(
                parsed,
                observed=observed,
                served_model=result.served_model,
                usage=result.usage,
                latency_ms=result.latency_ms,
                finish_reason=result.finish_reason,
            )
            return parsed
        except LocalAssistError as exc:
            call.record_error(exc.to_payload())
            raise


def validate_inputs(kind: Any, text: Any, focus: Any, max_items: Any) -> dict[str, Any]:
    if kind not in ALLOWED_KINDS:
        raise ModelOutputMalformed(
            "invalid_arguments",
            "kind must be one of the allowed kinds.",
            details={"allowed": sorted(ALLOWED_KINDS), "observed": kind},
        )
    if not isinstance(text, str) or not text.strip():
        raise ModelOutputMalformed("invalid_arguments", "text must be a non-empty string.")
    if len(text) > MAX_TEXT_CHARS:
        raise ModelOutputMalformed(
            "invalid_arguments",
            "text exceeds maximum length.",
            details={"max_chars": MAX_TEXT_CHARS, "observed": len(text)},
        )
    if focus is not None:
        if not isinstance(focus, str):
            raise ModelOutputMalformed("invalid_arguments", "focus must be a string or null.")
        if len(focus) > MAX_FOCUS_CHARS:
            raise ModelOutputMalformed(
                "invalid_arguments",
                "focus exceeds maximum length.",
                details={"max_chars": MAX_FOCUS_CHARS, "observed": len(focus)},
            )
    if not isinstance(max_items, int) or isinstance(max_items, bool):
        raise ModelOutputMalformed("invalid_arguments", "max_items must be an integer.")
    if max_items < MIN_MAX_ITEMS or max_items > MAX_MAX_ITEMS:
        raise ModelOutputMalformed(
            "invalid_arguments",
            "max_items out of range.",
            details={"min": MIN_MAX_ITEMS, "max": MAX_MAX_ITEMS, "observed": max_items},
        )
    return {"kind": kind, "text": text, "focus": focus, "max_items": max_items}


def build_prompt(validated: dict[str, Any]) -> str:
    parts = [f"kind: {validated['kind']}", f"max_items: {validated['max_items']}"]
    if validated["focus"]:
        parts.append(f"focus: {validated['focus']}")
    parts.append("text:")
    parts.append(validated["text"])
    return "\n".join(parts)


_DIFF_GIT_RE = re.compile(r"^diff --git a/(\S+) b/(\S+)", re.MULTILINE)
_DIFF_OLD_RE = re.compile(r"^--- a/(\S+)", re.MULTILINE)
_DIFF_NEW_RE = re.compile(r"^\+\+\+ b/(\S+)", re.MULTILINE)
_RENAME_FROM_RE = re.compile(r"^rename from (\S.*)$", re.MULTILINE)
_RENAME_TO_RE = re.compile(r"^rename to (\S.*)$", re.MULTILINE)


def extract_diff_files(text: str) -> set[str]:
    paths: set[str] = set()
    for match in _DIFF_GIT_RE.finditer(text):
        paths.add(match.group(1))
        paths.add(match.group(2))
    for match in _DIFF_OLD_RE.finditer(text):
        paths.add(match.group(1))
    for match in _DIFF_NEW_RE.finditer(text):
        paths.add(match.group(1))
    for match in _RENAME_FROM_RE.finditer(text):
        paths.add(match.group(1).strip())
    for match in _RENAME_TO_RE.finditer(text):
        paths.add(match.group(1).strip())
    paths.discard("/dev/null")
    return paths


def parse_and_validate(model_text: str, validated: dict[str, Any]) -> CompressContextResult:
    try:
        raw = json.loads(model_text)
    except json.JSONDecodeError as exc:
        raise ModelOutputMalformed(
            "malformed_model_output",
            "Model output was not valid JSON after artifact normalization.",
            details={"error": str(exc), "preview": model_text[:1000]},
        ) from exc

    if not isinstance(raw, dict):
        raise ModelOutputMalformed("malformed_model_output", "Model output must be a JSON object.")

    expected_keys = set(OUTPUT_KEYS)
    actual_keys = set(raw.keys())
    unexpected = actual_keys - expected_keys
    if unexpected:
        raise ModelOutputMalformed(
            "malformed_model_output",
            "Model output has unexpected top-level keys.",
            details={"unexpected": sorted(unexpected)},
        )
    missing = expected_keys - actual_keys
    if missing:
        raise ModelOutputMalformed(
            "malformed_model_output",
            "Model output is missing required top-level keys.",
            details={"missing": sorted(missing)},
        )

    summary = raw["summary"]
    if not isinstance(summary, str) or not summary.strip():
        raise ModelOutputMalformed("malformed_model_output", "summary must be a non-empty string.")

    max_items = validated["max_items"]
    parsed: dict[str, Any] = {"summary": summary}
    for key in LIST_KEYS:
        value = raw[key]
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ModelOutputMalformed(
                "malformed_model_output",
                f"{key} must be a list of strings.",
                details={"observed_type": type(value).__name__},
            )
        if len(value) > max_items:
            raise ModelOutputMalformed(
                "malformed_model_output",
                f"{key} exceeds max_items.",
                details={"max_items": max_items, "observed": len(value)},
            )
        parsed[key] = value

    if validated["kind"] == "diff":
        valid_paths = extract_diff_files(validated["text"])
        invented = [path for path in parsed["changed_files"] if path not in valid_paths]
        if invented:
            raise ModelOutputMalformed(
                "malformed_model_output",
                "changed_files contains paths not present in any diff header.",
                details={"invented": invented, "valid_paths_count": len(valid_paths)},
            )

    return parsed  # type: ignore[return-value]


def main() -> int:
    parser = argparse.ArgumentParser(description="Compress noisy context into a structured summary.")
    parser.add_argument("--kind", required=True, choices=sorted(ALLOWED_KINDS))
    parser.add_argument("--text", required=True, help="Source text (or @path).")
    parser.add_argument("--focus", default=None)
    parser.add_argument("--max-items", type=int, default=DEFAULT_MAX_ITEMS)
    args = parser.parse_args()
    text = _read_arg(args.text)
    try:
        result = run(args.kind, text, args.focus, args.max_items)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except LocalAssistError as exc:
        print(json.dumps({"error": exc.to_payload()}, indent=2, ensure_ascii=False), file=sys.stderr)
        return 1


def _read_arg(value: str) -> str:
    if value.startswith("@"):
        with open(value[1:], encoding="utf-8") as handle:
            return handle.read()
    return value


if __name__ == "__main__":
    raise SystemExit(main())
