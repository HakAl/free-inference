from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import sys
import time
from pathlib import Path
from typing import Any, TypedDict

from ..client import chat, default_timeout_seconds
from ..errors import LocalAssistError, ModelOutputMalformed
from ..lifecycle import require_chat_succeeds
from ..logging import caller_context, log_call
from ..routing import JOB_TO_MODEL
from ..workspace import read_confined_workspace_file


JOB = "compress_context"
ALLOWED_KINDS = {"diff", "test_output", "logs"}
MAX_TEXT_CHARS = 200_000
MAX_TEXT_BYTES = MAX_TEXT_CHARS * 4
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
- max_items: strict maximum length for EVERY list field

Output a JSON object with exactly these top-level keys, in any order:
summary, key_points, changed_files, failures, risks, commands, followups,
omitted. Do not add other top-level keys. Do not omit any of these keys.

Field semantics:
- summary: 1-3 sentence prose. Plain English. No bullet markers.
- key_points: the most important facts, as short strings (AT MOST max_items).
- changed_files: file paths drawn verbatim from the input. For kind=diff every
  entry MUST be a path that appears in a diff header in the text (after a
  `diff --git`, `+++ b/`, `--- a/`, `rename to`, or similar marker). For
  other kinds, ONLY include paths that appear verbatim in the text; otherwise
  return [].
- failures: failure descriptions for kind=test_output or error spans in
  kind=logs. Each entry must reference a test name, error line, or other
  distinctive substring that appears verbatim in the input. Quote exact
  error strings when they are likely to be searched for.
- risks: short advisory notes about what could go wrong. Model judgment.
- commands: runnable shell commands grounded in the input. ONLY include a
  command if it appears verbatim in the input or uses only file paths and
  identifiers present in the input. If nothing concrete is grounded in the
  input, return []. Prose advice belongs in followups, not here.
- followups: short advisory next steps in plain English (not commands).
- omitted: categories of content present in this specific input that you
  compressed away. Each entry must describe content actually in the input.
  If you compressed nothing, return []. Do not pad this field with
  generic categories that don't apply to the input you were given.

Hard rules:
- CRITICAL COUNT CAP: Every array field MUST contain AT MOST max_items item(s).
  Before emitting JSON, count every array and drop lower-priority entries so
  no array length exceeds max_items.
- DO NOT invent file paths or commands referencing paths absent from the input.
- DO NOT invent test names or error messages.
- DO NOT mark a passing run as a failure.
- Every list defaults to []. An empty list means "nothing to report".

Output JSON only, no commentary, no markdown."""


def run(
    kind: Any,
    text: Any = None,
    focus: Any = None,
    max_items: Any = DEFAULT_MAX_ITEMS,
    *,
    context_path: Any = None,
) -> CompressContextResult:
    model = JOB_TO_MODEL[JOB]
    text_chars = len(text) if isinstance(text, str) else 0
    text_sha256 = (
        hashlib.sha256(text.encode("utf-8")).hexdigest()
        if isinstance(text, str) and text
        else None
    )

    with log_call(
        JOB,
        model,
        args={
            "kind": kind,
            "text_chars": text_chars,
            "text_sha256": text_sha256,
            "context_path": context_path,
            "focus": focus,
            "max_items": max_items,
        },
        redact_prompt=True,
    ) as call:
        try:
            validated = validate_inputs(
                kind,
                text,
                focus,
                max_items,
                context_path=context_path,
            )
            resolved_text = validated["text"]
            call.args.update(
                {
                    "text_chars": len(resolved_text),
                    "text_sha256": hashlib.sha256(resolved_text.encode("utf-8")).hexdigest(),
                    "context_path": validated.get("source_path"),
                }
            )
            deadline = time.monotonic() + float(default_timeout_seconds())
            with call.measure_readiness():
                require_chat_succeeds(model, deadline=deadline)
            prompt = build_prompt(validated)
            call.record_prompt(system=SYSTEM, prompt=prompt)
            scaled_max_tokens = min(1536, 256 + 180 * int(validated["max_items"]))
            result = chat(
                model,
                SYSTEM,
                prompt,
                response_format="json",
                max_tokens=scaled_max_tokens,
                temperature=0.1,
                timeout_seconds=max(1, int(deadline - time.monotonic())),
            )
            call.record_completion(result)
            call.record_raw_response(raw_response=result.raw_text, normalized_response=result.text)
            parsed, meta = parse_and_validate_with_meta(result.text, validated, allow_clamp=True)
            observed: dict[str, Any] = {
                "kind": validated["kind"],
                "text_chars": len(resolved_text),
                "summary_chars": len(parsed["summary"]),
                "n_key_points": len(parsed["key_points"]),
                "n_changed_files": len(parsed["changed_files"]),
                "n_failures": len(parsed["failures"]),
                "n_risks": len(parsed["risks"]),
                "n_commands": len(parsed["commands"]),
                "n_followups": len(parsed["followups"]),
                "n_omitted": len(parsed["omitted"]),
                "clamped_fields": meta["clamped_fields"],
                "ungrounded_items_dropped": meta["ungrounded_items_dropped"],
            }
            if validated.get("source_path") is not None:
                observed["source_path"] = validated["source_path"]
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


def validate_inputs(
    kind: Any,
    text: Any = None,
    focus: Any = None,
    max_items: Any = DEFAULT_MAX_ITEMS,
    *,
    context_path: Any = None,
) -> dict[str, Any]:
    if kind not in ALLOWED_KINDS:
        raise ModelOutputMalformed(
            "invalid_arguments",
            "kind must be one of the allowed kinds.",
            details={"allowed": sorted(ALLOWED_KINDS), "observed": kind},
        )
    if text is not None and context_path is not None:
        raise ModelOutputMalformed(
            "invalid_arguments",
            "Provide either text or context_path, not both.",
        )

    source_path: str | None = None
    if context_path is not None:
        source_path, resolved_text, _ = read_confined_workspace_file(
            context_path,
            max_bytes=MAX_TEXT_BYTES,
            max_chars=MAX_TEXT_CHARS,
            param_name="context_path",
        )
        if not resolved_text.strip():
            raise ModelOutputMalformed(
                "invalid_arguments",
                "context_path file must not be empty.",
                details={"context_path": context_path},
            )
    else:
        if not isinstance(text, str) or not text.strip():
            raise ModelOutputMalformed(
                "invalid_arguments",
                "Provide a non-empty text string or context_path.",
            )
        if len(text) > MAX_TEXT_CHARS:
            raise ModelOutputMalformed(
                "invalid_arguments",
                "text exceeds maximum length.",
                details={"max_chars": MAX_TEXT_CHARS, "observed": len(text)},
            )
        resolved_text = text

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
    out: dict[str, Any] = {
        "kind": kind,
        "text": resolved_text,
        "focus": focus,
        "max_items": max_items,
    }
    if source_path is not None:
        out["source_path"] = source_path
    return out


def build_prompt(validated: dict[str, Any]) -> str:
    cap = validated["max_items"]
    parts = [
        f"kind: {validated['kind']}",
        f"max_items: {cap} (STRICT LIMIT: every array MUST have 0..{cap} item(s); never emit {cap + 1} or more)",
    ]
    if validated["focus"]:
        parts.append(f"focus: {validated['focus']}")
    parts.append(
        "reminder: include in changed_files and commands ONLY paths and commands grounded in the text below; otherwise return []."
    )
    parts.append("text:")
    parts.append(validated["text"])
    return "\n".join(parts)


_DIFF_GIT_RE = re.compile(r"^diff --git a/(\S+) b/(\S+)", re.MULTILINE)
_DIFF_OLD_RE = re.compile(r"^--- a/(\S+)", re.MULTILINE)
_DIFF_NEW_RE = re.compile(r"^\+\+\+ b/(\S+)", re.MULTILINE)
_RENAME_FROM_RE = re.compile(r"^rename from (\S.*)$", re.MULTILINE)
_RENAME_TO_RE = re.compile(r"^rename to (\S.*)$", re.MULTILINE)
_FILELIKE_EXT_RE = re.compile(
    r"\.(?:py|js|mjs|cjs|ts|tsx|jsx|rs|go|c|cc|cpp|h|hpp|swift|sh|zsh|yaml|yml|json|toml|md|txt|log)$",
    re.IGNORECASE,
)


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


def _is_path_grounded_in_text(candidate_path: str, source_text: str) -> bool:
    norm = candidate_path.strip().strip("`'\"")
    if not norm:
        return False
    if norm in source_text:
        return True
    trimmed = norm.lstrip("./")
    if trimmed and trimmed in source_text:
        return True
    return False


def _is_command_grounded_in_text(cmd_str: str, source_text: str) -> bool:
    norm = cmd_str.strip().strip("`")
    if not norm:
        return False
    if norm in source_text:
        return True
    try:
        tokens = shlex.split(norm)
    except ValueError:
        tokens = norm.split()
    if not tokens:
        return False
    exe = os.path.basename(tokens[0])
    if exe not in source_text:
        return False
    for tok in tokens[1:]:
        if tok.startswith("-"):
            continue
        clean_tok = tok.strip("'\",;:")
        if "/" in clean_tok or _FILELIKE_EXT_RE.search(clean_tok):
            if clean_tok not in source_text and clean_tok.lstrip("./") not in source_text:
                return False
    return True


def parse_and_validate_with_meta(
    model_text: str,
    validated: dict[str, Any],
    *,
    allow_clamp: bool = True,
) -> tuple[CompressContextResult, dict[str, Any]]:
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

    max_items = int(validated["max_items"])
    hard_cap = max(max_items * 3, 12)
    source_text = str(validated.get("text") or "")
    kind = str(validated.get("kind") or "")

    clamped_fields: list[str] = []
    ungrounded_dropped = 0
    parsed: dict[str, Any] = {"summary": summary}

    for key in LIST_KEYS:
        value = raw[key]
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ModelOutputMalformed(
                "malformed_model_output",
                f"{key} must be a list of strings.",
                details={"observed_type": type(value).__name__},
            )
        items = list(value)
        if allow_clamp and len(items) > hard_cap:
            raise ModelOutputMalformed(
                "malformed_model_output",
                f"{key} exceeds runaway cap ({hard_cap}) for max_items={max_items}.",
                details={"max_items": max_items, "hard_cap": hard_cap, "observed": len(items)},
            )
        if not allow_clamp and len(items) > max_items:
            raise ModelOutputMalformed(
                "malformed_model_output",
                f"{key} exceeds max_items.",
                details={"max_items": max_items, "observed": len(items)},
            )

        if kind != "diff" and source_text:
            if key == "changed_files":
                kept_paths = [p for p in items if _is_path_grounded_in_text(p, source_text)]
                ungrounded_dropped += len(items) - len(kept_paths)
                items = kept_paths
            elif key == "commands":
                kept_cmds = [c for c in items if _is_command_grounded_in_text(c, source_text)]
                ungrounded_dropped += len(items) - len(kept_cmds)
                items = kept_cmds

        if allow_clamp and len(items) > max_items:
            items = items[:max_items]
            clamped_fields.append(key)

        parsed[key] = items

    if kind == "diff":
        valid_paths = extract_diff_files(source_text)
        invented = [path for path in parsed["changed_files"] if path not in valid_paths]
        if invented:
            raise ModelOutputMalformed(
                "malformed_model_output",
                "changed_files contains paths not present in any diff header.",
                details={"invented": invented, "valid_paths_count": len(valid_paths)},
            )
        if source_text and parsed["commands"]:
            kept_diff_cmds = [
                c for c in parsed["commands"] if _is_command_grounded_in_text(c, source_text)
            ]
            ungrounded_dropped += len(parsed["commands"]) - len(kept_diff_cmds)
            parsed["commands"] = kept_diff_cmds

    meta = {
        "clamped_fields": clamped_fields,
        "ungrounded_items_dropped": ungrounded_dropped,
    }
    return parsed, meta  # type: ignore[return-value]


def parse_and_validate(model_text: str, validated: dict[str, Any]) -> CompressContextResult:
    parsed, _ = parse_and_validate_with_meta(model_text, validated, allow_clamp=False)
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description="Compress noisy context into a structured summary.")
    parser.add_argument("--kind", required=True, choices=sorted(ALLOWED_KINDS))
    parser.add_argument("--text", default=None, help="Source text (or @path).")
    parser.add_argument(
        "--context-path",
        dest="context_path",
        default=None,
        help="Workspace-confined file path read directly by compress_context.",
    )
    parser.add_argument("--focus", default=None)
    parser.add_argument("--max-items", type=int, default=DEFAULT_MAX_ITEMS)
    args = parser.parse_args()
    text = _read_arg(args.text) if args.text is not None else None
    try:
        with caller_context(transport="cli", client_name=f"local_assist.tools.{JOB}"):
            result = run(
                args.kind,
                text,
                args.focus,
                args.max_items,
                context_path=args.context_path,
            )
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
