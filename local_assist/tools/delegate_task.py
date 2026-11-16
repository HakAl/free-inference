from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from typing import Any, TypedDict

from ..client import chat, default_timeout_seconds
from ..errors import LocalAssistError, ModelOutputMalformed, ModelTimeout
from ..lifecycle import require_chat_succeeds
from ..logging import caller_context, log_call
from ..routing import JOB_TO_MODEL
from ..workspace import read_confined_workspace_file


JOB = "delegate_task"
ALLOWED_KINDS = {"draft_code", "generate_test_cases", "transform_text", "focused_qa"}
MAX_INSTRUCTION_CHARS = 8_000
MAX_CONTEXT_CHARS = 32_000
MAX_CONTEXT_BYTES = MAX_CONTEXT_CHARS * 4
MAX_CONSTRAINTS = 20
MAX_CONSTRAINT_CHARS = 500
DEFAULT_MAX_TOKENS = 1536
MIN_MAX_TOKENS = 256
MAX_MAX_TOKENS = 2048
MAX_LIST_ITEMS = 20

MODEL_OUTPUT_KEYS = (
    "summary",
    "output",
    "assumptions",
    "unverified_claims",
)


class DelegateTaskResult(TypedDict):
    id: str
    kind: str
    summary: str
    output: str
    ungrounded_identifiers: list[str]
    assumptions: list[str]
    unverified_claims: list[str]


KIND_GUIDANCE = {
    "draft_code": (
        "Dry-run boundary conditions (`0`, `1`, exact cap, `<` vs `<=`, empty inputs) "
        "and state mutations across repeated calls step by step before emitting code. "
        "Record any unspecified edge-case behavior in `assumptions`."
    ),
    "generate_test_cases": (
        "Return `output` as a string (for example a serialized JSON array or test code). "
        "Trace every expected output line by line through the provided implementation, "
        "paying special attention to `<` vs `<=` boundaries, off-by-one limits, zero/empty "
        "inputs, and state mutated across sequential calls."
    ),
    "transform_text": (
        "Preserve all factual values, identifiers, and constraints from the input; list any "
        "ambiguous source spans in `assumptions`."
    ),
    "focused_qa": (
        "Answer strictly from the supplied `context` and `instruction`. Trace boundary and "
        "stateful logic explicitly; list anything not proven by `context` in `assumptions` "
        "or `unverified_claims`."
    ),
}


SYSTEM = """You are a bounded local worker model executing a specific subtask delegated by a planner agent.

You are given:
- kind: one of draft_code, generate_test_cases, transform_text, focused_qa
- instruction: the exact task to perform
- constraints (optional): explicit rules your output must obey
- context (optional): source material, code, or reference text to operate on

Output a JSON object with exactly these top-level keys:
summary, output, assumptions, unverified_claims.
Do not add other top-level keys. Do not omit any of these keys.

Field semantics:
- summary: 1-2 sentence plain-English description of what you produced.
- output: the requested artifact as a non-empty string (for example drafted code, serialized JSON/YAML test cases, transformed text, or focused answer). Do not wrap the entire JSON response in markdown fences.
- assumptions: array of short strings (0 to 20 items) listing EVERY assumption, simplification, tie-break, or default you chose because `instruction` or `context` left it unspecified. Whenever `context` is partial or omitted, populate `assumptions` rather than leaving it empty.
- unverified_claims: array of short strings (0 to 20 items) listing any external library APIs, proper nouns, citations, hardware interfaces, or regional dialect idioms used in `output` that were NOT explicitly present in `context`.

Hard rules:
- Follow `instruction` and `constraints` literally.
- Mentally dry-run boundary values (`0`, `1`, exact limit `N`, `N - 1`, `N + 1`, `<` vs `<=`) and stateful mutations across calls before finalizing `output`.
- Never invent fake citations, fake person names, or fake dataset/forum names. If an example placeholder is needed, mark it clearly as a placeholder and list it in `unverified_claims`.
- Both `assumptions` and `unverified_claims` are advisory self-reports for the delegating planner to inspect; return [] only when none apply.

Output JSON only, no commentary, no markdown fences around the JSON object."""


_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+")
_PY_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+([A-Za-z_][A-Za-z0-9_.]*)\s+import|import\s+([A-Za-z_][A-Za-z0-9_]*))",
    re.MULTILINE,
)
_JS_IMPORT_RE = re.compile(
    r"""(?:from\s+['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]\s*\))"""
)
_PROPER_NOUN_RE = re.compile(
    r"\b(?:(?:Dr|Prof|Mr|Ms|Mrs)\.\s+)?[A-Z][a-z]{2,}(?:\s+(?:[A-Z][a-z]{2,}|Al-[A-Z][a-z]{2,}))+\b"
)
_GROUNDING_TOKEN_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b(?!-free)")


def stable_id(output_text: str) -> str:
    normalized = " ".join(output_text.strip().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:10]


def compute_ungrounded_identifiers(output_text: str, grounding_text: str) -> list[str]:
    grounding_tokens = set(_GROUNDING_TOKEN_RE.findall(grounding_text))
    grounding_urls = {m.group(0).rstrip(".,;:") for m in _URL_RE.finditer(grounding_text)}

    ungrounded: set[str] = set()
    for m in _URL_RE.finditer(output_text):
        url = m.group(0).rstrip(".,;:")
        if url and url not in grounding_urls:
            ungrounded.add(url)
    for m in _PY_IMPORT_RE.finditer(output_text):
        mod = m.group(1) or m.group(2)
        if mod:
            root_mod = mod.split(".")[0]
            if mod not in grounding_tokens and root_mod not in grounding_tokens:
                ungrounded.add(root_mod)
    for m in _JS_IMPORT_RE.finditer(output_text):
        mod = m.group(1) or m.group(2)
        if mod:
            root_mod = mod.split("/")[0].lstrip("@")
            if mod not in grounding_tokens and root_mod not in grounding_tokens:
                ungrounded.add(mod)
    for m in _PROPER_NOUN_RE.finditer(output_text):
        phrase = m.group(0).strip()
        if phrase and re.search(r"\b" + re.escape(phrase) + r"\b", grounding_text) is None:
            ungrounded.add(phrase)

    return sorted(ungrounded)[:50]


def validate_inputs(
    kind: Any,
    instruction: Any,
    context: Any = None,
    context_path: Any = None,
    constraints: Any = None,
    max_tokens: Any = DEFAULT_MAX_TOKENS,
) -> dict[str, Any]:
    if kind not in ALLOWED_KINDS:
        raise ModelOutputMalformed(
            "invalid_arguments",
            "kind must be one of the allowed kinds.",
            details={"allowed": sorted(ALLOWED_KINDS), "observed": kind},
        )
    if not isinstance(instruction, str) or not instruction.strip():
        raise ModelOutputMalformed(
            "invalid_arguments", "instruction must be a non-empty string."
        )
    if len(instruction) > MAX_INSTRUCTION_CHARS:
        raise ModelOutputMalformed(
            "invalid_arguments",
            "instruction exceeds maximum length.",
            details={"max_chars": MAX_INSTRUCTION_CHARS, "observed": len(instruction)},
        )

    if context is not None and not isinstance(context, str):
        raise ModelOutputMalformed(
            "invalid_arguments", "context must be a string or null."
        )
    if context_path is not None and not isinstance(context_path, str):
        raise ModelOutputMalformed(
            "invalid_arguments", "context_path must be a string or null."
        )
    if context and context_path:
        raise ModelOutputMalformed(
            "invalid_arguments",
            "Provide either context or context_path, not both.",
        )

    resolved_context = ""
    source_path: str | None = None
    if context_path:
        source_path, resolved_context, _ = read_confined_workspace_file(
            context_path,
            max_bytes=MAX_CONTEXT_BYTES,
            max_chars=MAX_CONTEXT_CHARS,
            param_name="context_path",
        )
    elif context:
        resolved_context = context

    if len(resolved_context) > MAX_CONTEXT_CHARS:
        raise ModelOutputMalformed(
            "invalid_arguments",
            "context exceeds maximum length.",
            details={"max_chars": MAX_CONTEXT_CHARS, "observed": len(resolved_context)},
        )

    clean_constraints: list[str] = []
    if constraints is not None:
        if not isinstance(constraints, list) or not all(
            isinstance(c, str) for c in constraints
        ):
            raise ModelOutputMalformed(
                "invalid_arguments",
                "constraints must be a list of strings or null.",
            )
        if len(constraints) > MAX_CONSTRAINTS:
            raise ModelOutputMalformed(
                "invalid_arguments",
                "constraints exceeds maximum item count.",
                details={"max_items": MAX_CONSTRAINTS, "observed": len(constraints)},
            )
        for c in constraints:
            if len(c) > MAX_CONSTRAINT_CHARS:
                raise ModelOutputMalformed(
                    "invalid_arguments",
                    "constraint item exceeds maximum length.",
                    details={"max_chars": MAX_CONSTRAINT_CHARS, "observed": len(c)},
                )
            if c.strip():
                clean_constraints.append(c.strip())

    if not isinstance(max_tokens, int) or isinstance(max_tokens, bool):
        raise ModelOutputMalformed("invalid_arguments", "max_tokens must be an integer.")
    if max_tokens < MIN_MAX_TOKENS or max_tokens > MAX_MAX_TOKENS:
        raise ModelOutputMalformed(
            "invalid_arguments",
            "max_tokens out of range.",
            details={
                "min": MIN_MAX_TOKENS,
                "max": MAX_MAX_TOKENS,
                "observed": max_tokens,
            },
        )

    context_sha256 = (
        hashlib.sha256(resolved_context.encode("utf-8")).hexdigest()
        if resolved_context
        else None
    )
    out: dict[str, Any] = {
        "kind": kind,
        "instruction": instruction,
        "context": resolved_context,
        "context_path": source_path if source_path is not None else context_path,
        "context_chars": len(resolved_context),
        "context_sha256": context_sha256,
        "constraints": clean_constraints,
        "max_tokens": max_tokens,
    }
    if source_path is not None:
        out["source_path"] = source_path
    return out


def build_prompt(validated: dict[str, Any], *, redact_context: bool = False) -> str:
    kind = validated["kind"]
    parts = [
        f"kind: {kind}",
    ]
    guidance = KIND_GUIDANCE.get(kind)
    if guidance:
        parts.append(f"kind_guidance: {guidance}")
    parts.append(f"instruction:\n{validated['instruction']}")
    if validated["constraints"]:
        parts.append("constraints:")
        for item in validated["constraints"]:
            parts.append(f"- {item}")
    if validated["context"]:
        parts.append("context:")
        if redact_context:
            parts.append(
                f"<redacted in audit log: chars={validated['context_chars']}, "
                f"sha256={validated['context_sha256']}>"
            )
        else:
            parts.append(validated["context"])
    return "\n".join(parts)


def parse_and_validate_with_meta(
    model_text: str,
    validated: dict[str, Any],
) -> tuple[DelegateTaskResult, dict[str, Any]]:
    try:
        raw = json.loads(model_text)
    except json.JSONDecodeError as exc:
        raise ModelOutputMalformed(
            "malformed_model_output",
            "Model output was not valid JSON after artifact normalization.",
            details={"error": str(exc), "preview": model_text[:1000]},
        ) from exc

    if not isinstance(raw, dict):
        raise ModelOutputMalformed(
            "malformed_model_output", "Model output must be a JSON object."
        )

    expected_keys = set(MODEL_OUTPUT_KEYS)
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
        raise ModelOutputMalformed(
            "malformed_model_output", "summary must be a non-empty string."
        )

    raw_output = raw["output"]
    coerced_structured = False
    if isinstance(raw_output, str):
        if not raw_output.strip():
            raise ModelOutputMalformed(
                "malformed_model_output", "output must be a non-empty string."
            )
        output_text = raw_output
    elif isinstance(raw_output, (list, dict)):
        if not raw_output:
            raise ModelOutputMalformed(
                "malformed_model_output",
                "structured output array/object must not be empty.",
            )
        output_text = json.dumps(raw_output, indent=2, ensure_ascii=False)
        coerced_structured = True
    else:
        raise ModelOutputMalformed(
            "malformed_model_output",
            "output must be a non-empty string (or non-empty structured array/object).",
            details={"observed_type": type(raw_output).__name__},
        )

    lists_out: dict[str, list[str]] = {}
    for key in ("assumptions", "unverified_claims"):
        val = raw[key]
        if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
            raise ModelOutputMalformed(
                "malformed_model_output",
                f"{key} must be a list of strings.",
                details={"observed_type": type(val).__name__},
            )
        if len(val) > MAX_LIST_ITEMS:
            raise ModelOutputMalformed(
                "malformed_model_output",
                f"{key} exceeds max length of {MAX_LIST_ITEMS}.",
                details={"max_items": MAX_LIST_ITEMS, "observed": len(val)},
            )
        lists_out[key] = val

    grounding_blob = "\n".join(
        [
            validated["instruction"],
            validated["context"],
            *validated["constraints"],
        ]
    )
    ungrounded = compute_ungrounded_identifiers(output_text, grounding_blob)

    result: DelegateTaskResult = {
        "id": stable_id(output_text),
        "kind": validated["kind"],
        "summary": summary.strip(),
        "output": output_text,
        "ungrounded_identifiers": ungrounded,
        "assumptions": lists_out["assumptions"],
        "unverified_claims": lists_out["unverified_claims"],
    }
    return result, {"coerced_structured_output": coerced_structured}


def parse_and_validate(model_text: str, validated: dict[str, Any]) -> DelegateTaskResult:
    result, _ = parse_and_validate_with_meta(model_text, validated)
    return result


def run(
    kind: Any,
    instruction: Any,
    context: Any = None,
    context_path: Any = None,
    constraints: Any = None,
    max_tokens: Any = DEFAULT_MAX_TOKENS,
) -> DelegateTaskResult:
    model = JOB_TO_MODEL[JOB]
    validated_for_log: dict[str, Any] = {
        "kind": kind,
        "instruction": instruction if isinstance(instruction, str) else str(instruction),
        "context_path": context_path,
        "context_chars": len(context) if isinstance(context, str) else 0,
        "context_sha256": None,
        "constraints": constraints,
        "max_tokens": max_tokens,
    }
    with log_call(JOB, model, args=validated_for_log) as call:
        try:
            validated = validate_inputs(
                kind=kind,
                instruction=instruction,
                context=context,
                context_path=context_path,
                constraints=constraints,
                max_tokens=max_tokens,
            )
            call.args.update(
                {
                    "kind": validated["kind"],
                    "instruction": validated["instruction"],
                    "context_path": validated["context_path"],
                    "context_chars": validated["context_chars"],
                    "context_sha256": validated["context_sha256"],
                    "constraints": validated["constraints"],
                    "max_tokens": validated["max_tokens"],
                }
            )
            started_mono = time.monotonic()
            deadline = started_mono + float(default_timeout_seconds())
            with call.measure_readiness():
                require_chat_succeeds(model, deadline=deadline)
            ready_seconds = round(time.monotonic() - started_mono, 4)
            rem_chat = deadline - time.monotonic()
            if rem_chat <= 0:
                raise ModelTimeout(
                    "timeout",
                    f"Timed out before delegate_task completion request for {model}.",
                    details={"model": model, "ready_seconds": ready_seconds},
                )
            prompt = build_prompt(validated, redact_context=False)
            redacted_prompt = build_prompt(validated, redact_context=True)
            call.record_prompt(system=SYSTEM, prompt=redacted_prompt)
            result = chat(
                model,
                SYSTEM,
                prompt,
                response_format="json",
                max_tokens=validated["max_tokens"],
                temperature=0.2,
                timeout_seconds=max(1, int(rem_chat)),
            )
            call.record_completion(result)
            call.record_raw_response(
                raw_response=result.raw_text, normalized_response=result.text
            )
            if result.finish_reason == "length":
                raise ModelOutputMalformed(
                    "output_truncated",
                    "Model output hit max_tokens completion ceiling before finishing.",
                    details={
                        "max_tokens": validated["max_tokens"],
                        "finish_reason": result.finish_reason,
                        "preview": result.text[:500],
                    },
                )
            parsed, meta = parse_and_validate_with_meta(result.text, validated)
            observed: dict[str, Any] = {
                "id": parsed["id"],
                "kind": parsed["kind"],
                "ready_seconds": ready_seconds,
                "instruction_chars": len(validated["instruction"]),
                "context_chars": validated["context_chars"],
                "output_chars": len(parsed["output"]),
                "n_ungrounded_identifiers": len(parsed["ungrounded_identifiers"]),
                "n_assumptions": len(parsed["assumptions"]),
                "n_unverified_claims": len(parsed["unverified_claims"]),
                "coerced_structured_output": meta["coerced_structured_output"],
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Delegate a bounded drafting, transformation, or QA subtask to the local Rung 1 model."
    )
    parser.add_argument("--kind", required=True, choices=sorted(ALLOWED_KINDS))
    parser.add_argument("--instruction", required=True, help="Task instruction string.")
    parser.add_argument("--context", default=None, help="Optional inline context string.")
    parser.add_argument(
        "--context-path",
        dest="context_path",
        default=None,
        help="Optional workspace file path read directly by the local tool.",
    )
    parser.add_argument(
        "--constraint",
        dest="constraints",
        action="append",
        default=None,
        help="Optional constraint (may be passed multiple times).",
    )
    parser.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS)
    args = parser.parse_args()
    try:
        with caller_context(transport="cli", client_name=f"local_assist.tools.{JOB}"):
            result = run(
                kind=args.kind,
                instruction=args.instruction,
                context=args.context,
                context_path=args.context_path,
                constraints=args.constraints,
                max_tokens=args.max_tokens,
            )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except LocalAssistError as exc:
        print(
            json.dumps({"error": exc.to_payload()}, indent=2, ensure_ascii=False),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
