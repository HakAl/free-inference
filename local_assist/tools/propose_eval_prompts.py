from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from typing import TypedDict

from ..client import chat, default_timeout_seconds
from ..errors import LocalAssistError, ModelOutputMalformed
from ..lifecycle import require_chat_succeeds
from ..logging import caller_context, log_call
from ..routing import JOB_TO_MODEL
from .check_eval_assertion import validate_assertion_syntax


JOB = "propose_eval_prompts"
ALLOWED_CATEGORIES = {
    "format",
    "reasoning",
    "coding",
    "long_context",
    "instruction_following",
    "structured_output",
}


class EvalPrompt(TypedDict):
    id: str
    prompt: str
    expected_signal: str
    assertion: str
    category: str


class EvalPromptResult(TypedDict):
    prompts: list[EvalPrompt]
    coverage_note: str | None


SYSTEM = """You propose candidate local-LLM eval prompts.

Given a requested category and N, produce up to N prompts that could reveal
behavioral differences between local models. Each prompt should be runnable as
a single promptfoo test case. Prefer concrete, compact tasks with clear pass
or fail behavior.

Output a JSON object with fields: prompts, coverage_note.
prompts is an array of objects. Each prompt object has:
- prompt: the exact user prompt to send to the model
- expected_signal: one-line human-readable description of what the prompt tests
- assertion: a synchronous promptfoo JavaScript expression that returns a boolean
  and can be used directly as assert[].value
- category: one of format, reasoning, coding, long_context,
  instruction_following, structured_output

Assertion authoring rules (CRITICAL):
- The assertion must be valid, synchronous executable JavaScript (never prose,
  never async/Promise). It may reference `output`. If multi-statement, include
  an explicit `return`.
- NEVER assert on unrequested formatting, key names, or value types (for example
  requiring `"30"` vs `30` or exact whitespace) unless `prompt` explicitly
  demands that exact schema, key name, and JSON type.
- NEVER use unanchored substring regexes on numbers or short tokens (for example
  `/6/.test(output)` falsely accepts `"16"` and `"60"`); use word boundaries
  such as `/\\b6\\b/.test(output)` or parse structured JSON fields explicitly.
- Set `coverage_note` to `null` (never empty string `""`) when returning N
  prompts. Only set a non-empty `coverage_note` when returning fewer than N
  prompts because additional prompts would be near-duplicates.

Output JSON only, no commentary, no markdown.

Important: your prompts are candidates only. Verify assertions with
check_eval_assertion against passing and failing outputs before promoting them."""


def run(category: str, n: int = 5) -> EvalPromptResult:
    model = JOB_TO_MODEL[JOB]
    prompt = f"Category: {category}\nN: {n}"

    with log_call(JOB, model, args={"category": category, "n": n}) as call:
        try:
            if category not in ALLOWED_CATEGORIES:
                raise ModelOutputMalformed(
                    "invalid_arguments",
                    "category must be one of the allowed signal categories.",
                    details={"allowed": sorted(ALLOWED_CATEGORIES), "observed": category},
                )
            if isinstance(n, bool) or not isinstance(n, int) or n < 1 or n > 25:
                raise ModelOutputMalformed(
                    "invalid_arguments",
                    "n must be an integer between 1 and 25.",
                    details={"n": n},
                )

            deadline = time.monotonic() + float(default_timeout_seconds())
            with call.measure_readiness():
                require_chat_succeeds(model, deadline=deadline)
            call.record_prompt(system=SYSTEM, prompt=prompt)
            result = chat(
                model,
                SYSTEM,
                prompt,
                response_format="json",
                max_tokens=1536,
                timeout_seconds=max(1, int(deadline - time.monotonic())),
            )
            call.record_completion(result)
            call.record_raw_response(raw_response=result.raw_text, normalized_response=result.text)
            parsed = parse_and_validate(result.text, n=n)
            prompts = parsed["prompts"]
            output: EvalPromptResult = {
                "prompts": prompts,
                "coverage_note": parsed["coverage_note"],
            }
            observed = {
                "n_requested": n,
                "n_returned": len(prompts),
                "n_distinct_categories": len({p["category"] for p in prompts}),
                "coverage_note_present": parsed["coverage_note"] is not None,
            }
            call.record_result(
                output,
                observed=observed,
                served_model=result.served_model,
                usage=result.usage,
                latency_ms=result.latency_ms,
                finish_reason=result.finish_reason,
            )
            return output
        except LocalAssistError as exc:
            call.record_error(exc.to_payload())
            raise


def parse_and_validate(text: str, *, n: int | None = None) -> EvalPromptResult:
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ModelOutputMalformed(
            "malformed_model_output",
            "Model output was not valid JSON after artifact normalization.",
            details={"error": str(exc), "preview": text[:1000]},
        ) from exc

    if not isinstance(raw, dict):
        raise ModelOutputMalformed("malformed_model_output", "Model output must be a JSON object.")
    prompts_raw = raw.get("prompts")
    if not isinstance(prompts_raw, list):
        raise ModelOutputMalformed("malformed_model_output", "Model output must contain prompts array.")

    coverage_note_raw = raw.get("coverage_note")
    if coverage_note_raw is not None and not isinstance(coverage_note_raw, str):
        raise ModelOutputMalformed("malformed_model_output", "coverage_note must be a string or null.")

    allow_partial = n is not None and n >= 2
    prompts: list[EvalPrompt] = []
    dropped_reasons: list[str] = []
    first_item_error: ModelOutputMalformed | None = None
    seen_ids: set[str] = set()
    seen_prompts: set[str] = set()
    for idx, item in enumerate(prompts_raw):
        try:
            if not isinstance(item, dict):
                raise ModelOutputMalformed("malformed_model_output", f"prompts[{idx}] must be an object.")

            prompt_value = item.get("prompt")
            expected_signal = item.get("expected_signal")
            assertion = item.get("assertion")
            category = item.get("category")

            if not isinstance(prompt_value, str) or not prompt_value.strip():
                raise ModelOutputMalformed("malformed_model_output", f"prompts[{idx}].prompt must be non-empty.")
            if not isinstance(expected_signal, str) or not expected_signal.strip():
                raise ModelOutputMalformed("malformed_model_output", f"prompts[{idx}].expected_signal must be non-empty.")
            if not isinstance(assertion, str) or not assertion.strip():
                raise ModelOutputMalformed("malformed_model_output", f"prompts[{idx}].assertion must be non-empty.")
            if "```" in assertion:
                raise ModelOutputMalformed(
                    "malformed_model_output",
                    f"prompts[{idx}].assertion must not contain markdown code fences.",
                )
            if not isinstance(category, str) or category not in ALLOWED_CATEGORIES:
                raise ModelOutputMalformed(
                    "malformed_model_output",
                    f"prompts[{idx}].category is invalid.",
                    details={"allowed": sorted(ALLOWED_CATEGORIES), "observed": category},
                )

            syn_ok, syn_err = validate_assertion_syntax("javascript", assertion)
            if not syn_ok:
                raise ModelOutputMalformed(
                    "malformed_model_output",
                    f"prompts[{idx}].assertion failed JavaScript syntax validation: {syn_err}",
                    details={"index": idx, "syntax_error": syn_err},
                )

            normalized_prompt = " ".join(prompt_value.split())
            if normalized_prompt in seen_prompts:
                raise ModelOutputMalformed("malformed_model_output", f"prompts[{idx}].prompt duplicates an earlier prompt.")

            prompt_id = stable_id(prompt_value)
            if prompt_id in seen_ids:
                raise ModelOutputMalformed("malformed_model_output", f"prompts[{idx}].id collision.")
        except ModelOutputMalformed as exc:
            if not allow_partial:
                raise
            if first_item_error is None:
                first_item_error = exc
            dropped_reasons.append(exc.message)
            continue

        seen_prompts.add(normalized_prompt)
        seen_ids.add(prompt_id)
        prompts.append(
            {
                "id": prompt_id,
                "prompt": prompt_value,
                "expected_signal": expected_signal,
                "assertion": assertion,
                "category": category,
            }
        )

    if not prompts and first_item_error is not None:
        raise first_item_error

    if n is not None:
        prompts = prompts[:n]

    normalized_note: str | None = None
    if isinstance(coverage_note_raw, str):
        stripped = coverage_note_raw.strip()
        if stripped:
            normalized_note = stripped
    if dropped_reasons and (n is None or len(prompts) < n):
        drop_summary = (
            f"Retained {len(prompts)} of {n if n is not None else len(prompts_raw)} requested prompts "
            f"(dropped {len(dropped_reasons)} invalid or duplicate candidate(s))."
        )
        normalized_note = f"{normalized_note} {drop_summary}".strip() if normalized_note else drop_summary
    elif normalized_note is None and n is not None and len(prompts) < n:
        normalized_note = f"Model returned {len(prompts)} of {n} requested prompts."

    return {"prompts": prompts, "coverage_note": normalized_note}


def stable_id(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:10]


def main() -> int:
    parser = argparse.ArgumentParser(description="Propose local LLM eval prompt candidates.")
    parser.add_argument("--category", required=True)
    parser.add_argument("--n", type=int, default=5)
    args = parser.parse_args()
    try:
        with caller_context(transport="cli", client_name=f"local_assist.tools.{JOB}"):
            result = run(args.category, args.n)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except LocalAssistError as exc:
        print(json.dumps({"error": exc.to_payload()}, indent=2, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
