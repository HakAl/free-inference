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
from ..logging import log_call
from ..routing import JOB_TO_MODEL


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
- assertion: a promptfoo JavaScript expression that returns boolean and can be
  used directly as assert[].value
- category: one of format, reasoning, coding, long_context,
  instruction_following, structured_output

The assertion must be executable JavaScript, not prose. It may reference the
promptfoo variable output. If it is a multi-statement assertion, include an
explicit return. Output JSON only, no commentary, no markdown.

Do not pad with near-duplicates. If you cannot produce N distinct prompts that
meaningfully differ, return fewer and set coverage_note to a short explanation.

Important: your prompts are candidates only. A downstream skill will keep only
candidates that produce non-uniform pass/fail vectors across at least two
runnable models. Usefulness of a discriminating prompt remains a human decision."""


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
            if n < 1 or n > 25:
                raise ModelOutputMalformed("invalid_arguments", "n must be between 1 and 25.", details={"n": n})

            deadline = time.monotonic() + float(default_timeout_seconds())
            require_chat_succeeds(model, deadline=deadline)
            call.record_prompt(system=SYSTEM, prompt=prompt)
            result = chat(
                model,
                SYSTEM,
                prompt,
                response_format="json",
                timeout_seconds=max(1, int(deadline - time.monotonic())),
            )
            call.record_raw_response(raw_response=result.raw_text, normalized_response=result.text)
            parsed = parse_and_validate(result.text)
            prompts = parsed["prompts"][:n]
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


def parse_and_validate(text: str) -> EvalPromptResult:
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

    prompts: list[EvalPrompt] = []
    seen_ids: set[str] = set()
    seen_prompts: set[str] = set()
    for idx, item in enumerate(prompts_raw):
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
        if not isinstance(category, str) or category not in ALLOWED_CATEGORIES:
            raise ModelOutputMalformed(
                "malformed_model_output",
                f"prompts[{idx}].category is invalid.",
                details={"allowed": sorted(ALLOWED_CATEGORIES), "observed": category},
            )

        normalized_prompt = " ".join(prompt_value.split())
        if normalized_prompt in seen_prompts:
            raise ModelOutputMalformed("malformed_model_output", f"prompts[{idx}].prompt duplicates an earlier prompt.")
        seen_prompts.add(normalized_prompt)

        prompt_id = stable_id(prompt_value)
        if prompt_id in seen_ids:
            raise ModelOutputMalformed("malformed_model_output", f"prompts[{idx}].id collision.")
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

    return {"prompts": prompts, "coverage_note": coverage_note_raw}


def stable_id(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:10]


def main() -> int:
    parser = argparse.ArgumentParser(description="Propose local LLM eval prompt candidates.")
    parser.add_argument("--category", required=True)
    parser.add_argument("--n", type=int, default=5)
    args = parser.parse_args()
    try:
        result = run(args.category, args.n)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except LocalAssistError as exc:
        print(json.dumps({"error": exc.to_payload()}, indent=2, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
