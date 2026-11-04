from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from typing import Any, TypedDict

from ..client import chat, default_timeout_seconds
from ..errors import LocalAssistError, ModelOutputMalformed
from ..lifecycle import require_chat_succeeds
from ..logging import log_call
from ..routing import JOB_TO_MODEL


JOB = "extract_fields"
ALLOWED_TYPES = {"string", "integer", "number", "boolean", "string_list"}
MAX_TEXT_CHARS = 100_000
MAX_FIELDS = 25
MAX_FIELD_NAME_LEN = 64


class ExtractFieldsResult(TypedDict):
    extracted: dict[str, Any]
    missing_required: list[str]
    extraction_note: str | None


SYSTEM = """You extract structured fields from a block of text.

You are given:
- text: the source content
- fields: an object mapping field_name to a spec with type and description

For each field, return the value found in the text. Use null when the field is
not present. Do not guess, infer, or fabricate values; null is the correct
answer when the text does not state the value.

Allowed types and how to return them:
- string: a string
- integer: a JSON integer, no quotes
- number: a JSON number (integer or float)
- boolean: true or false
- string_list: always a JSON array of strings, never null. Use [] when the
  text does not list any matching items, whether because it explicitly says
  none or because the list is simply not mentioned. The caller knows that
  empty array collapses these two cases together.

Output a JSON object with exactly two top-level keys: extracted and
extraction_note. Do not add any other top-level keys.
- extracted: an object whose keys are exactly the requested field names and
  whose values match the requested type (or are null when absent).
- extraction_note: null unless something about the extraction is ambiguous or
  partial; then a short human-readable explanation.

Output JSON only, no commentary, no markdown. Do not add fields that were not
requested. Do not omit fields that were requested."""


def run(text: Any, fields: Any) -> ExtractFieldsResult:
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
            "text_chars": text_chars,
            "text_sha256": text_sha256,
            "fields": fields,
        },
        redact_prompt=True,
    ) as call:
        try:
            validated_fields = validate_field_specs(text, fields)
            deadline = time.monotonic() + float(default_timeout_seconds())
            require_chat_succeeds(model, deadline=deadline)
            prompt = build_prompt(text, validated_fields)
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
            parsed = parse_and_validate(result.text, validated_fields)
            output: ExtractFieldsResult = parsed
            observed = {
                "n_fields_requested": len(validated_fields),
                "n_fields_found": sum(1 for v in parsed["extracted"].values() if v is not None),
                "n_missing_required": len(parsed["missing_required"]),
                "extraction_note_present": parsed["extraction_note"] is not None,
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


def validate_field_specs(text: Any, fields: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(text, str) or not text.strip():
        raise ModelOutputMalformed("invalid_arguments", "text must be a non-empty string.")
    if len(text) > MAX_TEXT_CHARS:
        raise ModelOutputMalformed(
            "invalid_arguments",
            "text exceeds maximum length.",
            details={"max_chars": MAX_TEXT_CHARS, "observed": len(text)},
        )
    if not isinstance(fields, dict) or not fields:
        raise ModelOutputMalformed("invalid_arguments", "fields must be a non-empty object.")
    if len(fields) > MAX_FIELDS:
        raise ModelOutputMalformed(
            "invalid_arguments",
            "fields exceeds maximum count.",
            details={"max_fields": MAX_FIELDS, "observed": len(fields)},
        )

    validated: dict[str, dict[str, Any]] = {}
    for name, spec in fields.items():
        if not isinstance(name, str) or not name.strip() or len(name) > MAX_FIELD_NAME_LEN:
            raise ModelOutputMalformed(
                "invalid_arguments",
                "field name must be a non-empty string within length limit.",
                details={"name": name, "max_len": MAX_FIELD_NAME_LEN},
            )
        if not isinstance(spec, dict):
            raise ModelOutputMalformed("invalid_arguments", f"fields[{name!r}] must be an object.")
        type_name = spec.get("type")
        description = spec.get("description")
        required = spec.get("required", False)
        if type_name not in ALLOWED_TYPES:
            raise ModelOutputMalformed(
                "invalid_arguments",
                f"fields[{name!r}].type is invalid.",
                details={"allowed": sorted(ALLOWED_TYPES), "observed": type_name},
            )
        if not isinstance(description, str) or not description.strip():
            raise ModelOutputMalformed(
                "invalid_arguments",
                f"fields[{name!r}].description must be a non-empty string.",
            )
        if not isinstance(required, bool):
            raise ModelOutputMalformed(
                "invalid_arguments",
                f"fields[{name!r}].required must be a boolean.",
            )
        validated[name] = {"type": type_name, "description": description, "required": required}
    return validated


def build_prompt(text: str, fields: dict[str, dict[str, Any]]) -> str:
    fields_block = json.dumps(fields, indent=2, ensure_ascii=False)
    return f"fields:\n{fields_block}\n\ntext:\n{text}"


def parse_and_validate(model_text: str, fields: dict[str, dict[str, Any]]) -> ExtractFieldsResult:
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

    unexpected_top_level = set(raw.keys()) - {"extracted", "extraction_note"}
    if unexpected_top_level:
        raise ModelOutputMalformed(
            "malformed_model_output",
            "Model output has unexpected top-level keys.",
            details={"unexpected": sorted(unexpected_top_level)},
        )

    extracted_raw = raw.get("extracted")
    if not isinstance(extracted_raw, dict):
        raise ModelOutputMalformed("malformed_model_output", "Model output must contain extracted object.")

    note_raw = raw.get("extraction_note")
    if note_raw is not None and not isinstance(note_raw, str):
        raise ModelOutputMalformed("malformed_model_output", "extraction_note must be a string or null.")

    requested = set(fields.keys())
    returned = set(extracted_raw.keys())
    unexpected = returned - requested
    if unexpected:
        raise ModelOutputMalformed(
            "malformed_model_output",
            "Model returned fields that were not requested.",
            details={"unexpected": sorted(unexpected)},
        )
    missing_keys = requested - returned
    if missing_keys:
        raise ModelOutputMalformed(
            "malformed_model_output",
            "Model omitted requested fields.",
            details={"omitted": sorted(missing_keys)},
        )

    extracted: dict[str, Any] = {}
    missing_required: list[str] = []
    for name, spec in fields.items():
        value = extracted_raw[name]
        if value is None:
            if spec["type"] == "string_list":
                raise ModelOutputMalformed(
                    "malformed_model_output",
                    f"extracted[{name!r}] is null but string_list must always be an array (use [] for empty).",
                )
            extracted[name] = None
            if spec["required"]:
                missing_required.append(name)
            continue
        check_value_type(name, spec["type"], value)
        extracted[name] = value

    return {
        "extracted": extracted,
        "missing_required": sorted(missing_required),
        "extraction_note": note_raw,
    }


def check_value_type(name: str, type_name: str, value: Any) -> None:
    if type_name == "string":
        if not isinstance(value, str):
            raise ModelOutputMalformed(
                "malformed_model_output",
                f"extracted[{name!r}] expected string.",
                details={"observed_type": type(value).__name__},
            )
    elif type_name == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ModelOutputMalformed(
                "malformed_model_output",
                f"extracted[{name!r}] expected integer.",
                details={"observed_type": type(value).__name__},
            )
    elif type_name == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ModelOutputMalformed(
                "malformed_model_output",
                f"extracted[{name!r}] expected number.",
                details={"observed_type": type(value).__name__},
            )
    elif type_name == "boolean":
        if not isinstance(value, bool):
            raise ModelOutputMalformed(
                "malformed_model_output",
                f"extracted[{name!r}] expected boolean.",
                details={"observed_type": type(value).__name__},
            )
    elif type_name == "string_list":
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ModelOutputMalformed(
                "malformed_model_output",
                f"extracted[{name!r}] expected list of strings.",
                details={"observed_type": type(value).__name__},
            )


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract structured fields from text via the local model.")
    parser.add_argument("--text", required=True, help="Source text (or @path to read from a file).")
    parser.add_argument(
        "--fields",
        required=True,
        help='JSON object mapping field_name to {"type":..., "description":..., "required":...} (or @path).',
    )
    args = parser.parse_args()
    text = _read_arg(args.text)
    fields = json.loads(_read_arg(args.fields))
    try:
        result = run(text, fields)
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
