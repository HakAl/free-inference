from __future__ import annotations

import argparse
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


JOB = "select_context"
MAX_QUERY_CHARS = 2_000
MAX_PATHS = 10
MAX_FILE_BYTES = 32_768
MAX_COMBINED_BYTES = 96_000
DEFAULT_MAX_EXCERPTS = 5
MIN_MAX_EXCERPTS = 1
MAX_MAX_EXCERPTS = 10
DEFAULT_MAX_LINES_PER_EXCERPT = 40
MIN_MAX_LINES_PER_EXCERPT = 1
MAX_MAX_LINES_PER_EXCERPT = 120


class ContextExcerpt(TypedDict):
    path: str
    start_line: int
    end_line: int
    reason: str
    excerpt: str
    source_sha256: str


class SelectContextResult(TypedDict):
    excerpts: list[ContextExcerpt]
    unanswered_aspects: list[str]


SYSTEM = """You select the minimal relevant line spans from supplied workspace files to answer a specific question.

You are given:
- query: the question or lookup objective
- max_excerpts: maximum number of spans to return
- max_lines_per_excerpt: maximum lines per span
- files: workspace-relative paths with 1-indexed numbered lines

Output a JSON object with exactly two top-level keys:
selections, unanswered_aspects.
Do not add other top-level keys. Do not omit either key.

Field semantics:
- selections: array (0..max_excerpts) of objects, each with exact keys:
  - path: exact workspace-relative path from the supplied files
  - start_line: 1-indexed inclusive start line integer
  - end_line: 1-indexed inclusive end line integer (>= start_line)
  - reason: short 1-sentence explanation of why this span answers the query
- unanswered_aspects: array of short strings (0..10) naming parts of the query
  that cannot be answered from the supplied files. Return [] when fully covered.

Hard rules:
- NEVER copy or rewrite file text into JSON; return line coordinates only. A
  deterministic caller slices verbatim text from disk using your coordinates.
- ONLY reference `path` values that appear in the supplied files list.
- Prefer tight spans (at most max_lines_per_excerpt lines each).

Output JSON only, no commentary, no markdown."""


def validate_inputs(
    query: Any,
    paths: Any,
    max_excerpts: Any = DEFAULT_MAX_EXCERPTS,
    max_lines_per_excerpt: Any = DEFAULT_MAX_LINES_PER_EXCERPT,
) -> dict[str, Any]:
    if not isinstance(query, str) or not query.strip():
        raise ModelOutputMalformed("invalid_arguments", "query must be a non-empty string.")
    if len(query) > MAX_QUERY_CHARS:
        raise ModelOutputMalformed(
            "invalid_arguments",
            "query exceeds maximum length.",
            details={"max_chars": MAX_QUERY_CHARS, "observed": len(query)},
        )
    if not isinstance(paths, list) or not paths:
        raise ModelOutputMalformed(
            "invalid_arguments",
            f"paths must be a non-empty list of 1..{MAX_PATHS} workspace file paths.",
        )
    if len(paths) > MAX_PATHS:
        raise ModelOutputMalformed(
            "invalid_arguments",
            f"paths exceeds maximum file count ({MAX_PATHS}).",
            details={"max_paths": MAX_PATHS, "observed": len(paths)},
        )
    if isinstance(max_excerpts, bool) or not isinstance(max_excerpts, int):
        raise ModelOutputMalformed("invalid_arguments", "max_excerpts must be an integer.")
    if max_excerpts < MIN_MAX_EXCERPTS or max_excerpts > MAX_MAX_EXCERPTS:
        raise ModelOutputMalformed(
            "invalid_arguments",
            "max_excerpts out of range.",
            details={"min": MIN_MAX_EXCERPTS, "max": MAX_MAX_EXCERPTS, "observed": max_excerpts},
        )
    if isinstance(max_lines_per_excerpt, bool) or not isinstance(max_lines_per_excerpt, int):
        raise ModelOutputMalformed("invalid_arguments", "max_lines_per_excerpt must be an integer.")
    if (
        max_lines_per_excerpt < MIN_MAX_LINES_PER_EXCERPT
        or max_lines_per_excerpt > MAX_MAX_LINES_PER_EXCERPT
    ):
        raise ModelOutputMalformed(
            "invalid_arguments",
            "max_lines_per_excerpt out of range.",
            details={
                "min": MIN_MAX_LINES_PER_EXCERPT,
                "max": MAX_MAX_LINES_PER_EXCERPT,
                "observed": max_lines_per_excerpt,
            },
        )

    files_map: dict[str, dict[str, Any]] = {}
    ordered_paths: list[str] = []
    combined_bytes = 0
    for raw_p in paths:
        rel_path, content, sha256_hex = read_confined_workspace_file(
            raw_p,
            max_bytes=MAX_FILE_BYTES,
            param_name="paths",
        )
        if rel_path in files_map:
            continue
        b_len = len(content.encode("utf-8"))
        combined_bytes += b_len
        if combined_bytes > MAX_COMBINED_BYTES:
            raise ModelOutputMalformed(
                "invalid_arguments",
                f"Combined size of supplied paths exceeds {MAX_COMBINED_BYTES} bytes.",
                details={"max_combined_bytes": MAX_COMBINED_BYTES, "observed": combined_bytes},
            )
        raw_lines = re.findall(r"[^\n]*\n|[^\n]+", content)
        lines = [ln.rstrip("\r\n") for ln in raw_lines]
        files_map[rel_path] = {
            "lines": lines,
            "raw_lines": raw_lines,
            "sha256": sha256_hex,
            "bytes": b_len,
        }
        ordered_paths.append(rel_path)

    return {
        "query": query.strip(),
        "ordered_paths": ordered_paths,
        "files_map": files_map,
        "combined_bytes": combined_bytes,
        "max_excerpts": max_excerpts,
        "max_lines_per_excerpt": max_lines_per_excerpt,
    }


def build_prompt(validated: dict[str, Any], *, redact_files: bool = False) -> str:
    parts = [
        f"query: {validated['query']}",
        f"max_excerpts: {validated['max_excerpts']}",
        f"max_lines_per_excerpt: {validated['max_lines_per_excerpt']}",
        "files:",
    ]
    for rel_path in validated["ordered_paths"]:
        info = validated["files_map"][rel_path]
        lines: list[str] = info["lines"]
        parts.append(f"=== FILE: {rel_path} (lines=1..{len(lines)}) ===")
        if redact_files:
            parts.append(f"<redacted in audit log: lines={len(lines)}, sha256={info['sha256']}>")
        else:
            for idx, line in enumerate(lines, start=1):
                parts.append(f"{idx}: {line}")
    return "\n".join(parts)


def parse_and_slice(
    model_text: str,
    validated: dict[str, Any],
) -> tuple[SelectContextResult, dict[str, Any]]:
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

    unexpected = set(raw.keys()) - {"selections", "unanswered_aspects"}
    if unexpected:
        raise ModelOutputMalformed(
            "malformed_model_output",
            "Model output has unexpected top-level keys.",
            details={"unexpected": sorted(unexpected)},
        )
    if "selections" not in raw or "unanswered_aspects" not in raw:
        raise ModelOutputMalformed(
            "malformed_model_output",
            "Model output must include both 'selections' and 'unanswered_aspects'.",
        )

    raw_selections = raw["selections"]
    if not isinstance(raw_selections, list):
        raise ModelOutputMalformed("malformed_model_output", "selections must be a list.")

    raw_unanswered = raw["unanswered_aspects"]
    if not isinstance(raw_unanswered, list) or not all(isinstance(x, str) for x in raw_unanswered):
        raise ModelOutputMalformed(
            "malformed_model_output",
            "unanswered_aspects must be a list of strings.",
        )

    files_map: dict[str, dict[str, Any]] = validated["files_map"]
    max_excerpts: int = validated["max_excerpts"]
    max_lines: int = validated["max_lines_per_excerpt"]

    excerpts: list[ContextExcerpt] = []
    seen_spans: set[tuple[str, int, int]] = set()
    dropped_ungrounded = 0
    clamped_spans = 0

    for idx, item in enumerate(raw_selections):
        if not isinstance(item, dict):
            raise ModelOutputMalformed("malformed_model_output", f"selections[{idx}] must be an object.")
        raw_path = item.get("path")
        start_line = item.get("start_line")
        end_line = item.get("end_line")
        reason = item.get("reason")

        if not isinstance(raw_path, str) or not raw_path.strip():
            dropped_ungrounded += 1
            continue
        norm_path = raw_path.strip().lstrip("./")
        file_entry = files_map.get(raw_path.strip()) or files_map.get(norm_path)
        canonical_path = (
            raw_path.strip()
            if raw_path.strip() in files_map
            else (norm_path if norm_path in files_map else None)
        )
        if file_entry is None or canonical_path is None:
            dropped_ungrounded += 1
            continue

        if (
            isinstance(start_line, bool)
            or not isinstance(start_line, int)
            or isinstance(end_line, bool)
            or not isinstance(end_line, int)
        ):
            raise ModelOutputMalformed(
                "malformed_model_output",
                f"selections[{idx}] start_line and end_line must be integers.",
            )
        if not isinstance(reason, str) or not reason.strip():
            reason = "Relevant span."

        lines: list[str] = file_entry["lines"]
        if not lines:
            dropped_ungrounded += 1
            continue

        s_line = max(1, min(start_line, len(lines)))
        e_line = max(s_line, min(end_line, len(lines)))
        if e_line - s_line + 1 > max_lines:
            e_line = s_line + max_lines - 1
            clamped_spans += 1

        span_key = (canonical_path, s_line, e_line)
        if span_key in seen_spans:
            continue
        seen_spans.add(span_key)

        raw_lines: list[str] | None = file_entry.get("raw_lines")
        if raw_lines is not None:
            verbatim = "".join(raw_lines[s_line - 1 : e_line])
        else:
            verbatim = "\n".join(lines[s_line - 1 : e_line])
        excerpts.append(
            {
                "path": canonical_path,
                "start_line": s_line,
                "end_line": e_line,
                "reason": reason.strip()[:300],
                "excerpt": verbatim,
                "source_sha256": file_entry["sha256"],
            }
        )
        if len(excerpts) >= max_excerpts:
            break

    unanswered = [u.strip() for u in raw_unanswered if u.strip()][:10]
    result: SelectContextResult = {
        "excerpts": excerpts,
        "unanswered_aspects": unanswered,
    }
    meta = {
        "dropped_ungrounded_selections": dropped_ungrounded,
        "clamped_spans": clamped_spans,
    }
    return result, meta


def run(
    query: Any,
    paths: Any,
    max_excerpts: Any = DEFAULT_MAX_EXCERPTS,
    max_lines_per_excerpt: Any = DEFAULT_MAX_LINES_PER_EXCERPT,
) -> SelectContextResult:
    model = JOB_TO_MODEL[JOB]
    with log_call(
        JOB,
        model,
        args={
            "query": query if isinstance(query, str) else str(query),
            "paths": paths if isinstance(paths, list) else [],
            "max_excerpts": max_excerpts,
            "max_lines_per_excerpt": max_lines_per_excerpt,
        },
        redact_prompt=True,
    ) as call:
        try:
            validated = validate_inputs(
                query=query,
                paths=paths,
                max_excerpts=max_excerpts,
                max_lines_per_excerpt=max_lines_per_excerpt,
            )
            call.args.update(
                {
                    "query": validated["query"],
                    "paths": validated["ordered_paths"],
                    "max_excerpts": validated["max_excerpts"],
                    "max_lines_per_excerpt": validated["max_lines_per_excerpt"],
                }
            )
            deadline = time.monotonic() + float(default_timeout_seconds())
            with call.measure_readiness():
                require_chat_succeeds(model, deadline=deadline)
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise ModelTimeout(
                    "timeout",
                    f"Timed out before select_context completion request for {model}.",
                    details={"model": model},
                )
            prompt = build_prompt(validated, redact_files=False)
            redacted_prompt = build_prompt(validated, redact_files=True)
            call.record_prompt(system=SYSTEM, prompt=redacted_prompt)
            result = chat(
                model,
                SYSTEM,
                prompt,
                response_format="json",
                max_tokens=1024,
                temperature=0.1,
                timeout_seconds=max(1, int(rem)),
            )
            call.record_completion(result)
            call.record_raw_response(raw_response=result.raw_text, normalized_response=result.text)
            parsed, meta = parse_and_slice(result.text, validated)
            observed = {
                "n_paths_supplied": len(validated["ordered_paths"]),
                "combined_bytes": validated["combined_bytes"],
                "n_excerpts": len(parsed["excerpts"]),
                "n_unanswered": len(parsed["unanswered_aspects"]),
                "dropped_ungrounded_selections": meta["dropped_ungrounded_selections"],
                "clamped_spans": meta["clamped_spans"],
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Select verbatim evidence-backed file excerpts for a query via Rung 1 coordinate selection."
    )
    parser.add_argument("--query", required=True, help="Question or lookup objective.")
    parser.add_argument(
        "--path",
        dest="paths",
        action="append",
        required=True,
        help="Workspace-relative file path (may be repeated 1..10 times).",
    )
    parser.add_argument("--max-excerpts", type=int, default=DEFAULT_MAX_EXCERPTS)
    parser.add_argument("--max-lines-per-excerpt", type=int, default=DEFAULT_MAX_LINES_PER_EXCERPT)
    args = parser.parse_args(argv)
    try:
        with caller_context(transport="cli", client_name=f"local_assist.tools.{JOB}"):
            res = run(
                query=args.query,
                paths=args.paths,
                max_excerpts=args.max_excerpts,
                max_lines_per_excerpt=args.max_lines_per_excerpt,
            )
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0
    except LocalAssistError as exc:
        print(json.dumps({"error": exc.to_payload()}, indent=2, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
