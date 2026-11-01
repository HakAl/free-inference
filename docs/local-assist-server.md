# `local-assist-server`

A small MCP server that exposes a locally-served model as a set of structured-output tools. The local model is treated as a **generator/noticer**, not a judge: every tool returns structured data with mechanically-validated schema, and consuming skills land their assertions on external signals (tests, classifiers, observed behavior) rather than on the model's confidence in its own output.

## Design principles

- **Treat tool output as advisory, never as verdict.** The model produces candidates; the caller validates them against external reality.
- **Structured outputs.** Every tool returns a typed shape (JSON conforming to a TypedDict), not free text. The tool layer enforces parse/schema/enum validity; the caller decides whether the values are *useful*.
- **No self-verification.** The local model never grades its own output. If you need verification, route it through a different model or an executable check.
- **Mechanical IDs.** Tools assign stable IDs via content hashing (`sha256(text)[:10]`), not by asking the model. Duplicate IDs mechanically indicate model padding.
- **Fail loudly.** Endpoint unreachable, model mismatch, parse failures, schema violations → all raise structured errors. The MCP SDK auto-wraps raised exceptions for the agent.

## Layout

```
free-inference/
├── scripts/
│   ├── local-assist-server          # MCP entry point (--auto-serve optional)
│   ├── delegate-local               # CLI entry point for planner delegation
│   └── delegate-local-e2e           # Live D1 negative test + lsof-sampled cold-start check
├── local_assist/                    # Python package
│   ├── server.py                    # MCP registration; dual framing (line + Content-Length)
│   ├── client.py                    # HTTP client → mlx_lm.server
│   ├── routing.py                   # job → model table
│   ├── logging.py                   # JSONL writer (redacts delegate_task context)
│   ├── lifecycle.py                 # listener verification + opt-in auto-serve + chat check
│   └── tools/
│       ├── propose_eval_prompts.py
│       ├── extract_fields.py
│       ├── compress_context.py
│       └── delegate_task.py
└── runs/
    └── local-assist/
        ├── YYYY-MM-DD.jsonl         # daily index, append-only
        └── YYYY-MM-DD/
            └── <HH-MM-SS>-<tool>-<id>.json
```

## Client responsibilities (`client.py`)

Two response-normalization passes happen at the client layer so every tool inherits them:

- **Strip `<|im_end|>` and other EOS residue.** `mlx_lm.server` has an EOS trim bug that leaves end-of-turn tokens in the raw response text. Stripping at the client layer means tools see clean text.
- **Strip Markdown JSON fences.** Local models often wrap JSON in ```json ... ``` fences despite "no markdown" instructions in the system prompt. Strip a single leading/trailing fence pair before returning. Tools' `parse_and_validate()` then operates on clean JSON.

Neither strip is "fixing" model behavior; both are normalizing known artifacts so the contract layer above can be strict. If the client's strip ever changes the *meaning* of a response, that's a bug.

## MCP tool surface

Four tools. Return types are shaped so consuming skills can verify each item independently:

```python
propose_eval_prompts(category: str, n: int = 5) -> EvalPromptResult
extract_fields(text: str, fields: dict[str, FieldSpec]) -> ExtractFieldsResult
compress_context(
    kind: str,                  # one of: diff, test_output, logs
    text: str,
    focus: str | None = None,
    max_items: int = 10,
) -> CompressContextResult
delegate_task(
    kind: str,                  # one of: draft_code, generate_test_cases, transform_text, focused_qa
    instruction: str,           # 1..8000 chars
    context: str | None = None, # <= 32000 chars; mutually exclusive with context_path
    context_path: str | None = None,
    constraints: list[str] | None = None,
    max_tokens: int = 1536,     # 256..2048
) -> DelegateTaskResult
```

### `propose_eval_prompts`

Generates candidate promptfoo eval prompts with executable JavaScript assertions. The model returns prompt text, expected signal description, the assertion expression, and a category. The tool validates parse/schema/non-empty fields/category/duplicate prompt text and assigns stable IDs.

The consuming skill provides the external contract: render candidates into a generated JSON promptfoo config, run against at least two runnable models, keep candidates whose pass/fail vector is non-uniform across models, print observed vectors.

### `extract_fields`

Extracts a caller-supplied flat schema from source text. The caller defines each field as `string`, `integer`, `number`, `boolean`, or `string_list`, with a description and optional `required` flag.

The tool validates that scalar fields match their requested JSON type or return `null` when absent, `string_list` fields always return an array of strings (never `null`), and `missing_required` is computed by the tool from required fields whose extracted value is `null`.

### `compress_context`

Compresses noisy context into structured action notes. Supported kinds are `diff`, `test_output`, and `logs`. Returns `summary`, `key_points`, `changed_files`, `failures`, `risks`, `commands`, `followups`, and `omitted`.

For `kind=diff`, every `changed_files` entry is mechanically verified against paths present in diff headers; the tool guarantees those came from the input. The other fields are model judgment, not extracted facts; the caller validates them externally.

### `delegate_task`

Delegates a bounded code/test/text/Q&A subtask (`draft_code`, `generate_test_cases`, `transform_text`, or `focused_qa`) to the cleared Rung 1 local model (`qwen3-30b-a3b-2507-mlx-4bit`) at $0 marginal cost. Accepts `instruction` (`<= 8000` chars), optional mutually exclusive `context` or `context_path` (`<= 32000` chars; `context_path` must be a regular non-symlink file inside `LOCAL_ASSIST_WORKSPACE_ROOT` / `cwd` with no `..` traversal and `<= 128000` bytes), optional `constraints` (`<= 20` items), and `max_tokens` (`256..2048`, default `1536`).

Returns `id`, `kind`, `summary`, `output`, `ungrounded_identifiers`, `assumptions`, and `unverified_claims`:
- **Mechanical fields**: `id` is `sha256(normalized_output)[:10]`; `ungrounded_identifiers` is computed deterministically by scanning `output` for URLs, Python/JS imports, and multi-word proper nouns absent as whole tokens/phrases from `instruction + context + constraints` (excluding `<pkg>-free` tokens from grounding).
- **Advisory self-reports**: `assumptions` and `unverified_claims` are model-reported lists. Empty `assumptions` or `unverified_claims` (`[]`) does **not** mean the output is verified; the delegating planner must still verify code, citations, or domain claims against external reality.
- **Audit redaction**: input `context` / `context_path` content is stored as length and SHA-256 hash (`context_chars`, `context_sha256`, and `context_path`) in `args` and `prompt` inside `runs/local-assist/`; model outputs (`raw_response`, `normalized_response`, `parsed_output`), which may quote or transform the context, are stored in full.
- **Data-control rung accounting**: when invoked by a planner running on a lower-control rung (for example Claude Code on Rung 5 `standard_api` or a frontier model on Rung 2/3), any context read by the planner or any tool output returned to the planner enters that planner's data-control rung. Passing `context_path` (or `--context-file` on `scripts/delegate-local`) lets the local tool read a workspace file directly without placing its full raw text into the planner's outbound prompt, though the returned summary/output still enters the planner session.

## Model routing (`routing.py`)

```python
JOB_TO_MODEL = {
    "propose_eval_prompts": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
    "extract_fields": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
    "compress_context": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
    "delegate_task": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
}
```

Tool decides which model to use, not caller. Values are **served OpenAI model IDs** (what `/v1/models` returns and what the chat request's `model` field expects), not registry IDs from `models.yaml`. Replace the default with whatever model you've reviewed and have running locally.

## System prompt template

Every tool's system prompt follows the same shape:

1. **Role**: one sentence on what the model is doing.
2. **Adversarial framing**: instruct the model to find or generate *concrete* artifacts, not to confirm correctness. Never confirmatory.
3. **Explicit criteria**: enumerate the specific classes of output to produce.
4. **Output schema**: state the exact return format. Structured JSON conforming to the tool's TypedDict. No prose preamble, no commentary, no markdown.
5. **Honesty directive (tool-specific)**: each tool has its own equivalent of anti-sycophancy. For generation tools: do not pad with near-duplicates; fewer high-quality outputs is preferable to N outputs with hidden repetition, and if N can't be reached, say so explicitly via `coverage_note`.

## Logging schema

JSONL index for fast scan, full payload as a sibling JSON file:

```json
{
  "ts": "2026-05-15T14:30:00-04:00",
  "tool": "propose_eval_prompts",
  "requested_model": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
  "served_model": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
  "args_summary": {"category": "reasoning", "n_requested": 5},
  "observed": {"n_returned": 5, "coverage_note_present": false},
  "usage": {"prompt_tokens": 120, "completion_tokens": 480},
  "latency_ms": 4321,
  "finish_reason": "stop",
  "payload_path": "runs/local-assist/2026-05-15/14-30-00-propose-eval-prompts-a4f3.json"
}
```

`payload_path` is relative to the repo root. `served_model` is captured separately from `requested_model` so audits can detect any drift between what the tool asked for and what answered.

## Lifecycle expectations

- **Default fail-closed; opt-in `--auto-serve`.** By default (`LOCAL_ASSIST_AUTO_SERVE` unset), `local_assist` does not auto-start models: if port `8080` is down, it raises `model_unavailable` with remediation (`Run: ./scripts/serve-model qwen3-30b-a3b-2507-mlx-4bit (or pass --auto-serve / set LOCAL_ASSIST_AUTO_SERVE=1)`). When `--auto-serve` (or `LOCAL_ASSIST_AUTO_SERVE=1`) is explicitly enabled on `scripts/local-assist-server` or `scripts/delegate-local`, `ensure_local_model_served()` auto-starts the model via `scripts/serve-model <id> --started-by auto-serve` (serialized with `fcntl.flock` on `runs/.serve.lock`), gated on `trust_tier == "local"` and `routing.private_local == "cleared"`. Because `qwen3-30b-a3b-2507-mlx-4bit` holds ~16 GB resident memory, stop it when finished via `./scripts/stop-model qwen3-30b-a3b-2507-mlx-4bit`.
- **Pre-chat listener verification (no silent hot-swap).** `mlx_lm.server` (`0.31.3`) lists every cached Hugging Face model on `/v1/models` and hot-swaps whichever `model` a chat request names. Therefore `ensure_local_model_served()` always runs `scripts/verify-served-model <id>` **before** any chat call: `verify-served-model` checks both `runs/.serve*.pid` records and live OS listener `--model <repo>` flags on the port (`lsof` + `ps`, failing closed if no listener with a matching `--model` flag can be identified; note that any future `trust_tier == "local"` custom runtime must also expose `--model <served_model_id>` or extend `extract_model_arg_from_command`) and exits with code `3` (`EXIT_MODEL_MISMATCH`) if another model is occupying port `8080`, failing closed before any chat request can trigger a hot-swap.
- **Per-call check and shared deadline.** After `ensure_local_model_served()` succeeds, `require_chat_succeeds()` verifies `/v1/models` and runs a short health-check chat call confirming `served_model == model` (note: in `mlx_lm.server`, `/v1/models` answers as soon as the HTTP listener binds while weights load on the generation thread during the smoke chat, and `served_model` echoes `requested_model` rather than providing independent proof; the pre-chat OS listener `--model` check is the authoritative occupant check). Every tool (`delegate_task`, `compress_context`, `extract_fields`, `propose_eval_prompts`) shares a single overall `default_timeout_seconds()` (`120`s) deadline across `ensure_local_model_served`, `require_chat_succeeds`, and the tool's `chat()` request.
- **Workspace root for `context_path`.** `scripts/local-assist-server` exports `LOCAL_ASSIST_WORKSPACE_ROOT="${LOCAL_ASSIST_WORKSPACE_ROOT:-$(pwd -P)}"` before changing directory to the repository root, and `scripts/opencode-local` sets `LOCAL_ASSIST_WORKSPACE_ROOT` to the caller's target workspace directory. Avoid launching from `$HOME` (`~`) so `context_path` and `opencode`'s file tools stay scoped to a specific project directory.
- **Endpoint unreachable / wrong model / chat mismatch / timeout / malformed output** → structured error raised. No retry, no auto-repair. The caller decides what to do.

## Explicit non-goals

- Auto model swapping
- Result caching / memoization
- Streaming responses (batched only)
- Multi-prompt batching
- Auth (localhost-only)
- Rate limiting
- Tool composition / chaining
- Embeddings, RAG, vector store
- **Self-verification by the local model.** Undermines the cross-family separation that makes downstream skill verification credible.
- **Semantic quality validation inside the tool.** The tool validates parse/schema/distinct-IDs. Whether the output is *good* is the consuming skill's job, validated against external signals.

If you find yourself wanting one of these, measure that you need it in JSONL logs first, then build.

## What this gets you that a chat UI doesn't

- **Programmatic invocation** from an orchestrator agent: the agent can include local model output in its own reasoning instead of you pasting between windows.
- **Structured outputs**: tools return shape, not free text, so a skill can verify each item against external signals.
- **Audit trail with observed values**: every call logged with what was asked, what was returned, and which model actually answered.
- **Failure transparency**: endpoint, model, timeout, malformed output all surface as structured errors instead of vague chat failures.
- **Cross-family separation preserved**: orchestrator (e.g., a frontier API model) is a different family from local model (a Qwen/Phi/etc. that you've reviewed and served). Skills doing the verification work get the cross-family benefit for free, as long as the local model never grades its own output.

## Installing as an MCP server

Register `scripts/local-assist-server` (absolute path) in your MCP client's config. The script is a thin entry point that starts the Python MCP server defined in `local_assist/server.py`. The package resolves `models.yaml` and other repo-local files via paths relative to its own `__file__`, so the working directory of the MCP client doesn't matter.
