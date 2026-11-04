# Local LLM Evaluation Workbench Plan

> **Current Architecture & Lineage Note**: `free-inference` evolved from an earlier Apple Silicon MLX evaluation workbench (`local-llm-lab`, May 2026) and expanded in October-November 2026 to the 5-rung data-control architecture (`local`, `enclave_weights_attested`, `enclave_runtime_attested`, `zdr_contract`, `standard_api`), hardware-backed Secure Enclave key sealing (`se-key-proxy`), and locked-down OpenCode launchers (`opencode-local`, `opencode-attested`). This document records the evaluation workbench design and milestone criteria. See [`docs/proposal.md`](./proposal.md) for the 5-rung architecture and [`models.yaml`](../models.yaml) plus [`docs/evals/`](./evals/README.md) for current model clearance status and committed evaluation evidence.

## Purpose

Build a durable local LLM lab for an Apple Silicon MacBook with 48 GB RAM. The workbench should make it easy to scout, verify, run, compare, and revisit local models as new Gemma, Qwen, Kimi, DeepSeek, and other releases appear.

The first target is a repeatable evaluation loop for coding and technical research tasks. The system should measure both quality and latency, preserve raw outputs, and support human consensus on which models deserve which roles.

## Guiding Decisions

- Optimize for practical local use on Apple Silicon, ideally with MLX.
- Prefer existing trusted tools before building custom UI.
- Keep the first implementation lightweight: no Open WebUI or Docker in v1.
- Treat model provenance, license, and hardware fit as first-class gates before downloading large weights.
- Measure quality and latency without fixing weights too early; decide tradeoffs after seeing data.
- Support offline operation after setup and downloads.
- Design for ongoing model scouting, not a one-time experiment.
- Treat model IDs in this document as illustrative until they are verified in `models.yaml`. `models.yaml` is the source of truth.

## Candidate Stack

### Primary v1 stack

- `mlx-lm`: text model serving and MLX runtime support.
- `mlx-vlm`: multimodal or VLM-packaged models, especially Gemma 4 variants if required.
- `promptfoo`: repeatable eval harness, model comparison, and local results viewer.
- `uv`: Python environment and package management.
- Node 22+: `promptfoo` runtime.
- Project-local scripts in `scripts/`: stable command interface for setup, serving, evals, and viewing results.

### Deferred / optional tools

- Open WebUI: optional later human comparison UI if promptfoo is not enough.
- Docker: avoid in v1 unless a deferred UI or tool clearly justifies it.
- Ollama/GGUF: fallback path if MLX serving blocks progress or if a strong model is only practical there.
- LLM-as-judge: defer until human scoring is understood.
- Full agent harness: defer until basic model quality, stability, and structured output are known.

## First Candidate Model Policy

Start with models that are MLX-ready, likely to fit comfortably on 48 GB unified memory, and useful for coding or technical work.

Practical fit policy for this Mac:

- Aim to keep model weights plus KV cache under about 32 GB resident memory so macOS, editor, browser, and shell tools remain usable.
- Dense models around 30B parameters or smaller are plausible at 4-bit quantization.
- Sparse/MoE models can fit only when active parameters, quantization, KV cache, and runtime overhead are favorable; total parameter count alone is not enough.
- Very large MoE models, including trillion-parameter Kimi-class models, are stretch or remote-baseline candidates unless a reviewed quantization proves they fit locally.
- Disqualify candidates from the primary list when expected resident memory exceeds the practical budget or when fit evidence is only speculative.

Quantization strategy:

- Prefer reviewed 4-bit MLX conversions for the first pass.
- For MLX, record quantization as bits, group size, conversion tool, and conversion version. Do not assume GGUF names such as `Q4_K_M` apply to native MLX models.
- For GGUF/Ollama fallback models, prefer strong 4-bit quality/performance tradeoffs such as `Q4_K_M` when available and well-sourced.
- When several MLX 4-bit conversions exist for the same upstream model, prefer conversions with clear provenance, documented group size, current MLX compatibility, and community/runtime evidence.
- Treat quantization choice as part of the eval result: a worse quant can make a strong upstream model look bad.

Initial model classes:

- Gemma 4 26B A4B 4-bit MLX as a top general reasoning/coding candidate.
- Gemma 4 E4B or E2B MLX as fast small-model baselines.
- Qwen coding model with a good MLX conversion, such as Qwen3-Coder-Next or a newer practical Qwen3.5/Qwen3.6 coding variant if verified.
- One fast small model for latency-sensitive utility tasks.
- Kimi K2.x and very large Qwen MoE models as stretch candidates only unless a practical local quantization and runtime fit are verified.

Do not download models just because they are interesting. Every large model must pass provenance review first.

## Candidate Provenance Review Gate

Before downloading large weights, create a candidate table and cross-review it with a second strong model or reviewer.

Each candidate must record:

- Local alias.
- Exact source repo, such as Hugging Face or Ollama ID.
- Upstream publisher.
- Conversion publisher, if different.
- License.
- Release date or last verified date.
- Architecture.
- Total parameters and active parameters, when applicable.
- Quantization type.
- Expected disk footprint.
- Expected RAM footprint.
- Context window.
- Modalities.
- Required runtime: `mlx-lm`, `mlx-vlm`, `ollama`, or other OpenAI-compatible server.
- Evidence that it works on Apple Silicon / MLX.
- Source links.
- Why it belongs in the eval.
- Known risks or caveats.
- Chat template source and whether system/user/assistant roles are supported.
- Runtime version used to create or validate the conversion, when available.

Review workflow:

1. Codex scouts candidates and fills the table with sources.
2. User cross-checks the table in this workspace with Claude or another strong model, asking it to challenge provenance, fit, missing candidates, and wasted downloads.
3. Only models that survive review move to `reviewed` status.
4. Download only the reviewed models needed for the current milestone.

Keep the cross-review prompt and response under `reviews/candidates/` so the process becomes reusable and can later move into the `local-llm-scout` skill.

## Model Registry

Create `models.yaml` as the source of truth for model lifecycle and plug-and-play updates.

Suggested schema:

```yaml
models:
  - id: example-model-mlx-4bit
    status: candidate
    repo: example-org/example-model-mlx-4bit
    upstream: example-publisher/example-model
    converter: example-org
    conversion_runtime_version: null
    runtime: mlx-lm
    serve_command: null
    promptfoo_provider:
      id: openai:chat:example-org/example-model-mlx-4bit
      apiBaseUrl: http://127.0.0.1:8080/v1
      apiKey: none
      apiKeyEnvar: null
    capabilities:
      tool_calling: false
    remote_trust: null
    # When runtime is `proxy` or `remote` (e.g. in a hybrid/baseline fork):
    # remote_trust:
    #   tier: enclave_runtime_attested # local | enclave_weights_attested | enclave_runtime_attested | zdr_contract | standard_api
    #   attestation_method: null
    #   weights_hash: null             # dmverity:sha256:<64-hex> (required for enclave_weights_attested)
    #   weights_source: null           # <org>/<repo>@<40-char-sha> (required for enclave_weights_attested)
    #   weights_verified_by: null      # e.g. "modelwrap --verify" (required for enclave_weights_attested)
    #   weights_verified_date: null    # YYYY-MM-DD (required for enclave_weights_attested)
    #   weights_verification_artifact: null # committed relative path, e.g. docs/attestations/<file> (required for enclave_weights_attested)
    #   usage_policy: unknown          # unknown | enclave_no_inspection | provider_filtered | provider_terms_apply
    #   jurisdiction: null
    #   pricing_per_m_tokens:
    #     input: null
    #     output: null
    license: null
    release_date: null
    verified_date: null
    params_total: null
    params_active: null
    quantization:
      bits: 4
      group_size: null
      tool: mlx-lm
      tool_version: null
    disk_gb_estimate: null
    ram_gb_estimate: null
    context_window: null
    modalities:
      - text
      - image
      - video
    chat_template:
      source: null
      roles_supported: []
    source_links: []
    fit_notes: null
    review_notes: null
    eval_summary: null
```

The example above is illustrative. It must not be treated as verified until a live source check confirms the exact repo, license, runtime, and fit.

Statuses:

- `candidate`
- `reviewed`
- `downloaded` (or `attested` for verified remote/proxy endpoints in forks)
- `sanity_checked`
- `runnable`
- `evaluated`
- `default`
- `archived`

## Repository Layout

```text
.
├── AGENTS.md
├── docs/
│   ├── plan.md
│   ├── local-assist-server.md
│   └── decisions/
│       └── <date>-model-selection.md
├── models.yaml
├── scripts/
│   ├── setup
│   ├── models
│   ├── serve-model
│   ├── stop-model
│   ├── sanity-check
│   ├── eval
│   ├── timing
│   └── view
├── evals/
│   ├── suites/
│   ├── prompts/
│   └── rubrics/
├── runs/
│   └── <date>-<suite>-<model>/
│       ├── output.json
│       ├── metrics.json
│       └── notes.md
├── reviews/
│   ├── candidates/
│   │   └── <date>-candidates.md
│   └── evals/
│       └── <date>-<suite>.md
```

## Script Interface

The first usable interface is the repo itself plus promptfoo.

Target scripts:

- `scripts/setup`: install or verify Homebrew dependencies, `uv`, Python packages, Node, and promptfoo.
- `scripts/models`: list candidates from `models.yaml` with status, runtime, trust tier, endpoint, size, and notes.
- `scripts/serve-model <model-id> [--port PORT] [--chat-template-args JSON]`: start the local server or proxy for the selected model using the host/port from `models.yaml`.
- `scripts/stop-model [model-id | --all]`: stop the active local model server recorded in `runs/.serve.pid` or per-model `runs/.serve-<model-id>.pid`.
- `scripts/verify-served-model <model-id> [--wait SECONDS]`: verify `/v1/models` on the model's configured `apiBaseUrl` matches the expected repo ID.
- `scripts/sanity-check <model-id>`: run a one-prompt tokenizer/chat-template smoke test before full evals.
- `scripts/render-suite <sanity|v1|tools>`: render suite configuration with long-context fixtures and provider definitions merged from `models.yaml`.
- `scripts/eval <sanity|v1|tools> <model-id>`: run promptfoo evals and save outputs.
- `scripts/timing <model-id>`: measure streaming timing against the model's configured OpenAI-compatible endpoint. This is the source of truth for latency metrics; promptfoo is the source of truth for prompt execution and saved outputs.
- `scripts/view`: open promptfoo local viewer.

Scripts should be thin and boring. Prefer existing tools over custom orchestration.

Script language:

- Use shell for environment checks and simple orchestration.
- Use Python for YAML parsing, metrics capture, OpenAI-compatible streaming timing, and any logic with structured data.

Server lifecycle:

- Keep local servers bound to `localhost`.
- Resolve base URL, port, and auth (`apiKey` or `apiKeyEnvar`) from `models.yaml` via `local_assist/registry.py` rather than hardcoding `127.0.0.1:8080`.
- Write per-model PID files (`runs/.serve-<model-id>.pid`) alongside `runs/.serve.pid` so a local model server and a local tool-calling server or proxy on another port can run concurrently without colliding.
- Record the active `model-id`, `api_base_url`, port, runtime, command, and PID.
- If the port is occupied, `scripts/serve-model` should report the active server; it should not silently collide.
- `scripts/eval` should verify that the served model matches the requested `model-id` before running the suite.

Runtime caveat:

- `mlx-lm.server` is expected to provide an OpenAI-compatible endpoint for normal text models.
- `mlx-vlm` server support and promptfoo integration must be verified in Milestone 0 before Gemma 4 VLM-packaged models are treated as v1-ready.

## Eval Suite v1

The first suite should be small enough to run repeatedly across models.

Target size: 10-15 prompts.

Prompt categories:

- Code explanation: explain unfamiliar code or a small repo section.
- Bug fix: diagnose a failing snippet or test and propose a patch.
- Feature planning: produce a conservative implementation plan.
- Shell/tool reasoning: recommend commands and explain why without executing them.
- Long-context summarization: summarize a long doc or several files.
- Needle-in-the-middle retrieval: find a critical detail buried in the middle of a longer document, distinct from summarization.
- Structured output: return strict JSON or a rubric table.
- General reasoning: one or two non-coding logic/math prompts.
- Tool-readiness smoke test: follow a function/tool schema in text.

Use both synthetic stable tasks and a small local-repo track. Synthetic tasks are the stable benchmark. Local-repo tasks test usefulness on real work and can evolve as this workspace grows.

Before running the full suite, every downloaded model must pass a tokenizer/chat-template sanity check:

- Prompt: `Write one sentence about the ocean.`
- Pass criteria: coherent one-sentence response, no repeated BOS/template artifacts, no role-marker leakage, no crash, and no obvious system/user/assistant formatting failure.
- Models that fail remain `downloaded` or move to `archived`; they do not become `runnable`.

## Tool-Calling Eval Suite (`tools`)

Models and serving runtimes intended for agentic coding harnesses must also pass `evals/suites/tools.yaml` (`scripts/eval tools <model-id>`), which tests native OpenAI-compatible `tools` / `tool_calls` behavior rather than plain-text JSON:

- **Single tool call (`single-tool-read-file`)**: selects `read_file` with strict schema adherence (`{"path": "models.yaml"}`).
- **Parallel tool calls (`parallel-tool-calls-diff-check`)**: emits multiple `read_file` tool calls in a single turn when asked to compare two files.
- **Multi-turn tool-result follow-up (`tool-result-followup`)**: consumes a `role: tool` result message and answers the user's question without re-invoking the tool in a loop.
- **No-tool abstention (`no-tool-when-unnecessary`)**: answers a conceptual question directly in `content` without hallucinating a tool call when tools are present but unneeded.

## Human Scoring Rubric

Score each output from 1-5 on:

- Correctness.
- Completeness.
- Instruction following.
- Code quality.
- Reasoning clarity.
- Concision.
- Structured-output validity.
- Practical usefulness.

Fatal flags:

- Hallucinated files, APIs, packages, or model capabilities.
- Invalid JSON when strict JSON was required.
- Unsafe or destructive shell commands without warning.
- Confidently wrong setup instructions.
- Refusal or evasion on normal technical tasks.
- Output that cannot be used without major repair.

Do not use LLM-as-judge for the initial decision. Human review is the source of truth in v1.

## Metrics

Collect lightweight automatic metrics plus manual notes.

Automatic metrics:

- Model load time.
- Time to first token from a small custom streaming wrapper when the runtime exposes an OpenAI-compatible streaming endpoint.
- Total generation time.
- Output token count, if available.
- Tokens per second, if available.
- Runtime and package versions, including `mlx`, `mlx-lm`, `mlx-vlm`, and the model conversion/runtime version when known.
- Basic memory usage from `ps`, `memory_pressure`, or equivalent.

Do not half-measure time-to-first-token through promptfoo alone. If streaming timing cannot be measured by the wrapper for a runtime, mark TTFT as `unsupported` for that run and rely on total generation time.

Promptfoo and the timing wrapper should write separate artifacts, then `metrics.json` should merge or reference both so eval output and latency measurement remain distinguishable.

Manual notes:

- Fan/noise/thermal feel.
- Whether the Mac remains usable during generation.
- Crashes, stalls, or repeated manual fixes.
- Subjective interactivity.
- Setup friction.

## Result Storage

Keep raw outputs, metrics, reviews, and decisions separate.

- `runs/<date>-<suite>-<model>/output.json`: raw promptfoo outputs.
- `runs/<date>-<suite>-<model>/metrics.json`: timing, memory, runtime versions.
- `runs/<date>-<suite>-<model>/notes.md`: run-specific observations.
- `reviews/evals/<date>-<suite>.md`: human scoring and qualitative comparison.
- `reviews/candidates/<date>-candidates.md`: provenance cross-review prompts and responses.
- `docs/decisions/<date>-model-selection.md`: final consensus and roles.

This keeps future reviews auditable when new models arrive.

## Consensus Protocol

After an eval cycle, write a decision record.

For each model, summarize:

- Where it wins.
- Where it fails.
- Quality notes.
- Latency and memory observations.
- MoE-vs-dense throughput comparison when relevant, especially whether a sparse 30B MoE actually beats a smaller dense model on tokens/sec while preserving or improving quality.
- Setup/runtime friction.
- License or provenance concerns.
- Recommended role.

Possible roles:

- Everyday default.
- Coding specialist.
- Fast helper.
- Deep reasoning model.
- Multimodal candidate.
- Stretch candidate.
- Archived.

Consensus does not require one universal winner. A small portfolio is acceptable if each model has a clear role.

## Definition of Done for Milestone 1

Milestone 1 is one complete end-to-end eval loop with 2-3 reviewed models.

Done means:

- Milestone 0 has passed.
- `models.yaml` exists with reviewed candidates.
- At least two MLX models are downloaded and runnable.
- `promptfoo` can run the starter eval suite against them.
- Raw outputs and basic timing are saved under `runs/`.
- A human review file compares quality.
- A decision record picks provisional roles, even if the answer is "keep testing."
- Offline-readiness passes after setup and downloads.

## Milestone 0 Spike

Before building the full registry or downloading large models, validate the smallest complete loop.

Milestone 0 should:

- Initialize git if the workspace is not already a repository.
- Install or verify `uv`, `mlx-lm`, `mlx-vlm`, Node 22+, and `promptfoo`.
- Install or verify `hf-transfer` and set `HF_HUB_ENABLE_HF_TRANSFER=1` for large Hugging Face downloads when supported.
- Serve one small verified MLX text model through `mlx-lm.server`.
- Run one promptfoo prompt against the local endpoint.
- Measure total generation time and, if streaming is available, TTFT through the custom timing wrapper.
- Run the tokenizer/chat-template sanity prompt.
- Spike `mlx-vlm` serving or wrapping enough to decide whether Gemma 4 VLM-packaged models can participate in v1.
- Record package versions and any integration failures.
- Check promptfoo offline behavior, including whether its local viewer, cache, and result storage work without network access after setup.

Pass/fail:

- Pass if a small MLX model can be served locally, promptfoo can hit it, output is saved, basic timing is captured, server lifecycle is understood, and `mlx-vlm` is either integrated or explicitly deferred with a fallback plan.
- Fail if promptfoo cannot reach a local MLX endpoint, output/metrics cannot be saved locally, or the VLM path remains ambiguous.

## Security and Trust

- Prefer official publisher repos or `mlx-community` conversions that clearly link to official weights.
- Record licenses before download.
- For Gemma-family models, review both the model license and any Google/Gemma usage terms or gated-access requirements before download.
- Disqualify models from the primary track when the license blocks the intended use, includes non-commercial-only terms that conflict with likely future use, forbids necessary local use, or leaves redistribution/conversion rights unclear.
- Avoid random reuploads unless there is a strong reason.
- Pin `mlx`, `mlx-lm`, `mlx-vlm`, promptfoo, and related serving packages once Milestone 0 works.
- Record both installed runtime versions and known conversion runtime versions in each run when available.
- Keep model servers bound to `localhost`.
- Do not expose local servers to the network by default.
- Store eval prompts and outputs locally.
- Do not paste private code into third-party services during cross-review.
- Cross-review metadata and candidate fit, not private prompt/output content.
- When a lab fork registers `runtime: proxy` or `runtime: remote` endpoints, `models.yaml` must include a validated `remote_trust` block (`tier` in `enclave_weights_attested`, `enclave_runtime_attested`, `zdr_contract`, `standard_api`, plus `usage_policy`, `attestation_method`, `jurisdiction`, `pricing_per_m_tokens`, and for `enclave_weights_attested` the verified `weights_hash`, `weights_source`, `weights_verified_by`, and `weights_verified_date`). Private coding workflows (`local_assist`) admit `local` models by default and admit `enclave_weights_attested` / `enclave_runtime_attested` models (which require `runtime: proxy` bound to `localhost` and a non-empty `attestation_method`) only under explicit opt-in (`LOCAL_ASSIST_ALLOW_ATTESTED_TEE=1`). `zdr_contract` and `standard_api` endpoints are blocked from private coding and restricted to synthetic/public benchmark comparisons. Never configure silent fallback across data-control rungs.

## Offline Readiness

After setup:

- Confirm downloaded models run without network access.
- Confirm promptfoo evals can run locally.
- Confirm local result viewing works.
- Document any commands that still require internet.
- Treat offline-readiness as pass/fail for Milestone 1.

## Backlog

- Create a dedicated Codex skill named `local-llm-scout`.
- Add multimodal evals for image, chart, OCR, and maybe audio tasks.
- Evaluate Open WebUI or another richer human comparison UI.
- Add LLM-as-judge as a secondary signal.
- Add an agent/tool execution harness.
- Add long-context repo packing.
- Add remote/cloud baseline comparisons.
- Add automated leaderboard/report generation.
- Explore fine-tuning or LoRA workflows after model selection is stable.
- Add Ollama/GGUF fallback support if MLX coverage is incomplete.

## `local-llm-scout` Skill Requirements

The future skill should formalize repeatable scouting.

It should define:

- Source priority order:
  1. Official model publisher pages and model cards.
  2. Official Hugging Face/Kaggle/Ollama repos.
  3. `mlx-community` or trusted runtime-specific conversions.
  4. Maintained GitHub runtime docs.
  5. Community reports only as secondary evidence.
- Required provenance fields for `models.yaml`.
- MLX and Apple Silicon fit checks.
- Model size, quantization, disk, and RAM estimate checks.
- License checks.
- Cross-review prompt template.
- Output format for updating `models.yaml`.
- Disqualification rules for stale, unclear, unsupported, or suspicious conversions.

## Immediate Next Steps

1. Initialize git if needed.
2. Run Milestone 0 with one small verified MLX model.
3. Create initial `models.yaml` candidate table with live source links.
4. Cross-review the candidate table before downloads.
5. Add minimal promptfoo config and starter eval suite.
6. Add thin scripts for setup, model listing, serving, sanity checks, timing, evals, and viewing.
7. Run Milestone 1 with 2-3 reviewed models.
