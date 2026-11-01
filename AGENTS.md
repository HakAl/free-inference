# Local LLM Workspace Instructions

This workspace is for building and maintaining a local LLM evaluation workbench on an Apple Silicon MacBook with substantial unified memory (target: 48 GB).

Read `docs/plan.md` before making changes. It is the design source for the current workflow, milestones, model registry, eval process, and backlog.

## Primary Goal

Create a durable local model lab that can:

- scout current local-weight models,
- verify provenance and Apple Silicon fit before download,
- run practical MLX-first model evals,
- measure quality and latency,
- preserve raw outputs and metrics,
- support human consensus on which models should be defaults, specialists, or archived.

## Platform Assumptions

- Hardware: Apple Silicon MacBook (M-series), 48 GB unified memory baseline.
- Preferred runtime: MLX.
- Practical memory target: keep model weights plus KV cache under about 32 GB resident memory for normal interactive use.
- Avoid Docker and Open WebUI in v1 unless the plan is explicitly changed.
- Prefer local/offline operation after setup and model downloads.

## Required Workflow

Before downloading large models or changing the model shortlist:

1. Browse current sources. Model availability changes quickly.
2. Prefer official publisher pages/model cards, official Hugging Face/Kaggle/Ollama repos, then trusted MLX conversions such as `mlx-community`.
3. Record exact repo IDs, license, publisher, converter, quantization, runtime, expected disk/RAM footprint, context window, modalities, chat template, and source links in `models.yaml`.
4. Save provenance cross-review prompts and results under `reviews/candidates/`.
5. Do not download large weights until the candidate has survived provenance review.

For implementation work:

1. Run or update Milestone 0 before committing to large downloads or broad evals.
2. Keep scripts thin and explicit.
3. Use shell for simple setup/orchestration.
4. Use Python for YAML parsing, metrics capture, streaming timing, and structured data.
5. Keep local servers bound to `localhost`.
6. Resolve endpoint `apiBaseUrl`, port, and auth (`apiKey: none` on Rung 1 `local`; `apiKeyKeychainService` + `se-key-proxy` session token on Rungs 2-5; `apiKeyEnvar` and plaintext `apiKey` are rejected on non-local rungs) from `models.yaml` rather than hardcoding `127.0.0.1:8080`.
7. Track active servers with `runs/.serve.pid` and per-model `runs/.serve-<model-id>.pid`.
8. Provide a stop path (`scripts/stop-model [model-id | --all]`) for any server started by repo scripts.
9. Launch everyday Rung 1 (`private-local`) coding sessions via `./scripts/opencode-local [-- <opencode args...>]` (and verify end-to-end with `./scripts/opencode-local-e2e`):
   - Always place `--` before `opencode` subcommands or flags (for example: `./scripts/opencode-local -- run "prompt"`) so launcher flags such as `--model` are not consumed by `parse_known_args` before `opencode` sees them.
   - Uses `config/opencode-private-local.json.tmpl` and isolates `opencode`'s own config, state, cache, and logs under `.home/opencode-private-local/` (`HOME`, `XDG_*`, `OPENCODE_CONFIG`, `OPENCODE_TEST_HOME`) so host `~/.config/opencode`, `~/.local/share/opencode`, `~/.cache/opencode`, and `~/Library/Application Support/opencode` are untouched.
   - Enforces `trust_tier == "local"`, `capabilities.tool_calling == true`, and `routing.private_local == "cleared"` (`qwen3-30b-a3b-2507-mlx-4bit` by default; pass `--allow-uncleared-model` to test other Rung 1 models).
   - Sets `enabled_providers: ["private-local"]`, maps both `model` and `small_model` to `private-local/<model-id>` (so `opencode`'s background `title` agent stays on Rung 1 and sends one short local title request per session), disables project-level config (`OPENCODE_DISABLE_PROJECT_CONFIG=1`), disables auto-formatters and LSP downloads (`formatter: false`, `lsp: false`), denies built-in network/remote tools (`webfetch`, `websearch`, `codesearch`, `context7*`), sets `"*": "ask"` as the catch-all permission default, and connects `local_assist` MCP (`codemode: false`, `timeout: 180000`).
   - Boundary note: interactive file edits (`edit`, `write`, `patch`), shell execution (`bash`), and any unlisted tools (`"*"`) prompt for operator approval (`"ask"`). Always launch `opencode-local` from a specific project workspace directory (not `~`), because `LOCAL_ASSIST_WORKSPACE_ROOT` and `opencode`'s workspace scope inherit the launch directory. Once approved, edits modify the target workspace and approved `bash` commands run in the operator's shell environment without an OS-level network sandbox (unless enforced externally via LuLu). `SSH_AUTH_SOCK` is passed through in `SAFE_ENV_ALLOWLIST` so approved `git` commands can use the SSH agent; because `HOME` is isolated by default, pass `--preserve-host-home` if approved `git commit` commands need to read `~/.gitconfig`.
   - Launch Rung 2/3 (`private-attested`) coding sessions via `./scripts/opencode-attested [--model <id>] [--allow-uncleared-model] [-- <opencode args...>]` (and verify with `./scripts/opencode-attested-e2e [--operator-approved]`):
     - Uses `config/opencode-private-attested.json.tmpl` and isolates `opencode` state under `.home/opencode-private-attested/`.
     - Requires `trust_tier in {"enclave_weights_attested", "enclave_runtime_attested"}`, `runtime == "proxy"`, `capabilities.tool_calling == true`, and `routing.private_attested == "cleared"` (`tinfoil-deepseek-v4-1-flash` by default; pass `--model <id> --allow-uncleared-model` to test candidate models `tinfoil-gpt-oss-120b`, `tinfoil-glm-5-3`, or `tinfoil-kimi-k3`).
     - Uses interactive default session caps (`--max-chat-requests 1000`, `--max-tokens-cap 16384`, `--max-request-bytes 8388608` [8 MB], `--ttl-seconds 43200` [12h], default context limit matching `endpoint.context_window` [`1048576` for `tinfoil-deepseek-v4-1-flash`], `"modalities": {"input": ["text"], "output": ["text"]}`) and supports an optional worst-case session spend ceiling (`--max-session-usd <usd>`, checked both when starting a proxy and when attaching to an active proxy session).
     - Data-control accounting: running `opencode-attested` sends workspace files read by the agent, approved `bash` outputs, conversation history, and any `local_assist` MCP tool outputs returned to the planner to the attested enclave under the model's `remote_trust.tier` (`enclave_runtime_attested`) and `usage_policy` (`provider_terms_apply`). `local_assist` MCP remains pointed at Rung 1 (`http://127.0.0.1:8080/v1`, auto-serve off by default), and `build_private_attested_env` never exports `LOCAL_ASSIST_ALLOW_ATTESTED_TEE` to child processes.
10. Delegate bounded subtasks from a stronger planner to Rung 1 (`qwen3-30b-a3b-2507-mlx-4bit` on `127.0.0.1:8080/v1`) via `./scripts/delegate-local [--auto-serve] <delegate_task|compress_context|extract_fields|propose_eval_prompts> ...` or the `local_assist` MCP server (`./scripts/local-assist-server [--auto-serve]`), and verify end-to-end with `./scripts/delegate-local-e2e`:
    - Data-control rung accounting: when a remote planner (such as Claude Code on Rung 5 `standard_api` or a frontier model on Rung 2/3) delegates to `local_assist`, any context read by the planner or tool output returned to the planner operates at the **planner's data-control rung** (the delegate call saves marginal API tokens and offloads boilerplate/compression, or keeps raw file contents out of the planner's outbound prompt when passed via `--context-file` / `context_path`). Pure Rung 1 data control requires running the entire session inside `./scripts/opencode-local`.
    - Pre-chat listener verification (`verify-served-model`): because `mlx_lm.server` lists all cached HF models on `/v1/models` and hot-swaps models on chat requests, `verify-served-model` inspects `runs/.serve*.pid` and live listener `--model` arguments (`lsof` + `ps`) and returns exit code `3` (`EXIT_MODEL_MISMATCH`) if another model occupies port `8080`. Both `opencode-local` and `local_assist` fail closed on exit code `3` before any chat call can hot-swap the active server.
    - Opt-in `--auto-serve`: auto-starting `qwen3-30b-a3b-2507-mlx-4bit` (~16 GB resident RAM) is off by default and enabled only with `--auto-serve` or `LOCAL_ASSIST_AUTO_SERVE=1` (recorded as `"started_by": "auto-serve"` in the PID file; stop with `./scripts/stop-model qwen3-30b-a3b-2507-mlx-4bit`).

## Tooling Direction

Preferred v1 stack:

- `mlx-lm` for text model serving.
- `mlx-vlm` only after its serving/wrapping path is verified or explicitly deferred.
- `promptfoo` for prompt execution and saved eval outputs.
- A custom timing wrapper for latency metrics when streaming is available.
- `uv` for Python environment management.
- Node.js (`^20.20.0 || >=22.22.0`) for promptfoo (`0.121.11`).
- `hf-transfer` with `HF_HUB_ENABLE_HF_TRANSFER=1` for large Hugging Face downloads when supported.

Do not treat promptfoo timing as the source of truth for time-to-first-token unless the implementation proves it is reliable. Keep prompt execution artifacts and timing artifacts distinguishable.

## Model Selection Rules

- Treat model IDs in documentation as illustrative unless verified in `models.yaml`.
- Prefer reviewed 4-bit MLX conversions for the first pass.
- For MLX, record quantization by bits, group size, conversion tool, and conversion version.
- Do not apply GGUF labels such as `Q4_K_M` to native MLX models.
- For GGUF/Ollama fallback models, `Q4_K_M` can be a good target when available and well-sourced.
- Treat very large MoE models (trillion-parameter, very large Qwen MoEs) as stretch or remote-baseline candidates unless local fit is proven.
- For Gemma-family models, review both model license and any Google/Gemma terms or gated-access requirements before download.

## Eval Rules

Every downloaded model must pass a tokenizer/chat-template sanity check before full eval:

- Prompt: `Write one sentence about the ocean.`
- Pass criteria: coherent one-sentence response, no repeated BOS/template artifacts, no role-marker leakage, no crash, and no obvious system/user/assistant formatting failure.

Every model/runtime pair intended to drive an agentic coding loop must also pass `scripts/eval tools <model-id>` (`evals/suites/tools.yaml`), verifying OpenAI-compatible `tools` / `tool_calls` (single call, parallel calls, tool-result follow-up, and no-tool abstention).

Keep result types separate:

- `runs/`: raw outputs, metrics, and run notes.
- `reviews/candidates/`: provenance cross-reviews.
- `reviews/evals/`: human scoring and qualitative eval reviews.
- `docs/decisions/`: model selection records.

Human review is the source of truth in v1. Do not add LLM-as-judge unless the plan is updated.

## Safety and Trust

- Do not expose local model servers beyond `localhost` by default.
- Do not paste private code or private eval outputs into third-party services during cross-review.
- Cross-review metadata and candidate fit, not private content.
- When a fork evaluates `runtime: proxy` baselines on Rungs 2-5 (`runtime: remote` is rejected so credentials never live in `os.environ`), `models.yaml` must provide a validated `remote_trust` block with `tier` in `DATA_CONTROL_RUNGS` (`enclave_weights_attested`, `enclave_runtime_attested`, `zdr_contract`, `standard_api`; legacy aliases `attested_tee` and `zero_data_retention` map to Rungs 3 and 4), `usage_policy` (`unrestricted_local` on Rung 1, or `enclave_no_inspection`, `provider_filtered`, `provider_terms_apply`, `unknown` on Rungs 2-5), and `promptfoo_provider.apiKeyKeychainService` (`free-inference.<service>` sealed in macOS Keychain under a Secure Enclave `.biometryCurrentSet` P-256 key via `./scripts/se-key store <service>` and unlocked per `serve-model` session via a live Touch ID tap in `bin/se-key-proxy`). Rung 2/3 (`enclave_*_attested`) require a non-empty `serve_command` for the local attesting proxy and forbid `upstreamBaseUrl`; Rung 4/5 (`zdr_contract`, `standard_api`) require `promptfoo_provider.upstreamBaseUrl` (`https://<host>/v1` on default port 443) and forbid `serve_command`. Rung 2 (`enclave_weights_attested`) additionally requires a 64-hex `weights_hash`, pinned `weights_source` (`<org>/<repo>@<40-char-sha>`), `weights_verified_by`, `weights_verified_date`, and `weights_verification_artifact` (a committed relative path inside the repository root, such as `docs/attestations/<file>`, not under gitignored `runs/`). Private coding workflows (`local-assist`) admit only `local` endpoints by default, or `enclave_weights_attested` / `enclave_runtime_attested` endpoints (requiring `runtime: proxy` on `localhost` and a non-empty `attestation_method`) when explicitly opted in with `LOCAL_ASSIST_ALLOW_ATTESTED_TEE=1`. `zdr_contract` and `standard_api` endpoints are blocked from private code and restricted to public/synthetic benchmark comparisons. Never allow automatic fallback across data-control rungs.
- Disqualify models from the primary track when licensing blocks intended use, includes conflicting non-commercial terms, forbids necessary local use, or leaves redistribution/conversion rights unclear.
- Pin `mlx`, `mlx-lm`, `mlx-vlm`, promptfoo, and related serving packages once Milestone 0 works.

## Editing Guidance

- Keep repo changes aligned with `docs/plan.md`.
- Update `docs/plan.md` when workflow decisions change.
- Avoid broad refactors while the workbench is still being bootstrapped.
- If the repo is not initialized as git, initialize it before substantive implementation work.
- Do not commit model weights, caches, or large generated outputs unless the user explicitly asks.
