# Committed Evaluation Evidence Manifests (`docs/evals/`)

Every model in [`models.yaml`](../../models.yaml) with `routing.private_local: cleared` or `routing.private_attested: cleared` must declare an `eval_evidence_artifact` pointing to a committed JSON manifest in this directory (`docs/evals/<model-id>.json`).

Because full promptfoo and `opencode-smoke` run directories under `runs/` are gitignored (they can be large and may contain workspace-local paths), these sanitized manifests provide reproducible, machine-verifiable evidence in git for every cleared model, including:

- Canonical SHA-256 digests (`tests_sha256` and `suite_spec_sha256`) for each suite (`sanity`, `v1`, `tools`):
  - `tests_sha256`: canonical SHA-256 of the expanded `tests:` array (after `__DELTA_INDEXER_LONG_CONTEXT__` expansion) in `promptfooconfig.yaml`, `evals/suites/v1.yaml`, and `evals/suites/tools.yaml`.
  - `suite_spec_sha256`: canonical SHA-256 of `{"max_tokens": ..., "prompts": ..., "temperature": ..., "tests": ..., "tools": ...}`, binding the suite's prompt templates, default `max_tokens`, default `temperature`, tool schemas (`tools` in `evals/suites/tools.yaml`), and expanded test cases. Suite-template or per-model `promptfoo_provider` overrides (such as `transform` expressions or `extraBody`/`passthrough` flags like `thinking: false`) are recorded per suite in `evaluated_provider_config` and in `models.yaml` rather than the cross-model `suite_spec_sha256` digest.
- Per-test case pass/fail and score entries (`cases`), non-secret `evaluated_provider_config` (`id`, `transform`, `temperature`, `max_tokens`, `extraBody`, `passthrough`), streaming TTFT (`ttft_seconds`), total generation time (`total_seconds`), and pinned runtime versions (`mlx`, `mlx-lm`, `mlx-vlm`, `promptfoo`).
- Streaming tool-call probe evidence (`tools_timing_probe`) and `opencode-smoke` token verification (`token_verified: true`, `only_read_tool_called: true`, `read_target_only: true`, `0` non-localhost sockets).
- Explicit `clearance_basis` (`automated_full_pass` for `10/10` on `v1`, or `operator_exception` with `operator_clearance_decision` referencing a committed decision artifact under `docs/`).

Current committed manifests:

- [`qwen3-30b-a3b-2507-mlx-4bit.json`](./qwen3-30b-a3b-2507-mlx-4bit.json): Rung 1 (`local`) default model cleared for `private-local` (`sanity` 1/1, `v1` 10/10, `tools` 4/4, `tool_call_chunks: 1`, `opencode-smoke` PASS).
- [`tinfoil-deepseek-v4-1-flash.json`](./tinfoil-deepseek-v4-1-flash.json): Rung 3 (`enclave_runtime_attested`) default model cleared for `private-attested` (`sanity` 1/1, `v1` 9/10 with documented `operator_clearance_decision` on `patch-like-edit-gitignore`, `tools` 4/4, `tool_call_chunks: 4`, `opencode-smoke` PASS, 0 session token leaks).

## Regenerating and Verifying Manifests

To validate all committed manifests in any checkout or CI environment (without requiring gitignored `runs/` directories) against `models.yaml`, `tests_sha256`, `suite_spec_sha256`, `run_dir_id` format, and pinned clearance modes/run IDs:

```bash
./scripts/generate-eval-manifest --check --offline-ci
```

To regenerate the manifests from `runs/` after evaluating a model:

```bash
./scripts/generate-eval-manifest --all
```

When the local `runs/<run_dir_id>/` clearance directories are present on disk, run full `--check` to cross-check every manifest by regenerating it from the raw `output.json`, `metrics.json`, `suite.yaml`, and `summary.json` artifacts:

```bash
./scripts/generate-eval-manifest --check
```

> **Verification Scope Note**: Full `--check` (without `--offline-ci`) requires the local `runs/<run_dir_id>/` directories and cross-checks every manifest by regenerating it from the raw `output.json`, `metrics.json`, `suite.yaml`, and `summary.json` artifacts. Because `runs/` is gitignored, `--offline-ci` verifies structural integrity, `tests_sha256` and `suite_spec_sha256` binding, `run_dir_id` format/pinning, and `clearance_basis` consistency, rather than independently re-proving raw promptfoo outputs that are not in the git checkout.
