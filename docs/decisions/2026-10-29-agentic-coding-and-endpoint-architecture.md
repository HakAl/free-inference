# Agentic Coding & Endpoint-Driven Registry Decision

## Outcome

The workbench is upgraded in-place as the reference implementation so that every downstream lab fork inherits:

1. **Endpoint-driven scripts (`local_assist/registry.py`)**: `scripts/serve-model`, `scripts/stop-model`, `scripts/verify-served-model`, `scripts/timing`, `scripts/models`, `scripts/provider-id`, `scripts/render-suite`, and `local_assist/client.py` resolve `apiBaseUrl`, host, port, and auth (`apiKey` or `apiKeyEnvar`) from `models.yaml` rather than hardcoding `http://127.0.0.1:8080/v1` and `Bearer none`. `scripts/eval` passes the target `model-id` to `scripts/render-suite <suite> <model-id>`, binding the rendered suite exclusively to that selected registry entry so entries sharing an OpenAI model ID across different endpoints or trust tiers cannot overwrite each other.
2. **Collision-free multi-process PID tracking & localhost bind enforcement**: `scripts/serve-model` writes per-model `runs/.serve-<slug>-<hash>.pid` alongside `runs/.serve.pid`, validates that custom proxy/runtime `serve_command` arguments explicitly bind to a loopback address (`127.0.0.1`, `localhost`, `::1`, `[::1]`) and never `0.0.0.0`, and preserves IPv6 brackets in health-check URLs. `scripts/stop-model` verifies the recorded `model_id` inside each PID file before signaling or unlinking.
3. **Strict OpenAI `tools` / `tool_calls` eval suite (`evals/suites/tools.yaml`)**: `scripts/eval tools <model-id>` verifies native OpenAI `tool_calls` arrays/objects (rejecting ordinary string content that merely contains JSON text), distinct non-empty `call.id` values, `type === "function"`, strict `additionalProperties: false` argument schemas, multi-turn `role: tool` follow-up, and no-tool abstention. Output transforms (`evals/transforms/harmony.js` and inline `<|im_end|>` transforms) pass structured `tool_calls` arrays/objects through untouched.
4. **Validated 5-rung data-control policy, freedom-of-use tracking & private-coding admission (`remote_trust`)**:
   - `local_assist/registry.py` ranks endpoints along five ordered data-control rungs (`DATA_CONTROL_RUNGS`):
     1. `local` (local weights and process on `localhost`)
     2. `enclave_weights_attested` (`runtime: proxy` on `localhost`, non-empty `attestation_method`, a 64-hex `weights_hash` matching `[dmverity:]sha256:<64-hex>`, a pinned `weights_source` matching `<org>/<repo>@<40-char-sha>`, non-empty `weights_verified_by` such as `modelwrap --verify`, and `weights_verified_date` in `YYYY-MM-DD`)
     3. `enclave_runtime_attested` (`runtime: proxy` on `localhost` and non-empty `attestation_method`, where the enclave runtime/manifest is verified by the local proxy but model weights are not independently reproduced/pinned by the client; legacy alias `attested_tee` maps here)
     4. `zdr_contract` (contractual zero data retention over standard TLS; legacy alias `zero_data_retention` maps here)
     5. `standard_api` (retaining or unspecified third-party API)
   - `remote_trust.usage_policy` records freedom-of-use characteristics (`unrestricted_local` on Rung 1, or `enclave_no_inspection`, `provider_filtered`, `provider_terms_apply`, `unknown` on Rungs 2-5, defaulting to `unknown` on all non-local rungs).
   - `local_assist/client.py` enforces trust-based admission before any request: `local` endpoints on `localhost` are admitted by default; `enclave_weights_attested` and `enclave_runtime_attested` endpoints via a localhost attesting proxy are admitted for private coding workflows **only** when explicitly opted in via `LOCAL_ASSIST_ALLOW_ATTESTED_TEE=1`; `zdr_contract` and `standard_api` endpoints are blocked from `local_assist` / private coding and restricted to synthetic/public benchmark comparisons.
   - No script, client, or gateway may silently fall back across data-control rungs.

## Why in the Base Workbench Rather Than Only in a Downstream Fork

- Agentic coding (native tool calling + multi-turn tool results + `local-assist` MCP delegation) is a core use case for the workbench, not a one-off experiment.
- Keeping endpoint resolution, collision-free multi-PID lifecycle, localhost command validation, trust-tier admission, and the `tools` eval suite in the base repo prevents forks from diverging on script plumbing while keeping specific third-party/attested provider candidates out of the base `models.yaml`.
