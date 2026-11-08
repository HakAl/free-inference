# `free-inference` Workspace Instructions

`free-inference` is a freedom- and data-control-first inference launcher, Secure Enclave key-sealing proxy, and evaluation workbench for open-weight coding agents on Apple Silicon Macs (target baseline: 48 GB unified memory for 30B MLX models).

Read these documents before making changes:

- [`README.md`](README.md): quick start, CLI reference, 5-rung ladder, and platform support matrix.
- [`SECURITY.md`](SECURITY.md): threat model, credential isolation, and residual operational boundaries.
- [`docs/proposal.md`](docs/proposal.md): 5-rung architecture (`local`, `enclave_weights_attested`, `enclave_runtime_attested`, `zdr_contract`, `standard_api`) and settled design decisions.
- [`docs/plan.md`](docs/plan.md): evaluation workbench design, provenance review gates, and capability suites (`sanity`, `v1`, `tools`).
- [`docs/local-assist-server.md`](docs/local-assist-server.md): Rung 1 MCP server (`local_assist`) and structured delegation contract.
- [`docs/evals/README.md`](docs/evals/README.md): committed machine-readable evaluation evidence manifests (`docs/evals/*.json`).

## Core Invariants (Non-Negotiable)

1. **5-rung data-control ladder**:
   - Every model in [`models.yaml`](models.yaml) declares its rung (`local`, `enclave_weights_attested`, `enclave_runtime_attested`, `zdr_contract`, `standard_api`) and `usage_policy` (`unrestricted_local`, `enclave_no_inspection`, `provider_filtered`, `provider_terms_apply`, `unknown`).
   - Never mark an enclave endpoint `enclave_weights_attested` (Rung 2) without an independently reproduced `dm-verity` root hash (`weights_hash`, `weights_source`, `weights_verified_by`, `weights_verified_date`, and a committed `weights_verification_artifact` under `docs/attestations/`). Proxy-verified manifests without independent weight reproduction stay at `enclave_runtime_attested` (Rung 3).
2. **No silent cross-rung fallback**:
   - Never configure a client, launcher, or MCP server to fall back across data-control rungs.
   - `local_assist/client.py` admits `local` by default, admits `enclave_weights_attested` and `enclave_runtime_attested` only when `LOCAL_ASSIST_ALLOW_ATTESTED_TEE=1` is explicitly set, and blocks `zdr_contract` and `standard_api` from private coding workflows.
   - `scripts/opencode-attested` never exports `LOCAL_ASSIST_ALLOW_ATTESTED_TEE` into child environments, keeping `local_assist` MCP sub-calls pinned to Rung 1 (`http://127.0.0.1:8080/v1`).
3. **Loopback-only servers and hardware-backed key sealing**:
   - All local servers and proxies bind explicitly to `127.0.0.1`, `localhost`, or `[::1]`.
   - Remote API keys on Rungs 2-5 use `promptfoo_provider.apiKeyKeychainService` (`free-inference.<service>` sealed in the Apple Silicon Secure Enclave via `./scripts/se-key store <service>` or migrated via `./scripts/se-key migrate <service>`, with the outer ECIES ciphertext envelope stored in `~/.config/free-inference/se-envelopes/` at mode `0700`/`0600`) and are unsealed into `bin/se-key-proxy` memory via a single live Touch ID tap per session. Plaintext `apiKey` and `apiKeyEnvar` are rejected on non-local rungs.
4. **Process-identity and offline verification**:
   - Active servers record `pid` and `pid_lstart` (plus `upstream_pid` and `upstream_pid_lstart` for dual proxies) in `runs/.serve*.pid`.
   - `scripts/verify-served-model` verifies `pid_lstart`, `/v1/models`, and live OS listener `--model` flags (`lsof` + `ps`) before any chat call can hot-swap `mlx_lm.server`, and `--require-offline` enforces `hf_offline: true` (`HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1`) for Rung 1 coding sessions.
5. **Executable verification & committed evidence**:
   - Every model cleared for `routing.private_local: cleared` or `routing.private_attested: cleared` must pass `sanity`, `v1`, `tools`, `tools_timing`, and `opencode-smoke`, and carry a verified `eval_evidence_artifact` in `docs/evals/<model-id>.json` checked by `./scripts/generate-eval-manifest --check --offline-ci` (and `--check` when local `runs/<run_dir_id>/` clearance artifacts are present).
   - Never record unverified model IDs, context windows, or prices in `models.yaml`.

## Everyday Commands

- Bootstrap & verify dependencies: `./scripts/setup`
- List registered models: `./scripts/models`
- Check or heal upstream model catalog drift (also tracked weekly via `.github/workflows/catalog-sync.yml` issues on `https://github.com/HakAl/free-inference/issues` or `gh issue list --repo HakAl/free-inference --state open`):
  - `./scripts/sync-model-catalog --check`
  - `./scripts/sync-model-catalog --apply`
- Launch Rung 1 local coding session (from target project directory): `/path/to/free-inference/scripts/opencode-local` (pass `--refresh-session` to restart the server)
- Launch Rung 3 attested enclave coding session (from target project directory): `/path/to/free-inference/scripts/opencode-attested` (pass `--refresh-session` to renew the 12h Touch ID proxy session)
- Launch unattended sandboxed worker (Rung 1 or Rung 3):
  - `/path/to/free-inference/scripts/opencode-local --unattended-worker -- run --format json "<prompt>"`
  - `/path/to/free-inference/scripts/opencode-attested --security-profile <profile.yaml> --max-session-usd 0.50 -- run --format json "<prompt>"`
- Delegate bounded Rung 1 subtasks: `./scripts/delegate-local <delegate_task|compress_context|extract_fields|propose_eval_prompts> ...`
- Serve / verify / eval / stop a model:
  - `./scripts/serve-model <model-id>`
  - `./scripts/verify-served-model <model-id> --wait 60`
  - `./scripts/eval <sanity|v1|tools> <model-id>`
  - `./scripts/stop-model <model-id>`

## Required Checks Before Submitting Changes

```bash
.venv/bin/python -B -m unittest discover -s tests -v
python3 -I -B -m unittest discover -s tests -v
./scripts/generate-eval-manifest --check --offline-ci
./scripts/opencode-attested-e2e
```
