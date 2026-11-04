# Changelog

All notable changes to `free-inference` are documented in this file.

## [0.1.1] - 2026-11-03

### Security and Hardening
- **Process start-time (`lstart`) binding across lifecycle scripts**: Recorded `pid_lstart` and `upstream_pid_lstart` (`LC_ALL=C TZ=UTC ps -p <pid> -o lstart=`) in PID files, refused legacy records lacking start-time metadata across `serve-model`, `verify-served-model`, `with-session-token`, and `stop-model` (with explicit `--force-legacy` and record-level `--discard-legacy` recovery flags on `stop-model`), and withheld `SIGKILL` escalation if escalation-time `lstart` cannot be verified, preventing PID-reuse signaling races.
- **Environment allowlisting in `serve-model`**: Restricted child environments for `mlx_lm server`, `tinfoil-proxy`, and `se-key-proxy` to explicit safe allowlists (`BASE_SAFE_ENV_ALLOWLIST`), forcing `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`, `HF_HUB_DISABLE_TELEMETRY=1`, and `DO_NOT_TRACK=1` by default on Rung 1.
- **Session cap and context clamping on proxy attachment**: `scripts/opencode-attested` now rejects attaching to proxy sessions whose caps exceed the launcher ceiling or explicitly passed CLI cap flags, requires `max_request_bytes >= 65536`, and clamps `output_limit` and `context_limit` to the active session's caps. Also set `scripts/serve-model --max-tokens-cap` default to `4096`.
- **`se-key-proxy` binary `CDHash` preservation and lexical ancestor walk**: Updated `build_se_key_proxy` in `local_assist/se_key.py` to preserve an already-verified `bin/se-key-proxy` release binary (avoiding unnecessary rebuilds that change the ad-hoc `CDHash` and trigger macOS Keychain partition ACL password prompts), and updated `verify_root_owned_binary_and_ancestors` to reject `.` and `..` segments and walk lexical path components with `os.lstat` before `.resolve()`.
- **JSON config escaping**: Escaped all string placeholders in `opencode-local`, `opencode-attested`, and `opencode-smoke` config renderers.
- **Prompt redaction in `local_assist` telemetry**: Redacted raw `text` in `compress_context` and `extract_fields` JSONL telemetry logs (`text_chars` + `text_sha256`, `redact_prompt=True`).

### Reproducibility, Testing, and Documentation
- **Committed evaluation evidence (`docs/evals/*.json`)**: Added `eval_evidence_artifact` to `models.yaml` for cleared models (`qwen3-30b-a3b-2507-mlx-4bit` and `tinfoil-deepseek-v4-1-flash`) and `scripts/generate-eval-manifest` (`--all`, `--check`, and `--offline-ci`) with `tests_sha256` and `suite_spec_sha256` digests, `evaluated_provider_config`, per-case pass/fail records, and strict `operator_exception` validation.
- **`_MiniYamlParser` YAML 1.2 parity**: Aligned folded block scalar (`>` / `>-`) line-joining with PyYAML, decoded quoted mapping keys, fixed mid-word apostrophe handling in comment stripping, and rejected unconsumed trailing input, unsupported YAML tags, anchors, flow collections, and YAML 1.1 boolean words.
- **Pinned dependencies and CI**: Added `requirements.txt`, SHA-pinned `.github/workflows/ci.yml` (`macos-15` hardware/e2e job + `ubuntu-latest` `verify-linux-portable` job), `SECURITY.md`, `CONTRIBUTING.md`, and `tests/__init__.py`.

## [0.1.0] - 2026-11-01

### Initial Release
- Evolved from the May 2026 `local-llm-lab` Apple Silicon MLX evaluation workbench into `free-inference`, adding the 5-rung data-control ladder (`local`, `enclave_weights_attested`, `enclave_runtime_attested`, `zdr_contract`, `standard_api`) in `models.yaml` and `local_assist/`.
- Rung 1 (`private-local` via `mlx-lm` on `127.0.0.1:8080`) with `qwen3-30b-a3b-2507-mlx-4bit` cleared across `sanity`, `v1`, `tools`, `tools_timing`, and `opencode-smoke`.
- Rung 3 (`private-attested` via `tinfoil-proxy` + `se-key-proxy` on `127.0.0.1:8081`) with hardware-backed Secure Enclave ECIES key sealing (`scripts/se-key`) and `tinfoil-deepseek-v4-1-flash` cleared.
- Locked-down OpenCode launchers (`scripts/opencode-local`, `scripts/opencode-attested`) and Rung 1 MCP server (`scripts/local-assist-server`).
