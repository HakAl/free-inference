# Contributing to `free-inference`

Thank you for your interest in contributing to `free-inference`.

## Development Prerequisites

- Apple Silicon Mac (`Darwin arm64`) running macOS 15+
- Xcode Command Line Tools (`swiftc`, `codesign`)
- Python 3.11+ and `uv`
- Node.js `^20.20.0 || >=22.22.0` and `npm`

Bootstrap the local environment:

```bash
./scripts/setup
```

## Invariants and Rules

1. **5-rung data-control ladder**: Every model in `models.yaml` is ranked by data control (`local`, `enclave_weights_attested`, `enclave_runtime_attested`, `zdr_contract`, `standard_api`) and records `usage_policy`.
2. **Weight attestation vs. runtime attestation**: Never set `tier: enclave_weights_attested` (Rung 2) unless `weights_hash` (`dmverity:sha256:...`) and `weights_source` (`org/repo@<40-hex-commit>`) have been independently reproduced via `modelwrap --verify`.
3. **Committed evaluation evidence**: Any model with `routing.private_local: cleared` or `routing.private_attested: cleared` must include `eval_evidence_artifact: docs/evals/<model-id>.json` validated by `./scripts/generate-eval-manifest --check --offline-ci` (and `./scripts/generate-eval-manifest --check` when local `runs/<run_dir_id>/` clearance artifacts are present).
4. **No silent fallback**: Never add cross-rung fallback logic.
5. **Localhost-only bindings**: All local servers and proxies must bind to `127.0.0.1`, `localhost`, or `::1`.
6. **Dual YAML parser parity**: `local_assist/_miniyaml.py` is the stdlib fallback for `PyYAML`. Any change to YAML configs (`models.yaml`, `promptfooconfig.yaml`, `evals/suites/*.yaml`) must parse identically under both `.venv/bin/python` (with `PyYAML`) and `python3 -I` (stdlib only).
7. **Zero em dashes**: Do not use the Unicode em dash (`U+2014`) in code, configs, or documentation.

## Verification Checklist Before Submitting a Pull Request

Run all checks locally from the repository root:

```bash
# 1. Rebuild se-key-proxy (if tools/se_key_proxy/main.swift changed, update EXPECTED_SWIFT_SOURCE_SHA256 in local_assist/se_key.py)
./scripts/se-key build --include-test-binary

# 2. Verify committed evaluation manifests (offline-ci check in any checkout; full check when local clearance runs/ are present)
./scripts/generate-eval-manifest --check --offline-ci

# 3. Run unit tests in both .venv (PyYAML) and isolated stdlib-only (-I -B) modes
.venv/bin/python -B -m unittest discover -s tests -v
python3 -I -B -m unittest discover -s tests -v

# 4. Run zero-spend offline end-to-end harnesses
./scripts/opencode-attested-e2e
./scripts/opencode-local-e2e
./scripts/delegate-local-e2e
./scripts/opencode-smoke qwen3-30b-a3b-2507-mlx-4bit
```
