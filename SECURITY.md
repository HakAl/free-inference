# Security Policy and Threat Model

`free-inference` is an open-source inference workbench and launch harness for coding agents on Apple Silicon macOS. It is built around a strict 5-rung data-control ladder (`local`, `enclave_weights_attested`, `enclave_runtime_attested`, `zdr_contract`, `standard_api`) with fail-closed admission checks and no silent cross-rung fallback.

## Threat Model and Trust Boundaries

### What `free-inference` protects against

1. **Silent cross-rung downgrade or cloud fallback**:
   - `local_assist/client.py`, `scripts/opencode-local`, and `scripts/opencode-attested` enforce explicit data-control admission gates before any model request is sent.
   - `private-local` (Rung 1) admits only `local` models served on loopback (`127.0.0.1`, `localhost`, `[::1]`) with `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1` verified via the active server PID record (`pid_lstart`) and OS listener command line (`lsof` + `ps`).
   - `private-attested` (Rung 2/3) admits only localhost-bound attesting enclave proxies backed by `apiKeyKeychainService` (`se-key-proxy` + `tinfoil-proxy`), while keeping the `local_assist` MCP sub-calls pinned to Rung 1 (`http://127.0.0.1:8080/v1`) without exporting `LOCAL_ASSIST_ALLOW_ATTESTED_TEE` into the MCP child environment.
   - Rung 4 (`zdr_contract`) and Rung 5 (`standard_api`) are blocked from private coding workflows.

2. **Raw API key exposure to coding agents, config files, and child processes**:
   - Provider API keys for Rung 2/3/4/5 endpoints are never stored in `models.yaml`, shell profiles, or `.env` files, and are never passed to coding agents.
   - `scripts/se-key store <service>` seals the raw provider API key with a hardware-bound Secure Enclave P-256 private key (`CryptoKit.SecureEnclave.P256.KeyAgreement`, `.biometryCurrentSet`, `.privateKeyUsage`) using ephemeral P-256 ECDH key agreement + `HKDF<SHA256>` (info `"free-inference/se-ecies-v1/" + service`) + `AES.GCM.seal` (`se-ecies-v1`), storing only the ciphertext envelope in the macOS login Keychain with `service` bound as AES-GCM Additional Authenticated Data (AAD).
   - At runtime, `scripts/serve-model` generates an ephemeral `se-session-<64-hex>` bearer token (`0600` in `runs/.se-session-<id>.token`) and passes it to `bin/se-key-proxy` via an inherited pipe descriptor (`--session-token-fd <fd>`). `bin/se-key-proxy` calls `ptrace(PT_DENY_ATTACH, 0, 0, 0)`, prompts for Touch ID once to unseal the provider API key in memory, and validates the session token on `http://127.0.0.1:<port>/v1` before injecting the real upstream `Authorization: Bearer` header.
   - `se-key-proxy` verifies that its loopback upstream socket (`127.0.0.1:<port+1000>`) belongs to the expected `tinfoil-proxy` child PID and matching kernel process start time (`proc_pidinfo(PROC_PIDTBSDINFO)`) via `proc_pidfdinfo(..., PROC_PIDFDSOCKETINFO)` before forwarding the unsealed Bearer key.

3. **Unbounded session spend or prompt exfiltration via OpenCode defaults**:
   - Both `scripts/opencode-local` and `scripts/opencode-attested` generate an isolated `opencode.json` in `.home/opencode-private-*` with `autoupdate: false`, `share: "disabled"`, `snapshot: false`, `lsp: false`, `formatter: false`, `OPENCODE_DISABLE_PROJECT_CONFIG=1`, `OPENCODE_DISABLE_MODELS_FETCH=1`, and `webfetch`/`websearch`/`codesearch` set to `"deny"`.
   - `se-key-proxy` enforces per-session caps on chat requests (`--max-chat-requests`), output tokens (`--max-tokens-cap`), request body size (`--max-request-bytes`), stream duration (`--stream-timeout-seconds`), and session TTL (`--ttl-seconds`), and `scripts/opencode-attested` supports a pre-flight worst-case spend ceiling (`--max-session-usd`).

### Residual Boundaries and Operational Disclosures

- **Ephemeral session token in `opencode` environment (`LOCAL_ASSIST_SESSION_TOKEN`)**:
  - The launchers write `"apiKey": "{env:LOCAL_ASSIST_SESSION_TOKEN}"` to `opencode.json` rather than writing the literal token to config. Scans of evaluated `opencode-smoke` and `opencode-attested-e2e` runs found `0` literal token matches across `.home/` (including `opencode.db`), though OpenCode's internal SQLite persistence is not independently audited. Because `LOCAL_ASSIST_SESSION_TOKEN` is an environment variable in the `opencode` process, it is inherited by child processes spawned by `opencode` (including operator-approved `bash` tool commands) and is readable by same-UID local processes; an approved `bash` command that prints its environment (such as `env` or `printenv`) could also place the session token into tool output and OpenCode's stored session database (`opencode.db`).
  - This session token **never** exposes the underlying Secure Enclave-sealed provider API key. It grants access only to the active single-model `se-key-proxy` loopback listener (`http://127.0.0.1:8081/v1`), bounded by the session's `--max-chat-requests`, `--max-tokens-cap`, `--max-request-bytes`, `--stream-timeout-seconds`, and `--ttl-seconds` limits, and can be revoked immediately with `./scripts/stop-model <model-id>`.
- **Operator-approved `bash` commands and `SSH_AUTH_SOCK`**:
  - Interactive `bash`, `edit`, `write`, and `patch` tools prompt for operator approval (`"ask"`). Once approved, `bash` commands run in the operator's normal user privilege domain without an OS-level network sandbox (unless enforced externally by a host firewall such as LuLu).
  - `SSH_AUTH_SOCK` is passed through in `SAFE_ENV_ALLOWLIST` so approved `git` operations can use the host SSH agent.
- **Rung 1 offline verification boundary**:
  - `scripts/serve-model` sets `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1` by default for Rung 1 servers, and `scripts/verify-served-model --require-offline` verifies `hf_offline: true` in the `pid_lstart`-bound PID record and checks the live OS listener `--model` flag (`lsof` + `ps`) before `opencode-local` or `local_assist` sends a chat request. This is a pre-flight process and listener verification gate, not a kernel-level packet filter.
- **Trusted repository configuration (`models.yaml` `serve_command`)**:
  - `models.yaml` is operator-authored configuration inside the trusted repository root. For `runtime: proxy` models on Rungs 2/3, `serve_command` is split with `shlex.split` (`shell=False`) and checked by a heuristic localhost flag validator (`validate_custom_command_localhost`), which is a denylist that a shell or interpreter wrapper (`sh -c`, `python3 -c`) can bypass. Furthermore, `bin/tinfoil-proxy`'s pinned SHA-256 and Apple Developer ID signature are verified during `./scripts/setup`, not re-hashed at `serve-model` launch (while `bin/se-key-proxy` is checked via `verify_root_owned_binary_and_ancestors`). Operators should treat edits to `models.yaml` with the same review rigor as executable code.
- **Same-UID local compromise**:
  - Processes running as the same macOS user account share the same OS privilege domain. While `PT_DENY_ATTACH` blocks unprivileged debugger attachment to `se-key-proxy` and the raw API key never enters agent environments or disk files, `free-inference` does not claim protection against a compromised local user account or kernel-level attacker.
- **Runtime attestation vs. weight attestation**:
  - Rung 3 (`enclave_runtime_attested`) verifies the enclave TLS certificate, binary measurement, and Sigstore transparency log via `tinfoil-proxy`, and records the provider's declared `dm-verity` root hash in `provider_manifest_weights_hash`. Promotion to Rung 2 (`enclave_weights_attested`) requires independently reproducing the `dm-verity` root hash from audited Hugging Face weights via `modelwrap --verify`.

## Reporting a Vulnerability

Please report security vulnerabilities privately via GitHub Security Advisories (`Security -> Advisories -> Report a vulnerability` on the repository) rather than opening a public issue. Include:

- Affected component (`local_assist`, `se-key-proxy`, `scripts/serve-model`, `scripts/opencode-*`, or `models.yaml`)
- Minimal reproduction steps on macOS arm64
- Impact on the 5-rung data-control boundary or credential isolation
