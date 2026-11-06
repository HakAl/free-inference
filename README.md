# free-inference

**Free as in freedom (libre), not free beer:** a private coding-agent launcher, Secure Enclave key-sealing proxy, and evaluation workbench for engineers running open-weight coding agents on Apple Silicon Macs.

Most "free inference" lists optimize for `$0` API tiers where your prompts and code become the product. `free-inference` is built for software engineers and security-conscious teams who want **verifiable data control** over their coding agent sessions (target baseline: 48 GB unified memory for 30B local MLX models; 16 GB+ Apple Silicon Macs for Rung 3 attested enclave sessions or smaller local models):

1. **Data control (`5-rung ladder`)**: Keep prompts, repository context, and outputs under the highest practical data control that clears the capability bar for the task.
2. **Freedom of use (`usage_policy`)**: Run open-weight coding models without opaque third-party content filters or silent middleware blocking legitimate engineering and security work.
3. **Verifiable boundaries**: Prompts leave the machine for a remote confidential compute enclave only through a local verifying proxy (`se-key-proxy` -> `tinfoil-proxy`), with an explicit registry boundary between **weight-attested** enclaves (Rung 2) and **runtime-attested** enclaves (Rung 3).
4. **Hardware-backed key sealing (Secure Enclave ECIES + per-session Touch ID unseal into local proxy memory)**: Remote API keys never sit in `.env` files, shell profiles, or `os.environ`. They are sealed with an Apple Silicon Secure Enclave `.biometryCurrentSet` key and unsealed into `se-key-proxy` memory via a single live Touch ID tap per 12-hour session.
5. **No silent downgrades**: Every model is gated by executable evals (`sanity`, `v1`, `tools`, and `opencode-smoke`), and no launcher or client ever silently falls back to a lower-control rung.

---

## The 5-Rung Data-Control Ladder

Every endpoint in [`models.yaml`](models.yaml) is ordered along five explicit data-control rungs enforced by [`local_assist/registry.py`](local_assist/registry.py) and [`local_assist/client.py`](local_assist/client.py):

| Rung | Tier & Verification Boundary | Cleared Default & Launcher |
|---|---|---|
| **1**<br>Local | `local`: Local weights (`mlx-lm`), localhost `127.0.0.1:8080`, `HF_HUB_OFFLINE=1` forced at serve time | `qwen3-30b-a3b-2507-mlx-4bit`<br>`1/1` sanity, `10/10` v1, `4/4` tools, `PASS` smoke ([evidence](docs/evals/qwen3-30b-a3b-2507-mlx-4bit.json))<br>Launcher: `./scripts/opencode-local` |
| **2**<br>Weights TEE | `enclave_weights_attested`: Hardware TEE + local proxy verifies enclave measurement **and** local `dm-verity` `weights_hash` reproduction against a pinned HF commit | *`0` models today (requires local `modelwrap --verify` build)*<br>Launcher: `./scripts/opencode-attested` |
| **3**<br>Runtime TEE | `enclave_runtime_attested`: Hardware TEE + `tinfoil-proxy` verifies SEV-SNP / TDX measurement & Sigstore provenance + `se-key-proxy` verifies kernel socket PCB (`libproc`) | `tinfoil-deepseek-v4-1-flash` (1M ctx)<br>`1/1` sanity, `9/10` v1, `4/4` tools, `PASS` smoke ([evidence](docs/evals/tinfoil-deepseek-v4-1-flash.json))<br>Launcher: `./scripts/opencode-attested` |
| **4**<br>ZDR API | `zdr_contract`: Contractual zero data retention over standard TLS (`store=False`) | Blocked from private coding *(eval / general only)* |
| **5**<br>Standard API | `standard_api`: Standard retaining third-party API | Blocked from private coding *(eval / general only)* |

### What Leaves Your Mac by Rung

| Rung & Admission | Network Egress | What Leaves Your Mac | Who Can Inspect Prompts & Code |
|---|---|---|---|
| **Rung 1** (`local`)<br>**Admitted** (default) | None (`127.0.0.1:8080`, offline env forced) | Nothing (`0` bytes leave localhost during inference) | Nobody outside your Mac |
| **Rung 2** (weights TEE)<br>**Admitted** (opt-in) | HPKE TLS (`:8081` -> `:9081` -> TEE) | Prompts, files read by agent, approved `bash` outputs, history, `small_model` title requests, and Rung 1 MCP outputs returned to planner | Hardware enclave only (AMD SEV-SNP / Intel TDX root of trust and memory-bus assumptions); runtime **and** weights reproduced (`0` models today) |
| **Rung 3** (runtime TEE)<br>**Admitted** (opt-in) | HPKE TLS (`:8081` -> `:9081` -> TEE) | Prompts, files read by agent, approved `bash` outputs, history, `small_model` title requests, and Rung 1 MCP outputs returned to planner | Hardware enclave only (AMD SEV-SNP / Intel TDX root of trust, memory-bus assumptions, and provider weight build pipeline; provider terms apply) |
| **Rung 4** (ZDR API)<br>**Blocked** | Standard HTTPS TLS | Synthetic/public benchmark prompts only | Provider infrastructure (contractual ZDR policy) |
| **Rung 5** (standard API)<br>**Blocked** | Standard HTTPS TLS | Synthetic/public benchmark prompts only | Provider infrastructure (retaining API) |

### Platform Support Matrix

| Platform | Rung 1 Local | Rung 2/3 Attested | Offline Tests & CI |
|---|---|---|---|
| **macOS Apple Silicon (`arm64`) + Touch ID** | Supported (48 GB RAM rec. for 30B MLX) | Supported (Secure Enclave + Touch ID) | Supported (all 65 tests + hardware SE selftest) |
| **macOS Apple Silicon (`arm64`) without Touch ID**<br>*(e.g. Mac mini / Studio without Magic Keyboard)* | Supported | Unsupported (`selftest` exits `77`; `setup` skips gracefully) | Supported (`test_se_key` skips biometric gate on exit `77`) |
| **Linux (`x86_64` / `arm64`)** | N/A (requires Apple Metal) | N/A (requires Secure Enclave) | Supported (portable stdlib unit + `--offline-ci` manifest suite) |

---

## Quick Start (macOS Apple Silicon)

### 1. Bootstrap environment and verified proxy binaries

Requires macOS on Apple Silicon (`Darwin arm64`; with Touch ID for Rung 2/3, while Rung 1 local inference works on all Apple Silicon Macs), `uv`, `python3` (`>= 3.11`), `node` (`^20.20.0 || >=22.22.0`) and `npm`, `curl`, `unzip`, Xcode Command Line Tools (`swiftc`, `codesign`), and [`opencode`](https://opencode.ai) (`v2.0.32+`). Optional: `gh` CLI (authenticated via `gh auth login`) for GitHub Sigstore SLSA provenance verification of `tinfoil-proxy`.

```bash
./scripts/setup
```

`./scripts/setup` validates the platform (`Darwin arm64`), Python (`>= 3.11`), and Node.js (`^20.20.0 || >=22.22.0`) versions, creates `.venv`, installs the exact pinned Python transitive closure from [`requirements.txt`](requirements.txt) and pinned `promptfoo` (`0.121.11`) via `npm ci`, compiles [`tools/se_key_proxy/main.swift`](tools/se_key_proxy/main.swift) into `bin/se-key-proxy` and `bin/se-key-proxy-test` (running the hardware Secure Enclave non-interactive selftest when Touch ID hardware is present, or skipping `exit 77` on Macs without Touch ID), and downloads `bin/tinfoil-proxy` (`v0.2.9`) into a temporary staging directory, verifying its pinned SHA-256 (`6b526fe3...`), Apple Developer ID signature (`TeamIdentifier=8KSH668LZT`), and (when `gh` is authenticated) GitHub SLSA Sigstore provenance bundle via `gh attestation verify` before moving the binary into `bin/tinfoil-proxy` (set `FREE_INFERENCE_REQUIRE_GH_ATTESTATION=1` to require `gh` attestation in strict environments).

### 2. Rung 1: Local Private Coding (`private-local`)

Runs `qwen3-30b-a3b-2507-mlx-4bit` locally on `http://127.0.0.1:8080/v1` with `HF_HUB_OFFLINE=1` (no API key or Touch ID required; ~16.95 GB disk, ~16-18 GB unified memory):

```bash
# First time only: download weights from Hugging Face, run sanity check to complete loading, then stop the online server
./scripts/serve-model qwen3-30b-a3b-2507-mlx-4bit --allow-hf-online
./scripts/sanity-check qwen3-30b-a3b-2507-mlx-4bit
./scripts/stop-model qwen3-30b-a3b-2507-mlx-4bit

# Launch OpenCode from your target project workspace (never launch from ~)
cd /path/to/your/project
/path/to/free-inference/scripts/opencode-local
```

> **Workspace Scoping Note**: Always launch `opencode-local` and `opencode-attested` from inside the specific project repository you want to work on (`cd /path/to/your/project`), not from `$HOME` (`~`). OpenCode's file tools and `LOCAL_ASSIST_WORKSPACE_ROOT` inherit the working directory where the launcher is invoked. Pass `--preserve-host-home` if approved `git commit` commands inside the session need to read `~/.gitconfig`.

### 3. Rung 3: Attested Enclave Coding & Cross-Family Review (`private-attested`)

Seal your [Tinfoil](https://tinfoil.sh) API key into the Apple Silicon Secure Enclave once on your Mac:

```bash
./scripts/se-key store free-inference.tinfoil
```

Then launch OpenCode from your target project workspace against the default cleared Rung 3 enclave model (`tinfoil-deepseek-v4-1-flash`, 1M token context window):

> **Pricing & Spend Ceiling (`tinfoil-deepseek-v4-1-flash`)**: Paid API calls bill against your Tinfoil account at **$0.65 / 1M input tokens ($0.13 cached) and $1.45 / 1M output tokens** (verified `2026-10-31` via `dash.tinfoil.sh` and cross-checked against `tinfoil.sh/pricing`). Pass `--max-session-usd <usd>` (for example `--max-session-usd 5.00`) to enforce a pre-flight worst-case session spend ceiling before starting or attaching to a proxy session.

```bash
cd /path/to/your/project

# Interactive TUI session (prompts Touch ID once to start a 12-hour proxy session)
/path/to/free-inference/scripts/opencode-attested

# Interactive session with an explicit $5.00 worst-case spend ceiling
/path/to/free-inference/scripts/opencode-attested --max-session-usd 5.00 --max-chat-requests 100 --max-request-bytes 262144 --max-tokens-cap 4096

# Non-interactive CLI call (attaches to the running proxy with zero Touch ID prompts)
/path/to/free-inference/scripts/opencode-attested -- run "Review the current git diff for security issues"
```

To try another evaluated Rung 3 candidate (`tinfoil-kimi-k3`, `tinfoil-glm-5-3`, or `tinfoil-gpt-oss-120b`), stop the active proxy on port `8081` and pass `--model <id> --allow-uncleared-model`:

```bash
./scripts/stop-model tinfoil-deepseek-v4-1-flash
./scripts/opencode-attested --model tinfoil-kimi-k3 --allow-uncleared-model
```

---

## Architecture, Security Controls, and Threat Model

```text
  opencode (private-local)    ──────> mlx_lm.server (127.0.0.1:8080)
                                      [Rung 1: local weights, HF_HUB_OFFLINE=1]

  opencode (private-attested) ──────> se-key-proxy (127.0.0.1:8081) ──────> tinfoil-proxy (127.0.0.1:9081)
       │                              [Touch ID SE unseal, per-session      [AMD SEV-SNP / Intel TDX
       │                               se-session-* token, libproc PCB       attestation + Sigstore SLSA
       │                               verification, request/byte/TTL caps]  verification + HPKE encryption]
       ▼
  local_assist MCP            ──────> mlx_lm.server (127.0.0.1:8080)
  (delegate_task, compress_context,   [Always pinned to Rung 1]
   extract_fields, propose_eval_prompts)
```

- **One Touch ID per session, zero prompts per CLI call**: When `scripts/serve-model` starts `se-key-proxy` on `127.0.0.1:8081`, `scripts/serve-model` generates a random `0600` session token (`runs/.se-session-*.token`) and passes it to `se-key-proxy` over an inherited pipe (`--session-token-fd`). You tap Touch ID once, and `se-key-proxy` unseals the API key into process memory (`PT_DENY_ATTACH`) for up to 12 hours (`--ttl-seconds 43200`) and 1,000 chat turns (`--max-chat-requests 1000`). All parallel OpenCode panes and CLI calls attach automatically using the session token without re-prompting Touch ID.
- **Kernel socket ownership verification (`F1`)**: Before forwarding any request or `Authorization` header over loopback to `tinfoil-proxy` (`127.0.0.1:9081`), `se-key-proxy` queries XNU `<libproc.h>` (`proc_pidinfo` + `proc_pidfdinfo`) to verify that the expected `tinfoil-proxy` PID and matching kernel start time (`pbi_start_tvsec`/`pbi_start_tvusec`) own the non-`SO_REUSEPORT` listening TCP kernel control block (`soi_pcb`).
- **Isolated OpenCode home & zero cloud leakage**: Both `./scripts/opencode-local` and `./scripts/opencode-attested` run `opencode` with an isolated `HOME` (`.home/opencode-*`), `OPENCODE_DISABLE_MODELS_FETCH=1`, `OPENCODE_DISABLE_AUTOUPDATE=1`, `OPENCODE_DISABLE_PROJECT_CONFIG=1`, `webfetch`/`websearch` denied, and `apiKey: "{env:LOCAL_ASSIST_SESSION_TOKEN}"` so the literal session token is never written to `opencode.json`.

### Threat Model & Asset Boundary

See [`SECURITY.md`](SECURITY.md) for the full threat model. Key operational boundaries:

- **Ephemeral session token (`LOCAL_ASSIST_SESSION_TOKEN`) vs. sealed API key**: The launchers write `"apiKey": "{env:LOCAL_ASSIST_SESSION_TOKEN}"` to `opencode.json` rather than writing the literal token to config. Scans of evaluated `opencode-smoke` and `opencode-attested-e2e` runs found `0` literal token matches across `.home/` (including `opencode.db`), though OpenCode's internal SQLite persistence is not independently audited. Because `LOCAL_ASSIST_SESSION_TOKEN` resides in the `opencode` process environment, it is inherited by child processes (such as operator-approved `bash` tool commands) and is readable by same-UID local processes; an approved `bash` command that prints its environment (such as `env` or `printenv`) could also place the session token into tool output and OpenCode's stored session database (`opencode.db`). This session token **never** exposes your Secure Enclave-sealed provider API key; it grants access only to the active single-model loopback proxy (`127.0.0.1:8081`) within the session's `--max-chat-requests`, `--max-tokens-cap`, `--max-request-bytes`, and `--ttl-seconds` limits, and is revoked immediately by `./scripts/stop-model <model-id>`.
- **Operator-approved `bash` commands and `SSH_AUTH_SOCK`**: Interactive `bash`, `edit`, `write`, and `patch` tools require operator approval (`"ask"`). Once approved, `bash` commands run in your normal user shell without an OS-level network sandbox (unless enforced by a host firewall such as LuLu), and `SSH_AUTH_SOCK` is passed through in `SAFE_ENV_ALLOWLIST` so approved `git` operations can authenticate via your SSH agent.
- **Rung 1 offline check is pre-flight**: `scripts/serve-model` launches Rung 1 servers with `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1`, and `scripts/verify-served-model --require-offline` verifies `hf_offline: true` in the `pid_lstart`-bound PID record plus the live OS listener `--model` flag (`lsof` + `ps`) before `opencode-local` or `local_assist` sends any chat request. This is a pre-flight process/listener check rather than a kernel packet filter.
- **Trusted `models.yaml` `serve_command`**: `models.yaml` is operator-authored configuration in the trusted repository root. Proxy `serve_command` strings are split with `shlex.split` (`shell=False`) and checked by a heuristic localhost flag validator (`validate_custom_command_localhost`), which is a denylist that a shell or interpreter wrapper can bypass, and `bin/tinfoil-proxy`'s digest and Developer ID signature are verified during `./scripts/setup` rather than re-hashed at launch. Review changes to `models.yaml` with the same care as executable code.

---

## CLI Reference, Key Rotation & Troubleshooting

| Command | Purpose |
|---|---|
| `./scripts/models` | List all models in `models.yaml` with data-control rung, status, and usage policy |
| `./scripts/serve-model <id>` | Start a local MLX server (`127.0.0.1:8080`) or dual attested proxy (`:8081` + `:9081`) |
| `./scripts/verify-served-model <id>` | Verify active PID records (`pid_lstart`), `/v1/models`, and OS listener `--model` flags (`--require-offline` for Rung 1) |
| `./scripts/stop-model <id>` | Stop a running model server or proxy after verifying `pid_lstart` (`--all` stops all) |
| `./scripts/opencode-local` | Launch OpenCode locked to Rung 1 (`private-local`) with isolated state and Rung 1 MCP |
| `./scripts/opencode-attested` | Launch OpenCode locked to Rung 2/3 (`private-attested`) with spend caps (`--max-session-usd`) and Rung 1 MCP |
| `./scripts/delegate-local <tool>` | Delegate bounded subtasks (`delegate_task`, `compress_context`, `extract_fields`, `propose_eval_prompts`) to Rung 1 |
| `./scripts/se-key <cmd> <service>` | Build `bin/se-key-proxy`, run `selftest`, or `store` / `status` / `delete` Secure Enclave keys |
| `./scripts/eval <suite> <id>` | Run `sanity`, `v1`, or `tools` promptfoo suites plus streaming TTFT probe |
| `./scripts/generate-eval-manifest` | Generate or `--check` (`--offline-ci`) committed evaluation evidence manifests in `docs/evals/` |

### Key Rotation & Clean Uninstall

```bash
# Rotate a sealed API key (stop any active proxy first since a running session holds the old key in memory,
# then run store, which replaces the existing Keychain envelope with a fresh Secure Enclave keypair)
./scripts/stop-model --all
./scripts/se-key store free-inference.tinfoil

# Delete a sealed API key from the macOS login Keychain
./scripts/se-key delete free-inference.tinfoil

# Full local cleanup (stop servers, delete Keychain item, remove build/venv/isolated-home directories)
./scripts/stop-model --all
./scripts/se-key delete free-inference.tinfoil
rm -rf .venv node_modules bin .home
```

### Common Troubleshooting

- **Online bootstrap server still running (`hf_offline=False`)**: If `./scripts/opencode-local` reports that the active server on port `8080` was started with `--allow-hf-online`, stop it with `./scripts/stop-model qwen3-30b-a3b-2507-mlx-4bit` and relaunch `./scripts/opencode-local` so it starts with `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1`.
- **Legacy PID record lacking `pid_lstart`**: Pre-`v0.1.1` PID records without process start-time binding (`pid_lstart` / `upstream_pid_lstart`) are refused by `serve-model`, `verify-served-model`, `with-session-token`, and `stop-model`. First run `./scripts/stop-model <model-id>` to inspect the reported PID and live command without signaling; if the process is your old server, run `./scripts/stop-model --force-legacy <model-id>`, or if the PID was reused by an unrelated process, run `./scripts/stop-model --discard-legacy <model-id>` to remove the stale record without signaling.
- **Port conflict / model mismatch (`exit code 3`)**: Only one model can occupy a given localhost port at a time. Run `./scripts/stop-model --all` before switching models on the same port.
- **Tighter proxy caps when attaching (`spend_ceiling_exceeded`)**: If you started `se-key-proxy` directly via `./scripts/serve-model` with custom caps and then attach via `./scripts/opencode-attested`, `opencode-attested` clamps `context` and `output` limits to the active proxy session's caps and refuses attachment if the active session exceeds the launcher's cap ceiling. Run `./scripts/stop-model tinfoil-deepseek-v4-1-flash` and launch directly via `./scripts/opencode-attested`.

---

## Repository Layout & Verification

```text
.
├── .github/workflows/ci.yml         macOS arm64 + Linux CI (build, selftest, manifest check, unit + e2e suites)
├── AGENTS.md                        Contributor invariants and 5-rung boundaries
├── CHANGELOG.md                     Release history and local-llm-lab lineage
├── CONTRIBUTING.md                  Contributor invariants and verification checklist
├── SECURITY.md                      Threat model, trust boundaries, and vulnerability reporting
├── models.yaml                      5-rung model registry, pricing, and routing gates
├── requirements.txt                 Pinned Python transitive dependencies
├── config/
│   ├── opencode-private-local.json.tmpl
│   └── opencode-private-attested.json.tmpl
├── docs/
│   ├── attestations/                Rung 3 Tinfoil attestation & 4-model trial records
│   ├── decisions/                   Architecture and model-selection decision records
│   ├── evals/                       Committed machine-readable evaluation evidence (*.json)
│   ├── local-assist-server.md       MCP server & Rung 1 delegation contract
│   ├── plan.md                      Evaluation workflow and capability gates
│   └── proposal.md                  5-rung architecture and design rationale
├── evals/{prompts,suites,rubrics,chat_templates,transforms}/
├── local_assist/                    Registry, admission gates, MCP server, and SE key verify
├── scripts/
│   ├── setup                        Bootstrap .venv, npm, bin/se-key-proxy, bin/tinfoil-proxy
│   ├── models                       List registered models with rung and usage policy
│   ├── se-key                       Build, selftest, store, status, and delete SE keys
│   ├── serve-model / stop-model     Start/stop local MLX servers or dual attested proxies
│   ├── verify-served-model          Verify PID records and live listener --model flags
│   ├── generate-eval-manifest       Generate/check docs/evals/*.json manifests
│   ├── opencode-local               Launch OpenCode on Rung 1 (private-local)
│   ├── opencode-attested            Launch OpenCode on Rung 2/3 (private-attested)
│   ├── delegate-local               CLI wrapper for Rung 1 local_assist tools
│   ├── eval / timing / opencode-smoke
│   └── *-e2e                        End-to-end verification harnesses
├── tests/                           96 offline unit, Seatbelt, and SE selftests
└── tools/se_key_proxy/main.swift    Hardware-backed Secure Enclave + Touch ID proxy
```

Run the offline unit, Seatbelt, and Secure Enclave selftest suite (96 tests, stdlib + Node):

```bash
.venv/bin/python -B -m unittest discover -s tests -v
python3 -I -B -m unittest discover -s tests -v
./scripts/generate-eval-manifest --check --offline-ci
./scripts/opencode-attested-e2e
```

## License

Apache 2.0. See [LICENSE](LICENSE).
