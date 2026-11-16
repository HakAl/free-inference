# free-inference

**Free as in liberty, not as in free compute. The software costs nothing; the Mac and the watts are yours to supply, and your prompts, keys, and code stay on your machine.** A private coding-agent launcher, Secure Enclave key-sealing proxy, and evaluation workbench for engineers running open-weight coding agents on Apple Silicon Macs.

Most "free inference" lists optimize for `$0` API tiers where your prompts and code become the product. `free-inference` is built for software engineers and security-conscious teams who want **verifiable data control** over their coding agent sessions, targeting 48 GB unified memory for 30B local MLX models and 16 GB+ Apple Silicon Macs for Rung 3 attested enclave sessions or smaller local models:

1. **5-rung data control**: Keep prompts, repository context, and outputs under the highest practical data control that clears the capability bar for the task.
2. **Freedom of use**: Run open-weight coding models without opaque third-party content filters or silent middleware blocking legitimate engineering and security work.
3. **Verifiable boundaries**: Prompts leave the machine for a remote confidential compute enclave only through a local verifying proxy (`se-key-proxy` -> `tinfoil-proxy` or `privatemode-proxy`), with an explicit registry boundary between **weight-attested** enclaves on Rung 2 and **runtime-attested** enclaves on Rung 3.
4. **Hardware-backed key sealing**: Remote API keys never sit in `.env` files, shell profiles, or `os.environ`. They are sealed with an Apple Silicon Secure Enclave `.biometryCurrentSet` ECIES key and unsealed into `se-key-proxy` memory through live Touch ID authorization. Interactive windows default to 2 hours and can be renewed explicitly.
5. **No silent downgrades**: Every model is gated by executable evals across `sanity`, `v1`, `tools`, and `opencode-smoke`, and no launcher or client ever silently falls back to a lower-control rung.

---

## The 5-Rung Data-Control Ladder

Every endpoint in [`models.yaml`](models.yaml) is ordered along five explicit data-control rungs enforced by [`local_assist/registry.py`](local_assist/registry.py) and [`local_assist/client.py`](local_assist/client.py):

| Rung | Tier & Verification Boundary | Cleared Default & Launcher |
|---|---|---|
| **1**<br>Local | `local`: Local weights (`mlx-lm`), localhost `127.0.0.1:8080`, `HF_HUB_OFFLINE=1` forced at serve time | `qwen3-30b-a3b-2507-mlx-4bit`<br>`1/1` sanity, `10/10` v1, `4/4` tools, `PASS` smoke ([evidence](docs/evals/qwen3-30b-a3b-2507-mlx-4bit.json))<br>Launcher: `./scripts/opencode-local` |
| **2**<br>Weights TEE | `enclave_weights_attested`: Hardware TEE + local proxy verifies enclave measurement **and** local `dm-verity` `weights_hash` reproduction against a pinned HF commit | *`0` models today (requires local `modelwrap --verify` build)*<br>Launcher: `./scripts/opencode-attested` |
| **3**<br>Runtime TEE | `enclave_runtime_attested`: Hardware TEE + local attesting proxy (`tinfoil-proxy` or `privatemode-proxy`) verifies SEV-SNP / TDX / NVIDIA CC measurement + `se-key-proxy` verifies kernel socket PCB (`libproc`) | `tinfoil-deepseek-v4-1-flash` (1M ctx, US, catalog default: [evidence](docs/evals/tinfoil-deepseek-v4-1-flash.json))<br>`privatemode-glm-5-3-flash` (1M ctx, DE/EU, cleared: [evidence](docs/evals/privatemode-glm-5-3-flash.json))<br>Launcher: `./scripts/opencode-attested` |
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
| **macOS Apple Silicon (`arm64`) + Touch ID** | Supported (48 GB RAM rec. for 30B MLX) | Supported (Secure Enclave + Touch ID) | Supported (all 108 tests + hardware SE selftest) |
| **macOS Apple Silicon (`arm64`) without Touch ID**<br>*(e.g. Mac mini / Studio without Magic Keyboard)* | Supported | Unsupported (`selftest` exits `77`; `setup` skips gracefully) | Supported (`test_se_key` skips biometric gate on exit `77`) |
| **Linux (`x86_64` / `arm64`)** | N/A (requires Apple Metal) | N/A (requires Secure Enclave) | Supported (portable stdlib unit + `--offline-ci` manifest suite) |

---

## Quick Start (macOS Apple Silicon)

### 1. Bootstrap environment and verified proxy binaries

Requires macOS on Apple Silicon (`Darwin arm64`; with Touch ID for Rung 2/3, while Rung 1 local inference works on all Apple Silicon Macs), `python3` (`>= 3.11`), `curl`, `unzip`, Xcode Command Line Tools (`swiftc`, `codesign`), and [`opencode`](https://opencode.ai) (`v2.0.32+`). Optional: `uv` (required for `--local-only` and full setup), `node` (`^20.20.0 || >=22.22.0`) and `npm` (required only for full evaluation setup), and `gh` CLI (authenticated via `gh auth login`) for GitHub Sigstore SLSA provenance verification of `tinfoil-proxy`.

Choose the setup mode matching your workflow:

| Mode | Command | Installed Packages | Disk Footprint (`.venv` + `node_modules`) | Cached Proxy Build/Verify Time |
|---|---|---|---|---|
| **Rung 2/3 Launcher Only** | `./scripts/setup --launcher-only` (`--proxy-only`) | `0` Python / `0` Node packages (uses stdlib Python 3.11+) | `0 MB` (`~61 MB` in `bin/` for `se-key-proxy` + `tinfoil-proxy`) | `~1.8s` |
| **Rung 1 Local MLX + Launchers** | `./scripts/setup --local-only` | `35` pinned Python packages ([`requirements-local.txt`](requirements-local.txt)), `0` Node packages | `~279 MB` `.venv` (`0 MB` `node_modules`; saves `~1.76 GB`) | `~2.5s` (warm uv wheel cache) |
| **Full Evaluation Workbench** | `./scripts/setup` | `71` pinned Python packages ([`requirements.txt`](requirements.txt)) + `promptfoo` (`0.121.11`) | `~706 MB` `.venv` + `~1,335 MB` `node_modules` (`~2.04 GB` total) | `~8-15s` (warm cache) |

```bash
# Rung 2/3 attested enclave launcher only (0 Python/Node packages; builds se-key-proxy and verifies tinfoil-proxy)
./scripts/setup --launcher-only

# Rung 1 local MLX + Rung 2/3 launchers (35 pinned Python packages from requirements-local.txt; skips Node/promptfoo and VLM/audio/OpenCV)
./scripts/setup --local-only

# Full evaluation workbench + launchers (71 pinned Python packages from requirements.txt + promptfoo 0.121.11 via npm ci)
./scripts/setup
```

`./scripts/setup` validates the platform (`Darwin arm64`) and Python (`>= 3.11`), provisions `.venv` when `--local-only` ([`requirements-local.txt`](requirements-local.txt), 35 packages) or full mode ([`requirements.txt`](requirements.txt), 71 packages + `promptfoo` `0.121.11` via `npm ci`) is selected, compiles [`tools/se_key_proxy/main.swift`](tools/se_key_proxy/main.swift) into `bin/se-key-proxy` and `bin/se-key-proxy-test` via atomic staging (running the hardware Secure Enclave non-interactive selftest when Touch ID hardware is present, or skipping `exit 77` on Macs without Touch ID), and downloads `bin/tinfoil-proxy` (`v0.2.9`) into a temporary staging directory, verifying its pinned SHA-256 (`6b526fe3...`), Apple Developer ID signature (`TeamIdentifier=8KSH668LZT`), and (when `gh` is authenticated) GitHub SLSA Sigstore provenance bundle via `gh attestation verify` before moving the binary into `bin/tinfoil-proxy` (set `FREE_INFERENCE_REQUIRE_GH_ATTESTATION=1` to require `gh` attestation in strict environments).

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

Seal your [Tinfoil](https://tinfoil.sh) API key into the Apple Silicon Secure Enclave once on your Mac (or migrate an existing pre-`v0.1.4` Keychain envelope with a single Touch ID tap and no password or API key re-entry via `./scripts/se-key migrate free-inference.tinfoil`):

```bash
./scripts/se-key store free-inference.tinfoil
# Or migrate an existing legacy Keychain entry into ~/.config/free-inference/se-envelopes/:
./scripts/se-key migrate free-inference.tinfoil
```

Then launch OpenCode from your target project workspace against a cleared Rung 3 enclave model (`tinfoil-deepseek-v4-1-flash` is pinned as the catalog default via `routing.default_private_attested: true` in `models.yaml`; `privatemode-glm-5-3-flash` in `DE/EU` is also cleared and runs without `--allow-uncleared-model` after `./scripts/setup --with-privatemode` and `./scripts/se-key store free-inference.privatemode`):

> **Default Model Selection & Spend Ceiling**: When `--model` is omitted, `opencode-attested` checks `FREE_INFERENCE_DEFAULT_ATTESTED_MODEL`, then `routing.default_private_attested: true` at the highest cleared data-control rung, then active session / installed proxy / sealed envelope narrowing within that rung, then LIFO catalog order. Paid API calls on `tinfoil-deepseek-v4-1-flash` bill at **$0.60 / 1M input tokens ($0.01 cached) and $1.45 / 1M output tokens** (`2026-11-07`), and `privatemode-glm-5-3-flash` bills at **EUR 0.20 / 1M input ($0.22 equiv, EUR 0.05 cached) and EUR 0.65 / 1M output ($0.72 equiv)** (`2026-11-13`). Pass `--max-session-usd <usd>` (for example `--max-session-usd 5.00`) to enforce a pre-flight worst-case session spend ceiling before starting or attaching to a proxy session.

```bash
cd /path/to/your/project

# Interactive TUI session (prompts Touch ID once to start a 2-hour proxy session)
/path/to/free-inference/scripts/opencode-attested

# Launch the cleared DE/EU Privatemode Rung 3 model directly (or set FREE_INFERENCE_DEFAULT_ATTESTED_MODEL=privatemode-glm-5-3-flash)
/path/to/free-inference/scripts/opencode-attested --model privatemode-glm-5-3-flash

# Inspect time and shared requests, or renew in place with fresh Touch ID
/path/to/free-inference/scripts/session status --model tinfoil-deepseek-v4-1-flash
/path/to/free-inference/scripts/session renew --model tinfoil-deepseek-v4-1-flash --for 2h

# Interactive session with an explicit $5.00 worst-case spend ceiling
/path/to/free-inference/scripts/opencode-attested --max-session-usd 5.00 --max-chat-requests 100 --max-request-bytes 262144 --max-tokens-cap 4096

# Non-interactive CLI call (attaches to the running proxy with zero Touch ID prompts)
/path/to/free-inference/scripts/opencode-attested -- run "Review the current git diff for security issues"
```

To try an uncleared Rung 3 candidate (`tinfoil-kimi-k3-1-pro`, `tinfoil-glm-5-3`, `tinfoil-gpt-oss-120b`, or `privatemode-glm-5-3`), pass `--model <id> --allow-uncleared-model`. If another model is already serving on port `8081`, `opencode-attested` automatically allocates the next free side-by-side localhost port pair (`8082`/`9082`, `8083`/`9083`, ...) and writes an isolated per-invocation OpenCode config so both sessions run concurrently without interfering (models with `deprecated: true` or a `deprecation_date` in `models.yaml`, such as `tinfoil-kimi-k3`, are blocked unless `--allow-deprecated-model` is also passed):

```bash
# Runs side-by-side (automatically selects 127.0.0.1:8082 if 8081 is occupied by another model)
./scripts/opencode-attested --model tinfoil-kimi-k3-1-pro --allow-uncleared-model

# Resume an interrupted session with fresh interactive caps (1,000 reqs / 16,384 output tokens)
./scripts/opencode-attested --model tinfoil-kimi-k3-1-pro --allow-uncleared-model --refresh-session -- -c

# Inspect all active model servers, bound ports, session caps, and remaining TTL
./scripts/models --active
```

See [`docs/runbooks.md`](docs/runbooks.md) for copy-paste operator runbooks covering multi-model side-by-side sessions, session recovery (`--refresh-session -- -c`), extended thinking (`--thinking`), subagents (`--allow-subagents`), spend controls, and registering `scripts/local-assist-server` as a Rung 1 stdio MCP server in OpenAI Codex CLI (`codex`), Claude Code (`claude`), and Google Antigravity CLI (`agy`) (see also [`docs/decisions/2026-11-10-codex-claude-agy-wire-discovery.md`](docs/decisions/2026-11-10-codex-claude-agy-wire-discovery.md)).

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

- **Explicit Touch ID windows, zero prompts per attached CLI call**: `scripts/serve-model` passes a random proxy token through an inherited pipe. The key holder unseals the API key into process memory (`PT_DENY_ATTACH`), publishes a protected generation-bound credential envelope, and exposes credential-free status through an owner-only control socket. Interactive sessions default to 2 hours and 1,000 shared chat requests, including title generation. `scripts/session renew --for 2h` requires fresh Touch ID, rotates the token in place, and preserves the remaining request budget. `session stop` revokes it immediately; `session watch --notify` provides foreground warnings. Windows are capped at 24 hours. Stop and expiry interrupt active streams.
- **Kernel socket ownership verification (`F1`)**: Before forwarding any request or `Authorization` header over loopback to `tinfoil-proxy` (`127.0.0.1:9081`), `se-key-proxy` queries XNU `<libproc.h>` (`proc_pidinfo` + `proc_pidfdinfo`) to verify that the expected `tinfoil-proxy` PID and matching kernel start time (`pbi_start_tvsec`/`pbi_start_tvusec`) own the non-`SO_REUSEPORT` listening TCP kernel control block (`soi_pcb`).
- **Isolated OpenCode home and credential custody**: Both launchers isolate OpenCode state and disable model fetching, auto-update, project config, webfetch, and websearch. The attested launcher keeps the proxy token in its trusted parent relay; OpenCode receives only a per-invocation relay credential, confined by the Seatbelt sandbox and credential guard. See [SECURITY.md](SECURITY.md) for the enforced boundary and residual limits.

### Threat Model & Asset Boundary

See [`SECURITY.md`](SECURITY.md) for the full threat model. Key operational boundaries:

- **Proxy credential vs. sealed API key**: The provider API key stays in key-holder memory. The upstream proxy token stays in the trusted launcher and its protected credential file; it is not exported to OpenCode or child environments. Each successful renewal replaces it, while stop or hard expiry terminates its authority. Interactive relays follow the live window; workers keep their own deadlines and budgets. This does not clean up credentials stored by historical sessions; containment remains a separate operator action.
- **Operator-approved shell commands and `SSH_AUTH_SOCK`**: Interactive shell, edit, write, and patch tools require operator approval and run within the launcher's Seatbelt confinement. `SSH_AUTH_SOCK` preserves permitted SSH agent signing; outbound SSH requires the explicit `--allow-ssh-remote` option. See [SECURITY.md](SECURITY.md) for the process, filesystem, and network boundaries.
- **Rung 1 offline check is pre-flight**: `scripts/serve-model` launches Rung 1 servers with `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1`, and `scripts/verify-served-model --require-offline` verifies `hf_offline: true` in the `pid_lstart`-bound PID record plus the live OS listener `--model` flag (`lsof` + `ps`) before `opencode-local` or `local_assist` sends any chat request. This is a pre-flight process/listener check rather than a kernel packet filter.
- **Trusted `models.yaml` `serve_command`**: `models.yaml` is operator-authored configuration in the trusted repository root. Proxy `serve_command` strings are split with `shlex.split` (`shell=False`) and checked by a heuristic localhost flag validator (`validate_custom_command_localhost`), which is a denylist that a shell or interpreter wrapper can bypass, and `bin/tinfoil-proxy`'s digest and Developer ID signature are verified during `./scripts/setup` rather than re-hashed at launch. Review changes to `models.yaml` with the same care as executable code.

---

## CLI Reference, Key Rotation & Troubleshooting

| Command | Purpose |
|---|---|
| `./scripts/models` | List all models in `models.yaml` with data-control rung, status, and usage policy (`--active` / `--sessions` inspects live served models, ports, caps, and TTL; `--json` emits JSON) |
| `./scripts/session status\|start\|stop\|renew\|watch` | Operator authorization windows, live time/shared requests, explicit revocation, in-place Touch ID renewal, and foreground warnings (`--model`, `--for 2h`, `--json`, `--notify`) |
| `./scripts/sync-model-catalog` | `--check` or `--apply` upstream model catalog drift against live enclave and Hugging Face sources |
| `./scripts/serve-model <id>` | Start a local MLX server (`127.0.0.1:8080`) or dual attested proxy (`:8081` + `:9081`; `--interactive`, `--eval-caps`, `--thinking`, `--port`, `--refresh-session`) |
| `./scripts/verify-served-model <id>` | Verify active PID records (`pid_lstart`), `/v1/models`, and OS listener `--model` flags (`--require-offline` for Rung 1) |
| `./scripts/stop-model <id>` | Stop a running model server or proxy after verifying `pid_lstart` (`--all` stops all) |
| `./scripts/opencode-local` | Launch OpenCode locked to Rung 1 (`private-local`) with isolated state and Rung 1 MCP (`--port`, `--allow-subagents`, `--refresh-session`) |
| `./scripts/opencode-attested` | Launch OpenCode locked to Rung 2/3 (`private-attested`) with spend caps (`--max-session-usd`, `--thinking`, `--allow-subagents`, `--port`, `--refresh-session`) and Rung 1 MCP |
| `./scripts/delegate-local <tool>` | Delegate bounded subtasks (`delegate_task`, `compress_context`, `extract_fields`, `propose_eval_prompts`) to Rung 1 |
| `./scripts/se-key <cmd> <service>` | Build `bin/se-key-proxy` (also buildable standalone via `swift build --package-path tools/se_key_proxy -c release`), run `selftest`, or `store` / `migrate` / `status` / `delete` Secure Enclave keys |
| `./scripts/eval <suite> <id>` | Run `sanity`, `v1`, or `tools` promptfoo suites plus streaming TTFT probe |
| `./scripts/generate-eval-manifest` | Generate or `--check` (`--offline-ci`) committed evaluation evidence manifests in `docs/evals/` |

### Key Rotation, Session Refresh & Clean Uninstall

```bash
# Restart an attested enclave session with fresh caps (or recover after TTL expiry)
./scripts/opencode-attested --refresh-session

# Rotate a sealed API key (stop any active proxy first since a running session holds the old key in memory,
# then run store, which replaces the existing envelope in ~/.config/free-inference/se-envelopes/ with a fresh Secure Enclave keypair)
./scripts/stop-model --all
./scripts/se-key store free-inference.tinfoil

# Delete a sealed API key envelope (writes a deleted tombstone so legacy Keychain items are not auto-reimported)
./scripts/se-key delete free-inference.tinfoil

# Full local cleanup (stop servers, delete sealed envelope store, remove build/venv/isolated-home directories)
./scripts/stop-model --all
./scripts/se-key delete free-inference.tinfoil
rm -rf ~/.config/free-inference/se-envelopes .venv node_modules bin .home
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
├── .github/workflows/
│   ├── ci.yml                       macOS arm64 + Linux CI (build, selftest, manifest check, unit + e2e suites)
│   └── catalog-sync.yml             Weekly upstream catalog drift check and GitHub issue reconciler
├── AGENTS.md                        Contributor invariants and 5-rung boundaries
├── CHANGELOG.md                     Release history and local-llm-lab lineage
├── CONTRIBUTING.md                  Contributor invariants and verification checklist
├── SECURITY.md                      Threat model, trust boundaries, and vulnerability reporting
├── models.yaml                      5-rung model registry, pricing, and routing gates
├── requirements-local.txt           Minimal pinned Python closure for Rung 1 mlx-lm (35 packages)
├── requirements.txt                 Full pinned Python closure for evaluation workbench (71 packages)
├── config/
│   ├── opencode-private-local.json.tmpl
│   └── opencode-private-attested.json.tmpl
├── docs/
│   ├── attestations/                Rung 3 Tinfoil attestation & 5-model trial records
│   ├── decisions/                   Architecture and model-selection decision records
│   ├── evals/                       Committed machine-readable evaluation evidence (*.json)
│   ├── local-assist-server.md       MCP server & Rung 1 delegation contract
│   ├── plan.md                      Evaluation workflow and capability gates
│   └── proposal.md                  5-rung architecture and design rationale
├── evals/{prompts,suites,rubrics,chat_templates,transforms}/
├── local_assist/                    Registry, catalog sync, launch helpers, admission gates, MCP server, SE key & worker sandbox
├── scripts/
│   ├── setup                        Bootstrap (--launcher-only, --local-only, or full), bin/se-key-proxy, bin/tinfoil-proxy
│   ├── models                       List registered models with rung and usage policy (--version)
│   ├── sync-model-catalog           Check/heal upstream catalog drift and reconcile [catalog-drift] issues
│   ├── se-key                       Build, selftest, store, status, and delete SE keys
│   ├── serve-model / stop-model     Start/stop local MLX servers or dual attested proxies
│   ├── verify-served-model          Verify PID records and live listener --model flags
│   ├── generate-eval-manifest       Generate/check docs/evals/*.json manifests
│   ├── opencode-local               Launch OpenCode on Rung 1 (private-local)
│   ├── opencode-attested            Launch OpenCode on Rung 2/3 (private-attested)
│   ├── delegate-local               CLI wrapper for Rung 1 local_assist tools
│   ├── eval / timing / opencode-smoke
│   └── *-e2e                        End-to-end verification harnesses
├── tests/                           108 offline unit, catalog sync, Seatbelt, and SE selftests
└── tools/se_key_proxy/main.swift    Hardware-backed Secure Enclave + Touch ID proxy
```

Run the offline unit, catalog sync, Seatbelt, and Secure Enclave selftest suite (108 tests, stdlib + Node):

```bash
.venv/bin/python -B -m unittest discover -s tests -v
python3 -I -B -m unittest discover -s tests -v
./scripts/generate-eval-manifest --check --offline-ci
./scripts/opencode-attested-e2e
```

## License

Apache 2.0. See [LICENSE](LICENSE).
