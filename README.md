# free-inference

**Free as in freedom (libre), not free beer:** a data-control-first inference workbench and launcher for open-weight coding agents on Apple Silicon.

Most "free inference" lists optimize for `$0` API tiers where your prompts and code become the product. `free-inference` is built around **freedom and control**:

1. **Data control (`5-rung ladder`)**: Keep prompts, repository context, and outputs under the highest practical data control that clears the capability bar for the task.
2. **Freedom of use (`usage_policy`)**: Run open-weight coding models without opaque third-party content filters or silent middleware blocking legitimate engineering and security work.
3. **Verifiable boundaries**: Prompts leave the machine for a remote confidential compute enclave only through a local verifying proxy (`se-key-proxy` -> `tinfoil-proxy`), with an explicit registry boundary between **weight-attested** enclaves (Rung 2) and **runtime-attested** enclaves (Rung 3).
4. **Hardware-bound credential custody**: Remote API keys never sit in `.env` files, shell profiles, or `os.environ`. They are sealed with an Apple Silicon Secure Enclave `.biometryCurrentSet` key and unsealed into `se-key-proxy` memory via a single live Touch ID tap per 12-hour session.
5. **No silent downgrades**: Every model is gated by executable evals (`sanity`, `v1`, `tools`, and `opencode-smoke`), and no launcher or client ever silently falls back to a lower-control rung.

---

## The 5-Rung Data-Control Ladder

Every endpoint in [`models.yaml`](models.yaml) is ordered along five explicit data-control rungs enforced by [`local_assist/registry.py`](local_assist/registry.py) and [`local_assist/client.py`](local_assist/client.py):

| Rung | `remote_trust.tier` | What is verified | Cleared Default Model | Launcher |
|---|---|---|---|---|
| **1** | `local` | Local weights (`mlx-lm`), localhost `127.0.0.1:8080`, `HF_HUB_OFFLINE=1` forced at serve time | `qwen3-30b-a3b-2507-mlx-4bit` (`1/1` sanity, `10/10` v1, `4/4` tools, `PASS` opencode-smoke) | `./scripts/opencode-local` |
| **2** | `enclave_weights_attested` | Hardware TEE + local proxy verifies enclave measurement **and** independent local `dm-verity` `weights_hash` reproduction against a pinned Hugging Face commit | *(Requires local multi-hundred-GB `modelwrap --verify` build)* | `./scripts/opencode-attested` |
| **3** | `enclave_runtime_attested` | Hardware TEE + local `tinfoil-proxy` verifies AMD SEV-SNP / Intel TDX enclave measurement and Sigstore provenance (`tinfoilsh/confidential-model-router`) + `se-key-proxy` verifies kernel socket PCB ownership (`libproc`) | `tinfoil-deepseek-v4-1-flash` (1M context, `1/1` sanity, `9/10` v1, `4/4` tools, `PASS` opencode-smoke) | `./scripts/opencode-attested` |
| **4** | `zdr_contract` | Contractual zero data retention over standard TLS (`store=False`) | Blocked from private coding workflows | Eval / general only |
| **5** | `standard_api` | Standard retaining third-party API | Blocked from private coding workflows | Eval / general only |

---

## Quick Start (macOS Apple Silicon)

### 1. Bootstrap environment and verified proxy binaries

Requires macOS on Apple Silicon (with Touch ID for Rung 2/3; Rung 1 local inference works on all Apple Silicon Macs), `uv`, `python3`, `node` (`^20.20.0 || >=22.22.0`) and `npm`, Xcode Command Line Tools (`swiftc`), and [`opencode`](https://opencode.ai) (`v2.0.32+`):

```bash
./scripts/setup
```

`./scripts/setup` validates the Node.js version, creates `.venv`, installs `mlx-lm` and pinned `promptfoo` (`0.121.11`) via `npm ci`, compiles [`tools/se_key_proxy/main.swift`](tools/se_key_proxy/main.swift) into `bin/se-key-proxy` (running the hardware Secure Enclave non-interactive selftest when Touch ID hardware is present, or skipping `exit 77` on Macs without Touch ID), and downloads `bin/tinfoil-proxy` (`v0.2.9`), unconditionally verifying its pinned SHA-256 (`6b526fe3...`) and Apple Developer ID signature (`TeamIdentifier=8KSH668LZT`), and additionally running `gh attestation verify` against Tinfoil's GitHub SLSA Sigstore provenance bundle when the `gh` CLI is installed and authenticated.

### 2. Rung 1: Local Private Coding (`private-local`)

Runs `qwen3-30b-a3b-2507-mlx-4bit` locally on `http://127.0.0.1:8080/v1` with `HF_HUB_OFFLINE=1` (no API key or Touch ID required; ~18 GB unified memory):

```bash
# First time only: download weights from Hugging Face, run sanity check to complete loading, then stop the online server
./scripts/serve-model qwen3-30b-a3b-2507-mlx-4bit --allow-hf-online
./scripts/sanity-check qwen3-30b-a3b-2507-mlx-4bit
./scripts/stop-model qwen3-30b-a3b-2507-mlx-4bit

# Launch OpenCode locked to Rung 1 (starts local server offline with HF_HUB_OFFLINE=1; refuses online-enabled servers)
./scripts/opencode-local
```

### 3. Rung 3: Attested Enclave Coding & Cross-Family Review (`private-attested`)

Seal your [Tinfoil](https://tinfoil.sh) API key into the Apple Silicon Secure Enclave once on your Mac:

```bash
./scripts/se-key store free-inference.tinfoil
```

Then launch OpenCode against the default cleared Rung 3 enclave model (`tinfoil-deepseek-v4-1-flash`, 1M token context window):

```bash
# Interactive TUI session (prompts Touch ID once to start a 12-hour proxy session)
./scripts/opencode-attested

# Non-interactive CLI call (attaches to the running proxy with zero Touch ID prompts)
./scripts/opencode-attested -- run "Review the current git diff for security issues"
```

To try another evaluated Rung 3 candidate (`tinfoil-kimi-k3`, `tinfoil-glm-5-3`, or `tinfoil-gpt-oss-120b`), stop the active proxy on port `8081` and pass `--model <id> --allow-uncleared-model`:

```bash
./scripts/stop-model tinfoil-deepseek-v4-1-flash
./scripts/opencode-attested --model tinfoil-kimi-k3 --allow-uncleared-model
```

---

## Architecture & Security Controls

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

- **One Touch ID per session, zero prompts per CLI call**: When `se-key-proxy` starts on `127.0.0.1:8081`, you tap Touch ID once. `se-key-proxy` unseals the API key into process memory (`PT_DENY_ATTACH`) for up to 12 hours (`--ttl-seconds 43200`) and 1,000 chat turns (`--max-chat-requests 1000`), and writes a random `0600` session token (`runs/.se-session-*.token`). All parallel OpenCode panes and CLI calls attach automatically without re-prompting Touch ID.
- **Kernel socket ownership verification (`F1`)**: Before forwarding any request or `Authorization` header over loopback to `tinfoil-proxy` (`127.0.0.1:9081`), `se-key-proxy` queries XNU `<libproc.h>` (`proc_pidinfo` + `proc_pidfdinfo`) to verify that the expected `tinfoil-proxy` PID owns the non-`SO_REUSEPORT` listening TCP kernel control block (`soi_pcb`).
- **Isolated OpenCode home & zero cloud leakage**: Both `./scripts/opencode-local` and `./scripts/opencode-attested` run `opencode` with an isolated `HOME` (`.home/opencode-*`), `OPENCODE_DISABLE_MODELS_FETCH=1`, `OPENCODE_DISABLE_AUTOUPDATE=1`, `OPENCODE_DISABLE_PROJECT_CONFIG=1`, `webfetch`/`websearch` denied, and `apiKey: "{env:LOCAL_ASSIST_SESSION_TOKEN}"` so session tokens are never written to `opencode.json` or `opencode.db`.

---

## Repository Layout & Verification

```text
.
├── AGENTS.md                        Operating rules and 5-rung boundaries
├── models.yaml                      5-rung model registry, pricing, and routing gates
├── config/
│   ├── opencode-private-local.json.tmpl
│   └── opencode-private-attested.json.tmpl
├── docs/
│   ├── attestations/                Rung 3 Tinfoil attestation & 4-model trial records
│   ├── decisions/                   Architecture and model-selection decision records
│   ├── local-assist-server.md       MCP server & Rung 1 delegation contract
│   └── plan.md                      Evaluation workflow and capability gates
├── evals/{prompts,suites,rubrics,chat_templates,transforms}/
├── local_assist/                    Registry, admission gates, MCP server, and SE key verify
├── scripts/
│   ├── setup                        Bootstrap .venv, npm, bin/se-key-proxy, bin/tinfoil-proxy
│   ├── models                       List registered models with rung and usage policy
│   ├── se-key                       Build, selftest, store, status, and delete SE keys
│   ├── serve-model / stop-model     Start/stop local MLX servers or dual attested proxies
│   ├── verify-served-model          Verify PID records and live listener --model flags
│   ├── opencode-local               Launch OpenCode on Rung 1 (private-local)
│   ├── opencode-attested            Launch OpenCode on Rung 2/3 (private-attested)
│   ├── delegate-local               CLI wrapper for Rung 1 local_assist tools
│   ├── eval / timing / opencode-smoke
│   └── *-e2e                        End-to-end verification harnesses
├── tests/                           55 offline unit and Secure Enclave selftests
└── tools/se_key_proxy/main.swift    Hardware-bound Secure Enclave + Touch ID proxy
```

Run the offline unit and Secure Enclave selftest suite (55 tests, stdlib + Node):

```bash
.venv/bin/python -m unittest discover -s tests -v
```

## License

Apache 2.0. See [LICENSE](LICENSE).
