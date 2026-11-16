# Rung 3 Attestation and Capability Record: Privatemode Enclave Trial (`glm-5.3-flash`, `glm-5.3`; 2026-11-13)

## Summary

- **Evaluated model IDs**:
  - `privatemode-glm-5-3-flash` (`served_model_id`: `glm-5.3-flash`; Section 4)
  - `privatemode-glm-5-3` (`served_model_id`: `glm-5.3`; Section 5)
  - Registered without Phase 2 capability re-run: `privatemode-gpt-oss-120b` (`served_model_id`: `openai/gpt-oss-120b`; same upstream `openai/gpt-oss-120b@b5c939de...` model scored `8/10` on `v1` and `3/4` on `tools` in the 2026-10-31 Tinfoil Rung 3 trial)
- **Registry status & routing gate**: On `2026-11-14`, following operator approval of the `9/10` `patch-like-edit-gitignore` POSIX unified diff exception, **`privatemode-glm-5-3-flash` was promoted to `status: active` and `routing.private_attested: cleared`** (`eval_evidence_artifact: docs/evals/privatemode-glm-5-3-flash.json`), while `privatemode-glm-5-3` (`8/10` on `v1`) and `privatemode-gpt-oss-120b` remain at `status: candidate` and `routing.private_attested: blocked` (`tinfoil-deepseek-v4-1-flash` remains pinned as the catalog default via `routing.default_private_attested: true`). `privatemode-glm-5-3-flash` passed `sanity` (`1/1`), `tools` (`4/4`, `5` streaming tool-call chunks), and `opencode-smoke` (`passed: true` in `2.2788s`, `smoke_seatbelt_enforced: true`, `matches_found: 0`, `active_token_checked: true`, `active_token_matches_found: 0` in `runs/2026-11-13-200441-opencode-smoke-privatemode-glm-5-3-flash-a319fedd-p1s_92n2`), and scored `9/10` on automated `v1` (missing only the `diff --git` header on a valid POSIX unified diff in `patch-like-edit-gitignore`, matching `tinfoil-deepseek-v4-1-flash` and outperforming full `privatemode-glm-5-3`).
- **Admitted data-control rung**: Rung 3 (`enclave_runtime_attested`)
- **Attestation method**: `privatemode-proxy-contrast` (`privatemode-proxy v1.63.0` built from source commit `2634ffb82c72339902f26ae071db513add2bdc2f` + `se-key-proxy`, pinned to `config/privatemode-manifest-v1.63.0.json` with strict NVIDIA OCSP)
- **Jurisdiction**: `DE/EU` (Edgeless Systems GmbH, Bochum, Germany; confidential clusters hosted in Sweden and Norway per Privatemode security documentation)
- **Usage policy**: `provider_terms_apply` (recorded conservatively per the trial protocol; attested Contrast deployment manifests in `edgelesssys/privatemode-public@v1.63.0` terminate HPKE request/response encryption inside the enclave mesh and contain no prompt-logging or AUP-inspection sidecar)
- **Rung 2 weight-attestation fields (`weights_hash` / `weights_source`)**: `null` / `null` on all three entries (kept `null` on Rung 3 so provider manifest claims cannot be mistaken for locally reproduced Rung 2 weight hashes)
- **Provider manifest claims (`provider_manifest_weights_source` / `provider_manifest_weights_hash` from `edgelesssys/privatemode-public@v1.63.0` `models.yaml` and `deployments/*.yaml`)**:
  - `privatemode-glm-5-3-flash`: `nvidia/GLM-5.3-Flash-NVFP4@da920bb0b9f4a06727223a349e55468e38352348` / `dmverity:sha256:c5dcd713fffc38c956bbd41fb299c360ed07d60de61938a6ff2729f6c3acd245` (`206,086,352,896` bytes / `206.1 GB`)
  - `privatemode-glm-5-3`: `nvidia/GLM-5.3-NVFP4@e3b8f9f2fad29727dfa95e766c5cac18ea1414bf` / `dmverity:sha256:df66c4cfc7f34c4f7aefd710795a511cde8384677cd041220a04b55541a07d75` (`467,840,147,456` bytes / `467.8 GB`)
  - `privatemode-gpt-oss-120b`: `openai/gpt-oss-120b@b5c939de8f754692c1647ca79fbf85e8c1e70f8a` / `dmverity:sha256:a19e31d4c7da198b4905539ac00e55b93f377ecc4048e287810b2cf3a197cb29` (`65,790,877,696` bytes / `65.8 GB`)
- **Why Rung 3 (not Rung 2)**: `edgelesssys/privatemode-public@v1.63.0` publishes deterministic EROFS + `dm-verity` packing scripts (`verity/verity.sh` and `models.yaml`, pinning `erofs-utils 1.9.4`, `veritysetup 2.8.7/2.8.8`, `hash_offset`, and `root_hash`), and each attested Confidential Container mounts the read-only weight disk via `disk-mounter` against that exact `dm-verity` `root_hash`. However, reproducing those multi-hundred-GB weight disks (`206.1 GB` for `glm-5.3-flash`, `467.8 GB` for `glm-5.3`) requires downloading the full Hugging Face revisions and running Linux container `mkfs.erofs` + `veritysetup format`, which has not been executed on this macOS host. Per `AGENTS.md` and `docs/proposal.md`, proxy-verified manifests without independent local weight reproduction stay at Rung 3 (`enclave_runtime_attested`).

---

## 1. Host Pre-Flight and Binary Provenance

### 1.1 Loopback Packet-Capture Check (`/dev/bpf*`)

Verified prior to starting the proxy chain that macOS Berkeley Packet Filter devices are restricted to `root:wheel` (`0600`), preventing unprivileged local processes from sniffing loopback HTTP traffic between `se-key-proxy` (`127.0.0.1:8082`) and `privatemode-proxy` (`127.0.0.1:9082`):

```text
crw-------  1 root  wheel  0x17000000 Nov 13 06:58 /dev/bpf0
crw-------  1 root  wheel  0x17000001 Nov 10 09:14 /dev/bpf1
crw-------  1 root  wheel  0x17000002 Nov 10 09:14 /dev/bpf2
crw-------  1 root  wheel  0x17000003 Nov 10 09:14 /dev/bpf3
```

### 1.2 Attesting Proxy Source Build and Stamp Provenance (`bin/`)

Unlike Tinfoil (`tinfoil-proxy`), Edgeless Systems distributes `privatemode-proxy` for macOS via unsigned tarballs / Cask archives without GitHub SLSA Sigstore attestations, while publishing full Go source in `github.com/edgelesssys/privatemode-public`. To eliminate unverified prebuilt binary trust, `./scripts/build-privatemode-proxy` fetches the exact `v1.63.0` git tag, verifies its commit SHA (`2634ffb82c72339902f26ae071db513add2bdc2f`), cross-checks `config/privatemode-manifest-v1.63.0.json` (`sha256: 5fa927e3b864738da35d427c10ba8e49ebeeb1531e49618899cf95f654d240c1`) byte-for-byte against the GitHub release `manifest.json` asset, compiles `./cmd/privatemode-proxy` locally with `CGO_ENABLED=0`, runs an offline macOS Seatbelt (`sandbox-exec` `(deny network-outbound)`) strict-OCSP startup check, and writes `bin/.privatemode-proxy.stamp`:

| Artifact | Source / Repository | Tag & Commit SHA | Verified SHA-256 | Verification Mechanism |
|---|---|---|---|---|
| `bin/privatemode-proxy` | `github.com/edgelesssys/privatemode-public` (`./cmd/privatemode-proxy/cli`) | `v1.63.0` (`2634ffb82c72339902f26ae071db513add2bdc2f`) | `e5ea92b5b9d9fa03cbf91de8815d3724f39015a6845cc323a0f6e92ee91fc845` | Built locally via `./scripts/build-privatemode-proxy` (`go1.27.2 darwin/arm64`, `-trimpath -buildvcs=false`, `-X .../constants.version=v1.63.0`); verified offline via `./scripts/build-privatemode-proxy --verify-only` (`bin/.privatemode-proxy.stamp` + `privatemode-proxy version` == `v1.63.0` + Seatbelt strict-OCSP listener check `passed: true`, `sigterm_exit_code: -15`). |
| `config/privatemode-manifest-v1.63.0.json` | `edgelesssys/privatemode-public/releases/download/v1.63.0/manifest.json` | `v1.63.0` | `5fa927e3b864738da35d427c10ba8e49ebeeb1531e49618899cf95f654d240c1` | Committed in repository and verified byte-for-byte against release `v1.63.0` asset. Note: on `2026-11-13`, unpinned `https://cdn.privatemode.ai/manifest/v1/manifest.json` returned `HTTP 502`, so explicit `--manifest-path` pinning prevented both silent manifest-update drift and a CDN outage. |
| `bin/se-key-proxy` | `tools/se_key_proxy/main.swift` | Local build (`source_sha256`: `f467d1e7e6c256d03c858fb26d2a8f239ab49b4ba7a05bd5387763cc8859b128`, `bin/.se-key-proxy.stamp`) | `49921863627b8adcccda12e52a911d41837944382e65985be39a32521fc72303` | Verified at every `serve-model` start via `local_assist/se_key.py` (`verify_se_key_proxy_binary`: source SHA-256, `Apple Swift version 6.3.3`, binary SHA-256, and `codesign -v --strict`). |

**Build discovery (`Privatemode-Version` header prefix)**:
- In `runs/2026-11-13-071839-privatemode-phase1-negtest`, an initial build linked with `-X .../constants.version=1.63.0` (without the leading `v` used in upstream `privatemode-proxy/version.nix`) caused `POST https://api.privatemode.ai/privatemode/v1/attest` to reject `Privatemode-Version: 1.63.0` with `HTTP 400` (`0` tokens billed, failed closed with `401` locally).
- Updating `scripts/build-privatemode-proxy` to link `constants.version=v1.63.0` (`embedded_version: "v1.63.0"` enforced by `--verify-only`) resolved the header format cleanly (`runs/2026-11-13-072915-privatemode-phase1-negtest`).

### 1.3 Secure Enclave Credential Enrollment (`free-inference.privatemode`)

Sealed in the Apple Secure Enclave under Keychain service `free-inference.privatemode` (`access_control: "biometryCurrentSet"`, `key_fingerprint: "cf7ae0bb027a7f88"`, `envelope_sha256: "44d9abcd90c094b8a03fdcd47cf96d974e94ce431b9657107130a188d49af377"`). Neither `privatemode-proxy` nor evaluation subprocesses ever receive the API key in argv, environment variables, or disk files.

---

## 2. Phase 1 Verification: Fail-Closed Attestation, Credential Isolation, and Live `/v1/models`

### 2.1 Fail-Closed Tampered-Manifest Negative Test (`runs/2026-11-13-072915-privatemode-phase1-negtest`)

To prove that `privatemode-proxy` fails closed on Contrast manifest mismatch before forwarding any prompt or model request, `config/privatemode-manifest-v1.63.0.json` was copied to a temporary file with a single hex nibble flipped in the `workload-glm-5-3-flash` Kata `initdata` policy hash (`abb78b0c3985a8eeb63c86f9ec9b544abeddadaa2868737379e18c531d906360` -> `...361`, `tampered_manifest_sha256: 93bd7efdb746b5f3c83d4d0b9f194759ae8ca86c5f04cd6a0700e2f3017925c5`).

Because `privatemode-proxy` performs remote attestation lazily during `secret-loop` credential setup on the first authenticated request, `se-key-proxy` (`127.0.0.1:8082`) was started in front of `privatemode-proxy` (`127.0.0.1:9082`) with `--manifest-path` pointing at the tampered manifest:
- `GET http://127.0.0.1:8082/v1/models` failed closed in `1.5026s` with `HTTP 401`:
  ```json
  {"error":{"message":"trying API key: setting secrets: All attempts fail:\n#1: updating mesh CA: active manifest does not match expected manifest","type":""}}
  ```
- `POST http://127.0.0.1:8082/v1/chat/completions` failed closed in `0.3548s` with the identical `HTTP 401` (`active manifest does not match expected manifest`).
- Proxy stderr logged `attest-Coordinator: Using AMD SEV-SNP root of trust ... snp-0-GENOA` followed immediately by `active manifest does not match expected manifest`. Zero HPKE secrets were exchanged, zero encrypted prompt bodies were sent, and `0` tokens were billed.

### 2.2 Live `/v1/models` and Pricing Verification (`runs/2026-11-13-073035-privatemode-phase1-models`)

Restarted with the pinned committed manifest `config/privatemode-manifest-v1.63.0.json` and strict NVIDIA OCSP flags (`--nvidia-ocsp-allow-unknown=false --nvidia-ocsp-revoked-grace-period=0`):
- Contrast Coordinator attestation (`snp-0-GENOA`) and `secret-loop` HPKE secret establishment succeeded on the first attempt (`GET /v1/models` returned `HTTP 200` in `2.189s` via `privatemode-proxy`'s `forwardUnencrypted` model-list path; strict GPU OCSP policy parameters were subsequently attached on `forwardEncrypted` inference requests and accepted by the attested backend across all `51` encrypted `/v1/chat/completions` requests in Section 2.3 and Sections 4-5 without error).
- `GET http://127.0.0.1:8082/v1/models` returned `13` served model IDs:
  - Coding / chat models: `glm-5.3-flash` (`tasks: ["generate", "tool_calling", "vision"]`), `glm-flash-latest`, `glm-5.3` (`tasks: ["generate", "tool_calling"]`), `glm-5.2`, `glm-latest`, `openai/gpt-oss-120b` (`tasks: ["generate", "tool_calling"]`), `gpt-oss-120b`, `gpt-oss-latest`
  - Non-chat / specialist models: `deepseek-ocr-2`, `openai/whisper-large-v3`, `whisper-large-v3`, `qwen3-embedding-4b`, `voxtral-mini-3b`
- **Pricing & free-quota billing verification (`2026-11-13`)**:
  - Verified against `https://privatemode.ai/pricing` and `https://docs.privatemode.ai/models/overview` (`2026-11-13`), converted from EUR to USD in `models.yaml` at the `2026-11-12` ECB EUR/USD reference rate (`1.1081`):
    - `glm-5.3-flash`: `EUR 0.20` (`$0.22`) input / `EUR 0.65` (`$0.72`) output / `EUR 0.05` (`$0.06`) cached input per 1M tokens
    - `glm-5.3`: `EUR 1.55` (`$1.72`) input / `EUR 5.74` (`$6.36`) output / `EUR 0.15` (`$0.17`) cached input per 1M tokens
    - `openai/gpt-oss-120b`: `EUR 0.20` (`$0.22`) input / `EUR 0.65` (`$0.72`) output / `EUR 0.04` (`$0.04`) cached input per 1M tokens
  - **Empirical free-tier gate finding**: While `GET /v1/models` succeeds immediately on a newly created organization, `POST /v1/chat/completions` returns `HTTP 402` (`{"error":{"message":"your organization's free token quota is locked; add a payment card at https://portal.privatemode.ai/billing to unlock it","type":""}}`, recorded in `runs/2026-11-13-170737-privatemode-phase1-step4ab/summary.json`) until a payment method is added to unlock the 5M-token free tier (`EUR 0.00` billed during this trial).

### 2.3 Dual-Proxy PCB Verification, Process Hygiene, and 4a/4b/4c Credential-Isolation Gate (`runs/2026-11-13-170737-privatemode-phase1-step4ab`, `runs/2026-11-13-171239-privatemode-phase1-step4b`)

Launched via `./scripts/serve-model privatemode-glm-5-3-flash --max-chat-requests 50 --max-tokens-cap 700 --max-request-bytes 65536 --ttl-seconds 3600 --stream-timeout-seconds 300`:
- `se-key-proxy` (`PID 74387`, `127.0.0.1:8082`) verified upstream `privatemode-proxy` (`PID 74327`, `127.0.0.1:9082`) via `<libproc.h>` `--upstream-pid 74327` PCB socket inspection before emitting `"status": "ready"`.
- `lsof -nP -iTCP:8082,9082 -sTCP:LISTEN`:
  ```text
  COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
  privatemo 74327 <user>    6u  IPv4 0x...                 0t0  TCP 127.0.0.1:9082 (LISTEN)
  se-key-pr 74387 <user>    3u  IPv4 0x...                 0t0  TCP 127.0.0.1:8082 (LISTEN)
  ```
- `ps eww -p 74327` and `ps eww -p 74387` confirmed zero API keys or session token values in argv or environment variables, and confirmed `HOME=<repo-root>/.home` on `privatemode-proxy` with `--workspace .home/privatemode-proxy`.
- **Gate 4a (Cold unauthenticated request to `:9082` before any authenticated `:8082` call)**:
  - `POST http://127.0.0.1:9082/v1/chat/completions` (no `Authorization` header) returned `HTTP 500` in `0.0077s` locally (`{"error":{"message":"forwarding request: mutating request: getting latest secret: don't have a credential yet","type":""}}`), confirming `privatemode-proxy` starts with zero credentials.
- **Gate 4b (Authenticated `:8082` request followed immediately by warm unauthenticated `:9082` request)**:
  - `POST http://127.0.0.1:8082/v1/chat/completions` with `Authorization: Bearer se-session-...` returned `HTTP 200` in `0.573s` (`model: "glm-5.3-flash"`, `content: "OK"`, `system_fingerprint: "vllm-0.31.0-tp2-ep-c68a58a5"`, `prompt_tokens: 16`, `completion_tokens: 2`, `total_tokens: 18`, `reasoning_tokens: 0`).
  - Immediately afterward, while `privatemode-proxy`'s in-memory `secret-loop` held active enclave HPKE secrets, an unauthenticated `POST http://127.0.0.1:9082/v1/chat/completions` returned `HTTP 401` in `0.1228s`:
    ```json
    {"error":{"message":"authenticating API key: no auth found: expected Authorization header with 'Bearer <auth>'","type":""}}
    ```
  - This proves `--api-key-fallback=never` prevents any unauthenticated local caller on `:9082` from piggybacking on a warm `privatemode-proxy` session.
- **Gate 4c (`stop-model` dual-PID teardown)**:
  - `./scripts/stop-model privatemode-glm-5-3-flash` terminated both `se-key-proxy` (`PID 74387`) and `privatemode-proxy` (`PID 74327`), leaving `0` listeners on `:8082` and `:9082`.

---

## 3. Contrast Confidential Containers Attestation and HPKE Encryption Chain (`edgelesssys/privatemode-public@v1.63.0`)

Privatemode uses Edgeless Systems Contrast Confidential Containers on Kubernetes with two cryptographic layers verified by `privatemode-proxy`:

### 3.1 Layer 1: Coordinator Attestation and Pinned `manifest.json` (`config/privatemode-manifest-v1.63.0.json`)

1. `privatemode-proxy` requests a hardware-attested Contrast Coordinator quote (`POST https://api.privatemode.ai/privatemode/v1/attest`) and verifies it locally against the AMD SEV-SNP Genoa hardware root of trust (`snp-0-GENOA`, Coordinator policy hash `b6b4a3d3a25a40e76c881decc848da766e46e5accf0ce71cf5c64a651d393529`), while attaching the strict NVIDIA GPU OCSP policy metadata (`--nvidia-ocsp-allow-unknown=false --nvidia-ocsp-revoked-grace-period=0`) on encrypted inference requests (`forwardEncrypted`) for enforcement inside the attested backend (note that `privatemode-proxy` transmits the OCSP policy constraints rather than recording a standalone GPU quote or OCSP responder transcript locally).
2. The attested Coordinator binds the active cluster `manifest.json`, which `privatemode-proxy` compares against the local pinned `--manifest-path config/privatemode-manifest-v1.63.0.json` (`sha256: 5fa927e3b864738da35d427c10ba8e49ebeeb1531e49618899cf95f654d240c1`). Any change to any Kata `initdata` workload policy hash, container image digest, command line, or `dm-verity` root hash changes `Policies` in `manifest.json` and fails closed at step 2 (proven in Section 2.1).

### 3.2 Layer 2: End-to-End HPKE (`MLKEM768X25519`) Request/Response Encryption Inside the Contrast Mesh

1. Unlike plain TLS termination at an ingress gateway, `privatemode-proxy` negotiates hybrid post-quantum HPKE shared secrets (`hpke.MLKEM768X25519()`) directly with `secret-service` (`apps/v1/StatefulSet/continuum-a225c8/secret-service`, Kata `initdata` policy `2e4247564198b08060ff49d1ed7822de22a31edd1cbd7034e610c7e9cb6d9f95`, image `ghcr.io/edgelesssys/privatemode/secret-service:v1.63.0@sha256:26c797bbde03151b1ae29fec1618dc74b67ba5a7b08f0bc1f20a9d90df06ec7b`) over the Coordinator-issued Contrast mesh CA.
2. Every chat prompt and streaming SSE completion chunk is encrypted end-to-end between local `privatemode-proxy` (`127.0.0.1:9082`) and the attested `envoy` `encryption-plugin` inside the Contrast mesh; the untrusted `api.privatemode.ai` outer ingress sees only ciphertext.
3. With `--disable-prompt-cache=false --prompt-cache-salt=random`, `privatemode-proxy` salts prompt-cache keys with an ephemeral per-process random secret held only in local proxy memory, preventing cross-tenant prompt-cache timing probes while preserving single-session prefix caching.

### 3.3 Workload Policies and `dm-verity` Weight Disks (`v1.63.0`)

Cross-referenced from `edgelesssys/privatemode-public@2634ffb82c72339902f26ae071db513add2bdc2f` (`manifest.json`, `models.yaml`, and `deployments/workload-*.yaml`):

| Served Model ID (`models.yaml` ID) | TEE RuntimeClass & Hardware | Kata `initdata` Policy SHA-256 (`Policies` in `manifest.json`) | Upstream HF Source & Commit (`models.yaml`) | `disk-mounter` `dm-verity` `root_hash` (`deployments/*.yaml`) | Serving Container & Parser Flags |
|---|---|---|---|---|---|
| `glm-5.3-flash` (`privatemode-glm-5-3-flash`) | `contrast-cc-metal-qemu-tdx-gpu` (Intel TDX + NVIDIA B200/B300 CC) | `abb78b0c3985a8eeb63c86f9ec9b544abeddadaa2868737379e18c531d906360` | `nvidia/GLM-5.3-Flash-NVFP4@da920bb0b9f4a06727223a349e55468e38352348` | `c5dcd713fffc38c956bbd41fb299c360ed07d60de61938a6ff2729f6c3acd245` (`206,086,352,896` B) | `vllm-openai:v0.31.0-x86_64-zstd@sha256:017d6959...` (`uid=10001`, `restrict-vllm-network.py`), `--tool-call-parser glm47`, `--reasoning-parser glm47`, `--max-model-len=1048576`, `chat_template_glm-5.3-flash.jinja` (`sha256: b9d96a1b...`) |
| `glm-5.3` (`privatemode-glm-5-3`) | `contrast-cc-metal-qemu-tdx-gpu` (Intel TDX + NVIDIA B200/B300 CC) | `8db3cfedc949f9a1e0702f5ca19ac96eb935fd1ff9cff6a0b2a94d1ceff9575d` | `nvidia/GLM-5.3-NVFP4@e3b8f9f2fad29727dfa95e766c5cac18ea1414bf` | `df66c4cfc7f34c4f7aefd710795a511cde8384677cd041220a04b55541a07d75` (`467,840,147,456` B) | `vllm-openai:v0.31.0-x86_64-zstd@sha256:017d6959...` (`uid=10001`, `restrict-vllm-network.py`), `--tool-call-parser glm47`, `--reasoning-parser glm47`, `--max-model-len=1048576`, `chat_template_glm-5.3.jinja` (`sha256: 4bd60b02...`) |
| `openai/gpt-oss-120b` (`privatemode-gpt-oss-120b`) | `contrast-cc-metal-qemu-snp-gpu` (AMD SEV-SNP Genoa + NVIDIA GPU CC) | `67cb2afc964dee742d9ee007824a989906d52a55b6d7a39c67f929f5e45fdb0d` | `openai/gpt-oss-120b@b5c939de8f754692c1647ca79fbf85e8c1e70f8a` | `a19e31d4c7da198b4905539ac00e55b93f377ecc4048e287810b2cf3a197cb29` (`65,790,877,696` B) | `vllm-openai:v0.31.0-x86_64-zstd@sha256:017d6959...` (`uid=10001`, `restrict-vllm-network.py`), `--max-model-len=131072` |

---

## 4. Phase 2 Capability and Security Evaluation (`privatemode-glm-5-3-flash`)

Evaluated in bounded session mode (`--max-chat-requests 50 --max-tokens-cap 700 --max-request-bytes 65536 --ttl-seconds 3600 --stream-timeout-seconds 300`) with `passthrough: {include_reasoning: false, chat_template_kwargs: {enable_thinking: false}}`. Unlike vLLM's older `glm45` parser, Privatemode's `vllm-0.31.0` `--reasoning-parser glm47` + `chat_template_glm-5.3-flash.jinja` honors `chat_template_kwargs.enable_thinking: false` cleanly (`reasoning_tokens: 0`, `reasoning: null`, `0` retries used across all suites).

### 4.1 Suite Results Summary (`privatemode-glm-5-3-flash`)

| Suite / Gate | Run Directory | Result | Latency / TTFT | Token Usage (Prompt / Completion / Total) | Saved Token Scan (`session_token_scan`) |
|---|---|---|---|---|---|
| `sanity` | `runs/2026-11-13-171255-sanity-privatemode-glm-5-3-flash-a319fedd-2HvmJs` | **PASS** (`1/1`) | `0s` suite (`0.452s`) / text TTFT **`0.2251s`** (`0.4527s` total) | `48` / `43` / `91` (`24` / `21` / `45` suite) | `matches_found: 0` (`60` files scanned) |
| `v1` | `runs/2026-11-13-171312-v1-privatemode-glm-5-3-flash-a319fedd-uzCxB4` | **9/10** (`90%`, `0` errors) | `39s` suite / text TTFT **`0.2343s`** (`0.5610s` total) | `23,639` / `2,527` / `26,166` | `matches_found: 0` (`60` files scanned) |
| `tools` | `runs/2026-11-13-171404-tools-privatemode-glm-5-3-flash-a319fedd-jDaSTE` | **4/4** (`100%`, `0` errors) | `3s` suite / text TTFT `0.2420s`, incremental tool TTFT **`0.4016s`** (`tool_call_chunks: 5`) | `1,644` / `228` / `1,872` | `matches_found: 0` (`61` files scanned) |
| `opencode-smoke` (`v2.0.32`) | `runs/2026-11-13-200441-opencode-smoke-privatemode-glm-5-3-flash-a319fedd-p1s_92n2` (post-isolation fix; pre-fix run `runs/2026-11-13-171420-opencode-smoke-privatemode-glm-5-3-flash-a319fedd-vd1kskax` retained) | **PASS** (`summary.passed: true`, `smoke_seatbelt_enforced: true`, `exit_code: 0`, `only_read_tool_called: true`, `read_target_only: true`, `token_verified: true`, `0` non-localhost sockets) | **`2.2788s`** total (`2` LLM steps, `3` HTTP requests) | `2,172` / `46` / `2,218` (`2,164` / `46` / `2,210` in pre-fix `171420`) | `matches_found: 0`, `active_token_checked: true`, `active_token_matches_found: 0` (`92` files scanned) |

### 4.2 Analysis of `privatemode-glm-5-3-flash` Results

- **Capability & latency**: `privatemode-glm-5-3-flash` matched `tinfoil-deepseek-v4-1-flash` across every capability and smoke gate (`1/1` on `sanity`, `9/10` on `v1` including `bug-fix-python-batching` and `shell-tool-reasoning-safe-commands`, `4/4` on `tools` including `parallel-tool-calls-diff-check` with `5` incremental streaming tool-call chunks and `0.4016s` tool TTFT, and `PASS` in `2.2788s` on `opencode-smoke`) at `$0.22/$0.72` per 1M tokens (`EUR 0.20/0.65`) versus `$0.60/$1.45` on `tinfoil-deepseek-v4-1-flash`.
- **Single `v1` miss (`patch-like-edit-gitignore`)**: Emitted a valid POSIX unified diff (`--- a/.gitignore\n+++ b/.gitignore...`) without the `diff --git a/.gitignore b/.gitignore` git header line, identical to `tinfoil-deepseek-v4-1-flash`, `tinfoil-kimi-k3-1-pro`, and Rung 1 `gemma-4-26b-a4b-it-optiq-mlx-4bit`.
- **`opencode-smoke` Seatbelt isolation and scan-scope fix**: An initial smoke run (`runs/2026-11-13-171420-opencode-smoke-privatemode-glm-5-3-flash-a319fedd-vd1kskax`, `8.5059s`, `2,210` tokens) passed all agent execution/tool/socket subchecks (`0` matches in `out_dir`) but failed closed (`summary.passed: false`) because `opencode-smoke` scanned unrelated sibling directories under `<repo-root>/.home` (`11,503` files / `529 MB`, hitting `9` matches in `.home/opencode-private-attested`). `scripts/opencode-smoke` and `local_assist/se_key.py` were subsequently hardened so Darwin `sandbox-exec` denies `file-read-data` and `file-write*` on `<repo-root>/.home` (and top-level symlink targets) for the smoke `opencode` process tree while `scan_and_redact_directory_tokens` scans `out_dir` plus permitted proxy state and checks exact active-token matches in memory. Re-running `./scripts/opencode-smoke privatemode-glm-5-3-flash` (`runs/2026-11-13-200441-opencode-smoke-privatemode-glm-5-3-flash-a319fedd-p1s_92n2`) passed cleanly (`summary.passed: true`, `smoke_seatbelt_enforced: true`, `matches_found: 0`, `active_token_checked: true`, `active_token_matches_found: 0`).

---

## 5. Phase 2 Capability and Security Evaluation (`privatemode-glm-5-3`)

Following `privatemode-glm-5-3-flash`, `./scripts/stop-model privatemode-glm-5-3-flash` tore down both proxy processes, and `privatemode-glm-5-3` (`nvidia/GLM-5.3-NVFP4`, `$1.72/$6.36` per 1M tokens) was served on `127.0.0.1:8082` (`privatemode-proxy` on `127.0.0.1:9082`) with `--max-chat-requests 40 --max-tokens-cap 700 --max-request-bytes 65536 --ttl-seconds 3600 --stream-timeout-seconds 300` (`enable_thinking: false`, `include_reasoning: false`, `0` retries used on `sanity`, `v1`, and `tools`, plus 1 post-fix `opencode-smoke` rerun with `--max-chat-requests 6 --max-tokens-cap 512 --ttl-seconds 600`).

### 5.1 Suite Results Summary (`privatemode-glm-5-3`)

| Suite / Gate | Run Directory | Result | Latency / TTFT | Token Usage (Prompt / Completion / Total) | Saved Token Scan (`session_token_scan`) |
|---|---|---|---|---|---|
| `sanity` | `runs/2026-11-13-172123-sanity-privatemode-glm-5-3-31376576-TqkdeO` | **PASS** (`1/1`) | `1s` suite / text TTFT `0.5997s` (`1.0364s` total) | `48` / `48` / `96` (`24` / `24` / `48` suite) | `matches_found: 0` (`60` files scanned) |
| `v1` | `runs/2026-11-13-172140-v1-privatemode-glm-5-3-31376576-ELK0vn` | **8/10** (`80%`, `0` errors) | `54s` suite / text TTFT `0.6009s` (`1.6814s` total) | `23,639` / `2,577` / `26,216` | `matches_found: 0` (`60` files scanned) |
| `tools` | `runs/2026-11-13-172313-tools-privatemode-glm-5-3-31376576-ejZxER` | **4/4** (`100%`, `0` errors) | `7s` suite / text TTFT `0.5257s`, incremental tool TTFT `0.6897s` (`tool_call_chunks: 5`) | `1,644` / `207` / `1,851` | `matches_found: 0` (`61` files scanned) |
| `opencode-smoke` (`v2.0.32`) | `runs/2026-11-13-200529-opencode-smoke-privatemode-glm-5-3-31376576-mgx3psmr` (post-isolation fix; pre-fix run `runs/2026-11-13-172349-opencode-smoke-privatemode-glm-5-3-31376576-u_himc0z` retained) | **PASS** (`summary.passed: true`, `smoke_seatbelt_enforced: true`, `exit_code: 0`, `only_read_tool_called: true`, `read_target_only: true`, `token_verified: true`, `0` non-localhost sockets) | **`2.9737s`** total (`2` LLM steps, `3` HTTP requests) | `2,162` / `45` / `2,207` (`2,166` / `33` / `2,199` in pre-fix `172349`) | `matches_found: 0`, `active_token_checked: true`, `active_token_matches_found: 0` (`92` files scanned) |

### 5.2 Analysis of `privatemode-glm-5-3` Results

- **Cross-provider parity with `tinfoil-glm-5-3`**: `privatemode-glm-5-3` (`nvidia/GLM-5.3-NVFP4`) reproduced `tinfoil-glm-5-3` (`Inferact/GLM-5.3-NVFP4`) identically (`1/1` on `sanity`, `8/10` on `v1`, `4/4` on `tools`, `PASS` on `opencode-smoke`), missing the exact same two `v1` cells for the exact same reasons:
  1. `shell-tool-reasoning-safe-commands`: listed only safe read-only inspection commands and appended `"Deliberately excluded: kill, rm, git checkout --, git reset..."`, tripping the negative regex `/checkout\s+--/i`.
  2. `patch-like-edit-gitignore`: emitted a POSIX unified diff (`--- a/.gitignore\n+++ b/.gitignore...`) without a `diff --git` header.
- **Comparison against `privatemode-glm-5-3-flash`**: On this workload, `privatemode-glm-5-3-flash` (`9/10` `v1`, `0.23s` text TTFT, `0.40s` tool TTFT, `2.28s` smoke, `$0.22/$0.72`) strictly dominated full `privatemode-glm-5-3` (`8/10` `v1`, `0.60s` text TTFT, `0.69s` tool TTFT, `2.97s` smoke, `$1.72/$6.36`) on score, latency, and price.

---

## 6. Cumulative Token and Budget Accounting

All Phase 1 and Phase 2 requests (including both the pre-fix `opencode-smoke` runs `171420` / `172349` and the post-fix `opencode-smoke` reruns `200441` / `200529`) ran against the organization's 5,000,000-token free tier (`$0.00` / `EUR 0.00` out-of-pocket spend), staying at `32.6%` of the `200,000`-token trial ceiling (`51` successful chat requests total):

| Phase / Model | Successful Chat Requests | Prompt Tokens | Completion Tokens | Total Tokens | Notional Value (USD at ECB `1.1081`) | Actual Billed Cost |
|---|---|---|---|---|---|---|
| Phase 1 Step 2 (`072915` tampered manifest) & Step 3 (`073035` `/v1/models`) | `0` | `0` | `0` | `0` | `$0.0000` | `$0.00` |
| Phase 1 Step 4b (`171239` authenticated `:8082` `glm-5.3-flash`) | `1` | `16` | `2` | `18` | `$0.000005` | `$0.00` |
| Phase 2 `privatemode-glm-5-3-flash` (`sanity` + `v1` + `tools` + pre-fix smoke `171420`) | `22` | `27,495` | `2,844` | `30,339` | `$0.008097` | `$0.00` |
| Phase 2 `privatemode-glm-5-3-flash` post-fix `opencode-smoke` (`200441`) | `3` | `2,172` | `46` | `2,218` | `$0.000511` | `$0.00` |
| Phase 2 `privatemode-glm-5-3` (`sanity` + `v1` + `tools` + pre-fix smoke `172349`) | `22` | `27,497` | `2,865` | `30,362` | `$0.065516` | `$0.00` |
| Phase 2 `privatemode-glm-5-3` post-fix `opencode-smoke` (`200529`) | `3` | `2,162` | `45` | `2,207` | `$0.004005` | `$0.00` |
| **Total** | **`51`** | **`59,342`** | **`5,802`** | **`65,144`** | **`$0.0781`** | **`$0.00`** |

Post-teardown verification: `./scripts/stop-model privatemode-glm-5-3` terminated both `se-key-proxy` and `privatemode-proxy` (`0` listeners remaining on `:8082` or `:9082`), and a full scan across `<repo-root>/runs/` confirmed `0` `se-session-` token occurrences in any run artifact.

---

## 7. Operator Clearance Decision (`2026-11-14`)

- **Approved**: `privatemode-glm-5-3-flash` promoted to `status: active` and `routing.private_attested: cleared` (`eval_evidence_artifact: docs/evals/privatemode-glm-5-3-flash.json`) under `clearance_basis.mode: "operator_exception"` (`v1` `9/10`, `failed_case: "patch-like-edit-gitignore"`, where the model emitted a valid minimal POSIX unified diff without the git-specific `diff --git` header line and outperformed full `privatemode-glm-5-3` at `8/10`).
- **Retained at `candidate` / `blocked`**: `privatemode-glm-5-3` (`8/10` on `v1`) and `privatemode-gpt-oss-120b` (not re-run on Phase 2; `8/10` `v1` and `3/4` `tools` on Tinfoil).
- **Default `private-attested` catalog selection**: `tinfoil-deepseek-v4-1-flash` sets `routing.default_private_attested: true` in `models.yaml`; `scripts/opencode-attested` resolves `--model`, then `FREE_INFERENCE_DEFAULT_ATTESTED_MODEL`, then `routing.default_private_attested: true` at the highest cleared data-control rung, then active session / installed proxy / sealed envelope narrowing within that rung, then LIFO catalog order (with zero hardcoded model IDs in launcher code).
