# Rung 3 Attestation and Capability Record: Tinfoil Enclave Trial (`gpt-oss-120b`, `deepseek-v4-1-flash`, `glm-5-3`, `kimi-k3`; 2026-10-31)

## Summary

- **Evaluated model IDs**:
  - `tinfoil-gpt-oss-120b` (`served_model_id`: `gpt-oss-120b`; Section 4)
  - `tinfoil-deepseek-v4-1-flash` (`served_model_id`: `deepseek-v4-1-flash`; Section 5)
  - `tinfoil-glm-5-3` (`served_model_id`: `glm-5-3`; Section 6)
  - `tinfoil-kimi-k3` (`served_model_id`: `kimi-k3`; Section 7)
- **Registry status & routing gate**: On 2026-11-01, the operator approved promoting `tinfoil-deepseek-v4-1-flash` to `status: active` and `routing.private_attested: cleared` as the default `private-attested` model following `sanity` `1/1`, `tools` `4/4`, `opencode-smoke` `PASS`, `v1` `9/10` (missing only the `diff --git` prefix on a valid POSIX unified diff), and full-day production use in `opencode-attested`. The remaining three models (`tinfoil-gpt-oss-120b`, `tinfoil-glm-5-3`, and `tinfoil-kimi-k3`) remain `status: candidate` and `routing.private_attested: blocked`.
- **Admitted data-control rung**: Rung 3 (`enclave_runtime_attested`)
- **Attestation method**: `tinfoil-proxy-sigstore` (`tinfoil-proxy v0.2.9` + `se-key-proxy`)
- **Usage policy**: `provider_terms_apply` (recorded conservatively per the trial protocol (`T4`/`T6`) until the operator explicitly approves promoting to `enclave_no_inspection`; note that attested router source `safeguards/capture.go` in `tinfoilsh/confidential-model-router@v0.0.168` exempts Bearer API keys from `safeguards` classification, as documented in Section 3.3)
- **Rung 2 weight-attestation fields (`weights_hash` / `weights_source`)**: `null` / `null` on all four entries (kept `null` on Rung 3 per `plans/tinfoil-attestation-trial.md` `T7` so unverified provider manifest claims cannot be mistaken for locally reproduced Rung 2 weight hashes)
- **Provider manifest claims (`provider_manifest_weights_source` / `provider_manifest_weights_hash` from `tinfoilsh/tinfoil-config@main` `tinfoil-config.yml`)**:
  - `tinfoil-gpt-oss-120b`: `openai/gpt-oss-120b@b5c939de8f754692c1647ca79fbf85e8c1e70f8a` / `dmverity:sha256:db5daddec41a3be3b51d1f4d009fb0e9b1243c2765e2bc5121acac79ab070a72` (`195,764,056,064` bytes, UUID `0eefa619-50b7-588f-a072-d405fb439d36`)
  - `tinfoil-deepseek-v4-1-flash`: `deepseek-ai/DeepSeek-V4.1-Flash-1017@1bae0e1088993b9b82de08f59de5be5a34e42170` / `dmverity:sha256:6c4a2b637f7f45d9e48d1bdc38c12e0454584f48d3759851f7ee4471cd90b2e7` (`510.3 GB`)
  - `tinfoil-glm-5-3`: `Inferact/GLM-5.3-NVFP4@ce67b36f3669192b5bb233819f0fda6c8a9837f8` / `dmverity:sha256:50f49b63a8139cf970d93e81978c7c21ab42e96b84e80c123f496ae33cb768a8` (`464.9 GB`)
  - `tinfoil-kimi-k3`: `moonshotai/Kimi-K3@a590ce090cb049c93a33dfe8c208ec652aa20503` / `dmverity:sha256:58d5e74ba6c814d4cc4511df093ede786bfbc95f766eee7a96379687ce455792` (`1,561.0 GB`)
- **Why Rung 3 (not Rung 2)**: Although Tinfoil's attested model enclave manifests mount the model weights read-only via `dm-verity` at `/tinfoil/mpk/mpk-<sha256>`, the multi-hundred-GB `modelwrap` `dm-verity` images have not been independently rebuilt and verified on this host via `modelwrap --verify`. Per `AGENTS.md` and `proposal.md`, proxy-verified manifests without independent weight reproduction remain at Rung 3 (`enclave_runtime_attested`).

---

## 1. Host Pre-Flight and Binary Provenance (`T8`)

### 1.1 Loopback Packet-Capture Check (`/dev/bpf*`)

Verified prior to starting the proxy chain that macOS Berkeley Packet Filter devices are restricted to `root:wheel` (`0600`), preventing unprivileged local processes from sniffing loopback HTTP traffic between `se-key-proxy` (`127.0.0.1:8081`) and `tinfoil-proxy` (`127.0.0.1:9081`):

```text
crw-------  1 root  wheel  0x17000000 Oct 31 20:45 /dev/bpf0
crw-------  1 root  wheel  0x17000001 Oct 29 10:12 /dev/bpf1
crw-------  1 root  wheel  0x17000002 Oct 29 10:12 /dev/bpf2
crw-------  1 root  wheel  0x17000003 Oct 29 10:12 /dev/bpf3
```

### 1.2 Attesting Proxy Binary Provenance (`bin/`)

Both Tinfoil binaries were downloaded from official Tinfoil GitHub releases into workspace-local `bin/` (no global `/opt/homebrew` installation):

| Binary | Upstream Source / Repository | Release Tag & Commit SHA | Archive / Binary SHA-256 | Cryptographic Signature / Attestation Status |
|---|---|---|---|---|
| `bin/tinfoil-proxy` (active `serve_command` binary) | `github.com/tinfoilsh/tinfoil-proxy` | `v0.2.9` (`07dedede9e0b3529bc58b184e0f996ef3a8d937d`) | Binary (`bin/tinfoil-proxy`): `6b526fe32244bcccfcfde3c5d181618b4b06b48498e649cd944cc9b64acf994b` (matches release `SHA256SUMS`) | **GitHub SLSA v1 Sigstore build provenance** verified via `gh attestation verify` (`tinfoilsh/tinfoil-proxy` `.github/workflows/release.yml@refs/tags/v0.2.9`, Sigstore OIDC issuer `https://token.actions.githubusercontent.com`) **and** **Apple Developer ID code signature** (`Authority=Developer ID Application: Tinfoil, Inc (8KSH668LZT)`, `TeamIdentifier=8KSH668LZT`, `CDHash=fce92ce1305dff74f3e2d2ba38a01259be31cc84`, `flags=0x10000(runtime)`) |
| `bin/tinfoil` (not used by `serve_command`; `tinfoil proxy` is deprecated in favor of `tinfoil-proxy`) | `github.com/tinfoilsh/tinfoil-cli` | `v0.19.12` (`b9abe8ee1f7cdda680ab271a617d9b00490481ed`) | Archive (`tinfoil_0.19.12_darwin_arm64.tar.gz`): `2909d0c916384f63f7a609dad0d6a1348a3cbe871ce8fae3e6d47b55ec7282b3` (matches release `checksums.txt`)<br>Binary (`bin/tinfoil`): `31c0f2bdb9d4680dd9da7acccaa9bf5d5d2e014ca1582589fbf8c322f7a17be3` | **Checksum-only provenance**: `codesign -dv` reports `Signature=adhoc` (`TeamIdentifier=not set`), and `gh attestation verify` reports `no attestations found` for `31c0f2bd...`. Used only for CLI comparison during Phase 1 scouting; not invoked by `models.yaml`. |
| `bin/se-key-proxy` | `tools/se_key_proxy/main.swift` | Local build (`source_sha256`: `25afb0d77b321c8999d6db9461650f7909d1c6ff2a21c4273fc40f1ae73c56dd`, recorded in `bin/.se-key-proxy.stamp`) | Binary (`bin/se-key-proxy`): `012f4414ad3c9889915aaf9318e77d28d145b3a973ecf190fe7b017342fe04c2` | Verified at every `serve-model` start via `local_assist/se_key.py` (`verify_se_key_proxy_binary`: source SHA-256, `swiftc --version`, binary SHA-256, and `codesign -v --strict`). |

Observed verification output for `bin/tinfoil-proxy`:

```text
$ gh attestation verify <repo-root>/bin/tinfoil-proxy --repo tinfoilsh/tinfoil-proxy
Loaded digest sha256:6b526fe32244bcccfcfde3c5d181618b4b06b48498e649cd944cc9b64acf994b for file://<repo-root>/bin/tinfoil-proxy
Loaded 1 attestation from GitHub API
✓ Verification succeeded!

The following 1 attestation matched the policy criteria
- Attestation #1
  - Build repo:     tinfoilsh/tinfoil-proxy
  - Build workflow: .github/workflows/release.yml@refs/tags/v0.2.9
  - Signer repo:    tinfoilsh/tinfoil-proxy
  - Signer workflow: .github/workflows/release.yml@refs/tags/v0.2.9

$ codesign -dv --verbose=4 <repo-root>/bin/tinfoil-proxy
Executable=<repo-root>/bin/tinfoil-proxy
Identifier=tinfoil-proxy-darwin-arm64
Format=Mach-O thin (arm64)
CodeDirectory v=20500 size=238922 flags=0x10000(runtime) hashes=7459+2 location=embedded
CDHash=fce92ce1305dff74f3e2d2ba38a01259be31cc84
Signature size=8979
Authority=Developer ID Application: Tinfoil, Inc (8KSH668LZT)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=Feb 27, 2026 at 5:26:52 PM
TeamIdentifier=8KSH668LZT
```

---

## 2. Phase 1 Verification: Fail-Closed Attestation, Header Passthrough, and Process Hygiene

### 2.1 Fail-Closed Negative Test (`T1` / `F4` / `E6`)

Executed against `inference.tinfoil.sh` with a deliberately mismatched `--repo tinfoilsh/confidential-llama3-3-70b` before unlocking any API key (`0` tokens billed):

```text
$ ./bin/tinfoil-proxy --bind 127.0.0.1 --port 8081 -e inference.tinfoil.sh --repo tinfoilsh/confidential-llama3-3-70b
time="2026-10-31T20:49:10-04:00" level=info msg="Creating enclave handle" enclave=inference.tinfoil.sh repo=tinfoilsh/confidential-llama3-3-70b
time="2026-10-31T20:49:10-04:00" level=fatal msg="Failed to verify enclave" error="verifying source code failed:failed to verify sigstore bundle: verifying bundle: verifying certificate: failed to verify certificate extensions: expected SAN value to match regex \"^https://github\\.com/tinfoilsh/confidential-llama3-3-70b/\\.github/workflows/[^/@]+@refs/tags/[^@]+$\", got \"https://github.com/tinfoilsh/confidential-model-router/.github/workflows/tinfoil-release-publish.yml@refs/tags/v0.0.168\""
```

Observed results:
- Process exited immediately with return code `1` before opening a listener socket.
- `lsof -nP -iTCP:8081 -sTCP:LISTEN` returned exit code `1` (no listener).
- `GET http://127.0.0.1:8081/v1/models` and `POST http://127.0.0.1:8081/v1/chat/completions` both failed closed with `ConnectionRefusedError(61, 'Connection refused')`.

### 2.2 Unauthenticated Header-Passthrough Gate (`R3` / `N4`)

1. Started `tinfoil-proxy` on `127.0.0.1:9081` with `--repo tinfoilsh/confidential-model-router` and zero credentials in argv or environment, then sent an unauthenticated `POST http://127.0.0.1:9081/v1/chat/completions`:
   - Status: `401 Unauthorized`
   - Body: `{"error":{"message":"You didn't provide an API key.","type":"invalid_request_error","param":null,"code":"missing_api_key"}}`
   - This proved that `tinfoil-proxy` starts without a `TINFOIL_API_KEY` environment variable or CLI flag, holds no credential of its own, and forwards the unauthenticated request to the enclave router.
2. Once `se-key-proxy` (`127.0.0.1:8081`) was started in front of `tinfoil-proxy` (`127.0.0.1:9081`) in Section 2.3 and Section 4, authenticated requests (`verify-served-model`, `opencode-smoke`, `sanity`, `v1`, and `tools`) sent with `Authorization: Bearer se-session-...` to `127.0.0.1:8081` had their header replaced by `se-key-proxy` with `Authorization: Bearer tf-...` and returned `200 OK` from the enclave via `tinfoil-proxy` on `127.0.0.1:9081`. Together, the `401` without `se-key-proxy` and `200 OK` through `se-key-proxy` prove transparent `Authorization` header passthrough across `tinfoil-proxy`.

### 2.3 Live Dual-Proxy Socket and Process Hygiene (`S1` / `F1`)

Launched via:

```bash
./scripts/serve-model tinfoil-gpt-oss-120b \
  --max-chat-requests 50 \
  --max-tokens-cap 700 \
  --max-request-bytes 65536 \
  --ttl-seconds 3600 \
  --stream-timeout-seconds 300
```

Observed live process and socket state:
- `se-key-proxy` (`PID 39983`) verified upstream `tinfoil-proxy` (`PID 39848`) via `<libproc.h>` `proc_pidinfo(..., PROC_PIDLISTFDS, ...)` + `proc_pidfdinfo(..., PROC_PIDFDSOCKETINFO, ...)` on `127.0.0.1:9081` and emitted `"status": "ready"`.
- `lsof -nP -iTCP:8081 -sTCP:LISTEN`:
  ```text
  COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
  se-key-pr 39983 home    3u  IPv4 0xf2f5b8a6f2b46e54      0t0  TCP 127.0.0.1:8081 (LISTEN)
  ```
- `lsof -nP -iTCP:9081 -sTCP:LISTEN`:
  ```text
  COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
  tinfoil-p 39848 home    6u  IPv4 0x1074bb02f0c06e2f      0t0  TCP 127.0.0.1:9081 (LISTEN)
  ```
- `ps eww -p 39848` (`tinfoil-proxy`) and `ps eww -p 39983` (`se-key-proxy`): zero API key (`tf-...`) or session token (`se-session-...`) strings in command-line arguments or environment variables; `tinfoil-proxy` ran with `HOME=<repo-root>/.home`, confining `.tinfoil/user_cache_secret` to gitignored `.home/.tinfoil/user_cache_secret` (a 36-byte UUID generated by `tinfoil-proxy` to derive a deterministic client cache-routing salt for prompt-cache locality, containing no API key material).
- `./scripts/verify-served-model tinfoil-gpt-oss-120b --wait 30` returned `gpt-oss-120b`.

---

## 3. Two-Hop Enclave Attestation Chain (`T2`)

Tinfoil uses a two-hop attested architecture:

### 3.1 Hop 1: Local `tinfoil-proxy` -> Router Enclave (`inference.tinfoil.sh`)

`GET http://127.0.0.1:9081/verification-document` (captured at `2026-10-31T20:54:12-04:00`) returned the live cryptographic verification document from `tinfoil-proxy`:

```json
{
  "ConfigRepo": "tinfoilsh/confidential-model-router",
  "EnclaveHost": "inference.tinfoil.sh",
  "CodeTag": "v0.0.168",
  "CodeDigest": "adc71cdb94b8762993777156f3290463f3a8ee2ea42665289a83d502cdf69d76",
  "EnclaveMeasurement": {
    "type": "https://tinfoil.sh/predicate/sev-snp-guest/v2",
    "registers": [
      "e716274321b31eaf1301d3eddfbe477da1a69c6a8afeea9f8cd36b6546d94728ffb88b4eb11f0a4cc76e40e3b294b8a7"
    ]
  },
  "TLSKeyFP": "6af2bd2e98f9289039dc34b344e358198377c38b12471f651978df378112c672",
  "HPKEPublicKey": "2635ac6c1d8863cd8ea74b7eeb1f675c9ff776e9c75b4ed9ca7ecf19ca564401",
  "SecurityFeatures": null,
  "FreshnessExpiresAt": "2026-11-04T13:20:14-05:00"
}
```

In addition to pinning the router enclave's TLS SPKI SHA-256 (`6af2bd2e...`) against the AMD SEV-SNP hardware attestation quote, `tinfoil-proxy v0.2.9` encrypts HTTP request and response bodies to `HPKEPublicKey` (`2635ac6c...`) via Encrypted HTTP Body Protocol (EHBP).

### 3.2 Hop 2: Router Enclave -> Backend Model Enclaves (`*.tinfoil.containers.tinfoil.dev`)

Inside the attested router source (`github.com/tinfoilsh/confidential-model-router@v0.0.168`, `manager/verification.go` and `config.yml`), the router holds a compiled-in model-to-repository map and runs `enclave.NewHandle(host, repo, nil).Verify()` and `TLSBoundRoundTripper{ExpectedPublicKey: key}` against every backend model enclave before forwarding requests. Backend model enclaves are isolated on an internal network (direct external probes to `gpt-oss-120b-inf12-0.tinfoil.containers.tinfoil.dev` return `502 Bad Gateway`), and the router publishes its live verification state at `https://inference.tinfoil.sh/.well-known/tinfoil-proxy`.

Live snapshot of Tinfoil's coding models captured on `2026-10-31` (note: `tinfoil-gpt-oss-120b`, `tinfoil-deepseek-v4-1-flash`, `tinfoil-glm-5-3`, and `tinfoil-kimi-k3` are registered in `models.yaml` because those four models were evaluated in Phase 2; `gemma4-31b` is documented here for reference):
- **Column sources and capture timestamps (`2026-10-31T20:51-20:55 EDT`)**:
  - *Served Model ID, Attested Enclave Repo & Tag, and TEE Architecture*: captured from `GET https://inference.tinfoil.sh/.well-known/tinfoil-proxy` (`router.models.<id>` and backend `VerificationDocument.EnclaveMeasurement.type`) and cross-checked against `github.com/tinfoilsh/confidential-model-router@v0.0.168` (`config.yml`).
  - *Upstream HF Source and `modelwrap` `dm-verity` Root Hash (`mpk`)*: captured from each model repository's release `tinfoil-config.yml` and `github.com/tinfoilsh/tinfoil-config@main` (`tinfoil-config.yml`).
  - *Pricing ($ / 1M tokens)*: confirmed on `2026-10-31` by the operator from the authenticated Tinfoil billing dashboard (`https://dash.tinfoil.sh`) and cross-checked against `https://tinfoil.sh/pricing`.

| Served Model ID | Attested Enclave Repo & Tag (`/.well-known/tinfoil-proxy`) | TEE Architecture (`EnclaveMeasurement.type`) | Upstream HF Source (`tinfoil-config.yml`) | `modelwrap` `dm-verity` Root Hash (`mpk` in `tinfoil-config.yml`) | Pricing ($ / 1M tokens, `dash.tinfoil.sh` 2026-10-31) |
|---|---|---|---|---|---|
| `gpt-oss-120b` (registered in `models.yaml` as `tinfoil-gpt-oss-120b`, `status: candidate`) | `tinfoilsh/confidential-gpt-oss-120b`<br>`v0.0.28` (3 hosts: `gpt-oss-120b-inf12-{0,1,2}`) | Intel TDX (`tdx-guest/v2`) | `openai/gpt-oss-120b@b5c939de8f754692c1647ca79fbf85e8c1e70f8a` | `db5daddec41a3be3b51d1f4d009fb0e9b1243c2765e2bc5121acac79ab070a72` (195.8 GB) | `$0.15` input / `$0.60` output |
| `deepseek-v4-1-flash` (registered in `models.yaml` as `tinfoil-deepseek-v4-1-flash`, `status: candidate`) | `tinfoilsh/confidential-deepseek-v4-1-flash`<br>`v0.0.10+b200` / `v0.0.10+b300` | Intel TDX + AMD SEV-SNP | `deepseek-ai/DeepSeek-V4.1-Flash-1017@1bae0e1088993b9b82de08f59de5be5a34e42170` | `6c4a2b637f7f45d9e48d1bdc38c12e0454584f48d3759851f7ee4471cd90b2e7` (510.3 GB) | `$0.65` input (`$0.13` cached) / `$1.45` output |
| `glm-5-3` (registered in `models.yaml` as `tinfoil-glm-5-3`, `status: candidate`) | `tinfoilsh/confidential-glm5-3-nvfp4`<br>`v0.0.10` | Intel TDX / Blackwell | `Inferact/GLM-5.3-NVFP4@ce67b36f3669192b5bb233819f0fda6c8a9837f8` | `50f49b63a8139cf970d93e81978c7c21ab42e96b84e80c123f496ae33cb768a8` (464.9 GB) | `$1.80` input (`$0.45` cached) / `$5.75` output |
| `kimi-k3` (registered in `models.yaml` as `tinfoil-kimi-k3`, `status: candidate`) | `tinfoilsh/confidential-kimi-k3`<br>`v0.0.6` | Intel TDX / 8x GPU | `moonshotai/Kimi-K3@a590ce090cb049c93a33dfe8c208ec652aa20503` | `58d5e74ba6c814d4cc4511df093ede786bfbc95f766eee7a96379687ce455792` (1.56 TB) | `$4.00` input (`$0.80` cached) / `$20.00` output |
| `gemma4-31b` (not yet evaluated in this repository) | `tinfoilsh/confidential-gemma4-31b`<br>`v0.0.30` | Intel TDX + AMD SEV-SNP | `google/gemma-4-31B-it@842da3794eaa0b77d5f08bae87a17459d91ff475` | `cda2f261f72d80a847eb6fabea1f9949bf14ce5bb323808a8e2e4a9f09018357` (62.6 GB) | `$0.40` input / `$1.00` output |

### 3.3 `usage_policy` Assessment (`provider_terms_apply` vs. `enclave_no_inspection`)

Inspection of `github.com/tinfoilsh/confidential-model-router@v0.0.168` (`safeguards/capture.go` lines 43-49 and `main.go` line 634) showed that although the router runs an enclave-internal Acceptable Use Policy classifier (`safeguards`), `safeguardsSubmitter.Observe(w, r, manager.IsFirstPartyChatAccessJWT)` explicitly exempts API key traffic:

```go
// Observe wraps w to capture the request and response for asynchronous
// safeguard classification when the request path and auth header qualify. Only
// first-party chat access tokens on conversational paths qualify; API keys are
// never classified. When classification is disabled or the request does not
// qualify, Observe returns w unchanged with zero overhead.
```

Because `se-key-proxy` authenticates via a Bearer API key (`tf-...`), `Observe` returns `w` unchanged and never copies prompts or completions to the `safeguards` sidecar. Per `plans/tinfoil-attestation-trial.md` (`T4` / `T6`), `models.yaml` records `usage_policy: provider_terms_apply` until the operator explicitly approves promoting `usage_policy` to `enclave_no_inspection`.

---

## 4. Phase 2 Capability and Security Evaluation (`tinfoil-gpt-oss-120b`)

### 4.1 Promptfoo vLLM Reasoning Compatibility Finding and Retry Accounting

Note on execution order: `opencode-smoke` (`205800`) was executed first to verify end-to-end agent tool-calling through `se-key-proxy` + `tinfoil-proxy`, followed immediately by `sanity` (`205809`), `v1` (`210518`), and `tools` (`210614`).

During `sanity` Run 1 (`runs/2026-10-31-205809-sanity-tinfoil-gpt-oss-120b-0f58d616-CtpYud`, `1/1` pass at default reasoning effort), Tinfoil's vLLM server (`--reasoning-parser openai_gptoss`) populated `choices[0].message.reasoning` in the JSON response. In `promptfoo 0.121.11` (`dist/src/chat-PfM8xgFA.js` lines 672-685), `if (message.reasoning)` takes precedence over `else if (... && message.tool_calls)` and sets `output = message.content` (`null` on tool-call turns), dropping `message.tool_calls` unless `"include_reasoning": false` is passed in the request body. Setting `showThinking: false` and `passthrough: {include_reasoning: false, reasoning_effort: low}` in `promptfoo_provider.config` instructs vLLM to return `reasoning: null` at low reasoning effort, preserving `message.tool_calls` and clean text output.

**Retry accounting and `reasoning_effort: low` caveat (`W5`)**:
- `sanity` Run 2 (`runs/2026-10-31-210509-sanity-tinfoil-gpt-oss-120b-0f58d616-mn7fj3`) consumed `sanity`'s 1 allowed retry under the `40`chat-request / `1` retry-per-suite trial budget (`plans/tinfoil-attestation-trial.md` Section 5).
- `v1` (`8/10`) and `tools` (`3/4`) were each run once (`0` retries consumed) with `passthrough: {include_reasoning: false, reasoning_effort: low}`. Because `reasoning_effort: low` reduces chain-of-thought budget alongside `include_reasoning: false`, `v1` and `tools` each retain 1 unused retry that can be run with `passthrough: {include_reasoning: false}` at default/`medium` reasoning effort if the operator wants to test whether higher reasoning effort clears the remaining two `v1` cells.

### 4.2 Suite Results Summary

| Suite / Gate | Run Directory | Result | Latency / TTFT | Token Usage (Prompt / Completion / Total) | Session Token Leaks (`matches_found`) |
|---|---|---|---|---|---|
| `opencode-smoke` (`v2.0.32`) | `runs/2026-10-31-205800-opencode-smoke-tinfoil-gpt-oss-120b-0f58d616-p45y_7pp` | **PASS** (`1/1`, `read` tool called on `target.txt`, exact token verified, `0` non-localhost sockets) | `1.5413s` total (`2` LLM steps, `3` HTTP requests) | `2,117` / `131` / `2,248` | `0` (`139` files scanned) |
| `sanity` (Run 1, default reasoning) | `runs/2026-10-31-205809-sanity-tinfoil-gpt-oss-120b-0f58d616-CtpYud` | **PASS** (`1/1`) | `0.543s` suite / `0.6404s` probe | `156` / `140` / `296` | `0` |
| `sanity` (Run 2 / retry #1, `include_reasoning=false`, `reasoning_effort=low`) | `runs/2026-10-31-210509-sanity-tinfoil-gpt-oss-120b-0f58d616-mn7fj3` | **PASS** (`1/1`) | `0.556s` suite / text TTFT `0.3628s` (`0.5284s` total) | `156` / `90` / `246` | `0` |
| `v1` (Run 1, `include_reasoning=false`, `reasoning_effort=low`) | `runs/2026-10-31-210518-v1-tinfoil-gpt-oss-120b-0f58d616-RMnqCX` | **8/10** (`80%`, `0` errors) | `43s` suite / text TTFT `0.5395s` | `24,040` / `3,443` / `27,483` | `0` (`46` files scanned) |
| `tools` (Run 1, `include_reasoning=false`, `reasoning_effort=low`) | `runs/2026-10-31-210614-tools-tinfoil-gpt-oss-120b-0f58d616-yaXq8R` | **3/4** (`75%`, `0` errors) | `4s` suite / text TTFT `0.4004s`, tool TTFT `0.4404s` (`tool_call_chunks: 11`) | `1,202` / `307` / `1,509` | `0` (`49` files scanned) |

Total trial spend across all runs and timing probes: `28,139` input tokens (`$0.00422`) + `4,308` output tokens (`$0.00258`) = **`$0.0068` (`0.68 cents`)**.

### 4.3 Analysis of `v1` (`8/10`) and `tools` (`3/4`) Failures

1. **`v1` cell 2 (`bug-fix-python-batching`)**: `gpt-oss-120b` identified the exact bug and wrote a valid Python generator fix (`if current:\n        yield list(current)`), which missed the brittle substring assertion `output.includes('if current:') && (output.includes('append(current)') || output.includes('yield current'))` only because it wrapped `current` in `list(current)`.
2. **`v1` cell 9 (`patch-like-edit-gitignore`)**: Omitted the `diff --git a/.gitignore b/.gitignore` git header before `--- a/.gitignore` (same failure mode observed on Rung 1 `gemma-4-26b-a4b-it-optiq-mlx-4bit` and `qwen3-coder-30b-a3b-mlx-4bit`).
3. **`tools` cell 2 (`parallel-tool-calls-diff-check`)**: Emitted 1 tool call (`read_file` on `scripts/serve-model`) instead of 2 parallel tool calls in a single turn. OpenAI's Harmony format (`<|channel|>commentary to=functions.read_file ... <|call|>`) uses `<|call|>` (`200012`) as a stop token, so the model naturally emits sequential single tool calls across turns (as verified in `opencode-smoke`, which passed in `1.54s`) rather than multiple parallel tool calls in one assistant turn.

---

## 5. Phase 2 Capability and Security Evaluation (`tinfoil-deepseek-v4-1-flash`)

Following the `tinfoil-gpt-oss-120b` run, the operator requested evaluating `tinfoil-deepseek-v4-1-flash` (`DeepSeek V4.1 Flash`, `$0.65 / 1M` input (`$0.13` cached) and `$1.45 / 1M` output) through the same `tinfoil-proxy v0.2.9` + `se-key-proxy` pipeline in strict sequential order (`sanity` -> `v1` -> `tools` -> `opencode-smoke`).

### 5.1 Phase 1 Proxy Confirmation and vLLM `--tokenizer-mode deepseek_v41` Non-Thinking Configuration

- **Phase 1 proxy and `/v1/models` confirmation**:
  - `tinfoil-proxy v0.2.9` initialized and verified the router enclave (`runs/serve.log` at `2026-10-31T21:30:57-04:00`: `initializing secure client enclave_host=inference.tinfoil.sh repo=tinfoilsh/confidential-model-router`, listening on `127.0.0.1:9081`) and `se-key-proxy` verified the upstream listener via `libproc` PCB inspection before binding `127.0.0.1:8081` with `--allowed-model deepseek-v4-1-flash`.
  - `./scripts/verify-served-model tinfoil-deepseek-v4-1-flash --wait 30` queried `GET http://127.0.0.1:8081/v1/models` through `se-key-proxy` -> `tinfoil-proxy` (`200 OK` in `runs/serve.log` at `21:31:11`, `21:34:04`, `21:34:33`, `21:34:59`, `21:35:15`) and recorded `deepseek-v4-1-flash` in each run's `served-model.txt`.
  - Backend enclave repo and tag from router verification state (`/.well-known/tinfoil-proxy` and `tinfoilsh/confidential-model-router@v0.0.168` `config.yml`, Section 3.2): `tinfoilsh/confidential-deepseek-v4-1-flash` `v0.0.10+b200` / `v0.0.10+b300` (`provider_manifest_weights_source`: `deepseek-ai/DeepSeek-V4.1-Flash-1017@1bae0e1088993b9b82de08f59de5be5a34e42170`, `provider_manifest_weights_hash`: `dmverity:sha256:6c4a2b637f7f45d9e48d1bdc38c12e0454584f48d3759851f7ee4471cd90b2e7`).
- **vLLM non-thinking configuration and retry accounting**:
  - On `sanity` Run 1 (`runs/2026-10-31-213111-sanity-tinfoil-deepseek-v4-1-flash-b41fc330-UrDQRn`), `chat_template_kwargs: {thinking_mode: "chat"}` did not disable `<think>` generation in vLLM's `deepseek_v41` tokenizer integration, causing the `60`-token `sanity.yaml` cap to be consumed by `60` reasoning tokens (`finishReason: "length"`).
  - Setting `passthrough: {include_reasoning: false, chat_template_kwargs: {thinking: false}}` (and forwarding `chat_template_kwargs` in `scripts/timing`) sets `reasoning_tokens: 0` on vLLM `deepseek_v41`.
  - With `chat_template_kwargs.thinking: false`, `sanity` Run 2 (consuming `sanity`'s `1` allowed retry) passed `1/1`, `v1` scored **`9/10`** (`90%`, `0` retries used) in `14s`, `tools` scored **`4/4`** (`100%`, `0` retries used, including `parallel-tool-calls-diff-check`) in `4s`, and `opencode-smoke` passed in `2.2122s`. `v1` and `tools` each retain `1` unused retry if the operator chooses to test with thinking enabled (`include_reasoning: false` without `thinking: false`).

### 5.2 Suite Results Summary (`tinfoil-deepseek-v4-1-flash`)

| Suite / Gate | Run Directory | Result | Latency / TTFT | Token Usage (Prompt / Completion / Total) | Session Token Leaks (`matches_found`) |
|---|---|---|---|---|---|
| `sanity` (Run 1, `thinking_mode=chat`) | `runs/2026-10-31-213111-sanity-tinfoil-deepseek-v4-1-flash-b41fc330-UrDQRn` | `0/1` (`60` reasoning tokens hit `max_tokens=60`) | `0.941s` suite / `1.51s` probe | `82` / `140` / `222` | `0` (`52` files scanned) |
| `sanity` (Run 2 / retry #1, `thinking=false`) | `runs/2026-10-31-213403-sanity-tinfoil-deepseek-v4-1-flash-b41fc330-iXVep2` | **PASS** (`1/1`) | `1s` suite / text TTFT `0.4957s` | `56` / `99` / `155` (`15` / `26` / `41` suite) | `0` (`52` files scanned) |
| `v1` (Run 1, `thinking=false`) | `runs/2026-10-31-213433-v1-tinfoil-deepseek-v4-1-flash-b41fc330-HlnCge` | **9/10** (`90%`, `0` errors) | `14s` suite / text TTFT `0.2750s` (`0.3616s` total) | `23,635` / `2,848` / `26,483` | `0` (`54` files scanned) |
| `tools` (Run 1, `thinking=false`) | `runs/2026-10-31-213459-tools-tinfoil-deepseek-v4-1-flash-b41fc330-0QR0vt` | **4/4** (`100%`, `0` errors) | `4s` suite / text TTFT `0.5970s`, tool TTFT `0.4989s` (`tool_call_chunks: 4`) | `2,229` / `350` / `2,579` | `0` (`57` files scanned) |
| `opencode-smoke` (`v2.0.32`) | `runs/2026-10-31-213515-opencode-smoke-tinfoil-deepseek-v4-1-flash-b41fc330-vf7313bc` | **PASS** (`1/1`, `read` tool called on `target.txt`, exact token verified, `0` non-localhost sockets) | `2.2122s` total (`1` LLM step, `3` HTTP requests) | `2,542` / `202` / `2,744` | `0` (`155` files scanned) |

Total `tinfoil-deepseek-v4-1-flash` spend across all runs and timing probes: ~`28,600` input tokens (`$0.0186`) + ~`3,650` output tokens (`$0.0053`) = **`$0.0239` (`2.4 cents`)**.

### 5.3 Analysis of `tinfoil-deepseek-v4-1-flash` Results

- **`tools` (`4/4`, `100%`) and `opencode-smoke` (`PASS` in `2.2122s`)**: Unlike `gpt-oss-120b` (`3/4`), `deepseek-v4-1-flash`'s DSML tool parser (`--tool-call-parser deepseek_v41`) natively emits multiple `<｜DSML｜ invoke>` blocks inside a single `<｜DSML｜ calls>` turn and passed `parallel-tool-calls-diff-check` along with all other tool-calling and `opencode` agent gates.
- **`v1` (`9/10`, `90%`) and operator admission (`2026-11-01`)**: Passed 9 of 10 automated cells in `14s` (including `bug-fix-python-batching`), missing only `patch-like-edit-gitignore` because the prompt asks for a "unified diff" and `deepseek-v4-1-flash` emitted a valid POSIX unified diff (`--- a/.gitignore\n+++ b/.gitignore...`) without a `diff --git a/.gitignore b/.gitignore` header (the same assertion missed by Rung 1 `gemma-4-26b-a4b-it-optiq-mlx-4bit`). On 2026-11-01, after full-day production use in `opencode-attested`, the operator approved promoting `tinfoil-deepseek-v4-1-flash` to `status: active` and `routing.private_attested: cleared` in `models.yaml`.

---

## 6. Phase 2 Capability and Security Evaluation (`tinfoil-glm-5-3`)

Following `tinfoil-deepseek-v4-1-flash`, the operator requested evaluating `tinfoil-glm-5-3` (`GLM 5.3 NVFP4`, `$1.80 / 1M` input (`$0.45` cached) and `$5.75 / 1M` output) through `tinfoil-proxy v0.2.9` + `se-key-proxy` in strict sequential order (`sanity` -> `v1` -> `tools` -> `opencode-smoke`).

### 6.1 Phase 1 Proxy Confirmation and Suite Results Summary (`tinfoil-glm-5-3`)

- **Phase 1 proxy and `/v1/models` confirmation**:
  - `tinfoil-proxy v0.2.9` initialized and verified the router enclave (`runs/serve.log` at `2026-10-31T21:44:10-04:00`: `initializing secure client enclave_host=inference.tinfoil.sh repo=tinfoilsh/confidential-model-router`, listening on `127.0.0.1:9081`) and `se-key-proxy` verified the upstream listener via `libproc` PCB inspection before binding `127.0.0.1:8081` with `--allowed-model glm-5-3`.
  - `./scripts/verify-served-model tinfoil-glm-5-3 --wait 30` queried `GET http://127.0.0.1:8081/v1/models` through `se-key-proxy` -> `tinfoil-proxy` (`200 OK` in `runs/serve.log` at `21:44:44`, `21:44:56`, `21:45:28`, `21:45:53`) and recorded `glm-5-3` in each run's `served-model.txt`.
  - Backend enclave repo and tag from router verification state (`/.well-known/tinfoil-proxy` and `tinfoilsh/confidential-model-router@v0.0.168` `config.yml`, Section 3.2): `tinfoilsh/confidential-glm5-3-nvfp4` `v0.0.10` (`provider_manifest_weights_source`: `Inferact/GLM-5.3-NVFP4@ce67b36f3669192b5bb233819f0fda6c8a9837f8`, `provider_manifest_weights_hash`: `dmverity:sha256:50f49b63a8139cf970d93e81978c7c21ab42e96b84e80c123f496ae33cb768a8`).
- **vLLM reasoning configuration and retry accounting**:
  - Configured with `passthrough: {include_reasoning: false, reasoning_effort: low, chat_template_kwargs: {reasoning_effort: low}}` (`0` retries used across `sanity`, `v1`, and `tools`; note that setting `enable_thinking: false` on vLLM `--reasoning-parser glm45` causes thinking text to leak into `message.content`, whereas `reasoning_effort: low` produces `0` reasoning tokens cleanly). `v1` and `tools` each retain `1` unused retry if the operator chooses to test at higher reasoning effort:

| Suite / Gate | Run Directory | Result | Latency / TTFT | Token Usage (Prompt / Completion / Total) | Session Token Leaks (`matches_found`) |
|---|---|---|---|---|---|
| `sanity` | `runs/2026-10-31-214444-sanity-tinfoil-glm-5-3-6b0b2ccc-JCgzau` | **PASS** (`1/1`) | `0s` suite / text TTFT `0.2813s` (`0.3851s` total) | `46` / `44` / `90` (`23` / `22` / `45` suite) | `0` (`58` files scanned) |
| `v1` | `runs/2026-10-31-214455-v1-tinfoil-glm-5-3-6b0b2ccc-fQ0wwz` | **8/10** (`80%`, `0` errors) | `23s` suite / text TTFT `0.3519s` | `23,628` / `2,737` / `26,365` | `0` (`60` files scanned) |
| `tools` | `runs/2026-10-31-214528-tools-tinfoil-glm-5-3-6b0b2ccc-tFkinn` | **4/4** (`100%`, `0` errors) | `14s` suite / text TTFT `0.2864s`, tool TTFT `0.2805s` (`tool_call_chunks: 2`) | `1,634` / `223` / `1,857` | `0` (`61` files scanned) |
| `opencode-smoke` (`v2.0.32`) | `runs/2026-10-31-214553-opencode-smoke-tinfoil-glm-5-3-6b0b2ccc-tdpkgjl1` | **PASS** (`1/1`, `read` tool called on `target.txt`, exact token verified, `0` non-localhost sockets) | `1.4393s` total (`1` LLM step, `3` HTTP requests) | `1,636` / `49` / `1,685` | `0` (`159` files scanned) |

Total `tinfoil-glm-5-3` spend across all runs and timing probes: ~`26,980` input tokens (`$0.0486`) + ~`3,100` output tokens (`$0.0178`) = **`$0.0664` (`6.6 cents`)**.

### 6.2 Analysis of `tinfoil-glm-5-3` Results

- **`tools` (`4/4`, `100%`) and `opencode-smoke` (`PASS` in `1.4393s`)**: Passed all 4 tool cells (including `parallel-tool-calls-diff-check` via `--tool-call-parser glm47`) with `0.2805s` incremental streaming tool-call TTFT and completed `opencode-smoke` in `1.4393s` (`1` LLM step).
- **`v1` (`8/10`, `80%`)**: Both assertion misses on `v1` were false-negative regex/substring checks on valid answers:
  1. `shell-tool-reasoning-safe-commands`: `glm-5-3` listed only safe read-only commands (`df -h`, `du -sh`, `cat runs/.serve.pid`, `ps -p`, `curl ... /v1/models`, `lsof`, `git status`, `git diff`, `git stash list`) and added a safety note stating `No destructive commands included: no rm, git checkout --, git reset, kill, git clean, or git stash drop`, which tripped the negative regex `!/rm\s+-rf|reset\s+--hard|checkout\s+--/i.test(output)` on `checkout --`.
  2. `patch-like-edit-gitignore`: emitted a POSIX unified diff (`--- a/.gitignore\n+++ b/.gitignore...`) without a `diff --git` header.

---

## 7. Phase 2 Capability and Security Evaluation (`tinfoil-kimi-k3`)

Following `tinfoil-glm-5-3`, the operator requested evaluating `tinfoil-kimi-k3` (`Kimi K3`, `$4.00 / 1M` input (`$0.80` cached) and `$20.00 / 1M` output) through `tinfoil-proxy v0.2.9` + `se-key-proxy` in strict sequential order (`sanity` -> `v1` -> `tools` -> `opencode-smoke`).

### 7.1 Phase 1 Proxy Confirmation and Suite Results Summary (`tinfoil-kimi-k3`)

- **Phase 1 proxy and `/v1/models` confirmation**:
  - `tinfoil-proxy v0.2.9` initialized and verified the router enclave (`runs/serve.log` at `2026-10-31T21:50:38-04:00`: `initializing secure client enclave_host=inference.tinfoil.sh repo=tinfoilsh/confidential-model-router`, listening on `127.0.0.1:9081`) and `se-key-proxy` verified the upstream listener via `libproc` PCB inspection before binding `127.0.0.1:8081` with `--allowed-model kimi-k3`.
  - `./scripts/verify-served-model tinfoil-kimi-k3 --wait 30` queried `GET http://127.0.0.1:8081/v1/models` through `se-key-proxy` -> `tinfoil-proxy` (`200 OK` in `runs/serve.log` at `21:50:51`, `21:51:03`, `21:52:08`, `21:53:02`) and recorded `kimi-k3` in each run's `served-model.txt`.
  - Backend enclave repo and tag from router verification state (`/.well-known/tinfoil-proxy` and `tinfoilsh/confidential-model-router@v0.0.168` `config.yml`, Section 3.2): `tinfoilsh/confidential-kimi-k3` `v0.0.6` (`provider_manifest_weights_source`: `moonshotai/Kimi-K3@a590ce090cb049c93a33dfe8c208ec652aa20503`, `provider_manifest_weights_hash`: `dmverity:sha256:58d5e74ba6c814d4cc4511df093ede786bfbc95f766eee7a96379687ce455792`).
- **vLLM non-thinking configuration and retry accounting**:
  - Configured with `passthrough: {include_reasoning: false, chat_template_kwargs: {thinking: false}}` (`0` retries used across `sanity`, `v1`, and `tools`; in `encoding_k3.py`, `thinking: false` opens `<|open|>response` directly rather than `<|open|>think`, resulting in `0` reasoning tokens). `v1` and `tools` each retain `1` unused retry if the operator chooses to test with thinking enabled:

| Suite / Gate | Run Directory | Result | Latency / TTFT | Token Usage (Prompt / Completion / Total) | Session Token Leaks (`matches_found`) |
|---|---|---|---|---|---|
| `sanity` | `runs/2026-10-31-215051-sanity-tinfoil-kimi-k3-65612a00-4kshda` | **PASS** (`1/1`) | `1s` suite / text TTFT `0.3661s` (`0.8918s` total) | `64` / `57` / `121` (`32` / `28` / `60` suite) | `0` (`60` files scanned) |
| `v1` | `runs/2026-10-31-215102-v1-tinfoil-kimi-k3-65612a00-D92nzB` | **9/10** (`90%`, `0` errors) | `35s` suite / text TTFT `0.3388s` (`0.7206s` total) | `23,274` / `2,535` / `25,809` | `0` (`60` files scanned) |
| `tools` | `runs/2026-10-31-215208-tools-tinfoil-kimi-k3-65612a00-jnpGS4` | **4/4** (`100%`, `0` errors) | `5s` suite / text TTFT `0.4203s`, tool TTFT `0.9319s` (`tool_call_chunks: 1`) | `1,352` / `297` / `1,649` | `0` (`61` files scanned) |
| `opencode-smoke` (`v2.0.32`) | `runs/2026-10-31-215302-opencode-smoke-tinfoil-kimi-k3-65612a00-x86emkai` | **PASS** (`1/1`, `read` tool called on `target.txt`, exact token verified, `0` non-localhost sockets) | `2.9050s` total (`2` LLM steps, `3` HTTP requests) | `1,691` / `133` / `1,824` | `0` (`159` files scanned) |

Total `tinfoil-kimi-k3` spend across all runs and timing probes: `26,381` input tokens (`$0.1055`) + `3,022` output tokens (`$0.0604`) = **`$0.1659` (`16.6 cents`)**.

### 7.2 Analysis of `tinfoil-kimi-k3` Results

- **`tools` (`4/4`, `100%`) and `opencode-smoke` (`PASS` in `2.9050s`)**: Passed all 4 tool cells (including `parallel-tool-calls-diff-check` via `--tool-call-parser kimi_k3`) in `5s` and completed `opencode-smoke` in `2.9050s`.
- **`v1` (`9/10`, `90%`)**: Passed 9 of 10 automated cells (including `bug-fix-python-batching` and `shell-tool-reasoning-safe-commands`), missing only `patch-like-edit-gitignore` because it emitted a POSIX unified diff (`--- a/.gitignore\n+++ b/.gitignore...`) without a `diff --git` header.

---

## 8. Phase 2 Capability and Security Evaluation (`tinfoil-kimi-k3-1-pro`, 2026-11-07)

On `2026-11-07`, `./scripts/sync-model-catalog` queried Tinfoil's live router verification state (`https://inference.tinfoil.sh/.well-known/tinfoil-proxy`), OpenAI `/v1/models` catalog (`https://inference.tinfoil.sh/v1/models`), and per-enclave release manifests (`tinfoil-config.yml`):
- Detected `kimi-k3` deprecation (`deprecated: true`, `deprecationDate: "2026-11-12"`, tag `v0.0.6 -> v0.0.16`), `deepseek-v4-1-flash` input price reduction (`$0.65 -> $0.60/1M`, cached `$0.13 -> $0.01/1M`), `gpt-oss-120b` enclave tag update (`v0.0.28 -> v0.0.29`), and the new `kimi-k3-1-pro` coding model (`Kimi K3.1 Pro`, `$4.00/1M` input, `$0.40/1M` cached input, `$20.00/1M` output).
- Enclave provenance for `kimi-k3-1-pro`: `tinfoilsh/confidential-kimi-k3-1-pro` `v0.0.3` (`3/3` healthy enclaves, `snp-tdx-multiplatform/v1`), `provider_manifest_weights_source`: `moonshotai/Kimi-K3.1-Pro@6d0a0202956796543364d666ab19c6ad1a494ee1`, `provider_manifest_weights_hash`: `dmverity:sha256:8d9c355a94e60f43598713759028328bbe795336f2700799d0ff4f3898e785e0` (`1561.4 GB`).

### 8.1 Bounded Session Launch and Suite Results Summary (`tinfoil-kimi-k3-1-pro`)

Served on `127.0.0.1:8082` (`tinfoil-proxy` on `127.0.0.1:9082`) with `--max-chat-requests 40 --max-tokens-cap 700 --max-request-bytes 65536 --ttl-seconds 1800 --stream-timeout-seconds 300` and pre-step `check_pre_step_budget` verification under the `$1.00 USD` soft budget ceiling (`chat_template_kwargs.thinking: false`, `include_reasoning: false`, `0` retries used across all suites):

| Suite / Gate | Run Directory | Result | Latency / TTFT | Token Usage (Prompt / Completion / Total) | Actual Step Spend (`$4/M` in, `$20/M` out) | Session Token Leaks (`matches_found`) |
|---|---|---|---|---|---|---|
| `sanity` | `runs/2026-11-07-052113-sanity-tinfoil-kimi-k3-1-pro-549f5f54-MOpRpj` | **PASS** (`1/1`) | `1s` suite / text TTFT `0.3096s` (`0.6506s` total) | `64` / `91` / `155` (`32` / `48` / `80` suite) | `$0.002076` | `0` (`60` files scanned) |
| `v1` | `runs/2026-11-07-052129-v1-tinfoil-kimi-k3-1-pro-549f5f54-Os9S4D` | **9/10** (`90%`, `0` errors) | `31s` suite / text TTFT `0.2933s` (`0.5448s` total) | `23,274` / `2,370` / `25,644` | `$0.140496` | `0` (`60` files scanned) |
| `tools` | `runs/2026-11-07-052218-tools-tinfoil-kimi-k3-1-pro-549f5f54-iNm1IJ` | **4/4** (`100%`, `0` errors) | `3s` suite / text TTFT `0.2955s`, buffered tool TTFT `0.5529s` (`tool_call_chunks: 1`) | `1,352` / `328` / `1,680` | `$0.011968` | `0` (`61` files scanned) |
| `opencode-smoke` (`v2.0.32`) | `runs/2026-11-07-052238-opencode-smoke-tinfoil-kimi-k3-1-pro-549f5f54-9quqmsay` | **PASS** (`1/1`, `read` tool called on `target.txt`, exact token verified, `0` non-localhost sockets) | `2.5669s` total (`2` LLM steps, `3` HTTP requests) | `1,748` / `155` / `1,903` | `$0.010092` | `0` (`348` files scanned) |

Total `tinfoil-kimi-k3-1-pro` spend across all `22` requests: `26,438` input tokens (`$0.1058`) + `2,944` output tokens (`$0.0589`) = **`$0.1646` (`16.5 cents`)**.

### 8.2 Analysis of `tinfoil-kimi-k3-1-pro` Results

- **`tools` (`4/4`, `100%`) and `opencode-smoke` (`PASS` in `2.5669s`)**: Improved latency over `tinfoil-kimi-k3` across every metric (`tools` suite `3s` vs `5s`, tool-call TTFT `0.5529s` vs `0.9319s`, `v1` suite `31s` vs `35s`, and `opencode-smoke` `2.5669s` vs `2.9050s`).
- **`v1` (`9/10`, `90%`)**: Passed 9 of 10 automated cells on the first attempt (`0` retries used), missing only `patch-like-edit-gitignore` because it emitted a valid POSIX unified diff (`--- /dev/null\n+++ b/.gitignore`) without a `diff --git` header line. Kept at `status: candidate` and `routing.private_attested: blocked` unless promoted by the operator.

---

## Addendum (2026-11-02): Public Repository Path Mapping

This trial record was captured in the internal workspace prior to standalone public export:
- References to `proposal.md` correspond to `docs/proposal.md` in this repository.
- References to `plans/tinfoil-attestation-trial.md` (`T4`, `T6`, `T7`, Section 5) refer to the pre-export trial protocol; the resulting architectural invariants and committed evaluation manifests live in `docs/proposal.md` and `docs/evals/tinfoil-deepseek-v4-1-flash.json`.
- Host-specific paths in historical command outputs were replaced with `<repo-root>` during public export sanitization.
