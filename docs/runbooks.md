# Operator Runbooks

Copy-paste recipes for everyday coding sessions, running multiple models side-by-side, recovering interrupted sessions, and controlling spend, reasoning tokens, and subagents.

All commands below assume `/path/to/free-inference` is your local checkout root (replace with your checkout path).

---

## 1. Daily Interactive Coding from Any Project Directory

Always launch `opencode-attested` or `opencode-local` **from inside the target repository** you want the coding agent to inspect or edit (`cd /path/to/your/project`), never from `$HOME` (`~`). OpenCode's file tools and `LOCAL_ASSIST_WORKSPACE_ROOT` inherit the working directory where the launcher is invoked.

### Rung 3: Attested Enclave Cleared Models (`tinfoil-deepseek-v4-1-flash` default, `privatemode-glm-5-3-flash` DE/EU)

```bash
cd /path/to/your/project

# Starts a 2-hour interactive proxy session on the configured catalog default
# (tinfoil-deepseek-v4-1-flash via routing.default_private_attested: true in models.yaml;
# override per shell with FREE_INFERENCE_DEFAULT_ATTESTED_MODEL=<cleared-model-id> or --model <id>).
# Prompts Touch ID once if the proxy is not already running.
/path/to/free-inference/scripts/opencode-attested

# Launch cleared DE/EU Privatemode GLM 5.3 Flash (127.0.0.1:8082 -> 127.0.0.1:9082, no --allow-uncleared-model needed)
/path/to/free-inference/scripts/opencode-attested --model privatemode-glm-5-3-flash
```

### Rung 3: Frontier Enclave Candidate (`tinfoil-kimi-k3-1-pro`)

```bash
cd /path/to/your/project

# Launch Kimi K2.5 (tinfoil-kimi-k3-1-pro). If tinfoil-deepseek-v4-1-flash is already
# serving on port 8081, opencode-attested automatically allocates the next free port pair
# (127.0.0.1:8082 -> 127.0.0.1:9082) so both models stay live side-by-side.
/path/to/free-inference/scripts/opencode-attested \
  --model tinfoil-kimi-k3-1-pro \
  --allow-uncleared-model
```

### Rung 1: Local Offline MLX (`qwen3-30b-a3b-2507-mlx-4bit`)

```bash
cd /path/to/your/project

# Runs locally on 127.0.0.1:8080 with HF_HUB_OFFLINE=1 (0 bytes leave your Mac).
/path/to/free-inference/scripts/opencode-local
```

> **Git commits inside OpenCode**: Because `HOME` is isolated by default (`.home/opencode-*`), pass `--preserve-host-home` if approved `git commit` commands inside the session need to read `~/.gitconfig`.

---

## 2. Running a Second Model Side-by-Side (Parallel Sessions)

### Explicit authorization windows

Run these commands in an operator terminal, outside the coding agent:

```bash
/path/to/free-inference/scripts/session start --model tinfoil-deepseek-v4-1-flash --for 2h
/path/to/free-inference/scripts/session status --model tinfoil-deepseek-v4-1-flash
/path/to/free-inference/scripts/session watch --model tinfoil-deepseek-v4-1-flash --notify
# In another terminal before expiry, authorize a replacement window with Touch ID:
/path/to/free-inference/scripts/session renew --model tinfoil-deepseek-v4-1-flash --for 12h
/path/to/free-inference/scripts/session stop --model tinfoil-deepseek-v4-1-flash
```

Start defaults to 2 hours. An already ON session is reported unchanged; use renew to change its window. Windows accept positive integer seconds, minutes, or hours, up to 24 hours. Renew measures the new window from successful authorization, rotates the proxy credential, preserves the process/listener, and does not refill requests or raise spend caps. Attached interactive relays follow the new window. Workers follow credential rotation while keeping their own time/request limits.

A session permits at most 32 authorization generations (the initial start plus 31 renewals). After that, explicitly stop/start to authorize a new session. This bounds retired-credential history. Relays cache credentials with a sleep-aware deadline and kernel process-lifetime observation. They refresh through identity-checked control on stale-token refusal or cached expiry, without authorizing a new window. They recheck lifetime after TCP connect before sending credentials or prompts. The key holder remains the authority for live expiry and request admission. Explicit handoff credentials are never replaced by a disk-backed lease.

Control sockets remain under the protected runs directory. Long checkout paths use directory-relative Unix socket addresses: the key holder binds before accepting traffic, and the trusted client uses a short-lived helper rather than changing a multithreaded launcher's working directory. Stop removes an owned inactive socket left after SIGKILL, but refuses to unlink a listener or an unverifiable node.

Containment accepts legacy token files and complete JSON envelopes, and recognizes encoded exposure. It attributes known current tokens across sessions before treating unknown retired exposure as ambiguous. When an exposed token predates the current envelope, automatic attribution can still be uncertain; containment preserves forensic state and requires explicit attribution or stopping ambiguous sessions rather than replaying credentials to an unverified listener.

Status reports ON, OFF, or UNKNOWN with authoritative time and shared requests remaining; UNKNOWN never triggers automatic replacement. With multiple active sessions, specify `--model`. `--json` produces sanitized status for scripts. The foreground watcher warns once per authorization at five minutes remaining and at the smaller of ten requests or ten percent remaining (minimum one). Notifications need `--notify`; there is no background auto-renewal.

Stop and hard expiry cancel active streams and remove the in-memory authorization and proxy credential file. The sealed provider key remains available for a later start. An expired or exhausted session cannot be renewed. Older helpers lack the control socket and show UNKNOWN; explicitly stop and restart them with the new helper. `--refresh-session` still restarts a proxy, resets its budgets, and can interrupt other attached clients; reserve it for cap changes or recovery.

Complete Touch ID before the current window expires. Hard expiry also terminates a pending renewal prompt; starting renewal does not grant a grace period. The watcher warns five minutes ahead so there is time to authorize the replacement window.

You do **not** need to stop your default model to try or run a second model in another terminal tab or project directory.

### Automatic side-by-side port allocation (recommended)

When you run `opencode-attested --model <second-model>` while another model already owns port `8081`, `opencode-attested` checks `runs/.serve*.pid`:
1. If port `8081` is owned by a live PID record for a different model, `opencode-attested` automatically selects the next free localhost port pair (`8082`/`9082`, `8083`/`9083`, ...) and starts the second model's proxy there.
2. Each OpenCode invocation creates its own `0700` per-invocation runtime directory (`.home/opencode-private-attested/.invocations/<inv_id>/`) with a dedicated `0400` `opencode.json`, dedicated per-invocation `service.json` port and password, parent-process `SessionAuthRelay` (`oc-relay-*`), and Seatbelt sandbox (`interactive.sb`), while sharing `.local/share/opencode/opencode.db` for conversation history (`--continue`). Neither terminal overwrites the other's model routing or session credentials.

```bash
# Terminal 1 (in project A): serves tinfoil-deepseek-v4-1-flash on 127.0.0.1:8081
cd /path/to/project-a
/path/to/free-inference/scripts/opencode-attested

# Terminal 2 (in project B): automatically serves tinfoil-kimi-k3-1-pro on 127.0.0.1:8082
cd /path/to/project-b
/path/to/free-inference/scripts/opencode-attested \
  --model tinfoil-kimi-k3-1-pro \
  --allow-uncleared-model
```

### Explicit port selection (`--port`)

If you prefer to pin a specific localhost port yourself:

```bash
cd /path/to/project-b
/path/to/free-inference/scripts/opencode-attested \
  --model tinfoil-kimi-k3-1-pro \
  --allow-uncleared-model \
  --port 8082
```

Or if starting the proxy directly with `serve-model` for interactive use:

```bash
cd /path/to/free-inference
./scripts/serve-model tinfoil-kimi-k3-1-pro --port 8082 --interactive
```

---

## 3. Continuing or Recovering an Interrupted Session

If an interactive session hits a request cap, output token cap, or authorization expiry (for example `Session chat request cap (50) reached` or `Compaction summary reached the output token limit`), your conversation history is still saved in OpenCode's local SQLite database (`.home/opencode-private-attested/.local/share/opencode/opencode.db`).

Recover and continue the exact conversation in one command:

```bash
cd /path/to/your/project

# --refresh-session restarts the model's proxy with fresh interactive caps
# (1,000 requests, 16,384 output tokens, 8 MiB payload, 2h TTL; 1 Touch ID tap).
# -- -c tells OpenCode to resume the most recent conversation in this directory.
/path/to/free-inference/scripts/opencode-attested \
  --model tinfoil-kimi-k3-1-pro \
  --allow-uncleared-model \
  --refresh-session \
  -- -c
```

Once the TUI opens on your previous conversation, type `continue` (or re-send your last prompt) to let the agent finish its turn.

> **Auto-upgrade when attaching to an eval-capped proxy**: If you previously started a model via `./scripts/serve-model <model>` with eval caps (`50` requests / `4,096` output tokens) and later run `./scripts/opencode-attested --model <model>` without explicit cap flags, `opencode-attested` automatically detects the low eval caps and restarts that model's proxy with interactive caps (`1,000` requests / `16,384` output tokens / `8 MiB`).

---

## 4. Spend, Reasoning Tokens (`--thinking`), and Subagents (`--allow-subagents`)

### Why default interactive sessions disable subagents and reasoning traces

1. **OpenCode subagents (`task` / `subagent` tools) are disabled by default**:
   When OpenCode's native `Explore` / `General` subagents are enabled, a single user prompt often fans out into multiple parallel subagents, each running 15-30 file-reading turns plus a compaction pass. Against frontier enclave models (`tinfoil-kimi-k3-1-pro` at `$4.00/1M` input, `$0.40/1M` cached input, and `$20.00/1M` output; or `tinfoil-deepseek-v4-1-flash` at `$0.60/1M` input, `$0.01/1M` cached input, and `$1.45/1M` output), that fan-out multiplies API spend 3x-5x and can fail mid-flight if a subagent hits a turn or compaction limit.
2. **Extended thinking (`thinking=false` / `include_reasoning=false`) is disabled by default**:
   Models in `models.yaml` configure `passthrough` defaults (`chat_template_kwargs.thinking: false`, `reasoning_effort: "none"`, `include_reasoning: false`), and `se-key-proxy` injects those defaults into every `/v1/chat/completions` request unless overridden. This prevents hidden reasoning token burn on routine file reads, edits, and tool calls.

### Opting into extended thinking (`--thinking`)

When working on a hard architecture, debugging, or security analysis problem where you want full chain-of-thought reasoning from `tinfoil-kimi-k3-1-pro` or `tinfoil-deepseek-v4-1-flash`:

```bash
cd /path/to/your/project

# Pass --thinking to enable model reasoning traces for this session.
# If the model is already serving with thinking off, opencode-attested automatically
# refreshes the proxy session with thinking enabled.
/path/to/free-inference/scripts/opencode-attested \
  --model tinfoil-kimi-k3-1-pro \
  --allow-uncleared-model \
  --thinking
```

To switch back to `thinking=off` on an active `--thinking` proxy session, run with `--refresh-session` (without `--thinking`).

### Opting into OpenCode subagents (`--allow-subagents`)

If you explicitly want OpenCode to spawn native `task`/`subagent` exploration workers (and accept the additional token/request spend):

```bash
cd /path/to/your/project

/path/to/free-inference/scripts/opencode-attested \
  --model tinfoil-kimi-k3-1-pro \
  --allow-uncleared-model \
  --allow-subagents
```

> **Note**: Passing `--allow-subagents` in an normal interactive session enables the `task` and `subagent` tools in OpenCode without activating the unattended Seatbelt worker sandbox. Use `--unattended-worker` (or `--security-profile`) only when launching a non-interactive sandboxed worker (`-- run ...`).

### Enforcing a strict dollar spend ceiling (`--max-session-usd`)

To cap worst-case session exposure on paid Rung 3 models (`ceil(max_request_bytes / 3)` worst-case uncached input tokens + `max_tokens_cap` output tokens per request across `max_chat_requests` requests; pass `--refresh-session` if replacing an already-running session that was started with larger default caps):

```bash
cd /path/to/your/project

# Example 1: $5.00 worst-case ceiling on tinfoil-kimi-k3-1-pro ($4.00/1M in, $20.00/1M out)
# 18 * (ceil(131072 / 3) * $4.00/1M + 4096 * $20.00/1M) = $4.6203 <= $5.00
/path/to/free-inference/scripts/opencode-attested \
  --model tinfoil-kimi-k3-1-pro \
  --allow-uncleared-model \
  --max-session-usd 5.00 \
  --max-chat-requests 18 \
  --max-request-bytes 131072 \
  --max-tokens-cap 4096 \
  --refresh-session

# Example 2: $5.00 worst-case ceiling on tinfoil-deepseek-v4-1-flash ($0.60/1M in, $1.45/1M out)
# 75 * (ceil(262144 / 3) * $0.60/1M + 8192 * $1.45/1M) = $4.8231 <= $5.00
/path/to/free-inference/scripts/opencode-attested \
  --model tinfoil-deepseek-v4-1-flash \
  --max-session-usd 5.00 \
  --max-chat-requests 75 \
  --max-request-bytes 262144 \
  --max-tokens-cap 8192 \
  --refresh-session
```

---

## 5. Checking Active Sessions and Stopping Models

### Inspect all running model servers and proxies (`./scripts/models --active`)

From anywhere, check which models are currently serving, which ports they occupy, whether they are in `interactive` or `eval` mode, whether `thinking` is on or off, and how much TTL remains:

```bash
cd /path/to/free-inference

# Human-readable table with copy-paste attach / refresh / stop commands
./scripts/models --active

# Machine-readable JSON output
./scripts/models --active --json

# Credential-free Rung 1 + active session status (safe for agents and scripts)
./scripts/assist-status
./scripts/assist-status --json
```

### Credential containment check and legacy-home cleanup (`./scripts/check-credential-containment`)

If an isolated OpenCode home still holds legacy uncontained `service.json` files from an earlier session, `opencode-attested` and `opencode-local` refuse to launch until containment is inspected and applied:

```bash
cd /path/to/free-inference

# Strictly read-only check (emits booleans and counts only; zero secret values or hashes)
./scripts/check-credential-containment --check

# Operator-approved containment cleanup (requires valid sanitized evidence snapshot)
./scripts/check-credential-containment --apply --operator-approved
```

Containment authority and lifecycle notes:

- `--evidence-path` must point to an operator-supplied sanitized evidence record outside the target OpenCode home and outside agent-writable Seatbelt roots. Provenance records canonicalize `source_sha256` paths (`SECURITY.md` and `tools/se_key_proxy/main.swift` are required protected baselines), strictly type-check `worktree_dirty_before_diagnosis` as a JSON boolean, and report any uncaptured pre-diagnosis modified tracked files via `dirty_unverified_sources`.
- Revocation probes never scrape or replay bearer tokens to localhost URLs found in untrusted SQLite/log/config text; authentication probes only contact ports positively owned by verified `runs/` `se-key-proxy` PID records, and any live current-UID production `se-key-proxy` process outside verified-distinct `runs/` records (regardless of its `--session-token-file` directory) fails closed without signaling or probing it.
- `--check` and `--apply` enumerate directories via explicit `os.lstat` and `os.scandir` traversal (rather than `Path.glob`/`Path.rglob`), separating metadata/directory-listing/unlink errors (`sink_inspection_ok`, `unlink_failures`) from confirmed absence or zero-match outcomes and including top-level and `.configs/opencode-*.json` config sinks (`legacy_config_files_present`, `config_matching_files`).
- Before authorized `--apply` deletes `opencode.db`, it writes a value-free, secret-free `0400` receipt (`.containment-state-<incident>-<hash>.json` next to `--evidence-path`) recording pre-cleanup SQLite event verification so subsequent `--check` runs, partial-failure retries, and later clean OpenCode sessions remain valid.

### Stop one model or all models (`./scripts/stop-model`)

```bash
cd /path/to/free-inference

# Stop a single model's proxy/server and revoke its session token immediately
./scripts/stop-model tinfoil-kimi-k3-1-pro

# Stop all active model servers and proxies
./scripts/stop-model --all
```

---

## 6. Using `local_assist` MCP from Codex CLI, Claude Code, and Antigravity (`agy`)

While `./scripts/opencode-local` and `./scripts/opencode-attested` run the primary coding planner directly on Rung 1 (`local`) or Rung 3 (`enclave_runtime_attested`) via OpenAI Chat Completions (`/v1/chat/completions`), OpenAI Codex CLI (`codex`), Claude Code (`claude`), and Google Antigravity CLI (`agy`) can delegate bounded subtasks (`assist_status`, `check_eval_assertion`, `select_context`, `extract_fields`, `compress_context`, `delegate_task`, `propose_eval_prompts`) to the local Rung 1 model (`qwen3-30b-a3b-2507-mlx-4bit` on `127.0.0.1:8080/v1` at `$0` marginal API cost) via native stdio MCP (`scripts/local-assist-server`) or CLI delegation (`scripts/delegate-local`).

See `docs/decisions/2026-11-10-codex-claude-agy-wire-discovery.md` for the wire-protocol study explaining why `codex` (`/v1/responses`), `claude` (`/v1/messages`), and `agy` integrate via MCP rather than a protocol-translation proxy.

> **Data-control boundary note**: When calling `local_assist` from a Rung 4/5 remote planner (`codex`, `claude`, `agy`), passing `context_path` to `delegate_task` reads the file directly inside the local Rung 1 tool without sending the raw file in the planner's outbound prompt, but the returned tool output enters the calling planner's session context and data-control rung.

### OpenAI Codex CLI (`codex`)

```bash
# Register local_assist (append --auto-serve to start the Rung 1 model on demand)
codex mcp add local_assist -- /path/to/free-inference/scripts/local-assist-server
codex mcp list
```

Recommended `~/.codex/config.toml` (or `$CODEX_HOME/config.toml`) settings to disable telemetry, raise `tool_timeout_sec` to `180` (above `local_assist`'s `120`s default `LOCAL_ASSIST_TIMEOUT_SECONDS` budget), and optionally pre-approve specific `local_assist` tools for non-interactive `codex exec` runs:

```toml
[analytics]
enabled = false

[feedback]
enabled = false

[mcp_servers.local_assist]
command = "/path/to/free-inference/scripts/local-assist-server"
# Optional: args = ["--auto-serve"]
tool_timeout_sec = 180

# Optional: explicit per-tool approval for unattended `codex exec -s read-only`
[mcp_servers.local_assist.tools.extract_fields]
approval_mode = "approve"

[mcp_servers.local_assist.tools.compress_context]
approval_mode = "approve"

[mcp_servers.local_assist.tools.delegate_task]
approval_mode = "approve"
```

### Claude Code (`claude`)

```bash
# Register local_assist in your project or user configuration
claude mcp add local_assist -- /path/to/free-inference/scripts/local-assist-server
claude mcp get local_assist
```

Recommended environment variables and `~/.claude/settings.json` keys to suppress nonessential background traffic:

```bash
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
export DISABLE_TELEMETRY=1
export CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL=1
```

In `~/.claude/settings.json`:

```json
{
  "skipWebFetchPreflight": true,
  "env": {
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    "DISABLE_TELEMETRY": "1",
    "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1"
  }
}
```

### Google Antigravity CLI (`agy`)

```bash
# Register local_assist globally in ~/.gemini/config/mcp_config.json
agy mcp add local_assist -- /path/to/free-inference/scripts/local-assist-server
agy mcp list
```

For workspace-only scoping in Antigravity (without editing `~/.gemini/config/mcp_config.json`), place a workspace plugin at `<workspace>/.agents/plugins/local-assist/plugin.json` (`{"name": "local-assist", "version": "0.3.1"}`) and `<workspace>/.agents/plugins/local-assist/mcp_config.json`, then validate with `agy plugin validate <workspace>/.agents/plugins/local-assist --strict`.

### Inspecting `local_assist` Telemetry (`./scripts/local-assist-stats`)

Every `local_assist` call logs self-reported `caller` (`mcp` `clientInfo` / `cli` / `LOCAL_ASSIST_CALLER` label), `startup_state` (`warm`, `auto_served`, `auto_serve_reused`, `auto_serve_failed`, `not_served`, `worker_handoff`), `readiness_ok`, `ready_ms`, `latency_ms`, `elapsed_ms`, and token counts to `runs/local-assist/<YYYY-MM-DD>.jsonl`:

```bash
cd /path/to/free-inference

# Trailing 7-day summary in America/New_York grouped by caller and tool
./scripts/local-assist-stats --days 7

# Full all-time machine-readable JSON summary (reports inclusive tokens.* plus nested error_tokens.*)
./scripts/local-assist-stats --json

# Offline fixture + behavioral-oracle validation (default when --live is omitted; 0 live model calls)
./scripts/eval-local-assist-dogfood --validate-fixtures

# Operator-approved live 3-5x Rung 1 benchmark against 127.0.0.1:8080
./scripts/eval-local-assist-dogfood --live --operator-approved --repeats 3
```

---

## 7. Unattended OpenCode Worker Runtime and Read-Only Custody (`v0.3.0`)

Supervisors such as `agent-comms` can launch sandboxed OpenCode workers directly from a read-only exported custody tree (`git archive <tag>` plus a hash-pinned `requirements-launcher.txt` target environment) without mutating any file in custody or placing session credentials in child process environments.

### Provisioning a Custody Dependency Directory (`requirements-launcher.txt`)

```bash
uv pip install \
  --target /path/to/custody/env \
  --no-compile \
  --no-deps \
  --require-hashes \
  -r /path/to/custody/launcher/requirements-launcher.txt
```

All four custody entrypoints (`scripts/opencode-attested`, `scripts/opencode-local`, `scripts/session`, and `scripts/verify-served-model`) set `sys.dont_write_bytecode = True` before importing modules and accept `--launcher-site-packages /path/to/custody/env` (or automatically discover a sibling `../env` directory when `ROOT` is read-only custody).

### Active-Runs Pointer (`~/.config/free-inference/active-runs.json`)

When the operator starts an attested session from a live checkout (`./scripts/session start` or `./scripts/serve-model`), `free-inference` writes an owner-only `0600` pointer file inside `0700` `~/.config/free-inference/active-runs.json` (`{"schema_version": 1, "runs_dir": "/abs/path/to/runs", "updated_at": <epoch>}`).

- Custody invocations (`scripts/session status --model <id> --json` and `scripts/opencode-attested`) resolve the active `runs/` store via `~/.config/free-inference/active-runs.json`, strip inherited `FREE_INFERENCE_RUNS_DIR` and runtime override environment variables, and refuse `--runs-dir`.
- Non-custody unattended worker and reap CLI invocations also strip inherited `FREE_INFERENCE_RUNS_DIR` (preventing ambient environment redirection while still honoring explicit `--runs-dir <abs-path>` in local tests).
- `worker.sb` denies both `file-read*` and `file-write*` on `~/.config/free-inference` and allocates per-worker homes under `~/.local/state/free-inference/workers` (`0700`) whenever `ROOT` is read-only custody.

### Unattended Supervisor Launch and Reap Flags

```bash
# Check active attested session readiness from custody before dispatching a worker
/path/to/custody/launcher/scripts/session \
  --launcher-site-packages /path/to/custody/env \
  status --model tinfoil-deepseek-v4-1-flash --json

# Launch an in-group Seatbelt-confined OpenCode worker attached to the live session
/path/to/custody/launcher/scripts/opencode-attested \
  --launcher-site-packages /path/to/custody/env \
  --opencode-bin /path/to/custody/opencode/bin/opencode \
  --model tinfoil-deepseek-v4-1-flash \
  --security-profile /path/to/bridge/profile.yaml \
  --inherit-process-group \
  --worker-manifest /path/to/bridge/manifest.json \
  --run-token "<run-token>" \
  --launcher-exit-file /path/to/bridge/launcher_exit.json \
  -- run "Complete the assigned task."

# Race-safe post-run / timeout reap on macOS (proc_pidinfo + 3-way sandbox_check + SSTOP verification)
/path/to/custody/launcher/scripts/opencode-attested \
  --launcher-site-packages /path/to/custody/env \
  --reap-worker /path/to/bridge/manifest.json
```

Key guarantees:
- **Early `manifest.json` publication (`R1`)**: When `--worker-manifest <abs-path>` is passed with `--inherit-process-group` and `--run-token`, both launchers publish the initial `0600` `manifest.json` (`children: []`) at entry before token handoff, CLI parsing, `--runs-dir` validation, or session readiness prechecks can exit, ensuring supervisors observe a valid recovery manifest on early `1`, `2`, or `4` exits (bounded residual: when `--worker-manifest` is invalid or unwritable, `--inherit-process-group` or `--run-token` is missing/invalid, `launcher_pgid != launcher_pid`, kernel `proc_pidinfo(os.getpid())` fails, or Python cannot import `local_assist`, the launcher fails closed without writing `manifest.json` or `launcher_exit.json`).
- **XDG `0400` `service.json` attach, reader-owned stderr drain, and strict CLI flags (`Q1`/`Q2`/`R2`/`R2-2`/`R2-3`)**: Under `--inherit-process-group`, the launcher stages `0400` `$XDG_CONFIG_HOME/opencode/service.json` (`{"hostname": "127.0.0.1", "port": <ephemeral>, "password": <secret>}`) inside the per-worker home so `opencode run` attaches over authenticated loopback HTTP without placing `--server <url>` or passwords in `argv` or process environment, drains `opencode serve --service` `stderr` continuously via a bounded `4096`-byte ring buffer (`_BoundedPipeDrain`) with exclusive reader-owned `os.dup` descriptor and self-pipe wake teardown, enforces `allow_abbrev=False` across CLI `ArgumentParser` instances so prefix abbreviations cannot bypass pre-separator scanners, and keeps both `opencode_serve` and `opencode_run` in `launcher_pgid == launcher_pid` (empirically verified on OpenCode `2.0.32`).
- **Descriptor-pinned session store propagation (`R3`/`R2-1`)**: Non-custody `session`, `opencode-attested`, and `opencode-local` validate lexical `FREE_INFERENCE_RUNS_DIR` overrides before resolution, probe absent cold-start stores read-only via `--allow-absent-runs-dir` without creating directories on `status`/`stop`/`--no-serve`, create absent stores via descriptor-relative `O_DIRECTORY | O_NOFOLLOW` traversal (`ensure_creatable_runs_dir`) only at start boundaries, pass `--runs-dir <abs-path>` paired with `_FREE_INFERENCE_PINNED_RUNS_STAT` (`<st_dev>:<st_ino>`) to `verify-served-model`, `stop-model`, and `serve-model`, and perform Python store operations through retained `dir_fd` handles (`--publish-active-runs` remains gated independently so explicit `--runs-dir` or interactive non-custody `FREE_INFERENCE_RUNS_DIR` overrides never clobber `~/.config/free-inference/active-runs.json` or stop a bystander session; unattended worker/reap CLI invocations strip ambient `FREE_INFERENCE_RUNS_DIR` up front).
- **`kinfo_proc` self-calibration and Seatbelt ancestor write-denies (`Q3`/`R4`)**: `proc_identity.py` cross-calibrates `sysctl(KERN_PROC_PID)` (`648`-byte `kinfo_proc`) against `proc_pidinfo(PROC_PIDTBSDINFO)` on `os.getpid()` before consulting `sysctl` for `SZOMB` or cross-UID `EPERM` records, and `compile_seatbelt_profile` emits intermediate ancestor `(literal "<dir>")` `file-write*` denies inside `write_roots` so standalone `manifest.json`, `launcher_exit.json`, `profile.yaml`, and local MCP executables cannot be swapped via parent-directory `rename()`.
- **Exit code `4` reservation (`EXIT_SESSION_BLOCKED`)**: Reserved strictly for `opencode_session_unavailable` and `opencode_session_caps_exhausted` (paired with an atomic `0600` `launcher_exit.json` record when `--launcher-exit-file` is passed; returns `1` if the diagnostic write fails, and normalizes child/non-session `4` to `1`).
- **Unix domain MCP bridge sockets (`network.allowed_unix_sockets` / `--allow-unix-socket`, `R6`/`R2-4`)**: Allows `AF_UNIX` `<= 103`-byte socket paths (rejecting duplicate slashes and case-insensitive, `/System/Volumes/Data` firmlink, and `(st_dev, st_ino)` `mDNSResponder` aliases) immediately after the default `(deny network-outbound)` / `(deny network-bind)` rules and before process-scoped `(remote ip ...)` rules in `worker.sb` Section 2 (preserving dedicated `local-assist-python` loopback TCP under macOS `libsandbox` while all subsequent `network-outbound` denies match remote IP ports and local MCP relays and shell children remain denied all IP/TCP/UDP outbound; combining `type: "local"` `mcp.servers` with `network.allowed_shell_localhost_ports` is rejected).
- **Attached session cap inheritance (`spend.inherit_attached_session_caps: true` / `--inherit-session-caps`)**: Inherits the attached session's live `requests_remaining`, `max_tokens_cap`, `max_request_bytes`, and remaining window seconds without enforcing interactive `$5.00` cold-start `--max-session-usd` ceilings.
