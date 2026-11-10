# Operator Runbooks

Copy-paste recipes for everyday coding sessions, running multiple models side-by-side, recovering interrupted sessions, and controlling spend, reasoning tokens, and subagents.

All commands below assume `/path/to/free-inference` is your local checkout root (replace with your checkout path).

---

## 1. Daily Interactive Coding from Any Project Directory

Always launch `opencode-attested` or `opencode-local` **from inside the target repository** you want the coding agent to inspect or edit (`cd /path/to/your/project`), never from `$HOME` (`~`). OpenCode's file tools and `LOCAL_ASSIST_WORKSPACE_ROOT` inherit the working directory where the launcher is invoked.

### Rung 3: Attested Enclave Default (`tinfoil-deepseek-v4-1-flash`)

```bash
cd /path/to/your/project

# Starts a 12-hour interactive proxy session (1,000 chat requests, 16,384 output tokens/turn,
# 8 MiB max request body, subagents disabled, reasoning tokens off by default).
# Prompts Touch ID once if the proxy is not already running.
/path/to/free-inference/scripts/opencode-attested
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

You do **not** need to stop your default model to try or run a second model in another terminal tab or project directory.

### Automatic side-by-side port allocation (recommended)

When you run `opencode-attested --model <second-model>` while another model already owns port `8081`, `opencode-attested` checks `runs/.pids/*.json`:
1. If port `8081` is owned by a live PID record for a different model, `opencode-attested` automatically selects the next free localhost port pair (`8082`/`9082`, `8083`/`9083`, ...) and starts the second model's proxy there.
2. Each OpenCode invocation writes its own immutable per-invocation config file (`.home/opencode-private-attested/.configs/opencode-<model>-<pid>-<nonce>.json`), tracks active client PIDs in `.active-opencode-clients.json`, and runs with `--standalone` whenever another OpenCode client is already active in the isolated home. Neither terminal overwrites the other's model routing or session token.

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

If an interactive session hits a request cap, output token cap, or 12-hour TTL expiry (for example `Session chat request cap (50) reached` or `Compaction summary reached the output token limit`), your conversation history is still saved in OpenCode's local SQLite database (`.home/opencode-private-attested/.local/share/opencode/opencode.db`).

Recover and continue the exact conversation in one command:

```bash
cd /path/to/your/project

# --refresh-session restarts the model's proxy with fresh interactive caps
# (1,000 requests, 16,384 output tokens, 8 MiB payload, 12h TTL; 1 Touch ID tap).
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
```

### Stop one model or all models (`./scripts/stop-model`)

```bash
cd /path/to/free-inference

# Stop a single model's proxy/server and revoke its session token immediately
./scripts/stop-model tinfoil-kimi-k3-1-pro

# Stop all active model servers and proxies
./scripts/stop-model --all
```
