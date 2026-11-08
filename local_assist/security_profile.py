from __future__ import annotations

import errno
import hmac
import http.client
import json
import math
import os
import re
import secrets
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlparse

from ._miniyaml import safe_load
from .paths import LOCAL_ASSIST_RUNS, ROOT
from .registry import (
    RegistryError,
    get_process_lstart,
    list_pid_records,
    load_model,
    pid_is_alive,
    pid_matches_record,
    resolve_endpoint,
)


SCHEMA_VERSION = 1
TESTED_OPENCODE_VERSION = "2.0.32"
WORKER_HOMES_DIR = ROOT / ".home" / "workers"
WORKER_SANDBOX_LOG_ROOT = LOCAL_ASSIST_RUNS / "worker-sandbox"
STALE_WORKER_HOME_MAX_AGE_SECONDS = 3600
MAX_HARVEST_LOG_BYTES = 10 * 1024 * 1024

KNOWN_BUILTIN_TOOLS: tuple[str, ...] = (
    "read",
    "edit",
    "write",
    "patch",
    "glob",
    "grep",
    "list",
    "shell",
    "bash",
    "webfetch",
    "websearch",
    "codesearch",
    "todowrite",
    "todoread",
    "task",
    "subagent",
    "lsp",
    "skill",
    "question",
    "external_directory",
    "doom_loop",
)

DEFAULT_ALLOWED_TOOLS: tuple[str, ...] = (
    "read",
    "edit",
    "write",
    "patch",
    "glob",
    "grep",
    "list",
    "shell",
    "todowrite",
)

DEFAULT_ENV_ALLOWLIST: tuple[str, ...] = (
    "PATH",
    "TERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "USER",
    "LOGNAME",
)

DEFAULT_CREDENTIAL_DENY_RELPATHS: tuple[str, ...] = (
    ".agent-comms",
    ".ssh",
    ".aws",
    ".azure",
    ".config/gcloud",
    ".config/gh",
    ".codex",
    ".claude",
    ".gemini",
    ".gnupg",
    ".netrc",
    ".git-credentials",
    ".docker",
    ".kube",
    ".npmrc",
    ".pypirc",
    ".cargo/credentials.toml",
    "Library/Keychains",
)

DEFAULT_STRIP_ENV_PREFIXES: tuple[str, ...] = (
    "AWS_",
    "OPENAI_",
    "ANTHROPIC_",
    "GOOGLE_",
    "GEMINI_",
    "VERTEX_",
    "AZURE_",
    "CLOUDFLARE_",
    "HF_",
    "HUGGING_FACE_",
    "TINFOIL_",
    "GITHUB_",
    "GH_",
    "GITLAB_",
    "NPM_",
    "PYPI_",
    "CARGO_REGISTRY_",
    "DOCKER_",
    "KUBE",
    "VAULT_",
    "DOPPLER_",
    "ONEPASSWORD_",
    "OP_",
    "SLACK_",
    "DISCORD_",
    "TELEGRAM_",
    "STRIPE_",
    "TWILIO_",
    "SENDGRID_",
    "DATADOG_",
    "SENTRY_",
    "NEW_RELIC_",
    "WANDB_",
    "LANGCHAIN_",
    "LANGSMITH_",
    "OPENCODE_",
    "LOCAL_ASSIST_",
)

DEFAULT_STRIP_ENV_NAMES: tuple[str, ...] = (
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "GPG_AGENT_INFO",
    "SECURITYSESSIONID",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "GIT_EXEC_PATH",
    "GIT_TEMPLATE_DIR",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_GLOBAL",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PYTHONHOME",
    "NODE_OPTIONS",
    "BASH_ENV",
    "ENV",
    "ZDOTDIR",
    "PROMPT_COMMAND",
)

RESERVED_WORKER_ENV_NAMES: tuple[str, ...] = (
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME",
    "TMPDIR",
    "OPENCODE_CONFIG",
    "OPENCODE_CONFIG_DIR",
    "OPENCODE_CONFIG_CONTENT",
    "OPENCODE_DISABLE_PROJECT_CONFIG",
    "OPENCODE_CONFIG_PROJECT_DISABLE",
    "OPENCODE_DISABLE_CLAUDE_CODE",
    "OPENCODE_DISABLE_CLAUDE_CODE_SKILLS",
    "OPENCODE_DISABLE_AUTOUPDATE",
    "OPENCODE_PERMISSION",
    "SHELL",
    "PATH",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_NOSYSTEM",
    "LOCAL_ASSIST_WORKER_SANDBOX",
    "LOCAL_ASSIST_WORKER_ID",
    "LOCAL_ASSIST_LOG_DIR",
    "LOCAL_ASSIST_VERIFIED_MODELS_FILE",
)

RESERVED_PORT_DENYLIST: tuple[int, ...] = (8080, 8081, 9081, 9181, 49374)

ALLOWED_RUN_BOOLEAN_FLAGS: frozenset[str] = frozenset({"--standalone", "--thinking"})
ALLOWED_RUN_VALUE_FLAGS: frozenset[str] = frozenset({"--format", "--title", "--variant"})

MCP_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SE_SESSION_REDACT_RE = re.compile(r"se-session-[A-Za-z0-9_-]+")

PROTECTED_WORKSPACE_FILE_RE = re.compile(
    r"(^|/)"
    r"(\.opencode|opencode\.json|opencode\.jsonc|\.env|"
    r"\.env\.(local|development|production|staging|test|secret|secrets|private)(\.[^/]+)?|"
    r"\.envrc|\.mcp\.json|\.gitmodules)"
    r"(/|$)"
)


class SecurityProfileError(ValueError):
    """Raised when a worker security profile or runtime invariant is invalid."""


@dataclass(frozen=True)
class McpServerPolicy:
    name: str
    type: str
    command: tuple[str, ...] = ()
    url: str | None = None
    environment: dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    timeout: int | None = None


@dataclass(frozen=True)
class WorkerSecurityProfile:
    schema_version: int = SCHEMA_VERSION
    mode: str = "unattended_worker"
    enforce_os_sandbox: bool = True
    allow_uncleared_model: bool = False
    spend_max_session_usd: float | None = None
    read_roots: tuple[str, ...] = (".",)
    write_roots: tuple[str, ...] = (".",)
    protected_paths: tuple[str, ...] = ()
    credential_deny_paths: tuple[str, ...] = ()
    allow_default_toolchains: bool = True
    allowed_tools: tuple[str, ...] = DEFAULT_ALLOWED_TOOLS
    denied_tools: tuple[str, ...] = ()
    allow_subagents: bool = False
    mcp_enable_local_assist: bool = False
    mcp_servers: dict[str, McpServerPolicy] = field(default_factory=dict)
    mcp_allowed_servers: tuple[str, ...] = ()
    mcp_allowed_tools: tuple[str, ...] = ()
    mcp_denied_tools: tuple[str, ...] = ()
    network_allowed_endpoints: tuple[str, ...] = ("loopback",)
    network_allowed_shell_localhost_ports: tuple[int, ...] = ()
    network_denied_localhost_ports: tuple[int, ...] = ()
    env_allowlist: tuple[str, ...] = DEFAULT_ENV_ALLOWLIST
    env_strip_prefixes: tuple[str, ...] = ()
    env_strip_names: tuple[str, ...] = ()
    env_set: dict[str, str] = field(default_factory=dict)
    allow_ssh_agent: bool = False


def default_unattended_worker_profile() -> WorkerSecurityProfile:
    return WorkerSecurityProfile()


def _ensure_mapping(obj: Any, context: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise SecurityProfileError(f"{context} must be a mapping, got {type(obj).__name__}.")
    return obj


def _reject_unknown_keys(mapping: dict[str, Any], allowed: set[str], context: str) -> None:
    unknown = set(mapping.keys()) - allowed
    if unknown:
        raise SecurityProfileError(
            f"Unknown keys in {context}: {', '.join(sorted(str(k) for k in unknown))}."
        )


def _ensure_bool(val: Any, context: str) -> bool:
    if not isinstance(val, bool):
        raise SecurityProfileError(f"{context} must be a boolean, got {val!r}.")
    return val


def _ensure_str_list(val: Any, context: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(val, list) or not all(isinstance(item, str) and item.strip() for item in val):
        raise SecurityProfileError(f"{context} must be a list of non-empty strings.")
    if not allow_empty and not val:
        raise SecurityProfileError(f"{context} must not be empty.")
    return tuple(item.strip() for item in val)


def _ensure_port_list(val: Any, context: str) -> tuple[int, ...]:
    if not isinstance(val, list):
        raise SecurityProfileError(f"{context} must be a list of TCP port integers.")
    ports: list[int] = []
    for item in val:
        if isinstance(item, bool) or not isinstance(item, int) or item < 1 or item > 65535:
            raise SecurityProfileError(
                f"{context} entries must be integers in 1..65535, got {item!r}."
            )
        ports.append(item)
    return tuple(ports)


def _validate_env_var_NotSecretOrReserved(
    name: str,
    *,
    context: str,
    extra_strip_prefixes: Sequence[str],
    extra_strip_names: Sequence[str],
    allow_path_in_allowlist: bool = False,
) -> None:
    if not ENV_NAME_RE.match(name):
        raise SecurityProfileError(f"{context}: invalid environment variable name {name!r}.")
    if allow_path_in_allowlist and name == "PATH":
        return
    if name in RESERVED_WORKER_ENV_NAMES:
        raise SecurityProfileError(
            f"{context}: '{name}' is a reserved worker runtime variable and cannot be overridden."
        )
    all_strip_names = set(DEFAULT_STRIP_ENV_NAMES) | set(extra_strip_names)
    if name in all_strip_names:
        raise SecurityProfileError(
            f"{context}: '{name}' is a stripped credential/runtime variable and cannot be passed."
        )
    all_strip_prefixes = tuple(DEFAULT_STRIP_ENV_PREFIXES) + tuple(extra_strip_prefixes)
    if any(name.startswith(prefix) for prefix in all_strip_prefixes):
        raise SecurityProfileError(
            f"{context}: '{name}' matches a stripped secret/credential prefix and cannot be passed."
        )


def _validate_loopback_http_url(url: str, context: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme != "http":
        raise SecurityProfileError(
            f"{context}: only http://127.0.0.1:<port> or http://localhost:<port> endpoints are permitted, got {url!r}."
        )
    if parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise SecurityProfileError(
            f"{context}: non-loopback host {parsed.hostname!r} is forbidden in {url!r}."
        )
    if parsed.port is None or parsed.port < 1 or parsed.port > 65535:
        raise SecurityProfileError(f"{context}: explicit TCP port is required in {url!r}.")
    if parsed.port in (9081, 9181, 49374):
        raise SecurityProfileError(
            f"{context}: port {parsed.port} is a reserved proxy/control port and cannot be used as an MCP endpoint."
        )
    return url.strip()


def _parse_mcp_servers(
    raw_servers: Any,
    *,
    extra_strip_prefixes: Sequence[str],
    extra_strip_names: Sequence[str],
) -> dict[str, McpServerPolicy]:
    mapping = _ensure_mapping(raw_servers, "mcp.servers")
    servers: dict[str, McpServerPolicy] = {}
    for server_name, raw_spec in mapping.items():
        if not isinstance(server_name, str) or not MCP_NAME_RE.match(server_name):
            raise SecurityProfileError(
                f"mcp.servers key {server_name!r} must match '^[A-Za-z0-9_-]{{1,64}}$'."
            )
        if server_name == "local_assist":
            raise SecurityProfileError(
                "mcp.servers cannot redefine reserved server 'local_assist'; use mcp.enable_local_assist: true instead."
            )
        spec = _ensure_mapping(raw_spec, f"mcp.servers.{server_name}")
        _reject_unknown_keys(
            spec,
            {"type", "command", "url", "environment", "enabled", "timeout"},
            f"mcp.servers.{server_name}",
        )
        srv_type = spec.get("type", "local")
        if srv_type not in ("local", "remote"):
            raise SecurityProfileError(
                f"mcp.servers.{server_name}.type must be 'local' or 'remote', got {srv_type!r}."
            )
        cmd_tuple: tuple[str, ...] = ()
        url_val: str | None = None
        if srv_type == "local":
            if "url" in spec and spec["url"] is not None:
                raise SecurityProfileError(
                    f"mcp.servers.{server_name}: local MCP server cannot specify 'url'."
                )
            cmd_tuple = _ensure_str_list(
                spec.get("command"), f"mcp.servers.{server_name}.command", allow_empty=False
            )
        else:
            if "command" in spec and spec["command"]:
                raise SecurityProfileError(
                    f"mcp.servers.{server_name}: remote MCP server cannot specify 'command'."
                )
            raw_url = spec.get("url")
            if not isinstance(raw_url, str) or not raw_url.strip():
                raise SecurityProfileError(
                    f"mcp.servers.{server_name}.url must be a non-empty loopback http URL."
                )
            url_val = _validate_loopback_http_url(raw_url, f"mcp.servers.{server_name}.url")

        raw_env = spec.get("environment") or {}
        env_map = _ensure_mapping(raw_env, f"mcp.servers.{server_name}.environment")
        clean_env: dict[str, str] = {}
        for k, v in env_map.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise SecurityProfileError(
                    f"mcp.servers.{server_name}.environment entries must be string-to-string."
                )
            _validate_env_var_NotSecretOrReserved(
                k,
                context=f"mcp.servers.{server_name}.environment",
                extra_strip_prefixes=extra_strip_prefixes,
                extra_strip_names=extra_strip_names,
            )
            clean_env[k] = v

        enabled = _ensure_bool(spec.get("enabled", True), f"mcp.servers.{server_name}.enabled")
        timeout = spec.get("timeout")
        if timeout is not None:
            if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
                raise SecurityProfileError(
                    f"mcp.servers.{server_name}.timeout must be a positive integer."
                )

        servers[server_name] = McpServerPolicy(
            name=server_name,
            type=srv_type,
            command=cmd_tuple,
            url=url_val,
            environment=clean_env,
            enabled=enabled,
            timeout=timeout,
        )

    # Check for prefix ambiguity across server names (e.g. "a" and "a_b").
    names = sorted(servers.keys())
    for i, first in enumerate(names):
        for second in names[i + 1 :]:
            if second.startswith(f"{first}_") or first.startswith(f"{second}_"):
                raise SecurityProfileError(
                    f"Ambiguous MCP server names '{first}' and '{second}': one is an underscore prefix of the other."
                )
    return servers


def _validate_mcp_tool_patterns(
    patterns: Sequence[str],
    *,
    configured_servers: set[str],
    context: str,
) -> None:
    for pattern in patterns:
        if "_" not in pattern:
            raise SecurityProfileError(
                f"{context}: MCP tool pattern '{pattern}' must be qualified as '<server>_<tool>'."
            )
        matching_servers = [s for s in configured_servers if pattern.startswith(f"{s}_")]
        if not matching_servers:
            raise SecurityProfileError(
                f"{context}: MCP tool pattern '{pattern}' does not match any configured MCP server "
                f"({', '.join(sorted(configured_servers)) or 'none'})."
            )
        if len(matching_servers) > 1:
            raise SecurityProfileError(
                f"{context}: MCP tool pattern '{pattern}' is ambiguous across servers {matching_servers}."
            )
        server_name = matching_servers[0]
        suffix = pattern[len(server_name) + 1 :]
        if not suffix or not re.match(r"^(\*|[A-Za-z0-9_-]+)$", suffix):
            raise SecurityProfileError(
                f"{context}: MCP tool pattern '{pattern}' has invalid tool suffix '{suffix}'."
            )


def parse_security_profile_dict(raw: dict[str, Any]) -> WorkerSecurityProfile:
    top = _ensure_mapping(raw, "security_profile")
    _reject_unknown_keys(
        top,
        {
            "schema_version",
            "mode",
            "enforce_os_sandbox",
            "allow_uncleared_model",
            "spend",
            "filesystem",
            "tools",
            "mcp",
            "network",
            "environment",
        },
        "security_profile",
    )

    schema_version = top.get("schema_version", SCHEMA_VERSION)
    if isinstance(schema_version, bool) or schema_version != SCHEMA_VERSION:
        raise SecurityProfileError(
            f"Unsupported schema_version {schema_version!r}; expected {SCHEMA_VERSION}."
        )

    mode = top.get("mode", "unattended_worker")
    if mode != "unattended_worker":
        raise SecurityProfileError(
            f"Unsupported security profile mode {mode!r}; expected 'unattended_worker'."
        )

    enforce_os_sandbox = _ensure_bool(
        top.get("enforce_os_sandbox", True), "enforce_os_sandbox"
    )
    if not enforce_os_sandbox:
        raise SecurityProfileError(
            "enforce_os_sandbox: false is refused for unattended_worker profiles; OS sandboxing is mandatory."
        )

    allow_uncleared_model = _ensure_bool(
        top.get("allow_uncleared_model", False), "allow_uncleared_model"
    )

    spend_raw = _ensure_mapping(top.get("spend") or {}, "spend")
    _reject_unknown_keys(spend_raw, {"max_session_usd"}, "spend")
    max_session_usd_raw = spend_raw.get("max_session_usd")
    spend_max_session_usd: float | None = None
    if max_session_usd_raw is not None:
        if (
            isinstance(max_session_usd_raw, bool)
            or not isinstance(max_session_usd_raw, (int, float))
            or not math.isfinite(float(max_session_usd_raw))
            or float(max_session_usd_raw) <= 0
        ):
            raise SecurityProfileError(
                f"spend.max_session_usd must be a finite positive number or null, got {max_session_usd_raw!r}."
            )
        spend_max_session_usd = float(max_session_usd_raw)

    fs_raw = _ensure_mapping(top.get("filesystem") or {}, "filesystem")
    _reject_unknown_keys(
        fs_raw,
        {
            "read_roots",
            "write_roots",
            "protected_paths",
            "credential_deny_paths",
            "allow_default_toolchains",
        },
        "filesystem",
    )
    read_roots = _ensure_str_list(
        fs_raw.get("read_roots", ["."]), "filesystem.read_roots", allow_empty=False
    )
    write_roots = _ensure_str_list(
        fs_raw.get("write_roots", ["."]), "filesystem.write_roots", allow_empty=True
    )
    protected_paths = _ensure_str_list(
        fs_raw.get("protected_paths", []), "filesystem.protected_paths"
    )
    credential_deny_paths = _ensure_str_list(
        fs_raw.get("credential_deny_paths", []), "filesystem.credential_deny_paths"
    )
    allow_default_toolchains = _ensure_bool(
        fs_raw.get("allow_default_toolchains", True), "filesystem.allow_default_toolchains"
    )

    tools_raw = _ensure_mapping(top.get("tools") or {}, "tools")
    _reject_unknown_keys(
        tools_raw,
        {"allowed_tools", "denied_tools", "allow_subagents"},
        "tools",
    )
    allowed_tools = _ensure_str_list(
        tools_raw.get("allowed_tools", list(DEFAULT_ALLOWED_TOOLS)), "tools.allowed_tools"
    )
    denied_tools = _ensure_str_list(
        tools_raw.get("denied_tools", []), "tools.denied_tools"
    )
    for t in (*allowed_tools, *denied_tools):
        if t not in KNOWN_BUILTIN_TOOLS:
            raise SecurityProfileError(
                f"Unknown built-in tool {t!r}. Allowed built-in tool names: {', '.join(KNOWN_BUILTIN_TOOLS)}."
            )
    allow_subagents = _ensure_bool(
        tools_raw.get("allow_subagents", False), "tools.allow_subagents"
    )

    env_raw = _ensure_mapping(top.get("environment") or {}, "environment")
    _reject_unknown_keys(
        env_raw,
        {"allowlist", "strip_prefixes", "strip_names", "set", "allow_ssh_agent"},
        "environment",
    )
    env_strip_prefixes = _ensure_str_list(
        env_raw.get("strip_prefixes", []), "environment.strip_prefixes"
    )
    env_strip_names = _ensure_str_list(
        env_raw.get("strip_names", []), "environment.strip_names"
    )
    env_allowlist = _ensure_str_list(
        env_raw.get("allowlist", list(DEFAULT_ENV_ALLOWLIST)), "environment.allowlist"
    )
    for var_name in env_allowlist:
        _validate_env_var_NotSecretOrReserved(
            var_name,
            context="environment.allowlist",
            extra_strip_prefixes=env_strip_prefixes,
            extra_strip_names=env_strip_names,
            allow_path_in_allowlist=True,
        )

    env_set_raw = _ensure_mapping(env_raw.get("set") or {}, "environment.set")
    env_set: dict[str, str] = {}
    for k, v in env_set_raw.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise SecurityProfileError("environment.set entries must be string-to-string.")
        _validate_env_var_NotSecretOrReserved(
            k,
            context="environment.set",
            extra_strip_prefixes=env_strip_prefixes,
            extra_strip_names=env_strip_names,
            allow_path_in_allowlist=False,
        )
        env_set[k] = v

    allow_ssh_agent = _ensure_bool(
        env_raw.get("allow_ssh_agent", False), "environment.allow_ssh_agent"
    )

    mcp_raw = _ensure_mapping(top.get("mcp") or {}, "mcp")
    _reject_unknown_keys(
        mcp_raw,
        {
            "enable_local_assist",
            "servers",
            "allowed_servers",
            "allowed_tools",
            "denied_tools",
        },
        "mcp",
    )
    mcp_enable_local_assist = _ensure_bool(
        mcp_raw.get("enable_local_assist", False), "mcp.enable_local_assist"
    )
    mcp_servers = _parse_mcp_servers(
        mcp_raw.get("servers") or {},
        extra_strip_prefixes=env_strip_prefixes,
        extra_strip_names=env_strip_names,
    )
    mcp_allowed_servers = _ensure_str_list(
        mcp_raw.get("allowed_servers", []), "mcp.allowed_servers"
    )
    mcp_allowed_tools = _ensure_str_list(
        mcp_raw.get("allowed_tools", []), "mcp.allowed_tools"
    )
    mcp_denied_tools = _ensure_str_list(
        mcp_raw.get("denied_tools", []), "mcp.denied_tools"
    )

    configured_server_names = set(mcp_servers.keys())
    if mcp_enable_local_assist:
        configured_server_names.add("local_assist")
    for srv_name in mcp_allowed_servers:
        if srv_name not in configured_server_names:
            raise SecurityProfileError(
                f"mcp.allowed_servers references unknown MCP server '{srv_name}'."
            )
    _validate_mcp_tool_patterns(
        mcp_allowed_tools,
        configured_servers=configured_server_names,
        context="mcp.allowed_tools",
    )
    _validate_mcp_tool_patterns(
        mcp_denied_tools,
        configured_servers=configured_server_names,
        context="mcp.denied_tools",
    )

    net_raw = _ensure_mapping(top.get("network") or {}, "network")
    _reject_unknown_keys(
        net_raw,
        {
            "allowed_endpoints",
            "allowed_shell_localhost_ports",
            "denied_localhost_ports",
        },
        "network",
    )
    network_allowed_endpoints = _ensure_str_list(
        net_raw.get("allowed_endpoints", ["loopback"]),
        "network.allowed_endpoints",
        allow_empty=False,
    )
    for ep in network_allowed_endpoints:
        if ep == "loopback":
            continue
        _validate_loopback_http_url(ep, "network.allowed_endpoints")

    network_allowed_shell_localhost_ports = _ensure_port_list(
        net_raw.get("allowed_shell_localhost_ports", []),
        "network.allowed_shell_localhost_ports",
    )
    for port in network_allowed_shell_localhost_ports:
        if port in RESERVED_PORT_DENYLIST:
            raise SecurityProfileError(
                f"network.allowed_shell_localhost_ports cannot expose reserved inference/proxy port {port}."
            )
    network_denied_localhost_ports = _ensure_port_list(
        net_raw.get("denied_localhost_ports", []),
        "network.denied_localhost_ports",
    )

    return WorkerSecurityProfile(
        schema_version=schema_version,
        mode=mode,
        enforce_os_sandbox=enforce_os_sandbox,
        allow_uncleared_model=allow_uncleared_model,
        spend_max_session_usd=spend_max_session_usd,
        read_roots=read_roots,
        write_roots=write_roots,
        protected_paths=protected_paths,
        credential_deny_paths=credential_deny_paths,
        allow_default_toolchains=allow_default_toolchains,
        allowed_tools=allowed_tools,
        denied_tools=denied_tools,
        allow_subagents=allow_subagents,
        mcp_enable_local_assist=mcp_enable_local_assist,
        mcp_servers=mcp_servers,
        mcp_allowed_servers=mcp_allowed_servers,
        mcp_allowed_tools=mcp_allowed_tools,
        mcp_denied_tools=mcp_denied_tools,
        network_allowed_endpoints=network_allowed_endpoints,
        network_allowed_shell_localhost_ports=network_allowed_shell_localhost_ports,
        network_denied_localhost_ports=network_denied_localhost_ports,
        env_allowlist=env_allowlist,
        env_strip_prefixes=env_strip_prefixes,
        env_strip_names=env_strip_names,
        env_set=env_set,
        allow_ssh_agent=allow_ssh_agent,
    )


def _reject_nonfinite_numbers(obj: Any, context: str = "security_profile") -> None:
    if isinstance(obj, float) and not math.isfinite(obj):
        raise SecurityProfileError(f"{context}: non-finite number {obj!r} is not permitted.")
    if isinstance(obj, dict):
        for k, v in obj.items():
            _reject_nonfinite_numbers(v, f"{context}.{k}")
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            _reject_nonfinite_numbers(item, f"{context}[{idx}]")


def load_security_profile(path: str | Path) -> WorkerSecurityProfile:
    profile_path = Path(path)
    if not profile_path.is_file():
        raise SecurityProfileError(f"Security profile file does not exist: {profile_path}")
    try:
        raw_text = profile_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SecurityProfileError(f"Failed to read security profile {profile_path}: {exc}") from exc
    try:
        loaded = safe_load(raw_text)
    except Exception as exc:
        raise SecurityProfileError(f"Invalid YAML/JSON in security profile {profile_path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise SecurityProfileError(
            f"Security profile {profile_path} must contain a top-level mapping."
        )
    _reject_nonfinite_numbers(loaded, "security_profile")
    return parse_security_profile_dict(loaded)


def apply_cli_overrides(
    profile: WorkerSecurityProfile,
    *,
    read_roots: Sequence[str] | None = None,
    write_roots: Sequence[str] | None = None,
    protected_paths: Sequence[str] | None = None,
    allowed_tools: Sequence[str] | None = None,
    denied_tools: Sequence[str] | None = None,
    allowed_mcp_tools: Sequence[str] | None = None,
    denied_mcp_tools: Sequence[str] | None = None,
    allow_subagents: bool | None = None,
    allow_ssh_agent: bool | None = None,
    allowed_localhost_ports: Sequence[int] | None = None,
    pass_env: Sequence[str] | None = None,
) -> WorkerSecurityProfile:
    eff_read_roots = tuple(read_roots) if read_roots else profile.read_roots
    eff_write_roots = tuple(write_roots) if write_roots else profile.write_roots
    eff_protected_paths = tuple(dict.fromkeys((*profile.protected_paths, *(protected_paths or ()))))
    eff_allowed_tools = tuple(allowed_tools) if allowed_tools else profile.allowed_tools
    eff_denied_tools = tuple(dict.fromkeys((*profile.denied_tools, *(denied_tools or ()))))
    eff_allowed_mcp_tools = (
        tuple(dict.fromkeys((*profile.mcp_allowed_tools, *allowed_mcp_tools)))
        if allowed_mcp_tools
        else profile.mcp_allowed_tools
    )
    eff_denied_mcp_tools = tuple(
        dict.fromkeys((*profile.mcp_denied_tools, *(denied_mcp_tools or ())))
    )
    eff_allow_subagents = (
        allow_subagents if allow_subagents is not None else profile.allow_subagents
    )
    eff_allow_ssh_agent = (
        allow_ssh_agent if allow_ssh_agent is not None else profile.allow_ssh_agent
    )

    extra_ports: list[int] = []
    for raw_port in allowed_localhost_ports or ():
        if isinstance(raw_port, bool) or not isinstance(raw_port, int) or raw_port < 1 or raw_port > 65535:
            raise SecurityProfileError(
                f"--allow-localhost-port must be an integer in 1..65535, got {raw_port!r}."
            )
        if raw_port in RESERVED_PORT_DENYLIST:
            raise SecurityProfileError(
                f"--allow-localhost-port cannot expose reserved inference/proxy port {raw_port}."
            )
        extra_ports.append(raw_port)
    eff_allowed_shell_ports = tuple(
        dict.fromkeys((*profile.network_allowed_shell_localhost_ports, *extra_ports))
    )

    extra_env_names: list[str] = []
    for raw_name in pass_env or ():
        if not isinstance(raw_name, str) or not raw_name.strip():
            raise SecurityProfileError("--pass-env requires a non-empty environment variable name.")
        var_name = raw_name.strip()
        if "=" in var_name:
            raise SecurityProfileError(
                f"--pass-env accepts variable names only (got {var_name!r}); use profile environment.set for values."
            )
        _validate_env_var_NotSecretOrReserved(
            var_name,
            context="--pass-env",
            extra_strip_prefixes=profile.env_strip_prefixes,
            extra_strip_names=profile.env_strip_names,
            allow_path_in_allowlist=False,
        )
        extra_env_names.append(var_name)
    eff_env_allowlist = tuple(
        dict.fromkeys((*profile.env_allowlist, *extra_env_names))
    )

    for t in (*eff_allowed_tools, *eff_denied_tools):
        if t not in KNOWN_BUILTIN_TOOLS:
            raise SecurityProfileError(
                f"Unknown built-in tool {t!r}. Allowed built-in tool names: {', '.join(KNOWN_BUILTIN_TOOLS)}."
            )

    configured_server_names = set(profile.mcp_servers.keys())
    if profile.mcp_enable_local_assist:
        configured_server_names.add("local_assist")
    _validate_mcp_tool_patterns(
        eff_allowed_mcp_tools,
        configured_servers=configured_server_names,
        context="--allow-mcp-tool",
    )
    _validate_mcp_tool_patterns(
        eff_denied_mcp_tools,
        configured_servers=configured_server_names,
        context="--deny-mcp-tool",
    )

    return WorkerSecurityProfile(
        schema_version=profile.schema_version,
        mode=profile.mode,
        enforce_os_sandbox=profile.enforce_os_sandbox,
        allow_uncleared_model=profile.allow_uncleared_model,
        spend_max_session_usd=profile.spend_max_session_usd,
        read_roots=eff_read_roots,
        write_roots=eff_write_roots,
        protected_paths=eff_protected_paths,
        credential_deny_paths=profile.credential_deny_paths,
        allow_default_toolchains=profile.allow_default_toolchains,
        allowed_tools=eff_allowed_tools,
        denied_tools=eff_denied_tools,
        allow_subagents=eff_allow_subagents,
        mcp_enable_local_assist=profile.mcp_enable_local_assist,
        mcp_servers=profile.mcp_servers,
        mcp_allowed_servers=profile.mcp_allowed_servers,
        mcp_allowed_tools=eff_allowed_mcp_tools,
        mcp_denied_tools=eff_denied_mcp_tools,
        network_allowed_endpoints=profile.network_allowed_endpoints,
        network_allowed_shell_localhost_ports=eff_allowed_shell_ports,
        network_denied_localhost_ports=profile.network_denied_localhost_ports,
        env_allowlist=eff_env_allowlist,
        env_strip_prefixes=profile.env_strip_prefixes,
        env_strip_names=profile.env_strip_names,
        env_set=profile.env_set,
        allow_ssh_agent=eff_allow_ssh_agent,
    )


def validate_worker_opencode_args(opencode_args: Sequence[str]) -> list[str]:
    args = list(opencode_args)
    if not args:
        raise SecurityProfileError(
            "Unattended worker profile requires the 'run' subcommand "
            "(for example: -- run --format json \"<prompt>\"). Interactive TUI mode is refused."
        )
    if args[0] != "run":
        raise SecurityProfileError(
            f"Unattended worker profile only allows the 'run' subcommand, got {args[0]!r}."
        )

    validated: list[str] = ["run"]
    has_standalone = False
    prompt_tokens: list[str] = []
    i = 1
    while i < len(args):
        token = args[i]
        if token == "--":
            for rem in args[i + 1 :]:
                if rem.strip():
                    prompt_tokens.append(rem)
                validated.append(rem)
            break
        if token.startswith("-"):
            if "=" in token:
                raise SecurityProfileError(
                    f"Inline '--flag=value' syntax ({token!r}) is not permitted in worker mode; "
                    "pass allowed flags as separate tokens."
                )
            if token in ALLOWED_RUN_BOOLEAN_FLAGS:
                if token == "--standalone":
                    has_standalone = True
                validated.append(token)
                i += 1
                continue
            if token in ALLOWED_RUN_VALUE_FLAGS:
                if i + 1 >= len(args) or args[i + 1].startswith("-"):
                    raise SecurityProfileError(
                        f"Flag {token!r} in opencode args is missing its value."
                    )
                val = args[i + 1]
                if token == "--format" and val not in ("default", "json"):
                    raise SecurityProfileError(
                        f"Unsupported --format value {val!r}; expected 'default' or 'json'."
                    )
                validated.extend([token, val])
                i += 2
                continue
            raise SecurityProfileError(
                f"Disallowed opencode flag {token!r} in unattended worker mode. "
                "Only '--standalone', '--format', '--title', '--variant', and '--thinking' are permitted."
            )
        if token.strip():
            prompt_tokens.append(token)
        validated.append(token)
        i += 1

    if not prompt_tokens:
        raise SecurityProfileError(
            "Unattended worker 'run' invocation requires a non-empty prompt message."
        )
    if not has_standalone:
        validated.insert(1, "--standalone")
    return validated


def verify_opencode_version(
    opencode_bin: str | Path,
    *,
    allow_version_drift: bool = False,
) -> str:
    try:
        proc = subprocess.run(
            [str(opencode_bin), "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except OSError as exc:
        raise SecurityProfileError(f"Failed to execute '{opencode_bin} --version': {exc}") from exc
    out = (proc.stdout or proc.stderr or "").strip()
    version_line = out.splitlines()[0].strip() if out else ""
    m = re.search(r"(\d+\.\d+\.\d+)", version_line)
    detected = m.group(1) if m else version_line
    if detected != TESTED_OPENCODE_VERSION:
        msg = (
            f"OpenCode version '{detected}' differs from security-verified version "
            f"'{TESTED_OPENCODE_VERSION}'."
        )
        if not allow_version_drift:
            raise SecurityProfileError(
                f"{msg} Pass --allow-opencode-version-drift to proceed after verifying compatibility."
            )
        print(f"WARNING: {msg}", file=sys.stderr)
    return detected


def _expand_tool_set(
    allowed_tools: Sequence[str],
    denied_tools: Sequence[str],
    *,
    allow_subagents: bool,
) -> set[str]:
    expanded_allowed: set[str] = set()
    for tool in allowed_tools:
        if tool == "edit":
            expanded_allowed.update(("edit", "write", "patch"))
        elif tool in ("shell", "bash"):
            expanded_allowed.update(("shell", "bash"))
        elif tool in ("task", "subagent"):
            expanded_allowed.update(("task", "subagent"))
        else:
            expanded_allowed.add(tool)

    if allow_subagents:
        expanded_allowed.update(("task", "subagent"))

    expanded_denied: set[str] = set()
    for tool in denied_tools:
        if tool in ("shell", "bash"):
            expanded_denied.update(("shell", "bash"))
        elif tool in ("task", "subagent"):
            expanded_denied.update(("task", "subagent"))
        else:
            expanded_denied.add(tool)

    if not allow_subagents:
        expanded_denied.update(("task", "subagent"))

    # Network/interactive/escape tools are always denied unless explicitly in allowed_tools and not in denied_tools.
    for always_guarded in ("webfetch", "websearch", "codesearch", "question", "external_directory"):
        if always_guarded not in allowed_tools:
            expanded_denied.add(always_guarded)

    return expanded_allowed - expanded_denied


def compile_opencode_security_config(
    base_config: dict[str, Any],
    profile: WorkerSecurityProfile,
    *,
    isolated_home: Path | None = None,
) -> dict[str, Any]:
    cfg = json.loads(json.dumps(base_config))
    effective_allowed = _expand_tool_set(
        profile.allowed_tools,
        profile.denied_tools,
        allow_subagents=profile.allow_subagents,
    )

    tools_map: dict[str, bool] = {}
    policies_map: dict[str, str] = {}
    permission_map: dict[str, Any] = {"*": "deny"}

    for tool_name in KNOWN_BUILTIN_TOOLS:
        is_allowed = tool_name in effective_allowed
        tools_map[tool_name] = is_allowed
        policies_map[tool_name] = "allow" if is_allowed else "deny"
        permission_map[tool_name] = "allow" if is_allowed else "deny"

    # In OpenCode, edit/write/patch share the 'edit' permission category.
    # Denying any of ('edit', 'write', 'patch') denies the 'edit' category unless all enabled edit aliases are allowed.
    if (
        ("edit" in effective_allowed or "write" in effective_allowed or "patch" in effective_allowed)
        and "edit" not in profile.denied_tools
        and "write" not in profile.denied_tools
        and "patch" not in profile.denied_tools
    ):
        permission_map["edit"] = "allow"
    else:
        permission_map["edit"] = "deny"
        for write_alias in ("edit", "write", "patch"):
            tools_map[write_alias] = False
            policies_map[write_alias] = "deny"
            permission_map[write_alias] = "deny"

    if "shell" in effective_allowed or "bash" in effective_allowed:
        permission_map["bash"] = "allow"
        permission_map["shell"] = "allow"
    else:
        permission_map["bash"] = "deny"
        permission_map["shell"] = "deny"

    if profile.allow_subagents and ("task" in effective_allowed or "subagent" in effective_allowed):
        permission_map["task"] = "allow"
        permission_map["subagent"] = "allow"
    else:
        permission_map["task"] = "deny"
        permission_map["subagent"] = "deny"

    permission_map["external_directory"] = "deny"
    permission_map["doom_loop"] = "deny"
    permission_map["question"] = "deny"

    # Configure MCP servers and fail-closed MCP tool permissions.
    mcp_servers_out: dict[str, Any] = {}
    existing_mcp = cfg.get("mcp")
    existing_servers: dict[str, Any] = {}
    if isinstance(existing_mcp, dict):
        if isinstance(existing_mcp.get("servers"), dict):
            existing_servers = existing_mcp["servers"]
        elif "local_assist" in existing_mcp and isinstance(existing_mcp["local_assist"], dict):
            existing_servers = {"local_assist": existing_mcp["local_assist"]}

    if "local_assist" in existing_servers and profile.mcp_enable_local_assist:
        local_assist_entry = json.loads(json.dumps(existing_servers["local_assist"]))
        env_block = dict(local_assist_entry.get("environment") or {})
        env_block["LOCAL_ASSIST_AUTO_SERVE"] = "0"
        env_block["LOCAL_ASSIST_WORKER_SANDBOX"] = "1"
        if isolated_home is not None:
            iso_resolved = isolated_home.resolve()
            env_block["LOCAL_ASSIST_LOG_DIR"] = str(
                iso_resolved / ".local" / "share" / "local-assist-runs"
            )
            env_block["LOCAL_ASSIST_VERIFIED_MODELS_FILE"] = str(
                iso_resolved / "verified-models.json"
            )
            env_block["PYTHONSAFEPATH"] = "1"
            env_block["PYTHONNOUSERSITE"] = "1"
            local_assist_entry["cwd"] = str(iso_resolved / "runtime")
            cmd_list = list(local_assist_entry.get("command") or [])
            if cmd_list:
                cmd_list[0] = str(iso_resolved / "bin" / "local-assist-python")
                if "-I" not in cmd_list[1:]:
                    cmd_list.insert(1, "-I")
                local_assist_entry["command"] = cmd_list
        local_assist_entry["environment"] = env_block
        local_assist_entry["disabled"] = False
        local_assist_entry.setdefault("codemode", False)
        mcp_servers_out["local_assist"] = local_assist_entry

    allowed_server_set = (
        set(profile.mcp_allowed_servers)
        if profile.mcp_allowed_servers
        else set(profile.mcp_servers.keys())
        | ({"local_assist"} if profile.mcp_enable_local_assist else set())
    )

    for srv_name, srv_policy in profile.mcp_servers.items():
        srv_enabled = srv_policy.enabled and (srv_name in allowed_server_set)
        entry: dict[str, Any] = {
            "type": srv_policy.type,
            "disabled": not srv_enabled,
            "codemode": False,
            "timeout": srv_policy.timeout if srv_policy.timeout is not None else 180000,
        }
        if srv_policy.type == "local":
            entry["command"] = list(srv_policy.command)
            if srv_policy.environment:
                entry["environment"] = dict(srv_policy.environment)
        else:
            entry["url"] = srv_policy.url
        mcp_servers_out[srv_name] = entry

    if profile.mcp_enable_local_assist and "local_assist" in mcp_servers_out:
        if "local_assist" not in allowed_server_set:
            mcp_servers_out["local_assist"]["disabled"] = True

    # Fail-closed per-server wildcard deny first, then specific allows, then specific denies.
    for srv_name in mcp_servers_out:
        tools_map[f"{srv_name}*"] = False
        tools_map[f"{srv_name}_*"] = False
        policies_map[f"{srv_name}_*"] = "deny"
        permission_map[f"{srv_name}*"] = "deny"
        permission_map[f"{srv_name}_*"] = "deny"

    if (
        profile.mcp_enable_local_assist
        and "local_assist" in allowed_server_set
        and not any(p.startswith("local_assist_") for p in profile.mcp_allowed_tools)
    ):
        tools_map["local_assist*"] = True
        tools_map["local_assist_*"] = True
        policies_map["local_assist_*"] = "allow"
        permission_map["local_assist*"] = "allow"
        permission_map["local_assist_*"] = "allow"

    for pattern in profile.mcp_allowed_tools:
        srv_match = [s for s in allowed_server_set if pattern.startswith(f"{s}_")]
        if not srv_match:
            continue
        tools_map[pattern] = True
        policies_map[pattern] = "allow"
        permission_map[pattern] = "allow"

    for pattern in profile.mcp_denied_tools:
        tools_map[pattern] = False
        policies_map[pattern] = "deny"
        permission_map[pattern] = "deny"

    cfg["tools"] = tools_map
    cfg["permission"] = permission_map
    cfg["mcp"] = {"servers": mcp_servers_out}

    if not profile.allow_subagents:
        agents_cfg = dict(cfg.get("agent") or {})
        for subagent_name in ("general", "explore"):
            sub_entry = dict(agents_cfg.get(subagent_name) or {})
            sub_entry["disable"] = True
            agents_cfg[subagent_name] = sub_entry
        cfg["agent"] = agents_cfg

    return cfg


def _seatbelt_escape_literal(path_str: str) -> str:
    return path_str.replace("\\", "\\\\").replace('"', '\\"')


def _seatbelt_escape_regex(path_str: str) -> str:
    return re.escape(path_str).replace('"', '\\"')


def _dual_realpath_variants(path: Path) -> list[str]:
    resolved = str(path.resolve())
    raw = str(path.expanduser().absolute())
    variants: list[str] = []
    for candidate in (resolved, raw):
        if candidate not in variants:
            variants.append(candidate)
        if candidate.startswith("/private/"):
            stripped = candidate[len("/private") :]
            if stripped and stripped not in variants:
                variants.append(stripped)
        elif candidate.startswith(("/var/", "/tmp/", "/etc/")):
            prefixed = f"/private{candidate}"
            if prefixed not in variants:
                variants.append(prefixed)
        if candidate.startswith("/Users/"):
            data_vol = f"/System/Volumes/Data{candidate}"
            if data_vol not in variants:
                variants.append(data_vol)
        elif candidate.startswith("/System/Volumes/Data/Users/"):
            short_users = candidate[len("/System/Volumes/Data") :]
            if short_users not in variants:
                variants.append(short_users)
    return variants


def _forbidden_broad_roots(*, is_write_root: bool) -> set[Path]:
    host_home = Path.home().resolve()
    forbidden_exact: set[Path] = {
        Path("/"),
        Path("/System"),
        Path("/System/Volumes"),
        Path("/System/Volumes/Data"),
        Path("/System/Volumes/Data/Users"),
        Path("/Users"),
        Path("/Volumes"),
        Path("/var"),
        Path("/private"),
        Path("/private/var"),
        Path("/private/var/folders"),
        Path("/var/folders"),
        Path("/tmp"),
        Path("/private/tmp"),
        host_home,
        host_home / ".local",
        host_home / ".local" / "share",
        host_home / ".config",
        host_home / ".cache",
    }
    for parent in host_home.parents:
        forbidden_exact.add(parent)
    if is_write_root:
        forbidden_exact.update(
            {
                Path("/opt"),
                Path("/opt/homebrew"),
                Path("/usr"),
                Path("/bin"),
                Path("/sbin"),
                Path("/Library"),
                Path("/Applications"),
            }
        )
    return forbidden_exact


def _is_forbidden_broad_read_root(path: Path) -> bool:
    try:
        resolved = path.expanduser().resolve()
    except OSError:
        resolved = path.expanduser().absolute()
    return resolved in _forbidden_broad_roots(is_write_root=False)


def _is_safe_opencode_package_root(root: Path) -> bool:
    if _is_forbidden_broad_read_root(root):
        return False
    try:
        resolved = root.expanduser().resolve()
    except OSError:
        return False
    host_home = Path.home().resolve()
    if resolved == host_home or host_home in resolved.parents:
        # Under $HOME, only allow dedicated opencode package directories (never ~/bin, ~/.local, or $HOME).
        allowed_home_prefixes = (
            host_home / ".local" / "share" / "opencode",
            host_home / ".opencode",
        )
        return any(
            resolved == pfx or pfx in resolved.parents for pfx in allowed_home_prefixes
        )
    return True


def _discover_existing_protected_paths(write_roots: Sequence[Path]) -> list[Path]:
    discovered: list[Path] = []
    protected_basenames = {
        ".git",
        ".opencode",
        "opencode.json",
        "opencode.jsonc",
        ".env",
        ".envrc",
        ".mcp.json",
        ".gitmodules",
    }
    for wr in write_roots:
        try:
            for dirpath, dirnames, filenames in os.walk(wr, topdown=True, followlinks=False):
                dp = Path(dirpath)
                keep_dirs: list[str] = []
                for dname in dirnames:
                    candidate = dp / dname
                    if dname in protected_basenames or PROTECTED_WORKSPACE_FILE_RE.search(dname):
                        discovered.append(candidate)
                        if dname == ".git":
                            continue
                    if not candidate.is_symlink():
                        keep_dirs.append(dname)
                dirnames[:] = keep_dirs
                for fname in filenames:
                    if fname in protected_basenames or PROTECTED_WORKSPACE_FILE_RE.search(fname):
                        discovered.append(dp / fname)
        except OSError:
            continue
    return discovered


def _resolve_and_validate_roots(
    roots: Sequence[str],
    *,
    workspace_dir: Path,
    credential_deny_paths: Sequence[Path],
    context: str,
    is_write_root: bool,
) -> list[Path]:
    ws_real = workspace_dir.resolve(strict=True)
    forbidden_exact = _forbidden_broad_roots(is_write_root=is_write_root)

    deny_resolved: list[Path] = []
    for dp in credential_deny_paths:
        try:
            deny_resolved.append(dp.expanduser().resolve())
        except OSError:
            deny_resolved.append(dp.expanduser().absolute())

    resolved_roots: list[Path] = []
    for raw_root in roots:
        candidate = Path(raw_root).expanduser()
        if not candidate.is_absolute():
            candidate = ws_real / candidate
        try:
            real_target = candidate.resolve(strict=True)
        except OSError as exc:
            raise SecurityProfileError(
                f"{context}: root path {raw_root!r} (resolved to {candidate}) does not exist: {exc}"
            ) from exc
        if not real_target.is_dir():
            raise SecurityProfileError(
                f"{context}: root path {raw_root!r} (resolved to {real_target}) must be a directory."
            )
        if real_target in forbidden_exact:
            raise SecurityProfileError(
                f"{context}: overly broad root directory '{real_target}' is forbidden."
            )
        for deny_path in deny_resolved:
            if real_target == deny_path or deny_path in real_target.parents:
                raise SecurityProfileError(
                    f"{context}: root '{real_target}' overlaps denied credential/runtime path '{deny_path}'."
                )
        if real_target not in resolved_roots:
            resolved_roots.append(real_target)
    return resolved_roots


def _collect_credential_deny_paths(profile: WorkerSecurityProfile) -> list[Path]:
    host_home = Path.home()
    paths: list[Path] = [host_home / rel for rel in DEFAULT_CREDENTIAL_DENY_RELPATHS]
    paths.append(ROOT / "runs")
    paths.append(ROOT / ".home")
    for raw in profile.credential_deny_paths:
        p = Path(raw).expanduser()
        if not p.is_absolute():
            p = host_home / p
        paths.append(p)
    return paths


def _collect_runtime_write_deny_paths() -> list[Path]:
    paths: list[Path] = [
        ROOT / "local_assist",
        ROOT / "scripts",
        ROOT / "bin",
        ROOT / "config",
        ROOT / "tools",
        ROOT / ".venv",
        ROOT / "models.yaml",
    ]
    for py_prefix in (
        Path(sys.base_prefix),
        Path(sys.exec_prefix),
        Path(sys.executable).resolve().parent.parent,
    ):
        try:
            rp = py_prefix.resolve()
        except OSError:
            rp = py_prefix.absolute()
        if rp not in paths:
            paths.append(rp)
    return paths


def check_tracked_protected_files(
    workspace_dir: Path,
    *,
    protected_paths: Sequence[str] = (),
) -> list[str]:
    ws_real = workspace_dir.resolve()
    try:
        proc = subprocess.run(
            ["git", "-C", str(ws_real), "ls-files"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except OSError:
        return []
    if proc.returncode != 0:
        return []

    protected_rel_set: set[str] = set()
    for raw_pp in protected_paths:
        p = Path(raw_pp).expanduser()
        if not p.is_absolute():
            p = ws_real / p
        try:
            rel = p.resolve().relative_to(ws_real).as_posix()
            protected_rel_set.add(rel)
        except ValueError:
            continue

    flagged: list[str] = []
    for line in (proc.stdout or "").splitlines():
        rel_path = line.strip()
        if not rel_path:
            continue
        if PROTECTED_WORKSPACE_FILE_RE.search(rel_path):
            flagged.append(rel_path)
            continue
        for prot_rel in protected_rel_set:
            if rel_path == prot_rel or rel_path.startswith(f"{prot_rel}/"):
                flagged.append(rel_path)
                break
    return sorted(set(flagged))


def compile_seatbelt_profile(
    profile: WorkerSecurityProfile,
    *,
    workspace_dir: Path,
    isolated_home: Path,
    opencode_bin: Path,
    sandbox_exec_bin: Path = Path("/usr/bin/sandbox-exec"),
    upstream_port: int | None = None,
    use_token_relay: bool = False,
) -> str:
    ws_real = workspace_dir.resolve(strict=True)
    iso_real = isolated_home.resolve(strict=True)
    opencode_real = opencode_bin.resolve(strict=True)
    opencode_bin_abs = opencode_bin.expanduser().absolute()
    sandbox_real = sandbox_exec_bin.resolve(strict=True)

    cred_deny_paths = _collect_credential_deny_paths(profile)
    runtime_write_deny_paths = _collect_runtime_write_deny_paths()
    write_deny_paths: list[Path] = list(cred_deny_paths)
    for rwp in runtime_write_deny_paths:
        if rwp not in write_deny_paths:
            write_deny_paths.append(rwp)

    read_roots = _resolve_and_validate_roots(
        profile.read_roots,
        workspace_dir=ws_real,
        credential_deny_paths=cred_deny_paths,
        context="filesystem.read_roots",
        is_write_root=False,
    )
    write_roots = _resolve_and_validate_roots(
        profile.write_roots,
        workspace_dir=ws_real,
        credential_deny_paths=write_deny_paths,
        context="filesystem.write_roots",
        is_write_root=True,
    )

    lines: list[str] = [
        "(version 1)",
        "(allow default)",
        "",
        ";; 1. Process signaling, job-creation, preferences, and Mach / host-escape lockdown",
        "(deny job-creation)",
        "(deny user-preference-read)",
        "(deny user-preference-write)",
        "(deny signal)",
        "(allow signal (target same-sandbox))",
        "(deny appleevent-send)",
        "(deny lsopen)",
        "(deny mach-lookup)",
        "(allow mach-lookup",
        '  (global-name "com.apple.logd")',
        '  (global-name "com.apple.system.logger")',
        '  (global-name "com.apple.system.notification_center")',
        '  (global-name "com.apple.system.DirectoryService.libinfo_v1")',
        '  (global-name "com.apple.system.opendirectoryd.libinfo")',
        '  (global-name "com.apple.system.opendirectoryd.membership")',
        ")",
    ]

    iso_variants = _dual_realpath_variants(iso_real)
    local_assist_py_variants: list[str] = [
        f"{iv}/bin/local-assist-python" for iv in iso_variants
    ]
    local_assist_py_proc_expr = (
        f'(process-path "{_seatbelt_escape_literal(local_assist_py_variants[0])}")'
        if len(local_assist_py_variants) == 1
        else "(require-any "
        + " ".join(
            f'(process-path "{_seatbelt_escape_literal(p)}")'
            for p in local_assist_py_variants
        )
        + ")"
    )
    local_assist_py_target_expr = (
        f'(literal "{_seatbelt_escape_literal(local_assist_py_variants[0])}")'
        if len(local_assist_py_variants) == 1
        else "(require-any "
        + " ".join(
            f'(literal "{_seatbelt_escape_literal(p)}")'
            for p in local_assist_py_variants
        )
        + ")"
    )

    exec_deny_literals: list[str] = []
    for p_str in (
        str(opencode_real),
        str(opencode_bin_abs),
        *local_assist_py_variants,
        "/usr/bin/open",
        "/usr/bin/osascript",
        "/bin/launchctl",
        "/usr/bin/security",
        "/usr/bin/defaults",
        "/usr/bin/crontab",
        "/usr/bin/at",
        "/usr/bin/pbcopy",
        "/usr/bin/pbpaste",
        "/usr/sbin/screencapture",
        "/usr/bin/screencapture",
    ):
        if p_str not in exec_deny_literals:
            exec_deny_literals.append(p_str)

    lines.append("(deny process-exec")
    for p_str in exec_deny_literals:
        lines.append(f'  (literal "{_seatbelt_escape_literal(p_str)}")')
    lines.append(")")

    opencode_exec_targets = [f'(literal "{_seatbelt_escape_literal(str(opencode_real))}")']
    if str(opencode_bin_abs) != str(opencode_real):
        opencode_exec_targets.append(
            f'(literal "{_seatbelt_escape_literal(str(opencode_bin_abs))}")'
        )
    target_expr = (
        opencode_exec_targets[0]
        if len(opencode_exec_targets) == 1
        else f"(require-any {' '.join(opencode_exec_targets)})"
    )

    lines.extend(
        [
            "(allow process-exec",
            "  (require-all",
            f'    (process-path "{_seatbelt_escape_literal(str(sandbox_real))}")',
            f"    {target_expr}",
            "  )",
            ")",
            "(allow process-exec",
            "  (require-all",
            f'    (process-path "{_seatbelt_escape_literal(str(opencode_real))}")',
            f"    {target_expr}",
            "  )",
            ")",
        ]
    )
    if profile.mcp_enable_local_assist:
        lines.extend(
            [
                "(allow process-exec",
                "  (require-all",
                f'    (process-path "{_seatbelt_escape_literal(str(opencode_real))}")',
                f"    {local_assist_py_target_expr}",
                "  )",
                ")",
                "(allow process-exec",
                "  (require-all",
                f"    {local_assist_py_proc_expr}",
                f"    {local_assist_py_target_expr}",
                "  )",
                ")",
            ]
        )

    lines.extend(
        [
            "",
            ";; 2. Network isolation",
            "(deny network-outbound)",
            "(deny network-bind)",
        ]
    )

    for iso_var in _dual_realpath_variants(iso_real):
        lines.append(
            f'(allow network-outbound (remote unix-socket (subpath "{_seatbelt_escape_literal(iso_var)}")))'
        )

    if profile.allow_ssh_agent:
        ssh_sock = os.environ.get("SSH_AUTH_SOCK", "").strip()
        if ssh_sock:
            for sock_var in _dual_realpath_variants(Path(ssh_sock)):
                lines.append(
                    f'(allow network-outbound (remote unix-socket (path-literal "{_seatbelt_escape_literal(sock_var)}")))'
                )

    # opencode run --standalone spins up an internal Bun/Hono HTTP server on an ephemeral
    # loopback port (127.0.0.1:0) and connects its CLI client to that ephemeral port as well
    # as the inference endpoint (8080 or the parent _WorkerTokenRelay port). Direct access to
    # se-key-proxy (8081), tinfoil-proxy (9081/9181), and profile-denied ports is blocked by
    # the subsequent (deny network-outbound ...) rule below, and worker-shell child processes
    # do not inherit this process-path grant.
    lines.extend(
        [
            "(allow network-bind",
            "  (require-all",
            f'    (process-path "{_seatbelt_escape_literal(str(opencode_real))}")',
            '    (local ip "localhost:*")',
            "  )",
            ")",
            "(allow network-outbound",
            "  (require-all",
            f'    (process-path "{_seatbelt_escape_literal(str(opencode_real))}")',
            '    (remote ip "localhost:*")',
            "  )",
            ")",
        ]
    )

    venv_python_real = Path(sys.executable).resolve()
    if profile.mcp_enable_local_assist:
        lines.extend(
            [
                "(allow network-outbound",
                "  (require-all",
                f"    {local_assist_py_proc_expr}",
                '    (remote ip "localhost:8080")',
                "  )",
                ")",
            ]
        )

    if profile.network_allowed_shell_localhost_ports:
        lines.append("(allow network-outbound")
        for port in profile.network_allowed_shell_localhost_ports:
            lines.append(f'  (remote ip "localhost:{port}")')
        lines.append(")")

    denied_ports: list[int] = [9081, 9181, 49374]
    if upstream_port is not None and upstream_port not in denied_ports:
        denied_ports.append(upstream_port)
    if use_token_relay and 8081 not in denied_ports:
        denied_ports.append(8081)
    for port in profile.network_denied_localhost_ports:
        if port not in denied_ports:
            denied_ports.append(port)

    lines.append("(deny network-outbound")
    for port in denied_ports:
        lines.append(f'  (remote ip "localhost:{port}")')
    lines.append(")")

    # 3. Filesystem read boundary
    lines.extend(
        [
            "",
            ";; 3. Filesystem read boundary",
            "(deny file-read-data",
            '  (subpath "/Users")',
            '  (subpath "/System/Volumes/Data/Users")',
            '  (subpath "/Volumes")',
            '  (subpath "/private/tmp")',
            '  (subpath "/tmp")',
            '  (subpath "/private/var/folders")',
            '  (subpath "/var/folders")',
            ")",
        ]
    )

    read_allow_literals: list[str] = []
    for bin_p in (opencode_real, opencode_bin_abs):
        for var in _dual_realpath_variants(bin_p):
            if var not in read_allow_literals:
                read_allow_literals.append(var)

    read_allow_subpaths: list[str] = []
    for p in (iso_real, *read_roots, *write_roots):
        for var in _dual_realpath_variants(p):
            if var not in read_allow_subpaths:
                read_allow_subpaths.append(var)

    # Only allow the package parent directory of opencode_real if it is a dedicated package/cellar directory
    # (never $HOME, ~/.local, or another broad root).
    if _is_safe_opencode_package_root(opencode_real.parent.parent):
        for var in _dual_realpath_variants(opencode_real.parent.parent):
            if var not in read_allow_subpaths:
                read_allow_subpaths.append(var)

    if profile.allow_default_toolchains:
        host_home = Path.home()
        for tc_rel in (
            ".local/share/opencode",
            ".local/share/uv",
            ".local/bin",
            ".cargo",
            ".rustup",
            ".pyenv",
            ".nvm",
            ".bun",
        ):
            tc_path = host_home / tc_rel
            if not _is_forbidden_broad_read_root(tc_path):
                for var in _dual_realpath_variants(tc_path):
                    if var not in read_allow_subpaths:
                        read_allow_subpaths.append(var)
        for py_prefix in (Path(sys.base_prefix), Path(sys.exec_prefix)):
            if not _is_forbidden_broad_read_root(py_prefix):
                for var in _dual_realpath_variants(py_prefix):
                    if var not in read_allow_subpaths:
                        read_allow_subpaths.append(var)

    if profile.mcp_enable_local_assist:
        for extra_p in (
            ROOT,
            venv_python_real.parent.parent,
            Path(sys.base_prefix).resolve(),
            Path(sys.exec_prefix).resolve(),
        ):
            if not _is_forbidden_broad_read_root(extra_p):
                for var in _dual_realpath_variants(extra_p):
                    if var not in read_allow_subpaths:
                        read_allow_subpaths.append(var)

    lines.append("(allow file-read-data")
    for lit in read_allow_literals:
        lines.append(f'  (literal "{_seatbelt_escape_literal(lit)}")')
    for sp in read_allow_subpaths:
        lines.append(f'  (subpath "{_seatbelt_escape_literal(sp)}")')
    lines.append(")")

    # Restrict opencode.json and .config reads to opencode_real only.
    iso_variants = _dual_realpath_variants(iso_real)
    lines.append("(deny file-read-data")
    for iv in iso_variants:
        lines.append(f'  (literal "{_seatbelt_escape_literal(iv)}/opencode.json")')
        lines.append(f'  (subpath "{_seatbelt_escape_literal(iv)}/.config")')
    lines.append(")")

    lines.append("(allow file-read-data")
    lines.append("  (require-all")
    lines.append(f'    (process-path "{_seatbelt_escape_literal(str(opencode_real))}")')
    lines.append("    (require-any")
    for iv in iso_variants:
        lines.append(f'      (literal "{_seatbelt_escape_literal(iv)}/opencode.json")')
        lines.append(f'      (subpath "{_seatbelt_escape_literal(iv)}/.config")')
    lines.append("    )")
    lines.append("  )")
    lines.append(")")

    cred_deny_subpaths: list[str] = []
    for cp in cred_deny_paths:
        for var in _dual_realpath_variants(cp):
            if var not in cred_deny_subpaths:
                cred_deny_subpaths.append(var)

    for op_name in ("file-read*", "file-read-data"):
        lines.append(f"(deny {op_name}")
        for sp in cred_deny_subpaths:
            lines.append(f'  (subpath "{_seatbelt_escape_literal(sp)}")')
        lines.append(")")

    # Re-allow this worker's runtime subdirectories inside isolated_home (since isolated_home is under LAB_ROOT/.home).
    for op_name in ("file-read*", "file-read-data"):
        lines.append(f"(allow {op_name}")
        for iv in iso_variants:
            lines.append(f'  (literal "{_seatbelt_escape_literal(iv)}/verified-models.json")')
            lines.append(f'  (literal "{_seatbelt_escape_literal(iv)}/pyvenv.cfg")')
            for sub in ("bin", "lib", "runtime", ".tmp", ".local", ".cache"):
                lines.append(f'  (subpath "{_seatbelt_escape_literal(iv)}/{sub}")')
        lines.append(")")
        lines.append(f"(allow {op_name}")
        lines.append("  (require-all")
        lines.append(f'    (process-path "{_seatbelt_escape_literal(str(opencode_real))}")')
        lines.append("    (require-any")
        for iv in iso_variants:
            lines.append(f'      (subpath "{_seatbelt_escape_literal(iv)}")')
        lines.append("    )")
        lines.append("  )")
        lines.append(")")

    # 4. Filesystem write boundary
    lines.extend(
        [
            "",
            ";; 4. Filesystem write boundary",
            "(deny file-write*)",
            "(allow file-write*",
            '  (literal "/dev/null")',
            '  (literal "/dev/zero")',
            '  (literal "/dev/random")',
            '  (literal "/dev/urandom")',
            '  (literal "/dev/tty")',
            '  (literal "/dev/dtracehelper")',
            '  (literal "/dev/ptmx")',
            '  (regex #"^/dev/ttys[0-9]+$")',
        ]
    )
    for wr in write_roots:
        for var in _dual_realpath_variants(wr):
            lines.append(f'  (subpath "{_seatbelt_escape_literal(var)}")')
    lines.append(")")

    write_deny_subpaths: list[str] = []
    for wp in write_deny_paths:
        for var in _dual_realpath_variants(wp):
            if var not in write_deny_subpaths:
                write_deny_subpaths.append(var)

    # Deny writes to all credential/runtime paths (such as LAB_ROOT/runs, LAB_ROOT/.home,
    # LAB_ROOT/local_assist, LAB_ROOT/scripts, LAB_ROOT/.venv, LAB_ROOT/models.yaml, ~/.ssh, etc.)
    # even when a write_root is a parent directory of those paths (WORK-MAJOR-1, R2-F1).
    lines.append("(deny file-write*")
    for sp in write_deny_subpaths:
        lines.append(f'  (literal "{_seatbelt_escape_literal(sp)}")')
        lines.append(f'  (subpath "{_seatbelt_escape_literal(sp)}")')
    lines.append(")")

    # Now re-allow ONLY this worker's mutable subdirectories inside isolated_home.
    lines.append("(allow file-write*")
    for iv in iso_variants:
        lines.append(f'  (subpath "{_seatbelt_escape_literal(iv)}/.tmp")')
    lines.append(")")

    lines.append("(allow file-write*")
    lines.append("  (require-all")
    lines.append(f'    (process-path "{_seatbelt_escape_literal(str(opencode_real))}")')
    lines.append("    (require-any")
    for iv in iso_variants:
        lines.append(f'      (subpath "{_seatbelt_escape_literal(iv)}/.local")')
        lines.append(f'      (subpath "{_seatbelt_escape_literal(iv)}/.cache")')
    lines.append("    )")
    lines.append("  )")
    lines.append(")")

    if profile.mcp_enable_local_assist:
        lines.append("(allow file-write*")
        lines.append("  (require-all")
        lines.append(f"    {local_assist_py_proc_expr}")
        lines.append("    (require-any (vnode-type REGULAR-FILE) (vnode-type DIRECTORY))")
        lines.append("    (require-any")
        for iv in iso_variants:
            esc_iv = _seatbelt_escape_regex(iv)
            lines.append(
                f'      (regex #"^{esc_iv}/\\.local/share/local-assist-runs/.+$")'
            )
        lines.append("    )")
        lines.append("  )")
        lines.append(")")

    # Default-deny all writes to .git under every writable root (both write_roots and isolated_home),
    # then allow only safe git working-tree plumbing (WORK-MAJOR-2).
    write_root_variants: list[str] = []
    for wr in write_roots:
        for var in _dual_realpath_variants(wr):
            if var not in write_root_variants:
                write_root_variants.append(var)

    all_writable_root_variants: list[str] = []
    for var in (*write_root_variants, *iso_variants):
        if var not in all_writable_root_variants:
            all_writable_root_variants.append(var)

    if all_writable_root_variants:
        lines.append("(deny file-write*")
        for wr_var in all_writable_root_variants:
            esc_wr = _seatbelt_escape_regex(wr_var)
            lines.append(f'  (regex #"^{esc_wr}(/.*)?/\\.git(/.*)?$")')
        lines.append(")")

        lines.append("(allow file-write*")
        for wr_var in all_writable_root_variants:
            esc_wr = _seatbelt_escape_regex(wr_var)
            lines.append(
                f'  (regex #"^{esc_wr}(/.*)?/\\.git/'
                r"(index(\.lock)?|next-index-[0-9]+(\.lock)?|index\.stash\.[0-9]+(\.lock)?|"
                r"(HEAD|ORIG_HEAD|FETCH_HEAD|MERGE_HEAD|CHERRY_PICK_HEAD|REVERT_HEAD|BISECT_HEAD|"
                r"AUTO_MERGE|BISECT_LOG|BISECT_NAMES|BISECT_START|BISECT_TERMS|BISECT_ANCESTORS_OK|"
                r"BISECT_EXPECTED_REV)(\.lock)?|"
                r"(MERGE_MODE|MERGE_MSG|COMMIT_EDITMSG|SQUASH_MSG|TAG_EDITMSG|NOTES_EDITMSG)(\..*|\.lock)?|"
                r"packed-refs(\.lock|\.new)?|gc\.(pid|log)(\.lock)?|info/refs(\.lock)?|"
                r'(objects|refs|logs|sequencer)(/.*)?)$")'
            )
        lines.append(")")

    # Final unconditional write deny (applies to opencode_real and all child processes).
    lines.append("(deny file-write*")
    for iv in iso_variants:
        lines.append(f'  (literal "{_seatbelt_escape_literal(iv)}")')
        lines.append(f'  (literal "{_seatbelt_escape_literal(iv)}/opencode.json")')
        lines.append(f'  (literal "{_seatbelt_escape_literal(iv)}/worker.sb")')
        lines.append(f'  (literal "{_seatbelt_escape_literal(iv)}/.worker-owner.json")')
        lines.append(f'  (literal "{_seatbelt_escape_literal(iv)}/.unconfirmed-process-group.json")')
        lines.append(f'  (literal "{_seatbelt_escape_literal(iv)}/verified-models.json")')
        lines.append(f'  (literal "{_seatbelt_escape_literal(iv)}/pyvenv.cfg")')
        lines.append(f'  (literal "{_seatbelt_escape_literal(iv)}/.keep-worker-home")')
        lines.append(f'  (literal "{_seatbelt_escape_literal(iv)}/.local")')
        lines.append(f'  (literal "{_seatbelt_escape_literal(iv)}/.local/share")')
        lines.append(f'  (literal "{_seatbelt_escape_literal(iv)}/.local/share/local-assist-runs")')
        lines.append(f'  (literal "{_seatbelt_escape_literal(iv)}/bin")')
        lines.append(f'  (subpath "{_seatbelt_escape_literal(iv)}/bin")')
        lines.append(f'  (literal "{_seatbelt_escape_literal(iv)}/lib")')
        lines.append(f'  (subpath "{_seatbelt_escape_literal(iv)}/lib")')
        lines.append(f'  (literal "{_seatbelt_escape_literal(iv)}/runtime")')
        lines.append(f'  (subpath "{_seatbelt_escape_literal(iv)}/runtime")')
        lines.append(f'  (literal "{_seatbelt_escape_literal(iv)}/.config")')
        lines.append(f'  (subpath "{_seatbelt_escape_literal(iv)}/.config")')

    for wr_var in all_writable_root_variants:
        esc_wr = _seatbelt_escape_regex(wr_var)
        lines.append(
            f'  (regex #"^{esc_wr}(/.*)?/\\.git/'
            r'(hooks|config|config\.worktree|info|modules|commondir|gitdir|worktrees|shallow|rebase-merge|rebase-apply)(/.*)?$")'
        )
        lines.append(
            f'  (regex #"^{esc_wr}(/.*)?/'
            r"(\.opencode|opencode\.json|opencode\.jsonc|\.env|"
            r"\.env\.(local|development|production|staging|test|secret|secrets|private)(\..*)?|"
            r'\.envrc|\.mcp\.json|\.gitmodules)(/.*)?$")'
        )

    # Re-apply final write-denies for all credential/runtime paths outside this worker's isolated_home,
    # and protect ancestor directories between write_roots and any credential/runtime path against rename.
    # For ancestor containers of isolated_home (such as ROOT/.home and WORKER_HOMES_DIR), emit a
    # (require-all (subpath ...) (require-not (subpath <iso>))) rule so Section 5's .git plumbing
    # allowlist on a containing write_root cannot reopen .git writes inside sibling worker homes (R2-MAJOR-3).
    iso_not_clauses = " ".join(
        f'(require-not (subpath "{_seatbelt_escape_literal(iv)}"))' for iv in iso_variants
    )
    protected_entries: list[str] = []
    for wh_var in _dual_realpath_variants(WORKER_HOMES_DIR):
        wh_lit = f'  (literal "{_seatbelt_escape_literal(wh_var)}")'
        if wh_lit not in protected_entries:
            protected_entries.append(wh_lit)
        wh_sub_rule = (
            f'  (require-all (subpath "{_seatbelt_escape_literal(wh_var)}") {iso_not_clauses})'
        )
        if wh_sub_rule not in protected_entries:
            protected_entries.append(wh_sub_rule)

    for cp in write_deny_paths:
        for cp_var in _dual_realpath_variants(cp):
            cp_path = Path(cp_var)
            lit_rule = f'  (literal "{_seatbelt_escape_literal(cp_var)}")'
            if lit_rule not in protected_entries:
                protected_entries.append(lit_rule)
            if not any(cp_path == Path(iv) or cp_path in Path(iv).parents for iv in iso_variants):
                sub_rule = f'  (subpath "{_seatbelt_escape_literal(cp_var)}")'
                if sub_rule not in protected_entries:
                    protected_entries.append(sub_rule)
            else:
                sub_not_rule = (
                    f'  (require-all (subpath "{_seatbelt_escape_literal(cp_var)}") {iso_not_clauses})'
                )
                if sub_not_rule not in protected_entries:
                    protected_entries.append(sub_not_rule)
            for wr_var in write_root_variants:
                wr_path = Path(wr_var)
                if wr_path in cp_path.parents:
                    cur = cp_path.parent
                    while cur != wr_path and wr_path in cur.parents:
                        anc_rule = f'  (literal "{_seatbelt_escape_literal(str(cur))}")'
                        if anc_rule not in protected_entries:
                            protected_entries.append(anc_rule)
                        cur = cur.parent

    # Caller-specified protected_paths AND existing nested .git / protected files inside write_roots
    # plus ancestor literals to block directory relocation attacks (WORK-MAJOR-2).
    explicit_protected_paths: list[Path] = []
    for raw_pp in profile.protected_paths:
        pp = Path(raw_pp).expanduser()
        if not pp.is_absolute():
            pp = ws_real / pp
        explicit_protected_paths.append(pp)

    for pp in explicit_protected_paths:
        for pp_var in _dual_realpath_variants(pp):
            lit_rule = f'  (literal "{_seatbelt_escape_literal(pp_var)}")'
            sub_rule = f'  (subpath "{_seatbelt_escape_literal(pp_var)}")'
            if lit_rule not in protected_entries:
                protected_entries.append(lit_rule)
            if sub_rule not in protected_entries:
                protected_entries.append(sub_rule)

    for pp in (*explicit_protected_paths, *_discover_existing_protected_paths(write_roots)):
        for pp_var in _dual_realpath_variants(pp):
            pp_path = Path(pp_var)
            for wr_var in write_root_variants:
                wr_path = Path(wr_var)
                if wr_path in pp_path.parents:
                    cur = pp_path.parent
                    while cur != wr_path and wr_path in cur.parents:
                        anc_rule = f'  (literal "{_seatbelt_escape_literal(str(cur))}")'
                        if anc_rule not in protected_entries:
                            protected_entries.append(anc_rule)
                        cur = cur.parent

    lines.extend(protected_entries)
    lines.append(")")
    lines.append("")
    return "\n".join(lines)


def build_worker_environment(
    profile: WorkerSecurityProfile,
    *,
    isolated_home: Path,
    worker_id: str,
    host_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    src_env = dict(os.environ if host_env is None else host_env)
    iso_real = isolated_home.resolve()
    bin_dir = iso_real / "bin"
    tmp_dir = iso_real / ".tmp"

    all_strip_prefixes = tuple(DEFAULT_STRIP_ENV_PREFIXES) + tuple(profile.env_strip_prefixes)
    all_strip_names = set(DEFAULT_STRIP_ENV_NAMES) | set(profile.env_strip_names)
    if profile.allow_ssh_agent:
        all_strip_names.discard("SSH_AUTH_SOCK")

    env: dict[str, str] = {}
    for key in profile.env_allowlist:
        if key == "PATH":
            continue
        if key in all_strip_names or key in RESERVED_WORKER_ENV_NAMES:
            continue
        if any(key.startswith(pfx) for pfx in all_strip_prefixes):
            continue
        val = src_env.get(key)
        if isinstance(val, str):
            env[key] = val

    if profile.allow_ssh_agent and "SSH_AUTH_SOCK" in src_env:
        env["SSH_AUTH_SOCK"] = src_env["SSH_AUTH_SOCK"]

    # Default neutral git identity so commits inside the sandbox never leak host user/hostname.
    env.setdefault("GIT_AUTHOR_NAME", "worker")
    env.setdefault("GIT_AUTHOR_EMAIL", "worker@local")
    env.setdefault("GIT_COMMITTER_NAME", "worker")
    env.setdefault("GIT_COMMITTER_EMAIL", "worker@local")

    for k, v in profile.env_set.items():
        env[k] = v

    base_path = src_env.get("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
    env["PATH"] = f"{bin_dir}:{base_path}"
    env["HOME"] = str(iso_real)
    env["XDG_CONFIG_HOME"] = str(iso_real / ".config")
    env["XDG_DATA_HOME"] = str(iso_real / ".local" / "share")
    env["XDG_STATE_HOME"] = str(iso_real / ".local" / "state")
    env["XDG_CACHE_HOME"] = str(iso_real / ".cache")
    env["TMPDIR"] = str(tmp_dir)
    env["OPENCODE_CONFIG"] = str(iso_real / "opencode.json")
    env["OPENCODE_CONFIG_DIR"] = str(iso_real / ".config" / "opencode")
    env["OPENCODE_DISABLE_PROJECT_CONFIG"] = "true"
    env["OPENCODE_CONFIG_PROJECT_DISABLE"] = "true"
    env["OPENCODE_DISABLE_CLAUDE_CODE"] = "true"
    env["OPENCODE_DISABLE_CLAUDE_CODE_SKILLS"] = "true"
    env["OPENCODE_DISABLE_AUTOUPDATE"] = "true"
    env["GIT_CONFIG_GLOBAL"] = "/dev/null"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["SHELL"] = str(bin_dir / "worker-shell")
    env["LOCAL_ASSIST_WORKER_SANDBOX"] = "1"
    env["LOCAL_ASSIST_WORKER_ID"] = worker_id
    env["LOCAL_ASSIST_LOG_DIR"] = str(iso_real / ".local" / "share" / "local-assist-runs")
    env["LOCAL_ASSIST_VERIFIED_MODELS_FILE"] = str(iso_real / "verified-models.json")
    return env


def _build_worker_shell_script(
    profile: WorkerSecurityProfile,
    *,
    isolated_home: Path,
    worker_id: str,
) -> str:
    iso_real = isolated_home.resolve()
    bin_dir = iso_real / "bin"
    tmp_dir = iso_real / ".tmp"
    unset_names = sorted(
        (set(DEFAULT_STRIP_ENV_NAMES) | set(profile.env_strip_names) | {"OPENCODE_CONFIG", "OPENCODE_CONFIG_DIR", "OPENCODE_CONFIG_CONTENT", "OPENCODE_PERMISSION"})
        - ({"SSH_AUTH_SOCK"} if profile.allow_ssh_agent else set())
    )
    unset_line = " ".join(shlex.quote(name) for name in unset_names)
    git_author_name = shlex.quote(profile.env_set.get("GIT_AUTHOR_NAME", "worker"))
    git_author_email = shlex.quote(profile.env_set.get("GIT_AUTHOR_EMAIL", "worker@local"))
    git_committer_name = shlex.quote(profile.env_set.get("GIT_COMMITTER_NAME", "worker"))
    git_committer_email = shlex.quote(profile.env_set.get("GIT_COMMITTER_EMAIL", "worker@local"))

    return (
        "#!/bin/sh\n"
        f"unset {unset_line}\n"
        f"export HOME={shlex.quote(str(iso_real))}\n"
        f"export TMPDIR={shlex.quote(str(tmp_dir))}\n"
        f"export GIT_CONFIG_GLOBAL=/dev/null\n"
        f"export GIT_CONFIG_NOSYSTEM=1\n"
        f"export GIT_TERMINAL_PROMPT=0\n"
        f"export GIT_AUTHOR_NAME={git_author_name}\n"
        f"export GIT_AUTHOR_EMAIL={git_author_email}\n"
        f"export GIT_COMMITTER_NAME={git_committer_name}\n"
        f"export GIT_COMMITTER_EMAIL={git_committer_email}\n"
        f"export LOCAL_ASSIST_WORKER_SANDBOX=1\n"
        f"export LOCAL_ASSIST_WORKER_ID={shlex.quote(worker_id)}\n"
        f"export LOCAL_ASSIST_VERIFIED_MODELS_FILE={shlex.quote(str(iso_real / 'verified-models.json'))}\n"
        f"export SHELL={shlex.quote(str(bin_dir / 'worker-shell'))}\n"
        'exec /bin/zsh -f "$@"\n'
    )


def allocate_worker_home() -> tuple[str, Path]:
    WORKER_HOMES_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(WORKER_HOMES_DIR, 0o700)
    except OSError:
        pass
    owner_pid = os.getpid()
    worker_id = f"worker-{owner_pid}-{int(time.time() * 1000)}-{secrets.token_hex(4)}"
    isolated_home = WORKER_HOMES_DIR / worker_id
    isolated_home.mkdir(parents=True, exist_ok=False, mode=0o700)
    for rel in (
        ".config/opencode",
        ".local/share/opencode",
        ".local/share/local-assist-runs",
        ".local/state/opencode",
        ".cache/opencode",
        ".tmp",
        "bin",
    ):
        sub = isolated_home / rel
        sub.mkdir(parents=True, exist_ok=True, mode=0o700)
    owner_meta_path = isolated_home / ".worker-owner.json"
    owner_meta = {
        "worker_id": worker_id,
        "owner_pid": owner_pid,
        "owner_pid_lstart": get_process_lstart(owner_pid),
        "created_at": time.time(),
    }
    owner_meta_path.write_text(json.dumps(owner_meta, indent=2) + "\n", encoding="utf-8")
    os.chmod(owner_meta_path, 0o400)
    return worker_id, isolated_home


def write_verified_local_models_handoff(
    *,
    isolated_home: Path,
    worker_id: str,
    ttl_seconds: int = 43200,
    runs_dir: Path | None = None,
    verify_runner: Any = None,
) -> Path:
    iso_real = isolated_home.resolve(strict=True)
    handoff_path = iso_real / "verified-models.json"
    now = time.time()
    verified_models: dict[str, dict[str, Any]] = {}
    verify_script = str(ROOT / "scripts" / "verify-served-model")
    runner = verify_runner or subprocess.run

    for item in list_pid_records(runs_dir):
        rec = item[1] if isinstance(item, tuple) and len(item) == 2 else item
        if not isinstance(rec, dict) or rec.get("status") != "ready":
            continue
        model_id = rec.get("model_id")
        pid = rec.get("pid")
        pid_lstart = rec.get("pid_lstart")
        hf_offline = rec.get("hf_offline")
        if (
            not isinstance(model_id, str)
            or not model_id
            or not isinstance(pid, int)
            or isinstance(pid, bool)
            or not isinstance(pid_lstart, str)
            or not pid_lstart.strip()
            or hf_offline is not True
        ):
            continue
        if not pid_matches_record(pid, pid_lstart, require_lstart=True):
            continue
        try:
            entry = load_model(model_id)
            ep = resolve_endpoint(entry, pid_record=rec, require_api_key=False)
        except RegistryError:
            continue
        if ep.trust_tier != "local" or ep.routing_private_local != "cleared":
            continue
        try:
            proc = runner(
                [sys.executable, verify_script, model_id, "--require-offline"],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except OSError:
            continue
        if proc.returncode != 0:
            continue
        verified_models[model_id] = {
            "model_id": model_id,
            "served_model_id": ep.served_model_id,
            "api_base_url": ep.api_base_url,
            "pid": pid,
            "pid_lstart": pid_lstart,
            "hf_offline": True,
        }

    manifest = {
        "schema_version": 1,
        "worker_id": worker_id,
        "issued_at": now,
        "expires_at": now + max(1, int(ttl_seconds)),
        "models": verified_models,
    }
    if handoff_path.exists():
        os.chmod(handoff_path, 0o600)
    handoff_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    os.chmod(handoff_path, 0o400)
    return handoff_path


def _resolve_real_python_macho() -> Path:
    for cand in (
        Path(sys.base_prefix).resolve()
        / "Resources"
        / "Python.app"
        / "Contents"
        / "MacOS"
        / "Python",
        Path(sys.exec_prefix).resolve()
        / "Resources"
        / "Python.app"
        / "Contents"
        / "MacOS"
        / "Python",
    ):
        try:
            if cand.is_file():
                return cand.resolve(strict=True)
        except OSError:
            continue
    return Path(sys.executable).resolve(strict=True)


def _provision_dedicated_local_assist_python(iso_real: Path) -> Path:
    bin_dir = iso_real / "bin"
    try:
        os.chmod(bin_dir, 0o700)
    except OSError:
        pass
    dest_bin = bin_dir / "local-assist-python"
    pyvenv_cfg = iso_real / "pyvenv.cfg"
    src_macho = _resolve_real_python_macho()
    home_bin = Path(sys.base_prefix).resolve() / "bin"

    if dest_bin.exists() or dest_bin.is_symlink():
        try:
            os.chmod(dest_bin, 0o700)
        except OSError:
            pass
        dest_bin.unlink()

    cp_done = False
    if Path("/bin/cp").is_file():
        try:
            cp_proc = subprocess.run(
                ["/bin/cp", "-c", str(src_macho), str(dest_bin)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            cp_done = cp_proc.returncode == 0 and dest_bin.is_file()
        except (OSError, subprocess.SubprocessError):
            cp_done = False
    if not cp_done:
        shutil.copy2(src_macho, dest_bin)

    os.chmod(dest_bin, 0o700)
    if Path("/usr/bin/codesign").is_file():
        sign_proc = subprocess.run(
            ["/usr/bin/codesign", "--force", "--sign", "-", str(dest_bin)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if sign_proc.returncode != 0:
            raise SecurityProfileError(
                f"Failed to ad-hoc codesign dedicated local-assist interpreter '{dest_bin}': "
                f"{(sign_proc.stderr or sign_proc.stdout or '').strip()}"
            )
    os.chmod(dest_bin, 0o500)

    if pyvenv_cfg.exists() or pyvenv_cfg.is_symlink():
        try:
            os.chmod(pyvenv_cfg, 0o600)
        except OSError:
            pass
    pyvenv_cfg.write_text(
        f"home = {home_bin}\ninclude-system-site-packages = false\n",
        encoding="utf-8",
    )
    os.chmod(pyvenv_cfg, 0o400)

    # Stage an immutable, self-contained local_assist runtime snapshot inside
    # <isolated_home>/runtime and bind it into <isolated_home>/lib/pythonX.Y/site-packages
    # via a .pth file so local-assist-python (-I) never imports or executes code from
    # a worker-writable workspace (R2-F1).
    runtime_dir = iso_real / "runtime"
    lib_dir = iso_real / "lib"
    for target_dir in (runtime_dir, lib_dir):
        if target_dir.exists() or target_dir.is_symlink():
            _safe_rmtree_nofollow(target_dir)

    runtime_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copytree(
        ROOT / "local_assist",
        runtime_dir / "local_assist",
        symlinks=False,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    runtime_scripts = runtime_dir / "scripts"
    runtime_scripts.mkdir(parents=True, exist_ok=True, mode=0o700)
    verify_src = ROOT / "scripts" / "verify-served-model"
    verify_dst = runtime_scripts / "verify-served-model"
    shutil.copy2(verify_src, verify_dst)

    models_src = ROOT / "models.yaml"
    if models_src.is_file():
        shutil.copy2(models_src, runtime_dir / "models.yaml")

    for doc_sub in ("evals", "attestations"):
        src_doc_dir = ROOT / "docs" / doc_sub
        if src_doc_dir.is_dir():
            shutil.copytree(
                src_doc_dir,
                runtime_dir / "docs" / doc_sub,
                symlinks=False,
            )

    py_ver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    site_packages = lib_dir / py_ver / "site-packages"
    site_packages.mkdir(parents=True, exist_ok=True, mode=0o700)
    pth_file = site_packages / "local_assist_runtime.pth"
    pth_file.write_text(f"{runtime_dir}\n", encoding="utf-8")

    # Copy any shared libpython*.dylib from the base/source Python installation into
    # <isolated_home>/lib so relocatable Python builds (such as actions/setup-python
    # linked against @executable_path/../lib/libpythonX.Y.dylib) resolve cleanly.
    for cand_lib_dir in (
        Path(sys.base_prefix).resolve() / "lib",
        Path(sys.exec_prefix).resolve() / "lib",
        src_macho.parent.parent / "lib",
    ):
        if not cand_lib_dir.is_dir():
            continue
        for dylib in cand_lib_dir.glob("libpython*.dylib"):
            if not dylib.is_file():
                continue
            dst_dylib = lib_dir / dylib.name
            if dst_dylib.exists():
                continue
            real_dylib = dylib.resolve()
            dylib_copied = False
            if Path("/bin/cp").is_file():
                try:
                    cp_dl = subprocess.run(
                        ["/bin/cp", "-c", str(real_dylib), str(dst_dylib)],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    dylib_copied = cp_dl.returncode == 0 and dst_dylib.is_file()
                except (OSError, subprocess.SubprocessError):
                    dylib_copied = False
            if not dylib_copied:
                shutil.copyfile(real_dylib, dst_dylib)

    for tree_root in (runtime_dir, lib_dir):
        for dirpath, _dirnames, filenames in os.walk(tree_root, topdown=False, followlinks=False):
            dp = Path(dirpath)
            for fname in filenames:
                fp = dp / fname
                try:
                    if fp == verify_dst:
                        os.chmod(fp, 0o500)
                    else:
                        os.chmod(fp, 0o400)
                except OSError:
                    pass
            try:
                os.chmod(dp, 0o500)
            except OSError:
                pass

    return dest_bin


def write_worker_runtime_artifacts(
    *,
    isolated_home: Path,
    worker_id: str,
    profile: WorkerSecurityProfile,
    opencode_config: dict[str, Any],
    seatbelt_text: str,
) -> tuple[Path, Path, Path]:
    iso_real = isolated_home.resolve(strict=True)
    config_path = iso_real / "opencode.json"
    seatbelt_path = iso_real / "worker.sb"
    shell_path = iso_real / "bin" / "worker-shell"

    if config_path.exists():
        os.chmod(config_path, 0o600)
    config_path.write_text(json.dumps(opencode_config, indent=2) + "\n", encoding="utf-8")
    os.chmod(config_path, 0o400)

    if seatbelt_path.exists():
        os.chmod(seatbelt_path, 0o600)
    seatbelt_path.write_text(seatbelt_text, encoding="utf-8")
    os.chmod(seatbelt_path, 0o400)

    if profile.mcp_enable_local_assist:
        if not (iso_real / "verified-models.json").exists():
            write_verified_local_models_handoff(isolated_home=iso_real, worker_id=worker_id)
        _provision_dedicated_local_assist_python(iso_real)

    try:
        os.chmod(iso_real / "bin", 0o700)
    except OSError:
        pass
    if shell_path.exists():
        os.chmod(shell_path, 0o700)
    shell_path.write_text(
        _build_worker_shell_script(profile, isolated_home=iso_real, worker_id=worker_id),
        encoding="utf-8",
    )
    os.chmod(shell_path, 0o500)
    os.chmod(iso_real / "bin", 0o500)
    os.chmod(iso_real / ".config" / "opencode", 0o500)
    os.chmod(iso_real / ".config", 0o500)
    return config_path, seatbelt_path, shell_path


def redact_session_tokens(text: str) -> str:
    return SE_SESSION_REDACT_RE.sub("se-session-REDACTED", text)


class _WorkerTokenRelay:
    """In-process loopback HTTP relay that keeps se-session-* tokens outside the worker sandbox."""

    def __init__(
        self,
        *,
        upstream_base_url: str,
        upstream_session_token: str,
        max_chat_requests: int = 25,
        max_request_bytes: int = 131072,
        max_tokens_cap: int = 2048,
        upstream_timeout_seconds: float = 120.0,
        max_response_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        parsed = urlparse(upstream_base_url.rstrip("/"))
        if parsed.hostname not in ("127.0.0.1", "localhost") or parsed.port is None:
            raise SecurityProfileError(
                f"_WorkerTokenRelay requires a localhost upstream URL with explicit port, got {upstream_base_url!r}."
            )
        if not upstream_session_token or not upstream_session_token.strip():
            raise SecurityProfileError("_WorkerTokenRelay requires a non-empty upstream token.")
        self.upstream_host = parsed.hostname
        self.upstream_port = parsed.port
        self._upstream_session_token = upstream_session_token.strip()
        self.relay_token = f"worker-relay-{secrets.token_hex(16)}"
        self.max_chat_requests = max(1, int(max_chat_requests))
        self.max_request_bytes = max(256, int(max_request_bytes))
        self.max_tokens_cap = max(1, int(max_tokens_cap))
        self.upstream_timeout_seconds = max(1.0, float(upstream_timeout_seconds))
        self.max_response_bytes = max(4096, int(max_response_bytes))
        self._lock = threading.Lock()
        self._inflight_sem = threading.BoundedSemaphore(16)
        self.chat_requests_used = 0
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def api_base_url(self) -> str:
        if self._httpd is None:
            raise RuntimeError("_WorkerTokenRelay has not been started.")
        _, port = self._httpd.server_address[:2]
        return f"http://127.0.0.1:{port}/v1"

    @property
    def port(self) -> int:
        if self._httpd is None:
            raise RuntimeError("_WorkerTokenRelay has not been started.")
        return int(self._httpd.server_address[1])

    def start(self) -> "_WorkerTokenRelay":
        relay = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self) -> None:
                try:
                    self.request.settimeout(min(30.0, relay.upstream_timeout_seconds))
                except OSError:
                    pass
                super().setup()

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _send_json_error(self, status: int, message: str, err_type: str) -> None:
                safe_msg = redact_session_tokens(
                    message.replace(relay._upstream_session_token, "[REDACTED]")
                )
                payload = json.dumps(
                    {"error": {"message": safe_msg, "type": err_type}}
                ).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    self.wfile.write(payload)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def _check_auth(self) -> bool:
                auth_hdr = self.headers.get("Authorization", "")
                if not auth_hdr.startswith("Bearer "):
                    self._send_json_error(
                        401, "Missing Bearer token for worker relay.", "auth_error"
                    )
                    return False
                candidate = auth_hdr[len("Bearer ") :].strip()
                if not hmac.compare_digest(
                    candidate.encode("utf-8"), relay.relay_token.encode("utf-8")
                ):
                    self._send_json_error(
                        401, "Invalid Bearer token for worker relay.", "auth_error"
                    )
                    return False
                return True

            def do_GET(self) -> None:
                if not self._check_auth():
                    return
                if self.path != "/v1/models":
                    self._send_json_error(
                        404, f"Worker relay path {self.path!r} is not permitted.", "not_found"
                    )
                    return
                self._forward_upstream("GET", "/v1/models", None)

            def do_POST(self) -> None:
                if not self._check_auth():
                    return
                if self.path != "/v1/chat/completions":
                    if self.path == "/v1/models":
                        self._send_json_error(405, "Method not allowed.", "method_not_allowed")
                    else:
                        self._send_json_error(
                            404, f"Worker relay path {self.path!r} is not permitted.", "not_found"
                        )
                    return

                if self.headers.get("Transfer-Encoding") is not None:
                    self._send_json_error(
                        400,
                        "Chunked Transfer-Encoding is not supported; Content-Length is required.",
                        "invalid_request_error",
                    )
                    return
                raw_cl = self.headers.get("Content-Length")
                if raw_cl is None:
                    self._send_json_error(
                        411, "Content-Length header is required.", "invalid_request_error"
                    )
                    return
                try:
                    content_length = int(raw_cl)
                except ValueError:
                    self._send_json_error(
                        400, "Invalid Content-Length header.", "invalid_request_error"
                    )
                    return
                if content_length < 0:
                    self._send_json_error(
                        400, "Negative Content-Length is invalid.", "invalid_request_error"
                    )
                    return
                if content_length > relay.max_request_bytes:
                    self._send_json_error(
                        413,
                        f"Request body ({content_length} bytes) exceeds worker max_request_bytes ({relay.max_request_bytes}).",
                        "request_too_large",
                    )
                    return

                raw_body = self.rfile.read(content_length)
                try:
                    parsed_body = json.loads(raw_body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self._send_json_error(
                        400, "Request body must be valid UTF-8 JSON.", "invalid_request_error"
                    )
                    return
                if not isinstance(parsed_body, dict):
                    self._send_json_error(
                        400, "Request body must be a JSON object.", "invalid_request_error"
                    )
                    return

                # Clamp n (and best_of when present) to 1 so worst-case output spend is bounded to 1 completion per request.
                if "n" in parsed_body:
                    parsed_body["n"] = 1
                if "best_of" in parsed_body:
                    parsed_body["best_of"] = 1

                # Clamp max_tokens and max_completion_tokens (and strip maxOutputTokens) on the forwarded payload.
                req_max_tok = parsed_body.get("max_tokens")
                req_max_out = parsed_body.pop("maxOutputTokens", None)
                if isinstance(req_max_tok, int) and not isinstance(req_max_tok, bool):
                    parsed_body["max_tokens"] = min(max(1, req_max_tok), relay.max_tokens_cap)
                elif isinstance(req_max_out, int) and not isinstance(req_max_out, bool):
                    parsed_body["max_tokens"] = min(max(1, req_max_out), relay.max_tokens_cap)
                else:
                    parsed_body["max_tokens"] = relay.max_tokens_cap

                req_max_comp = parsed_body.get("max_completion_tokens")
                if isinstance(req_max_comp, int) and not isinstance(req_max_comp, bool):
                    parsed_body["max_completion_tokens"] = min(
                        max(1, req_max_comp), relay.max_tokens_cap
                    )

                forwarded_bytes = json.dumps(parsed_body).encode("utf-8")
                if len(forwarded_bytes) > relay.max_request_bytes:
                    self._send_json_error(
                        413,
                        "Clamped request body exceeds worker max_request_bytes.",
                        "request_too_large",
                    )
                    return

                with relay._lock:
                    if relay.chat_requests_used >= relay.max_chat_requests:
                        self._send_json_error(
                            429,
                            f"Worker relay max_chat_requests ({relay.max_chat_requests}) reached.",
                            "rate_limit_error",
                        )
                        return
                    relay.chat_requests_used += 1

                self._forward_upstream("POST", "/v1/chat/completions", forwarded_bytes)

            def do_PUT(self) -> None:
                if not self._check_auth():
                    return
                self._send_json_error(405, "Method not allowed.", "method_not_allowed")

            def do_DELETE(self) -> None:
                if not self._check_auth():
                    return
                self._send_json_error(405, "Method not allowed.", "method_not_allowed")

            def _forward_upstream(
                self, method: str, path: str, body: bytes | None
            ) -> None:
                if not relay._inflight_sem.acquire(timeout=5.0):
                    self._send_json_error(
                        429,
                        "Too many concurrent worker relay requests.",
                        "rate_limit_error",
                    )
                    return
                conn = http.client.HTTPConnection(
                    relay.upstream_host,
                    relay.upstream_port,
                    timeout=relay.upstream_timeout_seconds,
                )
                headers_sent = False
                try:
                    up_headers: dict[str, str] = {
                        "Authorization": f"Bearer {relay._upstream_session_token}",
                        "Accept": self.headers.get("Accept", "application/json"),
                        "Connection": "close",
                    }
                    if body is not None:
                        up_headers["Content-Type"] = "application/json"
                        up_headers["Content-Length"] = str(len(body))
                    conn.request(method, path, body=body, headers=up_headers)
                    resp = conn.getresponse()
                    content_type = resp.getheader("Content-Type", "application/json")
                    is_sse = "text/event-stream" in content_type.lower()

                    self.send_response(resp.status)
                    headers_sent = True
                    self.send_header("Content-Type", content_type)
                    for pass_hdr in ("Retry-After", "x-request-id"):
                        hdr_val = resp.getheader(pass_hdr)
                        if hdr_val is not None:
                            self.send_header(pass_hdr, hdr_val)
                    if not is_sse:
                        up_cl = resp.getheader("Content-Length")
                        if up_cl is not None:
                            self.send_header("Content-Length", up_cl)
                    else:
                        self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "close")
                    self.end_headers()

                    total_read = 0
                    read_fn = getattr(resp, "read1", None)
                    while True:
                        chunk = read_fn(4096) if callable(read_fn) else resp.read(4096)
                        if not chunk:
                            break
                        total_read += len(chunk)
                        if total_read > relay.max_response_bytes:
                            if is_sse:
                                self.wfile.write(
                                    b'\ndata: {"error":{"message":"Response exceeded max_response_bytes","type":"response_truncated"}}\n\n'
                                )
                                self.wfile.flush()
                            break
                        self.wfile.write(chunk)
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    self.close_connection = True
                except Exception as exc:
                    self.close_connection = True
                    if not headers_sent:
                        try:
                            self._send_json_error(
                                502,
                                f"Upstream proxy error: {exc}",
                                "upstream_error",
                            )
                        except Exception:
                            pass
                finally:
                    relay._inflight_sem.release()
                    try:
                        conn.close()
                    except Exception:
                        pass

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="worker-token-relay",
            daemon=True,
        )
        self._thread.start()
        return self

    def close(self) -> None:
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
            except Exception:
                pass
            try:
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None


def check_pid_identity_state(pid: Any, expected_lstart: Any) -> str:
    if not pid_is_alive(pid):
        return "dead"
    if not isinstance(expected_lstart, str) or not expected_lstart.strip():
        return "unavailable"
    actual = get_process_lstart(pid)
    if actual is None:
        if not pid_is_alive(pid):
            return "dead"
        return "unavailable"
    if " ".join(actual.split()) == " ".join(expected_lstart.split()):
        return "verified"
    return "mismatch"


def _resolve_lsof_bin() -> str | None:
    for candidate in ("/usr/sbin/lsof", "/usr/bin/lsof"):
        if Path(candidate).is_file():
            return candidate
    return shutil.which("lsof")


def _pid_cwd_matches_variants(pid: int, iso_variants: Sequence[str]) -> tuple[bool, bool]:
    lsof_bin = _resolve_lsof_bin()
    if lsof_bin is None:
        return False, False
    try:
        proc = subprocess.run(
            [lsof_bin, "-a", "-p", str(pid), "-d", "cwd", "-Fn"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False, False

    err_text = (proc.stderr or "").strip()
    if proc.returncode != 0 or err_text:
        if not pid_is_alive(pid):
            return False, True
        return False, False

    current_pid: int | None = None
    for line in (proc.stdout or "").splitlines():
        if line.startswith("p") and line[1:].isdigit():
            current_pid = int(line[1:])
        elif line.startswith("n") and current_pid == pid:
            cwd_str = line[1:]
            if any(cwd_str == iv or cwd_str.startswith(f"{iv}/") for iv in iso_variants):
                return True, True
    return False, True


def _scan_worker_pids(
    *,
    worker_id: str | None = None,
    isolated_home: Path | None = None,
) -> tuple[dict[int, str], bool]:
    my_pid = os.getpid()
    markers: list[str] = []
    if worker_id:
        markers.append(f"LOCAL_ASSIST_WORKER_ID={worker_id}")
        markers.append(worker_id)
    if isolated_home is not None:
        for var in _dual_realpath_variants(isolated_home):
            if var not in markers:
                markers.append(var)

    if not markers:
        return {}, True

    uid_lstarts: dict[int, str] = {}
    ps_matched: dict[int, str] = {}
    ps_ok = False
    try:
        ps_env = dict(os.environ)
        ps_env["LC_ALL"] = "C"
        ps_env["TZ"] = "UTC"
        proc = subprocess.run(
            ["/bin/ps", "eww", "-U", str(os.getuid()), "-o", "pid=,lstart=,command="],
            env=ps_env,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0 and not (proc.stderr or "").strip():
            ps_ok = True
            for line in (proc.stdout or "").splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                parts = stripped.split(None, 6)
                if len(parts) < 7 or not parts[0].isdigit():
                    continue
                pid = int(parts[0])
                if pid <= 1:
                    continue
                row_lstart = " ".join(parts[1:6])
                uid_lstarts[pid] = row_lstart
                if pid == my_pid:
                    continue
                cmd_and_env = parts[6]
                if any(m in cmd_and_env for m in markers):
                    ps_matched[pid] = row_lstart
    except (OSError, subprocess.SubprocessError):
        ps_ok = False

    lsof_ok = isolated_home is None
    lsof_pids: set[int] = set()
    iso_variants: tuple[str, ...] = ()
    lsof_bin = _resolve_lsof_bin() if isolated_home is not None else None
    if isolated_home is not None and lsof_bin is not None:
        try:
            iso_variants = tuple(_dual_realpath_variants(isolated_home))
            lsof_proc = subprocess.run(
                [lsof_bin, "-a", "-u", str(os.getuid()), "-d", "cwd", "-Fn"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if lsof_proc.returncode == 0 and not (lsof_proc.stderr or "").strip():
                lsof_ok = True
            current_pid: int | None = None
            for line in (lsof_proc.stdout or "").splitlines():
                if line.startswith("p") and line[1:].isdigit():
                    current_pid = int(line[1:])
                elif line.startswith("n") and current_pid is not None:
                    cwd_str = line[1:]
                    if current_pid != my_pid and current_pid > 1 and any(
                        cwd_str == iv or cwd_str.startswith(f"{iv}/") for iv in iso_variants
                    ):
                        lsof_pids.add(current_pid)
        except (OSError, subprocess.SubprocessError):
            lsof_ok = False

    observer_ok = ps_ok and lsof_ok
    matched: dict[int, str] = {}

    for pid, row_lstart in sorted(ps_matched.items()):
        state = check_pid_identity_state(pid, row_lstart)
        if state == "verified":
            matched[pid] = row_lstart
        elif state == "unavailable":
            observer_ok = False

    for pid in sorted(lsof_pids):
        if pid in matched:
            continue
        pre_lstart = uid_lstarts.get(pid)
        if pre_lstart is not None:
            state = check_pid_identity_state(pid, pre_lstart)
            if state == "verified":
                matched[pid] = pre_lstart
                continue
            if state == "dead":
                continue
            if state == "unavailable":
                observer_ok = False
                continue

        # PID was either spawned after the ps snapshot or reused after ps.
        # Bracket a single-PID cwd observation with identical lstart checks before and after.
        lstart_before = get_process_lstart(pid)
        if lstart_before is None:
            if pid_is_alive(pid):
                observer_ok = False
            continue
        cwd_matched, cwd_obs_ok = _pid_cwd_matches_variants(pid, iso_variants)
        if not cwd_obs_ok:
            observer_ok = False
            continue
        if not cwd_matched:
            continue
        state_after = check_pid_identity_state(pid, lstart_before)
        if state_after == "verified":
            matched[pid] = lstart_before
        elif state_after == "unavailable":
            observer_ok = False

    return matched, observer_ok


def _find_worker_pids(
    *,
    worker_id: str | None = None,
    isolated_home: Path | None = None,
) -> list[int]:
    matched, _ = _scan_worker_pids(worker_id=worker_id, isolated_home=isolated_home)
    return sorted(matched.keys())


def reap_worker_processes_detailed(
    *,
    worker_id: str | None = None,
    isolated_home: Path | None = None,
    max_passes: int = 4,
    grace_seconds: float = 0.5,
) -> tuple[list[int], bool]:
    reaped_set: set[int] = set()
    all_observers_ok = True

    for _ in range(max(1, int(max_passes))):
        matched, obs_ok = _scan_worker_pids(
            worker_id=worker_id,
            isolated_home=isolated_home,
        )
        if not obs_ok:
            all_observers_ok = False
        if not matched:
            break

        term_targets: dict[int, str] = {}
        for pid, expected_lstart in matched.items():
            state = check_pid_identity_state(pid, expected_lstart)
            if state == "verified":
                try:
                    os.kill(pid, signal.SIGTERM)
                    term_targets[pid] = expected_lstart
                    reaped_set.add(pid)
                except OSError:
                    pass
            elif state == "unavailable":
                all_observers_ok = False

        if term_targets:
            deadline = time.monotonic() + max(0.05, float(grace_seconds))
            while time.monotonic() < deadline:
                still_alive = False
                for pid, expected_lstart in term_targets.items():
                    if check_pid_identity_state(pid, expected_lstart) in (
                        "verified",
                        "unavailable",
                    ):
                        still_alive = True
                        break
                if not still_alive:
                    break
                time.sleep(0.05)

            for pid, expected_lstart in term_targets.items():
                state = check_pid_identity_state(pid, expected_lstart)
                if state == "verified":
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except OSError:
                        pass
                elif state == "unavailable":
                    all_observers_ok = False

        post_kill_deadline = time.monotonic() + 0.25
        while time.monotonic() < post_kill_deadline:
            any_alive = any(
                check_pid_identity_state(pid, expected_lstart) == "verified"
                for pid, expected_lstart in term_targets.items()
            )
            if not any_alive:
                break
            time.sleep(0.03)

    final_matched, final_obs_ok = _scan_worker_pids(
        worker_id=worker_id,
        isolated_home=isolated_home,
    )
    if not final_obs_ok:
        all_observers_ok = False
    clean = all_observers_ok and len(final_matched) == 0
    return sorted(reaped_set), clean


def reap_worker_processes(
    *,
    worker_id: str | None = None,
    isolated_home: Path | None = None,
) -> list[int]:
    reaped, _ = reap_worker_processes_detailed(
        worker_id=worker_id,
        isolated_home=isolated_home,
    )
    return reaped


def _open_dir_chain_nofollow(base_dir: Path, rel_parts: Sequence[str]) -> int | None:
    try:
        base_st = os.lstat(base_dir)
    except OSError:
        return None
    if stat.S_ISLNK(base_st.st_mode) or not stat.S_ISDIR(base_st.st_mode):
        return None
    dir_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
    try:
        cur_fd = os.open(base_dir, dir_flags)
    except OSError:
        return None
    try:
        cur_st = os.fstat(cur_fd)
        if not stat.S_ISDIR(cur_st.st_mode) or (cur_st.st_dev, cur_st.st_ino) != (
            base_st.st_dev,
            base_st.st_ino,
        ):
            os.close(cur_fd)
            return None
        for part in rel_parts:
            if not part or part in (".", "..") or "/" in part or "\\" in part:
                os.close(cur_fd)
                return None
            next_fd = os.open(part, dir_flags, dir_fd=cur_fd)
            os.close(cur_fd)
            cur_fd = next_fd
            if not stat.S_ISDIR(os.fstat(cur_fd).st_mode):
                os.close(cur_fd)
                return None
        return cur_fd
    except OSError:
        try:
            os.close(cur_fd)
        except OSError:
            pass
        return None


def _read_regular_file_nofollow(
    path: Path,
    *,
    root_real: Path,
    root_dir_fd: int | None = None,
    max_bytes: int = MAX_HARVEST_LOG_BYTES,
) -> str | None:
    rel_parts: tuple[str, ...] | None = None
    for candidate_root in (root_real, *(Path(v) for v in _dual_realpath_variants(root_real))):
        try:
            rel = path.relative_to(candidate_root)
            rel_parts = rel.parts
            break
        except ValueError:
            continue
    if not rel_parts:
        return None
    for part in rel_parts:
        if not part or part in (".", "..") or "/" in part or "\\" in part:
            return None

    owns_root_fd = False
    base_fd = root_dir_fd
    if base_fd is None:
        base_fd = _open_dir_chain_nofollow(root_real, ())
        if base_fd is None:
            return None
        owns_root_fd = True

    dir_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    cur_fd = base_fd
    file_fd: int | None = None
    try:
        for part in rel_parts[:-1]:
            next_fd = os.open(part, dir_flags, dir_fd=cur_fd)
            if cur_fd != base_fd:
                os.close(cur_fd)
            cur_fd = next_fd
            if not stat.S_ISDIR(os.fstat(cur_fd).st_mode):
                return None
        file_fd = os.open(rel_parts[-1], file_flags, dir_fd=cur_fd)
        st = os.fstat(file_fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        if st.st_size < 0 or st.st_size > max_bytes:
            return None
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(file_fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                return None
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    finally:
        if file_fd is not None:
            try:
                os.close(file_fd)
            except OSError:
                pass
        if cur_fd != base_fd:
            try:
                os.close(cur_fd)
            except OSError:
                pass
        if owns_root_fd:
            try:
                os.close(base_fd)
            except OSError:
                pass


def _rewrite_harvested_payload_path(raw_path: Any, worker_id: str) -> str | None:
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None
    cleaned = raw_path.strip().replace("\\", "/")
    marker = "runs/local-assist/"
    if cleaned.startswith(marker):
        rel_after = cleaned[len(marker) :].lstrip("/")
    else:
        parts = [p for p in cleaned.split("/") if p and p not in (".", "..")]
        if len(parts) >= 2:
            rel_after = "/".join(parts[-2:])
        elif parts:
            rel_after = parts[-1]
        else:
            return None
    if not rel_after or ".." in rel_after.split("/"):
        return None
    return f"runs/local-assist/worker-sandbox/{worker_id}/{rel_after}"


def harvest_worker_local_assist_logs(
    *,
    isolated_home: Path,
    worker_id: str,
) -> Path | None:
    # Reject symlinks anywhere along the staging chain and open the staging root via
    # descriptor-relative O_NOFOLLOW traversal (WORK-MAJOR-3, R2-MAJOR-4, F4, F10).
    for ancestor in (
        isolated_home,
        isolated_home / ".local",
        isolated_home / ".local" / "share",
        isolated_home / ".local" / "share" / "local-assist-runs",
    ):
        try:
            st = os.lstat(ancestor)
        except OSError:
            return None
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            return None

    staging_root = isolated_home / ".local" / "share" / "local-assist-runs"
    try:
        staging_real = staging_root.resolve(strict=True)
        iso_real = isolated_home.resolve(strict=True)
    except OSError:
        return None
    if not staging_real.is_relative_to(iso_real):
        return None

    staging_fd = _open_dir_chain_nofollow(
        isolated_home,
        (".local", "share", "local-assist-runs"),
    )
    if staging_fd is None:
        return None

    try:
        json_files: list[Path] = []
        jsonl_files: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(staging_root, topdown=True, followlinks=False):
            dp = Path(dirpath)
            if dp.is_symlink():
                dirnames[:] = []
                continue
            safe_dirs: list[str] = []
            for dname in dirnames:
                sub_p = dp / dname
                try:
                    sub_st = os.lstat(sub_p)
                except OSError:
                    continue
                if not stat.S_ISLNK(sub_st.st_mode) and stat.S_ISDIR(sub_st.st_mode):
                    safe_dirs.append(dname)
            dirnames[:] = sorted(safe_dirs)
            for fname in sorted(filenames):
                fp = dp / fname
                try:
                    fp_st = os.lstat(fp)
                except OSError:
                    continue
                if stat.S_ISLNK(fp_st.st_mode) or not stat.S_ISREG(fp_st.st_mode):
                    continue
                if fname.endswith(".json"):
                    json_files.append(fp)
                elif fname.endswith(".jsonl") and dp == staging_root:
                    jsonl_files.append(fp)

        if not json_files and not jsonl_files:
            return None

        dest_root: Path | None = None

        for jf in json_files:
            raw_text = _read_regular_file_nofollow(
                jf,
                root_real=staging_root,
                root_dir_fd=staging_fd,
            )
            if raw_text is None:
                continue
            try:
                rel = jf.relative_to(staging_root)
                raw_obj = json.loads(raw_text)
                if not isinstance(raw_obj, dict):
                    continue
                raw_obj["sandbox_untrusted_source"] = True
                raw_obj["worker_id"] = worker_id
                raw_obj["worker_sandbox_preverified"] = True
                if "payload_path" in raw_obj:
                    raw_obj["original_sandbox_payload_path"] = raw_obj["payload_path"]
                raw_obj["payload_path"] = (
                    f"runs/local-assist/worker-sandbox/{worker_id}/{rel.as_posix()}"
                )
                if dest_root is None:
                    dest_root = WORKER_SANDBOX_LOG_ROOT / worker_id
                    dest_root.mkdir(parents=True, exist_ok=True)
                target = dest_root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(
                    json.dumps(raw_obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
                )
            except (OSError, ValueError, json.JSONDecodeError):
                continue

        for jlf in jsonl_files:
            raw_text = _read_regular_file_nofollow(
                jlf,
                root_real=staging_root,
                root_dir_fd=staging_fd,
            )
            if raw_text is None:
                continue
            try:
                valid_rows: list[str] = []
                for line in raw_text.splitlines():
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        continue
                    row["sandbox_untrusted_source"] = True
                    row["worker_id"] = worker_id
                    row["worker_sandbox_preverified"] = True
                    rewritten_pp = _rewrite_harvested_payload_path(
                        row.get("payload_path"), worker_id
                    )
                    if rewritten_pp is not None:
                        row["original_sandbox_payload_path"] = row.get("payload_path")
                        row["payload_path"] = rewritten_pp
                    valid_rows.append(json.dumps(row, ensure_ascii=False))
                if valid_rows:
                    if dest_root is None:
                        dest_root = WORKER_SANDBOX_LOG_ROOT / worker_id
                        dest_root.mkdir(parents=True, exist_ok=True)
                    target_index = dest_root / jlf.name
                    existing_lines: set[str] = set()
                    if target_index.is_file():
                        try:
                            existing_lines = {
                                ln.strip()
                                for ln in target_index.read_text(encoding="utf-8").splitlines()
                                if ln.strip()
                            }
                        except OSError:
                            existing_lines = set()
                    new_rows: list[str] = []
                    for r_str in valid_rows:
                        if r_str not in existing_lines:
                            new_rows.append(r_str)
                            existing_lines.add(r_str)
                    if new_rows:
                        with target_index.open("a", encoding="utf-8") as handle:
                            for r_str in new_rows:
                                handle.write(r_str + "\n")
            except (OSError, ValueError, json.JSONDecodeError):
                continue

        return dest_root
    finally:
        try:
            os.close(staging_fd)
        except OSError:
            pass


def _safe_rmtree_fd(dir_fd: int) -> bool:
    dir_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
    try:
        os.fchmod(dir_fd, 0o700)
    except OSError:
        pass
    ok = True
    try:
        with os.scandir(dir_fd) as it:
            entries = list(it)
    except OSError:
        return False

    for entry in entries:
        name = entry.name
        if not name or name in (".", ".."):
            continue
        try:
            os.unlink(name, dir_fd=dir_fd)
            continue
        except FileNotFoundError:
            continue
        except (IsADirectoryError, PermissionError) as exc:
            err_no = getattr(exc, "errno", None)
            if isinstance(exc, PermissionError) and err_no not in (
                errno.EPERM,
                errno.EISDIR,
                errno.EACCES,
            ):
                ok = False
                continue
        except OSError:
            ok = False
            continue

        # Entry is a directory (or racing symlink replacement). Open descriptor-relatively with O_NOFOLLOW | O_DIRECTORY.
        sub_fd: int | None = None
        try:
            sub_fd = os.open(name, dir_flags, dir_fd=dir_fd)
            sub_st = os.fstat(sub_fd)
            if not stat.S_ISDIR(sub_st.st_mode):
                ok = False
                continue
            if not _safe_rmtree_fd(sub_fd):
                ok = False
        except FileNotFoundError:
            continue
        except OSError as exc:
            if getattr(exc, "errno", None) in (errno.ELOOP, errno.ENOTDIR):
                try:
                    os.unlink(name, dir_fd=dir_fd)
                    continue
                except FileNotFoundError:
                    continue
                except OSError:
                    ok = False
                    continue
            ok = False
            continue
        finally:
            if sub_fd is not None:
                try:
                    os.close(sub_fd)
                except OSError:
                    pass

        try:
            os.rmdir(name, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        except OSError:
            ok = False

    return ok


def _safe_rmtree_nofollow(root: Path) -> bool:
    try:
        st = os.lstat(root)
    except FileNotFoundError:
        return True
    except OSError:
        return False

    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return False

    dir_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
    root_fd: int | None = None
    try:
        root_fd = os.open(root, dir_flags)
        fd_st = os.fstat(root_fd)
        if not stat.S_ISDIR(fd_st.st_mode) or (fd_st.st_dev, fd_st.st_ino) != (
            st.st_dev,
            st.st_ino,
        ):
            return False
        if not _safe_rmtree_fd(root_fd):
            return False
    except OSError:
        return False
    finally:
        if root_fd is not None:
            try:
                os.close(root_fd)
            except OSError:
                pass

    try:
        post_st = os.lstat(root)
        if stat.S_ISLNK(post_st.st_mode) or (post_st.st_dev, post_st.st_ino) != (
            st.st_dev,
            st.st_ino,
        ):
            return False
        os.rmdir(root)
        return not root.exists()
    except FileNotFoundError:
        return True
    except OSError:
        return False


UNCONFIRMED_GROUP_FILENAME = ".unconfirmed-process-group.json"


def _write_unconfirmed_group_marker(isolated_home: Path, owned_pgid: int | None) -> bool:
    try:
        st = os.lstat(isolated_home)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return False
    marker = isolated_home / UNCONFIRMED_GROUP_FILENAME
    try:
        if marker.is_symlink():
            marker.unlink()
        elif marker.exists():
            try:
                os.chmod(marker, 0o600)
            except OSError:
                pass
        payload = {
            "pgid": (
                int(owned_pgid)
                if isinstance(owned_pgid, int)
                and not isinstance(owned_pgid, bool)
                and owned_pgid > 1
                else None
            ),
            "recorded_at": time.time(),
        }
        marker.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        os.chmod(marker, 0o400)
        return True
    except OSError:
        try:
            mst = os.lstat(marker)
            if not stat.S_ISLNK(mst.st_mode) and stat.S_ISREG(mst.st_mode):
                return True
        except OSError:
            pass
        return False


def _clear_unconfirmed_group_marker(isolated_home: Path) -> bool:
    marker = isolated_home / UNCONFIRMED_GROUP_FILENAME
    try:
        os.lstat(marker)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    try:
        os.chmod(marker, 0o600)
    except OSError:
        pass
    try:
        marker.unlink()
        return True
    except FileNotFoundError:
        return True
    except OSError:
        return False


def _check_persisted_unconfirmed_group(isolated_home: Path) -> bool:
    marker = isolated_home / UNCONFIRMED_GROUP_FILENAME
    try:
        st = os.lstat(marker)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return False
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(data, dict):
        return False
    pgid = data.get("pgid")
    if not isinstance(pgid, int) or isinstance(pgid, bool) or pgid <= 1:
        return False
    if _process_group_alive(pgid):
        return False
    return _clear_unconfirmed_group_marker(isolated_home)


def teardown_worker_home(
    isolated_home: Path,
    *,
    worker_id: str | None = None,
    harvest_logs: bool = False,
    remove_home: bool = True,
    reap_processes: bool = True,
    group_clean: bool = True,
    owned_pgid: int | None = None,
) -> dict[str, Any]:
    effective_group_clean = bool(group_clean)
    if not effective_group_clean:
        _write_unconfirmed_group_marker(isolated_home, owned_pgid)
    elif isolated_home.exists() and not isolated_home.is_symlink():
        if owned_pgid is not None:
            effective_group_clean = _clear_unconfirmed_group_marker(isolated_home)
        else:
            effective_group_clean = _check_persisted_unconfirmed_group(isolated_home)

    reaped_pids: list[int] = []
    reaper_clean = True
    if reap_processes:
        reaped_pids, reaper_clean = reap_worker_processes_detailed(
            worker_id=worker_id,
            isolated_home=isolated_home,
        )

    effective_reaper_clean = (reaper_clean if reap_processes else True) and effective_group_clean

    harvested_dir: Path | None = None
    if harvest_logs and worker_id and isolated_home.exists():
        try:
            harvested_dir = harvest_worker_local_assist_logs(
                isolated_home=isolated_home,
                worker_id=worker_id,
            )
        except Exception:
            harvested_dir = None

    removed = False
    if remove_home:
        if not isolated_home.exists() and not isolated_home.is_symlink():
            removed = True
        elif effective_reaper_clean:
            removed = _safe_rmtree_nofollow(isolated_home)
        else:
            # Preserve isolated_home on disk when process observation/reaping or owned
            # process-group termination is incomplete so subsequent sweeps retain recovery
            # evidence (F6/F7, R2-F3, P2-PLAN-MAJOR-1, P3-PLAN-MINOR-1).
            removed = False

    clean = effective_reaper_clean and (removed if remove_home else True)
    return {
        "reaped_pids": reaped_pids,
        "group_clean": effective_group_clean,
        "reaper_clean": effective_reaper_clean,
        "harvested_dir": harvested_dir,
        "removed": removed,
        "clean": clean,
    }


def cleanup_worker_home(
    isolated_home: Path,
    *,
    worker_id: str | None = None,
    harvest_logs: bool = False,
) -> bool:
    res = teardown_worker_home(
        isolated_home,
        worker_id=worker_id,
        harvest_logs=harvest_logs,
        remove_home=True,
        reap_processes=True,
    )
    return bool(res["clean"])


def _process_group_alive(pgid: int) -> bool:
    if pgid <= 1:
        return False
    try:
        os.killpg(pgid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def _terminate_process_group(
    proc: subprocess.Popen[Any],
    *,
    grace_seconds: float = 2.0,
) -> bool:
    pgid = proc.pid
    if pgid <= 1:
        try:
            proc.wait(timeout=1.0)
        except Exception:
            pass
        return proc.poll() is not None

    if proc.poll() is None or _process_group_alive(pgid):
        try:
            os.killpg(pgid, signal.SIGTERM)
        except OSError:
            pass

        deadline = time.monotonic() + max(0.05, float(grace_seconds))
        while time.monotonic() < deadline:
            if proc.poll() is not None and not _process_group_alive(pgid):
                break
            time.sleep(0.05)

        if proc.poll() is None or _process_group_alive(pgid):
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                pass
            kill_deadline = time.monotonic() + 1.0
            while time.monotonic() < kill_deadline and _process_group_alive(pgid):
                time.sleep(0.02)

    try:
        proc.wait(timeout=1.0)
    except Exception:
        pass
    return proc.poll() is not None and not _process_group_alive(pgid)


def run_worker_sandbox_lifecycle(
    cmd: Sequence[str],
    *,
    cwd: str | Path,
    env: Mapping[str, str],
    isolated_home: Path,
    worker_id: str,
    harvest_logs: bool = False,
    remove_home: bool = True,
    reap_processes: bool = True,
    relay: _WorkerTokenRelay | None = None,
    grace_seconds: float = 2.0,
    popen_factory: Any = None,
    pre_teardown_hook: Callable[[], None] | None = None,
    teardown_fn: Callable[[bool, int | None], dict[str, Any]] | None = None,
) -> tuple[int, dict[str, Any]]:
    actual_popen = popen_factory if popen_factory is not None else subprocess.Popen
    cancel_state: dict[str, Any] = {
        "signum": None,
        "proc": None,
        "in_teardown": False,
    }
    prev_handlers: dict[int, Any] = {}

    def _on_signal(signum: int, _frame: Any) -> None:
        if cancel_state["signum"] is None:
            cancel_state["signum"] = signum
        proc_ref = cancel_state.get("proc")
        if proc_ref is not None and not cancel_state["in_teardown"]:
            try:
                os.killpg(proc_ref.pid, signal.SIGTERM)
            except OSError:
                pass

    for sig in (signal.SIGTERM, signal.SIGHUP):
        try:
            prev_handlers[sig] = signal.getsignal(sig)
            signal.signal(sig, _on_signal)
        except (OSError, ValueError):
            pass

    exit_code = 1
    group_clean = True
    owned_pgid: int | None = None
    teardown_res: dict[str, Any] = {
        "reaped_pids": [],
        "group_clean": False,
        "reaper_clean": False,
        "harvested_dir": None,
        "removed": False,
        "clean": False,
    }
    try:
        try:
            if cancel_state["signum"] is not None:
                exit_code = 128 + int(cancel_state["signum"])
            elif teardown_fn is None and not _write_unconfirmed_group_marker(isolated_home, None):
                group_clean = False
                exit_code = 1
            else:
                proc = actual_popen(
                    list(cmd),
                    cwd=str(cwd),
                    env=dict(env),
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )
                cancel_state["proc"] = proc
                owned_pgid = proc.pid
                if teardown_fn is None:
                    _write_unconfirmed_group_marker(isolated_home, owned_pgid)
                if cancel_state["signum"] is not None:
                    group_clean = _terminate_process_group(proc, grace_seconds=grace_seconds)
                    exit_code = 128 + int(cancel_state["signum"])
                else:
                    while True:
                        if cancel_state["signum"] is not None:
                            group_clean = _terminate_process_group(proc, grace_seconds=grace_seconds)
                            exit_code = 128 + int(cancel_state["signum"])
                            break
                        rc = proc.poll()
                        if rc is not None:
                            if cancel_state["signum"] is not None:
                                group_clean = _terminate_process_group(
                                    proc, grace_seconds=grace_seconds
                                )
                                exit_code = 128 + int(cancel_state["signum"])
                            else:
                                exit_code = int(rc)
                            break
                        time.sleep(0.03)
        finally:
            cancel_state["in_teardown"] = True
            proc_ref = cancel_state.get("proc")
            if proc_ref is not None:
                group_clean = _terminate_process_group(
                    proc_ref, grace_seconds=grace_seconds
                ) and group_clean
            if pre_teardown_hook is not None:
                try:
                    pre_teardown_hook()
                except Exception:
                    pass
            if relay is not None:
                relay.close()
            if teardown_fn is not None:
                teardown_res = teardown_fn(group_clean, owned_pgid)
            else:
                if not remove_home and worker_id:
                    try:
                        (isolated_home / ".keep-worker-home").write_text(
                            "1\n", encoding="utf-8"
                        )
                    except OSError:
                        pass
                teardown_res = teardown_worker_home(
                    isolated_home,
                    worker_id=worker_id or None,
                    harvest_logs=harvest_logs,
                    remove_home=remove_home,
                    reap_processes=reap_processes,
                    group_clean=group_clean,
                    owned_pgid=owned_pgid,
                )
            if cancel_state["signum"] is not None and exit_code == 0:
                exit_code = 128 + int(cancel_state["signum"])
            if not teardown_res.get("clean", False) and exit_code == 0:
                exit_code = 1
    finally:
        for sig, prev in prev_handlers.items():
            try:
                signal.signal(sig, prev)
            except (OSError, ValueError):
                pass

    return exit_code, teardown_res


def run_worker_sandbox_process(
    cmd: Sequence[str],
    *,
    cwd: str | Path,
    env: Mapping[str, str],
    grace_seconds: float = 2.0,
    popen_factory: Any = subprocess.Popen,
    teardown_callback: Callable[[], None] | None = None,
) -> int:
    def _callback_only_teardown(group_ok: bool, _pgid: int | None) -> dict[str, Any]:
        if teardown_callback is not None:
            teardown_callback()
        return {
            "reaped_pids": [],
            "group_clean": bool(group_ok),
            "reaper_clean": bool(group_ok),
            "harvested_dir": None,
            "removed": False,
            "clean": bool(group_ok),
        }

    exit_code, _ = run_worker_sandbox_lifecycle(
        cmd,
        cwd=cwd,
        env=env,
        isolated_home=Path(cwd),
        worker_id="",
        harvest_logs=False,
        remove_home=False,
        reap_processes=False,
        grace_seconds=grace_seconds,
        popen_factory=popen_factory,
        teardown_fn=_callback_only_teardown,
    )
    return exit_code


def _worker_home_owner_state(child: Path) -> str:
    owner_meta_path = child / ".worker-owner.json"
    owner_pid: int | None = None
    owner_lstart: str | None = None
    meta_read_error = False
    if owner_meta_path.exists() or owner_meta_path.is_symlink():
        if owner_meta_path.is_symlink() or not owner_meta_path.is_file():
            return "unavailable"
        try:
            meta = json.loads(owner_meta_path.read_text(encoding="utf-8"))
            if isinstance(meta, dict):
                raw_pid = meta.get("owner_pid")
                if isinstance(raw_pid, int) and not isinstance(raw_pid, bool) and raw_pid > 1:
                    owner_pid = raw_pid
                raw_lstart = meta.get("owner_pid_lstart")
                if isinstance(raw_lstart, str) and raw_lstart.strip():
                    owner_lstart = raw_lstart.strip()
            else:
                meta_read_error = True
        except (OSError, json.JSONDecodeError):
            meta_read_error = True

    if owner_pid is None:
        parts = child.name.split("-")
        if len(parts) >= 3 and parts[1].isdigit():
            owner_pid = int(parts[1])

    if owner_pid is None or owner_pid <= 1:
        return "unavailable" if meta_read_error else "dead"

    if owner_lstart is not None:
        return check_pid_identity_state(owner_pid, owner_lstart)

    if pid_is_alive(owner_pid):
        return "unavailable"
    return "dead"


def _is_worker_home_owner_alive(child: Path) -> bool:
    # Treat both "verified" and "unavailable" (where the owner PID is alive in the kernel
    # but `ps` start-time observation failed or timed out) as active so an active worker home
    # is never swept during transient observer failure (F7).
    return _worker_home_owner_state(child) in ("verified", "unavailable")


def sweep_stale_worker_homes_detailed(
    max_age_seconds: int = STALE_WORKER_HOME_MAX_AGE_SECONDS,
) -> dict[str, list[Path]]:
    result: dict[str, list[Path]] = {
        "removed": [],
        "skipped_active": [],
        "incomplete": [],
    }
    if not WORKER_HOMES_DIR.is_dir():
        return result
    now = time.time()
    for child in sorted(WORKER_HOMES_DIR.iterdir()):
        if child.is_symlink() or not child.is_dir() or not child.name.startswith("worker-"):
            continue
        # Never reap or remove a worker home whose owner is alive or whose identity observation is unavailable (WORK-MAJOR-8, F7).
        if _is_worker_home_owner_alive(child):
            result["skipped_active"].append(child)
            continue
        try:
            age = now - child.stat().st_mtime
        except OSError:
            age = max_age_seconds + 1
        keep_marker = child / ".keep-worker-home"
        if keep_marker.exists() and age < max_age_seconds:
            result["skipped_active"].append(child)
            continue
        if age >= max_age_seconds or not keep_marker.exists():
            teardown = teardown_worker_home(
                child,
                worker_id=child.name,
                harvest_logs=True,
                remove_home=True,
                reap_processes=True,
            )
            if teardown["clean"] and teardown["removed"]:
                result["removed"].append(child)
            else:
                result["incomplete"].append(child)
    return result


def sweep_stale_worker_homes(
    max_age_seconds: int = STALE_WORKER_HOME_MAX_AGE_SECONDS,
) -> list[Path]:
    return sweep_stale_worker_homes_detailed(max_age_seconds=max_age_seconds)["removed"]
