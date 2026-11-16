from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Sequence
from urllib.parse import urlparse

from .errors import LocalAssistError
from .relay import SessionAuthRelay
from .registry import (
    BASE_SAFE_ENV_ALLOWLIST,
    LAUNCHER_EXTRA_ENV_ALLOWLIST,
    EndpointConfig,
    _effective_runs_dir,
    get_process_lstart,
    is_model_effectively_deprecated,
    list_pid_records,
    pid_is_alive,
    pid_is_zombie,
    read_pid_record_for_model,
)
from .security_profile import (
    SecurityProfileError,
    WorkerSecurityProfile,
    _WorkerTokenRelay,
    _allocate_loopback_ephemeral_port,
    _dual_realpath_variants,
    _locate_host_node_binary,
    _provision_dedicated_local_assist_python,
    _safe_rmtree_nofollow,
    _stage_credential_guard_plugin,
    allocate_worker_home,
    apply_cli_overrides,
    build_worker_environment,
    check_pid_identity_state,
    check_tracked_protected_files,
    compile_interactive_seatbelt_profile,
    compile_opencode_security_config,
    compile_seatbelt_profile,
    default_unattended_worker_profile,
    load_security_profile,
    reap_worker_processes_detailed,
    redact_session_tokens,
    run_worker_sandbox_lifecycle,
    sweep_stale_worker_homes,
    teardown_worker_home,
    validate_worker_opencode_args,
    verify_opencode_version,
    write_verified_local_models_handoff,
    write_worker_runtime_artifacts,
)

EXIT_MODEL_MISMATCH = 3
SAFE_ENV_ALLOWLIST = tuple(sorted(BASE_SAFE_ENV_ALLOWLIST | LAUNCHER_EXTRA_ENV_ALLOWLIST))

INTERACTIVE_MIN_CHAT_REQUESTS = 200
INTERACTIVE_MIN_MAX_TOKENS = 8192
INTERACTIVE_MIN_REQUEST_BYTES = 2 * 1024 * 1024


def json_escape(val: Any) -> str:
    return json.dumps(str(val))[1:-1]


def check_endpoint_lifecycle_status(
    endpoint: EndpointConfig,
    *,
    allow_deprecated_model: bool = False,
    err_stream: Any = None,
) -> None:
    if endpoint.status == "archived":
        raise LocalAssistError(
            "model_archived",
            f"Refusing to launch archived model '{endpoint.model_id}' (status='archived' in models.yaml).",
            details={
                "model_id": endpoint.model_id,
                "status": endpoint.status,
            },
        )
    if is_model_effectively_deprecated(endpoint.deprecated, endpoint.deprecation_date):
        dep_suffix = (
            f" (deprecation_date={endpoint.deprecation_date})"
            if endpoint.deprecation_date
            else ""
        )
        if not allow_deprecated_model:
            raise LocalAssistError(
                "model_deprecated",
                f"Refusing to launch deprecated model '{endpoint.model_id}'{dep_suffix}. "
                "Select an active replacement model (for example 'tinfoil-kimi-k3-1-pro') "
                "or pass --allow-deprecated-model to override.",
                details={
                    "model_id": endpoint.model_id,
                    "deprecated": endpoint.deprecated,
                    "deprecation_date": endpoint.deprecation_date,
                },
            )
        out = err_stream if err_stream is not None else sys.stderr
        print(
            f"WARNING: Running with deprecated model '{endpoint.model_id}'{dep_suffix}.",
            file=out,
        )


def add_common_launcher_arguments(
    parser: argparse.ArgumentParser,
    *,
    default_output_limit: int,
    default_wait_seconds: float,
    wait_help: str,
    no_serve_help: str,
    print_config_help: str,
    unattended_help: str,
) -> None:
    parser.add_argument(
        "--allow-deprecated-model",
        action="store_true",
        default=False,
        help="Allow launching a model marked deprecated: true or with deprecation_date set in models.yaml.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Override the localhost port for this model session (1024..64535).",
    )
    parser.add_argument(
        "--output-limit",
        type=int,
        default=default_output_limit,
        help=f"Max output tokens per turn in opencode config (default: {default_output_limit}).",
    )
    parser.add_argument(
        "--allow-edit",
        action="store_true",
        default=False,
        help="Set edit/write/patch permissions to 'allow' instead of 'ask' (for non-interactive runs).",
    )
    parser.add_argument(
        "--allow-bash",
        action="store_true",
        default=False,
        help="Set bash/shell permission to 'allow' instead of 'ask' in interactive/CLI runs.",
    )
    parser.add_argument(
        "--allow-shell-localhost-port",
        type=int,
        action="append",
        default=None,
        help="Allow interactive sandbox child processes to connect to an unreserved localhost TCP port (repeatable).",
    )
    parser.add_argument(
        "--allow-ssh-remote",
        action="store_true",
        default=False,
        help="Allow interactive sandbox child processes to make outbound SSH connections (TCP port 22 + DNS).",
    )
    parser.add_argument(
        "--allow-self-edit",
        action="store_true",
        default=False,
        help="Allow interactive sessions to edit lab runtime files (local_assist/, scripts/, config/, models.yaml).",
    )
    parser.add_argument(
        "--wait",
        type=float,
        default=default_wait_seconds,
        help=wait_help,
    )
    parser.add_argument(
        "--no-serve",
        action="store_true",
        default=False,
        help=no_serve_help,
    )
    parser.add_argument(
        "--refresh-session",
        "--restart",
        dest="refresh_session",
        action="store_true",
        default=False,
        help="Stop any active session for the target model and start a fresh session (for example a fresh 12-hour Touch ID session).",
    )
    parser.add_argument(
        "--preserve-host-home",
        action="store_true",
        default=False,
        help="Keep parent HOME for child shell commands while isolating XDG_* and OPENCODE_TEST_HOME.",
    )
    parser.add_argument(
        "--print-config",
        action="store_true",
        default=False,
        help=print_config_help,
    )
    parser.add_argument(
        "--security-profile",
        default=None,
        help="Path to a YAML or JSON worker security profile enforcing Seatbelt and OpenCode tool/MCP boundaries.",
    )
    parser.add_argument(
        "--unattended-worker",
        action="store_true",
        default=False,
        help=unattended_help,
    )
    parser.add_argument(
        "--read-root",
        action="append",
        default=None,
        help="Override filesystem.read_roots in the worker security profile (repeatable).",
    )
    parser.add_argument(
        "--write-root",
        action="append",
        default=None,
        help="Override filesystem.write_roots in the worker security profile (repeatable).",
    )
    parser.add_argument(
        "--protect-path",
        action="append",
        default=None,
        help="Append to filesystem.protected_paths in the worker security profile (repeatable).",
    )
    parser.add_argument(
        "--allow-tool",
        action="append",
        default=None,
        help="Override tools.allowed_tools in the worker security profile (repeatable).",
    )
    parser.add_argument(
        "--deny-tool",
        action="append",
        default=None,
        help="Append to tools.denied_tools in the worker security profile (repeatable).",
    )
    parser.add_argument(
        "--allow-mcp-tool",
        action="append",
        default=None,
        help="Append '<server>_<tool>' pattern to mcp.allowed_tools in the worker security profile (repeatable).",
    )
    parser.add_argument(
        "--deny-mcp-tool",
        action="append",
        default=None,
        help="Append '<server>_<tool>' pattern to mcp.denied_tools in the worker security profile (repeatable).",
    )
    parser.add_argument(
        "--allow-subagents",
        action="store_true",
        default=False,
        help="Allow native OpenCode subagents (task/subagent tools) in interactive or worker sessions (default: disabled).",
    )
    parser.add_argument(
        "--allow-ssh-agent",
        action="store_true",
        default=False,
        help="Allow SSH_AUTH_SOCK forwarding into the worker sandbox.",
    )
    parser.add_argument(
        "--allow-localhost-port",
        type=int,
        action="append",
        default=None,
        help="Allow worker-shell child processes to connect to an unreserved localhost TCP port (repeatable).",
    )
    parser.add_argument(
        "--pass-env",
        action="append",
        default=None,
        help="Append a non-secret, unreserved environment variable name to environment.allowlist (repeatable).",
    )
    parser.add_argument(
        "--keep-worker-home",
        action="store_true",
        default=False,
        help="Preserve the per-invocation worker home directory under .home/workers/ after exit for inspection.",
    )
    parser.add_argument(
        "--allow-opencode-version-drift",
        action="store_true",
        default=False,
        help="Allow running unattended worker mode when the installed opencode version differs from the tested version.",
    )


def split_launcher_argv(
    parser: argparse.ArgumentParser,
    argv: list[str],
) -> tuple[argparse.Namespace, list[str]]:
    if "--" in argv[1:]:
        sep_idx = argv.index("--", 1)
        our_argv = argv[1:sep_idx]
        opencode_args = argv[sep_idx + 1 :]
        args = parser.parse_args(our_argv)
    else:
        args, opencode_args = parser.parse_known_args(argv[1:])
    return args, opencode_args


def resolve_active_security_profile(
    args: argparse.Namespace,
) -> WorkerSecurityProfile | None:
    has_override_flags = any(
        val is not None and val is not False
        for val in (
            args.read_root,
            args.write_root,
            args.protect_path,
            args.allow_tool,
            args.deny_tool,
            args.allow_mcp_tool,
            args.deny_mcp_tool,
            args.allow_ssh_agent,
            args.allow_localhost_port,
            args.pass_env,
        )
    )
    if not args.security_profile and not args.unattended_worker and not has_override_flags:
        return None

    base_profile = (
        load_security_profile(args.security_profile)
        if args.security_profile
        else default_unattended_worker_profile()
    )
    return apply_cli_overrides(
        base_profile,
        read_roots=args.read_root,
        write_roots=args.write_root,
        protected_paths=args.protect_path,
        allowed_tools=args.allow_tool,
        denied_tools=args.deny_tool,
        allowed_mcp_tools=args.allow_mcp_tool,
        denied_mcp_tools=args.deny_mcp_tool,
        allow_subagents=True if args.allow_subagents else None,
        allow_ssh_agent=True if args.allow_ssh_agent else None,
        allowed_localhost_ports=args.allow_localhost_port,
        pass_env=args.pass_env,
    )


def validate_common_worker_flags(
    args: argparse.Namespace,
    active_profile: WorkerSecurityProfile | None,
) -> str | None:
    raw_port = getattr(args, "port", None)
    if raw_port is not None:
        if isinstance(raw_port, bool) or not isinstance(raw_port, int) or raw_port < 1024 or raw_port > 64535:
            return f"Invalid --port {raw_port!r}: must be an integer between 1024 and 64535."
    if getattr(args, "refresh_session", False) and getattr(args, "no_serve", False):
        return "Refusing --refresh-session (--restart) with --no-serve: refreshing a session requires starting a server/proxy."
    if active_profile is None:
        return None
    if getattr(args, "refresh_session", False):
        return "Refusing --refresh-session (--restart) in unattended worker mode: unattended workers require a pre-served model session."
    if getattr(args, "preserve_host_home", False):
        return "Refusing --preserve-host-home: host HOME cannot be preserved when a worker security profile is active."
    if getattr(args, "allow_uncleared_model", False) and not active_profile.allow_uncleared_model:
        return "Refusing --allow-uncleared-model in unattended worker mode because security profile has allow_uncleared_model=false."
    if getattr(args, "allow_deprecated_model", False):
        return "Refusing --allow-deprecated-model in unattended worker mode: deprecated models cannot be used for unattended worker sessions."
    return None


PID_IDENTITY_STATES: tuple[str, str, str, str] = (
    "matched",
    "reused",
    "dead",
    "unavailable",
)


def classify_pid_identity(pid: Any, expected_lstart: Any) -> str:
    if (
        not isinstance(pid, int)
        or isinstance(pid, bool)
        or pid <= 0
        or not pid_is_alive(pid)
        or pid_is_zombie(pid)
    ):
        return "dead"
    if not isinstance(expected_lstart, str) or not expected_lstart.strip():
        return "unavailable"
    actual_lstart = get_process_lstart(pid)
    if not isinstance(actual_lstart, str) or not actual_lstart.strip():
        if not pid_is_alive(pid) or pid_is_zombie(pid):
            return "dead"
        return "unavailable"
    if " ".join(actual_lstart.split()) == " ".join(expected_lstart.split()):
        return "matched"
    return "reused"


def pid_record_is_live_or_starting(rec: dict[str, Any] | None) -> tuple[bool, bool]:
    """Return (is_active, is_unavailable) for a PID record."""
    if not isinstance(rec, dict):
        return False, False
    pid_state = classify_pid_identity(rec.get("pid"), rec.get("pid_lstart"))
    up_pid = rec.get("upstream_pid")
    has_up = isinstance(up_pid, int) and not isinstance(up_pid, bool) and up_pid > 0
    up_state = (
        classify_pid_identity(up_pid, rec.get("upstream_pid_lstart"))
        if has_up
        else "dead"
    )
    is_starting = rec.get("status") == "starting"
    is_unavail = (pid_state == "unavailable") or (up_state == "unavailable")
    is_active = (pid_state == "matched") or (up_state == "matched") or is_starting
    return is_active, is_unavail


def is_port_owned_by_different_active_model(
    model_id: str,
    port: int,
    *,
    runs_dir: Path | None = None,
) -> tuple[bool, str | None]:
    """Return (True, owner_model_id) only when port is positively owned by a different active model."""
    own_rec = read_pid_record_for_model(model_id, runs_dir)
    own_active, own_unavail = pid_record_is_live_or_starting(own_rec)
    if own_active or own_unavail:
        return False, None

    owner_model_id: str | None = None
    for _, rec in list_pid_records(runs_dir):
        rec_port = rec.get("port", 8080)
        rec_up_port = rec.get("upstream_port")
        if rec_port != port and rec_up_port != port:
            continue
        rec_active, rec_unavail = pid_record_is_live_or_starting(rec)
        if rec_unavail:
            return False, None
        if not rec_active:
            continue
        rec_mid = str(rec.get("model_id") or "").strip()
        if not rec_mid or rec_mid == model_id:
            return False, None
        owner_model_id = rec_mid

    if owner_model_id is not None:
        return True, owner_model_id
    return False, None


def _can_bind_loopback_port(port: int) -> bool:
    if port < 1024 or port > 65535:
        return False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.2)
        if probe.connect_ex(("127.0.0.1", port)) == 0:
            return False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False


def allocate_side_by_side_port(
    preferred_port: int,
    *,
    uses_upstream_port: bool = True,
    runs_dir: Path | None = None,
    max_scan: int = 32,
) -> int:
    """Allocate the next available localhost port above preferred_port."""
    reserved_ports: set[int] = set()
    for _, rec in list_pid_records(runs_dir):
        rec_active, rec_unavail = pid_record_is_live_or_starting(rec)
        if rec_active or rec_unavail:
            rec_p = rec.get("port")
            if isinstance(rec_p, int) and not isinstance(rec_p, bool):
                reserved_ports.add(rec_p)
            rec_up = rec.get("upstream_port")
            if isinstance(rec_up, int) and not isinstance(rec_up, bool):
                reserved_ports.add(rec_up)

    for offset in range(1, max(1, int(max_scan)) + 1):
        candidate = preferred_port + offset
        if candidate > 64535:
            break
        if candidate in reserved_ports or not _can_bind_loopback_port(candidate):
            continue
        if uses_upstream_port:
            up_cand = candidate + 1000
            if up_cand > 65535 or up_cand in reserved_ports or not _can_bind_loopback_port(up_cand):
                continue
        return candidate

    raise LocalAssistError(
        "port_allocation_failed",
        f"Could not find a free localhost port pair above {preferred_port} (scanned {max_scan} ports).",
        details={"preferred_port": preferred_port, "max_scan": max_scan},
    )


def validate_worker_binary_and_args(
    args: argparse.Namespace,
    active_profile: WorkerSecurityProfile | None,
    opencode_bin: str | None,
    opencode_args: list[str],
    sandbox_exec_bin: Path,
) -> tuple[bool, list[str], str | None]:
    if active_profile is None:
        if not getattr(args, "print_config", False):
            is_fast_ro = len(opencode_args) == 1 and opencode_args[0] in (
                "--help",
                "-h",
                "--version",
                "-v",
            )
            if not is_fast_ro and not sandbox_exec_bin.is_file():
                return (
                    False,
                    [],
                    f"Required macOS Seatbelt binary '{sandbox_exec_bin}' not found; refusing unsandboxed OpenCode launch.",
                )
        return True, [], None
    if opencode_bin:
        try:
            verify_opencode_version(
                opencode_bin,
                allow_version_drift=bool(getattr(args, "allow_opencode_version_drift", False)),
            )
        except SecurityProfileError as exc:
            return False, [], str(exc)
    if not getattr(args, "print_config", False):
        if not sandbox_exec_bin.is_file():
            return (
                False,
                [],
                f"Required macOS Seatbelt binary '{sandbox_exec_bin}' not found for worker security profile.",
            )
        assert opencode_bin is not None
        try:
            validated_args = validate_worker_opencode_args(opencode_args)
        except SecurityProfileError as exc:
            return False, [], str(exc)
        return True, validated_args, None
    return True, [], None


def build_isolated_opencode_env(
    workspace_dir: Path,
    isolated_home: Path,
    opencode_config_path: Path,
    *,
    local_assist_base_url: str,
    preserve_host_home: bool = False,
    base_env: dict[str, str] | None = None,
    extra_env: dict[str, str] | None = None,
    pass_through_env_keys: tuple[str, ...] = (),
) -> dict[str, str]:
    src = base_env if base_env is not None else os.environ
    env: dict[str, str] = {}
    for key in SAFE_ENV_ALLOWLIST:
        if key in src:
            env[key] = src[key]
    for key in pass_through_env_keys:
        if key and key in src:
            env[key] = src[key]

    effective_home = (
        src.get("HOME", str(isolated_home)) if preserve_host_home else str(isolated_home)
    )
    env.update(
        {
            "PWD": str(workspace_dir),
            "HOME": effective_home,
            "OPENCODE_TEST_HOME": str(isolated_home),
            "XDG_CONFIG_HOME": str(isolated_home / ".config"),
            "XDG_DATA_HOME": str(isolated_home / ".local" / "share"),
            "XDG_CACHE_HOME": str(isolated_home / ".cache"),
            "XDG_STATE_HOME": str(isolated_home / ".local" / "state"),
            "OPENCODE_DISABLE_AUTOUPDATE": "1",
            "OPENCODE_DISABLE_MODELS_FETCH": "1",
            "OPENCODE_DISABLE_PROJECT_CONFIG": "1",
            "OPENCODE_DISABLE_CLAUDE_CODE": "1",
            "OPENCODE_DISABLE_CLAUDE_CODE_SKILLS": "1",
            "OPENCODE_CONFIG": str(opencode_config_path),
            "HF_HUB_OFFLINE": "1",
            "LOCAL_ASSIST_BASE_URL": local_assist_base_url,
            "LOCAL_ASSIST_WORKSPACE_ROOT": str(workspace_dir.resolve()),
        }
    )
    if extra_env:
        env.update(extra_env)
    return env


@contextlib.contextmanager
def _opencode_launch_lock(isolated_home: Path):
    isolated_home.mkdir(parents=True, exist_ok=True)
    lock_path = isolated_home / ".opencode-launch.lock"
    fd = os.open(
        str(lock_path),
        os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass


def _atomic_write_text_0600(target_path: Path, content: str) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_str = tempfile.mkstemp(
        prefix=f".{target_path.name}.",
        dir=str(target_path.parent),
    )
    tmp_path = Path(tmp_str)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(str(tmp_path), str(target_path))
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def _write_exclusive_config_0600(target_path: Path, content: str) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(target_path), flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, content.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def _prune_active_opencode_clients(
    isolated_home: Path,
    *,
    current_invocation_cfg: Path | None = None,
) -> tuple[list[dict[str, Any]], bool, bool]:
    """Prune confirmed-dead entries in .active-opencode-clients.json under .opencode-launch.lock.

    Returns (retained_entries, registry_existed, registry_unavailable).
    """
    registry_file = isolated_home / ".active-opencode-clients.json"
    configs_dir = isolated_home / ".configs"
    registry_existed = registry_file.exists()
    raw_entries: list[Any] = []
    if registry_existed:
        try:
            parsed = json.loads(registry_file.read_text(encoding="utf-8"))
            if not isinstance(parsed, list):
                return [], registry_existed, True
            raw_entries = parsed
        except (OSError, json.JSONDecodeError):
            return [], registry_existed, True

    retained: list[dict[str, Any]] = []
    corrupt_entry = False
    for entry in raw_entries:
        if not isinstance(entry, dict):
            corrupt_entry = True
            continue
        status = entry.get("status")
        l_pid = entry.get("launcher_pid")
        l_lstart = entry.get("launcher_lstart")
        c_pid = entry.get("child_pid")
        c_lstart = entry.get("child_lstart")

        l_state = classify_pid_identity(l_pid, l_lstart)
        has_recorded_child = (
            status == "running"
            and isinstance(c_pid, int)
            and not isinstance(c_pid, bool)
            and c_pid > 0
            and isinstance(c_lstart, str)
            and bool(c_lstart.strip())
        )
        if not has_recorded_child:
            # Unconfirmed handoff (status == "starting" or child_pid is None):
            # retain conservatively even if launcher_pid is dead because the wrapper
            # may have terminated right after Popen before persisting child_pid (R3-PLAN-MAJOR-1).
            retained.append(entry)
            continue

        c_state = classify_pid_identity(c_pid, c_lstart)
        if l_state in ("dead", "reused") and c_state in ("dead", "reused"):
            continue
        retained.append(entry)

    if not corrupt_entry and configs_dir.is_dir():
        kept_cfg_paths = {
            str(e.get("config_path"))
            for e in retained
            if isinstance(e, dict) and e.get("config_path")
        }
        if current_invocation_cfg is not None:
            kept_cfg_paths.add(str(current_invocation_cfg))
        for cfg_file in sorted(configs_dir.glob("opencode-*.json")):
            if str(cfg_file) not in kept_cfg_paths:
                try:
                    cfg_file.unlink(missing_ok=True)
                except OSError:
                    pass

    if registry_existed or retained:
        try:
            _atomic_write_text_0600(
                registry_file, json.dumps(retained, indent=2) + "\n"
            )
        except OSError:
            return retained, registry_existed, True

    return retained, registry_existed, corrupt_entry


def has_unregistered_opencode_service(
    isolated_home: Path,
    retained_entries: list[dict[str, Any]],
    *,
    registry_existed: bool = True,
    ps_runner: Any = subprocess.run,
) -> bool:
    """Detect pre-upgrade or unregistered OpenCode clients/daemons for isolated_home."""
    sync_file = isolated_home / ".last-service-sync.json"
    if not registry_existed and sync_file.exists():
        return True

    try:
        ps_env = {"PATH": "/bin:/usr/bin", "LC_ALL": "C", "TZ": "UTC"}
        proc = ps_runner(
            ["/bin/ps", "eww", "-U", str(os.getuid()), "-o", "pid=,command="],
            env=ps_env,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return True

    if proc.returncode != 0 or not (proc.stdout or "").strip():
        return True

    registered_pids: set[int] = {os.getpid()}
    for entry in retained_entries:
        if not isinstance(entry, dict):
            continue
        for key in ("launcher_pid", "child_pid"):
            val = entry.get(key)
            if isinstance(val, int) and not isinstance(val, bool) and val > 0:
                registered_pids.add(val)

    iso_variants = {str(isolated_home)}
    try:
        iso_variants.add(str(isolated_home.resolve()))
    except OSError:
        pass
    iso_markers = tuple(f"OPENCODE_TEST_HOME={v}" for v in iso_variants)

    for line in (proc.stdout or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(None, 1)
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        pid = int(parts[0])
        if pid in registered_pids:
            continue
        cmd = parts[1]
        if "opencode" not in cmd:
            continue
        has_env_tag = "OPENCODE_TEST_HOME=" in cmd
        matches_this_home = any(m in cmd for m in iso_markers)
        if has_env_tag and not matches_this_home:
            continue
        if not has_env_tag:
            # Synthetic or external process without OPENCODE_TEST_HOME tag:
            if "opencode service" in cmd or "opencode serve --service" in cmd:
                return True
            continue
        # Matches this isolated_home: any unregistered opencode process or service daemon
        # with OPENCODE_TEST_HOME=<isolated_home> denies exclusivity.
        return True

    return False


FORBIDDEN_INTERACTIVE_SUBCOMMANDS: frozenset[str] = frozenset({
    "service",
    "serve",
    "acp",
    "pair",
    "auth",
    "upgrade",
    "update",
    "uninstall",
})


def check_uncontained_legacy_home(isolated_home: Path) -> str | None:
    """Detect legacy uncontained service.json files inside isolated_home without mutating state."""
    candidate_dirs = (
        isolated_home / ".local" / "state" / "opencode",
        isolated_home / ".local" / "share" / "opencode",
        isolated_home / ".config" / "opencode",
    )
    found_paths: list[Path] = []
    for d in candidate_dirs:
        try:
            if not d.exists() and not d.is_symlink():
                continue
            if d.is_dir() and not d.is_symlink():
                svc_exact = d / "service.json"
                if svc_exact.exists() or svc_exact.is_symlink():
                    found_paths.append(svc_exact)
                for p in sorted(d.glob("service-*.json")):
                    if p not in found_paths:
                        found_paths.append(p)
        except OSError:
            return (
                f"Refusing to launch against isolated home '{isolated_home}': unable to inspect "
                "legacy OpenCode service state. Run './scripts/check-credential-containment --check'."
            )
    if not found_paths:
        return None
    return (
        f"Refusing to launch against uncontained legacy OpenCode home '{isolated_home}' "
        f"(found {len(found_paths)} legacy service state file(s)). "
        "Inspect first with './scripts/check-credential-containment --check', then remediate "
        "with operator approval via './scripts/check-credential-containment --apply --operator-approved'."
    )


def _redact_config_obj_for_print(cfg_obj: dict[str, Any]) -> dict[str, Any]:
    out = json.loads(json.dumps(cfg_obj))
    providers = out.get("provider")
    if isinstance(providers, dict):
        for prov_entry in providers.values():
            if not isinstance(prov_entry, dict):
                continue
            opts = prov_entry.get("options")
            if not isinstance(opts, dict):
                continue
            api_key = opts.get("apiKey")
            if (
                isinstance(api_key, str)
                and api_key
                and not api_key.startswith("{env:")
                and api_key != "local-no-key"
            ):
                opts["apiKey"] = "[REDACTED_PER_INVOCATION_RELAY_TOKEN]"
    return out


_CMD_PORT_RE = re.compile(r"(?:^|\s)--port(?:=|\s+)(\d{1,5})(?:\s|$)")


def _resolve_lsof_binary() -> str | None:
    for cand in ("/usr/sbin/lsof", "/usr/bin/lsof"):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return shutil.which("lsof")


def _observe_opencode_service_ownership(
    pid: int,
    *,
    expected_port: int | None,
    scope_dir: Path,
    scope_id: str | None,
) -> str:
    """Return 'owned', 'foreign', or 'unavailable' for a candidate OpenCode service PID."""
    if pid <= 1 or not pid_is_alive(pid) or pid_is_zombie(pid):
        return "foreign"

    clean_env = {"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"}
    try:
        ps_proc = subprocess.run(
            ["/bin/ps", "eww", "-p", str(pid), "-o", "command="],
            capture_output=True,
            text=True,
            env=clean_env,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "foreign" if (not pid_is_alive(pid) or pid_is_zombie(pid)) else "unavailable"

    if ps_proc.returncode != 0:
        return "foreign" if (not pid_is_alive(pid) or pid_is_zombie(pid)) else "unavailable"

    cmd_line = (ps_proc.stdout or "").strip()
    if not cmd_line:
        return "foreign" if (not pid_is_alive(pid) or pid_is_zombie(pid)) else "unavailable"
    if "opencode" not in cmd_line:
        return "foreign"

    if expected_port is not None:
        m_port = _CMD_PORT_RE.search(cmd_line)
        if m_port is not None and int(m_port.group(1)) != int(expected_port):
            return "foreign"

    scope_variants = _dual_realpath_variants(scope_dir)
    if (
        scope_id
        and len(scope_id) >= 8
        and re.search(rf"(?:^|[\s=:\"'/]){re.escape(scope_id)}(?:$|[\s/:\"'])", cmd_line)
    ) or any(
        re.search(rf"(?:^|[\s=:\"']){re.escape(v)}(?:$|[\s/:\"'])", cmd_line)
        for v in scope_variants
    ):
        return "owned"

    if expected_port is not None and 1 <= int(expected_port) <= 65535:
        lsof_bin = _resolve_lsof_binary()
        if not lsof_bin:
            return "foreign" if (not pid_is_alive(pid) or pid_is_zombie(pid)) else "unavailable"
        try:
            lsof_probe = subprocess.run(
                [lsof_bin, "-n", "-P", "-p", str(pid), "-Fn"],
                capture_output=True,
                text=True,
                env=clean_env,
                timeout=3,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return "foreign" if (not pid_is_alive(pid) or pid_is_zombie(pid)) else "unavailable"
        if lsof_probe.returncode != 0 or not (lsof_probe.stdout or "").strip():
            return "foreign" if (not pid_is_alive(pid) or pid_is_zombie(pid)) else "unavailable"

        try:
            lsof_proc = subprocess.run(
                [
                    lsof_bin,
                    "-Pan",
                    "-p",
                    str(pid),
                    f"-iTCP:{int(expected_port)}",
                    "-sTCP:LISTEN",
                    "-Fn",
                ],
                capture_output=True,
                text=True,
                env=clean_env,
                timeout=3,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return "foreign" if (not pid_is_alive(pid) or pid_is_zombie(pid)) else "unavailable"

        if lsof_proc.returncode not in (0, 1) or (
            lsof_proc.returncode == 1 and (lsof_proc.stderr or "").strip()
        ):
            return "foreign" if (not pid_is_alive(pid) or pid_is_zombie(pid)) else "unavailable"

        port_suffix = f":{int(expected_port)}"
        if lsof_proc.returncode == 0 and any(
            ln.startswith("n") and ln.endswith(port_suffix)
            for ln in (lsof_proc.stdout or "").splitlines()
        ):
            return "owned"

    return "foreign"


def _parse_loopback_service_url_port(raw_url: Any) -> tuple[bool, int | None]:
    if not isinstance(raw_url, str) or not raw_url.strip():
        return False, None
    s = raw_url.strip()
    if any(ch.isspace() or ord(ch) < 32 for ch in s):
        return False, None
    try:
        parsed = urlparse(s)
        port = parsed.port
    except ValueError:
        return False, None
    if parsed.scheme.lower() not in ("http", "https"):
        return False, None
    if (parsed.hostname or "").lower() not in ("127.0.0.1", "localhost", "::1"):
        return False, None
    if parsed.username is not None or parsed.password is not None:
        return False, None
    if parsed.path not in ("", "/") or parsed.params != "" or parsed.query != "" or parsed.fragment != "":
        return False, None
    if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
        return False, None
    return True, int(port)


def _parse_service_record_port_strict(svc_obj: dict[str, Any]) -> tuple[bool, int | None]:
    if "hostname" in svc_obj:
        raw_h = svc_obj.get("hostname")
        if not isinstance(raw_h, str) or raw_h.strip().lower() not in ("127.0.0.1", "localhost", "::1"):
            return False, None
    port_val: int | None = None
    if "port" in svc_obj:
        raw_p = svc_obj.get("port")
        if isinstance(raw_p, int) and not isinstance(raw_p, bool) and 1 <= raw_p <= 65535:
            port_val = int(raw_p)
        else:
            return False, None
    if "url" in svc_obj:
        url_ok, url_port = _parse_loopback_service_url_port(svc_obj.get("url"))
        if not url_ok or url_port is None:
            return False, None
        if port_val is not None and port_val != url_port:
            return False, None
        port_val = url_port
    return True, port_val


def _try_bind_service_identity_sidecar(
    *,
    scope_dir: Path,
    state_svc_file: Path,
    sidecar_path: Path,
    scope_id: str,
    service_port: int | None,
) -> bool:
    """Coherently bind service PID + lstart into an immutable 0400 sidecar (ISO-P1)."""
    try:
        if sidecar_path.is_symlink():
            return False
        if sidecar_path.is_file():
            return True
    except OSError:
        return False

    try:
        st = os.lstat(state_svc_file)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            return False
        svc_obj = json.loads(state_svc_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False

    if not isinstance(svc_obj, dict):
        return False
    svc_pid = svc_obj.get("pid")
    if not isinstance(svc_pid, int) or isinstance(svc_pid, bool) or svc_pid <= 1:
        return False

    # 1. Capture lstart BEFORE ownership inspection (ISO-P1).
    lstart_before = get_process_lstart(svc_pid)
    if not isinstance(lstart_before, str) or not lstart_before.strip():
        return False
    norm_lstart = " ".join(lstart_before.split())

    # 2. Observe positive invocation/home or listener-port ownership.
    rec_port_ok, rec_port = _parse_service_record_port_strict(svc_obj)
    if not rec_port_ok:
        return False
    if service_port is not None and rec_port is not None and service_port != rec_port:
        return False
    eff_port = service_port if service_port is not None else rec_port
    ownership = _observe_opencode_service_ownership(
        svc_pid,
        expected_port=eff_port,
        scope_dir=scope_dir,
        scope_id=scope_id,
    )
    if ownership != "owned":
        return False

    # 3. Re-verify exact same process identity AFTER ownership inspection before publishing.
    if classify_pid_identity(svc_pid, norm_lstart) != "matched":
        return False

    payload = {
        "schema_version": 1,
        "id": scope_id,
        "pid": svc_pid,
        "pid_lstart": norm_lstart,
        "service_port": eff_port,
    }
    tmp_path = sidecar_path.parent / f".tmp-{sidecar_path.name}-{os.getpid()}-{secrets.token_hex(4)}"
    try:
        fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, (json.dumps(payload, indent=2) + "\n").encode("utf-8"))
        finally:
            os.close(fd)
        os.chmod(tmp_path, 0o400)
        os.replace(tmp_path, sidecar_path)
        return True
    except OSError:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        return False


def _terminate_bound_opencode_service(
    pid: int,
    *,
    expected_lstart: str | None,
    expected_port: int | None,
    scope_dir: Path,
    scope_id: str | None,
    grace_seconds: float = 1.5,
) -> tuple[bool, bool]:
    """Terminate an owned OpenCode service PID safely; returns (terminated_or_exited, observer_ok)."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        return True, True
    if not pid_is_alive(pid) or pid_is_zombie(pid):
        return True, True

    if isinstance(expected_lstart, str) and expected_lstart.strip():
        st = classify_pid_identity(pid, expected_lstart)
        if st in ("dead", "reused"):
            return True, True
        if st == "unavailable":
            return False, False
        bound_lstart = " ".join(expected_lstart.split())
    else:
        lstart_before = get_process_lstart(pid)
        if not isinstance(lstart_before, str) or not lstart_before.strip():
            if not pid_is_alive(pid) or pid_is_zombie(pid):
                return True, True
            return False, False
        ownership = _observe_opencode_service_ownership(
            pid,
            expected_port=expected_port,
            scope_dir=scope_dir,
            scope_id=scope_id,
        )
        if ownership == "unavailable":
            if not pid_is_alive(pid) or pid_is_zombie(pid):
                return True, True
            return False, False
        if ownership == "foreign":
            return True, True
        bound_lstart = " ".join(lstart_before.split())

    st_pre_term = classify_pid_identity(pid, bound_lstart)
    if st_pre_term in ("dead", "reused"):
        return True, True
    if st_pre_term == "unavailable":
        return False, False

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return True, True
    except OSError:
        if not pid_is_alive(pid) or pid_is_zombie(pid):
            return True, True
        return False, True

    deadline = time.monotonic() + max(0.1, float(grace_seconds))
    while time.monotonic() < deadline:
        st_poll = classify_pid_identity(pid, bound_lstart)
        if st_poll in ("dead", "reused"):
            return True, True
        time.sleep(0.04)

    st_pre_kill = classify_pid_identity(pid, bound_lstart)
    if st_pre_kill in ("dead", "reused"):
        return True, True
    if st_pre_kill == "unavailable":
        return False, False

    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return True, True
    except OSError:
        pass

    kill_deadline = time.monotonic() + 0.5
    while time.monotonic() < kill_deadline:
        st_post = classify_pid_identity(pid, bound_lstart)
        if st_post in ("dead", "reused"):
            return True, True
        time.sleep(0.03)

    st_final = classify_pid_identity(pid, bound_lstart)
    if st_final in ("dead", "reused"):
        return True, True
    if st_final == "unavailable":
        return False, False
    return False, True


def _lstat_regular_json_dict(path: Path) -> tuple[bool, dict[str, Any] | None]:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return True, None
    except OSError:
        return False, None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return False, None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False, None
    if not isinstance(obj, dict):
        return False, None
    return True, obj


def _read_optional_service_port(scope_dir: Path, cfg_svc_rel: Path) -> tuple[bool, int | None]:
    cfg_file_ok, cfg_obj = _lstat_regular_json_dict(scope_dir / cfg_svc_rel)
    if not cfg_file_ok:
        return False, None
    cfg_port: int | None = None
    if cfg_obj is not None:
        if "pid" in cfg_obj:
            raw_cpid = cfg_obj.get("pid")
            if not isinstance(raw_cpid, int) or isinstance(raw_cpid, bool) or raw_cpid <= 1:
                return False, None
        cfg_ok, cfg_port = _parse_service_record_port_strict(cfg_obj)
        if not cfg_ok:
            return False, None

    owner_file_ok, owner_obj = _lstat_regular_json_dict(scope_dir / "owner.json")
    if not owner_file_ok:
        return False, None
    owner_port: int | None = None
    if owner_obj is not None and "service_port" in owner_obj:
        val = owner_obj.get("service_port")
        if val is not None:
            if not isinstance(val, int) or isinstance(val, bool) or not (1 <= val <= 65535):
                return False, None
            owner_port = int(val)

    if cfg_port is not None and owner_port is not None and cfg_port != owner_port:
        return False, None
    return True, (cfg_port if cfg_port is not None else owner_port)


def _cleanup_scope_opencode_service(
    scope_dir: Path,
    *,
    state_svc_rel: Path,
    sidecar_name: str,
    cfg_svc_rel: Path,
    scope_id: str | None,
    fallback_port: int | None = None,
    grace_seconds: float = 1.5,
) -> bool:
    # Phase 1: Validate all relevant metadata files and cross-record agreement BEFORE signaling.
    if fallback_port is not None and (
        not isinstance(fallback_port, int)
        or isinstance(fallback_port, bool)
        or not (1 <= fallback_port <= 65535)
    ):
        return False

    opt_ok, opt_port = _read_optional_service_port(scope_dir, cfg_svc_rel)
    if not opt_ok:
        return False
    if fallback_port is not None and opt_port is not None and fallback_port != opt_port:
        return False

    known_ports: set[int] = set()
    if opt_port is not None:
        known_ports.add(opt_port)
    if fallback_port is not None:
        known_ports.add(fallback_port)

    sc_file_ok, sc_obj = _lstat_regular_json_dict(scope_dir / sidecar_name)
    if not sc_file_ok:
        return False
    sc_pid: int | None = None
    sc_lstart: str | None = None
    if sc_obj is not None:
        raw_pid = sc_obj.get("pid")
        raw_ls = sc_obj.get("pid_lstart")
        raw_port = sc_obj.get("service_port")
        port_field_ok = raw_port is None or (
            isinstance(raw_port, int) and not isinstance(raw_port, bool) and 1 <= raw_port <= 65535
        )
        if (
            not port_field_ok
            or not isinstance(raw_pid, int)
            or isinstance(raw_pid, bool)
            or raw_pid <= 1
            or not isinstance(raw_ls, str)
            or not raw_ls.strip()
            or raw_ls.strip() == "unavailable"
        ):
            return False
        sc_pid = int(raw_pid)
        sc_lstart = " ".join(raw_ls.split())
        if raw_port is not None:
            known_ports.add(int(raw_port))
            if len(known_ports) > 1:
                return False

    st_file_ok, svc_data = _lstat_regular_json_dict(scope_dir / state_svc_rel)
    if not st_file_ok:
        return False
    st_pid: int | None = None
    if svc_data is not None:
        if "pid" in svc_data:
            raw_st_pid = svc_data.get("pid")
            if not isinstance(raw_st_pid, int) or isinstance(raw_st_pid, bool) or raw_st_pid <= 1:
                return False
            st_pid = int(raw_st_pid)
        if "pid_lstart" in svc_data:
            raw_st_ls = svc_data.get("pid_lstart")
            if (
                st_pid is None
                or not isinstance(raw_st_ls, str)
                or not raw_st_ls.strip()
                or raw_st_ls.strip() == "unavailable"
            ):
                return False
            norm_st_ls = " ".join(raw_st_ls.split())
            if sc_pid is not None and st_pid == sc_pid and sc_lstart is not None and norm_st_ls != sc_lstart:
                return False
        st_port_ok, st_port = _parse_service_record_port_strict(svc_data)
        if not st_port_ok:
            return False
        if st_port is not None:
            known_ports.add(st_port)
            if len(known_ports) > 1:
                return False

    # Phase 2: All present records are valid and non-conflicting; terminate verified owned PIDs.
    eff_port = next(iter(known_ports)) if known_ports else None
    clean = True
    if sc_pid is not None and sc_lstart is not None:
        term_ok, obs_ok = _terminate_bound_opencode_service(
            sc_pid,
            expected_lstart=sc_lstart,
            expected_port=eff_port,
            scope_dir=scope_dir,
            scope_id=scope_id,
            grace_seconds=grace_seconds,
        )
        if not (term_ok and obs_ok):
            clean = False

    if st_pid is not None and (sc_pid is None or st_pid != sc_pid):
        term_ok, obs_ok = _terminate_bound_opencode_service(
            st_pid,
            expected_lstart=None,
            expected_port=eff_port,
            scope_dir=scope_dir,
            scope_id=scope_id,
            grace_seconds=grace_seconds,
        )
        if not (term_ok and obs_ok):
            clean = False

    return clean


def _reap_invocation_service_and_children(inv_dir: Path, *, invocation_id: str) -> bool:
    clean = _cleanup_scope_opencode_service(
        inv_dir,
        state_svc_rel=Path(".state") / "opencode" / "service.json",
        sidecar_name="service-identity.json",
        cfg_svc_rel=Path(".config") / "opencode" / "service.json",
        scope_id=invocation_id,
        grace_seconds=1.5,
    )

    _, reaper_ok = reap_worker_processes_detailed(
        worker_id=invocation_id,
        isolated_home=inv_dir,
        max_passes=3,
        grace_seconds=0.4,
    )
    if not reaper_ok:
        clean = False
    return clean


def _sweep_dead_invocations(isolated_home: Path, *, skip_inv_id: str | None = None) -> None:
    inv_root = isolated_home / ".invocations"
    if not inv_root.is_dir() or inv_root.is_symlink():
        return
    for cand in sorted(inv_root.iterdir()):
        if cand.name == skip_inv_id or cand.is_symlink() or not cand.is_dir():
            continue
        owner_file = cand / "owner.json"
        preserve_cand = False
        try:
            if owner_file.exists() or owner_file.is_symlink():
                if owner_file.is_symlink() or not owner_file.is_file():
                    preserve_cand = True
                else:
                    meta = json.loads(owner_file.read_text(encoding="utf-8"))
                    if not isinstance(meta, dict):
                        preserve_cand = True
                    else:
                        opid = meta.get("pid")
                        olstart = meta.get("pid_lstart")
                        if (
                            not isinstance(opid, int)
                            or isinstance(opid, bool)
                            or opid <= 1
                            or not isinstance(olstart, str)
                            or not olstart.strip()
                            or olstart.strip() == "unavailable"
                        ):
                            preserve_cand = True
                        else:
                            st = classify_pid_identity(opid, olstart)
                            if st in ("matched", "unavailable"):
                                preserve_cand = True
            else:
                if (time.time() - cand.stat().st_mtime) < 60.0:
                    preserve_cand = True
                else:
                    parts = cand.name.split("-")
                    if len(parts) >= 3 and parts[0] == "inv" and parts[1].isdigit():
                        cand_pid = int(parts[1])
                        if cand_pid <= 1 or pid_is_alive(cand_pid):
                            preserve_cand = True
                    else:
                        preserve_cand = True
        except (OSError, json.JSONDecodeError):
            preserve_cand = True
        if preserve_cand:
            continue
        if _reap_invocation_service_and_children(cand, invocation_id=cand.name):
            _safe_rmtree_nofollow(cand)


def _normalize_interactive_opencode_args(opencode_args: Sequence[str]) -> tuple[bool, list[str], str | None]:
    cleaned: list[str] = []
    first_positional: str | None = None
    for raw_arg in opencode_args:
        arg = str(raw_arg)
        if arg == "--standalone" or arg.startswith("--standalone="):
            continue
        if arg == "--server" or arg.startswith("--server="):
            return (
                False,
                [],
                "Refusing '--server' in contained OpenCode launcher: external uncontained server URLs are blocked.",
            )
        if first_positional is None and not arg.startswith("-"):
            first_positional = arg
            if first_positional in FORBIDDEN_INTERACTIVE_SUBCOMMANDS:
                return (
                    False,
                    [],
                    f"Refusing OpenCode subcommand '{first_positional}': persistent/uncontained daemon management is disabled.",
                )
        cleaned.append(arg)
    return True, cleaned, None


def publish_and_run_opencode(
    *,
    opencode_bin: str | None,
    opencode_args: list[str],
    caller_cwd: Path,
    isolated_home: Path,
    endpoint: EndpointConfig,
    config_text: str,
    build_env_fn: Callable[[Path], dict[str, str]],
    current_sync: dict[str, Any],
    print_config: bool = False,
    build_print_config_payload_fn: Callable[[Path, dict[str, Any]], dict[str, Any]] | None = None,
    relay_factory: Callable[[str], SessionAuthRelay] | None = None,
    endpoint_port: int | None = None,
    upstream_port: int | None = None,
    local_assist_port: int = 8080,
    use_token_relay: bool = False,
    allowed_shell_localhost_ports: Sequence[int] = (),
    allow_ssh_remote: bool = False,
    allow_self_edit: bool = False,
    sandbox_exec_bin: Path = Path("/usr/bin/sandbox-exec"),
    popen_fn: Any = subprocess.Popen,
    run_service_cmd: Any = subprocess.run,
    ps_runner: Any = subprocess.run,
) -> int:
    """Provision an isolated per-invocation runtime directory and run OpenCode inside Seatbelt."""
    del current_sync, run_service_cmd, ps_runner

    legacy_err = check_uncontained_legacy_home(isolated_home)
    if legacy_err is not None:
        print(legacy_err, file=sys.stderr)
        return 1

    args_ok, effective_opencode_args, args_err = _normalize_interactive_opencode_args(opencode_args)
    if not args_ok:
        print(args_err or "Invalid OpenCode arguments.", file=sys.stderr)
        return 1

    invocation_id = f"inv-{os.getpid()}-{int(time.time() * 1000)}-{secrets.token_hex(6)}"
    inv_root = isolated_home / ".invocations"
    inv_dir = inv_root / invocation_id
    inv_cfg_path = inv_dir / "opencode.json"

    if print_config:
        parsed_preview = _redact_config_obj_for_print(json.loads(config_text))
        _ = build_env_fn(inv_cfg_path)
        if build_print_config_payload_fn is not None:
            payload = build_print_config_payload_fn(inv_cfg_path, parsed_preview)
        else:
            payload = {
                "model_id": endpoint.model_id,
                "served_model_id": endpoint.served_model_id,
                "api_base_url": endpoint.api_base_url,
                "opencode_config_path": str(inv_cfg_path),
                "isolated_home": str(isolated_home),
                "config": parsed_preview,
            }
        print(redact_session_tokens(json.dumps(payload, indent=2)))
        return 0

    assert opencode_bin is not None

    # Fast-path read-only CLI flags (--help/-h/--version/-v) without starting service/relay
    if len(effective_opencode_args) == 1 and effective_opencode_args[0] in (
        "--help",
        "-h",
        "--version",
        "-v",
    ):
        clean_help_env = {
            k: os.environ[k]
            for k in ("PATH", "HOME", "TERM", "LANG", "LC_ALL", "LC_CTYPE")
            if k in os.environ
        }
        proc_fast = popen_fn(
            [opencode_bin, *effective_opencode_args],
            cwd=str(caller_cwd),
            env=clean_help_env,
        )
        return int(proc_fast.wait())

    is_real_launch = popen_fn is subprocess.Popen
    if is_real_launch:
        if not sandbox_exec_bin.is_file():
            print(
                f"Refusing unsandboxed OpenCode launch: required macOS Seatbelt binary '{sandbox_exec_bin}' not found.",
                file=sys.stderr,
            )
            return 1
        if not Path(opencode_bin).is_file():
            print(
                f"Refusing OpenCode launch: executable '{opencode_bin}' not found.",
                file=sys.stderr,
            )
            return 1

    use_real_sandbox = is_real_launch

    isolated_home.mkdir(parents=True, exist_ok=True, mode=0o700)
    for shared_sub in (".local/share/opencode", ".cache/opencode", ".invocations"):
        (isolated_home / shared_sub).mkdir(parents=True, exist_ok=True, mode=0o700)

    with _opencode_launch_lock(isolated_home):
        _sweep_dead_invocations(isolated_home, skip_inv_id=invocation_id)
        inv_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        for sub_rel in (".config/opencode", ".state/opencode", ".tmp", "bin"):
            (inv_dir / sub_rel).mkdir(parents=True, exist_ok=True, mode=0o700)
        service_port = _allocate_loopback_ephemeral_port()
        service_password = secrets.token_urlsafe(32)
        owner_meta = {
            "invocation_id": invocation_id,
            "pid": os.getpid(),
            "pid_lstart": get_process_lstart(os.getpid()) or "unavailable",
            "service_port": service_port,
            "model_id": endpoint.model_id,
            "created_at": time.time(),
        }
        owner_path = inv_dir / "owner.json"
        owner_path.write_text(json.dumps(owner_meta, indent=2) + "\n", encoding="utf-8")
        os.chmod(owner_path, 0o400)

    relay: SessionAuthRelay | None = None
    proc: Any = None
    cancel_state: dict[str, Any] = {"signum": None, "proc": None}
    prev_handlers: dict[int, Any] = {}

    def _forward_signal(signum: int, _frame: Any) -> None:
        if cancel_state["signum"] is None:
            cancel_state["signum"] = signum
        child_ref = cancel_state.get("proc")
        if child_ref is not None:
            try:
                if hasattr(child_ref, "send_signal"):
                    child_ref.send_signal(signal.SIGTERM)
                elif isinstance(getattr(child_ref, "pid", None), int) and child_ref.pid > 1:
                    os.kill(child_ref.pid, signal.SIGTERM)
            except OSError:
                pass

    for sig in (signal.SIGTERM, signal.SIGHUP):
        try:
            prev_handlers[sig] = signal.getsignal(sig)
            signal.signal(sig, _forward_signal)
        except (OSError, ValueError):
            pass

    rc = 1
    reaped_clean = True
    try:
        inv_dir_real = inv_dir.resolve(strict=True)
        svc_cfg_path = inv_dir_real / ".config" / "opencode" / "service.json"
        svc_cfg_path.write_text(
            json.dumps(
                {"hostname": "127.0.0.1", "port": service_port, "password": service_password},
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        os.chmod(svc_cfg_path, 0o400)

        parsed_cfg = json.loads(config_text)
        if relay_factory is not None:
            relay = relay_factory(service_password).start()
            if isinstance(parsed_cfg, dict):
                providers = parsed_cfg.get("provider")
                if isinstance(providers, dict) and isinstance(
                    providers.get("private-attested"), dict
                ):
                    opts = dict(providers["private-attested"].get("options") or {})
                    opts["baseURL"] = relay.api_base_url
                    opts["apiKey"] = relay.relay_token
                    providers["private-attested"]["options"] = opts

        if use_real_sandbox and isinstance(parsed_cfg, dict):
            plugin_dir = _stage_credential_guard_plugin(inv_dir_real)
            existing_plugins = [
                str(p) for p in (parsed_cfg.get("plugins") or []) if isinstance(p, str) and p
            ]
            if str(plugin_dir) not in existing_plugins:
                existing_plugins.append(str(plugin_dir))
            parsed_cfg["plugins"] = existing_plugins

            mcp_obj = parsed_cfg.get("mcp")
            mcp_servers = mcp_obj.get("servers") if isinstance(mcp_obj, dict) else None
            if isinstance(mcp_servers, dict) and isinstance(mcp_servers.get("local_assist"), dict):
                write_verified_local_models_handoff(
                    isolated_home=inv_dir_real,
                    worker_id=invocation_id,
                )
                _provision_dedicated_local_assist_python(inv_dir_real)
                la_log_dir = (_effective_runs_dir() / "local-assist").resolve()
                la_log_dir.mkdir(parents=True, exist_ok=True)
                la_entry = dict(mcp_servers["local_assist"])
                la_env = dict(la_entry.get("environment") or {})
                la_env["LOCAL_ASSIST_AUTO_SERVE"] = "0"
                la_env["LOCAL_ASSIST_WORKER_SANDBOX"] = "1"
                la_env["LOCAL_ASSIST_WORKER_ID"] = invocation_id
                la_env["LOCAL_ASSIST_LOG_DIR"] = str(la_log_dir)
                la_env["LOCAL_ASSIST_VERIFIED_MODELS_FILE"] = str(
                    inv_dir_real / "verified-models.json"
                )
                la_env["LOCAL_ASSIST_WORKSPACE_ROOT"] = str(caller_cwd.resolve())
                la_env["PYTHONSAFEPATH"] = "1"
                la_env["PYTHONNOUSERSITE"] = "1"
                if _locate_host_node_binary() is not None:
                    la_env["LOCAL_ASSIST_ASSERTION_NODE_BIN"] = str(
                        inv_dir_real / "bin" / "local-assist-node"
                    )
                if "FREE_INFERENCE_RUNS_DIR" in os.environ:
                    la_env["FREE_INFERENCE_RUNS_DIR"] = os.environ["FREE_INFERENCE_RUNS_DIR"]
                la_entry["command"] = [
                    str(inv_dir_real / "bin" / "local-assist-python"),
                    "-I",
                    "-m",
                    "local_assist.server",
                ]
                la_entry["cwd"] = str(inv_dir_real / "runtime")
                la_entry["environment"] = la_env
                mcp_servers["local_assist"] = la_entry

        final_cfg_path = inv_dir_real / "opencode.json" if use_real_sandbox else inv_cfg_path
        final_cfg_path.write_text(json.dumps(parsed_cfg, indent=2) + "\n", encoding="utf-8")
        os.chmod(final_cfg_path, 0o400)
        os.chmod(inv_dir_real / ".config" / "opencode", 0o500)
        os.chmod(inv_dir_real / ".config", 0o500)

        env = dict(build_env_fn(final_cfg_path))
        cfg_base = inv_dir_real if use_real_sandbox else inv_dir
        env["OPENCODE_CONFIG"] = str(final_cfg_path)
        env["OPENCODE_CONFIG_DIR"] = str(cfg_base / ".config" / "opencode")
        env["XDG_CONFIG_HOME"] = str(cfg_base / ".config")
        env["XDG_STATE_HOME"] = str(cfg_base / ".state")
        env["XDG_DATA_HOME"] = str(isolated_home / ".local" / "share")
        env["XDG_CACHE_HOME"] = str(isolated_home / ".cache")
        env["TMPDIR"] = str(cfg_base / ".tmp")
        for secret_env_key in (
            "OPENCODE_PASSWORD",
            "OPENCODE_SERVER_PASSWORD",
            "LOCAL_ASSIST_SESSION_TOKEN",
            "_FREE_INFERENCE_TOKEN_FD",
        ):
            env.pop(secret_env_key, None)

        if use_real_sandbox:
            sb_text = compile_interactive_seatbelt_profile(
                workspace_dir=caller_cwd,
                isolated_home=isolated_home,
                invocation_dir=inv_dir_real,
                opencode_bin=Path(opencode_bin),
                sandbox_exec_bin=sandbox_exec_bin,
                service_port=service_port,
                relay_port=relay.port if relay is not None else None,
                endpoint_port=endpoint_port if endpoint_port is not None else endpoint.port,
                upstream_port=upstream_port,
                local_assist_port=local_assist_port,
                use_token_relay=use_token_relay or (relay is not None),
                allowed_shell_localhost_ports=allowed_shell_localhost_ports,
                allow_ssh_remote=allow_ssh_remote,
                allow_self_edit=allow_self_edit,
            )
            sb_path = inv_dir_real / "interactive.sb"
            sb_path.write_text(sb_text, encoding="utf-8")
            os.chmod(sb_path, 0o400)
            launch_cmd = [
                str(sandbox_exec_bin),
                "-f",
                str(sb_path),
                str(opencode_bin),
                *effective_opencode_args,
            ]
        else:
            launch_cmd = [str(opencode_bin), *effective_opencode_args]

        if use_real_sandbox:
            with _opencode_launch_lock(isolated_home):
                proc = popen_fn(
                    launch_cmd,
                    cwd=str(caller_cwd),
                    env=env,
                )
                cancel_state["proc"] = proc
                if cancel_state["signum"] is not None:
                    _forward_signal(cancel_state["signum"], None)
                state_svc_file = inv_dir_real / ".state" / "opencode" / "service.json"
                sidecar_path = inv_dir_real / "service-identity.json"
                svc_deadline = time.monotonic() + 5.0
                while time.monotonic() < svc_deadline and proc.poll() is None:
                    if state_svc_file.is_file():
                        _try_bind_service_identity_sidecar(
                            scope_dir=inv_dir_real,
                            state_svc_file=state_svc_file,
                            sidecar_path=sidecar_path,
                            scope_id=invocation_id,
                            service_port=service_port,
                        )
                        break
                    time.sleep(0.05)
        else:
            proc = popen_fn(
                launch_cmd,
                cwd=str(caller_cwd),
                env=env,
            )
            cancel_state["proc"] = proc
            if cancel_state["signum"] is not None:
                _forward_signal(cancel_state["signum"], None)

        rc = int(proc.wait())
        if use_real_sandbox:
            _try_bind_service_identity_sidecar(
                scope_dir=inv_dir_real,
                state_svc_file=inv_dir_real / ".state" / "opencode" / "service.json",
                sidecar_path=inv_dir_real / "service-identity.json",
                scope_id=invocation_id,
                service_port=service_port,
            )
        if cancel_state["signum"] is not None and rc == 0:
            rc = 128 + int(cancel_state["signum"])
    except SecurityProfileError as exc:
        print(str(exc), file=sys.stderr)
        rc = 1
    finally:
        for sig, prev in prev_handlers.items():
            try:
                signal.signal(sig, prev)
            except (OSError, ValueError):
                pass
        if proc is not None:
            try:
                if proc.poll() is None:
                    if hasattr(proc, "terminate"):
                        proc.terminate()
                    elif isinstance(getattr(proc, "pid", None), int) and proc.pid > 1:
                        os.kill(proc.pid, signal.SIGTERM)
                    if hasattr(proc, "wait"):
                        proc.wait(timeout=3)
            except Exception:
                try:
                    if hasattr(proc, "kill"):
                        proc.kill()
                except Exception:
                    pass
        if relay is not None:
            relay.close()
        if use_real_sandbox:
            reaped_clean = _reap_invocation_service_and_children(
                inv_dir, invocation_id=invocation_id
            )
            if reaped_clean:
                _safe_rmtree_nofollow(inv_dir)
            elif rc == 0:
                rc = 1
        else:
            _safe_rmtree_nofollow(inv_dir)
        with _opencode_launch_lock(isolated_home):
            _sweep_dead_invocations(isolated_home)
    return rc


def sync_and_run_opencode(
    opencode_bin: str,
    opencode_args: list[str],
    *,
    caller_cwd: Path,
    isolated_home: Path,
    env: dict[str, str],
    current_sync: dict[str, Any],
) -> int:
    del current_sync
    ok, cleaned_args, err = _normalize_interactive_opencode_args(opencode_args)
    if not ok:
        print(err or "Invalid OpenCode arguments.", file=sys.stderr)
        return 1
    proc = subprocess.run(
        [opencode_bin, *cleaned_args],
        cwd=str(caller_cwd),
        env=env,
        check=False,
    )
    return int(proc.returncode)


def execute_worker_profile_session(
    *,
    active_profile: WorkerSecurityProfile,
    args: argparse.Namespace,
    caller_cwd: Path,
    opencode_bin: str | None,
    sandbox_exec_bin: Path,
    validated_worker_args: list[str],
    build_base_config_fn: Callable[[_WorkerTokenRelay | None], dict[str, Any]],
    build_print_config_payload_fn: Callable[[str, Path, Path, Path, dict[str, Any], _WorkerTokenRelay | None], dict[str, Any]],
    relay_factory: Callable[[], _WorkerTokenRelay] | None = None,
    upstream_port: int | None = None,
    endpoint_port: int | None = None,
    local_assist_port: int = 8080,
    use_token_relay: bool = False,
    allocate_worker_home_fn: Callable[[], tuple[str, Path]] = allocate_worker_home,
) -> int:
    sweep_stale_worker_homes()
    worker_id, isolated_home = allocate_worker_home_fn()
    retain_home = bool(getattr(args, "keep_worker_home", False) or getattr(args, "print_config", False))
    relay: _WorkerTokenRelay | None = None
    exit_code = 1
    lifecycle_handled_teardown = False
    worker_service_port = _allocate_loopback_ephemeral_port()
    worker_service_password = secrets.token_urlsafe(32)
    try:
        if relay_factory is not None:
            relay_inst = relay_factory()
            relay_inst._extra_canary_secrets = (
                *relay_inst._extra_canary_secrets,
                worker_service_password,
            )
            relay = relay_inst.start()

        base_cfg = build_base_config_fn(relay)
        compiled_cfg = compile_opencode_security_config(
            base_cfg,
            active_profile,
            isolated_home=isolated_home,
            workspace_dir=caller_cwd,
        )
        opencode_bin_for_sb = Path(opencode_bin) if opencode_bin else Path("/usr/bin/true")
        sb_bin_for_sb = sandbox_exec_bin if sandbox_exec_bin.is_file() else Path("/usr/bin/true")
        seatbelt_kwargs: dict[str, Any] = {
            "workspace_dir": caller_cwd,
            "isolated_home": isolated_home,
            "opencode_bin": opencode_bin_for_sb,
            "sandbox_exec_bin": sb_bin_for_sb,
            "service_port": worker_service_port,
            "local_assist_port": local_assist_port,
        }
        if upstream_port is not None:
            seatbelt_kwargs["upstream_port"] = upstream_port
        if endpoint_port is not None:
            seatbelt_kwargs["endpoint_port"] = endpoint_port
        if use_token_relay:
            seatbelt_kwargs["use_token_relay"] = True
        seatbelt_text = compile_seatbelt_profile(active_profile, **seatbelt_kwargs)
        opencode_config_path, seatbelt_path, _ = write_worker_runtime_artifacts(
            isolated_home=isolated_home,
            worker_id=worker_id,
            profile=active_profile,
            opencode_config=compiled_cfg,
            seatbelt_text=seatbelt_text,
            service_port=worker_service_port,
            service_password=worker_service_password,
        )
        env = build_worker_environment(
            active_profile,
            isolated_home=isolated_home,
            worker_id=worker_id,
        )
        flagged_tracked = check_tracked_protected_files(
            caller_cwd,
            protected_paths=active_profile.protected_paths,
        )
        if flagged_tracked:
            print(
                f"WARNING: git repository tracks protected path(s) {flagged_tracked}; "
                "writes to these paths inside the worker sandbox will be denied by Seatbelt.",
                file=sys.stderr,
            )
        if getattr(args, "print_config", False):
            redacted_compiled_cfg = _redact_config_obj_for_print(compiled_cfg)
            payload = build_print_config_payload_fn(
                worker_id,
                opencode_config_path,
                seatbelt_path,
                isolated_home,
                redacted_compiled_cfg,
                relay,
            )
            print(redact_session_tokens(json.dumps(payload, indent=2)))
            exit_code = 0
        else:
            assert opencode_bin is not None
            lifecycle_handled_teardown = True

            svc_st = isolated_home / ".local" / "state" / "opencode" / "service.json"
            worker_sidecar = isolated_home / ".service-identity.json"

            def _bind_worker_service_sidecar() -> None:
                if svc_st.is_file():
                    _try_bind_service_identity_sidecar(
                        scope_dir=isolated_home,
                        state_svc_file=svc_st,
                        sidecar_path=worker_sidecar,
                        scope_id=worker_id,
                        service_port=worker_service_port,
                    )

            def _stop_worker_service() -> bool:
                return _cleanup_scope_opencode_service(
                    isolated_home,
                    state_svc_rel=Path(".local") / "state" / "opencode" / "service.json",
                    sidecar_name=".service-identity.json",
                    cfg_svc_rel=Path(".config") / "opencode" / "service.json",
                    scope_id=worker_id,
                    fallback_port=worker_service_port,
                    grace_seconds=1.0,
                )

            lifecycle_kwargs: dict[str, Any] = {
                "cwd": str(caller_cwd),
                "env": env,
                "isolated_home": isolated_home,
                "worker_id": worker_id,
                "harvest_logs": active_profile.mcp_enable_local_assist,
                "remove_home": not retain_home,
                "poll_hook": _bind_worker_service_sidecar,
                "pre_teardown_hook": _stop_worker_service,
            }
            if relay is not None:
                lifecycle_kwargs["relay"] = relay
            exit_code, teardown_res = run_worker_sandbox_lifecycle(
                [
                    str(sandbox_exec_bin),
                    "-f",
                    str(seatbelt_path),
                    str(opencode_bin),
                    *validated_worker_args,
                ],
                **lifecycle_kwargs,
            )
            relay = None
            if not teardown_res.get("clean", False):
                print(
                    f"WARNING: worker teardown for '{worker_id}' was incomplete "
                    f"(reaper_clean={teardown_res.get('reaper_clean')}, removed={teardown_res.get('removed')}).",
                    file=sys.stderr,
                )
                exit_code = exit_code or 1
    except SecurityProfileError as exc:
        print(str(exc), file=sys.stderr)
        exit_code = 1
    finally:
        if relay is not None:
            relay.close()
        if not lifecycle_handled_teardown:
            if retain_home:
                try:
                    (isolated_home / ".keep-worker-home").write_text("1\n", encoding="utf-8")
                except OSError:
                    pass
            teardown_res = teardown_worker_home(
                isolated_home,
                worker_id=worker_id,
                harvest_logs=active_profile.mcp_enable_local_assist,
                remove_home=not retain_home,
                reap_processes=True,
            )
            if not teardown_res.get("clean", False):
                print(
                    f"WARNING: worker teardown for '{worker_id}' was incomplete "
                    f"(reaper_clean={teardown_res.get('reaper_clean')}, removed={teardown_res.get('removed')}).",
                    file=sys.stderr,
                )
                exit_code = exit_code or 1
    return exit_code
