from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from .errors import LocalAssistError
from .registry import (
    BASE_SAFE_ENV_ALLOWLIST,
    LAUNCHER_EXTRA_ENV_ALLOWLIST,
    EndpointConfig,
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
    allocate_worker_home,
    apply_cli_overrides,
    build_worker_environment,
    check_tracked_protected_files,
    compile_opencode_security_config,
    compile_seatbelt_profile,
    default_unattended_worker_profile,
    load_security_profile,
    redact_session_tokens,
    run_worker_sandbox_lifecycle,
    sweep_stale_worker_homes,
    teardown_worker_home,
    validate_worker_opencode_args,
    verify_opencode_version,
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


def _inject_standalone_arg(opencode_args: list[str]) -> list[str]:
    if "--standalone" in opencode_args or "--server" in opencode_args:
        return list(opencode_args)
    if not opencode_args or opencode_args[0].startswith("-"):
        return ["--standalone", *opencode_args]
    if opencode_args[0] in ("run", "mini"):
        return [opencode_args[0], "--standalone", *opencode_args[1:]]
    return list(opencode_args)


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
    popen_fn: Any = subprocess.Popen,
    run_service_cmd: Any = subprocess.run,
    ps_runner: Any = subprocess.run,
) -> int:
    """Write a unique immutable per-invocation config and run opencode with child-aware ownership."""
    configs_dir = isolated_home / ".configs"
    registry_file = isolated_home / ".active-opencode-clients.json"
    shared_cfg_path = isolated_home / "opencode.json"
    sync_file = isolated_home / ".last-service-sync.json"

    safe_mid = "".join(
        ch if ch.isalnum() or ch in ("-", "_", ".") else "-"
        for ch in endpoint.model_id
    )
    invocation_id = f"{os.getpid()}-{secrets.token_hex(8)}"
    invocation_cfg_path = configs_dir / f"opencode-{safe_mid}-{invocation_id}.json"

    proc: Any = None
    child_pid: int | None = None
    child_lstart: str | None = None

    with _opencode_launch_lock(isolated_home):
        _write_exclusive_config_0600(invocation_cfg_path, config_text)
        retained_entries, registry_existed, registry_unavail = _prune_active_opencode_clients(
            isolated_home,
            current_invocation_cfg=invocation_cfg_path,
        )
        unregistered_service = has_unregistered_opencode_service(
            isolated_home,
            retained_entries,
            registry_existed=registry_existed,
            ps_runner=ps_runner,
        )
        is_exclusive_owner = (
            (not registry_unavail)
            and (len(retained_entries) == 0)
            and (not unregistered_service)
        )

        if print_config:
            try:
                if is_exclusive_owner:
                    _atomic_write_text_0600(shared_cfg_path, config_text)
                    invocation_cfg_path.unlink(missing_ok=True)
                    reported_cfg_path = shared_cfg_path
                else:
                    reported_cfg_path = invocation_cfg_path

                _ = build_env_fn(reported_cfg_path)
                parsed_cfg = json.loads(config_text)
                if build_print_config_payload_fn is not None:
                    payload = build_print_config_payload_fn(reported_cfg_path, parsed_cfg)
                else:
                    payload = {
                        "model_id": endpoint.model_id,
                        "served_model_id": endpoint.served_model_id,
                        "api_base_url": endpoint.api_base_url,
                        "opencode_config_path": str(reported_cfg_path),
                        "isolated_home": str(isolated_home),
                        "config": parsed_cfg,
                    }
                print(json.dumps(payload, indent=2))
                return 0
            finally:
                if not is_exclusive_owner:
                    try:
                        invocation_cfg_path.unlink(missing_ok=True)
                    except OSError:
                        pass

        assert opencode_bin is not None
        env = dict(build_env_fn(invocation_cfg_path))
        env["OPENCODE_CONFIG"] = str(invocation_cfg_path)

        launcher_pid = os.getpid()
        launcher_lstart = get_process_lstart(launcher_pid) or "unavailable"
        my_entry: dict[str, Any] = {
            "invocation_id": invocation_id,
            "launcher_pid": launcher_pid,
            "launcher_lstart": launcher_lstart,
            "child_pid": None,
            "child_lstart": None,
            "status": "starting",
            "model_id": endpoint.model_id,
            "config_path": str(invocation_cfg_path),
            "sync": current_sync,
        }
        active_entries = [*retained_entries, my_entry]
        _atomic_write_text_0600(
            registry_file, json.dumps(active_entries, indent=2) + "\n"
        )

        if is_exclusive_owner:
            _atomic_write_text_0600(shared_cfg_path, config_text)
            effective_opencode_args = list(opencode_args)
            if (
                "--standalone" not in effective_opencode_args
                and "--server" not in effective_opencode_args
            ):
                prev_sync: dict[str, Any] | None = None
                if sync_file.exists():
                    try:
                        prev_sync = json.loads(sync_file.read_text(encoding="utf-8"))
                    except Exception:
                        prev_sync = None
                if prev_sync != current_sync:
                    run_service_cmd(
                        [opencode_bin, "service", "restart"],
                        cwd=str(caller_cwd),
                        env=env,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    _atomic_write_text_0600(
                        sync_file, json.dumps(current_sync, indent=2) + "\n"
                    )
        else:
            effective_opencode_args = _inject_standalone_arg(opencode_args)

        try:
            proc = popen_fn(
                [opencode_bin, *effective_opencode_args],
                cwd=str(caller_cwd),
                env=env,
            )
        except BaseException:
            # Known pre-child failure: no child process was spawned, so remove the
            # provisional "starting" record and per-invocation config immediately (R3-PLAN-MAJOR-1).
            try:
                _atomic_write_text_0600(
                    registry_file, json.dumps(retained_entries, indent=2) + "\n"
                )
            except OSError:
                pass
            try:
                invocation_cfg_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

        raw_cpid = getattr(proc, "pid", None)
        if isinstance(raw_cpid, int) and not isinstance(raw_cpid, bool) and raw_cpid > 0:
            child_pid = raw_cpid
            child_lstart = get_process_lstart(raw_cpid)
        my_entry["child_pid"] = child_pid
        my_entry["child_lstart"] = child_lstart
        if (
            child_pid is not None
            and isinstance(child_lstart, str)
            and bool(child_lstart.strip())
        ):
            my_entry["status"] = "running"
        _atomic_write_text_0600(
            registry_file, json.dumps(active_entries, indent=2) + "\n"
        )

    try:
        rc = proc.wait()
        return int(rc)
    finally:
        with _opencode_launch_lock(isolated_home):
            child_exited = False
            try:
                if proc is not None and proc.poll() is not None:
                    child_exited = True
            except Exception:
                child_exited = False
            if (
                not child_exited
                and child_pid is not None
                and isinstance(child_lstart, str)
                and child_lstart.strip()
            ):
                if classify_pid_identity(child_pid, child_lstart) in ("dead", "reused"):
                    child_exited = True

            if child_exited:
                try:
                    if registry_file.exists():
                        cur_list = json.loads(registry_file.read_text(encoding="utf-8"))
                        if isinstance(cur_list, list):
                            filtered = [
                                item
                                for item in cur_list
                                if not (
                                    isinstance(item, dict)
                                    and item.get("invocation_id") == invocation_id
                                )
                            ]
                            _atomic_write_text_0600(
                                registry_file, json.dumps(filtered, indent=2) + "\n"
                            )
                except (OSError, json.JSONDecodeError):
                    pass
                try:
                    invocation_cfg_path.unlink(missing_ok=True)
                except OSError:
                    pass
                _prune_active_opencode_clients(isolated_home)


def sync_and_run_opencode(
    opencode_bin: str,
    opencode_args: list[str],
    *,
    caller_cwd: Path,
    isolated_home: Path,
    env: dict[str, str],
    current_sync: dict[str, Any],
) -> int:
    if "--standalone" not in opencode_args:
        sync_file = isolated_home / ".last-service-sync.json"
        prev_sync: dict[str, Any] | None = None
        if sync_file.exists():
            try:
                prev_sync = json.loads(sync_file.read_text())
            except Exception:
                prev_sync = None
        if prev_sync != current_sync:
            subprocess.run(
                [opencode_bin, "service", "restart"],
                cwd=str(caller_cwd),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            sync_file.write_text(json.dumps(current_sync, indent=2))

    proc = subprocess.run(
        [opencode_bin, *opencode_args],
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
    use_token_relay: bool = False,
    allocate_worker_home_fn: Callable[[], tuple[str, Path]] = allocate_worker_home,
) -> int:
    sweep_stale_worker_homes()
    worker_id, isolated_home = allocate_worker_home_fn()
    retain_home = bool(getattr(args, "keep_worker_home", False) or getattr(args, "print_config", False))
    relay: _WorkerTokenRelay | None = None
    exit_code = 1
    lifecycle_handled_teardown = False
    try:
        if relay_factory is not None:
            relay = relay_factory().start()

        base_cfg = build_base_config_fn(relay)
        compiled_cfg = compile_opencode_security_config(
            base_cfg,
            active_profile,
            isolated_home=isolated_home,
        )
        opencode_bin_for_sb = Path(opencode_bin) if opencode_bin else Path("/usr/bin/true")
        sb_bin_for_sb = sandbox_exec_bin if sandbox_exec_bin.is_file() else Path("/usr/bin/true")
        seatbelt_kwargs: dict[str, Any] = {
            "workspace_dir": caller_cwd,
            "isolated_home": isolated_home,
            "opencode_bin": opencode_bin_for_sb,
            "sandbox_exec_bin": sb_bin_for_sb,
        }
        if upstream_port is not None:
            seatbelt_kwargs["upstream_port"] = upstream_port
        if use_token_relay:
            seatbelt_kwargs["use_token_relay"] = True
        seatbelt_text = compile_seatbelt_profile(active_profile, **seatbelt_kwargs)
        opencode_config_path, seatbelt_path, _ = write_worker_runtime_artifacts(
            isolated_home=isolated_home,
            worker_id=worker_id,
            profile=active_profile,
            opencode_config=compiled_cfg,
            seatbelt_text=seatbelt_text,
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
            payload = build_print_config_payload_fn(
                worker_id,
                opencode_config_path,
                seatbelt_path,
                isolated_home,
                compiled_cfg,
                relay,
            )
            print(redact_session_tokens(json.dumps(payload, indent=2)))
            exit_code = 0
        else:
            assert opencode_bin is not None
            lifecycle_handled_teardown = True
            lifecycle_kwargs: dict[str, Any] = {
                "cwd": str(caller_cwd),
                "env": env,
                "isolated_home": isolated_home,
                "worker_id": worker_id,
                "harvest_logs": active_profile.mcp_enable_local_assist,
                "remove_home": not retain_home,
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
