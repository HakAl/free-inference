from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import errno
import fcntl
import http.client
import io
import json
import math
import os
import re
import secrets
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlparse

from .client import open_loopback_http
from .custody import set_cli_runs_dir_override, validate_cli_runs_dir, validate_owned_directory
from .errors import LocalAssistError
from .proc_identity import read_proc_bsdinfo
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
EXIT_SESSION_BLOCKED = 4
VALID_LAUNCHER_EXIT_REASONS: frozenset[str] = frozenset({
    "opencode_session_unavailable",
    "opencode_session_caps_exhausted",
})
SAFE_ENV_ALLOWLIST = tuple(sorted(BASE_SAFE_ENV_ALLOWLIST | LAUNCHER_EXTRA_ENV_ALLOWLIST))


def normalize_non_session_exit_code(rc: int) -> int:
    code = int(rc)
    return 1 if code == EXIT_SESSION_BLOCKED else code

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
        "--allow-unix-socket",
        action="append",
        default=None,
        help="Allow sandboxed worker and declared local MCP processes to connect to an explicit absolute Unix domain socket path (repeatable).",
    )
    parser.add_argument(
        "--pass-env",
        action="append",
        default=None,
        help="Append a non-secret, unreserved environment variable name to environment.allowlist (repeatable).",
    )
    parser.add_argument(
        "--opencode-bin",
        default=None,
        help="Explicit absolute path to the OpenCode executable (avoids PATH lookup in custody runs).",
    )
    parser.add_argument(
        "--launcher-site-packages",
        default=None,
        help="Explicit absolute path to a read-only installed launcher dependency directory (for example PyYAML).",
    )
    parser.add_argument(
        "--runs-dir",
        default=None,
        help="Explicit session store directory override for non-custody local checkout runs (refused in custody mode).",
    )
    parser.add_argument(
        "--inherit-process-group",
        action="store_true",
        default=False,
        help="Start OpenCode serve and run inside the caller's process group instead of creating a new session.",
    )
    parser.add_argument(
        "--worker-manifest",
        default=None,
        help="Write an atomic 0600 worker process identity and Seatbelt tag manifest JSON to this absolute path.",
    )
    parser.add_argument(
        "--run-token",
        default=None,
        help="Supervisor run token bound into --worker-manifest and --launcher-exit-file.",
    )
    parser.add_argument(
        "--launcher-exit-file",
        default=None,
        help="Write an atomic 0600 session-failure diagnostic JSON to this absolute path before exiting with code 4.",
    )
    parser.add_argument(
        "--reap-worker",
        default=None,
        help="Execute race-safe Section 6.4 worker process reaping from the specified 0600 manifest JSON and exit.",
    )
    parser.add_argument(
        "--reap-timeout",
        type=float,
        default=10.0,
        help="Maximum seconds to wait for two consecutive empty same-UID enumerations during --reap-worker (default: 10.0).",
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
            getattr(args, "allow_unix_socket", None),
            getattr(args, "inherit_session_caps", False),
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
        allowed_unix_sockets=getattr(args, "allow_unix_socket", None),
        inherit_session_caps=True if getattr(args, "inherit_session_caps", False) else None,
        pass_env=args.pass_env,
    )


def _validate_output_artifact_path(raw_path: str, flag_name: str) -> tuple[Path | None, str | None]:
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None, f"{flag_name} must be a non-empty absolute file path."
    cleaned = raw_path.strip()
    if not cleaned.startswith("/") or cleaned.endswith("/"):
        return None, f"{flag_name} must be an absolute file path starting with '/', got {raw_path!r}."
    segs = [s for s in cleaned.split("/") if s]
    if not segs or "." in segs or ".." in segs:
        return None, f"{flag_name} must not contain '.' or '..' segments: {raw_path!r}."
    p = Path(cleaned)
    if not validate_owned_directory(p.parent):
        return (
            None,
            f"{flag_name} parent directory '{p.parent}' must be an existing, non-symlink directory owned by uid {os.geteuid()} and not group/world-writable.",
        )
    try:
        st = os.lstat(p)
        if stat.S_ISLNK(st.st_mode) or stat.S_ISDIR(st.st_mode):
            return None, f"{flag_name} target '{p}' must not be a symlink or directory."
    except FileNotFoundError:
        pass
    except OSError as exc:
        return None, f"{flag_name} cannot stat '{p}': {exc}"
    return p, None


def resolve_opencode_binary(args: argparse.Namespace) -> tuple[str | None, str | None]:
    explicit = getattr(args, "opencode_bin", None)
    if explicit is not None:
        if not isinstance(explicit, str) or not explicit.strip():
            return None, "--opencode-bin must be a non-empty absolute path."
        cleaned = explicit.strip()
        if not cleaned.startswith("/"):
            return None, f"--opencode-bin must be an absolute path, got {explicit!r}."
        segs = [s for s in cleaned.split("/") if s]
        if "." in segs or ".." in segs:
            return None, f"--opencode-bin must not contain '.' or '..' segments: {explicit!r}."
        cand = Path(cleaned)
        if not cand.is_file() or not os.access(cand, os.X_OK):
            return None, f"--opencode-bin '{cand}' does not exist or is not an executable file."
        return str(cand), None
    return shutil.which("opencode"), None


def apply_inprocess_runs_dir_arg(args: argparse.Namespace) -> str | None:
    raw_runs = getattr(args, "runs_dir", None)
    allow_absent = bool(getattr(args, "allow_absent_runs_dir", False))
    if raw_runs is None:
        if allow_absent:
            return "--allow-absent-runs-dir requires --runs-dir."
        return None
    from .custody import (
        PINNED_RUNS_STAT_ENV_VAR,
        get_active_bootstrap_state,
        inspect_existing_runs_dir,
        is_custody_tree,
        parse_pinned_runs_stat_env,
        validate_creatable_runs_dir,
    )
    from .paths import ROOT as _LAB_ROOT

    st = get_active_bootstrap_state()
    if (st is not None and st.custody_mode) or is_custody_tree(_LAB_ROOT):
        return "Refusing --runs-dir in read-only/custody mode."
    expected_stat, pin_err = parse_pinned_runs_stat_env()
    if pin_err is not None:
        return pin_err
    if allow_absent:
        if expected_stat is not None:
            return f"Cannot combine --allow-absent-runs-dir with {PINNED_RUNS_STAT_ENV_VAR}."
        v_res, err = validate_creatable_runs_dir(raw_runs, label="--runs-dir")
    else:
        v_res, err = inspect_existing_runs_dir(
            raw_runs,
            expected_stat=expected_stat,
            label="--runs-dir",
        )
    if err is not None or v_res is None:
        return err or "Invalid --runs-dir."
    set_cli_runs_dir_override(v_res.path, runs_stat=v_res.stat_id)
    return None


def write_launcher_exit_diagnostic(
    exit_file: str | Path,
    *,
    run_token: str,
    reason: str,
) -> bool:
    if reason not in VALID_LAUNCHER_EXIT_REASONS:
        return False
    if not isinstance(run_token, str) or not run_token.strip():
        return False
    target_path, err = _validate_output_artifact_path(str(exit_file), "--launcher-exit-file")
    if err is not None or target_path is None:
        return False
    payload = {
        "schema_version": 1,
        "run_token": run_token.strip(),
        "launcher_pid": os.getpid(),
        "reason": reason,
    }
    try:
        _atomic_write_text_0600(target_path, json.dumps(payload, indent=2) + "\n")
        st = os.lstat(target_path)
        return not stat.S_ISLNK(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600
    except OSError:
        return False


@dataclass(frozen=True)
class PreparedWorkerIdentity:
    worker_id: str
    isolated_home: Path
    worker_tag: str
    manifest_path: Path
    run_token: str
    retain_home: bool
    launcher_pid: int
    launcher_pgid: int
    launcher_start_tvsec: int
    launcher_start_tvusec: int
    launcher_lstart: str


def cleanup_prepared_worker_identity(identity: PreparedWorkerIdentity | None) -> None:
    if identity is None:
        return
    if identity.retain_home:
        try:
            (identity.isolated_home / ".keep-worker-home").write_text("1\n", encoding="utf-8")
        except OSError:
            pass
    try:
        teardown_worker_home(
            identity.isolated_home,
            worker_id=identity.worker_id,
            harvest_logs=False,
            remove_home=not identity.retain_home,
            reap_processes=False,
        )
    except Exception:
        pass


def prepare_early_worker_manifest_from_argv(
    argv: Sequence[str],
    *,
    allocate_worker_home_fn: Callable[[], tuple[str, Path]] = allocate_worker_home,
) -> tuple[bool, PreparedWorkerIdentity | None, str | None]:
    """Publish initial 0600 manifest.json (children: []) before any pre-OpenCode failure can return (R1)."""
    tokens = list(argv[1:])
    if "--" in tokens:
        tokens = tokens[: tokens.index("--")]

    has_reap = False
    has_inherit_pg = False
    retain_home = False
    raw_manifest: str | None = None
    manifest_seen = False
    raw_run_token: str | None = None
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--reap-worker" or tok.startswith("--reap-worker="):
            has_reap = True
            i += 1
            continue
        if tok == "--inherit-process-group":
            has_inherit_pg = True
            i += 1
            continue
        if tok in ("--keep-worker-home", "--print-config"):
            retain_home = True
            i += 1
            continue
        if tok == "--worker-manifest":
            manifest_seen = True
            if i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                raw_manifest = tokens[i + 1]
                i += 2
                continue
            raw_manifest = ""
            i += 1
            continue
        if tok.startswith("--worker-manifest="):
            manifest_seen = True
            raw_manifest = tok.split("=", 1)[1]
            i += 1
            continue
        if tok == "--run-token":
            if i + 1 < len(tokens):
                raw_run_token = tokens[i + 1]
                i += 2
                continue
            raw_run_token = ""
            i += 1
            continue
        if tok.startswith("--run-token="):
            raw_run_token = tok.split("=", 1)[1]
            i += 1
            continue
        i += 1

    if has_reap or not manifest_seen:
        return True, None, None

    if not has_inherit_pg:
        return False, None, "--worker-manifest requires --inherit-process-group."
    if not isinstance(raw_run_token, str) or not raw_run_token.strip():
        return False, None, "--worker-manifest requires a non-empty --run-token."
    manifest_path, path_err = _validate_output_artifact_path(raw_manifest or "", "--worker-manifest")
    if path_err is not None or manifest_path is None:
        return False, None, path_err or "Invalid --worker-manifest."

    launcher_pid = os.getpid()
    launcher_pgid = os.getpgrp()
    if launcher_pgid != launcher_pid:
        return (
            False,
            None,
            f"Refusing --worker-manifest with --inherit-process-group: launcher_pgid ({launcher_pgid}) != launcher_pid ({launcher_pid}).",
        )
    st_self, info_self = read_proc_bsdinfo(launcher_pid)
    if st_self != "alive" or info_self is None:
        return (
            False,
            None,
            "Refusing --worker-manifest: proc_pidinfo start-time query unavailable on this platform.",
        )

    sweep_stale_worker_homes()
    try:
        worker_id, isolated_home = allocate_worker_home_fn()
    except Exception as exc:
        return False, None, f"Failed to allocate worker home: {exc}"

    worker_tag = secrets.token_hex(16)
    launcher_lstart = get_process_lstart(launcher_pid) or ""
    identity = PreparedWorkerIdentity(
        worker_id=worker_id,
        isolated_home=isolated_home,
        worker_tag=worker_tag,
        manifest_path=manifest_path,
        run_token=raw_run_token.strip(),
        retain_home=retain_home,
        launcher_pid=int(launcher_pid),
        launcher_pgid=int(launcher_pgid),
        launcher_start_tvsec=int(info_self["start_tvsec"]),
        launcher_start_tvusec=int(info_self["start_tvusec"]),
        launcher_lstart=launcher_lstart,
    )
    doc = {
        "schema_version": 1,
        "run_token": identity.run_token,
        "launcher_pid": identity.launcher_pid,
        "launcher_pgid": identity.launcher_pgid,
        "launcher_start_tvsec": identity.launcher_start_tvsec,
        "launcher_start_tvusec": identity.launcher_start_tvusec,
        "launcher_lstart": identity.launcher_lstart,
        "worker_id": identity.worker_id,
        "isolated_home": str(identity.isolated_home),
        "worker_tag": identity.worker_tag,
        "children": [],
    }
    try:
        _atomic_write_text_0600(manifest_path, json.dumps(doc, indent=2) + "\n")
        mst = os.lstat(manifest_path)
        if stat.S_ISLNK(mst.st_mode) or stat.S_IMODE(mst.st_mode) != 0o600:
            cleanup_prepared_worker_identity(identity)
            return False, None, f"Failed to verify 0600 permissions on worker manifest '{manifest_path}'."
    except OSError as exc:
        cleanup_prepared_worker_identity(identity)
        return False, None, f"Failed to write worker manifest '{manifest_path}': {exc}"

    return True, identity, None


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

    raw_manifest = getattr(args, "worker_manifest", None)
    raw_exit_file = getattr(args, "launcher_exit_file", None)
    raw_run_token = getattr(args, "run_token", None)
    inherit_pg = bool(getattr(args, "inherit_process_group", False))

    if raw_manifest is not None:
        _, m_err = _validate_output_artifact_path(raw_manifest, "--worker-manifest")
        if m_err is not None:
            return m_err
        if not isinstance(raw_run_token, str) or not raw_run_token.strip():
            return "--worker-manifest requires a non-empty --run-token."
        if not inherit_pg:
            return "Refusing --worker-manifest without --inherit-process-group."

    if raw_exit_file is not None:
        _, e_err = _validate_output_artifact_path(raw_exit_file, "--launcher-exit-file")
        if e_err is not None:
            return e_err
        if not isinstance(raw_run_token, str) or not raw_run_token.strip():
            return "--launcher-exit-file requires a non-empty --run-token."

    if active_profile is None:
        if inherit_pg or raw_manifest is not None:
            return "Refusing --inherit-process-group / --worker-manifest outside unattended worker security profile mode."
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


def _terminate_and_reap_process_bounded(
    proc_obj: Any,
    *,
    term_timeout: float = 2.0,
    kill_timeout: float = 1.0,
) -> bool:
    """Bounded terminate -> wait -> kill -> wait; returns True only if process exit is confirmed."""
    try:
        if proc_obj.poll() is not None:
            return True
    except Exception:
        return False
    try:
        if hasattr(proc_obj, "terminate"):
            proc_obj.terminate()
        elif isinstance(getattr(proc_obj, "pid", None), int) and proc_obj.pid > 1:
            os.kill(proc_obj.pid, signal.SIGTERM)
        if hasattr(proc_obj, "wait"):
            proc_obj.wait(timeout=term_timeout)
    except Exception:
        try:
            if hasattr(proc_obj, "kill"):
                proc_obj.kill()
            elif isinstance(getattr(proc_obj, "pid", None), int) and proc_obj.pid > 1:
                os.kill(proc_obj.pid, signal.SIGKILL)
            if hasattr(proc_obj, "wait"):
                proc_obj.wait(timeout=kill_timeout)
        except Exception:
            pass
    try:
        return proc_obj.poll() is not None
    except Exception:
        return False


def _pending_service_boot_marker_path(isolated_home: Path) -> Path:
    return isolated_home / ".opencode-service-boot.pending.json"


_BOOT_UUID_RE = re.compile(
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
)


def _get_host_boot_id() -> str | None:
    """Return a canonical per-boot host UUID (macOS kern.bootsessionuuid or Linux boot_id)."""
    if sys.platform == "darwin":
        try:
            import ctypes

            libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
            fn = libc.sysctlbyname
            fn.argtypes = [
                ctypes.c_char_p,
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_size_t),
                ctypes.c_void_p,
                ctypes.c_size_t,
            ]
            fn.restype = ctypes.c_int
            size = ctypes.c_size_t(0)
            if fn(b"kern.bootsessionuuid", None, ctypes.byref(size), None, 0) == 0 and 0 < size.value <= 256:
                buf = ctypes.create_string_buffer(size.value)
                if fn(b"kern.bootsessionuuid", buf, ctypes.byref(size), None, 0) == 0:
                    val = buf.value.decode("ascii", errors="ignore").strip()
                    if _BOOT_UUID_RE.fullmatch(val):
                        return val.lower()
        except Exception:
            pass
    elif sys.platform.startswith("linux"):
        try:
            val = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
            if _BOOT_UUID_RE.fullmatch(val):
                return val.lower()
        except OSError:
            pass
    return None


def _write_pending_service_boot_guard(
    isolated_home: Path,
    *,
    invocation_id: str,
    proc_obj: Any = None,
) -> bool:
    """Persist durable write-ahead guard before spawning serve_proc (and update with serve pid after spawn)."""
    payload: dict[str, Any] = {
        "invocation_id": invocation_id,
        "boot_id": _get_host_boot_id() or "unavailable",
        "launcher_pid": os.getpid(),
        "launcher_lstart": get_process_lstart(os.getpid()) or "unavailable",
        "recorded_at": time.time(),
    }
    pid = getattr(proc_obj, "pid", None) if proc_obj is not None else None
    if isinstance(pid, int) and not isinstance(pid, bool) and pid > 1:
        payload["pid"] = pid
        payload["pid_lstart"] = get_process_lstart(pid) or "unavailable"
    try:
        _atomic_write_text_0600(
            _pending_service_boot_marker_path(isolated_home),
            json.dumps(payload, indent=2) + "\n",
        )
        return True
    except OSError:
        return False


def _clear_pending_service_reap_if_matches(
    isolated_home: Path,
    *,
    invocation_id: str | None = None,
    expected_pid: int | None = None,
) -> None:
    marker = _pending_service_boot_marker_path(isolated_home)
    if not marker.is_file() or marker.is_symlink():
        return
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return
    if not isinstance(data, dict):
        return
    id_match = invocation_id is not None and data.get("invocation_id") == invocation_id
    pid_match = expected_pid is not None and data.get("pid") == expected_pid
    if id_match or pid_match:
        try:
            marker.unlink()
        except OSError:
            pass


def _unlink_pending_boot_marker(marker: Path) -> bool:
    try:
        marker.unlink()
        return True
    except FileNotFoundError:
        return True
    except OSError:
        return False


def _check_and_clear_pending_service_reap(isolated_home: Path) -> tuple[bool, str | None]:
    """Return (True, None) if clear to boot, else (False, actionable_reason)."""
    marker = _pending_service_boot_marker_path(isolated_home)
    if not marker.exists() and not marker.is_symlink():
        return True, None
    if marker.is_symlink() or not marker.is_file():
        return (
            False,
            f"corrupt or unsafe service-boot guard at '{marker}'; verify no 'opencode serve --service' "
            f"process is running for '{isolated_home}', then remove '{marker}' to recover.",
        )
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return (
            False,
            f"unreadable service-boot guard at '{marker}'; verify no 'opencode serve --service' "
            f"process is running for '{isolated_home}', then remove '{marker}' to recover.",
        )
    if not isinstance(data, dict):
        return (
            False,
            f"malformed service-boot guard at '{marker}'; verify no 'opencode serve --service' "
            f"process is running for '{isolated_home}', then remove '{marker}' to recover.",
        )

    # Host reboot proves every local process from the prior boot is gone, even when child PID was not recorded.
    # Require canonical UUID syntax on BOTH saved and current boot IDs so malformed/corrupt boot_id values
    # never bypass PID liveness or fail-closed checks.
    saved_boot_id = data.get("boot_id")
    cur_boot_id = _get_host_boot_id()
    saved_boot_valid = isinstance(saved_boot_id, str) and bool(_BOOT_UUID_RE.fullmatch(saved_boot_id))
    cur_boot_valid = isinstance(cur_boot_id, str) and bool(_BOOT_UUID_RE.fullmatch(cur_boot_id))
    if saved_boot_valid and cur_boot_valid and saved_boot_id.lower() != cur_boot_id.lower():
        if _unlink_pending_boot_marker(marker):
            return True, None
        return (
            False,
            f"failed to clear stale prior-boot guard '{marker}' after host reboot; remove '{marker}' manually to recover.",
        )

    pid = data.get("pid")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        # Same host boot (or boot ID unavailable) and child PID was never recorded (e.g. abrupt
        # interruption or post-spawn ENOSPC): stay fail-closed and guide supported recovery.
        if saved_boot_valid and cur_boot_valid:
            recovery_clause = f"then remove '{marker}' or reboot to recover."
        elif saved_boot_valid:
            recovery_clause = (
                f"then manually remove '{marker}' to recover (current host boot UUID could not be read, "
                "so reboot auto-clear cannot be verified now; a later boot reporting a different valid boot UUID will auto-clear this guard)."
            )
        else:
            recovery_clause = (
                f"then manually remove '{marker}' to recover (reboot alone will not auto-clear this guard "
                "because no valid boot UUID was recorded)."
            )
        return (
            False,
            f"a prior service boot on '{isolated_home}' was interrupted before recording its child service PID "
            f"(guard '{marker}', invocation={data.get('invocation_id', 'unknown')}, "
            f"launcher_pid={data.get('launcher_pid', 'unknown')}); verify no 'opencode serve --service' "
            f"process is running for this home, {recovery_clause}",
        )

    saved_lstart = data.get("pid_lstart")
    if not pid_is_alive(pid):
        if _unlink_pending_boot_marker(marker):
            return True, None
        return (
            False,
            f"failed to clear stale service-boot guard '{marker}' after pid {pid} exited; remove '{marker}' manually to recover.",
        )
    saved_lstart_norm = saved_lstart.strip() if isinstance(saved_lstart, str) else ""
    saved_lstart_valid = bool(saved_lstart_norm) and saved_lstart_norm != "unavailable"
    cur_lstart = get_process_lstart(pid)
    cur_lstart_norm = cur_lstart.strip() if isinstance(cur_lstart, str) else ""
    cur_lstart_valid = bool(cur_lstart_norm) and cur_lstart_norm != "unavailable"
    if saved_lstart_valid and cur_lstart_valid and cur_lstart_norm != saved_lstart_norm:
        # PID has been recycled to a different process; prior service is gone.
        if _unlink_pending_boot_marker(marker):
            return True, None
        return (
            False,
            f"failed to clear recycled-PID service-boot guard '{marker}'; remove '{marker}' manually to recover.",
        )
    identity_confirmed = saved_lstart_valid and cur_lstart_valid and cur_lstart_norm == saved_lstart_norm
    if identity_confirmed:
        if saved_boot_valid and cur_boot_valid:
            return (
                False,
                f"a prior failed per-invocation service (pid={pid}, start time verified) is still alive/unreaped "
                f"on '{isolated_home}' (guard '{marker}'); stop pid {pid} (or reboot) and retry.",
            )
        if saved_boot_valid:
            return (
                False,
                f"a prior failed per-invocation service (pid={pid}, start time verified) is still alive/unreaped "
                f"on '{isolated_home}' (guard '{marker}'); stop pid {pid} and retry (or manually remove '{marker}' "
                "after confirming it is gone; current host boot UUID could not be read, though a later boot reporting "
                "a different valid boot UUID will auto-clear this guard).",
            )
        return (
            False,
            f"a prior failed per-invocation service (pid={pid}, start time verified) is still alive/unreaped "
            f"on '{isolated_home}' (guard '{marker}'); stop pid {pid} and retry (or manually remove '{marker}' "
            "after confirming it is gone; reboot alone will not auto-clear this guard because no valid boot UUID was recorded).",
        )
    saved_disp = saved_lstart_norm if saved_lstart_valid else "unavailable"
    cur_disp = cur_lstart_norm if cur_lstart_valid else "unavailable"
    if saved_boot_valid and cur_boot_valid:
        unverified_recovery = f"remove '{marker}' or reboot to recover."
    elif saved_boot_valid:
        unverified_recovery = (
            f"manually remove '{marker}' to recover (current host boot UUID could not be read, "
            "so reboot auto-clear cannot be verified now; a later boot reporting a different valid boot UUID will auto-clear this guard)."
        )
    else:
        unverified_recovery = (
            f"manually remove '{marker}' to recover (reboot alone will not auto-clear this guard "
            "because no valid boot UUID was recorded)."
        )
    return (
        False,
        f"a live process occupies recorded pid={pid} on '{isolated_home}', but its service identity is unverified "
        f"(saved_lstart={saved_disp}, current_lstart={cur_disp}; guard '{marker}'); confirm that pid {pid} is "
        f"actually 'opencode serve --service' for '{isolated_home}' before stopping it, then {unverified_recovery}",
    )


@contextlib.contextmanager
def _opencode_service_boot_lock(isolated_home: Path):
    """Serialize concurrent OpenCode 2.3.2 service DB migrations without blocking _opencode_launch_lock."""
    isolated_home.mkdir(parents=True, exist_ok=True)
    lock_path = isolated_home / ".opencode-service-boot.lock"
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
    "api",
    "plugin",
    "reload",
    "mcp",
})

INTERACTIVE_ROOT_VALUE_FLAGS: frozenset[str] = frozenset({
    "--session",
    "-s",
    "--prompt",
    "--completions",
    "--log-level",
})

MAX_CLI_CONFIG_BYTES = 65536


def _is_finite_number(val: Any) -> bool:
    if not isinstance(val, (int, float)) or isinstance(val, bool):
        return False
    try:
        return math.isfinite(float(val))
    except (OverflowError, ValueError, TypeError):
        return False


def _is_nonneg_int(val: Any) -> bool:
    return isinstance(val, int) and not isinstance(val, bool) and val >= 0


def _validate_cli_leaf(path: tuple[str, ...], val: Any) -> bool:
    if path == ("$schema",):
        return isinstance(val, str)
    if path in (("animations",), ("highlights",), ("mouse",)):
        return isinstance(val, bool)
    if len(path) != 2:
        return False
    section, key = path
    if section == "theme":
        if key == "name":
            return isinstance(val, str)
        if key == "mode":
            return val in ("system", "dark", "light")
        return False
    if section == "keybinds":
        if not isinstance(key, str) or not key:
            return False
        if isinstance(val, (str, bool)):
            return True
        if isinstance(val, list):
            return all(isinstance(item, str) for item in val)
        return False
    if section == "leader":
        return key == "timeout" and _is_nonneg_int(val)
    if section == "scroll":
        if key == "speed":
            return _is_finite_number(val) and float(val) >= 0.001
        if key == "acceleration":
            return isinstance(val, bool)
        return False
    if section == "attention":
        if key in ("notifications", "sound"):
            return isinstance(val, bool)
        if key == "volume":
            return _is_finite_number(val) and 0.0 <= float(val) <= 1.0
        if key == "sound_pack":
            return isinstance(val, str)
        return False
    if section == "diffs":
        if key == "source":
            return isinstance(val, str)
        if key == "wrap":
            return val in ("word", "none")
        if key in ("tree", "single", "fullscreen"):
            return isinstance(val, bool)
        if key == "view":
            return val in ("auto", "split", "unified")
        return False
    if section == "terminal":
        if key == "title":
            return isinstance(val, bool)
        if key == "copy":
            return val in ("manual", "select")
        return False
    if section == "prompt":
        if key in ("editor", "image_preview"):
            return isinstance(val, bool)
        if key == "paste":
            return val in ("compact", "full")
        return False
    if section == "session":
        if key == "sidebar":
            return val in ("auto", "hide")
        if key in ("scrollbar", "image_preview", "tps"):
            return isinstance(val, bool)
        if key == "submit_scroll":
            return val in ("bottom", "keep")
        if key == "thinking":
            return val in ("show", "hide")
        if key == "grouping":
            return val in ("auto", "none")
        if key == "verbosity":
            return val in ("low", "medium", "high")
        if key == "markdown":
            return val in ("source", "rendered")
        if key == "new_location":
            return val in ("launch", "inherit")
        if key == "permissions":
            return val in ("prompt", "autoaccept")
        return False
    if section == "tabs":
        if key == "mode":
            return val in ("auto", "on", "off")
        if key == "enabled":
            return isinstance(val, bool)
        if key == "scope":
            return val in ("global", "cwd")
        if key == "layout":
            return val in ("horizontal", "vertical")
        if key == "indicators":
            return val in ("status", "numbers")
        return False
    if section == "mini":
        if key in ("thinking", "tools", "shell_output", "turn_summary", "footer", "splash"):
            return val in ("show", "hide")
        if key == "work_spinner":
            return isinstance(val, str)
        if key in ("mono", "replay"):
            return isinstance(val, bool)
        if key == "replay_limit":
            return _is_nonneg_int(val)
        return False
    if section == "debug":
        if key in ("devtools", "timing"):
            return isinstance(val, bool)
        if key == "turn_tokens":
            return isinstance(val, bool) or val == "verbose"
        return False
    if section == "cursor":
        if key == "style":
            return val in ("block", "underline", "line", "default")
        if key == "blinking":
            return isinstance(val, bool)
        return False
    return False


_CLI_CONFIG_NESTED_SECTIONS: frozenset[str] = frozenset({
    "theme",
    "keybinds",
    "leader",
    "scroll",
    "attention",
    "diffs",
    "terminal",
    "prompt",
    "session",
    "tabs",
    "mini",
    "debug",
    "cursor",
})

_CLI_CONFIG_SCALAR_ROOTS: frozenset[str] = frozenset({
    "$schema",
    "animations",
    "highlights",
    "mouse",
})


def sanitize_cli_config_dict(raw: Any) -> dict[str, Any]:
    """Filter raw JSON object to allowlisted, type-checked non-executable CLI UI preferences."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for top_key, top_val in raw.items():
        if not isinstance(top_key, str):
            continue
        if top_key in _CLI_CONFIG_SCALAR_ROOTS:
            if _validate_cli_leaf((top_key,), top_val):
                out[top_key] = copy.deepcopy(top_val)
        elif top_key in _CLI_CONFIG_NESTED_SECTIONS and isinstance(top_val, dict):
            sec_out: dict[str, Any] = {}
            for leaf_key, leaf_val in top_val.items():
                if not isinstance(leaf_key, str):
                    continue
                if _validate_cli_leaf((top_key, leaf_key), leaf_val):
                    sec_out[leaf_key] = copy.deepcopy(leaf_val)
            if sec_out:
                out[top_key] = sec_out
    return out


def _flatten_cli_config_leaves(sanitized: Mapping[str, Any]) -> dict[tuple[str, ...], Any]:
    leaves: dict[tuple[str, ...], Any] = {}
    for top_key, top_val in sanitized.items():
        if top_key in _CLI_CONFIG_SCALAR_ROOTS:
            leaves[(top_key,)] = copy.deepcopy(top_val)
        elif top_key in _CLI_CONFIG_NESTED_SECTIONS and isinstance(top_val, dict):
            for leaf_key, leaf_val in top_val.items():
                leaves[(top_key, leaf_key)] = copy.deepcopy(leaf_val)
    return leaves


def _unflatten_cli_config_leaves(leaves: Mapping[tuple[str, ...], Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for path in sorted(leaves.keys()):
        val = copy.deepcopy(leaves[path])
        if len(path) == 1:
            out[path[0]] = val
        elif len(path) == 2:
            sec = out.setdefault(path[0], {})
            if isinstance(sec, dict):
                sec[path[1]] = val
    return out


def merge_cli_config_three_way(
    staged: Mapping[str, Any],
    final: Mapping[str, Any],
    disk: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Three-way leaf-path merge preserving concurrent sibling updates and additions."""
    staged_leaves = _flatten_cli_config_leaves(sanitize_cli_config_dict(dict(staged)))
    final_leaves = _flatten_cli_config_leaves(sanitize_cli_config_dict(dict(final)))
    disk_leaves = _flatten_cli_config_leaves(sanitize_cli_config_dict(dict(disk)))

    updates = {
        k: v
        for k, v in final_leaves.items()
        if k not in staged_leaves or staged_leaves[k] != v
    }
    deletes = {k for k in staged_leaves if k not in final_leaves}
    if not updates and not deletes:
        return None

    merged = dict(disk_leaves)
    for k in deletes:
        if k in merged and merged[k] == staged_leaves[k]:
            del merged[k]
    for k, v in updates.items():
        merged[k] = v
    return _unflatten_cli_config_leaves(merged)


def _open_pinned_opencode_config_dir(
    base_dir: Path,
    *,
    create: bool,
) -> tuple[str, int | None]:
    """Walk base_dir/.config/opencode with O_DIRECTORY|O_NOFOLLOW and fstat validation."""
    euid = os.geteuid()
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    cur_fd: int | None = None
    try:
        try:
            cur_fd = os.open(str(base_dir), dir_flags)
        except FileNotFoundError:
            return "absent", None
        except OSError:
            return "invalid", None
        try:
            st_base = os.fstat(cur_fd)
        except OSError:
            return "invalid", None
        if not stat.S_ISDIR(st_base.st_mode) or st_base.st_uid != euid:
            return "invalid", None

        for seg in (".config", "opencode"):
            created_seg = False
            try:
                next_fd = os.open(seg, dir_flags, dir_fd=cur_fd)
            except FileNotFoundError:
                if not create:
                    return "absent", None
                try:
                    os.mkdir(seg, 0o700, dir_fd=cur_fd)
                    created_seg = True
                except FileExistsError:
                    pass
                except OSError:
                    return "invalid", None
                try:
                    next_fd = os.open(seg, dir_flags, dir_fd=cur_fd)
                except OSError:
                    return "invalid", None
            except OSError:
                return "invalid", None

            old_fd = cur_fd
            cur_fd = next_fd
            try:
                os.close(old_fd)
            except OSError:
                pass
            try:
                st_seg = os.fstat(cur_fd)
            except OSError:
                return "invalid", None
            if (
                not stat.S_ISDIR(st_seg.st_mode)
                or st_seg.st_uid != euid
                or (st_seg.st_mode & 0o022) != 0
            ):
                return "invalid", None
            if created_seg:
                try:
                    os.fchmod(cur_fd, 0o700)
                except OSError:
                    return "invalid", None

        res_fd = cur_fd
        cur_fd = None
        return "ok", res_fd
    finally:
        if cur_fd is not None:
            try:
                os.close(cur_fd)
            except OSError:
                pass


def _read_cli_config_from_dirfd(dir_fd: int) -> tuple[str, dict[str, Any] | None]:
    """Read and sanitize cli.json relative to pinned dir_fd without following symlinks."""
    euid = os.geteuid()
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    fd: int | None = None
    try:
        try:
            fd = os.open("cli.json", flags, dir_fd=dir_fd)
        except FileNotFoundError:
            return "absent", {}
        except OSError:
            return "invalid", None

        try:
            st = os.fstat(fd)
        except OSError:
            return "invalid", None
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != euid
            or st.st_size > MAX_CLI_CONFIG_BYTES
        ):
            return "invalid", None

        chunks: list[bytes] = []
        total = 0
        limit = MAX_CLI_CONFIG_BYTES + 1
        try:
            while total < limit:
                chunk = os.read(fd, min(8192, limit - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
        except OSError:
            return "invalid", None
        if total > MAX_CLI_CONFIG_BYTES:
            return "invalid", None

        raw_bytes = b"".join(chunks)
        try:
            parsed = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
            return "invalid", None
        if not isinstance(parsed, dict):
            return "invalid", None
        return "ok", sanitize_cli_config_dict(parsed)
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _write_cli_config_to_dirfd(
    dir_fd: int,
    data: Mapping[str, Any],
    *,
    err_stream: Any = None,
) -> bool:
    """Atomically write bounded sanitized cli.json via O_CREAT|O_EXCL temp file and dirfd os.replace."""
    sanitized = sanitize_cli_config_dict(dict(data))
    payload = (json.dumps(sanitized, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > MAX_CLI_CONFIG_BYTES:
        out = err_stream if err_stream is not None else sys.stderr
        print(
            f"WARNING: Refusing to persist cli.json: serialized size {len(payload)} bytes exceeds "
            f"{MAX_CLI_CONFIG_BYTES}-byte limit; keeping existing file unchanged.",
            file=out,
        )
        return False

    tmp_name = f".cli.json.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
    )
    fd: int | None = None
    created = False
    try:
        fd = os.open(tmp_name, flags, 0o600, dir_fd=dir_fd)
        created = True
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, "Temporary cli.json target is not a regular file")
        os.fchmod(fd, 0o600)
        view = memoryview(payload)
        written = 0
        while written < len(payload):
            n = os.write(fd, view[written:])
            if n <= 0:
                raise OSError(errno.EIO, "Short write persisting cli.json")
            written += n
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.replace(tmp_name, "cli.json", src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        created = False
        return True
    except OSError as exc:
        out = err_stream if err_stream is not None else sys.stderr
        print(f"WARNING: Failed to persist cli.json safely: {exc}", file=out)
        return False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if created:
            try:
                os.unlink(tmp_name, dir_fd=dir_fd)
            except OSError:
                pass


def _stage_interactive_cli_config(
    isolated_home: Path,
    inv_dir: Path,
    *,
    err_stream: Any = None,
) -> tuple[dict[str, Any], bool]:
    """Read sanitized cli.json from isolated_home and stage into inv_dir/.config/opencode/cli.json."""
    src_status, src_dir_fd = _open_pinned_opencode_config_dir(isolated_home, create=False)
    if src_status == "invalid":
        out = err_stream if err_stream is not None else sys.stderr
        print(
            f"WARNING: Ignoring unsafe persistent cli.json directory under '{isolated_home}'; "
            "write-back disabled for this session.",
            file=out,
        )
        return {}, False
    if src_status == "absent" or src_dir_fd is None:
        return {}, True

    try:
        file_status, staged = _read_cli_config_from_dirfd(src_dir_fd)
    finally:
        os.close(src_dir_fd)

    if file_status == "invalid" or staged is None:
        out = err_stream if err_stream is not None else sys.stderr
        print(
            f"WARNING: Ignoring invalid or unsafe persistent cli.json under '{isolated_home}'; "
            "write-back disabled for this session.",
            file=out,
        )
        return {}, False
    if file_status == "absent" or not staged:
        return {}, True

    dst_status, dst_dir_fd = _open_pinned_opencode_config_dir(inv_dir, create=False)
    if dst_status != "ok" or dst_dir_fd is None:
        return {}, False
    try:
        if not _write_cli_config_to_dirfd(dst_dir_fd, staged, err_stream=err_stream):
            return {}, False
    finally:
        os.close(dst_dir_fd)
    return copy.deepcopy(staged), True


def _persist_interactive_cli_config(
    isolated_home: Path,
    inv_dir: Path,
    staged_cli_cfg: Mapping[str, Any],
    *,
    err_stream: Any = None,
) -> bool:
    """Merge safe cli.json updates from inv_dir back into isolated_home/.config/opencode/cli.json."""
    inv_status, inv_dir_fd = _open_pinned_opencode_config_dir(inv_dir, create=False)
    if inv_status != "ok" or inv_dir_fd is None:
        return False
    try:
        final_status, final_cfg = _read_cli_config_from_dirfd(inv_dir_fd)
    finally:
        os.close(inv_dir_fd)

    if final_status == "invalid" or final_cfg is None:
        return False
    if final_status == "absent" and not staged_cli_cfg:
        return False

    # Quick check before taking lock: skip disk I/O if nothing changed.
    if merge_cli_config_three_way(staged_cli_cfg, final_cfg, {}) is None:
        return False

    with _opencode_launch_lock(isolated_home):
        dst_status, dst_dir_fd = _open_pinned_opencode_config_dir(isolated_home, create=True)
        if dst_status != "ok" or dst_dir_fd is None:
            out = err_stream if err_stream is not None else sys.stderr
            print(
                f"WARNING: Refusing cli.json write-back: unsafe target directory under '{isolated_home}'.",
                file=out,
            )
            return False
        try:
            disk_status, disk_cfg = _read_cli_config_from_dirfd(dst_dir_fd)
            if disk_status == "invalid" or disk_cfg is None:
                out = err_stream if err_stream is not None else sys.stderr
                print(
                    f"WARNING: Refusing cli.json write-back: existing file under '{isolated_home}' is invalid or unsafe.",
                    file=out,
                )
                return False
            merged = merge_cli_config_three_way(staged_cli_cfg, final_cfg, disk_cfg)
            if merged is None:
                return False
            return _write_cli_config_to_dirfd(dst_dir_fd, merged, err_stream=err_stream)
        finally:
            os.close(dst_dir_fd)


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


def _interactive_first_positional(opencode_args: Sequence[str]) -> str | None:
    """Return the first non-flag positional token before '--', skipping root value-flag operands."""
    i = 0
    total = len(opencode_args)
    while i < total:
        arg = str(opencode_args[i])
        if arg == "--":
            return None
        if arg in INTERACTIVE_ROOT_VALUE_FLAGS:
            i += 2 if (i + 1) < total else 1
            continue
        if arg.startswith("-"):
            i += 1
            continue
        return arg
    return None


MAX_SERVICE_INFO_BYTES = 65536


class _BoundedSocketRawIO(io.RawIOBase):
    """Socket reader enforcing an overall monotonic deadline, process liveness, and wire byte cap."""

    def __init__(
        self,
        sock: socket.socket,
        *,
        deadline: float,
        max_bytes: int,
        serve_proc: Any,
    ) -> None:
        self._sock = sock
        self._deadline = deadline
        self._max_bytes = max_bytes
        self._serve_proc = serve_proc
        self._received = 0
        self.wire_bytes = bytearray()

    def readable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int:
        if self._serve_proc.poll() is not None:
            raise TimeoutError("invocation service exited during readiness probe")
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("invocation service readiness deadline exceeded")
        budget = (self._max_bytes + 1) - self._received
        if budget <= 0:
            raise ValueError("invocation service response exceeded byte limit")
        self._sock.settimeout(min(0.5, max(0.01, remaining)))
        view = memoryview(b)[:budget]
        n = self._sock.recv_into(view)
        self._received += n
        if self._received > self._max_bytes:
            raise ValueError("invocation service response exceeded byte limit")
        if n > 0:
            self.wire_bytes.extend(view[:n])
        return n


class _BoundedDeadlineSocket:
    """Minimal socket adapter for http.client.HTTPResponse using _BoundedSocketRawIO."""

    def __init__(
        self,
        sock: socket.socket,
        *,
        deadline: float,
        max_bytes: int,
        serve_proc: Any,
    ) -> None:
        self._sock = sock
        self._deadline = deadline
        self._max_bytes = max_bytes
        self._serve_proc = serve_proc
        self.raw_io: _BoundedSocketRawIO | None = None

    def makefile(self, mode: str = "rb", buffering: int = -1) -> io.BufferedReader:
        raw = _BoundedSocketRawIO(
            self._sock,
            deadline=self._deadline,
            max_bytes=self._max_bytes,
            serve_proc=self._serve_proc,
        )
        self.raw_io = raw
        return io.BufferedReader(raw, buffer_size=4096)


_HEXDIG_RE = re.compile(rb"[0-9A-Fa-f]+")
_HTTP_STATUS_LINE_RE = re.compile(rb"HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?")
_HTTP_TRAILER_FIELD_RE = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+:[^\r\n]*")


def _is_complete_chunked_wire(wire: bytes) -> bool:
    """Verify RFC 9112 §7.1 chunked framing on the final HTTP response (after any 1xx interim headers)."""
    pos = 0
    total = len(wire)
    while True:
        hdr_sep = wire.find(b"\r\n\r\n", pos)
        if hdr_sep < 0:
            return False
        first_line_end = wire.find(b"\r\n", pos, hdr_sep)
        status_line = wire[pos:first_line_end] if first_line_end >= 0 else wire[pos:hdr_sep]
        m = _HTTP_STATUS_LINE_RE.fullmatch(status_line)
        if not m:
            return False
        status_code = int(m.group(1))
        pos = hdr_sep + 4
        if 100 <= status_code < 200:
            continue
        break

    while True:
        line_end = wire.find(b"\r\n", pos)
        if line_end < 0:
            return False
        size_line = wire[pos:line_end]
        if b";" in size_line:
            # RFC 9112 §7.1: BWS is allowed immediately before ';' chunk-ext, never leading.
            size_tok = size_line.split(b";", 1)[0].rstrip(b" \t")
        else:
            size_tok = size_line
        if not _HEXDIG_RE.fullmatch(size_tok):
            return False
        chunk_size = int(size_tok, 16)
        pos = line_end + 2
        if chunk_size == 0:
            # Trailer section must contain only valid HTTP field-lines and terminate with an empty CRLF line.
            while True:
                if pos + 2 <= total and wire[pos : pos + 2] == b"\r\n":
                    return True
                tr_end = wire.find(b"\r\n", pos)
                if tr_end < 0:
                    return False
                trailer_line = wire[pos:tr_end]
                if not _HTTP_TRAILER_FIELD_RE.fullmatch(trailer_line):
                    return False
                pos = tr_end + 2
        if pos + chunk_size + 2 > total or wire[pos + chunk_size : pos + chunk_size + 2] != b"\r\n":
            return False
        pos += chunk_size + 2


def _probe_invocation_service_info(
    *,
    service_port: int,
    auth_token: str,
    deadline: float,
    serve_proc: Any,
) -> dict[str, Any] | None:
    """Issue a strictly deadline- and byte-bounded loopback GET /api/info request."""
    remaining = deadline - time.monotonic()
    if remaining <= 0 or serve_proc.poll() is not None:
        return None
    sock: socket.socket | None = None
    resp: http.client.HTTPResponse | None = None
    try:
        sock = socket.create_connection(
            ("127.0.0.1", int(service_port)),
            timeout=min(0.5, max(0.01, remaining)),
        )
        remaining = deadline - time.monotonic()
        if remaining <= 0 or serve_proc.poll() is not None:
            return None
        sock.settimeout(min(0.5, max(0.01, remaining)))
        req_bytes = (
            f"GET /api/info HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{int(service_port)}\r\n"
            f"Authorization: Basic {auth_token}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii")
        sock.sendall(req_bytes)
        bounded_sock = _BoundedDeadlineSocket(
            sock,
            deadline=deadline,
            max_bytes=MAX_SERVICE_INFO_BYTES,
            serve_proc=serve_proc,
        )
        resp = http.client.HTTPResponse(bounded_sock, method="GET")
        resp.begin()
        if resp.status != 200:
            return None
        raw_body = resp.read(MAX_SERVICE_INFO_BYTES + 1)
        if len(raw_body) > MAX_SERVICE_INFO_BYTES:
            return None
        if resp.length not in (None, 0):
            return None
        if resp.chunked:
            if not resp.isclosed() or bounded_sock.raw_io is None:
                return None
            if not _is_complete_chunked_wire(bytes(bounded_sock.raw_io.wire_bytes)):
                return None
        parsed = json.loads(raw_body.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def _wait_for_invocation_service_ready(
    *,
    serve_proc: Any,
    state_svc_file: Path,
    service_port: int,
    service_password: str,
    timeout_seconds: float = 10.0,
) -> bool:
    """Wait until pre-started sandboxed 'opencode serve --service' publishes verified identity and passes auth /api/info."""
    expected_pid = getattr(serve_proc, "pid", None)
    if not isinstance(expected_pid, int) or isinstance(expected_pid, bool) or expected_pid <= 1:
        return False
    auth_token = base64.b64encode(f"opencode:{service_password}".encode("utf-8")).decode("ascii")
    deadline = time.monotonic() + max(0.05, float(timeout_seconds))
    while time.monotonic() < deadline:
        if serve_proc.poll() is not None:
            return False
        if state_svc_file.is_file() and not state_svc_file.is_symlink():
            try:
                parsed = json.loads(state_svc_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, ValueError):
                parsed = None
            if (
                isinstance(parsed, dict)
                and isinstance(parsed.get("pid"), int)
                and not isinstance(parsed.get("pid"), bool)
                and parsed["pid"] == expected_pid
                and isinstance(parsed.get("url"), str)
            ):
                try:
                    u = urlparse(parsed["url"].strip())
                    parsed_port = u.port
                except ValueError:
                    u = None
                    parsed_port = None
                if (
                    u is not None
                    and u.scheme == "http"
                    and u.hostname in ("127.0.0.1", "localhost")
                    and parsed_port == int(service_port)
                ):
                    body = _probe_invocation_service_info(
                        service_port=int(service_port),
                        auth_token=auth_token,
                        deadline=deadline,
                        serve_proc=serve_proc,
                    )
                    if (
                        isinstance(body, dict)
                        and isinstance(body.get("pid"), int)
                        and not isinstance(body.get("pid"), bool)
                        and body["pid"] == expected_pid
                        and isinstance(body.get("version"), str)
                        and bool(body["version"].strip())
                    ):
                        return True
        sleep_for = min(0.025, deadline - time.monotonic())
        if sleep_for <= 0:
            break
        time.sleep(sleep_for)
    return False


def _normalize_interactive_opencode_args(opencode_args: Sequence[str]) -> tuple[bool, list[str], str | None]:
    # Unconditional --server rejection takes precedence over positional parsing and '--'.
    for raw_tok in opencode_args:
        tok = str(raw_tok)
        if tok == "--server" or tok.startswith("--server="):
            return (
                False,
                [],
                "Refusing '--server' in contained OpenCode launcher: external uncontained server URLs are blocked.",
            )

    cleaned: list[str] = []
    first_positional: str | None = None
    after_double_dash = False
    i = 0
    total = len(opencode_args)
    while i < total:
        arg = str(opencode_args[i])
        if not after_double_dash:
            if arg == "--standalone" or arg.startswith("--standalone="):
                i += 1
                continue
            if arg == "--":
                after_double_dash = True
                cleaned.append(arg)
                i += 1
                continue
            if first_positional is None:
                if arg in INTERACTIVE_ROOT_VALUE_FLAGS:
                    if i + 1 >= total:
                        return (
                            False,
                            [],
                            f"Flag '{arg}' in OpenCode arguments is missing its value.",
                        )
                    nxt = str(opencode_args[i + 1])
                    if nxt == "--" or nxt.startswith("-"):
                        return (
                            False,
                            [],
                            f"Flag '{arg}' in OpenCode arguments requires a non-flag value (got '{nxt}').",
                        )
                    cleaned.extend([arg, nxt])
                    i += 2
                    continue
                if arg.startswith("-"):
                    cleaned.append(arg)
                    i += 1
                    continue
                first_positional = arg
                if first_positional in FORBIDDEN_INTERACTIVE_SUBCOMMANDS:
                    return (
                        False,
                        [],
                        f"Refusing OpenCode subcommand '{first_positional}': persistent/uncontained daemon management is disabled.",
                    )
        cleaned.append(arg)
        i += 1
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

    staged_cli_cfg: dict[str, Any] = {}
    cli_writeback_allowed = False
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
    serve_proc: Any = None
    proc: Any = None
    cancel_state: dict[str, Any] = {"signum": None, "proc": None, "serve_proc": None}
    prev_handlers: dict[int, Any] = {}

    def _forward_signal(signum: int, _frame: Any) -> None:
        if cancel_state["signum"] is None:
            cancel_state["signum"] = signum
        for ref_key in ("proc", "serve_proc"):
            child_ref = cancel_state.get(ref_key)
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
    proc_exited = False
    try:
        inv_dir_real = inv_dir.resolve(strict=True)
        with _opencode_launch_lock(isolated_home):
            staged_cli_cfg, cli_writeback_allowed = _stage_interactive_cli_config(
                isolated_home,
                inv_dir_real,
            )
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
        os.chmod(inv_dir_real / ".config" / "opencode", 0o700)
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
            "OPENCODE_CLI_CONFIG_CONTENT",
            "OPENCODE_PTY_HANDOFF",
            "OPENCODE_PTY_SOCKET_DIR",
            "OPENCODE_DB",
        ):
            env.pop(secret_env_key, None)
        env["OPENCODE_PTY_BIN"] = str(cfg_base / ".config" / ".disabled-opencode-pty")

        needs_prestarted_service = use_real_sandbox and (
            _interactive_first_positional(effective_opencode_args) == "run"
        )
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
                allow_opencode_self_exec=not needs_prestarted_service,
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
            state_svc_file = inv_dir_real / ".state" / "opencode" / "service.json"
            sidecar_path = inv_dir_real / "service-identity.json"
            if needs_prestarted_service:
                # OpenCode 2.3.2 'run' calls autostart=false and falls back to standalone
                # 'serve --stdio --port 0' (which leaks OPENCODE_PASSWORD in KERN_PROCARGS2
                # and binds an unpinned port) unless the sandboxed service is already ready.
                # Seatbelt also disables opencode self-exec (allow_opencode_self_exec=False)
                # so 'opencode run' cannot spawn 'serve --stdio' even if the service dies mid-attach.
                # Keep _opencode_launch_lock free so sibling cli.json staging/write-back and
                # invocation registration/cleanup never block on startup; serialize only the
                # strictly deadline-bounded service boot via _opencode_service_boot_lock so
                # concurrent first-run SQLite migrations on shared XDG_DATA_HOME/opencode.db
                # do not collide.
                serve_cmd = [
                    str(sandbox_exec_bin),
                    "-f",
                    str(sb_path),
                    str(opencode_bin),
                    "serve",
                    "--service",
                ]
                ready = False
                boot_block_reason: str | None = None
                boot_guard_failed = False
                with _opencode_service_boot_lock(isolated_home):
                    boot_clear, boot_block_reason = _check_and_clear_pending_service_reap(isolated_home)
                    if not boot_clear:
                        pass
                    elif not _write_pending_service_boot_guard(
                        isolated_home,
                        invocation_id=invocation_id,
                    ):
                        boot_guard_failed = True
                    else:
                        try:
                            serve_proc = popen_fn(
                                serve_cmd,
                                cwd=str(caller_cwd),
                                env=env,
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                            )
                            cancel_state["serve_proc"] = serve_proc
                            # Best-effort enrich durable pre-spawn guard with child serve PID;
                            # even if this write fails (e.g. ENOSPC), the pre-spawn guard stays durable.
                            _write_pending_service_boot_guard(
                                isolated_home,
                                invocation_id=invocation_id,
                                proc_obj=serve_proc,
                            )
                            if cancel_state["signum"] is not None:
                                _forward_signal(cancel_state["signum"], None)
                            ready = _wait_for_invocation_service_ready(
                                serve_proc=serve_proc,
                                state_svc_file=state_svc_file,
                                service_port=service_port,
                                service_password=service_password,
                                timeout_seconds=10.0,
                            )
                        finally:
                            if serve_proc is None:
                                _clear_pending_service_reap_if_matches(
                                    isolated_home,
                                    invocation_id=invocation_id,
                                )
                            elif ready and serve_proc.poll() is None:
                                _clear_pending_service_reap_if_matches(
                                    isolated_home,
                                    invocation_id=invocation_id,
                                )
                            else:
                                if _terminate_and_reap_process_bounded(serve_proc):
                                    _clear_pending_service_reap_if_matches(
                                        isolated_home,
                                        invocation_id=invocation_id,
                                    )
                                else:
                                    _write_pending_service_boot_guard(
                                        isolated_home,
                                        invocation_id=invocation_id,
                                        proc_obj=serve_proc,
                                    )
                if boot_block_reason is not None or boot_guard_failed:
                    print(
                        "Refusing OpenCode 'run' launch: "
                        + (
                            boot_block_reason
                            if boot_block_reason is not None
                            else "failed to persist durable service-boot guard on this isolated home."
                        ),
                        file=sys.stderr,
                    )
                    rc = 1
                else:
                    sidecar_bound = False
                    if ready:
                        sidecar_bound = _try_bind_service_identity_sidecar(
                            scope_dir=inv_dir_real,
                            state_svc_file=state_svc_file,
                            sidecar_path=sidecar_path,
                            scope_id=invocation_id,
                            service_port=service_port,
                        )
                    if not ready or not sidecar_bound or serve_proc is None or serve_proc.poll() is not None:
                        print(
                            "Refusing OpenCode 'run' launch: per-invocation sandboxed service "
                            "failed verified readiness or identity binding (blocking standalone --stdio fallback).",
                            file=sys.stderr,
                        )
                        rc = 1
                    else:
                        proc = popen_fn(
                            launch_cmd,
                            cwd=str(caller_cwd),
                            env=env,
                        )
                        cancel_state["proc"] = proc
                        if cancel_state["signum"] is not None:
                            _forward_signal(cancel_state["signum"], None)
            else:
                with _opencode_launch_lock(isolated_home):
                    proc = popen_fn(
                        launch_cmd,
                        cwd=str(caller_cwd),
                        env=env,
                    )
                    cancel_state["proc"] = proc
                    if cancel_state["signum"] is not None:
                        _forward_signal(cancel_state["signum"], None)
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

        if proc is not None:
            rc = int(proc.wait())
            proc_exited = True
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
                    if hasattr(proc, "wait"):
                        proc.wait(timeout=1)
                except Exception:
                    pass
            try:
                if proc.poll() is not None:
                    proc_exited = True
            except Exception:
                pass
        if relay is not None:
            relay.close()
        if serve_proc is not None:
            reaped_serve = _terminate_and_reap_process_bounded(
                serve_proc, term_timeout=5.0, kill_timeout=1.0
            )
            if reaped_serve:
                spid = getattr(serve_proc, "pid", None)
                try:
                    with _opencode_service_boot_lock(isolated_home):
                        _clear_pending_service_reap_if_matches(
                            isolated_home,
                            invocation_id=invocation_id,
                            expected_pid=spid if (isinstance(spid, int) and not isinstance(spid, bool) and spid > 1) else None,
                        )
                except OSError:
                    pass
        if use_real_sandbox:
            reaped_clean = _reap_invocation_service_and_children(
                inv_dir, invocation_id=invocation_id
            )
            if proc_exited and reaped_clean and cli_writeback_allowed:
                try:
                    _persist_interactive_cli_config(isolated_home, inv_dir, staged_cli_cfg)
                except Exception as exc:
                    print(
                        f"WARNING: Failed to persist interactive cli.json: {exc}",
                        file=sys.stderr,
                    )
            if reaped_clean:
                _safe_rmtree_nofollow(inv_dir)
            elif rc == 0:
                rc = 1
        else:
            if proc_exited and cli_writeback_allowed:
                try:
                    _persist_interactive_cli_config(isolated_home, inv_dir, staged_cli_cfg)
                except Exception as exc:
                    print(
                        f"WARNING: Failed to persist interactive cli.json: {exc}",
                        file=sys.stderr,
                    )
            _safe_rmtree_nofollow(inv_dir)
        with _opencode_launch_lock(isolated_home):
            _sweep_dead_invocations(isolated_home)
    return normalize_non_session_exit_code(rc)


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
    return normalize_non_session_exit_code(int(proc.returncode))


def _probe_worker_service_ready_http(port: int, password: str, timeout: float = 0.5) -> bool:
    from urllib.request import Request

    basic = base64.b64encode(f"opencode:{password}".encode("utf-8")).decode("ascii")
    for path_suffix in ("/global/health", "/api/info"):
        req = Request(
            f"http://127.0.0.1:{port}{path_suffix}",
            headers={
                "Accept": "application/json",
                "Authorization": f"Basic {basic}",
            },
            method="GET",
        )
        try:
            with open_loopback_http(req, timeout=timeout) as resp:
                if 200 <= int(resp.status) < 300:
                    return True
        except Exception:
            continue
    return False


def _terminate_in_group_child(
    proc: subprocess.Popen[Any] | None,
    expected_start: tuple[int, int] | None,
    *,
    grace_seconds: float = 1.5,
) -> bool:
    if proc is None:
        return True
    pid = proc.pid
    if pid <= 1 or proc.poll() is not None:
        return True

    def _still_same_alive() -> bool:
        if proc.poll() is not None:
            return False
        if expected_start is not None and sys.platform == "darwin":
            st, info = read_proc_bsdinfo(pid)
            if st in ("absent", "zombie"):
                return False
            if st == "alive" and info is not None:
                return (int(info["start_tvsec"]), int(info["start_tvusec"])) == expected_start
            return True
        return pid_is_alive(pid)

    if _still_same_alive():
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
        deadline = time.monotonic() + max(0.05, float(grace_seconds))
        while time.monotonic() < deadline:
            if not _still_same_alive():
                break
            time.sleep(0.03)
        if _still_same_alive():
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            kill_deadline = time.monotonic() + 0.5
            while time.monotonic() < kill_deadline and _still_same_alive():
                time.sleep(0.02)
    try:
        proc.wait(timeout=1.0)
    except Exception:
        pass
    return proc.poll() is not None


class _BoundedPipeDrain:
    """Continuously drain a child pipe into a bounded ring buffer with reader-owned descriptor lifetime (R2, R2-3)."""

    def __init__(self, stream: Any, *, max_bytes: int = 4096) -> None:
        self._max_bytes = max(256, int(max_bytes))
        self._lock = threading.Lock()
        self._buf = bytearray()
        self._stop_event = threading.Event()
        self._owned_fd: int | None = None
        self._wake_rfd: int | None = None
        self._wake_wfd: int | None = None
        self._stream: Any = None

        raw_fd: int | None = None
        if stream is not None:
            try:
                raw_fd = int(stream.fileno())
            except Exception:
                raw_fd = None

        if raw_fd is not None and raw_fd >= 0:
            dup_fd = os.dup(raw_fd)
            try:
                os.set_blocking(dup_fd, False)
                rfd, wfd = os.pipe()
                try:
                    os.set_blocking(rfd, False)
                    os.set_blocking(wfd, False)
                except BaseException:
                    os.close(rfd)
                    os.close(wfd)
                    raise
            except BaseException:
                os.close(dup_fd)
                raise
            self._owned_fd = dup_fd
            self._wake_rfd = rfd
            self._wake_wfd = wfd
            try:
                stream.close()
            except Exception:
                pass
        else:
            self._stream = stream

        self._thread = threading.Thread(target=self._drain_loop, daemon=True)
        self._thread.start()

    def _after_chunk_hook(self) -> None:
        return

    def _append_chunk(self, chunk: bytes) -> None:
        with self._lock:
            self._buf.extend(chunk)
            if len(self._buf) > self._max_bytes:
                del self._buf[: len(self._buf) - self._max_bytes]

    def _drain_nonblocking_once(self, *, max_chunks: int = 16) -> bool:
        """Read up to max_chunks from _owned_fd; return True when EOF is reached."""
        if self._owned_fd is None:
            return True
        for _ in range(max_chunks):
            try:
                chunk = os.read(self._owned_fd, 4096)
            except BlockingIOError:
                return False
            except OSError:
                return True
            if not chunk:
                return True
            self._append_chunk(chunk)
        return False

    def _drain_loop(self) -> None:
        try:
            if self._owned_fd is not None and self._wake_rfd is not None:
                while not self._stop_event.is_set():
                    try:
                        rlist, _, _ = select.select([self._owned_fd, self._wake_rfd], [], [], 0.2)
                    except (OSError, ValueError):
                        break
                    if self._stop_event.is_set():
                        self._drain_nonblocking_once(max_chunks=8)
                        break
                    if self._owned_fd in rlist:
                        eof = self._drain_nonblocking_once(max_chunks=16)
                        if eof:
                            break
                        self._after_chunk_hook()
                        if self._stop_event.is_set():
                            self._drain_nonblocking_once(max_chunks=8)
                            break
            else:
                while not self._stop_event.is_set() and self._stream is not None:
                    try:
                        raw = self._stream.read(4096)
                    except Exception:
                        break
                    if not raw:
                        break
                    chunk = raw if isinstance(raw, bytes) else str(raw).encode("utf-8", errors="replace")
                    self._append_chunk(chunk)
                    self._after_chunk_hook()
        finally:
            # Exclusive descriptor ownership: only _drain_loop closes _owned_fd / _wake_rfd / _stream.
            if self._owned_fd is not None:
                fd_close = self._owned_fd
                self._owned_fd = None
                try:
                    os.close(fd_close)
                except OSError:
                    pass
            if self._wake_rfd is not None:
                rfd_close = self._wake_rfd
                self._wake_rfd = None
                try:
                    os.close(rfd_close)
                except OSError:
                    pass
            if self._stream is not None:
                st_close = self._stream
                self._stream = None
                try:
                    st_close.close()
                except Exception:
                    pass

    def tail_text(self) -> str:
        with self._lock:
            return bytes(self._buf).decode("utf-8", errors="replace").strip()

    def close(self, *, _join_timeout: float = 1.0) -> None:
        self._stop_event.set()
        with self._lock:
            wfd = self._wake_wfd
            self._wake_wfd = None
        if wfd is not None:
            try:
                os.write(wfd, b"\x01")
            except OSError:
                pass
            try:
                os.close(wfd)
            except OSError:
                pass
        self._thread.join(timeout=max(0.0, float(_join_timeout)))


def _run_in_group_worker_lifecycle(
    *,
    sandbox_exec_bin: Path,
    seatbelt_path: Path,
    opencode_bin: str,
    validated_worker_args: Sequence[str],
    caller_cwd: Path,
    env: dict[str, str],
    isolated_home: Path,
    worker_id: str,
    worker_tag: str,
    worker_service_port: int,
    worker_service_password: str,
    harvest_logs: bool,
    remove_home: bool,
    relay: _WorkerTokenRelay | None,
    worker_manifest_path: Path | None,
    run_token: str | None,
    bind_sidecar_fn: Callable[[], None],
    stop_service_fn: Callable[[], bool],
    skip_http_service_probe: bool = False,
    popen_factory: Any = None,
    prepared_identity: PreparedWorkerIdentity | None = None,
) -> tuple[int, dict[str, Any]]:
    actual_popen = popen_factory if popen_factory is not None else subprocess.Popen
    launcher_pid = os.getpid()
    launcher_pgid = os.getpgrp()
    children_entries: list[dict[str, Any]] = []

    cancel_state: dict[str, Any] = {
        "signum": None,
        "serve_proc": None,
        "run_proc": None,
        "in_teardown": False,
    }
    prev_handlers: dict[int, Any] = {}

    def _on_signal(signum: int, _frame: Any) -> None:
        if cancel_state["signum"] is None:
            cancel_state["signum"] = signum
        if not cancel_state["in_teardown"]:
            for key in ("run_proc", "serve_proc"):
                pref = cancel_state.get(key)
                if pref is not None and pref.poll() is None:
                    try:
                        os.kill(pref.pid, signal.SIGTERM)
                    except OSError:
                        pass

    for sig in (signal.SIGTERM, signal.SIGHUP):
        try:
            prev_handlers[sig] = signal.getsignal(sig)
            signal.signal(sig, _on_signal)
        except (OSError, ValueError):
            pass

    exit_code = 1
    serve_proc: subprocess.Popen[Any] | None = None
    stderr_drain: _BoundedPipeDrain | None = None
    run_proc: subprocess.Popen[Any] | None = None
    serve_start: tuple[int, int] | None = None
    run_start: tuple[int, int] | None = None
    spawned_any = False
    group_clean = True
    teardown_res: dict[str, Any] = {
        "reaped_pids": [],
        "group_clean": False,
        "reaper_clean": False,
        "harvested_dir": None,
        "removed": False,
        "clean": False,
        "teardown_executed": False,
    }

    try:
        try:
            if worker_manifest_path is not None and launcher_pgid != launcher_pid:
                print(
                    f"Refusing --worker-manifest with --inherit-process-group: launcher_pgid ({launcher_pgid}) != launcher_pid ({launcher_pid}).",
                    file=sys.stderr,
                )
                exit_code = 1
                raise SecurityProfileError("PGID mismatch for --worker-manifest.")

            if prepared_identity is not None:
                info_self: dict[str, Any] | None = {
                    "start_tvsec": prepared_identity.launcher_start_tvsec,
                    "start_tvusec": prepared_identity.launcher_start_tvusec,
                }
                launcher_lstart = prepared_identity.launcher_lstart
            else:
                st_self, info_self = read_proc_bsdinfo(launcher_pid)
                if worker_manifest_path is not None and (st_self != "alive" or info_self is None):
                    print(
                        "Refusing --worker-manifest: proc_pidinfo start-time query unavailable on this platform.",
                        file=sys.stderr,
                    )
                    exit_code = 1
                    raise SecurityProfileError("proc_pidinfo unavailable for --worker-manifest.")
                launcher_lstart = get_process_lstart(launcher_pid) or ""

            def _write_manifest() -> bool:
                if worker_manifest_path is None:
                    return True
                assert info_self is not None and isinstance(run_token, str)
                doc = {
                    "schema_version": 1,
                    "run_token": run_token.strip(),
                    "launcher_pid": int(launcher_pid),
                    "launcher_pgid": int(launcher_pgid),
                    "launcher_start_tvsec": int(info_self["start_tvsec"]),
                    "launcher_start_tvusec": int(info_self["start_tvusec"]),
                    "launcher_lstart": launcher_lstart,
                    "worker_id": worker_id,
                    "isolated_home": str(isolated_home),
                    "worker_tag": worker_tag,
                    "children": list(children_entries),
                }
                try:
                    _atomic_write_text_0600(worker_manifest_path, json.dumps(doc, indent=2) + "\n")
                    mst = os.lstat(worker_manifest_path)
                    return not stat.S_ISLNK(mst.st_mode) and stat.S_IMODE(mst.st_mode) == 0o600
                except OSError as exc:
                    print(f"Failed to write worker manifest '{worker_manifest_path}': {exc}", file=sys.stderr)
                    return False

            if not _write_manifest():
                exit_code = 1
                raise SecurityProfileError("Failed writing initial worker manifest.")

            if cancel_state["signum"] is not None:
                exit_code = 128 + int(cancel_state["signum"])
            else:
                serve_cmd = [
                    str(sandbox_exec_bin),
                    "-f",
                    str(seatbelt_path),
                    str(opencode_bin),
                    "serve",
                    "--service",
                ]
                serve_proc = actual_popen(
                    serve_cmd,
                    cwd=str(caller_cwd),
                    env=dict(env),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    start_new_session=False,
                )
                spawned_any = True
                if serve_proc.stderr is not None:
                    stderr_drain = _BoundedPipeDrain(serve_proc.stderr, max_bytes=4096)
                cancel_state["serve_proc"] = serve_proc
                st_srv, info_srv = read_proc_bsdinfo(serve_proc.pid)
                if st_srv == "alive" and info_srv is not None:
                    serve_start = (int(info_srv["start_tvsec"]), int(info_srv["start_tvusec"]))
                    children_entries.append(
                        {
                            "role": "opencode_serve",
                            "pid": int(serve_proc.pid),
                            "pgid": int(info_srv["pgid"]),
                            "start_tvsec": serve_start[0],
                            "start_tvusec": serve_start[1],
                            "lstart": get_process_lstart(serve_proc.pid) or "",
                        }
                    )
                elif worker_manifest_path is not None:
                    if serve_proc.poll() is None:
                        print("Failed to read proc_pidinfo for opencode_serve child.", file=sys.stderr)
                        group_clean = False
                        exit_code = 1
                        raise SecurityProfileError("proc_pidinfo failed on opencode_serve child.")
                if not _write_manifest():
                    raise SecurityProfileError("Failed updating worker manifest after opencode_serve spawn.")

                state_svc_file = isolated_home / ".local" / "state" / "opencode" / "service.json"
                svc_ready = False
                svc_deadline = time.monotonic() + 15.0
                while time.monotonic() < svc_deadline:
                    if cancel_state["signum"] is not None:
                        break
                    if serve_proc.poll() is not None:
                        break
                    if state_svc_file.is_file():
                        bind_sidecar_fn()
                        if skip_http_service_probe or _probe_worker_service_ready_http(
                            worker_service_port, worker_service_password
                        ):
                            svc_ready = True
                            break
                    time.sleep(0.04)

                if cancel_state["signum"] is not None:
                    exit_code = 128 + int(cancel_state["signum"])
                elif not svc_ready:
                    time.sleep(0.03)
                    srv_err = stderr_drain.tail_text() if stderr_drain is not None else ""
                    print(
                        f"In-group 'opencode serve --service' failed to become ready on 127.0.0.1:{worker_service_port}"
                        + (f": {srv_err}" if srv_err else "."),
                        file=sys.stderr,
                    )
                    exit_code = 1
                else:
                    run_cmd = [
                        str(sandbox_exec_bin),
                        "-f",
                        str(seatbelt_path),
                        str(opencode_bin),
                        *validated_worker_args,
                    ]
                    run_proc = actual_popen(
                        run_cmd,
                        cwd=str(caller_cwd),
                        env=dict(env),
                        stdin=subprocess.DEVNULL,
                        start_new_session=False,
                    )
                    cancel_state["run_proc"] = run_proc
                    st_run, info_run = read_proc_bsdinfo(run_proc.pid)
                    if st_run == "alive" and info_run is not None:
                        run_start = (int(info_run["start_tvsec"]), int(info_run["start_tvusec"]))
                        children_entries.append(
                            {
                                "role": "opencode_run",
                                "pid": int(run_proc.pid),
                                "pgid": int(info_run["pgid"]),
                                "start_tvsec": run_start[0],
                                "start_tvusec": run_start[1],
                                "lstart": get_process_lstart(run_proc.pid) or "",
                            }
                        )
                    elif worker_manifest_path is not None and run_proc.poll() is None:
                        raise SecurityProfileError("proc_pidinfo failed on opencode_run child.")
                    if not _write_manifest():
                        raise SecurityProfileError("Failed updating worker manifest after opencode_run spawn.")

                    while True:
                        bind_sidecar_fn()
                        if cancel_state["signum"] is not None:
                            exit_code = 128 + int(cancel_state["signum"])
                            break
                        rc = run_proc.poll()
                        if rc is not None:
                            if cancel_state["signum"] is not None:
                                exit_code = 128 + int(cancel_state["signum"])
                            else:
                                exit_code = normalize_non_session_exit_code(int(rc))
                            break
                        time.sleep(0.03)
        except SecurityProfileError:
            exit_code = 1
        finally:
            cancel_state["in_teardown"] = True
            run_ok = _terminate_in_group_child(run_proc, run_start, grace_seconds=1.5)
            srv_ok = _terminate_in_group_child(serve_proc, serve_start, grace_seconds=1.5)
            if stderr_drain is not None:
                stderr_drain.close()
            elif serve_proc is not None and serve_proc.stderr is not None:
                try:
                    serve_proc.stderr.close()
                except Exception:
                    pass
            group_clean = group_clean and run_ok and srv_ok
            service_clean = True
            if spawned_any:
                try:
                    if stop_service_fn() is False:
                        service_clean = False
                except Exception:
                    service_clean = False
            if relay is not None:
                relay.close()
            if not remove_home and worker_id:
                try:
                    (isolated_home / ".keep-worker-home").write_text("1\n", encoding="utf-8")
                except OSError:
                    pass
            teardown_res = teardown_worker_home(
                isolated_home,
                worker_id=worker_id or None,
                harvest_logs=harvest_logs if spawned_any else False,
                remove_home=remove_home,
                reap_processes=spawned_any,
                group_clean=group_clean,
                service_clean=service_clean,
                owned_pgid=None,
            )
            teardown_res["teardown_executed"] = True
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

    return normalize_non_session_exit_code(exit_code), teardown_res


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
    skip_http_service_probe: bool = False,
    relay_observer_fn: Callable[[_WorkerTokenRelay], None] | None = None,
    prepared_identity: PreparedWorkerIdentity | None = None,
    ownership_callback: Callable[[], None] | None = None,
) -> int:
    if prepared_identity is not None:
        if ownership_callback is not None:
            ownership_callback()
        worker_id = prepared_identity.worker_id
        isolated_home = prepared_identity.isolated_home
        worker_tag = prepared_identity.worker_tag
    else:
        sweep_stale_worker_homes()
        worker_id, isolated_home = allocate_worker_home_fn()
        worker_tag = secrets.token_hex(16)
    retain_home = bool(getattr(args, "keep_worker_home", False) or getattr(args, "print_config", False))
    relay: _WorkerTokenRelay | None = None
    exit_code = 1
    lifecycle_handled_teardown = False
    try:
        worker_service_port = _allocate_loopback_ephemeral_port()
        worker_service_password = secrets.token_urlsafe(32)
        raw_manifest = getattr(args, "worker_manifest", None)
        manifest_path = Path(raw_manifest) if isinstance(raw_manifest, str) and raw_manifest.strip() else None
        raw_exit_file = getattr(args, "launcher_exit_file", None)
        exit_file_path = Path(raw_exit_file) if isinstance(raw_exit_file, str) and raw_exit_file.strip() else None
        raw_sec_prof = getattr(args, "security_profile", None)
        sec_prof_path = Path(raw_sec_prof) if isinstance(raw_sec_prof, str) and raw_sec_prof.strip() else None
        raw_site_pkgs = getattr(args, "launcher_site_packages", None)
        site_pkgs_path = Path(raw_site_pkgs) if isinstance(raw_site_pkgs, str) and raw_site_pkgs.strip() else None
        if relay_factory is not None:
            relay_inst = relay_factory()
            relay_inst._extra_canary_secrets = (
                *relay_inst._extra_canary_secrets,
                worker_service_password,
            )
            relay = relay_inst.start()
            if relay_observer_fn is not None:
                relay_observer_fn(relay)

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
            "worker_tag": worker_tag,
            "launcher_site_packages": site_pkgs_path,
            "worker_manifest_path": manifest_path,
            "launcher_exit_path": exit_file_path,
            "security_profile_path": sec_prof_path,
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

            if bool(getattr(args, "inherit_process_group", False)):
                exit_code, teardown_res = _run_in_group_worker_lifecycle(
                    sandbox_exec_bin=sandbox_exec_bin,
                    seatbelt_path=seatbelt_path,
                    opencode_bin=opencode_bin,
                    validated_worker_args=validated_worker_args,
                    caller_cwd=caller_cwd,
                    env=env,
                    isolated_home=isolated_home,
                    worker_id=worker_id,
                    worker_tag=worker_tag,
                    worker_service_port=worker_service_port,
                    worker_service_password=worker_service_password,
                    harvest_logs=active_profile.mcp_enable_local_assist,
                    remove_home=not retain_home,
                    relay=relay,
                    worker_manifest_path=manifest_path,
                    run_token=getattr(args, "run_token", None),
                    bind_sidecar_fn=_bind_worker_service_sidecar,
                    stop_service_fn=_stop_worker_service,
                    skip_http_service_probe=skip_http_service_probe,
                    prepared_identity=prepared_identity,
                )
                if teardown_res.get("teardown_executed", False):
                    lifecycle_handled_teardown = True
                    relay = None
            else:
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
                lifecycle_handled_teardown = True
                relay = None
            if not teardown_res.get("clean", False):
                print(
                    f"WARNING: worker teardown for '{worker_id}' was incomplete "
                    f"(reaper_clean={teardown_res.get('reaper_clean')}, removed={teardown_res.get('removed')}).",
                    file=sys.stderr,
                )
                exit_code = exit_code or 1
    except (SecurityProfileError, OSError) as exc:
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
    return normalize_non_session_exit_code(exit_code)
