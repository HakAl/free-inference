from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from .errors import LocalAssistError
from .registry import (
    BASE_SAFE_ENV_ALLOWLIST,
    LAUNCHER_EXTRA_ENV_ALLOWLIST,
    EndpointConfig,
    is_model_effectively_deprecated,
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
        help="Allow native OpenCode subagents (task/subagent tools) in the worker security profile.",
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
            args.allow_subagents,
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
