"""Unified CLI dispatcher for free-inference scripts.

Routes top-level subcommands to the audited scripts in ``scripts/`` via
``os.execv`` without duplicating launcher, custody, proxy, or registry logic.
Compatible with Python >= 3.9 stdlib so fixed-prefix system Python fallbacks
work identically to the repository's Python >= 3.11 runtime.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import os
from pathlib import Path
import signal
import sys
from types import MappingProxyType
from typing import Callable, Sequence, TextIO

from local_assist import __version__


class DispatchError(Exception):
    """Raised when a target script cannot be safely resolved for execution."""


@dataclass(frozen=True)
class CommandSpec:
    """Static single-target subcommand specification."""

    name: str
    script_name: str
    prefix_args: tuple[str, ...]
    summary: str
    help_text: str | None = None


COMMAND_SPECS: Mapping[str, CommandSpec] = MappingProxyType(
    {
        "status": CommandSpec(
            name="status",
            script_name="session",
            prefix_args=("status",),
            summary="Show active attested session window, caps, and remaining time",
        ),
        "doctor": CommandSpec(
            name="doctor",
            script_name="doctor",
            prefix_args=(),
            summary="Run read-only environment, custody, binary, and registry audit",
        ),
        "models": CommandSpec(
            name="models",
            script_name="models",
            prefix_args=(),
            summary="List registered 5-rung models (--active for live sessions)",
        ),
        "session": CommandSpec(
            name="session",
            script_name="session",
            prefix_args=(),
            summary="Manage Touch ID attested session windows (status|start|stop|renew|watch)",
        ),
        "local": CommandSpec(
            name="local",
            script_name="opencode-local",
            prefix_args=(),
            summary="Launch OpenCode locked to Rung 1 (private-local)",
        ),
        "attested": CommandSpec(
            name="attested",
            script_name="opencode-attested",
            prefix_args=(),
            summary="Launch OpenCode locked to Rung 2/3 (private-attested)",
        ),
        "delegate": CommandSpec(
            name="delegate",
            script_name="delegate-local",
            prefix_args=(),
            summary="Delegate bounded subtasks to Rung 1 local_assist",
        ),
        "sync": CommandSpec(
            name="sync",
            script_name="sync-model-catalog",
            prefix_args=(),
            summary="Check or heal upstream Tinfoil / Privatemode catalog drift",
        ),
        "setup": CommandSpec(
            name="setup",
            script_name="setup",
            prefix_args=(),
            summary="Bootstrap local runtime and verified proxy binaries",
        ),
        "se-key": CommandSpec(
            name="se-key",
            script_name="se-key",
            prefix_args=(),
            summary="Build, selftest, store, migrate, status, or delete Secure Enclave keys",
        ),
        "serve": CommandSpec(
            name="serve",
            script_name="serve-model",
            prefix_args=(),
            summary="Start a local MLX server or attested proxy",
        ),
        "stop": CommandSpec(
            name="stop",
            script_name="stop-model",
            prefix_args=(),
            summary="Stop a running model server or proxy",
            help_text=(
                "Usage: free-inference stop [--runs-dir <abs-path>] [--force-legacy | --discard-legacy] [model-id | --all]\n"
                "Stop a running model server or proxy (delegates to scripts/stop-model).\n"
                "Note: scripts/stop-model does not implement --help, so 'free-inference help stop'\n"
                "prints this usage summary directly without invoking scripts/stop-model.\n"
            ),
        ),
        "verify": CommandSpec(
            name="verify",
            script_name="verify-served-model",
            prefix_args=(),
            summary="Verify PID records, /v1/models, and live OS listeners",
        ),
    }
)

DEFAULT_SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"


def format_usage(prog: str = "free-inference") -> str:
    """Return top-level CLI usage text listing all supported subcommands."""
    width = max(len(name) for name in COMMAND_SPECS) + 2
    lines = [
        f"Usage: {prog} <command> [args...]",
        f"       {prog} help [command]",
        f"       {prog} --version",
        "",
        "Commands:",
    ]
    for name, spec in COMMAND_SPECS.items():
        lines.append(f"  {name.ljust(width)}{spec.summary}")
    lines.extend(
        [
            "",
            f"Run '{prog} help <command>' to show help for a subcommand.",
        ]
    )
    return "\n".join(lines) + "\n"


def resolve_target_script(scripts_dir: Path, script_name: str) -> Path:
    """Resolve and validate a direct, non-symlink executable inside scripts_dir."""
    if (
        not isinstance(script_name, str)
        or not script_name
        or "/" in script_name
        or "\\" in script_name
        or "\x00" in script_name
        or ".." in script_name
        or script_name in {".", ".."}
    ):
        raise DispatchError(f"Error: invalid target script name '{script_name}'.")

    scripts_root = Path(scripts_dir)
    try:
        if not scripts_root.is_dir():
            raise DispatchError(f"Error: scripts directory not found: {scripts_root}")

        resolved_root = scripts_root.resolve()
        target = scripts_root / script_name

        if target.is_symlink():
            raise DispatchError(
                f"Error: refusing symlinked target script scripts/{script_name}."
            )
        if not target.exists():
            raise DispatchError(
                f"Error: target script scripts/{script_name} is not available in this checkout."
            )
        if not target.is_file():
            raise DispatchError(
                f"Error: target scripts/{script_name} is not a regular file."
            )
        if not os.access(target, os.X_OK):
            raise DispatchError(
                f"Error: target script scripts/{script_name} is not executable."
            )

        resolved_target = target.resolve()
    except OSError as exc:
        raise DispatchError(
            f"Error: cannot inspect target script scripts/{script_name}: {exc}"
        ) from exc

    if resolved_target.parent != resolved_root or resolved_target.name != script_name:
        raise DispatchError(
            f"Error: target script scripts/{script_name} escapes scripts directory."
        )
    return resolved_target


def dispatch(
    argv: Sequence[str],
    *,
    scripts_dir: Path | None = None,
    exec_fn: Callable[[str, list[str]], object] = os.execv,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    prog: str = "free-inference",
) -> int:
    """Dispatch CLI arguments to a single audited target script via exec_fn."""
    out = sys.stdout if stdout is None else stdout
    err = sys.stderr if stderr is None else stderr
    base_scripts = DEFAULT_SCRIPTS_DIR if scripts_dir is None else Path(scripts_dir)
    args = list(argv)

    if not args or (len(args) == 1 and args[0] in {"-h", "--help", "help"}):
        out.write(format_usage(prog))
        return 0

    if args[0] == "help":
        if len(args) != 2 or args[1] not in COMMAND_SPECS:
            err.write(f"Error: unknown or invalid help target: {' '.join(args[1:])}\n")
            err.write(f"Run '{prog} --help' to list available subcommands.\n")
            return 2
        spec = COMMAND_SPECS[args[1]]
        if spec.help_text is not None:
            out.write(spec.help_text)
            return 0
        forward_args = [*spec.prefix_args, "--help"]
    elif args[0] in {"--version", "-V"}:
        if len(args) != 1:
            err.write(
                f"Error: unexpected arguments after {args[0]}: {' '.join(args[1:])}\n"
            )
            err.write(f"Run '{prog} --help' for usage.\n")
            return 2
        out.write(f"free-inference {__version__}\n")
        return 0
    elif args[0] in COMMAND_SPECS:
        spec = COMMAND_SPECS[args[0]]
        forward_args = [*spec.prefix_args, *args[1:]]
    else:
        err.write(f"Error: unknown subcommand or option '{args[0]}'.\n")
        err.write(f"Run '{prog} --help' to list available subcommands.\n")
        return 2

    try:
        target = resolve_target_script(base_scripts, spec.script_name)
    except DispatchError as exc:
        err.write(f"{exc}\n")
        return 1

    exec_argv = [str(target), *forward_args]
    prev_sigpipe = None
    if exec_fn is os.execv and hasattr(signal, "SIGPIPE"):
        prev_sigpipe = signal.getsignal(signal.SIGPIPE)
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    try:
        exec_fn(str(target), exec_argv)
    except OSError as exc:
        if prev_sigpipe is not None:
            signal.signal(signal.SIGPIPE, prev_sigpipe)
        err.write(f"Error: failed to execute scripts/{spec.script_name}: {exc}\n")
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entrypoint for scripts/free-inference."""
    return dispatch(sys.argv[1:] if argv is None else argv)
