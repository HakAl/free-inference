"""Read-only custody bootstrap, active-runs pointer, and worker home scoping (P4)."""
from __future__ import annotations

import atexit
import contextlib
from dataclasses import dataclass, replace
import errno
import fcntl
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import tempfile
import time
from typing import Iterator, Sequence

try:
    import pwd
except ImportError:  # pragma: no cover
    pwd = None  # type: ignore[assignment]


ACTIVE_RUNS_POINTER_SCHEMA_VERSION = 1
ACTIVE_RUNS_POINTER_FILENAME = "active-runs.json"
PINNED_RUNS_STAT_ENV_VAR = "_FREE_INFERENCE_PINNED_RUNS_STAT"
_DARWIN_F_GETPATH = 50

WORKER_OR_REAP_CLI_FLAGS: frozenset[str] = frozenset({
    "--security-profile",
    "--unattended-worker",
    "--reap-worker",
    "--inherit-process-group",
    "--worker-manifest",
    "--launcher-exit-file",
    "--inherit-session-caps",
    "--read-root",
    "--write-root",
    "--protect-path",
    "--allow-tool",
    "--deny-tool",
    "--allow-mcp-tool",
    "--deny-mcp-tool",
    "--allow-ssh-agent",
    "--allow-localhost-port",
    "--allow-unix-socket",
    "--pass-env",
})

CUSTODY_STRIPPED_OVERRIDE_ENV_VARS: tuple[str, ...] = (
    "FREE_INFERENCE_RUNS_DIR",
    PINNED_RUNS_STAT_ENV_VAR,
    "FREE_INFERENCE_DEFAULT_ATTESTED_MODEL",
    "FREE_INFERENCE_LOCAL_ASSIST_BASE_URL",
    "FREE_INFERENCE_SE_PROXY_BIN",
    "FREE_INFERENCE_SANDBOX_EXEC_BIN",
    "FREE_INFERENCE_OPENCODE_ATTESTED_HOME",
    "FREE_INFERENCE_OPENCODE_LOCAL_HOME",
    "FREE_INFERENCE_WORKER_HOMES_DIR",
)


@dataclass(frozen=True)
class VerifiedRunsDir:
    path: Path
    exists: bool
    stat_id: tuple[int, int] | None
    dir_fd: int | None


@dataclass(frozen=True)
class CustodyBootstrapState:
    custody_mode: bool
    worker_or_reap_cli: bool
    launcher_site_packages: Path | None
    cli_runs_dir: Path | None
    bootstrap_error: str | None = None
    cli_runs_stat: tuple[int, int] | None = None
    env_runs_dir: Path | None = None
    env_runs_stat: tuple[int, int] | None = None
    pinned_runs_dir: Path | None = None
    pinned_runs_dir_fd: int | None = None
    pinned_runs_stat: tuple[int, int] | None = None


_ACTIVE_BOOTSTRAP_STATE: CustodyBootstrapState | None = None
_PINNED_POINTER_FD_STATE: tuple[Path, int, tuple[int, int]] | None = None


def clear_pinned_pointer_fd() -> None:
    global _PINNED_POINTER_FD_STATE
    prev = _PINNED_POINTER_FD_STATE
    _PINNED_POINTER_FD_STATE = None
    if prev is not None and prev[1] >= 0:
        try:
            os.close(prev[1])
        except OSError:
            pass


atexit.register(clear_pinned_pointer_fd)


def _set_pinned_pointer_fd(path: Path, dir_fd: int, stat_id: tuple[int, int]) -> None:
    global _PINNED_POINTER_FD_STATE
    prev = _PINNED_POINTER_FD_STATE
    _PINNED_POINTER_FD_STATE = (path, dir_fd, stat_id)
    if prev is not None and prev[1] >= 0 and prev[1] != dir_fd:
        try:
            os.close(prev[1])
        except OSError:
            pass


def get_active_bootstrap_state() -> CustodyBootstrapState | None:
    return _ACTIVE_BOOTSTRAP_STATE


def set_cli_runs_dir_override(
    runs_dir: Path | None,
    *,
    runs_stat: tuple[int, int] | None = None,
) -> None:
    global _ACTIVE_BOOTSTRAP_STATE
    prev = _ACTIVE_BOOTSTRAP_STATE
    if prev is None:
        _ACTIVE_BOOTSTRAP_STATE = CustodyBootstrapState(
            custody_mode=False,
            worker_or_reap_cli=False,
            launcher_site_packages=None,
            cli_runs_dir=runs_dir,
            bootstrap_error=None,
            cli_runs_stat=runs_stat if runs_dir is not None else None,
        )
    else:
        _ACTIVE_BOOTSTRAP_STATE = replace(
            prev,
            cli_runs_dir=runs_dir,
            cli_runs_stat=runs_stat if runs_dir is not None else None,
        )


def format_pinned_runs_stat(stat_id: tuple[int, int]) -> str:
    return f"{int(stat_id[0])}:{int(stat_id[1])}"


def parse_pinned_runs_stat_env(raw_val: str | None = None) -> tuple[tuple[int, int] | None, str | None]:
    val = os.environ.get(PINNED_RUNS_STAT_ENV_VAR, "") if raw_val is None else raw_val
    cleaned = val.strip()
    if not cleaned:
        return None, None
    parts = cleaned.split(":")
    if len(parts) != 2 or not parts[0].lstrip("-").isdigit() or not parts[1].isdigit():
        return None, f"Invalid {PINNED_RUNS_STAT_ENV_VAR} format: {val!r}."
    return (int(parts[0]), int(parts[1])), None


def validate_owned_directory(path: Path, *, exact_mode: int | None = None) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return False
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        return False
    mode = stat.S_IMODE(st.st_mode)
    if exact_mode is not None:
        return mode == exact_mode
    return (mode & 0o022) == 0


def _resolve_passwd_home_dir() -> Path | None:
    if pwd is None or not hasattr(os, "geteuid"):
        return None
    try:
        home_raw = pwd.getpwuid(os.geteuid()).pw_dir
    except (KeyError, OSError):
        return None
    if not isinstance(home_raw, str) or not home_raw.startswith("/"):
        return None
    segments = [seg for seg in home_raw.split("/") if seg]
    if not segments or ".." in segments or "." in segments:
        return None
    home_dir = Path("/" + "/".join(segments))
    if not validate_owned_directory(home_dir):
        return None
    return home_dir


def resolve_user_custody_opencode_dir() -> Path | None:
    home_dir = _resolve_passwd_home_dir()
    if home_dir is None:
        return None
    return home_dir / ".local" / "share" / "agent-comms" / "custody" / "opencode"


def _is_staged_local_assist_runtime_snapshot(root: Path) -> bool:
    """Return True when root is a staged <isolated_home>/runtime snapshot for local-assist-python."""
    try:
        return (
            root.name == "runtime"
            and (root.parent / "bin" / "local-assist-python").is_file()
            and (root.parent / "pyvenv.cfg").is_file()
            and not (root / "scripts" / "opencode-attested").exists()
        )
    except OSError:
        return False


def is_custody_tree(
    root: Path,
    *,
    explicit_site_packages: str | Path | None = None,
) -> bool:
    if explicit_site_packages is not None:
        return True
    home_dir = _resolve_passwd_home_dir()
    if home_dir is not None:
        custody_root = home_dir / ".local" / "share" / "agent-comms" / "custody"
        try:
            root_real = root.resolve()
            custody_real = custody_root.resolve() if custody_root.exists() else custody_root
            if root_real == custody_real or custody_real in root_real.parents:
                return True
        except OSError:
            pass
    try:
        has_dot_git = (root / ".git").exists()
    except OSError:
        has_dot_git = False
    if (
        not has_dot_git
        and not os.access(root, os.W_OK)
        and not _is_staged_local_assist_runtime_snapshot(root)
    ):
        return True
    return False


def _strip_data_firmlink_prefix(raw: str) -> str:
    if raw.startswith("/System/Volumes/Data/"):
        stripped = raw[len("/System/Volumes/Data") :]
        return stripped if stripped else "/"
    return raw


def _trusted_code_root_ancestors() -> frozenset[str]:
    try:
        code_root = _strip_data_firmlink_prefix(str(Path(__file__).resolve().parents[1]))
    except OSError:
        return frozenset()
    if not code_root.startswith("/"):
        return frozenset()
    parts = [p for p in code_root.split("/") if p]
    out: set[str] = set()
    for i in range(1, len(parts) + 1):
        out.add("/" + "/".join(parts[:i]))
    return frozenset(out)


_CODE_ROOT_ANCESTORS: frozenset[str] = _trusted_code_root_ancestors()


def _is_trusted_ancestor_stat(st: os.stat_result, *, cand_abs: str = "") -> bool:
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return False
    euid = os.geteuid() if hasattr(os, "geteuid") else st.st_uid
    if st.st_uid not in (0, euid):
        return False
    mode = stat.S_IMODE(st.st_mode)
    if (mode & 0o022) == 0:
        return True
    if st.st_uid == 0 and bool(st.st_mode & stat.S_ISVTX):
        return True
    if (
        cand_abs
        and _strip_data_firmlink_prefix(cand_abs) in _CODE_ROOT_ANCESTORS
        and st.st_uid == euid
        and (mode & 0o002) == 0
    ):
        return True
    return False


def _fd_has_create_child_perm(st: os.stat_result) -> bool:
    mode = stat.S_IMODE(st.st_mode)
    if hasattr(os, "geteuid"):
        euid = os.geteuid()
        if euid == 0:
            return True
        if st.st_uid == euid:
            return (mode & 0o300) == 0o300
        try:
            groups = set(os.getgroups())
            groups.add(os.getegid())
        except OSError:
            groups = set()
        if st.st_gid in groups:
            return (mode & 0o030) == 0o030
    return (mode & 0o003) == 0o003


def _expand_tilde_strict(raw: str) -> tuple[str | None, str | None]:
    if raw == "~" or raw.startswith("~/"):
        pw_home = _resolve_passwd_home_dir()
        base = str(pw_home) if pw_home is not None else os.path.expanduser("~")
        if not base.startswith("/"):
            return None, "Cannot resolve '~' to an absolute home directory."
        suffix = raw[1:]
        return base.rstrip("/") + suffix, None
    if raw.startswith("~"):
        expanded = os.path.expanduser(raw)
        if expanded.startswith("~") or not expanded.startswith("/"):
            return None, f"Cannot expand user home in {raw!r}."
        return expanded, None
    return raw, None


def _walk_and_validate_runs_dir(
    raw_path: str | Path,
    *,
    require_existing: bool,
    create: bool,
    retain_fd: bool = False,
    allow_tilde: bool = False,
    expected_stat: tuple[int, int] | None = None,
    label: str = "--runs-dir",
) -> tuple[VerifiedRunsDir | None, str | None]:
    raw_str = str(raw_path) if isinstance(raw_path, Path) else raw_path
    if not isinstance(raw_str, str) or not raw_str.strip():
        return None, f"{label} must be a non-empty absolute path."
    cleaned = raw_str.strip()
    if allow_tilde and cleaned.startswith("~"):
        exp, t_err = _expand_tilde_strict(cleaned)
        if t_err is not None or exp is None:
            return None, t_err or f"Invalid {label}: {raw_path!r}."
        cleaned = exp
    if not cleaned.startswith("/"):
        return None, f"{label} must be an absolute path, got {raw_path!r}."
    if len(cleaned) > 1:
        cleaned = cleaned.rstrip("/")
    if "//" in cleaned:
        return None, f"{label} must not contain duplicate '/' separators: {raw_path!r}."
    segments = [s for s in cleaned.split("/") if s]
    if not segments:
        return None, f"{label} cannot be the root directory '/'."
    if "." in segments or ".." in segments:
        return None, f"{label} must not contain '.' or '..' segments: {raw_path!r}."

    o_dir = getattr(os, "O_DIRECTORY", 0)
    o_nofollow = getattr(os, "O_NOFOLLOW", 0)
    euid = os.geteuid() if hasattr(os, "geteuid") else 0

    cur_fd: int | None = None
    try:
        cur_fd = os.open("/", os.O_RDONLY | o_dir)
    except PermissionError as exc:
        if exc.errno != errno.EPERM:
            return None, f"{label}: cannot open '/': {exc}"
        cur_fd = None
    except OSError as exc:
        return None, f"{label}: cannot open '/': {exc}"

    def _close_quiet(fd: int | None) -> None:
        if fd is not None and fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass

    def _verify_darwin_fd_path(fd: int, expected_abs: str) -> str | None:
        if sys.platform != "darwin":
            return None
        try:
            raw_fd_path = (
                fcntl.fcntl(fd, _DARWIN_F_GETPATH, bytes(1024))
                .split(b"\x00", 1)[0]
                .decode("utf-8", errors="surrogateescape")
            )
        except OSError as exc:
            return f"{label}: F_GETPATH failed on '{expected_abs}': {exc}"
        if _strip_data_firmlink_prefix(raw_fd_path) != _strip_data_firmlink_prefix(expected_abs):
            return f"{label}: descriptor path mismatch on '{expected_abs}' (got '{raw_fd_path}')."
        return None

    canonical_parts: list[str] = []
    try:
        for idx, seg in enumerate(segments):
            is_leaf = idx == len(segments) - 1

            # Allow root-owned macOS /tmp, /var, /etc -> private/<seg> symlink at depth 0.
            if idx == 0 and not canonical_parts and seg in ("tmp", "var", "etc"):
                try:
                    st0 = (
                        os.stat(seg, dir_fd=cur_fd, follow_symlinks=False)
                        if cur_fd is not None
                        else os.lstat(f"/{seg}")
                    )
                except FileNotFoundError:
                    st0 = None
                except OSError as exc:
                    _close_quiet(cur_fd)
                    return None, f"{label}: cannot inspect '/{seg}': {exc}"
                if st0 is not None and stat.S_ISLNK(st0.st_mode):
                    if is_leaf:
                        _close_quiet(cur_fd)
                        return None, f"{label} '{cleaned}' must not be a symlink."
                    try:
                        link_target = (
                            os.readlink(seg, dir_fd=cur_fd)
                            if cur_fd is not None
                            else os.readlink(f"/{seg}")
                        )
                    except OSError as exc:
                        _close_quiet(cur_fd)
                        return None, f"{label}: cannot readlink '/{seg}': {exc}"
                    if st0.st_uid != 0 or link_target != f"private/{seg}":
                        _close_quiet(cur_fd)
                        return None, f"{label}: untrusted symlink ancestor '/{seg}'."
                    priv_fd: int | None = None
                    try:
                        priv_fd = (
                            os.open("private", os.O_RDONLY | o_dir | o_nofollow, dir_fd=cur_fd)
                            if cur_fd is not None
                            else os.open("/private", os.O_RDONLY | o_dir | o_nofollow)
                        )
                    except PermissionError as exc:
                        if exc.errno != errno.EPERM:
                            _close_quiet(cur_fd)
                            return None, f"{label}: cannot open '/private': {exc}"
                        try:
                            st_priv = (
                                os.stat("private", dir_fd=cur_fd, follow_symlinks=False)
                                if cur_fd is not None
                                else os.lstat("/private")
                            )
                        except OSError as st_exc:
                            _close_quiet(cur_fd)
                            return None, f"{label}: cannot inspect '/private': {st_exc}"
                        if not _is_trusted_ancestor_stat(st_priv):
                            _close_quiet(cur_fd)
                            return None, f"{label}: untrusted '/private' directory."
                        _close_quiet(cur_fd)
                        cur_fd = None
                    except OSError as exc:
                        _close_quiet(cur_fd)
                        return None, f"{label}: cannot open '/private': {exc}"
                    else:
                        st_priv = os.fstat(priv_fd)
                        if not _is_trusted_ancestor_stat(st_priv):
                            _close_quiet(priv_fd)
                            _close_quiet(cur_fd)
                            return None, f"{label}: untrusted '/private' directory."
                        _close_quiet(cur_fd)
                        cur_fd = priv_fd

                    sub_abs = f"/private/{seg}"
                    sub_fd: int | None = None
                    try:
                        sub_fd = (
                            os.open(seg, os.O_RDONLY | o_dir | o_nofollow, dir_fd=cur_fd)
                            if cur_fd is not None
                            else os.open(sub_abs, os.O_RDONLY | o_dir | o_nofollow)
                        )
                    except PermissionError as exc:
                        if exc.errno != errno.EPERM:
                            _close_quiet(cur_fd)
                            return None, f"{label}: cannot open '{sub_abs}': {exc}"
                        try:
                            st_sub = (
                                os.stat(seg, dir_fd=cur_fd, follow_symlinks=False)
                                if cur_fd is not None
                                else os.lstat(sub_abs)
                            )
                        except OSError as st_exc:
                            _close_quiet(cur_fd)
                            return None, f"{label}: cannot inspect '{sub_abs}': {st_exc}"
                        if not _is_trusted_ancestor_stat(st_sub):
                            _close_quiet(cur_fd)
                            return None, f"{label}: untrusted ancestor '{sub_abs}'."
                        _close_quiet(cur_fd)
                        cur_fd = None
                    except OSError as exc:
                        _close_quiet(cur_fd)
                        return None, f"{label}: cannot open '{sub_abs}': {exc}"
                    else:
                        st_sub = os.fstat(sub_fd)
                        if not _is_trusted_ancestor_stat(st_sub):
                            _close_quiet(sub_fd)
                            _close_quiet(cur_fd)
                            return None, f"{label}: untrusted ancestor '{sub_abs}'."
                        if cur_fd is None:
                            fd_err = _verify_darwin_fd_path(sub_fd, sub_abs)
                            if fd_err is not None:
                                _close_quiet(sub_fd)
                                return None, fd_err
                        _close_quiet(cur_fd)
                        cur_fd = sub_fd
                    canonical_parts.extend(["private", seg])
                    continue

            cand_abs = "/" + "/".join([*canonical_parts, seg])
            was_unanchored = cur_fd is None
            next_fd: int | None = None
            try:
                next_fd = (
                    os.open(seg, os.O_RDONLY | o_dir | o_nofollow, dir_fd=cur_fd)
                    if cur_fd is not None
                    else os.open(cand_abs, os.O_RDONLY | o_dir | o_nofollow)
                )
            except FileNotFoundError:
                if require_existing or expected_stat is not None:
                    _close_quiet(cur_fd)
                    return (
                        None,
                        f"{label} '{cleaned}' must be an existing, non-symlink directory owned by uid {euid} and not group/world-writable.",
                    )
                if cur_fd is None:
                    return (
                        None,
                        f"{label}: nearest existing ancestor for '{cleaned}' is not accessible.",
                    )
                if not create:
                    st_cur = os.fstat(cur_fd)
                    if not _fd_has_create_child_perm(st_cur):
                        _close_quiet(cur_fd)
                        return None, f"{label}: nearest existing ancestor for '{cleaned}' is not writable."
                    anc_abs = "/" + "/".join(canonical_parts)
                    fd_err = _verify_darwin_fd_path(cur_fd, anc_abs)
                    _close_quiet(cur_fd)
                    if fd_err is not None:
                        return None, fd_err
                    abs_absent = Path("/" + "/".join([*canonical_parts, *segments[idx:]]))
                    return (
                        VerifiedRunsDir(path=abs_absent, exists=False, stat_id=None, dir_fd=None),
                        None,
                    )
                # create=True: create descriptor-relatively inside cur_fd with mode 0700.
                created_here = False
                try:
                    os.mkdir(seg, 0o700, dir_fd=cur_fd)
                    created_here = True
                except FileExistsError:
                    created_here = False
                except OSError as exc:
                    _close_quiet(cur_fd)
                    return None, f"{label}: failed to create directory component '{seg}' for '{cleaned}': {exc}"
                try:
                    next_fd = os.open(seg, os.O_RDONLY | o_dir | o_nofollow, dir_fd=cur_fd)
                except OSError as exc:
                    _close_quiet(cur_fd)
                    return None, f"{label}: component '{seg}' in '{cleaned}' failed no-follow directory open after mkdir: {exc}"
                if created_here:
                    try:
                        os.fchmod(next_fd, 0o700)
                    except OSError as exc:
                        _close_quiet(next_fd)
                        _close_quiet(cur_fd)
                        return None, f"{label}: failed to chmod 0700 on '{seg}': {exc}"
                st_created = os.fstat(next_fd)
                if (
                    not stat.S_ISDIR(st_created.st_mode)
                    or (hasattr(os, "geteuid") and st_created.st_uid != euid)
                    or (stat.S_IMODE(st_created.st_mode) & 0o022) != 0
                ):
                    _close_quiet(next_fd)
                    _close_quiet(cur_fd)
                    return (
                        None,
                        f"{label}: directory component '{seg}' in '{cleaned}' has untrusted ownership or permissions.",
                    )
                _close_quiet(cur_fd)
                cur_fd = next_fd
                canonical_parts.append(seg)
                continue
            except PermissionError as exc:
                if not is_leaf and exc.errno == errno.EPERM:
                    try:
                        st_anc = (
                            os.stat(seg, dir_fd=cur_fd, follow_symlinks=False)
                            if cur_fd is not None
                            else os.lstat(cand_abs)
                        )
                    except OSError as st_exc:
                        _close_quiet(cur_fd)
                        return None, f"{label}: cannot inspect ancestor '{cand_abs}': {st_exc}"
                    if not _is_trusted_ancestor_stat(st_anc, cand_abs=cand_abs):
                        _close_quiet(cur_fd)
                        return (
                            None,
                            f"{label}: ancestor directory '{cand_abs}' has untrusted ownership or group/world-writable permissions.",
                        )
                    _close_quiet(cur_fd)
                    cur_fd = None
                    canonical_parts.append(seg)
                    continue
                _close_quiet(cur_fd)
                return None, f"{label}: cannot open component '{seg}' in '{cleaned}': {exc}"
            except OSError as exc:
                _close_quiet(cur_fd)
                if exc.errno in (errno.ELOOP, errno.ENOTDIR, getattr(errno, "EFTYPE", -1)):
                    return (
                        None,
                        f"{label} '{cleaned}' must be an existing, non-symlink directory owned by uid {euid} and not group/world-writable.",
                    )
                return None, f"{label}: cannot open component '{seg}' in '{cleaned}': {exc}"

            st_next = os.fstat(next_fd)
            if is_leaf:
                if (
                    not stat.S_ISDIR(st_next.st_mode)
                    or (hasattr(os, "geteuid") and st_next.st_uid != euid)
                    or (stat.S_IMODE(st_next.st_mode) & 0o022) != 0
                ):
                    _close_quiet(next_fd)
                    _close_quiet(cur_fd)
                    return (
                        None,
                        f"{label} '{cleaned}' must be an existing, non-symlink directory owned by uid {euid} and not group/world-writable.",
                    )
            else:
                if not _is_trusted_ancestor_stat(st_next, cand_abs=cand_abs):
                    _close_quiet(next_fd)
                    _close_quiet(cur_fd)
                    return (
                        None,
                        f"{label}: ancestor directory '{cand_abs}' has untrusted ownership or group/world-writable permissions.",
                    )
            if was_unanchored:
                fd_err = _verify_darwin_fd_path(next_fd, cand_abs)
                if fd_err is not None:
                    _close_quiet(next_fd)
                    _close_quiet(cur_fd)
                    return None, fd_err
            _close_quiet(cur_fd)
            cur_fd = next_fd
            canonical_parts.append(seg)

        if cur_fd is None:
            return None, f"{label}: cannot open leaf directory '{cleaned}'."
        canonical_path = Path("/" + "/".join(canonical_parts))
        st_leaf = os.fstat(cur_fd)
        actual_stat = (int(st_leaf.st_dev), int(st_leaf.st_ino))
        if expected_stat is not None and actual_stat != (int(expected_stat[0]), int(expected_stat[1])):
            _close_quiet(cur_fd)
            return (
                None,
                f"{label} '{canonical_path}' directory identity changed after validation (expected {expected_stat}, got {actual_stat}).",
            )
        try:
            st_path = os.lstat(canonical_path)
        except OSError as exc:
            _close_quiet(cur_fd)
            return None, f"{label}: post-walk lstat failed on '{canonical_path}': {exc}"
        if (
            stat.S_ISLNK(st_path.st_mode)
            or not stat.S_ISDIR(st_path.st_mode)
            or (int(st_path.st_dev), int(st_path.st_ino)) != actual_stat
        ):
            _close_quiet(cur_fd)
            return None, f"{label}: directory '{canonical_path}' was replaced during validation."
        fd_leaf_err = _verify_darwin_fd_path(cur_fd, str(canonical_path))
        if fd_leaf_err is not None:
            _close_quiet(cur_fd)
            return None, fd_leaf_err

        if retain_fd:
            return (
                VerifiedRunsDir(path=canonical_path, exists=True, stat_id=actual_stat, dir_fd=cur_fd),
                None,
            )
        _close_quiet(cur_fd)
        return (
            VerifiedRunsDir(path=canonical_path, exists=True, stat_id=actual_stat, dir_fd=None),
            None,
        )
    except BaseException:
        _close_quiet(cur_fd)
        raise


def raw_env_runs_dir() -> str | None:
    raw_val = os.environ.get("FREE_INFERENCE_RUNS_DIR", "")
    if not isinstance(raw_val, str):
        return None
    cleaned = raw_val.strip()
    return cleaned if cleaned else None


def validate_effective_env_runs_dir(*, create: bool = False) -> tuple[Path | None, str | None]:
    raw_val = raw_env_runs_dir()
    if raw_val is None:
        return None, None
    if create:
        res, err = ensure_creatable_runs_dir(
            raw_val,
            allow_tilde=True,
            label="FREE_INFERENCE_RUNS_DIR",
        )
    else:
        res, err = validate_creatable_runs_dir(
            raw_val,
            allow_tilde=True,
            label="FREE_INFERENCE_RUNS_DIR",
        )
    if err is not None or res is None:
        return None, err
    return res.path, None


def inspect_existing_runs_dir(
    raw_path: str | Path,
    *,
    expected_stat: tuple[int, int] | None = None,
    label: str = "--runs-dir",
) -> tuple[VerifiedRunsDir | None, str | None]:
    return _walk_and_validate_runs_dir(
        raw_path,
        require_existing=True,
        create=False,
        retain_fd=False,
        allow_tilde=False,
        expected_stat=expected_stat,
        label=label,
    )


def validate_cli_runs_dir(raw_path: str) -> tuple[Path | None, str | None]:
    res, err = inspect_existing_runs_dir(raw_path, label="--runs-dir")
    if err is not None or res is None:
        return None, err
    return res.path, None


def validate_creatable_runs_dir(
    raw_path: str | Path,
    *,
    allow_tilde: bool = False,
    label: str = "--runs-dir",
) -> tuple[VerifiedRunsDir | None, str | None]:
    return _walk_and_validate_runs_dir(
        raw_path,
        require_existing=False,
        create=False,
        retain_fd=False,
        allow_tilde=allow_tilde,
        expected_stat=None,
        label=label,
    )


def ensure_creatable_runs_dir(
    raw_path: str | Path,
    *,
    retain_fd: bool = False,
    allow_tilde: bool = False,
    expected_stat: tuple[int, int] | None = None,
    label: str = "--runs-dir",
) -> tuple[VerifiedRunsDir | None, str | None]:
    return _walk_and_validate_runs_dir(
        raw_path,
        require_existing=False,
        create=True,
        retain_fd=retain_fd,
        allow_tilde=allow_tilde,
        expected_stat=expected_stat,
        label=label,
    )


def open_existing_runs_dir(
    raw_path: str | Path,
    *,
    expected_stat: tuple[int, int] | None = None,
    label: str = "--runs-dir",
) -> tuple[VerifiedRunsDir | None, str | None]:
    return _walk_and_validate_runs_dir(
        raw_path,
        require_existing=True,
        create=False,
        retain_fd=True,
        allow_tilde=False,
        expected_stat=expected_stat,
        label=label,
    )


@contextlib.contextmanager
def bind_pinned_runs_dir(
    raw_path: str | Path,
    *,
    create: bool = False,
    allow_tilde: bool = False,
    expected_stat: tuple[int, int] | None = None,
    label: str = "--runs-dir",
) -> Iterator[VerifiedRunsDir]:
    global _ACTIVE_BOOTSTRAP_STATE
    if create:
        verified, err = ensure_creatable_runs_dir(
            raw_path,
            retain_fd=True,
            allow_tilde=allow_tilde,
            expected_stat=expected_stat,
            label=label,
        )
    else:
        verified, err = _walk_and_validate_runs_dir(
            raw_path,
            require_existing=True,
            create=False,
            retain_fd=True,
            allow_tilde=allow_tilde,
            expected_stat=expected_stat,
            label=label,
        )
    if err is not None or verified is None or verified.dir_fd is None:
        raise ValueError(err or f"Invalid {label}: {raw_path!r}")

    prev = _ACTIVE_BOOTSTRAP_STATE
    if prev is None:
        _ACTIVE_BOOTSTRAP_STATE = CustodyBootstrapState(
            custody_mode=False,
            worker_or_reap_cli=False,
            launcher_site_packages=None,
            cli_runs_dir=None,
            pinned_runs_dir=verified.path,
            pinned_runs_dir_fd=verified.dir_fd,
            pinned_runs_stat=verified.stat_id,
        )
    else:
        _ACTIVE_BOOTSTRAP_STATE = replace(
            prev,
            pinned_runs_dir=verified.path,
            pinned_runs_dir_fd=verified.dir_fd,
            pinned_runs_stat=verified.stat_id,
        )
    try:
        yield verified
    finally:
        _ACTIVE_BOOTSTRAP_STATE = prev
        try:
            os.close(verified.dir_fd)
        except OSError:
            pass


def get_pinned_runs_dir_fd_for(runs_dir: Path) -> int | None:
    target_norm = _strip_data_firmlink_prefix(str(runs_dir))
    st = _ACTIVE_BOOTSTRAP_STATE
    if st is not None and st.pinned_runs_dir_fd is not None and st.pinned_runs_dir is not None:
        if st.pinned_runs_dir == runs_dir or _strip_data_firmlink_prefix(str(st.pinned_runs_dir)) == target_norm:
            return st.pinned_runs_dir_fd
    ptr_st = _PINNED_POINTER_FD_STATE
    if ptr_st is not None and ptr_st[1] >= 0:
        if ptr_st[0] == runs_dir or _strip_data_firmlink_prefix(str(ptr_st[0])) == target_norm:
            return ptr_st[1]
    return None


def _expected_stat_for_unpinned_store(runs_dir: Path) -> tuple[int, int] | None:
    target_norm = _strip_data_firmlink_prefix(str(runs_dir))
    st = _ACTIVE_BOOTSTRAP_STATE
    if st is not None:
        if (
            st.cli_runs_dir is not None
            and st.cli_runs_stat is not None
            and (st.cli_runs_dir == runs_dir or _strip_data_firmlink_prefix(str(st.cli_runs_dir)) == target_norm)
        ):
            return st.cli_runs_stat
        if (
            st.env_runs_dir is not None
            and st.env_runs_stat is not None
            and (st.env_runs_dir == runs_dir or _strip_data_firmlink_prefix(str(st.env_runs_dir)) == target_norm)
        ):
            return st.env_runs_stat
    return None


@contextlib.contextmanager
def _resolve_store_dir_fd_for_read(runs_dir: Path) -> Iterator[int | None]:
    pinned_fd = get_pinned_runs_dir_fd_for(runs_dir)
    if pinned_fd is not None:
        yield pinned_fd
        return
    exp_stat = _expected_stat_for_unpinned_store(runs_dir)
    v_tr, tr_err = open_existing_runs_dir(
        runs_dir,
        expected_stat=exp_stat,
        label="runs store",
    )
    if tr_err is not None or v_tr is None or v_tr.dir_fd is None:
        yield None
        return
    try:
        yield v_tr.dir_fd
    finally:
        try:
            os.close(v_tr.dir_fd)
        except OSError:
            pass


def _check_simple_store_filename(filename: str) -> None:
    if not filename or "/" in filename or "\\" in filename or filename in (".", ".."):
        raise ValueError(f"Invalid store filename: {filename!r}")


def runs_store_read_text(runs_dir: Path, filename: str) -> str | None:
    _check_simple_store_filename(filename)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    with _resolve_store_dir_fd_for_read(runs_dir) as dir_fd:
        if dir_fd is None:
            return None
        try:
            fd = os.open(filename, flags, dir_fd=dir_fd)
        except OSError:
            return None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return None
            chunks: list[bytes] = []
            while True:
                buf = os.read(fd, 65536)
                if not buf:
                    break
                chunks.append(buf)
            return b"".join(chunks).decode("utf-8")
        except (OSError, UnicodeDecodeError):
            return None
        finally:
            try:
                os.close(fd)
            except OSError:
                pass


def runs_store_list_names(runs_dir: Path, *, prefix: str = "", suffix: str = "") -> list[str]:
    names: list[str] = []
    with _resolve_store_dir_fd_for_read(runs_dir) as dir_fd:
        if dir_fd is None:
            return []
        try:
            dup_fd = os.dup(dir_fd)
            try:
                with os.scandir(dup_fd) as it:
                    for entry in it:
                        if not entry.name.startswith(prefix) or not entry.name.endswith(suffix):
                            continue
                        try:
                            if entry.is_file(follow_symlinks=False):
                                names.append(entry.name)
                        except OSError:
                            continue
            finally:
                try:
                    os.close(dup_fd)
                except OSError:
                    pass
        except OSError:
            return []
    return sorted(names)


def runs_store_write_atomic(
    runs_dir: Path,
    filename: str,
    content: str,
    *,
    mode: int = 0o600,
) -> None:
    _check_simple_store_filename(filename)
    dir_fd = get_pinned_runs_dir_fd_for(runs_dir)
    tmp_name = f".tmp.{filename}.{os.getpid()}.{secrets.token_hex(6)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    raw_bytes = content.encode("utf-8")
    if dir_fd is not None:
        fd = os.open(tmp_name, flags, mode, dir_fd=dir_fd)
        try:
            os.fchmod(fd, mode)
            os.write(fd, raw_bytes)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(tmp_name, dir_fd=dir_fd)
            except OSError:
                pass
            raise
        os.close(fd)
        os.replace(tmp_name, filename, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        return

    runs_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp_path = runs_dir / tmp_name
    dst_path = runs_dir / filename
    fd = os.open(str(tmp_path), flags, mode)
    try:
        os.fchmod(fd, mode)
        os.write(fd, raw_bytes)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    os.close(fd)
    os.replace(str(tmp_path), str(dst_path))


def runs_store_write_exclusive(
    runs_dir: Path,
    filename: str,
    content: str,
    *,
    mode: int = 0o600,
) -> None:
    _check_simple_store_filename(filename)
    runs_store_unlink(runs_dir, filename)
    dir_fd = get_pinned_runs_dir_fd_for(runs_dir)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    raw_bytes = content.encode("utf-8")
    if dir_fd is not None:
        fd = os.open(filename, flags, mode, dir_fd=dir_fd)
    else:
        runs_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(runs_dir / filename), flags, mode)
    try:
        os.fchmod(fd, mode)
        os.write(fd, raw_bytes)
    finally:
        os.close(fd)


def runs_store_unlink(runs_dir: Path, filename: str) -> None:
    _check_simple_store_filename(filename)
    dir_fd = get_pinned_runs_dir_fd_for(runs_dir)
    try:
        if dir_fd is not None:
            st = os.stat(filename, dir_fd=dir_fd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                return
            os.unlink(filename, dir_fd=dir_fd)
        else:
            cand = runs_dir / filename
            st = os.lstat(cand)
            if stat.S_ISDIR(st.st_mode):
                return
            cand.unlink()
    except FileNotFoundError:
        return
    except OSError:
        return


def runs_store_open_file(
    runs_dir: Path,
    filename: str,
    *,
    append: bool = False,
    mode: int = 0o600,
):
    _check_simple_store_filename(filename)
    dir_fd = get_pinned_runs_dir_fd_for(runs_dir)
    flags = os.O_CREAT | (os.O_WRONLY | os.O_APPEND if append else os.O_RDWR) | getattr(os, "O_NOFOLLOW", 0)
    if dir_fd is not None:
        fd = os.open(filename, flags, mode, dir_fd=dir_fd)
    else:
        runs_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(runs_dir / filename), flags, mode)
    return os.fdopen(fd, "a" if append else "r+", encoding="utf-8")


def _scan_pre_separator_argv(
    argv: Sequence[str],
    *,
    allow_absent_runs_dir_flag: bool = False,
) -> tuple[str | None, str | None, bool, bool, str | None]:
    """Return (raw_site_packages, raw_runs_dir, allow_absent_runs, has_worker_or_reap_flag, parse_error)."""
    site_pkgs: str | None = None
    runs_dir: str | None = None
    allow_absent_runs = False
    has_worker_or_reap = False
    tokens = list(argv[1:])
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--":
            break
        if tok in WORKER_OR_REAP_CLI_FLAGS or any(
            tok.startswith(f"{f}=") for f in WORKER_OR_REAP_CLI_FLAGS
        ):
            has_worker_or_reap = True
        if tok == "--launcher-site-packages":
            if i + 1 >= len(tokens) or tokens[i + 1] == "--":
                return None, None, False, has_worker_or_reap, "--launcher-site-packages requires an absolute directory path."
            site_pkgs = tokens[i + 1]
            i += 2
            continue
        if tok.startswith("--launcher-site-packages="):
            site_pkgs = tok.split("=", 1)[1]
            i += 1
            continue
        if tok == "--runs-dir":
            if i + 1 >= len(tokens) or tokens[i + 1] == "--":
                return site_pkgs, None, False, has_worker_or_reap, "--runs-dir requires an absolute directory path."
            runs_dir = tokens[i + 1]
            i += 2
            continue
        if tok.startswith("--runs-dir="):
            runs_dir = tok.split("=", 1)[1]
            i += 1
            continue
        if allow_absent_runs_dir_flag and tok == "--allow-absent-runs-dir":
            allow_absent_runs = True
            i += 1
            continue
        i += 1
    return site_pkgs, runs_dir, allow_absent_runs, has_worker_or_reap, None


def validate_site_packages_dir(raw_path: str) -> tuple[Path | None, str | None]:
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None, "--launcher-site-packages must be a non-empty absolute path."
    cleaned = raw_path.strip()
    if not cleaned.startswith("/"):
        return None, f"--launcher-site-packages must be an absolute path, got {raw_path!r}."
    segments = [s for s in cleaned.split("/") if s]
    if "." in segments or ".." in segments:
        return None, f"--launcher-site-packages must not contain '.' or '..' segments: {raw_path!r}."
    cand = Path(cleaned)
    if not validate_owned_directory(cand):
        return (
            None,
            f"--launcher-site-packages '{cand}' must be an existing, non-symlink directory owned by uid {os.geteuid()} and not group/world-writable.",
        )
    return cand.resolve(), None


def bootstrap_entrypoint(
    root: Path,
    argv: Sequence[str],
    *,
    exit_on_error: bool = True,
    allow_absent_runs_dir_flag: bool = False,
) -> CustodyBootstrapState:
    global _ACTIVE_BOOTSTRAP_STATE
    sys.dont_write_bytecode = True
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

    def _finish_err(
        msg: str,
        *,
        in_custody: bool,
        worker_cli: bool,
        site_dir: Path | None = None,
    ) -> CustodyBootstrapState:
        global _ACTIVE_BOOTSTRAP_STATE
        if in_custody:
            for env_key in CUSTODY_STRIPPED_OVERRIDE_ENV_VARS:
                os.environ.pop(env_key, None)
        elif worker_cli:
            os.environ.pop("FREE_INFERENCE_RUNS_DIR", None)
            os.environ.pop(PINNED_RUNS_STAT_ENV_VAR, None)
        if exit_on_error:
            print(msg, file=sys.stderr)
            raise SystemExit(1)
        st_err = CustodyBootstrapState(
            custody_mode=in_custody,
            worker_or_reap_cli=worker_cli,
            launcher_site_packages=site_dir,
            cli_runs_dir=None,
            bootstrap_error=msg,
        )
        _ACTIVE_BOOTSTRAP_STATE = st_err
        return st_err

    raw_site, raw_runs, allow_absent_runs, has_worker_or_reap, scan_err = _scan_pre_separator_argv(
        argv,
        allow_absent_runs_dir_flag=allow_absent_runs_dir_flag,
    )
    base_custody = is_custody_tree(root, explicit_site_packages=raw_site)
    if scan_err is not None:
        return _finish_err(scan_err, in_custody=base_custody, worker_cli=has_worker_or_reap)

    resolved_site: Path | None = None
    if raw_site is not None:
        resolved_site, site_err = validate_site_packages_dir(raw_site)
        if site_err is not None or resolved_site is None:
            return _finish_err(
                site_err or "Invalid --launcher-site-packages.",
                in_custody=True,
                worker_cli=has_worker_or_reap,
            )

    custody_mode = is_custody_tree(root, explicit_site_packages=resolved_site)
    resolved_runs: Path | None = None
    resolved_runs_stat: tuple[int, int] | None = None
    resolved_env_runs: Path | None = None
    resolved_env_stat: tuple[int, int] | None = None

    if custody_mode:
        for env_key in CUSTODY_STRIPPED_OVERRIDE_ENV_VARS:
            os.environ.pop(env_key, None)

        if resolved_site is None and not (root / ".venv" / "bin" / "python").exists():
            for sibling_cand in (root.parent / "env", root.parent / f"{root.name}-env"):
                if validate_owned_directory(sibling_cand):
                    resolved_site = sibling_cand.resolve()
                    break

        if resolved_site is not None:
            site_str = str(resolved_site)
            if site_str in sys.path:
                sys.path.remove(site_str)
            root_str = str(root)
            insert_idx = (sys.path.index(root_str) + 1) if root_str in sys.path else 0
            sys.path.insert(insert_idx, site_str)

        if raw_runs is not None or allow_absent_runs:
            return _finish_err(
                "Refusing --runs-dir in read-only/custody mode.",
                in_custody=True,
                worker_cli=has_worker_or_reap,
                site_dir=resolved_site,
            )
    else:
        if has_worker_or_reap:
            os.environ.pop("FREE_INFERENCE_RUNS_DIR", None)
        if allow_absent_runs and raw_runs is None:
            return _finish_err(
                "--allow-absent-runs-dir requires --runs-dir.",
                in_custody=False,
                worker_cli=has_worker_or_reap,
            )
        expected_stat, pin_err = parse_pinned_runs_stat_env()
        if pin_err is not None:
            return _finish_err(pin_err, in_custody=False, worker_cli=has_worker_or_reap)
        if raw_runs is not None:
            if allow_absent_runs:
                if expected_stat is not None:
                    return _finish_err(
                        f"Cannot combine --allow-absent-runs-dir with {PINNED_RUNS_STAT_ENV_VAR}.",
                        in_custody=False,
                        worker_cli=has_worker_or_reap,
                    )
                v_res, runs_err = validate_creatable_runs_dir(raw_runs, label="--runs-dir")
            else:
                v_res, runs_err = inspect_existing_runs_dir(
                    raw_runs,
                    expected_stat=expected_stat,
                    label="--runs-dir",
                )
            if runs_err is not None or v_res is None:
                return _finish_err(
                    runs_err or "Invalid --runs-dir.",
                    in_custody=False,
                    worker_cli=has_worker_or_reap,
                )
            resolved_runs = v_res.path
            resolved_runs_stat = v_res.stat_id
        elif not has_worker_or_reap:
            raw_env_runs = os.environ.get("FREE_INFERENCE_RUNS_DIR", "").strip()
            if raw_env_runs:
                if expected_stat is not None:
                    env_res, env_err = _walk_and_validate_runs_dir(
                        raw_env_runs,
                        require_existing=True,
                        create=False,
                        retain_fd=False,
                        allow_tilde=True,
                        expected_stat=expected_stat,
                        label="FREE_INFERENCE_RUNS_DIR",
                    )
                else:
                    env_res, env_err = validate_creatable_runs_dir(
                        raw_env_runs,
                        allow_tilde=True,
                        label="FREE_INFERENCE_RUNS_DIR",
                    )
                if env_err is not None or env_res is None:
                    return _finish_err(
                        env_err or "Invalid FREE_INFERENCE_RUNS_DIR.",
                        in_custody=False,
                        worker_cli=has_worker_or_reap,
                    )
                resolved_env_runs = env_res.path
                resolved_env_stat = env_res.stat_id
            elif expected_stat is not None:
                imp_res, imp_err = inspect_existing_runs_dir(
                    root / "runs",
                    expected_stat=expected_stat,
                    label="--runs-dir",
                )
                if imp_err is not None or imp_res is None:
                    return _finish_err(
                        imp_err or "Invalid implicit runs directory.",
                        in_custody=False,
                        worker_cli=has_worker_or_reap,
                    )

    state = CustodyBootstrapState(
        custody_mode=custody_mode,
        worker_or_reap_cli=has_worker_or_reap,
        launcher_site_packages=resolved_site,
        cli_runs_dir=resolved_runs,
        bootstrap_error=None,
        cli_runs_stat=resolved_runs_stat,
        env_runs_dir=resolved_env_runs,
        env_runs_stat=resolved_env_stat,
    )
    _ACTIVE_BOOTSTRAP_STATE = state
    return state


def resolve_user_free_inference_config_dir(*, create: bool = False) -> Path | None:
    home_dir = _resolve_passwd_home_dir()
    if home_dir is None:
        return None
    dot_config = home_dir / ".config"
    if create and not dot_config.exists() and not dot_config.is_symlink():
        try:
            dot_config.mkdir(mode=0o700)
        except OSError:
            return None
    if not validate_owned_directory(dot_config):
        return None

    fi_dir = dot_config / "free-inference"
    if create and not fi_dir.exists() and not fi_dir.is_symlink():
        try:
            fi_dir.mkdir(mode=0o700)
            os.chmod(fi_dir, 0o700)
        except OSError:
            return None
    if not validate_owned_directory(fi_dir, exact_mode=0o700):
        return None
    return fi_dir


def _before_pointer_replace_hook() -> None:
    return


def write_active_runs_pointer(
    runs_dir: Path,
    *,
    expected_stat: tuple[int, int] | None = None,
) -> Path:
    v_res, v_err = inspect_existing_runs_dir(
        runs_dir,
        expected_stat=expected_stat,
        label="active-runs pointer",
    )
    if v_err is not None or v_res is None or v_res.stat_id is None:
        raise ValueError(v_err or f"Untrusted runs_dir for active-runs pointer: {runs_dir}")
    fi_dir = resolve_user_free_inference_config_dir(create=True)
    if fi_dir is None:
        raise ValueError("Cannot validate or create ~/.config/free-inference (exact mode 0700 required).")

    o_dir = getattr(os, "O_DIRECTORY", 0)
    o_nofollow = getattr(os, "O_NOFOLLOW", 0)
    fi_fd = os.open(str(fi_dir), os.O_RDONLY | o_dir | o_nofollow)
    tmp_name = f".active-runs.{os.getpid()}.{secrets.token_hex(6)}"
    try:
        st_fi = os.fstat(fi_fd)
        if not stat.S_ISDIR(st_fi.st_mode) or stat.S_IMODE(st_fi.st_mode) != 0o700:
            raise ValueError("~/.config/free-inference must be an owned 0700 directory.")
        try:
            st_existing = os.stat(ACTIVE_RUNS_POINTER_FILENAME, dir_fd=fi_fd, follow_symlinks=False)
            if stat.S_ISLNK(st_existing.st_mode) or stat.S_ISDIR(st_existing.st_mode):
                raise ValueError(f"Refusing non-regular file at {fi_dir / ACTIVE_RUNS_POINTER_FILENAME}")
        except FileNotFoundError:
            pass

        payload = {
            "schema_version": ACTIVE_RUNS_POINTER_SCHEMA_VERSION,
            "runs_dir": str(v_res.path),
            "runs_dev": int(v_res.stat_id[0]),
            "runs_ino": int(v_res.stat_id[1]),
            "updated_at": int(time.time()),
        }
        content = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
        fd = os.open(
            tmp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | o_nofollow,
            0o600,
            dir_fd=fi_fd,
        )
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, content)
            os.fsync(fd)
        finally:
            os.close(fd)
        _before_pointer_replace_hook()
        v_pre_rep, pre_rep_err = inspect_existing_runs_dir(
            v_res.path,
            expected_stat=v_res.stat_id,
            label="active-runs pointer",
        )
        if pre_rep_err is not None or v_pre_rep is None:
            raise ValueError(pre_rep_err or f"Session store '{v_res.path}' changed before pointer publication.")
        os.replace(tmp_name, ACTIVE_RUNS_POINTER_FILENAME, src_dir_fd=fi_fd, dst_dir_fd=fi_fd)
        st_after = os.stat(ACTIVE_RUNS_POINTER_FILENAME, dir_fd=fi_fd, follow_symlinks=False)
        if stat.S_ISLNK(st_after.st_mode) or stat.S_IMODE(st_after.st_mode) != 0o600:
            raise ValueError("Failed to establish exact 0600 mode on active-runs.json.")
        v_post_rep, post_rep_err = inspect_existing_runs_dir(
            v_res.path,
            expected_stat=v_res.stat_id,
            label="active-runs pointer",
        )
        if post_rep_err is not None or v_post_rep is None:
            try:
                os.unlink(ACTIVE_RUNS_POINTER_FILENAME, dir_fd=fi_fd)
            except OSError:
                pass
            raise ValueError(post_rep_err or f"Session store '{v_res.path}' changed during pointer publication.")
    finally:
        try:
            os.unlink(tmp_name, dir_fd=fi_fd)
        except OSError:
            pass
        try:
            os.close(fi_fd)
        except OSError:
            pass
    return fi_dir / ACTIVE_RUNS_POINTER_FILENAME


def _after_pointer_read_hook() -> None:
    return


def read_active_runs_pointer() -> Path | None:
    fi_dir = resolve_user_free_inference_config_dir(create=False)
    if fi_dir is None:
        clear_pinned_pointer_fd()
        return None
    ptr_path = fi_dir / ACTIVE_RUNS_POINTER_FILENAME
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(ptr_path), flags)
    except OSError:
        clear_pinned_pointer_fd()
        return None
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or (hasattr(os, "geteuid") and st.st_uid != os.geteuid())
            or stat.S_IMODE(st.st_mode) != 0o600
            or st.st_size <= 0
            or st.st_size > 4096
        ):
            clear_pinned_pointer_fd()
            return None
        raw = os.read(fd, 4097)
        if len(raw) > 4096:
            clear_pinned_pointer_fd()
            return None
    except OSError:
        clear_pinned_pointer_fd()
        return None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        clear_pinned_pointer_fd()
        return None
    if not isinstance(obj, dict):
        clear_pinned_pointer_fd()
        return None
    if type(obj.get("schema_version")) is not int or obj["schema_version"] != ACTIVE_RUNS_POINTER_SCHEMA_VERSION:
        clear_pinned_pointer_fd()
        return None
    raw_runs = obj.get("runs_dir")
    if not isinstance(raw_runs, str) or not raw_runs.startswith("/"):
        clear_pinned_pointer_fd()
        return None
    expected_ptr_stat: tuple[int, int] | None = None
    if "runs_dev" in obj or "runs_ino" in obj:
        raw_dev = obj.get("runs_dev")
        raw_ino = obj.get("runs_ino")
        if type(raw_dev) is not int or type(raw_ino) is not int or raw_ino <= 0:
            clear_pinned_pointer_fd()
            return None
        expected_ptr_stat = (raw_dev, raw_ino)
    v_ptr, ptr_err = open_existing_runs_dir(
        raw_runs,
        expected_stat=expected_ptr_stat,
        label="active-runs pointer",
    )
    if ptr_err is not None or v_ptr is None or v_ptr.dir_fd is None or v_ptr.stat_id is None:
        clear_pinned_pointer_fd()
        return None
    _set_pinned_pointer_fd(v_ptr.path, v_ptr.dir_fd, v_ptr.stat_id)
    _after_pointer_read_hook()
    return v_ptr.path


def unvalidated_external_worker_homes_path() -> Path | None:
    """Return lexical ~/.local/state/free-inference/workers path for defensive Seatbelt deny emission."""
    home_dir = _resolve_passwd_home_dir()
    if home_dir is None:
        return None
    return home_dir / ".local" / "state" / "free-inference" / "workers"


def resolve_external_worker_homes_dir(*, create: bool = False) -> Path | None:
    home_dir = _resolve_passwd_home_dir()
    if home_dir is None:
        return None
    dot_local = home_dir / ".local"
    state_dir = dot_local / "state"
    fi_state = state_dir / "free-inference"
    workers_dir = fi_state / "workers"
    if create:
        for anc in (dot_local, state_dir):
            if not anc.exists() and not anc.is_symlink():
                try:
                    anc.mkdir(mode=0o700)
                except OSError:
                    return None
            if not validate_owned_directory(anc):
                return None
        for priv in (fi_state, workers_dir):
            if not priv.exists() and not priv.is_symlink():
                try:
                    priv.mkdir(mode=0o700)
                    os.chmod(priv, 0o700)
                except OSError:
                    return None
            if not validate_owned_directory(priv, exact_mode=0o700):
                try:
                    if validate_owned_directory(priv):
                        os.chmod(priv, 0o700)
                except OSError:
                    return None
                if not validate_owned_directory(priv, exact_mode=0o700):
                    return None
        return workers_dir.resolve()

    for anc in (dot_local, state_dir):
        if not validate_owned_directory(anc):
            return None
    for priv in (fi_state, workers_dir):
        if not validate_owned_directory(priv, exact_mode=0o700):
            return None
    return workers_dir.resolve()


def effective_worker_homes_dir(root: Path, *, create: bool = False) -> Path:
    state = get_active_bootstrap_state()
    in_custody = (
        state.custody_mode
        if state is not None
        else is_custody_tree(root)
    )
    if not in_custody and os.access(root, os.W_OK):
        raw_override = os.environ.get("FREE_INFERENCE_WORKER_HOMES_DIR", "").strip()
        if raw_override:
            p = Path(raw_override).expanduser().resolve()
            if create:
                p.mkdir(parents=True, exist_ok=True, mode=0o700)
            return p
        local_workers = root / ".home" / "workers"
        if create:
            local_workers.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                os.chmod(local_workers, 0o700)
            except OSError:
                pass
        return local_workers

    ext_workers = resolve_external_worker_homes_dir(create=create)
    if ext_workers is None:
        raise RuntimeError(
            "Cannot validate or create external worker homes directory ~/.local/state/free-inference/workers (0700)."
        )
    return ext_workers
