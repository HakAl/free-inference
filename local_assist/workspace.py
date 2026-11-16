from __future__ import annotations

import errno
import fcntl
import hashlib
import os
import stat
import sys
from pathlib import Path
from typing import Any, Callable

from .errors import ModelOutputMalformed


_RESTRICTED_DIR_NAMES = frozenset({
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".config",
    ".invocations",
    ".home",
})

_RESTRICTED_EXACT_FILENAMES = frozenset({
    ".env",
    ".envrc",
    ".mcp.json",
    "service.json",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials",
    "credentials.json",
    "auth.json",
})

_RESTRICTED_PREFIXES = (
    ".env.",
    ".se-session-",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
)

_RESTRICTED_SUFFIXES = (
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".token",
)


def resolve_workspace_root(explicit_root: Path | None = None) -> Path:
    if explicit_root is not None:
        return explicit_root.resolve()
    raw = os.environ.get("LOCAL_ASSIST_WORKSPACE_ROOT", "").strip()
    base = Path(raw) if raw else Path.cwd()
    return base.resolve()


def is_restricted_secret_filename(name: str) -> bool:
    low = name.strip().lower()
    if not low:
        return True
    if low in _RESTRICTED_EXACT_FILENAMES:
        return True
    if any(low.startswith(pref) for pref in _RESTRICTED_PREFIXES):
        return True
    if any(low.endswith(suf) for suf in _RESTRICTED_SUFFIXES):
        return True
    return False


def _descriptor_within_workspace(fd: int, ws_root: Path) -> bool:
    if sys.platform == "darwin":
        f_getpath = getattr(fcntl, "F_GETPATH", 50)
        try:
            raw_buf = fcntl.fcntl(fd, f_getpath, b"\x00" * 1024)
            nul_idx = raw_buf.find(b"\x00")
            raw_str = (raw_buf[:nul_idx] if nul_idx >= 0 else raw_buf).decode("utf-8")
            if not raw_str:
                return False
            resolved_fd_path = Path(raw_str).resolve()
            return resolved_fd_path.is_relative_to(ws_root)
        except OSError:
            return False
    if sys.platform.startswith("linux"):
        try:
            raw_str = os.readlink(f"/proc/self/fd/{fd}")
            if not raw_str or raw_str.endswith(" (deleted)"):
                return False
            resolved_fd_path = Path(raw_str).resolve()
            return resolved_fd_path.is_relative_to(ws_root)
        except OSError:
            return False
    return True


def read_confined_workspace_file(
    raw_path: Any,
    *,
    workspace_root: Path | None = None,
    max_bytes: int,
    max_chars: int | None = None,
    param_name: str = "context_path",
    _step_hook: Callable[[str, str], None] | None = None,
) -> tuple[str, str, str]:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ModelOutputMalformed(
            "invalid_arguments",
            f"{param_name} must be a non-empty string when provided.",
        )
    if "\x00" in raw_path:
        raise ModelOutputMalformed(
            "invalid_arguments",
            f"{param_name} must not contain null bytes.",
            details={param_name: raw_path},
        )

    cleaned = raw_path.strip()
    p = Path(cleaned)
    if ".." in p.parts:
        raise ModelOutputMalformed(
            "invalid_arguments",
            f"{param_name} must not contain '..' path traversal segments.",
            details={param_name: raw_path},
        )

    ws_root = resolve_workspace_root(workspace_root)
    raw_env_root = os.environ.get("LOCAL_ASSIST_WORKSPACE_ROOT", "").strip()
    unres_root = explicit_root if (explicit_root := workspace_root) is not None else (
        Path(raw_env_root) if raw_env_root else Path.cwd()
    )

    if p.is_absolute():
        if p.is_relative_to(ws_root):
            rel_parts = p.relative_to(ws_root).parts
        elif p.is_relative_to(unres_root):
            rel_parts = p.relative_to(unres_root).parts
        else:
            raise ModelOutputMalformed(
                "invalid_arguments",
                f"{param_name} must resolve inside the allowed workspace root.",
                details={
                    param_name: raw_path,
                    "workspace_root": str(ws_root),
                },
            )
    else:
        rel_parts = tuple(seg for seg in p.parts if seg not in ("", "."))

    if not rel_parts:
        raise ModelOutputMalformed(
            "invalid_arguments",
            f"{param_name} must reference a regular file inside the workspace root.",
            details={param_name: raw_path},
        )

    for dir_seg in rel_parts[:-1]:
        if dir_seg.lower() in _RESTRICTED_DIR_NAMES:
            raise ModelOutputMalformed(
                "invalid_arguments",
                f"{param_name} references a restricted directory ({dir_seg!r}).",
                details={param_name: raw_path},
            )
    if is_restricted_secret_filename(rel_parts[-1]):
        raise ModelOutputMalformed(
            "invalid_arguments",
            f"{param_name} references a restricted secret or credential filename ({rel_parts[-1]!r}).",
            details={param_name: raw_path},
        )

    for seg in rel_parts:
        if not seg or seg in (".", "..") or "/" in seg or "\\" in seg:
            raise ModelOutputMalformed(
                "invalid_arguments",
                f"{param_name} contains an invalid path segment ({seg!r}).",
                details={param_name: raw_path},
            )

    root_dir_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    step_dir_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    leaf_flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )

    try:
        ws_stat = os.stat(str(ws_root))
        cur_fd = os.open(str(ws_root), root_dir_flags)
    except OSError as exc:
        raise ModelOutputMalformed(
            "invalid_arguments",
            f"Could not open workspace root for {param_name}: {exc}",
            details={param_name: raw_path, "workspace_root": str(ws_root)},
        ) from exc

    fd: int | None = None
    try:
        cur_st = os.fstat(cur_fd)
        if not stat.S_ISDIR(cur_st.st_mode) or (cur_st.st_dev, cur_st.st_ino) != (
            ws_stat.st_dev,
            ws_stat.st_ino,
        ):
            raise ModelOutputMalformed(
                "invalid_arguments",
                f"Workspace root changed during {param_name} resolution.",
                details={param_name: raw_path, "workspace_root": str(ws_root)},
            )

        for seg in rel_parts[:-1]:
            if _step_hook is not None:
                _step_hook("dir", seg)
            try:
                next_fd = os.open(seg, step_dir_flags, dir_fd=cur_fd)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise ModelOutputMalformed(
                        "invalid_arguments",
                        f"{param_name} must not traverse or reference symlinks.",
                        details={param_name: raw_path},
                    ) from exc
                if exc.errno == errno.ENOENT:
                    raise ModelOutputMalformed(
                        "invalid_arguments",
                        f"{param_name} file not found: {raw_path}",
                        details={param_name: raw_path, "workspace_root": str(ws_root)},
                    ) from exc
                raise ModelOutputMalformed(
                    "invalid_arguments",
                    f"Could not open parent directory for {param_name}: {exc}",
                    details={param_name: raw_path},
                ) from exc
            os.close(cur_fd)
            cur_fd = next_fd
            step_st = os.fstat(cur_fd)
            if not stat.S_ISDIR(step_st.st_mode) or not _descriptor_within_workspace(
                cur_fd, ws_root
            ):
                raise ModelOutputMalformed(
                    "invalid_arguments",
                    f"{param_name} must resolve inside the allowed workspace root.",
                    details={param_name: raw_path, "workspace_root": str(ws_root)},
                )

        leaf_name = rel_parts[-1]
        if _step_hook is not None:
            _step_hook("leaf", leaf_name)
        try:
            fd = os.open(leaf_name, leaf_flags, dir_fd=cur_fd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise ModelOutputMalformed(
                    "invalid_arguments",
                    f"{param_name} must reference a regular file (not a symlink).",
                    details={param_name: raw_path},
                ) from exc
            if exc.errno == errno.ENOENT:
                raise ModelOutputMalformed(
                    "invalid_arguments",
                    f"{param_name} file not found: {raw_path}",
                    details={param_name: raw_path, "workspace_root": str(ws_root)},
                ) from exc
            raise ModelOutputMalformed(
                "invalid_arguments",
                f"Could not open {param_name}: {exc}",
                details={param_name: raw_path},
            ) from exc

        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ModelOutputMalformed(
                "invalid_arguments",
                f"{param_name} must reference a regular file.",
                details={param_name: raw_path},
            )
        if not _descriptor_within_workspace(fd, ws_root):
            raise ModelOutputMalformed(
                "invalid_arguments",
                f"{param_name} must resolve inside the allowed workspace root.",
                details={param_name: raw_path, "workspace_root": str(ws_root)},
            )
        if st.st_size > max_bytes:
            raise ModelOutputMalformed(
                "invalid_arguments",
                f"{param_name} file exceeds maximum size limit.",
                details={
                    param_name: raw_path,
                    "size_bytes": st.st_size,
                    "max_bytes": max_bytes,
                },
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ModelOutputMalformed(
                    "invalid_arguments",
                    f"{param_name} file exceeds maximum size limit.",
                    details={param_name: raw_path, "max_bytes": max_bytes},
                )
            chunks.append(chunk)
        raw_bytes = b"".join(chunks)
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.close(cur_fd)
        except OSError:
            pass

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ModelOutputMalformed(
            "invalid_arguments",
            f"Could not decode UTF-8 text from {param_name}: {exc}",
            details={param_name: raw_path},
        ) from exc

    if max_chars is not None and len(text) > max_chars:
        raise ModelOutputMalformed(
            "invalid_arguments",
            f"{param_name} exceeds maximum character length.",
            details={
                param_name: raw_path,
                "max_chars": max_chars,
                "observed": len(text),
            },
        )

    rel_posix = Path(*rel_parts).as_posix()
    sha256_hex = hashlib.sha256(raw_bytes).hexdigest()
    return rel_posix, text, sha256_hex
