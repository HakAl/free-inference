"""Read-only, offline-by-default health and security-posture audit for free-inference."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import errno
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import stat
import subprocess
import sys
from typing import Any

from .custody import (
    ActiveRunsPointerInspection,
    CustodyBootstrapState,
    _resolve_passwd_home_dir,
    _sanitize_single_line_text,
    _walk_and_validate_runs_dir_detailed,
    check_runs_dir_custody_portability,
    get_active_bootstrap_state,
    inspect_active_runs_pointer,
    is_custody_tree,
    open_existing_runs_dir,
)
from .paths import ROOT
from .registry import (
    ATTESTED_ENCLAVE_TIERS,
    RegistryError,
    load_models,
    pid_is_alive,
    resolve_endpoint,
)
from .se_key import (
    DEFAULT_ENVELOPE_ACCOUNT,
    EXPECTED_SWIFT_SOURCE_SHA256,
    SEKeyIntegrityError,
    sha256_file,
    verify_root_owned_binary_and_ancestors,
)
from .session import _probe_control_socket_via_ctl_fd, control_path, sanitize_status

DOCTOR_SCHEMA_VERSION = 1
TINFOIL_PROXY_VERSION = "0.2.9"
TINFOIL_PROXY_SHA256 = "6b526fe32244bcccfcfde3c5d181618b4b06b48498e649cd944cc9b64acf994b"
TINFOIL_TEAM_IDENTIFIER = "8KSH668LZT"
PRIVATEMODE_MANIFEST_REL = "config/privatemode-manifest-v1.63.0.json"
PRIVATEMODE_MANIFEST_SHA256 = "5fa927e3b864738da35d427c10ba8e49ebeeb1531e49618899cf95f654d240c1"
DARWIN_CODESIGN_BIN = "/usr/bin/codesign"
DARWIN_SWIFTC_BIN = "/usr/bin/swiftc"
FIXED_SYSTEM_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
FIXED_PS_ENV = {"PATH": "/bin:/usr/bin", "LC_ALL": "C", "TZ": "UTC"}
MAX_PID_RECORD_BYTES = 65536
MAX_VALID_PID = (1 << 31) - 1


class _DoctorCliError(Exception):
    """Raised on argparse errors so doctor emits a static stderr line and exits 1."""


class _SafeDoctorArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _DoctorCliError(message)


@dataclass(frozen=True)
class DoctorCheck:
    id: str
    status: str  # "pass", "warn", "fail", "skip"
    summary: str
    details: dict[str, Any]
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "summary": self.summary,
            "details": self.details,
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class _DoctorStoreDecision:
    source: str  # "cli_override", "env_override", "active_runs_pointer", "default_store"
    status: str  # "ok", "absent", "refused"
    runs_dir: Path | None = None
    stat_id: tuple[int, int] | None = None
    reason_code: str | None = None
    message: str | None = None
    remediation: str | None = None
    custody_portable: bool | None = None
    portability_reason: str | None = None
    portability_remediation: str | None = None


def _before_live_sessions_store_check_hook(_stage: str) -> None:
    return


def sanitize_bootstrap_error(raw_msg: str | None) -> tuple[str, str]:
    """Map raw custody bootstrap errors to fixed static codes and messages."""
    text = (raw_msg or "").lower()
    if "custody" in text and "--runs-dir" in text:
        return (
            "custody_runs_dir_refused",
            "Refusing --runs-dir in read-only/custody mode.",
        )
    if "--launcher-site-packages" in text or "site-packages" in text:
        return (
            "invalid_site_packages",
            "Invalid or untrusted --launcher-site-packages directory.",
        )
    if "_free_inference_pinned_runs_stat" in text or "pinned" in text:
        return (
            "invalid_pinned_runs_stat",
            "Invalid pinned session store identity environment variable.",
        )
    if "free_inference_runs_dir" in text:
        return (
            "invalid_env_runs_dir",
            "FREE_INFERENCE_RUNS_DIR is invalid or untrusted.",
        )
    if "--runs-dir" in text:
        return (
            "invalid_cli_runs_dir",
            "--runs-dir is invalid, missing, or untrusted.",
        )
    return (
        "bootstrap_failed",
        "Doctor bootstrap validation failed; check CLI flags and store permissions.",
    )


def _select_verified_system_binary(candidates: tuple[str, ...]) -> str | None:
    for cand in candidates:
        try:
            verify_root_owned_binary_and_ancestors(cand)
        except (SEKeyIntegrityError, OSError, ValueError):
            continue
        return cand
    return None


def _run_pinned_system_cmd(
    candidates: tuple[str, ...],
    args: list[str],
    *,
    env: dict[str, str],
    timeout: float = 10.0,
) -> tuple[str | None, subprocess.CompletedProcess[str] | None]:
    binary = _select_verified_system_binary(candidates)
    if binary is None:
        return None, None
    try:
        proc = subprocess.run(
            [binary, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=dict(env),
        )
    except (OSError, subprocess.SubprocessError):
        return binary, None
    return binary, proc


def _ps_candidates() -> tuple[str, ...]:
    if sys.platform == "darwin":
        return ("/bin/ps",)
    return ("/usr/bin/ps", "/bin/ps")


def _doctor_ps_query(pid: int, column: str) -> str | None:
    _, proc = _run_pinned_system_cmd(
        _ps_candidates(),
        ["-p", str(pid), "-o", f"{column}="],
        env=FIXED_PS_ENV,
        timeout=3.0,
    )
    if proc is None or proc.returncode != 0:
        return None
    out = (proc.stdout or "").strip()
    return out if out else None


def _doctor_classify_pid_identity(pid: Any, expected_lstart: Any) -> str:
    if not isinstance(pid, int) or isinstance(pid, bool) or not (1 <= pid <= MAX_VALID_PID):
        return "unavailable"
    if not isinstance(expected_lstart, str) or not expected_lstart.strip():
        return "unavailable"
    try:
        alive = pid_is_alive(pid)
    except (OverflowError, OSError, ValueError):
        return "unavailable"
    if not alive:
        return "dead"
    stat_out = _doctor_ps_query(pid, "stat")
    if stat_out is not None and stat_out.lstrip().upper().startswith("Z"):
        return "dead"
    actual = _doctor_ps_query(pid, "lstart")
    if actual is None:
        try:
            still_alive = pid_is_alive(pid)
        except (OverflowError, OSError, ValueError):
            return "unavailable"
        return "dead" if not still_alive else "unavailable"
    return "matched" if actual == expected_lstart.strip() else "reused"


def _store_identity_intact(
    runs_path: Path,
    expected_stat: tuple[int, int],
    runs_fd: int,
    *,
    ctl_fd: int | None = None,
    stage: str = "check",
) -> bool:
    _before_live_sessions_store_check_hook(stage)
    try:
        st_path = os.lstat(runs_path)
        st_fd = os.fstat(runs_fd)
    except OSError:
        return False
    if (
        stat.S_ISLNK(st_path.st_mode)
        or not stat.S_ISDIR(st_path.st_mode)
        or (int(st_path.st_dev), int(st_path.st_ino)) != expected_stat
        or (int(st_fd.st_dev), int(st_fd.st_ino)) != expected_stat
    ):
        return False
    if ctl_fd is not None:
        try:
            st_ctl_fd = os.fstat(ctl_fd)
            st_ctl_entry = os.stat(".control", dir_fd=runs_fd, follow_symlinks=False)
        except OSError:
            return False
        if (
            stat.S_ISLNK(st_ctl_entry.st_mode)
            or not stat.S_ISDIR(st_ctl_entry.st_mode)
            or (int(st_ctl_entry.st_dev), int(st_ctl_entry.st_ino))
            != (int(st_ctl_fd.st_dev), int(st_ctl_fd.st_ino))
        ):
            return False
    return True


def _resolve_doctor_store(
    root: Path,
    *,
    cli_runs_dir: Path | None,
    cli_runs_stat: tuple[int, int] | None,
    env_runs_dir: Path | None,
    env_runs_stat: tuple[int, int] | None,
    in_custody: bool,
) -> _DoctorStoreDecision:
    if cli_runs_dir is not None:
        v_res, v_err, detail = _walk_and_validate_runs_dir_detailed(
            cli_runs_dir,
            require_existing=True,
            create=False,
            retain_fd=False,
            allow_tilde=False,
            expected_stat=cli_runs_stat,
            label="--runs-dir",
            allow_code_root_ancestors=True,
        )
        if v_err is not None or v_res is None or v_res.stat_id is None:
            code = detail.reason_code if detail is not None else "target_unreadable"
            return _DoctorStoreDecision(
                source="cli_override",
                status="refused",
                reason_code=code,
                message="Explicit --runs-dir store could not be validated safely.",
                remediation="Verify --runs-dir ownership, permissions, and ancestor trust.",
            )
        port = check_runs_dir_custody_portability(
            v_res.path,
            expected_stat=v_res.stat_id,
            require_existing=True,
        )
        return _DoctorStoreDecision(
            source="cli_override",
            status="ok",
            runs_dir=v_res.path,
            stat_id=v_res.stat_id,
            custody_portable=(port.status == "ok"),
            portability_reason=port.reason_code if port.status != "ok" else None,
            portability_remediation=port.remediation if port.status != "ok" else None,
        )

    if env_runs_dir is not None and not in_custody:
        v_res, v_err, detail = _walk_and_validate_runs_dir_detailed(
            env_runs_dir,
            require_existing=False,
            create=False,
            retain_fd=False,
            allow_tilde=False,
            expected_stat=env_runs_stat,
            label="FREE_INFERENCE_RUNS_DIR",
            allow_code_root_ancestors=True,
            require_creatable=False,
        )
        if v_err is not None or v_res is None:
            code = detail.reason_code if detail is not None else "target_unreadable"
            return _DoctorStoreDecision(
                source="env_override",
                status="refused",
                reason_code=code,
                message="FREE_INFERENCE_RUNS_DIR store could not be validated safely.",
                remediation="Verify FREE_INFERENCE_RUNS_DIR ownership, permissions, and ancestor trust.",
            )
        if not v_res.exists:
            port = check_runs_dir_custody_portability(
                v_res.path,
                require_existing=False,
                require_creatable=False,
            )
            return _DoctorStoreDecision(
                source="env_override",
                status="absent",
                runs_dir=v_res.path,
                stat_id=None,
                custody_portable=(port.status in ("ok", "absent")),
                portability_reason=port.reason_code if port.status == "refused" else None,
                portability_remediation=port.remediation if port.status == "refused" else None,
            )
        port = check_runs_dir_custody_portability(
            v_res.path,
            expected_stat=v_res.stat_id,
            require_existing=True,
        )
        return _DoctorStoreDecision(
            source="env_override",
            status="ok",
            runs_dir=v_res.path,
            stat_id=v_res.stat_id,
            custody_portable=(port.status == "ok"),
            portability_reason=port.reason_code if port.status != "ok" else None,
            portability_remediation=port.remediation if port.status != "ok" else None,
        )

    ptr: ActiveRunsPointerInspection = inspect_active_runs_pointer(
        pin_fd=False,
        allow_code_root_ancestors=(not in_custody),
    )
    if ptr.status == "refused":
        return _DoctorStoreDecision(
            source="active_runs_pointer",
            status="refused",
            reason_code=ptr.reason_code,
            message=ptr.message,
            remediation=ptr.remediation,
            custody_portable=False,
            portability_reason=ptr.reason_code,
            portability_remediation=ptr.remediation,
        )
    if ptr.status == "ok" and ptr.path is not None and ptr.stat_id is not None:
        port = check_runs_dir_custody_portability(
            ptr.path,
            expected_stat=ptr.stat_id,
            require_existing=True,
        )
        return _DoctorStoreDecision(
            source="active_runs_pointer",
            status="ok",
            runs_dir=ptr.path,
            stat_id=ptr.stat_id,
            custody_portable=(port.status == "ok"),
            portability_reason=port.reason_code if port.status != "ok" else None,
            portability_remediation=port.remediation if port.status != "ok" else None,
        )

    # Pointer absent: inspect DEFAULT_RUNS_DIR via read-only structured walker
    # (require_creatable=False so a trusted 0500 read-only custody checkout with no runs/
    # passes as absent, while dangling symlinks or untrustworthy leaves still fail).
    default_runs = root / "runs"
    v_def, def_err, def_detail = _walk_and_validate_runs_dir_detailed(
        default_runs,
        require_existing=False,
        create=False,
        retain_fd=False,
        allow_tilde=False,
        expected_stat=None,
        label="default runs store",
        allow_code_root_ancestors=(not in_custody),
        require_creatable=False,
    )
    if def_err is not None or v_def is None:
        code = def_detail.reason_code if def_detail is not None else "target_unreadable"
        anc = def_detail.untrusted_ancestor if def_detail is not None else None
        owned_gw = def_detail.ancestor_owned_group_writable if def_detail is not None else False
        if code == "target_untrusted_ancestor" and owned_gw and anc:
            safe_anc = _sanitize_single_line_text(anc)
            if safe_anc == anc:
                remediation = (
                    f"Tighten ancestor permissions (chmod 0750 {shlex.quote(safe_anc)}) or use a 0700-parented session store."
                )
            else:
                remediation = (
                    "Tighten ancestor permissions to 0750 or use a 0700-parented session store."
                )
        else:
            remediation = (
                "Ensure the default runs directory is a non-symlink owned directory without group/world write permissions."
            )
        return _DoctorStoreDecision(
            source="default_store",
            status="refused",
            reason_code=code,
            message="Default session store directory failed trust validation.",
            remediation=remediation,
            custody_portable=False,
            portability_reason=code,
            portability_remediation=remediation,
        )
    if not v_def.exists:
        port = check_runs_dir_custody_portability(
            v_def.path,
            require_existing=False,
            require_creatable=False,
        )
        return _DoctorStoreDecision(
            source="default_store",
            status="absent",
            runs_dir=v_def.path,
            stat_id=None,
            custody_portable=(port.status in ("ok", "absent")),
            portability_reason=port.reason_code if port.status == "refused" else None,
            portability_remediation=port.remediation if port.status == "refused" else None,
        )
    port = check_runs_dir_custody_portability(
        v_def.path,
        expected_stat=v_def.stat_id,
        require_existing=True,
    )
    return _DoctorStoreDecision(
        source="default_store",
        status="ok",
        runs_dir=v_def.path,
        stat_id=v_def.stat_id,
        custody_portable=(port.status == "ok"),
        portability_reason=port.reason_code if port.status != "ok" else None,
        portability_remediation=port.remediation if port.status != "ok" else None,
    )


def check_platform_runtime(root: Path) -> DoctorCheck:
    py_ver = ".".join(str(x) for x in sys.version_info[:3])
    is_darwin = sys.platform == "darwin"
    sys_name = platform.system()
    machine = platform.machine()
    venv_python = root / ".venv" / "bin" / "python"
    venv_present = venv_python.is_file() and os.access(venv_python, os.X_OK)

    # Read-only discovery only: use lstat (with symlink target regular/X_OK check); never execute opencode!
    opencode_found = shutil.which("opencode")
    opencode_executable = False
    opencode_is_symlink = False
    if opencode_found:
        try:
            st_l = os.lstat(opencode_found)
            if stat.S_ISLNK(st_l.st_mode):
                opencode_is_symlink = True
                st_t = os.stat(opencode_found)
                opencode_executable = stat.S_ISREG(st_t.st_mode) and os.access(opencode_found, os.X_OK)
            else:
                opencode_executable = stat.S_ISREG(st_l.st_mode) and os.access(opencode_found, os.X_OK)
        except OSError:
            opencode_executable = False

    details: dict[str, Any] = {
        "system": sys_name,
        "machine": machine,
        "python": py_ver,
        "venv_present": venv_present,
        "opencode_discovered": opencode_executable,
        "opencode_is_symlink": opencode_is_symlink,
        "opencode_path": _sanitize_single_line_text(opencode_found) if opencode_executable and opencode_found else None,
        "opencode_executed": False,
    }
    if sys.version_info < (3, 11):
        return DoctorCheck(
            id="platform_runtime",
            status="fail",
            summary=f"Unsupported Python {py_ver}; Python >= 3.11 is required.",
            details=details,
            remediation="Install Python 3.11+ and rerun ./scripts/doctor.",
        )
    if is_darwin:
        warns: list[str] = []
        if machine != "arm64":
            warns.append(f"non-arm64 macOS ({machine})")
        if not opencode_executable:
            warns.append("opencode not found on PATH")
        if not venv_present:
            warns.append(".venv absent (Rung 1 local MLX unavailable; --launcher-only mode still works)")
        if warns:
            return DoctorCheck(
                id="platform_runtime",
                status="warn",
                summary=f"Darwin {machine}, Python {py_ver}: " + "; ".join(warns) + ".",
                details=details,
                remediation="Install opencode and/or run ./scripts/setup --local-only if you need Rung 1 local MLX.",
            )
        return DoctorCheck(
            id="platform_runtime",
            status="pass",
            summary=f"Darwin {machine}, Python {py_ver}, .venv and opencode binary discovered.",
            details=details,
        )
    return DoctorCheck(
        id="platform_runtime",
        status="pass",
        summary=f"Portable non-Darwin platform ({sys_name} {machine}, Python {py_ver}).",
        details=details,
    )


def check_runs_store_and_pointer(store: _DoctorStoreDecision, *, in_custody: bool) -> DoctorCheck:
    details: dict[str, Any] = {
        "source": store.source,
        "store_status": store.status,
        "runs_dir": _sanitize_single_line_text(str(store.runs_dir)) if store.runs_dir is not None else None,
        "custody_portable": store.custody_portable,
        "reason_code": store.reason_code or store.portability_reason,
    }
    if store.status == "refused":
        return DoctorCheck(
            id="runs_store_and_pointer",
            status="fail",
            summary=store.message or "Session store or active-runs pointer was refused.",
            details=details,
            remediation=store.remediation,
        )
    if store.custody_portable is False:
        status = "fail" if in_custody else "warn"
        summary = (
            f"Session store ({store.source}) is valid locally but not portable to read-only custody launchers "
            f"({store.portability_reason or 'untrusted_ancestor'})."
        )
        return DoctorCheck(
            id="runs_store_and_pointer",
            status=status,
            summary=summary,
            details=details,
            remediation=store.portability_remediation,
        )
    if store.status == "absent":
        return DoctorCheck(
            id="runs_store_and_pointer",
            status="pass",
            summary=f"No active session pointer; target store ({store.source}) does not exist yet under trusted ancestors.",
            details=details,
        )
    return DoctorCheck(
        id="runs_store_and_pointer",
        status="pass",
        summary=f"Session store ({store.source}) validated and custody-portable.",
        details=details,
    )


def check_se_key_proxy(root: Path, *, env: dict[str, str] | None = None) -> DoctorCheck:
    if sys.platform != "darwin":
        return DoctorCheck(
            id="se_key_proxy",
            status="skip",
            summary="Skipped on non-Darwin platform (Secure Enclave proxy requires Apple Silicon macOS).",
            details={"platform": sys.platform},
        )
    eff_env = env if env is not None else os.environ
    src_path = root / "tools" / "se_key_proxy" / "main.swift"
    stamp_path = root / "bin" / ".se-key-proxy.stamp"
    override_bin = (eff_env.get("FREE_INFERENCE_SE_PROXY_BIN") or "").strip()

    # 1. Verify Swift source hash
    if not src_path.is_file() or src_path.is_symlink():
        return DoctorCheck(
            id="se_key_proxy",
            status="fail",
            summary="Secure Enclave proxy Swift source is missing or invalid.",
            details={"reason_code": "source_sha_mismatch"},
            remediation="Restore tools/se_key_proxy/main.swift from a clean checkout.",
        )
    try:
        actual_src_sha = sha256_file(src_path)
    except OSError:
        return DoctorCheck(
            id="se_key_proxy",
            status="fail",
            summary="Failed to hash Secure Enclave proxy Swift source.",
            details={"reason_code": "source_sha_mismatch"},
            remediation="Check permissions on tools/se_key_proxy/main.swift.",
        )
    if actual_src_sha != EXPECTED_SWIFT_SOURCE_SHA256:
        return DoctorCheck(
            id="se_key_proxy",
            status="fail",
            summary="Secure Enclave proxy Swift source digest does not match pinned source hash.",
            details={"reason_code": "source_sha_mismatch"},
            remediation="Restore tools/se_key_proxy/main.swift or rebuild after updating the pinned source hash.",
        )

    # 2. Verify root-owned override if configured
    target_bin = root / "bin" / "se-key-proxy"
    if override_bin:
        try:
            verify_root_owned_binary_and_ancestors(override_bin)
        except (SEKeyIntegrityError, OSError, ValueError):
            return DoctorCheck(
                id="se_key_proxy",
                status="fail",
                summary="FREE_INFERENCE_SE_PROXY_BIN failed root-owned binary/ancestor verification.",
                details={"reason_code": "override_untrusted"},
                remediation="Point FREE_INFERENCE_SE_PROXY_BIN at a root-owned 0755 binary with non-writable ancestors, or unset it.",
            )
        target_bin = Path(override_bin).resolve()
        if target_bin.name == "se-key-proxy-test":
            return DoctorCheck(
                id="se_key_proxy",
                status="fail",
                summary="FREE_INFERENCE_SE_PROXY_BIN points at the test binary.",
                details={"reason_code": "override_untrusted"},
                remediation="Point FREE_INFERENCE_SE_PROXY_BIN at the release se-key-proxy binary.",
            )

    # 3. Verify build stamp
    if not stamp_path.is_file() or stamp_path.is_symlink():
        return DoctorCheck(
            id="se_key_proxy",
            status="warn",
            summary="se-key-proxy build stamp is missing (not built yet).",
            details={"reason_code": "stamp_missing"},
            remediation="Run ./scripts/se-key build or ./scripts/setup --launcher-only.",
        )
    try:
        stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        return DoctorCheck(
            id="se_key_proxy",
            status="fail",
            summary="se-key-proxy build stamp is unreadable or invalid JSON.",
            details={"reason_code": "stamp_invalid"},
            remediation="Run ./scripts/se-key build to regenerate bin/se-key-proxy and its stamp.",
        )
    if not isinstance(stamp, dict):
        return DoctorCheck(
            id="se_key_proxy",
            status="fail",
            summary="se-key-proxy build stamp is malformed.",
            details={"reason_code": "stamp_invalid"},
            remediation="Run ./scripts/se-key build.",
        )
    if stamp.get("source_sha256") != actual_src_sha:
        return DoctorCheck(
            id="se_key_proxy",
            status="fail",
            summary="se-key-proxy build stamp source digest does not match current Swift source.",
            details={"reason_code": "source_sha_mismatch"},
            remediation="Run ./scripts/se-key build to rebuild bin/se-key-proxy.",
        )
    expected_bin_sha = stamp.get("binary_sha256")
    if not isinstance(expected_bin_sha, str) or len(expected_bin_sha) != 64:
        return DoctorCheck(
            id="se_key_proxy",
            status="fail",
            summary="se-key-proxy build stamp is missing a valid binary SHA-256.",
            details={"reason_code": "stamp_invalid"},
            remediation="Run ./scripts/se-key build.",
        )

    # 4. Verify swiftc version via pinned /usr/bin/swiftc (zero caller PATH)
    _, swiftc_proc = _run_pinned_system_cmd(
        (DARWIN_SWIFTC_BIN,),
        ["--version"],
        env=FIXED_SYSTEM_ENV,
        timeout=10.0,
    )
    if swiftc_proc is None or swiftc_proc.returncode != 0:
        return DoctorCheck(
            id="se_key_proxy",
            status="fail",
            summary="Pinned /usr/bin/swiftc is unavailable or failed.",
            details={"reason_code": "swiftc_unavailable"},
            remediation="Ensure Xcode Command Line Tools are installed (/usr/bin/swiftc).",
        )
    first_line = (swiftc_proc.stdout or "").strip().splitlines()
    swiftc_ver = first_line[0].strip() if first_line else ""
    if not swiftc_ver or stamp.get("swiftc_version") != swiftc_ver:
        return DoctorCheck(
            id="se_key_proxy",
            status="fail",
            summary="se-key-proxy build stamp toolchain version does not match /usr/bin/swiftc.",
            details={"reason_code": "swiftc_mismatch"},
            remediation="Run ./scripts/se-key build to rebuild for the installed Swift toolchain.",
        )

    # 5. Verify release binary existence, SHA-256, and pinned /usr/bin/codesign
    if not target_bin.is_file() or target_bin.is_symlink():
        return DoctorCheck(
            id="se_key_proxy",
            status="warn" if not override_bin else "fail",
            summary="se-key-proxy release binary is missing.",
            details={"reason_code": "binary_missing"},
            remediation="Run ./scripts/se-key build or ./scripts/setup --launcher-only.",
        )
    try:
        actual_bin_sha = sha256_file(target_bin)
    except OSError:
        return DoctorCheck(
            id="se_key_proxy",
            status="fail",
            summary="Failed to hash se-key-proxy release binary.",
            details={"reason_code": "binary_sha_mismatch"},
            remediation="Run ./scripts/se-key build.",
        )
    if actual_bin_sha != expected_bin_sha:
        return DoctorCheck(
            id="se_key_proxy",
            status="fail",
            summary="se-key-proxy release binary SHA-256 does not match its build stamp.",
            details={"reason_code": "binary_sha_mismatch"},
            remediation="Run ./scripts/se-key build to rebuild bin/se-key-proxy.",
        )

    _, cs_proc = _run_pinned_system_cmd(
        (DARWIN_CODESIGN_BIN,),
        ["-v", "--strict", str(target_bin)],
        env=FIXED_SYSTEM_ENV,
        timeout=10.0,
    )
    if cs_proc is None or cs_proc.returncode != 0:
        return DoctorCheck(
            id="se_key_proxy",
            status="fail",
            summary="se-key-proxy binary failed pinned /usr/bin/codesign verification.",
            details={"reason_code": "codesign_failed"},
            remediation="Run ./scripts/se-key build to re-sign bin/se-key-proxy.",
        )

    return DoctorCheck(
        id="se_key_proxy",
        status="pass",
        summary="se-key-proxy Swift source, build stamp, binary digest, and codesign signature verified.",
        details={
            "override_used": bool(override_bin),
            "binary_sha256_prefix": actual_bin_sha[:16],
        },
    )


def check_attested_proxies(root: Path) -> DoctorCheck:
    manifest_path = root / PRIVATEMODE_MANIFEST_REL
    manifest_ok = False
    manifest_reason: str | None = None
    if not manifest_path.is_file() or manifest_path.is_symlink():
        manifest_reason = "manifest_missing"
    else:
        try:
            actual_m_sha = sha256_file(manifest_path)
            if actual_m_sha == PRIVATEMODE_MANIFEST_SHA256:
                manifest_ok = True
            else:
                manifest_reason = "manifest_sha_mismatch"
        except OSError:
            manifest_reason = "manifest_unreadable"

    details: dict[str, Any] = {
        "privatemode_manifest_verified": manifest_ok,
        "privatemode_manifest_reason": manifest_reason,
    }
    if not manifest_ok:
        return DoctorCheck(
            id="attested_proxies",
            status="fail",
            summary="Committed Privatemode Contrast manifest failed SHA-256 verification.",
            details=details,
            remediation=f"Restore {PRIVATEMODE_MANIFEST_REL} from a clean checkout.",
        )

    if sys.platform != "darwin":
        details["darwin_binaries"] = "skipped"
        return DoctorCheck(
            id="attested_proxies",
            status="pass",
            summary="Committed Privatemode manifest verified; Darwin proxy binaries skipped on non-Darwin.",
            details=details,
        )

    tf_bin = root / "bin" / "tinfoil-proxy"
    pm_bin = root / "bin" / "privatemode-proxy"
    pm_stamp = root / "bin" / ".privatemode-proxy.stamp"

    tinfoil_status = "missing"
    tinfoil_reason: str | None = None
    try:
        st_tf = os.lstat(tf_bin)
    except FileNotFoundError:
        tinfoil_status = "missing"
    except OSError:
        tinfoil_status = "fail"
        tinfoil_reason = "tinfoil_unreadable"
    else:
        if stat.S_ISLNK(st_tf.st_mode):
            tinfoil_status = "fail"
            tinfoil_reason = "tinfoil_symlink"
        elif not stat.S_ISREG(st_tf.st_mode):
            tinfoil_status = "fail"
            tinfoil_reason = "tinfoil_nonregular"
        elif not os.access(tf_bin, os.X_OK):
            tinfoil_status = "fail"
            tinfoil_reason = "tinfoil_not_executable"
        else:
            try:
                tf_sha = sha256_file(tf_bin)
            except OSError:
                tf_sha = ""
            if tf_sha != TINFOIL_PROXY_SHA256:
                tinfoil_status = "fail"
                tinfoil_reason = "tinfoil_sha_mismatch"
            else:
                _, cs_v = _run_pinned_system_cmd(
                    (DARWIN_CODESIGN_BIN,),
                    ["-v", "--strict", str(tf_bin)],
                    env=FIXED_SYSTEM_ENV,
                    timeout=10.0,
                )
                _, cs_d = _run_pinned_system_cmd(
                    (DARWIN_CODESIGN_BIN,),
                    ["-dv", "--verbose=4", str(tf_bin)],
                    env=FIXED_SYSTEM_ENV,
                    timeout=10.0,
                )
                cs_info = ((cs_d.stderr or "") + "\n" + (cs_d.stdout or "")) if cs_d is not None else ""
                if cs_v is None or cs_v.returncode != 0:
                    tinfoil_status = "fail"
                    tinfoil_reason = "tinfoil_codesign_failed"
                elif cs_d is None or cs_d.returncode != 0 or f"TeamIdentifier={TINFOIL_TEAM_IDENTIFIER}" not in cs_info:
                    tinfoil_status = "fail"
                    tinfoil_reason = "tinfoil_team_id_mismatch"
                else:
                    tinfoil_status = "verified"

    pm_status = "not_installed"
    pm_reason: str | None = None
    try:
        st_pm = os.lstat(pm_bin)
    except FileNotFoundError:
        pm_status = "not_installed"
    except OSError:
        pm_status = "fail"
        pm_reason = "privatemode_unreadable"
    else:
        if stat.S_ISLNK(st_pm.st_mode):
            pm_status = "fail"
            pm_reason = "privatemode_symlink"
        elif not stat.S_ISREG(st_pm.st_mode):
            pm_status = "fail"
            pm_reason = "privatemode_nonregular"
        elif not os.access(pm_bin, os.X_OK):
            pm_status = "fail"
            pm_reason = "privatemode_not_executable"
        else:
            pm_status = "present"
            try:
                st_pms = os.lstat(pm_stamp)
            except FileNotFoundError:
                pass
            except OSError:
                pm_status = "fail"
                pm_reason = "privatemode_stamp_unreadable"
            else:
                if stat.S_ISLNK(st_pms.st_mode):
                    pm_status = "fail"
                    pm_reason = "privatemode_stamp_symlink"
                elif not stat.S_ISREG(st_pms.st_mode):
                    pm_status = "fail"
                    pm_reason = "privatemode_stamp_nonregular"
                else:
                    try:
                        st_obj = json.loads(pm_stamp.read_text(encoding="utf-8"))
                        exp_sha = st_obj.get("binary_sha256") if isinstance(st_obj, dict) else None
                        if not isinstance(exp_sha, str) or len(exp_sha) != 64:
                            pm_status = "fail"
                            pm_reason = "privatemode_stamp_invalid"
                        elif sha256_file(pm_bin) != exp_sha:
                            pm_status = "fail"
                            pm_reason = "privatemode_sha_mismatch"
                        else:
                            pm_status = "verified"
                    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
                        pm_status = "fail"
                        pm_reason = "privatemode_stamp_invalid"

    details.update({
        "tinfoil_proxy_status": tinfoil_status,
        "tinfoil_proxy_reason": tinfoil_reason,
        "privatemode_proxy_status": pm_status,
        "privatemode_proxy_reason": pm_reason,
    })

    if tinfoil_status == "fail" or pm_status == "fail":
        return DoctorCheck(
            id="attested_proxies",
            status="fail",
            summary="One or more attested enclave proxy binaries failed integrity or signature checks.",
            details=details,
            remediation="Re-verify or reinstall proxies via ./scripts/setup --launcher-only (and --with-privatemode if used).",
        )
    if tinfoil_status == "missing":
        return DoctorCheck(
            id="attested_proxies",
            status="warn",
            summary="bin/tinfoil-proxy is not installed (Privatemode manifest verified).",
            details=details,
            remediation="Run ./scripts/setup --launcher-only to install and verify bin/tinfoil-proxy.",
        )
    return DoctorCheck(
        id="attested_proxies",
        status="pass",
        summary=f"bin/tinfoil-proxy v{TINFOIL_PROXY_VERSION} and Privatemode manifest verified (privatemode-proxy: {pm_status}).",
        details=details,
    )


def _envelope_stem(service: str, account: str = DEFAULT_ENVELOPE_ACCOUNT) -> str:
    return hashlib.sha256(f"{service}\0{account}".encode("utf-8")).hexdigest()


def check_se_envelopes(root: Path) -> DoctorCheck:
    """Metadata-only SE envelope presence/permissions audit. Never opens or reads payloads."""
    if sys.platform != "darwin":
        return DoctorCheck(
            id="se_envelopes",
            status="skip",
            summary="Skipped on non-Darwin platform (Secure Enclave envelopes require macOS).",
            details={"platform": sys.platform, "integrity_checked": False},
        )

    cleared_services: set[str] = set()
    all_services: set[str] = set()
    try:
        for m in load_models(root / "models.yaml"):
            ep = resolve_endpoint(m, require_api_key=False)
            if ep.api_key_keychain_service:
                all_services.add(ep.api_key_keychain_service)
                if ep.routing_private_attested == "cleared":
                    cleared_services.add(ep.api_key_keychain_service)
    except RegistryError:
        pass

    home_dir = _resolve_passwd_home_dir()
    if home_dir is None:
        return DoctorCheck(
            id="se_envelopes",
            status="fail",
            summary="Cannot resolve trusted passwd home directory for Secure Enclave envelopes.",
            details={"reason_code": "home_untrusted", "integrity_checked": False},
            remediation="Ensure your home directory is owned by your user and not group/world-writable.",
        )

    o_dir = getattr(os, "O_DIRECTORY", 0)
    o_nofollow = getattr(os, "O_NOFOLLOW", 0)
    euid = os.geteuid() if hasattr(os, "geteuid") else 0
    home_fd: int | None = None
    cfg_fd: int | None = None
    fi_fd: int | None = None
    env_fd: int | None = None
    try:
        try:
            home_fd = os.open(str(home_dir), os.O_RDONLY | o_dir | o_nofollow)
            st_home = os.fstat(home_fd)
        except OSError:
            return DoctorCheck(
                id="se_envelopes",
                status="fail",
                summary="Home directory could not be opened safely.",
                details={"reason_code": "home_untrusted", "integrity_checked": False},
            )
        if not stat.S_ISDIR(st_home.st_mode) or st_home.st_uid != euid or (stat.S_IMODE(st_home.st_mode) & 0o022) != 0:
            return DoctorCheck(
                id="se_envelopes",
                status="fail",
                summary="Home directory has untrusted ownership or permissions.",
                details={"reason_code": "home_untrusted", "integrity_checked": False},
            )

        try:
            cfg_fd = os.open(".config", os.O_RDONLY | o_dir | o_nofollow, dir_fd=home_fd)
            st_cfg = os.fstat(cfg_fd)
        except FileNotFoundError:
            return DoctorCheck(
                id="se_envelopes",
                status="warn",
                summary="No ~/.config/free-inference/se-envelopes directory found yet.",
                details={"present_services": [], "missing_services": sorted(all_services), "integrity_checked": False},
                remediation="Run ./scripts/se-key store free-inference.tinfoil to seal an enclave API key.",
            )
        except OSError:
            return DoctorCheck(
                id="se_envelopes",
                status="fail",
                summary="~/.config has untrusted type or could not be opened safely.",
                details={"reason_code": "config_dir_untrusted", "integrity_checked": False},
            )
        if not stat.S_ISDIR(st_cfg.st_mode) or st_cfg.st_uid != euid or (stat.S_IMODE(st_cfg.st_mode) & 0o022) != 0:
            return DoctorCheck(
                id="se_envelopes",
                status="fail",
                summary="~/.config has untrusted ownership or group/world write permissions.",
                details={"reason_code": "config_dir_untrusted", "integrity_checked": False},
            )

        try:
            fi_fd = os.open("free-inference", os.O_RDONLY | o_dir | o_nofollow, dir_fd=cfg_fd)
            st_fi = os.fstat(fi_fd)
        except FileNotFoundError:
            return DoctorCheck(
                id="se_envelopes",
                status="warn",
                summary="No ~/.config/free-inference/se-envelopes directory found yet.",
                details={"present_services": [], "missing_services": sorted(all_services), "integrity_checked": False},
                remediation="Run ./scripts/se-key store free-inference.tinfoil to seal an enclave API key.",
            )
        except OSError:
            return DoctorCheck(
                id="se_envelopes",
                status="fail",
                summary="~/.config/free-inference has untrusted type or permissions.",
                details={"reason_code": "config_dir_untrusted", "integrity_checked": False},
                remediation="Ensure ~/.config/free-inference is an owned 0700 directory.",
            )
        if not stat.S_ISDIR(st_fi.st_mode) or st_fi.st_uid != euid or stat.S_IMODE(st_fi.st_mode) != 0o700:
            return DoctorCheck(
                id="se_envelopes",
                status="fail",
                summary="~/.config/free-inference must be an owned 0700 directory.",
                details={"reason_code": "config_dir_untrusted", "integrity_checked": False},
                remediation="Run chmod 0700 ~/.config/free-inference.",
            )

        try:
            env_fd = os.open("se-envelopes", os.O_RDONLY | o_dir | o_nofollow, dir_fd=fi_fd)
            st_env = os.fstat(env_fd)
        except FileNotFoundError:
            return DoctorCheck(
                id="se_envelopes",
                status="warn",
                summary="No ~/.config/free-inference/se-envelopes directory found yet.",
                details={"present_services": [], "missing_services": sorted(all_services), "integrity_checked": False},
                remediation="Run ./scripts/se-key store free-inference.tinfoil to seal an enclave API key.",
            )
        except OSError:
            return DoctorCheck(
                id="se_envelopes",
                status="fail",
                summary="~/.config/free-inference/se-envelopes has untrusted type or permissions.",
                details={"reason_code": "envelope_dir_untrusted", "integrity_checked": False},
                remediation="Ensure ~/.config/free-inference/se-envelopes is an owned 0700 directory.",
            )
        if not stat.S_ISDIR(st_env.st_mode) or st_env.st_uid != euid or stat.S_IMODE(st_env.st_mode) != 0o700:
            return DoctorCheck(
                id="se_envelopes",
                status="fail",
                summary="~/.config/free-inference/se-envelopes must be an owned 0700 directory.",
                details={"reason_code": "envelope_dir_untrusted", "integrity_checked": False},
                remediation="Run chmod 0700 ~/.config/free-inference/se-envelopes.",
            )

        present_services: list[str] = []
        missing_services: list[str] = []
        bad_services: list[str] = []
        state_present: list[str] = []

        for service in sorted(all_services):
            stem = _envelope_stem(service)
            env_name = f"{stem}.json"
            state_name = f"{stem}.state.json"

            # Metadata-only stat relative to env_fd; never open or read payloads!
            try:
                st_file = os.stat(env_name, dir_fd=env_fd, follow_symlinks=False)
            except FileNotFoundError:
                missing_services.append(service)
            except OSError:
                bad_services.append(service)
            else:
                if (
                    stat.S_ISLNK(st_file.st_mode)
                    or not stat.S_ISREG(st_file.st_mode)
                    or st_file.st_uid != euid
                    or stat.S_IMODE(st_file.st_mode) != 0o600
                    or st_file.st_size <= 0
                ):
                    bad_services.append(service)
                else:
                    present_services.append(service)

            try:
                st_state = os.stat(state_name, dir_fd=env_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError:
                if service not in bad_services:
                    bad_services.append(service)
            else:
                if (
                    stat.S_ISLNK(st_state.st_mode)
                    or not stat.S_ISREG(st_state.st_mode)
                    or st_state.st_uid != euid
                    or stat.S_IMODE(st_state.st_mode) != 0o600
                    or st_state.st_size <= 0
                ):
                    if service not in bad_services:
                        bad_services.append(service)
                else:
                    state_present.append(service)

        details: dict[str, Any] = {
            "present_services": present_services,
            "missing_services": missing_services,
            "invalid_metadata_services": bad_services,
            "lifecycle_state_files_present": state_present,
            "integrity_checked": False,
        }
        if bad_services:
            return DoctorCheck(
                id="se_envelopes",
                status="fail",
                summary=f"Secure Enclave envelope metadata check failed for {len(bad_services)} service(s).",
                details=details,
                remediation="Ensure envelope files under ~/.config/free-inference/se-envelopes are owned 0600 regular non-empty files (or re-seal via ./scripts/se-key store <service>).",
            )
        has_cleared_present = any(svc in present_services for svc in cleared_services) if cleared_services else bool(present_services)
        if not has_cleared_present:
            return DoctorCheck(
                id="se_envelopes",
                status="warn",
                summary="Envelope directory is 0700, but no cleared Rung 3 provider envelope file is present.",
                details=details,
                remediation="Run ./scripts/se-key store free-inference.tinfoil (or free-inference.privatemode).",
            )
        return DoctorCheck(
            id="se_envelopes",
            status="pass",
            summary=(
                f"Metadata-only envelope presence/permissions check passed for {len(present_services)} service(s) "
                "(run './scripts/se-key status <service>' to verify cryptographic integrity)."
            ),
            details=details,
        )
    finally:
        for fd_item in (env_fd, fi_fd, cfg_fd, home_fd):
            if fd_item is not None and fd_item >= 0:
                try:
                    os.close(fd_item)
                except OSError:
                    pass


def check_bpf_permissions(*, bpf_path: Path = Path("/dev/bpf0")) -> DoctorCheck:
    if sys.platform != "darwin":
        return DoctorCheck(
            id="bpf_permissions",
            status="skip",
            summary="Skipped on non-Darwin platform (/dev/bpf0 check is macOS-specific).",
            details={"platform": sys.platform},
        )
    try:
        st = os.lstat(bpf_path)
    except FileNotFoundError:
        return DoctorCheck(
            id="bpf_permissions",
            status="warn",
            summary="/dev/bpf0 not found; could not verify loopback capture permissions.",
            details={"present": False},
        )
    except OSError:
        return DoctorCheck(
            id="bpf_permissions",
            status="warn",
            summary="Could not inspect /dev/bpf0 permissions.",
            details={"present": False},
        )
    mode = stat.S_IMODE(st.st_mode)
    details = {
        "uid": int(st.st_uid),
        "gid": int(st.st_gid),
        "mode_octal": oct(mode),
    }
    if st.st_uid != 0 or (mode & 0o077) != 0:
        return DoctorCheck(
            id="bpf_permissions",
            status="fail",
            summary=f"/dev/bpf0 has loose permissions ({oct(mode)}, uid={st.st_uid}); non-root loopback sniffing may be possible.",
            details=details,
            remediation="Restrict /dev/bpf0 to root:wheel 0600 (disable ChmodBPF / access_bpf) before attested sessions.",
        )
    return DoctorCheck(
        id="bpf_permissions",
        status="pass",
        summary=f"/dev/bpf0 restricted to root ({oct(mode)}).",
        details=details,
    )


def _load_generate_eval_manifest_module(root: Path) -> Any:
    script_path = root / "scripts" / "generate-eval-manifest"
    if not script_path.is_file() or script_path.is_symlink():
        return None
    loader = importlib.machinery.SourceFileLoader("_doctor_generate_eval_manifest", str(script_path))
    spec = importlib.util.spec_from_loader("_doctor_generate_eval_manifest", loader)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    prev_dont_write = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = prev_dont_write
    return mod


def check_model_registry(root: Path) -> DoctorCheck:
    try:
        models = load_models(root / "models.yaml")
    except RegistryError:
        return DoctorCheck(
            id="model_registry",
            status="fail",
            summary="Failed to load models.yaml.",
            details={"reason_code": "registry_load_failed"},
            remediation="Fix YAML or schema errors in models.yaml.",
        )

    rung1_cleared = 0
    rung2_cleared = 0
    rung3_cleared = 0
    candidates = 0
    archived = 0
    invalid_models: list[str] = []

    for m in models:
        mid = str(m.get("id") or "unknown")
        try:
            ep = resolve_endpoint(m, require_api_key=False)
        except RegistryError:
            invalid_models.append(_sanitize_single_line_text(mid))
            continue
        if ep.status == "archived":
            archived += 1
        elif ep.status == "candidate":
            candidates += 1
        if ep.data_control_rung == 1 and ep.routing_private_local == "cleared":
            rung1_cleared += 1
        elif ep.data_control_rung == 2 and ep.routing_private_attested == "cleared":
            rung2_cleared += 1
        elif ep.data_control_rung == 3 and ep.routing_private_attested == "cleared":
            rung3_cleared += 1

    manifest_ok = False
    manifest_error_count = 0
    manifest_validator_loaded = False
    try:
        gem = _load_generate_eval_manifest_module(root)
        if gem is not None and hasattr(gem, "check_all_cleared_models"):
            manifest_validator_loaded = True
            manifest_ok, m_errs = gem.check_all_cleared_models(root_dir=root, offline_ci=True)
            manifest_error_count = len(m_errs)
    except Exception:
        manifest_ok = False
        manifest_error_count = 1

    details: dict[str, Any] = {
        "total_models": len(models),
        "rung1_cleared": rung1_cleared,
        "rung2_cleared": rung2_cleared,
        "rung3_cleared": rung3_cleared,
        "candidates": candidates,
        "archived": archived,
        "invalid_model_count": len(invalid_models),
        "offline_manifest_check_passed": manifest_ok,
        "offline_manifest_error_count": manifest_error_count,
        "offline_manifest_validator_loaded": manifest_validator_loaded,
    }
    if invalid_models or not manifest_validator_loaded or not manifest_ok:
        return DoctorCheck(
            id="model_registry",
            status="fail",
            summary=(
                f"Model registry or offline eval-manifest verification failed "
                f"(invalid_models={len(invalid_models)}, manifest_errors={manifest_error_count})."
            ),
            details=details,
            remediation="Run python3 -I -B ./scripts/generate-eval-manifest --check --offline-ci to inspect mismatches.",
        )
    return DoctorCheck(
        id="model_registry",
        status="pass",
        summary=(
            f"Registry valid ({len(models)} models; cleared: Rung 1={rung1_cleared}, "
            f"Rung 2={rung2_cleared}, Rung 3={rung3_cleared}; offline eval manifests verified)."
        ),
        details=details,
    )


def _read_pid_record_from_dir_fd(runs_fd: int, filename: str) -> dict[str, Any] | None:
    o_nofollow = getattr(os, "O_NOFOLLOW", 0)
    o_nonblock = getattr(os, "O_NONBLOCK", 0)
    fd: int | None = None
    try:
        fd = os.open(filename, os.O_RDONLY | o_nofollow | o_nonblock, dir_fd=runs_fd)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size <= 0 or st.st_size > MAX_PID_RECORD_BYTES:
            return None
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_PID_RECORD_BYTES:
            part = os.read(fd, (MAX_PID_RECORD_BYTES + 1) - total)
            if not part:
                break
            chunks.append(part)
            total += len(part)
        if total == 0 or total > MAX_PID_RECORD_BYTES:
            return None
        parsed = json.loads(b"".join(chunks).decode("utf-8"))
        return parsed if isinstance(parsed, dict) else None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        return None
    finally:
        if fd is not None and fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def _parse_upstream_state(record: dict[str, Any]) -> tuple[bool, str | None]:
    has_up_pid = "upstream_pid" in record
    has_up_ls = "upstream_pid_lstart" in record
    if not has_up_pid and not has_up_ls:
        return False, None

    raw_pid = record.get("upstream_pid")
    raw_ls = record.get("upstream_pid_lstart")
    if has_up_pid and has_up_ls and raw_pid is None and raw_ls is None:
        if record.get("status") == "starting":
            return False, None
        return True, "unavailable"

    if (
        not has_up_pid
        or not has_up_ls
        or not isinstance(raw_pid, int)
        or isinstance(raw_pid, bool)
        or not (1 <= raw_pid <= MAX_VALID_PID)
        or not isinstance(raw_ls, str)
        or not raw_ls.strip()
    ):
        return True, "unavailable"

    return True, _doctor_classify_pid_identity(raw_pid, raw_ls)


def _probe_attested_socket_via_runs_fd(
    runs_path: Path,
    expected_stat: tuple[int, int],
    runs_fd: int,
    *,
    model_id: str,
    expected_repo: str,
    expected_pid: int,
) -> tuple[str, dict[str, Any] | None, bool]:
    """Return (socket_state, sanitized_info, identity_ok).

    socket_state is 'ON', 'OFF', or 'UNKNOWN'.
    identity_ok=False means store identity changed and takes precedence over all errors.
    """
    if not _store_identity_intact(runs_path, expected_stat, runs_fd, stage="pre_open_control"):
        return "UNKNOWN", None, False

    o_dir = getattr(os, "O_DIRECTORY", 0)
    o_nofollow = getattr(os, "O_NOFOLLOW", 0)
    euid = os.geteuid() if hasattr(os, "geteuid") else 0
    sock_name = control_path(runs_path, model_id).name
    ctl_fd: int | None = None
    try:
        try:
            ctl_fd = os.open(".control", os.O_RDONLY | o_dir | o_nofollow, dir_fd=runs_fd)
        except OSError:
            ok = _store_identity_intact(runs_path, expected_stat, runs_fd, stage="post_control_open_error")
            return "UNKNOWN", None, ok

        try:
            st_ctl = os.fstat(ctl_fd)
        except OSError:
            ok = _store_identity_intact(runs_path, expected_stat, runs_fd, ctl_fd=ctl_fd, stage="post_control_fstat_error")
            return "UNKNOWN", None, ok
        if not stat.S_ISDIR(st_ctl.st_mode) or st_ctl.st_uid != euid or stat.S_IMODE(st_ctl.st_mode) != 0o700:
            ok = _store_identity_intact(runs_path, expected_stat, runs_fd, ctl_fd=ctl_fd, stage="post_control_mode_error")
            return "UNKNOWN", None, ok

        if not _store_identity_intact(runs_path, expected_stat, runs_fd, ctl_fd=ctl_fd, stage="pre_socket_stat"):
            return "UNKNOWN", None, False

        try:
            st_sock = os.stat(sock_name, dir_fd=ctl_fd, follow_symlinks=False)
        except OSError:
            ok = _store_identity_intact(runs_path, expected_stat, runs_fd, ctl_fd=ctl_fd, stage="post_socket_stat_error")
            return "UNKNOWN", None, ok
        if not stat.S_ISSOCK(st_sock.st_mode) or st_sock.st_uid != euid or stat.S_IMODE(st_sock.st_mode) != 0o600:
            ok = _store_identity_intact(runs_path, expected_stat, runs_fd, ctl_fd=ctl_fd, stage="post_socket_mode_error")
            return "UNKNOWN", None, ok

        if not _store_identity_intact(runs_path, expected_stat, runs_fd, ctl_fd=ctl_fd, stage="pre_socket_exchange"):
            return "UNKNOWN", None, False

        try:
            raw = _probe_control_socket_via_ctl_fd(
                ctl_fd,
                sock_name,
                expected_pid=expected_pid,
                timeout=1.5,
            )
            info = sanitize_status(raw, expected_model=expected_repo, expected_pid=expected_pid)
        except (OSError, ValueError, KeyError, json.JSONDecodeError, RecursionError):
            ok = _store_identity_intact(runs_path, expected_stat, runs_fd, ctl_fd=ctl_fd, stage="post_socket_exchange_error")
            return "UNKNOWN", None, ok

        if not _store_identity_intact(runs_path, expected_stat, runs_fd, ctl_fd=ctl_fd, stage="post_socket_exchange"):
            return "UNKNOWN", None, False

        return str(info.get("state") or "UNKNOWN"), info, True
    finally:
        if ctl_fd is not None and ctl_fd >= 0:
            try:
                os.close(ctl_fd)
            except OSError:
                pass


def check_live_sessions(root: Path, store: _DoctorStoreDecision, *, in_custody: bool = False) -> DoctorCheck:
    if store.status == "refused":
        return DoctorCheck(
            id="live_sessions",
            status="skip",
            summary="Skipped live-session audit because the selected session store was refused.",
            details={"reason_code": store.reason_code},
        )
    if store.status == "absent" or store.runs_dir is None or store.stat_id is None:
        return DoctorCheck(
            id="live_sessions",
            status="pass",
            summary="No session store created yet (0 active, 0 stale).",
            details={"active_count": 0, "warn_count": 0, "sessions": []},
        )

    attested_model_ids: set[str] = set()
    try:
        for m in load_models(root / "models.yaml"):
            ep = resolve_endpoint(m, require_api_key=False)
            if ep.trust_tier in ATTESTED_ENCLAVE_TIERS:
                attested_model_ids.add(ep.model_id)
    except RegistryError:
        pass

    v_runs, open_err = open_existing_runs_dir(
        store.runs_dir,
        expected_stat=store.stat_id,
        label="doctor runs store",
        allow_code_root_ancestors=(not in_custody),
    )
    if open_err is not None or v_runs is None or v_runs.dir_fd is None or v_runs.stat_id != store.stat_id:
        if v_runs is not None and v_runs.dir_fd is not None and v_runs.dir_fd >= 0:
            try:
                os.close(v_runs.dir_fd)
            except OSError:
                pass
        return DoctorCheck(
            id="live_sessions",
            status="fail",
            summary="Selected session store identity changed during audit.",
            details={"reason_code": "store_identity_changed"},
            remediation="Re-run ./scripts/doctor and verify no process is replacing the session store directory.",
        )

    runs_fd = v_runs.dir_fd
    try:
        names: list[str] = []
        try:
            dup_fd = os.dup(runs_fd)
            try:
                with os.scandir(dup_fd) as it:
                    for entry in it:
                        if entry.name.startswith(".serve") and entry.name.endswith(".pid"):
                            names.append(entry.name)
            finally:
                try:
                    os.close(dup_fd)
                except OSError:
                    pass
        except OSError:
            return DoctorCheck(
                id="live_sessions",
                status="fail",
                summary="Failed to scan verified session store directory.",
                details={"reason_code": "store_identity_changed"},
            )

        sessions_out: list[dict[str, Any]] = []
        active_count = 0
        warn_count = 0
        stale_models: list[str] = []

        for fname in sorted(names):
            rec = _read_pid_record_from_dir_fd(runs_fd, fname)
            if rec is None:
                if not _store_identity_intact(store.runs_dir, store.stat_id, runs_fd, stage="post_malformed_record"):
                    return DoctorCheck(
                        id="live_sessions",
                        status="fail",
                        summary="Selected session store identity changed during audit.",
                        details={"reason_code": "store_identity_changed"},
                        remediation="Re-run ./scripts/doctor and verify the session store was not replaced.",
                    )
                sessions_out.append({
                    "model_id": "unknown",
                    "is_attested": False,
                    "primary_pid_state": "unavailable",
                    "category": "unverifiable",
                    "reason_code": "malformed_pid_record",
                })
                warn_count += 1
                continue

            raw_mid = rec.get("model_id")
            model_id = _sanitize_single_line_text(raw_mid) if isinstance(raw_mid, str) and raw_mid.strip() else "unknown"
            is_attested = bool(rec.get("session_token_file")) or (model_id in attested_model_ids)
            primary_state = _doctor_classify_pid_identity(rec.get("pid"), rec.get("pid_lstart"))
            has_upstream, upstream_state = _parse_upstream_state(rec)

            entry_info: dict[str, Any] = {
                "model_id": model_id,
                "is_attested": is_attested,
                "primary_pid_state": primary_state,
            }
            if has_upstream:
                entry_info["upstream_pid_state"] = upstream_state

            category = "unverifiable"
            if not is_attested:
                if primary_state == "matched":
                    category = "active_local"
                    entry_info["process_identity_only"] = True
                elif primary_state in ("dead", "reused"):
                    category = "stale"
                else:
                    category = "unverifiable"
            else:
                if rec.get("status") == "starting":
                    entry_info["starting"] = True
                    if primary_state in ("dead", "reused") and has_upstream and upstream_state == "matched":
                        category = "orphaned_upstream"
                    elif primary_state in ("dead", "reused") and (not has_upstream or upstream_state in ("dead", "reused")):
                        category = "stale"
                    else:
                        category = "unverifiable"
                elif primary_state in ("dead", "reused"):
                    if has_upstream and upstream_state == "matched":
                        category = "orphaned_upstream"
                    elif has_upstream and upstream_state == "unavailable":
                        category = "unverifiable"
                    else:
                        category = "stale"
                elif primary_state == "unavailable":
                    category = "unverifiable"
                else:
                    # primary_state == "matched"
                    expected_repo = rec.get("repo") if isinstance(rec.get("repo"), str) else ""
                    sock_state, live_ctrl, id_ok = _probe_attested_socket_via_runs_fd(
                        store.runs_dir,
                        store.stat_id,
                        runs_fd,
                        model_id=model_id,
                        expected_repo=expected_repo,
                        expected_pid=int(rec["pid"]),
                    )
                    if not id_ok:
                        return DoctorCheck(
                            id="live_sessions",
                            status="fail",
                            summary="Selected session store identity changed during control-socket audit.",
                            details={"reason_code": "store_identity_changed"},
                            remediation="Re-run ./scripts/doctor and verify the session store was not replaced.",
                        )
                    entry_info["control_state"] = sock_state
                    if live_ctrl is not None:
                        entry_info["remaining_seconds"] = live_ctrl.get("remaining_seconds")
                        entry_info["requests_remaining"] = live_ctrl.get("requests_remaining")
                        entry_info["request_limit"] = live_ctrl.get("request_limit")

                    if has_upstream and upstream_state != "matched":
                        category = "degraded_attested"
                    elif sock_state == "ON":
                        category = "active_attested"
                    elif sock_state == "OFF":
                        category = "expired_attested"
                    else:
                        category = "unverifiable"

            if not _store_identity_intact(store.runs_dir, store.stat_id, runs_fd, stage="pre_commit_record"):
                return DoctorCheck(
                    id="live_sessions",
                    status="fail",
                    summary="Selected session store identity changed during audit.",
                    details={"reason_code": "store_identity_changed"},
                    remediation="Re-run ./scripts/doctor and verify the session store was not replaced.",
                )

            entry_info["category"] = category
            sessions_out.append(entry_info)
            if category in ("active_local", "active_attested"):
                active_count += 1
            else:
                warn_count += 1
                if category in ("stale", "orphaned_upstream", "degraded_attested", "expired_attested"):
                    stale_models.append(model_id)

        if not _store_identity_intact(store.runs_dir, store.stat_id, runs_fd, stage="pre_aggregate_publish"):
            return DoctorCheck(
                id="live_sessions",
                status="fail",
                summary="Selected session store identity changed during audit.",
                details={"reason_code": "store_identity_changed"},
                remediation="Re-run ./scripts/doctor and verify the session store was not replaced.",
            )

        details = {
            "active_count": active_count,
            "warn_count": warn_count,
            "sessions": sessions_out,
        }
        if warn_count > 0:
            return DoctorCheck(
                id="live_sessions",
                status="warn",
                summary=f"Found {active_count} active session(s) and {warn_count} degraded/expired/stale/unverifiable record(s).",
                details=details,
                remediation=(
                    "Inspect or clean up session records with ./scripts/session status or ./scripts/stop-model <model-id>."
                ),
            )
        return DoctorCheck(
            id="live_sessions",
            status="pass",
            summary=f"Session store clean ({active_count} active, 0 warnings).",
            details=details,
        )
    finally:
        try:
            os.close(runs_fd)
        except OSError:
            pass


def check_legacy_containment(root: Path, *, in_custody: bool, env: dict[str, str] | None = None) -> DoctorCheck:
    from .launch import check_uncontained_legacy_home

    eff_env = env if env is not None else os.environ
    homes: dict[str, Path] = {}
    for label, env_key, rel in (
        ("attested", "FREE_INFERENCE_OPENCODE_ATTESTED_HOME", ".home/opencode-private-attested"),
        ("local", "FREE_INFERENCE_OPENCODE_LOCAL_HOME", ".home/opencode-private-local"),
    ):
        override = (eff_env.get(env_key) or "").strip() if not in_custody else ""
        homes[label] = Path(override).expanduser().resolve() if override else (root / rel)

    uncontained: list[str] = []
    for label, path in homes.items():
        if check_uncontained_legacy_home(path) is not None:
            uncontained.append(label)

    details = {"uncontained_homes": uncontained}
    if uncontained:
        return DoctorCheck(
            id="legacy_containment",
            status="fail",
            summary=f"Uncontained legacy OpenCode home(s) detected: {', '.join(uncontained)}.",
            details=details,
            remediation="Run ./scripts/check-credential-containment --check to inspect and remediate legacy state.",
        )
    return DoctorCheck(
        id="legacy_containment",
        status="pass",
        summary="No uncontained legacy OpenCode homes detected.",
        details=details,
    )


def check_catalog_drift(root: Path, *, enabled: bool) -> DoctorCheck:
    if not enabled:
        return DoctorCheck(
            id="catalog_drift",
            status="skip",
            summary="Skipped in default offline mode (pass --check-catalog to query upstream feeds).",
            details={"enabled": False},
        )
    try:
        from ._miniyaml import safe_load
        from . import catalog_sync

        models_data = safe_load((root / "models.yaml").read_text(encoding="utf-8"))
        if not isinstance(models_data, dict):
            raise ValueError("invalid models.yaml")
        router_doc = catalog_sync.fetch_tinfoil_router_manifest(
            catalog_sync.DEFAULT_ROUTER_MANIFEST_URL, timeout=20
        )
        models_doc = catalog_sync.fetch_tinfoil_openai_models(
            catalog_sync.DEFAULT_OPENAI_MODELS_URL, timeout=20
        )
        enclave_cache: dict[str, dict[str, Any]] = {}
        fetch_budget = [0]

        def _fetch_enclave(repo: str, tag: str) -> dict[str, Any]:
            key = f"{repo}@{tag}"
            if key not in enclave_cache:
                enclave_cache[key] = catalog_sync.fetch_tinfoil_enclave_config(
                    repo,
                    tag,
                    raw_base_url=catalog_sync.DEFAULT_GITHUB_RAW_BASE_URL,
                    timeout=20,
                )
            return enclave_cache[key]

        report = catalog_sync.compute_catalog_drift(
            models_data,
            router_doc,
            models_doc,
            enclave_cache,
            enclave_config_fetcher=_fetch_enclave,
            discover_new_coding_models=True,
            ignored_served_ids=set(catalog_sync.DEFAULT_IGNORED_SERVED_IDS),
            fetch_budget=fetch_budget,
        )
    except Exception:
        return DoctorCheck(
            id="catalog_drift",
            status="fail",
            summary="Live upstream catalog drift check failed.",
            details={"enabled": True, "reason_code": "catalog_fetch_failed"},
            remediation="Verify network connectivity and rerun ./scripts/sync-model-catalog --check.",
        )
    item_count = len(report.items)
    disagreement_count = len(report.disagreements)
    drift_count = item_count + disagreement_count
    details = {
        "enabled": True,
        "drift_count": drift_count,
        "item_count": item_count,
        "disagreement_count": disagreement_count,
    }
    if drift_count > 0:
        return DoctorCheck(
            id="catalog_drift",
            status="warn",
            summary=f"Upstream catalog drift detected ({item_count} item(s), {disagreement_count} disagreement(s)).",
            details=details,
            remediation="Run ./scripts/sync-model-catalog --check or --apply to review and reconcile.",
        )
    return DoctorCheck(
        id="catalog_drift",
        status="pass",
        summary="Live upstream catalog check clean (0 drift items).",
        details=details,
    )


def run_doctor(
    *,
    root: Path = ROOT,
    cli_runs_dir: Path | None = None,
    cli_runs_stat: tuple[int, int] | None = None,
    env_runs_dir: Path | None = None,
    env_runs_stat: tuple[int, int] | None = None,
    check_catalog: bool = False,
    in_custody: bool = False,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    store = _resolve_doctor_store(
        root,
        cli_runs_dir=cli_runs_dir,
        cli_runs_stat=cli_runs_stat,
        env_runs_dir=env_runs_dir,
        env_runs_stat=env_runs_stat,
        in_custody=in_custody,
    )
    checks: list[DoctorCheck] = [
        check_platform_runtime(root),
        check_runs_store_and_pointer(store, in_custody=in_custody),
        check_se_key_proxy(root, env=env),
        check_attested_proxies(root),
        check_se_envelopes(root),
        check_bpf_permissions(),
        check_model_registry(root),
        check_live_sessions(root, store, in_custody=in_custody),
        check_legacy_containment(root, in_custody=in_custody, env=env),
        check_catalog_drift(root, enabled=check_catalog),
    ]
    counts = {"pass": 0, "warn": 0, "fail": 0, "skip": 0}
    for chk in checks:
        counts[chk.status] = counts.get(chk.status, 0) + 1
    if counts["fail"] > 0:
        overall = "fail"
    elif counts["warn"] > 0:
        overall = "warn"
    else:
        overall = "pass"
    return {
        "schema_version": DOCTOR_SCHEMA_VERSION,
        "platform": {
            "system": platform.system(),
            "machine": platform.machine(),
            "python": ".".join(str(x) for x in sys.version_info[:3]),
        },
        "overall": overall,
        "counts": counts,
        "checks": [chk.to_dict() for chk in checks],
    }


def format_doctor_report(report: dict[str, Any]) -> str:
    lines: list[str] = []
    plat = report.get("platform") or {}
    lines.append(
        f"free-inference doctor ({plat.get('system', '?')} {plat.get('machine', '?')}, "
        f"Python {plat.get('python', '?')}) -> {str(report.get('overall', 'fail')).upper()}"
    )
    for chk in report.get("checks", []):
        tag = str(chk.get("status", "fail")).upper().ljust(4)
        lines.append(f"  [{tag}] {chk.get('id')}: {chk.get('summary')}")
        rem = chk.get("remediation")
        if rem:
            lines.append(f"         Fix: {rem}")
    counts = report.get("counts") or {}
    lines.append(
        f"Summary: {counts.get('pass', 0)} pass, {counts.get('warn', 0)} warn, "
        f"{counts.get('fail', 0)} fail, {counts.get('skip', 0)} skip"
    )
    return "\n".join(lines)


def main(
    argv: list[str] | None = None,
    *,
    root: Path = ROOT,
    bootstrap_state: CustodyBootstrapState | None = None,
) -> int:
    parser = _SafeDoctorArgumentParser(
        description="Read-only health and security-posture audit for free-inference.",
        allow_abbrev=False,
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON report.")
    parser.add_argument("--strict", action="store_true", help="Exit 1 on warnings as well as failures.")
    parser.add_argument("--check-catalog", action="store_true", help="Opt-in live upstream catalog drift check.")
    parser.add_argument("--launcher-site-packages", default=None, help="Explicit custody dependency directory.")
    parser.add_argument("--runs-dir", default=None, help="Explicit non-custody session store directory.")
    try:
        args = parser.parse_args(argv)
    except _DoctorCliError:
        print("Invalid CLI arguments; run ./scripts/doctor --help for usage.", file=sys.stderr)
        return 1

    boot = bootstrap_state if bootstrap_state is not None else get_active_bootstrap_state()
    if boot is not None and boot.bootstrap_error is not None:
        _, safe_msg = sanitize_bootstrap_error(boot.bootstrap_error)
        print(safe_msg, file=sys.stderr)
        return 1

    in_custody = (boot is not None and boot.custody_mode) or is_custody_tree(root)
    cli_runs_dir = boot.cli_runs_dir if boot is not None else None
    cli_runs_stat = boot.cli_runs_stat if boot is not None else None
    env_runs_dir = boot.env_runs_dir if boot is not None else None
    env_runs_stat = boot.env_runs_stat if boot is not None else None

    if args.runs_dir is not None and cli_runs_dir is None:
        if in_custody:
            print("Refusing --runs-dir in read-only/custody mode.", file=sys.stderr)
            return 1
        v_cli, cli_err, _ = _walk_and_validate_runs_dir_detailed(
            args.runs_dir,
            require_existing=True,
            create=False,
            retain_fd=False,
            allow_tilde=False,
            label="--runs-dir",
            allow_code_root_ancestors=True,
        )
        if cli_err is not None or v_cli is None or v_cli.stat_id is None:
            print("--runs-dir is invalid, missing, or untrusted.", file=sys.stderr)
            return 1
        cli_runs_dir = v_cli.path
        cli_runs_stat = v_cli.stat_id

    report = run_doctor(
        root=root,
        cli_runs_dir=cli_runs_dir,
        cli_runs_stat=cli_runs_stat,
        env_runs_dir=env_runs_dir,
        env_runs_stat=env_runs_stat,
        check_catalog=bool(args.check_catalog),
        in_custody=in_custody,
    )
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(format_doctor_report(report))

    overall = report.get("overall")
    if overall == "fail":
        return 1
    if overall == "warn" and args.strict:
        return 1
    return 0
