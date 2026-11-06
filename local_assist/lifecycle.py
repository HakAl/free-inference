from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

from .client import chat, default_timeout_seconds, get_models
from .errors import LocalAssistError, ModelMismatch, ModelTimeout, ModelUnavailable
from .paths import ROOT
from .registry import (
    RegistryError,
    find_model_by_id_or_repo,
    load_model,
    pid_is_alive,
    pid_matches_record,
    read_pid_record_for_model,
    resolve_endpoint,
)
from .routing import MODEL_TO_REGISTRY_ID


SMOKE_SYSTEM = "You are a health-check responder. Follow the user instruction exactly."
SMOKE_PROMPT = "Return exactly OK."
DEFAULT_AUTO_SERVE_WAIT_SECONDS = 45.0
_PROC_PIDTBSDINFO = 3
_PROC_SZOMB = 5


class _ProcBsdInfo(ctypes.Structure):
    _fields_ = [
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16),
        ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    ]


def _sandbox_safe_pid_matches_lstart(pid: int, expected_lstart: str) -> bool:
    if not pid_is_alive(pid):
        return False
    expected_norm = " ".join(expected_lstart.strip().split())
    if not expected_norm:
        return False
    # Under macOS Seatbelt, /bin/ps is setuid-root and cannot be executed, so query
    # the kernel directly via libSystem proc_pidinfo(PROC_PIDTBSDINFO) (R2-MAJOR-2).
    if sys.platform == "darwin":
        try:
            libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
            info = _ProcBsdInfo()
            ret = libc.proc_pidinfo(
                int(pid),
                _PROC_PIDTBSDINFO,
                0,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            if ret == ctypes.sizeof(info):
                if info.pbi_status == _PROC_SZOMB:
                    return False
                actual_lstart = time.strftime(
                    "%a %b %e %H:%M:%S %Y",
                    time.gmtime(int(info.pbi_start_tvsec)),
                ).strip()
                actual_norm = " ".join(actual_lstart.split())
                return actual_norm == expected_norm
        except Exception:
            pass
    return pid_matches_record(pid, expected_lstart, require_lstart=True)


def _default_auto_serve_wait_seconds() -> float:
    raw = os.environ.get("LOCAL_ASSIST_AUTO_SERVE_WAIT_SECONDS")
    if raw is not None:
        try:
            val = float(raw)
            return max(1.0, val)
        except ValueError:
            pass
    overall = float(default_timeout_seconds())
    return min(DEFAULT_AUTO_SERVE_WAIT_SECONDS, max(5.0, overall - 15.0))


def _verify_worker_sandbox_handoff(real_id: str, endpoint: Any) -> bool:
    if (
        os.environ.get("LOCAL_ASSIST_WORKER_SANDBOX") != "1"
        or endpoint.trust_tier != "local"
        or endpoint.routing_private_local != "cleared"
    ):
        return False
    worker_id = os.environ.get("LOCAL_ASSIST_WORKER_ID", "").strip()
    handoff_raw = os.environ.get("LOCAL_ASSIST_VERIFIED_MODELS_FILE", "").strip()
    if not worker_id or not handoff_raw:
        return False
    handoff_path = Path(handoff_raw)
    if handoff_path.is_symlink() or not handoff_path.is_file():
        return False
    try:
        manifest = json.loads(handoff_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        return False
    if manifest.get("worker_id") != worker_id:
        return False
    expires_at = manifest.get("expires_at")
    if (
        isinstance(expires_at, bool)
        or not isinstance(expires_at, (int, float))
        or time.time() > float(expires_at)
    ):
        return False
    models_map = manifest.get("models")
    if not isinstance(models_map, dict):
        return False
    entry = models_map.get(real_id)
    if not isinstance(entry, dict):
        return False
    if (
        entry.get("model_id") != real_id
        or entry.get("served_model_id") != endpoint.served_model_id
        or entry.get("api_base_url") != endpoint.api_base_url
        or entry.get("hf_offline") is not True
    ):
        return False
    pid = entry.get("pid")
    pid_lstart = entry.get("pid_lstart")
    if (
        isinstance(pid, bool)
        or not isinstance(pid, int)
        or pid <= 1
        or not isinstance(pid_lstart, str)
        or not pid_lstart.strip()
    ):
        return False
    return _sandbox_safe_pid_matches_lstart(pid, pid_lstart)


def _is_sandbox_unverifiable_verify_result(returncode: int, detail: str) -> bool:
    if returncode == 1:
        return True
    if returncode != 3:
        return False
    # Exit code 3 is only eligible for the worker sandbox handoff when verify-served-model
    # failed solely because runs/ PID records or lsof/ps listener inspection were blocked
    # by Seatbelt, never when a positive model or offline mismatch was observed (R3-MAJOR-2).
    if "served model mismatch" in detail or "was started with --allow-hf-online" in detail:
        return False
    return (
        "has no active PID record confirming offline startup" in detail
        or "could not identify any OS listener process via lsof/ps" in detail
    )


def ensure_local_model_served(
    model: str,
    *,
    auto_serve: bool | None = None,
    wait_seconds: float | None = None,
    deadline: float | None = None,
    run_cmd: Any = None,
) -> None:
    runner = run_cmd or subprocess.run
    effective_auto_serve = (
        auto_serve
        if auto_serve is not None
        else (os.environ.get("LOCAL_ASSIST_AUTO_SERVE") == "1")
    )
    registry_id = MODEL_TO_REGISTRY_ID.get(model, model)

    try:
        entry = find_model_by_id_or_repo(registry_id) or find_model_by_id_or_repo(model)
        if entry is None:
            raise ModelUnavailable(
                "model_unavailable",
                f"Model '{model}' (registry_id='{registry_id}') is not present in models.yaml.",
                details={"required_model": model, "registry_id": registry_id},
            )
        real_id = str(entry["id"])
        pid_record = read_pid_record_for_model(real_id)
        endpoint = resolve_endpoint(entry, pid_record=pid_record, require_api_key=False)
    except RegistryError as exc:
        raise LocalAssistError(
            "registry_error",
            str(exc),
            details={"model": model, "registry_id": registry_id},
        ) from exc

    verify_script = str(ROOT / "scripts" / "verify-served-model")
    serve_script = str(ROOT / "scripts" / "serve-model")

    def _rem(cap: float) -> float:
        if deadline is None:
            return cap
        rem = deadline - time.monotonic()
        if rem <= 0:
            raise ModelTimeout(
                "timeout",
                f"Timed out waiting for local model '{real_id}' before deadline.",
                details={"model_id": real_id},
            )
        return min(cap, max(1.0, rem))

    check_proc = runner(
        [sys.executable, verify_script, real_id, "--require-offline"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=max(1, int(_rem(10.0))),
        check=False,
    )
    if check_proc.returncode == 0:
        return

    check_detail = (check_proc.stderr or check_proc.stdout or "").strip()
    if (
        _is_sandbox_unverifiable_verify_result(check_proc.returncode, check_detail)
        and _verify_worker_sandbox_handoff(real_id, endpoint)
    ):
        try:
            available = get_models(timeout_seconds=max(1, int(_rem(5.0))), model=model)
        except LocalAssistError:
            available = []
        if model in available or real_id in available or endpoint.served_model_id in available:
            return

    if check_proc.returncode == 3:
        raise ModelMismatch(
            "model_mismatch",
            f"Refusing to use {endpoint.api_base_url} for '{real_id}': another model is occupying the port ({check_detail}).",
            details={
                "required_model": model,
                "registry_id": real_id,
                "api_base_url": endpoint.api_base_url,
                "verify_error": check_detail,
            },
        )

    if not effective_auto_serve:
        raise ModelUnavailable(
            "model_unavailable",
            f"Required local model '{real_id}' is not currently served at {endpoint.api_base_url} ({check_detail}).",
            details={
                "required_model": model,
                "registry_id": real_id,
                "api_base_url": endpoint.api_base_url,
                "remediation": (
                    f"Run: ./scripts/serve-model {real_id} "
                    "(or pass --auto-serve / set LOCAL_ASSIST_AUTO_SERVE=1)"
                ),
            },
        )

    if endpoint.trust_tier != "local":
        raise LocalAssistError(
            "trust_tier_blocked",
            f"Refusing auto-serve for non-local model '{real_id}' with trust_tier='{endpoint.trust_tier}'.",
            details={"model_id": real_id, "trust_tier": endpoint.trust_tier},
        )
    if endpoint.routing_private_local != "cleared":
        raise LocalAssistError(
            "routing_gate_blocked",
            f"Refusing auto-serve for model '{real_id}' because routing.private_local is "
            f"'{endpoint.routing_private_local}' (must be 'cleared').",
            details={
                "model_id": real_id,
                "routing_private_local": endpoint.routing_private_local,
            },
        )

    effective_wait = (
        wait_seconds
        if wait_seconds is not None
        else _rem(_default_auto_serve_wait_seconds())
    )
    print(
        f"[local-assist] auto-starting Rung 1 model '{real_id}' on {endpoint.api_base_url} ...",
        file=sys.stderr,
    )
    serve_proc = runner(
        [sys.executable, serve_script, real_id, "--started-by", "auto-serve"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=max(1, int(_rem(30.0))),
        check=False,
    )
    serve_detail = (serve_proc.stderr or serve_proc.stdout or "").strip()
    if serve_proc.returncode == 3:
        raise ModelMismatch(
            "model_mismatch",
            f"Refusing auto-serve for '{real_id}': {serve_detail}",
            details={"required_model": model, "registry_id": real_id, "serve_error": serve_detail},
        )
    if serve_proc.returncode != 0:
        raise ModelUnavailable(
            "model_unavailable",
            f"scripts/serve-model failed for '{real_id}' (exit {serve_proc.returncode}): {serve_detail}",
            details={"required_model": model, "registry_id": real_id, "serve_error": serve_detail},
        )

    wait_budget = _rem(effective_wait)
    wait_proc = runner(
        [sys.executable, verify_script, real_id, "--wait", str(wait_budget), "--require-offline"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=max(5, int(wait_budget) + 5),
        check=False,
    )
    wait_detail = (wait_proc.stderr or wait_proc.stdout or "").strip()
    if wait_proc.returncode == 3:
        raise ModelMismatch(
            "model_mismatch",
            f"Model mismatch at {endpoint.api_base_url} after auto-start ({wait_detail}).",
            details={"required_model": model, "registry_id": real_id, "verify_error": wait_detail},
        )
    if wait_proc.returncode != 0:
        raise ModelUnavailable(
            "model_unavailable",
            f"Model '{real_id}' did not become ready within {wait_budget}s: {wait_detail}",
            details={"required_model": model, "registry_id": real_id, "verify_error": wait_detail},
        )


def require_chat_succeeds(model: str, *, deadline: float | None = None) -> str:
    effective_deadline = (
        deadline
        if deadline is not None
        else (time.monotonic() + float(default_timeout_seconds()))
    )
    ensure_local_model_served(model, deadline=effective_deadline)
    rem_models = max(1, int(min(5.0, effective_deadline - time.monotonic())))
    available = get_models(timeout_seconds=rem_models, model=model)
    if model not in available:
        registry_id = MODEL_TO_REGISTRY_ID.get(model, model)
        raise ModelUnavailable(
            "model_unavailable",
            f"Required model is not available: {model}.",
            details={
                "required_model": model,
                "available_models": available,
                "remediation": f"Run: scripts/serve-model {registry_id}",
            },
        )

    rem_smoke = effective_deadline - time.monotonic()
    if rem_smoke <= 0:
        raise ModelTimeout(
            "timeout",
            f"Timed out before smoke health-check for {model}.",
            details={"model": model},
        )
    result = chat(
        model,
        SMOKE_SYSTEM,
        SMOKE_PROMPT,
        max_tokens=8,
        temperature=0,
        timeout_seconds=max(1, int(min(30.0, rem_smoke))),
    )
    if result.served_model != model:
        raise ModelMismatch(
            "model_mismatch",
            "Requested model and served model differed.",
            details={"requested_model": model, "served_model": result.served_model},
        )
    return result.served_model
