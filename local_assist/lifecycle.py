from __future__ import annotations

import os
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
    read_pid_record_for_model,
    resolve_endpoint,
)
from .routing import MODEL_TO_REGISTRY_ID


SMOKE_SYSTEM = "You are a health-check responder. Follow the user instruction exactly."
SMOKE_PROMPT = "Return exactly OK."
DEFAULT_AUTO_SERVE_WAIT_SECONDS = 45.0


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
            if effective_auto_serve:
                load_model(registry_id)
            return
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
