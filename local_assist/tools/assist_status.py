from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, TypedDict
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request

from .. import __version__
from ..client import _RESERVED_NON_LOCAL_PORTS, open_loopback_http
from ..lifecycle import _sandbox_safe_pid_matches_lstart, _verify_worker_sandbox_handoff
from ..registry import (
    LOCAL_HOSTS,
    RegistryError,
    _effective_runs_dir,
    find_model_by_id_or_repo,
    list_pid_records,
    pid_is_alive,
    read_pid_record_for_model,
    resolve_endpoint,
)
from ..routing import JOB_TO_MODEL, MODEL_TO_REGISTRY_ID
from ..workspace import resolve_workspace_root


JOB = "assist_status"

ADVERTISED_TOOLS = (
    "propose_eval_prompts",
    "extract_fields",
    "compress_context",
    "delegate_task",
    "assist_status",
    "check_eval_assertion",
    "select_context",
)


class AssistStatusResult(TypedDict):
    server: dict[str, Any]
    rung1_local: dict[str, Any]
    active_sessions: list[dict[str, Any]]


def _resolve_runs_dir() -> Path:
    raw = os.environ.get("LOCAL_ASSIST_RUNS_DIR", "").strip()
    if raw:
        return Path(raw).resolve()
    return _effective_runs_dir()


def _pid_record_active(record: dict[str, Any]) -> bool:
    pid = record.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
        return False
    expected_lstart = record.get("pid_lstart")
    if isinstance(expected_lstart, str) and expected_lstart.strip():
        return _sandbox_safe_pid_matches_lstart(pid, expected_lstart)
    return pid_is_alive(pid)


def _sanitize_int(val: Any) -> int | None:
    if isinstance(val, int) and not isinstance(val, bool) and val >= 0:
        return val
    return None


def _sanitize_short_str(val: Any, *, max_len: int = 80) -> str | None:
    if not isinstance(val, str):
        return None
    clean = " ".join(val.strip().split())
    if not clean:
        return None
    return clean[:max_len]


def _handoff_port_override(real_id: str) -> dict[str, int] | None:
    if os.environ.get("LOCAL_ASSIST_WORKER_SANDBOX") != "1":
        return None
    handoff_raw = os.environ.get("LOCAL_ASSIST_VERIFIED_MODELS_FILE", "").strip()
    if not handoff_raw:
        return None
    handoff_path = Path(handoff_raw)
    if handoff_path.is_symlink() or not handoff_path.is_file():
        return None
    try:
        manifest = json.loads(handoff_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(manifest, dict):
        return None
    models_map = manifest.get("models")
    if not isinstance(models_map, dict):
        return None
    entry = models_map.get(real_id)
    if not isinstance(entry, dict):
        return None
    raw_url = entry.get("api_base_url")
    if not isinstance(raw_url, str) or not raw_url.strip():
        return None
    parsed = urlparse(raw_url.strip())
    if (
        (parsed.scheme or "").lower() not in ("http", "https")
        or (parsed.hostname or "").lower() not in LOCAL_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is None
    ):
        return None
    port = int(parsed.port)
    if port < 1024 or port > 65535 or port in _RESERVED_NON_LOCAL_PORTS:
        return None
    return {"port": port}


def _probe_rung1_models_unauthenticated(
    api_base_url: str,
    *,
    timeout_seconds: float = 1.0,
) -> list[str]:
    parsed = urlparse(api_base_url.strip())
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    if (
        scheme not in ("http", "https")
        or host not in LOCAL_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or (parsed.port is not None and parsed.port in _RESERVED_NON_LOCAL_PORTS)
    ):
        return []
    models_url = f"{api_base_url.strip().rstrip('/')}/models"
    req = Request(
        models_url,
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with open_loopback_http(req, timeout=timeout_seconds) as resp:
            raw = resp.read(65_536).decode("utf-8", errors="replace")
        payload = json.loads(raw)
    except (HTTPError, URLError, OSError, TimeoutError, json.JSONDecodeError):
        return []
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if not isinstance(data, list):
        return []
    return [
        item["id"]
        for item in data
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    ]


def run() -> AssistStatusResult:
    """Return side-effect-free, credential-free local_assist readiness and endpoint metadata."""
    runs_dir = _resolve_runs_dir()
    ws_root = resolve_workspace_root()
    default_served_id = JOB_TO_MODEL["delegate_task"]
    registry_id = MODEL_TO_REGISTRY_ID.get(default_served_id, default_served_id)

    rung1_info: dict[str, Any] = {
        "registry_id": registry_id,
        "served_model_id": default_served_id,
        "data_control_rung": 1,
        "trust_tier": "local",
        "usage_policy": "unrestricted_local",
        "api_base_url": "http://127.0.0.1:8080/v1",
        "routing_private_local": None,
        "pid_alive": False,
        "offline_verified": False,
        "live_served": False,
    }

    try:
        entry = find_model_by_id_or_repo(registry_id) or find_model_by_id_or_repo(default_served_id)
        if entry is not None:
            real_id = str(entry["id"])
            pid_rec = read_pid_record_for_model(real_id, runs_dir=runs_dir)
            pid_rec_public: dict[str, Any] | None = None
            if isinstance(pid_rec, dict):
                pid_rec_public = {
                    k: v for k, v in pid_rec.items() if k != "session_token_file"
                }
            else:
                pid_rec_public = _handoff_port_override(real_id)
            endpoint = resolve_endpoint(entry, pid_record=pid_rec_public, require_api_key=False)
            pid_alive = _pid_record_active(pid_rec) if isinstance(pid_rec, dict) else False
            offline_ok = bool(
                (pid_alive and isinstance(pid_rec, dict) and pid_rec.get("hf_offline") is True)
                or _verify_worker_sandbox_handoff(real_id, endpoint)
            )
            probe_url = endpoint.api_base_url
            env_base = os.environ.get("LOCAL_ASSIST_BASE_URL", "").strip()
            if env_base:
                probe_url = env_base.rstrip("/")
            available = (
                _probe_rung1_models_unauthenticated(probe_url, timeout_seconds=1.0)
                if endpoint.trust_tier == "local"
                else []
            )
            live_served = (
                default_served_id in available
                or real_id in available
                or endpoint.served_model_id in available
            )
            rung1_info.update(
                {
                    "registry_id": real_id,
                    "served_model_id": endpoint.served_model_id,
                    "data_control_rung": endpoint.data_control_rung,
                    "trust_tier": endpoint.trust_tier,
                    "usage_policy": endpoint.usage_policy,
                    "api_base_url": endpoint.api_base_url,
                    "routing_private_local": endpoint.routing_private_local,
                    "pid_alive": pid_alive,
                    "offline_verified": offline_ok,
                    "live_served": live_served,
                }
            )
    except RegistryError:
        pass

    active_sessions: list[dict[str, Any]] = []
    seen_session_keys: set[tuple[str, int | None, int | None]] = set()
    for _, rec in list_pid_records(runs_dir):
        if not _pid_record_active(rec):
            continue
        model_id = _sanitize_short_str(rec.get("model_id"), max_len=120)
        if not model_id:
            continue
        rec_pid = _sanitize_int(rec.get("pid"))
        rec_port = _sanitize_int(rec.get("port"))
        dedup_key = (model_id, rec_pid, rec_port)
        if dedup_key in seen_session_keys:
            continue
        seen_session_keys.add(dedup_key)
        trust_tier: str | None = None
        rung_num: int | None = None
        usage_policy: str | None = None
        try:
            m_entry = find_model_by_id_or_repo(model_id)
            if m_entry is not None:
                ep = resolve_endpoint(m_entry, pid_record=None, require_api_key=False)
                trust_tier = ep.trust_tier
                rung_num = ep.data_control_rung
                usage_policy = ep.usage_policy
        except RegistryError:
            pass

        has_tok_ref = bool(
            isinstance(rec.get("session_token_file"), str) and rec["session_token_file"].strip()
        )
        active_sessions.append(
            {
                "model_id": model_id,
                "trust_tier": trust_tier,
                "data_control_rung": rung_num,
                "usage_policy": usage_policy,
                "port": _sanitize_int(rec.get("port")),
                "pid_alive": True,
                "started_at": _sanitize_short_str(rec.get("started_at"), max_len=64),
                "ttl_seconds": _sanitize_int(rec.get("ttl_seconds")),
                "max_chat_requests": _sanitize_int(rec.get("max_chat_requests")),
                "session_token_managed": has_tok_ref,
            }
        )

    return {
        "server": {
            "name": "local-assist-server",
            "version": __version__,
            "auto_serve_enabled": os.environ.get("LOCAL_ASSIST_AUTO_SERVE") == "1",
            "worker_sandbox_mode": os.environ.get("LOCAL_ASSIST_WORKER_SANDBOX") == "1",
            "workspace_root": str(ws_root),
            "tools": list(ADVERTISED_TOOLS),
        },
        "rung1_local": rung1_info,
        "active_sessions": active_sessions,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Side-effect-free, credential-free status check for local_assist and active local/proxy endpoints."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=True,
        help="Emit machine-readable JSON output (default).",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output (default).",
    )
    parser.parse_args(argv)
    payload = run()
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
