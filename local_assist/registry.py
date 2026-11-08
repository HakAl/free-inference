from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ._miniyaml import safe_dump, safe_load


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODELS_PATH = ROOT / "models.yaml"
DEFAULT_RUNS_DIR = ROOT / "runs"
DEFAULT_BASE_URL = "http://127.0.0.1:8080/v1"
DEFAULT_API_KEY = "none"
KEYCHAIN_PLACEHOLDER_KEY = "se-keychain-managed"
SESSION_TOKEN_ENV_VAR = "LOCAL_ASSIST_SESSION_TOKEN"
BASE_SAFE_ENV_ALLOWLIST = frozenset({
    "PATH",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "TERM",
    "SYSTEMROOT",
})
LAUNCHER_EXTRA_ENV_ALLOWLIST = frozenset({
    "COLORTERM",
    "SSH_AUTH_SOCK",
    "EDITOR",
    "VISUAL",
})
DEFAULT_EOS_TRANSFORM = (
    "typeof output === 'string' ? output.replace(/<\\|im_end\\|>\\s*$/g, '').trim() : output"
)

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
LOCAL_RUNTIMES = {"mlx-lm", "mlx-vlm", "vllm-mlx", "omlx", "llama.cpp", "ollama"}
REMOTE_OR_PROXY_RUNTIMES = {"proxy", "remote"}
VALID_RUNTIMES = LOCAL_RUNTIMES | REMOTE_OR_PROXY_RUNTIMES

DATA_CONTROL_RUNGS = (
    "local",
    "enclave_weights_attested",
    "enclave_runtime_attested",
    "zdr_contract",
    "standard_api",
)
LEGACY_TIER_ALIASES = {
    "attested_tee": "enclave_runtime_attested",
    "zero_data_retention": "zdr_contract",
}
VALID_TRUST_TIERS = set(DATA_CONTROL_RUNGS) | set(LEGACY_TIER_ALIASES)
ATTESTED_ENCLAVE_TIERS = {"enclave_weights_attested", "enclave_runtime_attested"}

VALID_USAGE_POLICIES = {
    "unrestricted_local",
    "enclave_no_inspection",
    "provider_filtered",
    "provider_terms_apply",
    "unknown",
}
VALID_ROUTING_CLEARANCES = {"cleared", "blocked"}
VALID_MODEL_STATUSES = {"active", "runnable", "reviewed", "candidate", "archived"}
WEIGHTS_HASH_RE = re.compile(r"^(?:dmverity:)?sha256:[0-9a-f]{64}$")
WEIGHTS_SOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}@[0-9a-f]{40}$")
ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def is_model_effectively_deprecated(
    deprecated: bool,
    deprecation_date: str | date | None,
    *,
    today: date | None = None,
) -> bool:
    if deprecated is True:
        return True
    if deprecation_date is None:
        return False
    if isinstance(deprecation_date, date) and not isinstance(deprecation_date, datetime):
        parsed_date = deprecation_date
    elif isinstance(deprecation_date, str):
        clean_str = deprecation_date.strip()
        if not ISO_DATE_RE.match(clean_str):
            return False
        try:
            parsed_date = date.fromisoformat(clean_str)
        except ValueError:
            return False
    else:
        return False
    ref_today = today or datetime.now(timezone.utc).date()
    return parsed_date <= ref_today
KEYCHAIN_SERVICE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


class RegistryError(Exception):
    """Raised when a model registry entry or endpoint configuration is invalid."""


@dataclass(frozen=True)
class EndpointConfig:
    model_id: str
    served_model_id: str
    provider_id: str
    api_base_url: str
    host: str
    port: int | None
    api_key: str
    api_key_envar: str | None
    runtime: str
    trust_tier: str
    attestation_method: str | None
    is_local_host: bool
    weights_hash: str | None = None
    weights_source: str | None = None
    weights_verified_by: str | None = None
    weights_verified_date: str | None = None
    weights_verification_artifact: str | None = None
    usage_policy: str = "unrestricted_local"
    capabilities: dict[str, Any] = field(default_factory=dict)
    routing_private_local: str | None = None
    routing_private_attested: str = "blocked"
    api_key_keychain_service: str | None = None
    upstream_base_url: str | None = None
    pricing_per_m_tokens: dict[str, float] | None = None
    context_window: int | None = None
    eval_evidence_artifact: str | None = None
    status: str = "candidate"
    deprecated: bool = False
    deprecation_date: str | None = None

    @property
    def data_control_rung(self) -> int:
        canonical = LEGACY_TIER_ALIASES.get(self.trust_tier, self.trust_tier)
        if canonical not in DATA_CONTROL_RUNGS:
            raise RegistryError(f"Unknown trust_tier '{self.trust_tier}'")
        return DATA_CONTROL_RUNGS.index(canonical) + 1


def format_host_for_url(host: str) -> str:
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        return f"[{host}]"
    return host


def build_base_url(host: str, port: int, scheme: str = "http") -> str:
    return f"{scheme}://{format_host_for_url(host)}:{port}/v1"


def canonical_endpoint_key(url: str) -> tuple[str, str, int, str]:
    parsed = urlparse(url.rstrip("/"))
    scheme = (parsed.scheme or "http").lower()
    raw_host = (parsed.hostname or "127.0.0.1").lower()
    host = "127.0.0.1" if raw_host in ("localhost", "127.0.0.1") else raw_host
    try:
        port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise RegistryError(f"Invalid port in URL '{url}': {exc}") from exc
    path = parsed.path.rstrip("/") or "/v1"
    return (scheme, host, port, path)


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise RegistryError(f"models.yaml not found at {path}")
    try:
        data = safe_load(path.read_text()) or {}
    except Exception as exc:
        raise RegistryError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RegistryError(f"Expected mapping at top of {path}")
    return data


def load_models(models_path: Path | None = None) -> list[dict[str, Any]]:
    path = models_path or DEFAULT_MODELS_PATH
    data = _load_yaml(path)
    models = data.get("models", [])
    if not isinstance(models, list):
        raise RegistryError(f"Expected 'models' list in {path}")
    return [m for m in models if isinstance(m, dict)]


def load_model(model_id: str, models_path: Path | None = None) -> dict[str, Any]:
    for model in load_models(models_path):
        if model.get("id") == model_id:
            return model
    raise RegistryError(f"Model not found in models.yaml: {model_id}")


def find_model_by_id_or_repo(identifier: str, models_path: Path | None = None) -> dict[str, Any] | None:
    try:
        models = load_models(models_path)
    except RegistryError:
        return None
    for model in models:
        if model.get("id") == identifier:
            return model
    matches = [m for m in models if m.get("repo") == identifier]
    if len(matches) == 1:
        return matches[0]
    for m in matches:
        if (m.get("runtime") or "mlx-lm") in LOCAL_RUNTIMES:
            return m
    return matches[0] if matches else None


# Keep alias for backwards compatibility
find_model_by_Id_or_repo = find_model_by_id_or_repo


def _is_valid_committed_artifact_path(rel_path: str) -> bool:
    if not rel_path or rel_path.startswith(("/", "\\", "~")):
        return False
    norm = rel_path.replace("\\", "/")
    parts = [p for p in norm.split("/") if p]
    if len(parts) < 3 or any(p in (".", "..") or p.startswith(".") for p in parts):
        return False
    if parts[:2] != ["docs", "attestations"]:
        return False
    return True


def _is_valid_committed_eval_artifact_path(
    rel_path: str,
    *,
    model_id: str | None = None,
    require_exists: bool = True,
) -> bool:
    if not rel_path or rel_path.startswith(("/", "\\", "~")):
        return False
    norm = rel_path.replace("\\", "/")
    parts = [p for p in norm.split("/") if p]
    if len(parts) != 3 or any(p in (".", "..") or p.startswith(".") for p in parts):
        return False
    if parts[:2] != ["docs", "evals"] or not parts[2].endswith(".json"):
        return False
    if model_id is not None and parts[2] != f"{model_id}.json":
        return False
    if require_exists:
        full_path = ROOT / norm
        if not full_path.is_file():
            return False
        try:
            manifest_obj = json.loads(full_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        if not isinstance(manifest_obj, dict):
            return False
        if model_id is not None and manifest_obj.get("model_id") != model_id:
            return False
    return True


def _validate_trust_config(
    model_id: str,
    runtime: str,
    is_local_host: bool,
    remote_trust: Any,
) -> tuple[str, str | None, str | None, str | None, str | None, str | None, str | None, str]:
    if runtime not in VALID_RUNTIMES:
        raise RegistryError(
            f"Model {model_id}: unsupported runtime '{runtime}'. Must be one of {sorted(VALID_RUNTIMES)}."
        )

    if runtime in REMOTE_OR_PROXY_RUNTIMES:
        if not isinstance(remote_trust, dict) or not remote_trust:
            raise RegistryError(
                f"Model {model_id}: runtime='{runtime}' requires a non-empty 'remote_trust' mapping in models.yaml."
            )
        if "data_control" in remote_trust:
            raise RegistryError(
                f"Model {model_id}: use 'remote_trust.tier' (not 'data_control') to specify the data-control rung."
            )
        raw_tier = remote_trust.get("tier")
        if not isinstance(raw_tier, str) or raw_tier not in VALID_TRUST_TIERS:
            raise RegistryError(
                f"Model {model_id}: invalid remote_trust.tier '{raw_tier}'. "
                f"Must be one of {list(DATA_CONTROL_RUNGS[1:])} (or legacy aliases {sorted(LEGACY_TIER_ALIASES)})."
            )
        tier = LEGACY_TIER_ALIASES.get(raw_tier, raw_tier)
        if tier == "local":
            raise RegistryError(
                f"Model {model_id}: runtime='{runtime}' cannot claim remote_trust.tier='local'."
            )
        raw_attestation = remote_trust.get("attestation_method")
        attestation_method = (
            str(raw_attestation).strip() if isinstance(raw_attestation, str) and raw_attestation.strip() else None
        )
        raw_weights_hash = remote_trust.get("weights_hash")
        weights_hash = (
            str(raw_weights_hash).strip() if isinstance(raw_weights_hash, str) and raw_weights_hash.strip() else None
        )
        raw_weights_source = remote_trust.get("weights_source")
        weights_source = (
            str(raw_weights_source).strip() if isinstance(raw_weights_source, str) and raw_weights_source.strip() else None
        )
        raw_verified_by = remote_trust.get("weights_verified_by")
        weights_verified_by = (
            str(raw_verified_by).strip() if isinstance(raw_verified_by, str) and raw_verified_by.strip() else None
        )
        raw_verified_date = remote_trust.get("weights_verified_date")
        if isinstance(raw_verified_date, date) and not isinstance(raw_verified_date, datetime):
            weights_verified_date: str | None = raw_verified_date.isoformat()
        elif isinstance(raw_verified_date, str) and raw_verified_date.strip():
            weights_verified_date = raw_verified_date.strip()
        else:
            weights_verified_date = None

        raw_artifact = remote_trust.get("weights_verification_artifact")
        weights_verification_artifact = (
            str(raw_artifact).strip() if isinstance(raw_artifact, str) and raw_artifact.strip() else None
        )

        raw_policy = remote_trust.get("usage_policy")
        usage_policy = (
            str(raw_policy).strip()
            if isinstance(raw_policy, str) and raw_policy.strip()
            else "unknown"
        )
        if usage_policy not in VALID_USAGE_POLICIES:
            raise RegistryError(
                f"Model {model_id}: invalid remote_trust.usage_policy '{usage_policy}'. "
                f"Must be one of {sorted(VALID_USAGE_POLICIES)}."
            )
        if usage_policy == "unrestricted_local":
            raise RegistryError(
                f"Model {model_id}: remote_trust.usage_policy='unrestricted_local' is reserved for Rung 1 (local)."
            )
        if usage_policy == "enclave_no_inspection" and tier not in ATTESTED_ENCLAVE_TIERS:
            raise RegistryError(
                f"Model {model_id}: remote_trust.usage_policy='enclave_no_inspection' requires an attested enclave tier."
            )

        if tier in ATTESTED_ENCLAVE_TIERS:
            if not attestation_method:
                raise RegistryError(
                    f"Model {model_id}: remote_trust.tier='{tier}' requires a non-empty 'attestation_method'."
                )
            if runtime != "proxy" or not is_local_host:
                raise RegistryError(
                    f"Model {model_id}: remote_trust.tier='{tier}' requires runtime='proxy' bound to a localhost apiBaseUrl."
                )
            if tier == "enclave_weights_attested":
                if not weights_hash or not WEIGHTS_HASH_RE.match(weights_hash):
                    raise RegistryError(
                        f"Model {model_id}: remote_trust.tier='enclave_weights_attested' requires a 64-hex SHA-256 "
                        "'weights_hash' matching '[dmverity:]sha256:<64-hex>'. Use 'enclave_runtime_attested' when only the enclave runtime/manifest is attested."
                    )
                if not weights_source or not WEIGHTS_SOURCE_RE.match(weights_source):
                    raise RegistryError(
                        f"Model {model_id}: remote_trust.tier='enclave_weights_attested' requires 'weights_source' "
                        "pinned as '<org>/<repo>@<40-char-commit-sha>'."
                    )
                if not weights_verified_by:
                    raise RegistryError(
                        f"Model {model_id}: remote_trust.tier='enclave_weights_attested' requires non-empty "
                        "'weights_verified_by' (e.g. 'modelwrap --verify')."
                    )
                if not weights_verified_date or not ISO_DATE_RE.match(weights_verified_date):
                    raise RegistryError(
                        f"Model {model_id}: remote_trust.tier='enclave_weights_attested' requires "
                        "'weights_verified_date' in YYYY-MM-DD format."
                    )
                try:
                    date.fromisoformat(weights_verified_date)
                except ValueError as exc:
                    raise RegistryError(
                        f"Model {model_id}: remote_trust.tier='enclave_weights_attested' has invalid calendar date "
                        f"'{weights_verified_date}' for 'weights_verified_date'."
                    ) from exc
                if not weights_verification_artifact or not _is_valid_committed_artifact_path(
                    weights_verification_artifact
                ):
                    raise RegistryError(
                        f"Model {model_id}: remote_trust.tier='enclave_weights_attested' requires "
                        "'weights_verification_artifact' as a committed relative path under 'docs/attestations/'."
                    )
        if tier != "enclave_weights_attested" and any(
            (
                weights_hash,
                weights_source,
                weights_verified_by,
                weights_verified_date,
                weights_verification_artifact,
            )
        ):
            raise RegistryError(
                f"Model {model_id}: remote_trust.tier='{tier}' must not set Rung 2 weight-attestation "
                "fields (weights_hash, weights_source, weights_verified_by, weights_verified_date, "
                "weights_verification_artifact); use provider_manifest_weights_hash / "
                "provider_manifest_weights_source for unverified provider manifest claims."
            )
        return (
            tier,
            attestation_method,
            weights_hash,
            weights_source,
            weights_verified_by,
            weights_verified_date,
            weights_verification_artifact,
            usage_policy,
        )

    # Local runtime
    if not is_local_host:
        raise RegistryError(
            f"Model {model_id}: local runtime '{runtime}' must use a localhost apiBaseUrl."
        )
    usage_policy = "unrestricted_local"
    if remote_trust is not None:
        if not isinstance(remote_trust, dict):
            raise RegistryError(f"Model {model_id}: remote_trust must be null or a mapping.")
        if "data_control" in remote_trust:
            raise RegistryError(
                f"Model {model_id}: use 'remote_trust.tier' (not 'data_control') to specify the data-control rung."
            )
        tier = remote_trust.get("tier")
        if tier is not None and tier != "local":
            raise RegistryError(
                f"Model {model_id}: local runtime '{runtime}' cannot set remote_trust.tier='{tier}'."
            )
        if isinstance(remote_trust.get("usage_policy"), str) and remote_trust["usage_policy"].strip():
            usage_policy = remote_trust["usage_policy"].strip()
            if usage_policy not in ("unrestricted_local", "unknown"):
                raise RegistryError(
                    f"Model {model_id}: local runtime '{runtime}' cannot set remote_trust.usage_policy='{usage_policy}'."
                )
    return "local", None, None, None, None, None, None, usage_policy


def _validate_https_upstream_url(model_id: str, upstream_url: str) -> str:
    cleaned = upstream_url.strip().rstrip("/")
    parsed = urlparse(cleaned)
    if (parsed.scheme or "").lower() != "https":
        raise RegistryError(
            f"Model {model_id}: promptfoo_provider.upstreamBaseUrl must use scheme 'https'."
        )
    if parsed.username is not None or parsed.password is not None:
        raise RegistryError(
            f"Model {model_id}: promptfoo_provider.upstreamBaseUrl must not contain userinfo credentials."
        )
    if parsed.port is not None and parsed.port != 443:
        raise RegistryError(
            f"Model {model_id}: promptfoo_provider.upstreamBaseUrl must use default HTTPS port 443 (got port {parsed.port})."
        )
    hostname = (parsed.hostname or "").strip().lower()
    if (
        not hostname
        or hostname.startswith(".")
        or hostname.endswith(".")
        or hostname in LOCAL_HOSTS
        or hostname.endswith((".local", ".localhost"))
    ):
        raise RegistryError(
            f"Model {model_id}: promptfoo_provider.upstreamBaseUrl host '{hostname}' must be a public hostname."
        )
    try:
        ip_obj = ipaddress.ip_address(hostname)
    except ValueError:
        ip_obj = None
    if ip_obj is not None:
        if (
            ip_obj.is_loopback
            or ip_obj.is_private
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
            or not ip_obj.is_global
        ):
            raise RegistryError(
                f"Model {model_id}: promptfoo_provider.upstreamBaseUrl IP '{hostname}' must not be loopback, private, or reserved."
            )
    else:
        labels = hostname.split(".")
        if len(labels) < 2 or any(not lbl for lbl in labels):
            raise RegistryError(
                f"Model {model_id}: promptfoo_provider.upstreamBaseUrl host '{hostname}' must be a qualified public hostname."
            )
        all_numeric_or_hex = all(
            (lbl.startswith("0x") and len(lbl) > 2 and all(c in "0123456789abcdef" for c in lbl[2:]))
            or lbl.isdigit()
            for lbl in labels
        )
        if all_numeric_or_hex:
            raise RegistryError(
                f"Model {model_id}: promptfoo_provider.upstreamBaseUrl host '{hostname}' must not use numeric/hex IPv4 shorthand."
            )
    return cleaned


def resolve_endpoint(
    model: dict[str, Any],
    *,
    pid_record: dict[str, Any] | None = None,
    require_api_key: bool = True,
    require_eval_evidence_file: bool = True,
) -> EndpointConfig:
    model_id = str(model.get("id") or "").strip()
    if not model_id:
        raise RegistryError("Model entry is missing 'id'")

    served_model_id = str(model.get("repo") or model_id)
    runtime = str(model.get("runtime") or "mlx-lm")
    provider = model.get("promptfoo_provider") or {}
    if not isinstance(provider, dict):
        raise RegistryError(f"Model {model_id}: promptfoo_provider must be a mapping")

    provider_id = str(provider.get("id") or f"openai:chat:{served_model_id}")

    configured_url = provider.get("apiBaseUrl")
    if configured_url:
        api_base_url = str(configured_url).rstrip("/")
        if (
            isinstance(pid_record, dict)
            and pid_record.get("model_id") == model_id
            and isinstance(pid_record.get("port"), int)
            and not isinstance(pid_record.get("port"), bool)
        ):
            cfg_parsed = urlparse(api_base_url)
            cfg_host = cfg_parsed.hostname or "127.0.0.1"
            if cfg_host in LOCAL_HOSTS:
                api_base_url = build_base_url(
                    cfg_host, pid_record["port"], scheme=(cfg_parsed.scheme or "http").lower()
                )
    elif pid_record and isinstance(pid_record.get("port"), int) and not isinstance(pid_record.get("port"), bool):
        api_base_url = build_base_url("127.0.0.1", pid_record["port"])
    else:
        api_base_url = DEFAULT_BASE_URL

    parsed = urlparse(api_base_url)
    scheme = (parsed.scheme or "http").lower()
    host = parsed.hostname or "127.0.0.1"
    try:
        port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise RegistryError(f"Model {model_id}: invalid port in apiBaseUrl '{api_base_url}': {exc}") from exc
    is_local_host = host in LOCAL_HOSTS

    (
        trust_tier,
        attestation_method,
        weights_hash,
        weights_source,
        weights_verified_by,
        weights_verified_date,
        weights_verification_artifact,
        usage_policy,
    ) = _validate_trust_config(
        model_id,
        runtime,
        is_local_host,
        model.get("remote_trust"),
    )

    raw_envar = provider.get("apiKeyEnvar")
    api_key_envar = str(raw_envar).strip() or None if raw_envar is not None else None

    raw_kc_service = provider.get("apiKeyKeychainService")
    api_key_keychain_service = (
        str(raw_kc_service).strip() or None if raw_kc_service is not None else None
    )

    raw_upstream_url = provider.get("upstreamBaseUrl")
    upstream_base_url = (
        str(raw_upstream_url).strip() or None if raw_upstream_url is not None else None
    )

    raw_key = provider.get("apiKey")
    configured_api_key = str(raw_key).strip() if raw_key is not None else DEFAULT_API_KEY
    if not configured_api_key:
        configured_api_key = DEFAULT_API_KEY

    raw_serve_cmd = model.get("serve_command")
    has_serve_command = isinstance(raw_serve_cmd, str) and bool(raw_serve_cmd.strip())

    if trust_tier == "local":
        if api_key_keychain_service is not None:
            raise RegistryError(
                f"Model {model_id}: Rung 1 (local) models must not set promptfoo_provider.apiKeyKeychainService."
            )
        if upstream_base_url is not None:
            raise RegistryError(
                f"Model {model_id}: Rung 1 (local) models must not set promptfoo_provider.upstreamBaseUrl."
            )
        if api_key_envar is not None:
            raise RegistryError(
                f"Model {model_id}: Rung 1 (local) models must not set promptfoo_provider.apiKeyEnvar."
            )
        if configured_api_key != DEFAULT_API_KEY:
            raise RegistryError(
                f"Model {model_id}: Rung 1 (local) models must use apiKey='none'."
            )
        api_key = DEFAULT_API_KEY
    else:
        if runtime != "proxy" or not is_local_host:
            raise RegistryError(
                f"Model {model_id}: non-local tier '{trust_tier}' requires runtime='proxy' bound to a localhost "
                "apiBaseUrl so credentials are managed by se-key-proxy and never placed in os.environ."
            )
        if api_key_envar is not None:
            raise RegistryError(
                f"Model {model_id}: promptfoo_provider.apiKeyEnvar ('{api_key_envar}') is forbidden on non-local rungs; "
                "use promptfoo_provider.apiKeyKeychainService with se-key-proxy instead of environment variables."
            )
        if configured_api_key not in (DEFAULT_API_KEY, KEYCHAIN_PLACEHOLDER_KEY):
            raise RegistryError(
                f"Model {model_id}: plaintext promptfoo_provider.apiKey is forbidden on non-local rungs; "
                "use promptfoo_provider.apiKeyKeychainService."
            )
        if not api_key_keychain_service or not KEYCHAIN_SERVICE_RE.match(api_key_keychain_service):
            raise RegistryError(
                f"Model {model_id}: non-local tier '{trust_tier}' requires a valid "
                "promptfoo_provider.apiKeyKeychainService matching '^[A-Za-z0-9_.-]{1,128}$'."
            )

        if trust_tier in ATTESTED_ENCLAVE_TIERS:
            if upstream_base_url is not None:
                raise RegistryError(
                    f"Model {model_id}: attested enclave tier '{trust_tier}' must not set "
                    "promptfoo_provider.upstreamBaseUrl; route through a local attesting proxy via serve_command."
                )
            if not has_serve_command:
                raise RegistryError(
                    f"Model {model_id}: attested enclave tier '{trust_tier}' requires a non-empty serve_command "
                    "for the local attesting proxy."
                )
        else:
            # Rung 4 (zdr_contract) and Rung 5 (standard_api)
            if has_serve_command:
                raise RegistryError(
                    f"Model {model_id}: tier '{trust_tier}' must not set serve_command; "
                    "use promptfoo_provider.upstreamBaseUrl with se-key-proxy."
                )
            if not upstream_base_url:
                raise RegistryError(
                    f"Model {model_id}: tier '{trust_tier}' requires promptfoo_provider.upstreamBaseUrl "
                    "('https://<host>/v1') for se-key-proxy."
                )
            upstream_base_url = _validate_https_upstream_url(model_id, upstream_base_url)

        session_token: str | None = None
        if isinstance(pid_record, dict):
            token_path_str = pid_record.get("session_token_file")
            if isinstance(token_path_str, str) and token_path_str.strip():
                token_path = Path(token_path_str)
                if token_path.is_file():
                    try:
                        raw_tok = token_path.read_text(encoding="utf-8").strip()
                        if raw_tok.startswith("se-session-") and len(raw_tok) >= 20:
                            session_token = raw_tok
                    except OSError:
                        session_token = None

        if session_token is not None:
            api_key = session_token
        elif require_api_key:
            raise RegistryError(
                f"Model {model_id} requires an active se-key-proxy session for "
                f"apiKeyKeychainService='{api_key_keychain_service}', but no session token was found. "
                f"Run 'scripts/serve-model {model_id}' first."
            )
        else:
            api_key = KEYCHAIN_PLACEHOLDER_KEY

    raw_caps = model.get("capabilities")
    if raw_caps is None:
        capabilities: dict[str, Any] = {}
    elif isinstance(raw_caps, dict):
        capabilities = dict(raw_caps)
    else:
        raise RegistryError(f"Model {model_id}: capabilities must be a mapping")
    if "tool_calling" in capabilities and not isinstance(capabilities["tool_calling"], bool):
        raise RegistryError(
            f"Model {model_id}: capabilities.tool_calling must be a boolean (true or false), "
            f"got {capabilities['tool_calling']!r}."
        )

    raw_routing = model.get("routing")
    routing_private_local: str | None = None
    routing_private_attested: str = "blocked"
    if raw_routing is not None:
        if not isinstance(raw_routing, dict):
            raise RegistryError(f"Model {model_id}: routing must be null or a mapping")
        allowed_routing_keys = {"private_local", "private_attested", "eval_evidence_artifact"}
        unknown_routing_keys = set(raw_routing.keys()) - allowed_routing_keys
        if unknown_routing_keys:
            raise RegistryError(
                f"Model {model_id}: unknown keys in routing {sorted(str(k) for k in unknown_routing_keys)}; "
                f"allowed keys are {sorted(allowed_routing_keys)}."
            )
        raw_pl = raw_routing.get("private_local")
        if raw_pl is not None:
            if not isinstance(raw_pl, str) or raw_pl not in VALID_ROUTING_CLEARANCES:
                raise RegistryError(
                    f"Model {model_id}: invalid routing.private_local '{raw_pl}'. "
                    f"Must be one of {sorted(VALID_ROUTING_CLEARANCES)}."
                )
            if raw_pl == "cleared" and trust_tier != "local":
                raise RegistryError(
                    f"Model {model_id}: routing.private_local='cleared' is only valid for trust_tier='local'."
                )
            routing_private_local = raw_pl

        raw_pa = raw_routing.get("private_attested")
        if raw_pa is not None:
            if not isinstance(raw_pa, str) or raw_pa not in VALID_ROUTING_CLEARANCES:
                raise RegistryError(
                    f"Model {model_id}: invalid routing.private_attested '{raw_pa}'. "
                    f"Must be one of {sorted(VALID_ROUTING_CLEARANCES)}."
                )
            if raw_pa == "cleared":
                if trust_tier not in ATTESTED_ENCLAVE_TIERS:
                    raise RegistryError(
                        f"Model {model_id}: routing.private_attested='cleared' is only valid for "
                        f"attested enclave tiers ({sorted(ATTESTED_ENCLAVE_TIERS)})."
                    )
                if capabilities.get("tool_calling") is not True:
                    raise RegistryError(
                        f"Model {model_id}: routing.private_attested='cleared' requires capabilities.tool_calling=true."
                    )
            routing_private_attested = raw_pa

    raw_eval_artifact = model.get("eval_evidence_artifact")
    if raw_eval_artifact is None and isinstance(raw_routing, dict):
        raw_eval_artifact = raw_routing.get("eval_evidence_artifact")
    eval_evidence_artifact = (
        str(raw_eval_artifact).strip()
        if isinstance(raw_eval_artifact, str) and raw_eval_artifact.strip()
        else None
    )
    if eval_evidence_artifact is not None and not _is_valid_committed_eval_artifact_path(
        eval_evidence_artifact,
        model_id=model_id,
        require_exists=require_eval_evidence_file,
    ):
        raise RegistryError(
            f"Model {model_id}: eval_evidence_artifact must be a committed relative path "
            f"under 'docs/evals/{model_id}.json' whose manifest model_id matches '{model_id}', "
            f"got '{eval_evidence_artifact}'."
        )
    if (
        routing_private_local == "cleared" or routing_private_attested == "cleared"
    ) and not eval_evidence_artifact:
        raise RegistryError(
            f"Model {model_id}: routing clearance ('cleared') requires a committed "
            "'eval_evidence_artifact' path under 'docs/evals/<model-id>.json'."
        )

    raw_status = model.get("status")
    if raw_status is None:
        status = "candidate"
    elif isinstance(raw_status, str) and raw_status.strip() in VALID_MODEL_STATUSES:
        status = raw_status.strip()
    else:
        raise RegistryError(
            f"Model {model_id}: invalid status {raw_status!r}. Must be one of {sorted(VALID_MODEL_STATUSES)}."
        )

    raw_deprecated = model.get("deprecated")
    if raw_deprecated is None:
        deprecated = False
    elif isinstance(raw_deprecated, bool):
        deprecated = raw_deprecated
    else:
        raise RegistryError(
            f"Model {model_id}: 'deprecated' must be a boolean (true or false), got {raw_deprecated!r}."
        )

    raw_dep_date = model.get("deprecation_date")
    if raw_dep_date is None:
        deprecation_date: str | None = None
    elif isinstance(raw_dep_date, date) and not isinstance(raw_dep_date, datetime):
        deprecation_date = raw_dep_date.isoformat()
    elif isinstance(raw_dep_date, str) and raw_dep_date.strip():
        clean_dep_date = raw_dep_date.strip()
        if not ISO_DATE_RE.match(clean_dep_date):
            raise RegistryError(
                f"Model {model_id}: 'deprecation_date' must be in YYYY-MM-DD format, got {raw_dep_date!r}."
            )
        try:
            date.fromisoformat(clean_dep_date)
        except ValueError as exc:
            raise RegistryError(
                f"Model {model_id}: invalid calendar date '{clean_dep_date}' for 'deprecation_date'."
            ) from exc
        deprecation_date = clean_dep_date
    else:
        raise RegistryError(
            f"Model {model_id}: 'deprecation_date' must be null or a YYYY-MM-DD string, got {raw_dep_date!r}."
        )

    if routing_private_local == "cleared" or routing_private_attested == "cleared":
        if status == "archived":
            raise RegistryError(
                f"Model {model_id}: archived models (status='archived') cannot have routing clearance ('cleared')."
            )
        if is_model_effectively_deprecated(deprecated, deprecation_date):
            raise RegistryError(
                f"Model {model_id}: deprecated models (deprecated={deprecated}, deprecation_date={deprecation_date!r}) "
                "cannot have routing clearance ('cleared')."
            )

    raw_remote_trust = model.get("remote_trust")
    pricing_per_m_tokens: dict[str, float] | None = None
    if isinstance(raw_remote_trust, dict):
        raw_pricing = raw_remote_trust.get("pricing_per_m_tokens")
        if raw_pricing is not None:
            if not isinstance(raw_pricing, dict):
                raise RegistryError(
                    f"Model {model_id}: remote_trust.pricing_per_m_tokens must be null or a mapping."
                )
            parsed_pricing: dict[str, float] = {}
            for k in ("input", "output", "cached_input"):
                val = raw_pricing.get(k)
                if val is not None:
                    if (
                        isinstance(val, bool)
                        or not isinstance(val, (int, float))
                        or not math.isfinite(float(val))
                        or float(val) < 0
                    ):
                        raise RegistryError(
                            f"Model {model_id}: remote_trust.pricing_per_m_tokens.{k} must be a finite non-negative number."
                        )
                    parsed_pricing[k] = float(val)
            if parsed_pricing:
                pricing_per_m_tokens = parsed_pricing

    raw_ctx_window = model.get("context_window")
    context_window: int | None = None
    if raw_ctx_window is not None:
        if isinstance(raw_ctx_window, bool) or not isinstance(raw_ctx_window, int) or raw_ctx_window <= 0:
            raise RegistryError(f"Model {model_id}: context_window must be a positive integer or null.")
        context_window = int(raw_ctx_window)

    return EndpointConfig(
        model_id=model_id,
        served_model_id=served_model_id,
        provider_id=provider_id,
        api_base_url=api_base_url,
        host=host,
        port=port,
        api_key=api_key,
        api_key_envar=api_key_envar,
        runtime=runtime,
        trust_tier=trust_tier,
        attestation_method=attestation_method,
        is_local_host=is_local_host,
        weights_hash=weights_hash,
        weights_source=weights_source,
        weights_verified_by=weights_verified_by,
        weights_verified_date=weights_verified_date,
        weights_verification_artifact=weights_verification_artifact,
        usage_policy=usage_policy,
        capabilities=capabilities,
        routing_private_local=routing_private_local,
        routing_private_attested=routing_private_attested,
        api_key_keychain_service=api_key_keychain_service,
        upstream_base_url=upstream_base_url,
        pricing_per_m_tokens=pricing_per_m_tokens,
        context_window=context_window,
        eval_evidence_artifact=eval_evidence_artifact,
        status=status,
        deprecated=deprecated,
        deprecation_date=deprecation_date,
    )


def build_promptfoo_provider_entry(
    model: dict[str, Any],
    *,
    max_tokens: int = 700,
    temperature: float = 0.2,
    tools: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    endpoint = resolve_endpoint(model, require_api_key=False)
    provider = model.get("promptfoo_provider") or {}
    transform = provider.get("transform") or DEFAULT_EOS_TRANSFORM

    config: dict[str, Any] = {
        "apiBaseUrl": endpoint.api_base_url,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "maxRetries": 0,
    }
    raw_provider_cfg = provider.get("config")
    if isinstance(raw_provider_cfg, dict):
        for allowed_key in ("showThinking", "reasoning_effort", "passthrough", "extraBody"):
            if allowed_key in raw_provider_cfg:
                val = raw_provider_cfg[allowed_key]
                config[allowed_key] = dict(val) if isinstance(val, dict) else val
    if endpoint.api_key_keychain_service:
        config["apiKeyEnvar"] = SESSION_TOKEN_ENV_VAR
    else:
        config["apiKey"] = endpoint.api_key

    if tools is not None:
        config["tools"] = tools

    return {
        "id": endpoint.provider_id,
        "transform": transform,
        "config": config,
    }


def validate_custom_command_localhost(
    cmd: list[str],
    *,
    expected_port: int,
) -> str | None:
    """Verify a custom serve_command explicitly binds to localhost and not a wildcard/remote address."""
    if not cmd:
        return "serve_command produced an empty command"

    bind_flags = {"--host", "-H", "--bind", "--listen", "--address"}
    port_flags = {"--port", "-p"}
    valid_loopbacks = {"127.0.0.1", "localhost", "::1", "[::1]"}

    found_loopback_bind = False
    found_port: int | None = None

    def _inspect_bind_target(target: str) -> tuple[bool, str | None]:
        raw = target.strip()
        if not raw:
            return False, "empty bind target"
        if "://" in raw:
            parsed = urlparse(raw)
            h = parsed.hostname or ""
            p = parsed.port
            if h not in LOCAL_HOSTS:
                return False, f"non-localhost bind host '{h}' in '{raw}'"
            nonlocal found_port
            if p is not None:
                found_port = p
            return True, None
        # Check host:port (IPv4/hostname:port or [::1]:port)
        if raw.startswith("[") and "]:" in raw:
            h, _, p_str = raw[1:].partition("]:")
            if h not in LOCAL_HOSTS:
                return False, f"non-localhost bind host '{h}' in '{raw}'"
            if p_str.isdigit():
                found_port = int(p_str)
            return True, None
        if raw.count(":") == 1 and not raw.startswith(":"):
            h, _, p_str = raw.partition(":")
            if p_str.isdigit():
                if h not in LOCAL_HOSTS:
                    return False, f"non-localhost bind host '{h}' in '{raw}'"
                found_port = int(p_str)
                return True, None
        if raw in valid_loopbacks:
            return True, None
        return False, f"non-localhost bind target '{raw}'"

    i = 0
    while i < len(cmd):
        token = cmd[i]
        if token == "--":
            # Positional arguments after '--' cannot establish bind flags,
            # but still must not contain wildcard bind literals.
            for rem in cmd[i + 1 :]:
                if rem in ("0.0.0.0", "::", "[::]", "*") or rem.startswith(("0.0.0.0:", "[::]:")):
                    return f"Refusing wildcard bind address '{rem}' in serve_command"
            break

        flag_name = None
        flag_val = None

        if "=" in token:
            prefix, _, val = token.partition("=")
            if prefix in bind_flags or prefix in port_flags:
                flag_name = prefix
                flag_val = val
            elif val in ("0.0.0.0", "::", "[::]", "*") or val.startswith(("0.0.0.0:", "[::]:")):
                return f"Refusing wildcard bind address in '{token}'"
        elif token in bind_flags or token in port_flags:
            flag_name = token
            if i + 1 >= len(cmd) or cmd[i + 1].startswith("-"):
                return f"flag '{token}' is missing its argument in serve_command"
            flag_val = cmd[i + 1]
            i += 1

        if flag_name in bind_flags and flag_val is not None:
            ok, reason = _inspect_bind_target(flag_val)
            if not ok:
                return f"Refusing non-localhost bind in serve_command: {reason}"
            found_loopback_bind = True
        elif flag_name in port_flags and flag_val is not None:
            if not flag_val.isdigit():
                return f"Invalid port '{flag_val}' in serve_command"
            found_port = int(flag_val)
        else:
            # Reject standalone wildcard bind tokens like 0.0.0.0 or 0.0.0.0:8080.
            # Never treat unrelated positional or option values as establishing a loopback bind.
            if token in ("0.0.0.0", "::", "[::]", "*") or token.startswith(("0.0.0.0:", "[::]:")):
                return f"Refusing wildcard bind address '{token}' in serve_command"
        i += 1

    if not found_loopback_bind:
        return (
            "serve_command must explicitly bind to localhost via a recognized bind flag "
            "(e.g. --host {host} --port {port} or --bind 127.0.0.1:{port})"
        )
    if found_port is None:
        return (
            f"serve_command must explicitly specify the listener port ({expected_port}) "
            "via --port/-p or host:port bind flag"
        )
    if found_port != expected_port:
        return (
            f"serve_command port {found_port} does not match resolved endpoint port {expected_port}"
        )
    return None


def pid_file_for_model(model_id: str, runs_dir: Path | None = None) -> Path:
    base = runs_dir or DEFAULT_RUNS_DIR
    safe_id = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "-" for ch in model_id)
    digest = hashlib.sha256(model_id.encode("utf-8")).hexdigest()[:8]
    return base / f".serve-{safe_id}-{digest}.pid"


def session_token_file_for_model(model_id: str, runs_dir: Path | None = None) -> Path:
    base = runs_dir or DEFAULT_RUNS_DIR
    safe_id = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "-" for ch in model_id)
    digest = hashlib.sha256(model_id.encode("utf-8")).hexdigest()[:8]
    return base / f".se-session-{safe_id}-{digest}.token"


def _legacy_unhashed_pid_file(model_id: str, runs_dir: Path | None = None) -> Path:
    base = runs_dir or DEFAULT_RUNS_DIR
    safe_id = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "-" for ch in model_id)
    return base / f".serve-{safe_id}.pid"


def legacy_pid_file(runs_dir: Path | None = None) -> Path:
    base = runs_dir or DEFAULT_RUNS_DIR
    return base / ".serve.pid"


def read_pid_record_for_model(
    model_id: str, runs_dir: Path | None = None
) -> dict[str, Any] | None:
    base = runs_dir or DEFAULT_RUNS_DIR
    for candidate in (
        pid_file_for_model(model_id, base),
        _legacy_unhashed_pid_file(model_id, base),
    ):
        try:
            if candidate.exists():
                record = json.loads(candidate.read_text())
                if isinstance(record, dict) and record.get("model_id") == model_id:
                    return record
        except (OSError, json.JSONDecodeError):
            pass

    for _, record in list_pid_records(base):
        if record.get("model_id") == model_id:
            return record

    legacy = legacy_pid_file(base)
    try:
        if legacy.exists():
            record = json.loads(legacy.read_text())
            if isinstance(record, dict) and record.get("model_id") == model_id:
                return record
    except (OSError, json.JSONDecodeError):
        pass
    return None


def list_pid_records(runs_dir: Path | None = None) -> list[tuple[Path, dict[str, Any]]]:
    base = runs_dir or DEFAULT_RUNS_DIR
    try:
        if not base.exists():
            return []
        paths = sorted(base.glob(".serve*.pid"))
    except OSError:
        return []
    records: list[tuple[Path, dict[str, Any]]] = []
    for path in paths:
        try:
            data = json.loads(path.read_text())
            if isinstance(data, dict):
                records.append((path, data))
        except (OSError, json.JSONDecodeError):
            continue
    return records


def pid_is_alive(pid: Any) -> bool:
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def _run_ps_query(pid: int, column: str) -> str | None:
    proc = None
    try:
        proc = subprocess.Popen(
            ["ps", "-p", str(pid), "-o", f"{column}="],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={"PATH": "/bin:/usr/bin", "LC_ALL": "C", "TZ": "UTC"},
        )
        stdout, _ = proc.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        if proc is not None:
            try:
                proc.kill()
                proc.communicate()
            except Exception:
                pass
        return None
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    out = (stdout or "").strip()
    return out if out else None


def get_process_lstart(pid: Any) -> str | None:
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return None
    return _run_ps_query(pid, "lstart")


def get_process_command(pid: Any) -> str | None:
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return None
    return _run_ps_query(pid, "command")


def pid_is_zombie(pid: Any) -> bool:
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    stat_out = _run_ps_query(pid, "stat")
    if stat_out is None:
        return False
    return stat_out.lstrip().upper().startswith("Z")


def pid_matches_record(
    pid: Any,
    expected_lstart: Any,
    *,
    require_lstart: bool = True,
) -> bool:
    if not pid_is_alive(pid):
        return False
    if isinstance(expected_lstart, str) and expected_lstart.strip():
        actual = get_process_lstart(pid)
        return actual == expected_lstart.strip()
    if require_lstart:
        return False
    return True
