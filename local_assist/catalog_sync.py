from __future__ import annotations

import contextlib
import copy
import datetime
import fcntl
import hashlib
import json
import math
import os
import re
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

from ._miniyaml import _MiniYamlParser, parse_yaml_with_flow_sequences, safe_load
from .registry import (
    DEFAULT_MODELS_PATH,
    ISO_DATE_RE,
    WEIGHTS_HASH_RE,
    WEIGHTS_SOURCE_RE,
    RegistryError,
    resolve_endpoint,
)


DEFAULT_ROUTER_MANIFEST_URL = "https://inference.tinfoil.sh/.well-known/tinfoil-proxy"
DEFAULT_OPENAI_MODELS_URL = "https://inference.tinfoil.sh/v1/models"
DEFAULT_GITHUB_RAW_BASE_URL = "https://raw.githubusercontent.com"
TINFOIL_ATTESTATION_METHOD = "tinfoil-proxy-sigstore"
TINFOIL_SERVE_COMMAND = (
    "./bin/tinfoil-proxy --bind {host} --port {port} "
    "-e inference.tinfoil.sh --repo tinfoilsh/confidential-model-router"
)
TINFOIL_KEYCHAIN_SERVICE = "free-inference.tinfoil"
TINFOIL_API_BASE_URL = "http://127.0.0.1:8081/v1"
DEFAULT_IGNORED_SERVED_IDS: frozenset[str] = frozenset({"gemma4-31b", "llama3-3-70b"})

MPK_DESCRIPTOR_RE = re.compile(
    r"^(?P<sha256>[0-9a-f]{64})_(?P<size_bytes>\d+)_[0-9a-fA-F-]{36}$"
)
ENCLAVE_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ENCLAVE_TAG_RE = re.compile(r"^[A-Za-z0-9_+-][A-Za-z0-9_.+-]{0,63}$")


class CatalogSyncError(Exception):
    """Raised when live catalog sources are unreachable, malformed, or disagree."""


@dataclass
class ModelDriftItem:
    model_id: str
    served_model_id: str
    action: str  # "update", "demote_weights_changed", "demote_zero_health", "archive_removed", "quarantine_disagreement"
    changes: dict[str, dict[str, Any]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    weights_changed: bool = False


@dataclass
class FeedDisagreementItem:
    model_id: str
    served_model_id: str
    in_router_manifest: bool
    in_openai_models: bool
    router_healthy: int | None
    reason: str


@dataclass
class CatalogDriftReport:
    observed_date: str
    updated_models: list[ModelDriftItem] = field(default_factory=list)
    new_models: list[dict[str, Any]] = field(default_factory=list)
    removed_models: list[ModelDriftItem] = field(default_factory=list)
    disagreements: list[FeedDisagreementItem] = field(default_factory=list)
    base_catalog_sha256: str | None = None

    @property
    def has_drift(self) -> bool:
        return bool(
            self.updated_models
            or self.new_models
            or self.removed_models
            or self.disagreements
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "observed_date": self.observed_date,
            "base_catalog_sha256": self.base_catalog_sha256,
            "has_drift": self.has_drift,
            "updated_models": [
                {
                    "model_id": item.model_id,
                    "served_model_id": item.served_model_id,
                    "action": item.action,
                    "weights_changed": item.weights_changed,
                    "changes": item.changes,
                    "notes": item.notes,
                }
                for item in self.updated_models
            ],
            "new_models": [
                {
                    "id": m.get("id"),
                    "repo": m.get("repo"),
                    "upstream": m.get("upstream"),
                    "status": m.get("status"),
                    "remote_trust": m.get("remote_trust"),
                    "context_window": m.get("context_window"),
                }
                for m in self.new_models
            ],
            "removed_models": [
                {
                    "model_id": item.model_id,
                    "served_model_id": item.served_model_id,
                    "action": item.action,
                    "changes": item.changes,
                    "notes": item.notes,
                }
                for item in self.removed_models
            ],
            "disagreements": [
                {
                    "model_id": d.model_id,
                    "served_model_id": d.served_model_id,
                    "in_router_manifest": d.in_router_manifest,
                    "in_openai_models": d.in_openai_models,
                    "router_healthy": d.router_healthy,
                    "reason": d.reason,
                }
                for d in self.disagreements
            ],
        }


def parse_tinfoil_config_yaml(text: str) -> dict[str, Any]:
    """Parse a Tinfoil enclave tinfoil-config.yml manifest identically with or without PyYAML."""
    if not isinstance(text, str) or not text.strip():
        raise CatalogSyncError("Empty tinfoil-config.yml content")
    try:
        parsed = parse_yaml_with_flow_sequences(text)
    except Exception as exc:
        raise CatalogSyncError(f"Failed to parse tinfoil-config.yml with stdlib parser: {exc}") from exc

    if not isinstance(parsed, dict):
        raise CatalogSyncError("tinfoil-config.yml must parse to a top-level mapping")

    try:
        import yaml as pyyaml  # type: ignore[import-untyped]
    except ImportError:
        pyyaml = None

    if pyyaml is not None:
        try:
            py_parsed = pyyaml.safe_load(text)
        except Exception as exc:
            raise CatalogSyncError(f"PyYAML rejected tinfoil-config.yml: {exc}") from exc
        if parsed != py_parsed:
            raise CatalogSyncError(
                "Stdlib flow-enabled YAML parser and PyYAML produced different structures on tinfoil-config.yml"
            )

    return parsed


def parse_mpk_descriptor(mpk_str: str) -> tuple[str, float]:
    """Extract ('dmverity:sha256:<64-hex>', disk_gb_estimate) from a Tinfoil MPK string."""
    if not isinstance(mpk_str, str):
        raise CatalogSyncError(f"Invalid mpk descriptor (expected string): {mpk_str!r}")
    match = MPK_DESCRIPTOR_RE.match(mpk_str.strip())
    if not match:
        raise CatalogSyncError(
            f"Malformed mpk descriptor {mpk_str!r}; expected '<64-hex-sha256>_<size-bytes>_<uuid>'"
        )
    sha256_hex = match.group("sha256")
    size_bytes = int(match.group("size_bytes"))
    if size_bytes <= 0:
        raise CatalogSyncError(f"Invalid non-positive byte size in mpk descriptor: {mpk_str!r}")
    weights_hash = f"dmverity:sha256:{sha256_hex}"
    if not WEIGHTS_HASH_RE.match(weights_hash):
        raise CatalogSyncError(f"Constructed weights hash failed validation: {weights_hash!r}")
    disk_gb = round(size_bytes / 1_000_000_000, 1)
    return weights_hash, disk_gb


def extract_enclave_manifest_metadata(
    tinfoil_cfg: dict[str, Any],
    served_model_id: str,
) -> dict[str, Any]:
    """Validate and extract weights source, dm-verity hash, disk size, and vLLM flags from tinfoil-config.yml."""
    if not isinstance(tinfoil_cfg, dict):
        raise CatalogSyncError(f"Model {served_model_id}: enclave config is not a mapping")

    raw_models = tinfoil_cfg.get("models")
    if not isinstance(raw_models, list) or not raw_models:
        raise CatalogSyncError(
            f"Model {served_model_id}: tinfoil-config.yml is missing non-empty 'models' list"
        )

    matched_model_entry: dict[str, Any] | None = None
    for entry in raw_models:
        if isinstance(entry, dict) and str(entry.get("name") or "").strip() == served_model_id:
            matched_model_entry = entry
            break

    if not isinstance(matched_model_entry, dict):
        raise CatalogSyncError(
            f"Model {served_model_id}: could not locate primary model entry with name={served_model_id!r} in tinfoil-config.yml"
        )

    weights_source = str(matched_model_entry.get("repo") or "").strip()
    if not weights_source or not WEIGHTS_SOURCE_RE.match(weights_source):
        raise CatalogSyncError(
            f"Model {served_model_id}: invalid or unpinned repo '{weights_source}' in tinfoil-config.yml "
            "(expected '<org>/<repo>@<40-hex-commit>')"
        )
    upstream_repo = weights_source.split("@", 1)[0]

    mpk_raw = str(matched_model_entry.get("mpk") or "").strip()
    weights_hash, disk_gb = parse_mpk_descriptor(mpk_raw)

    raw_containers = tinfoil_cfg.get("containers")
    if not isinstance(raw_containers, list) or not raw_containers or not isinstance(raw_containers[0], dict):
        raise CatalogSyncError(
            f"Model {served_model_id}: tinfoil-config.yml is missing 'containers[0]' mapping"
        )
    container = raw_containers[0]
    raw_cmd = container.get("command")
    if not isinstance(raw_cmd, list) or not raw_cmd:
        raise CatalogSyncError(
            f"Model {served_model_id}: tinfoil-config.yml 'containers[0].command' must be a non-empty list"
        )
    cmd_tokens = [str(tok) for tok in raw_cmd]

    def _flag_value(flag: str) -> str | None:
        for idx, tok in enumerate(cmd_tokens):
            if tok == flag and idx + 1 < len(cmd_tokens):
                return cmd_tokens[idx + 1]
            if tok.startswith(f"{flag}="):
                return tok.split("=", 1)[1]
        return None

    tool_call_parser = _flag_value("--tool-call-parser")
    reasoning_parser = _flag_value("--reasoning-parser")
    kv_cache_dtype = _flag_value("--kv-cache-dtype")
    max_model_len_str = _flag_value("--max-model-len")
    max_model_len: int | None = None
    if max_model_len_str and max_model_len_str.isdigit():
        max_model_len = int(max_model_len_str)

    return {
        "weights_source": weights_source,
        "upstream": upstream_repo,
        "weights_hash": weights_hash,
        "disk_gb_estimate": disk_gb,
        "tool_call_parser": tool_call_parser,
        "reasoning_parser": reasoning_parser,
        "kv_cache_dtype": kv_cache_dtype,
        "max_model_len": max_model_len,
    }


MAX_CATALOG_RESPONSE_BYTES = 2 * 1024 * 1024
ALLOWED_CATALOG_HOSTS = frozenset(
    {
        "inference.tinfoil.sh",
        "raw.githubusercontent.com",
        "127.0.0.1",
        "localhost",
    }
)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        raise CatalogSyncError(f"Refusing HTTP redirect ({code}) from {req.full_url} to {newurl}")


def _http_get_text(
    url: str,
    *,
    timeout: float = 15.0,
    max_bytes: int = MAX_CATALOG_RESPONSE_BYTES,
) -> str:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "https":
        if host not in ALLOWED_CATALOG_HOSTS:
            raise CatalogSyncError(f"Refusing non-allowlisted catalog host {host!r} in URL: {url}")
    elif parsed.scheme == "http":
        if host not in ("127.0.0.1", "localhost"):
            raise CatalogSyncError(f"Refusing plaintext HTTP catalog URL on non-loopback host: {url}")
    else:
        raise CatalogSyncError(f"Refusing unsupported URL scheme {parsed.scheme!r} in catalog URL: {url}")

    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json, text/plain, */*", "User-Agent": "free-inference-catalog-sync/1.0"},
        method="GET",
    )
    opener = urllib.request.build_opener(_NoRedirectHandler())
    try:
        with opener.open(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            if status != 200:
                raise CatalogSyncError(f"HTTP {status} from {url}")
            raw_bytes = resp.read(max_bytes + 1)
            if len(raw_bytes) > max_bytes:
                raise CatalogSyncError(
                    f"Catalog response from {url} exceeded {max_bytes}-byte limit"
                )
            return raw_bytes.decode("utf-8")
    except CatalogSyncError:
        raise
    except Exception as exc:
        raise CatalogSyncError(f"Failed to fetch {url}: {exc}") from exc


def fetch_tinfoil_router_manifest(
    url: str = DEFAULT_ROUTER_MANIFEST_URL,
    *,
    timeout: float = 15.0,
    http_get: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    getter = http_get or (lambda u: _http_get_text(u, timeout=timeout))
    text = getter(url)
    try:
        data = json.loads(text)
    except Exception as exc:
        raise CatalogSyncError(f"Invalid JSON from router manifest {url}: {exc}") from exc
    validate_router_manifest(data)
    return data


def fetch_tinfoil_openai_models(
    url: str = DEFAULT_OPENAI_MODELS_URL,
    *,
    timeout: float = 15.0,
    http_get: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    getter = http_get or (lambda u: _http_get_text(u, timeout=timeout))
    text = getter(url)
    try:
        data = json.loads(text)
    except Exception as exc:
        raise CatalogSyncError(f"Invalid JSON from OpenAI models endpoint {url}: {exc}") from exc
    validate_openai_models(data)
    return data


def fetch_tinfoil_enclave_config(
    repo: str,
    tag: str,
    *,
    raw_base_url: str = DEFAULT_GITHUB_RAW_BASE_URL,
    timeout: float = 15.0,
    http_get: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    if not isinstance(repo, str) or not ENCLAVE_REPO_RE.match(repo.strip()):
        raise CatalogSyncError(f"Invalid enclave repository identifier: {repo!r}")
    if not isinstance(tag, str) or not ENCLAVE_TAG_RE.match(tag.strip()):
        raise CatalogSyncError(f"Invalid enclave release tag: {tag!r}")
    url = f"{raw_base_url.rstrip('/')}/{repo.strip()}/{tag.strip()}/tinfoil-config.yml"
    getter = http_get or (lambda u: _http_get_text(u, timeout=timeout))
    text = getter(url)
    return parse_tinfoil_config_yaml(text)


def validate_router_manifest(data: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(data, dict):
        raise CatalogSyncError("Router manifest must be a JSON object")
    raw_models = data.get("models")
    if not isinstance(raw_models, dict) or not raw_models:
        raise CatalogSyncError("Router manifest is missing non-empty 'models' mapping")
    validated: dict[str, dict[str, Any]] = {}
    for mid, info in raw_models.items():
        if not isinstance(mid, str) or not mid.strip() or not isinstance(info, dict):
            raise CatalogSyncError(f"Router manifest contains malformed model entry for {mid!r}")
        repo = info.get("repo")
        tag = info.get("tag")
        ver = info.get("verification")
        if not isinstance(repo, str) or not repo.strip():
            raise CatalogSyncError(f"Router manifest model '{mid}' is missing 'repo'")
        if tag is not None and not isinstance(tag, str):
            raise CatalogSyncError(f"Router manifest model '{mid}' has non-string 'tag'")
        if (
            not isinstance(ver, dict)
            or not isinstance(ver.get("healthy"), int)
            or isinstance(ver.get("healthy"), bool)
        ):
            raise CatalogSyncError(
                f"Router manifest model '{mid}' is missing integer 'verification.healthy'"
            )
        if ver["healthy"] < 0:
            raise CatalogSyncError(
                f"Router manifest model '{mid}' has negative 'verification.healthy': {ver['healthy']}"
            )
        cfg_val = ver.get("configured")
        if cfg_val is not None and (
            isinstance(cfg_val, bool) or not isinstance(cfg_val, int) or cfg_val < 0
        ):
            raise CatalogSyncError(
                f"Router manifest model '{mid}' has invalid 'verification.configured': {cfg_val!r}"
            )
        raw_hosts = ver.get("hosts")
        host_code_tags: list[str] = []
        if isinstance(raw_hosts, dict):
            seen_tags: set[str] = set()
            for host_info in raw_hosts.values():
                if isinstance(host_info, dict):
                    ct = host_info.get("code_tag")
                    if isinstance(ct, str) and ct.strip():
                        seen_tags.add(ct.strip())
            host_code_tags = sorted(seen_tags)
        entry_copy = dict(info)
        if host_code_tags:
            entry_copy["host_code_tags"] = host_code_tags
            if isinstance(tag, str) and tag.strip() in host_code_tags:
                entry_copy["tag"] = host_code_tags[0]
        validated[mid.strip()] = entry_copy
    return validated


def validate_openai_models(data: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(data, dict) or data.get("object") != "list":
        raise CatalogSyncError("OpenAI /v1/models response must be a JSON object with object='list'")
    raw_list = data.get("data")
    if not isinstance(raw_list, list) or not raw_list:
        raise CatalogSyncError("OpenAI /v1/models response has empty or non-list 'data'")
    validated: dict[str, dict[str, Any]] = {}
    for item in raw_list:
        if not isinstance(item, dict):
            raise CatalogSyncError("OpenAI /v1/models 'data' contains non-object item")
        mid = item.get("id")
        if not isinstance(mid, str) or not mid.strip():
            raise CatalogSyncError("OpenAI /v1/models item is missing string 'id'")
        validated[mid.strip()] = item
    return validated


def is_tinfoil_managed_model(model: dict[str, Any]) -> bool:
    if not isinstance(model, dict):
        return False
    if model.get("runtime") != "proxy":
        return False
    rt = model.get("remote_trust")
    if not isinstance(rt, dict):
        return False
    return rt.get("attestation_method") == TINFOIL_ATTESTATION_METHOD


def _demote_routing_and_preserve_evidence(model: dict[str, Any], *, new_status: str) -> dict[str, Any]:
    """Demote status and routing.private_attested to blocked while moving eval_evidence_artifact to stale_eval_evidence_artifact."""
    changes: dict[str, Any] = {}
    old_status = model.get("status")
    if old_status != new_status:
        changes["status"] = {"from": old_status, "to": new_status}
        model["status"] = new_status

    routing = model.get("routing")
    if not isinstance(routing, dict):
        routing = {"private_local": "blocked", "private_attested": "blocked"}
        model["routing"] = routing
    old_pa = routing.get("private_attested", "blocked")
    if old_pa != "blocked":
        changes["routing.private_attested"] = {"from": old_pa, "to": "blocked"}
        routing["private_attested"] = "blocked"

    ev = model.pop("eval_evidence_artifact", None)
    if ev is None and isinstance(routing, dict):
        ev = routing.pop("eval_evidence_artifact", None)
    elif isinstance(routing, dict):
        routing.pop("eval_evidence_artifact", None)

    if ev:
        model["stale_eval_evidence_artifact"] = ev
        changes["eval_evidence_artifact"] = {
            "from": ev,
            "to": None,
            "preserved_as": "stale_eval_evidence_artifact",
        }
    return changes


def _infer_promptfoo_passthrough_config(
    served_id: str,
    oai_entry: dict[str, Any],
    enclave_meta: dict[str, Any],
) -> dict[str, Any]:
    config: dict[str, Any] = {"showThinking": False}
    passthrough: dict[str, Any] = {"include_reasoning": False}
    r_parser = enclave_meta.get("reasoning_parser") or ""
    r_params = ((oai_entry.get("reasoning_params") or {}).get("params") or {}).get(
        "/v1/chat/completions"
    ) or {}
    disable_cfg = r_params.get("disable")
    if isinstance(disable_cfg, dict) and isinstance(disable_cfg.get("chat_template_kwargs"), dict):
        passthrough["chat_template_kwargs"] = copy.deepcopy(disable_cfg["chat_template_kwargs"])
    elif r_parser in ("kimi_k3", "deepseek_v41"):
        passthrough["chat_template_kwargs"] = {"thinking": False}
    elif r_parser in ("glm45", "openai_gptoss"):
        passthrough["reasoning_effort"] = "low"
        passthrough["chat_template_kwargs"] = {"reasoning_effort": "low"}
    config["passthrough"] = passthrough
    return config


def _build_candidate_model_entry(
    served_id: str,
    router_entry: dict[str, Any],
    oai_entry: dict[str, Any],
    enclave_meta: dict[str, Any],
    observed_date: str,
) -> dict[str, Any]:
    model_id = served_id if served_id.startswith("tinfoil-") else f"tinfoil-{served_id}"
    enclave_repo = str(router_entry.get("repo") or "").strip()
    enclave_tag = str(router_entry.get("tag") or "").strip()
    upstream_repo = enclave_meta["upstream"]

    raw_pricing = oai_entry.get("pricing") or {}
    in_price = raw_pricing.get("inputTokenPricePer1M")
    out_price = raw_pricing.get("outputTokenPricePer1M")
    cached_price = raw_pricing.get("cachedInputTokenPricePer1M")
    if (
        isinstance(in_price, bool)
        or not isinstance(in_price, (int, float))
        or isinstance(out_price, bool)
        or not isinstance(out_price, (int, float))
    ):
        raise CatalogSyncError(
            f"New coding model '{served_id}' is missing numeric input/output pricing in /v1/models"
        )

    pricing_dict: dict[str, float] = {
        "input": float(in_price),
        "output": float(out_price),
    }
    if (
        not isinstance(cached_price, bool)
        and isinstance(cached_price, (int, float))
        and float(cached_price) >= 0
    ):
        pricing_dict["cached_input"] = float(cached_price)

    raw_oai_ctx = oai_entry.get("context_window")
    raw_meta_ctx = enclave_meta.get("max_model_len")
    ctx_win: int | None = None
    if not isinstance(raw_oai_ctx, bool) and isinstance(raw_oai_ctx, int) and raw_oai_ctx > 0:
        ctx_win = int(raw_oai_ctx)
    elif not isinstance(raw_meta_ctx, bool) and isinstance(raw_meta_ctx, int) and raw_meta_ctx > 0:
        ctx_win = int(raw_meta_ctx)

    modalities = ["text", "image"] if oai_entry.get("multimodal") is True else ["text"]
    kv_dtype = enclave_meta.get("kv_cache_dtype")
    repo_lower = upstream_repo.lower()
    if "nvfp4" in repo_lower:
        quant_bits: int | None = 4
        quant_tool: str | None = "nvfp4"
    elif "fp4" in repo_lower:
        quant_bits = 4
        quant_tool = "fp4"
    elif "-fp8" in repo_lower or "_fp8" in repo_lower or repo_lower.endswith("fp8"):
        quant_bits = 8
        quant_tool = "fp8"
    else:
        quant_bits = None
        quant_tool = None

    raw_license = oai_entry.get("license")
    license_val: str | None = (
        raw_license.strip()
        if isinstance(raw_license, str) and raw_license.strip()
        else None
    )
    chat_source = enclave_meta.get("reasoning_parser") or enclave_meta.get("tool_call_parser") or "vllm"

    cached_note = f" (${float(cached_price):.2f} cached)" if isinstance(cached_price, (int, float)) and not isinstance(cached_price, bool) else ""
    ctx_note = f"{ctx_win} context window" if ctx_win is not None else "unspecified context window"
    display_name = str(oai_entry.get("name") or served_id)
    fit_notes = (
        f"{display_name} served inside Tinfoil's attested enclaves "
        f"({enclave_repo} {enclave_tag}) with "
        f"--tool-call-parser {enclave_meta.get('tool_call_parser') or 'auto'}, "
        f"--reasoning-parser {enclave_meta.get('reasoning_parser') or 'auto'}, and "
        f"{ctx_note}. Pricing verified on {observed_date}: "
        f"${float(in_price):.2f}/1M input{cached_note} and ${float(out_price):.2f}/1M output.\n"
    )
    review_notes = (
        f"Discovered and scaffolded via scripts/sync-model-catalog on {observed_date} "
        f"from live router manifest ({enclave_repo}@{enclave_tag}) and /v1/models. "
        "Kept at status: candidate and routing.private_attested: blocked until evaluated.\n"
    )

    entry: dict[str, Any] = {
        "id": model_id,
        "status": "candidate",
        "repo": served_id,
        "upstream": upstream_repo,
        "converter": "tinfoilsh",
        "conversion_runtime_version": "vllm",
        "runtime": "proxy",
        "serve_command": TINFOIL_SERVE_COMMAND,
        "enclave_repo": enclave_repo,
        "enclave_tag": enclave_tag,
        "promptfoo_provider": {
            "id": f"openai:chat:{served_id}",
            "apiBaseUrl": TINFOIL_API_BASE_URL,
            "apiKeyKeychainService": TINFOIL_KEYCHAIN_SERVICE,
            "config": _infer_promptfoo_passthrough_config(served_id, oai_entry, enclave_meta),
        },
        "capabilities": {
            "tool_calling": bool(oai_entry.get("tool_calling", True)),
        },
        "routing": {
            "private_local": "blocked",
            "private_attested": "blocked",
        },
        "remote_trust": {
            "tier": "enclave_runtime_attested",
            "attestation_method": TINFOIL_ATTESTATION_METHOD,
            "weights_hash": None,
            "weights_source": None,
            "provider_manifest_weights_hash": enclave_meta["weights_hash"],
            "provider_manifest_weights_source": enclave_meta["weights_source"],
            "usage_policy": "provider_terms_apply",
            "jurisdiction": "US",
            "pricing_per_m_tokens": pricing_dict,
        },
        "license": license_val,
        "release_date": None,
        "verified_date": observed_date,
        "params_total": None,
        "params_active": None,
        "quantization": {
            "bits": quant_bits,
            "group_size": None,
            "tool": quant_tool,
            "tool_version": None,
        },
        "kv_cache_dtype": kv_dtype,
        "disk_gb_estimate": enclave_meta["disk_gb_estimate"],
        "ram_gb_estimate": None,
        "context_window": ctx_win,
        "modalities": modalities,
        "chat_template": {
            "source": chat_source,
            "roles_supported": ["system", "user", "assistant", "tool"],
        },
        "source_links": [
            f"https://github.com/{enclave_repo}",
            "https://github.com/tinfoilsh/confidential-model-router",
            f"https://huggingface.co/{upstream_repo}",
        ],
        "fit_notes": fit_notes,
        "review_notes": review_notes,
        "eval_summary": None,
    }
    return entry


def compute_models_data_digest(models_data: dict[str, Any]) -> str:
    canonical = json.dumps(models_data, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@contextlib.contextmanager
def catalog_file_lock(models_path: Path) -> Iterator[None]:
    lock_path = models_path.parent / f".{models_path.name}.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w", encoding="utf-8") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def compute_catalog_drift(
    models_data: dict[str, Any],
    router_manifest: dict[str, Any],
    openai_models: dict[str, Any],
    enclave_configs: dict[str, dict[str, Any]] | None = None,
    *,
    enclave_config_fetcher: Callable[[str, str], dict[str, Any]] | None = None,
    observed_date: str | None = None,
    discover_new_coding_models: bool = True,
    ignored_served_ids: set[str] | None = None,
) -> CatalogDriftReport:
    """Compare models.yaml against live Tinfoil router, /v1/models, and per-enclave tinfoil-config.yml."""
    if not isinstance(models_data, dict) or not isinstance(models_data.get("models"), list):
        raise CatalogSyncError("models_data must be a mapping with a 'models' list")

    router_map = validate_router_manifest(router_manifest)
    oai_map = validate_openai_models(openai_models)
    today_str = observed_date or datetime.date.today().isoformat()
    if not ISO_DATE_RE.match(today_str):
        raise CatalogSyncError(f"Invalid observed_date '{today_str}'; expected YYYY-MM-DD")

    cfg_cache: dict[str, dict[str, Any]] = dict(enclave_configs or {})

    def _get_enclave_cfg(
        served_id: str,
        repo: str,
        tag: str,
        *,
        allow_served_id_fallback: bool = True,
    ) -> dict[str, Any]:
        key_pair = f"{repo}@{tag}"
        if key_pair in cfg_cache:
            return cfg_cache[key_pair]
        if allow_served_id_fallback and served_id in cfg_cache:
            return cfg_cache[served_id]
        if enclave_config_fetcher is not None:
            fetched = enclave_config_fetcher(repo, tag)
            cfg_cache[key_pair] = fetched
            return fetched
        if not allow_served_id_fallback and served_id in cfg_cache:
            raise CatalogSyncError(
                f"Ambiguous served-ID-only cache for multi-tag model '{served_id}': "
                f"missing tag-qualified enclave config for '{key_pair}'"
            )
        raise CatalogSyncError(
            f"Missing enclave tinfoil-config.yml for '{served_id}' ({key_pair})"
        )

    def _resolve_verified_enclave_meta(
        served_id: str,
        enclave_repo: str,
        enclave_tag: str,
        host_code_tags: list[str] | None,
    ) -> dict[str, Any]:
        extra_tags = [t for t in (host_code_tags or []) if t != enclave_tag]
        allow_alias = len(extra_tags) == 0
        primary_cfg = _get_enclave_cfg(
            served_id,
            enclave_repo,
            enclave_tag,
            allow_served_id_fallback=allow_alias,
        )
        primary_meta = extract_enclave_manifest_metadata(primary_cfg, served_id)
        for extra_tag in extra_tags:
            extra_cfg = _get_enclave_cfg(
                served_id,
                enclave_repo,
                extra_tag,
                allow_served_id_fallback=False,
            )
            extra_meta = extract_enclave_manifest_metadata(extra_cfg, served_id)
            if (
                extra_meta["weights_hash"] != primary_meta["weights_hash"]
                or extra_meta["weights_source"] != primary_meta["weights_source"]
            ):
                raise CatalogSyncError(
                    f"Model '{served_id}' has inconsistent weights across active host code_tags "
                    f"({enclave_tag}: {primary_meta['weights_hash']} vs {extra_tag}: {extra_meta['weights_hash']})"
                )
        return primary_meta

    report = CatalogDriftReport(
        observed_date=today_str,
        base_catalog_sha256=compute_models_data_digest(models_data),
    )
    registered_served_ids: set[str] = set()
    all_existing_by_id: dict[str, dict[str, Any]] = {}
    all_existing_by_repo: dict[str, dict[str, Any]] = {}

    for m in models_data["models"]:
        if not isinstance(m, dict):
            continue
        mid_raw = str(m.get("id") or "").strip()
        mrepo_raw = str(m.get("repo") or "").strip()
        if mid_raw:
            all_existing_by_id[mid_raw] = m
        if mrepo_raw:
            all_existing_by_repo[mrepo_raw] = m

    for model in models_data["models"]:
        if not is_tinfoil_managed_model(model):
            continue
        model_id = str(model.get("id") or "").strip()
        served_id = str(model.get("repo") or model_id).strip()
        registered_served_ids.add(served_id)

        r_entry = router_map.get(served_id)
        o_entry = oai_map.get(served_id)

        # Case 1: Absent from both feeds -> positively observed removal
        if r_entry is None and o_entry is None:
            if model.get("status") != "archived" or (model.get("routing") or {}).get("private_attested") != "blocked":
                sim_model = copy.deepcopy(model)
                changes = _demote_routing_and_preserve_evidence(sim_model, new_status="archived")
                report.removed_models.append(
                    ModelDriftItem(
                        model_id=model_id,
                        served_model_id=served_id,
                        action="archive_removed",
                        changes=changes,
                        notes=["Absent from both /.well-known/tinfoil-proxy and /v1/models"],
                    )
                )
            continue

        # Case 2: Present in router manifest with verification.healthy <= 0 (evaluated BEFORE config fetch or disagreement)
        if r_entry is not None:
            healthy_count = int((r_entry.get("verification") or {}).get("healthy") or 0)
            if healthy_count <= 0:
                if healthy_count < 0:
                    raise CatalogSyncError(
                        f"Router manifest model '{served_id}' has negative verification.healthy: {healthy_count}"
                    )
                sim_model = copy.deepcopy(model)
                changes = _demote_routing_and_preserve_evidence(sim_model, new_status="candidate")
                if changes:
                    report.updated_models.append(
                        ModelDriftItem(
                            model_id=model_id,
                            served_model_id=served_id,
                            action="demote_zero_health",
                            changes=changes,
                            notes=["Router manifest reports verification.healthy == 0"],
                        )
                    )
                continue

        # Case 3: Feed disagreement (present in one feed with healthy >= 1, absent in the other)
        if (r_entry is None) != (o_entry is None):
            r_healthy = (
                int((r_entry.get("verification") or {}).get("healthy") or 0)
                if r_entry is not None
                else None
            )
            report.disagreements.append(
                FeedDisagreementItem(
                    model_id=model_id,
                    served_model_id=served_id,
                    in_router_manifest=r_entry is not None,
                    in_openai_models=o_entry is not None,
                    router_healthy=r_healthy,
                    reason=(
                        f"Model '{served_id}' is present in "
                        f"{'router_manifest' if r_entry is not None else 'openai_models'} "
                        f"but absent from {'openai_models' if r_entry is not None else 'router_manifest'}"
                    ),
                )
            )
            continue

        assert r_entry is not None and o_entry is not None
        enclave_repo = str(r_entry.get("repo") or "").strip()
        enclave_tag = str(r_entry.get("tag") or "").strip()
        if not enclave_tag:
            raise CatalogSyncError(
                f"Router manifest model '{served_id}' has healthy enclaves but empty 'tag'"
            )

        enclave_meta = _resolve_verified_enclave_meta(
            served_id,
            enclave_repo,
            enclave_tag,
            r_entry.get("host_code_tags"),
        )

        changes: dict[str, dict[str, Any]] = {}
        notes: list[str] = []
        action = "update"

        rt = model.get("remote_trust") or {}
        old_hash = rt.get("provider_manifest_weights_hash")
        new_hash = enclave_meta["weights_hash"]
        old_source = rt.get("provider_manifest_weights_source")
        new_source = enclave_meta["weights_source"]

        weights_changed = (old_hash != new_hash) or (old_source != new_source)
        if old_hash != new_hash:
            changes["remote_trust.provider_manifest_weights_hash"] = {
                "from": old_hash,
                "to": new_hash,
            }
        if old_source != new_source:
            changes["remote_trust.provider_manifest_weights_source"] = {
                "from": old_source,
                "to": new_source,
            }
        if model.get("upstream") != enclave_meta["upstream"]:
            changes["upstream"] = {
                "from": model.get("upstream"),
                "to": enclave_meta["upstream"],
            }

        if weights_changed:
            sim_model = copy.deepcopy(model)
            demote_changes = _demote_routing_and_preserve_evidence(sim_model, new_status="candidate")
            if demote_changes:
                action = "demote_weights_changed"
                changes.update(demote_changes)
                notes.append(
                    "Demoted to candidate/blocked because provider_manifest_weights_hash or source changed"
                )

        # Check enclave_repo / enclave_tag metadata
        if model.get("enclave_repo") not in (None, enclave_repo):
            changes["enclave_repo"] = {"from": model.get("enclave_repo"), "to": enclave_repo}
        if model.get("enclave_tag") != enclave_tag:
            changes["enclave_tag"] = {"from": model.get("enclave_tag"), "to": enclave_tag}

        # Check optional pricing in /v1/models (missing optional fields never erase existing values)
        raw_pricing = o_entry.get("pricing")
        if isinstance(raw_pricing, dict):
            cur_pricing = rt.get("pricing_per_m_tokens") or {}
            in_val = raw_pricing.get("inputTokenPricePer1M")
            out_val = raw_pricing.get("outputTokenPricePer1M")
            cached_val = raw_pricing.get("cachedInputTokenPricePer1M")
            if (
                not isinstance(in_val, bool)
                and isinstance(in_val, (int, float))
                and float(in_val) >= 0
                and cur_pricing.get("input") != float(in_val)
            ):
                changes["remote_trust.pricing_per_m_tokens.input"] = {
                    "from": cur_pricing.get("input"),
                    "to": float(in_val),
                }
            if (
                not isinstance(out_val, bool)
                and isinstance(out_val, (int, float))
                and float(out_val) >= 0
                and cur_pricing.get("output") != float(out_val)
            ):
                changes["remote_trust.pricing_per_m_tokens.output"] = {
                    "from": cur_pricing.get("output"),
                    "to": float(out_val),
                }
            if (
                not isinstance(cached_val, bool)
                and isinstance(cached_val, (int, float))
                and float(cached_val) >= 0
                and cur_pricing.get("cached_input") != float(cached_val)
            ):
                changes["remote_trust.pricing_per_m_tokens.cached_input"] = {
                    "from": cur_pricing.get("cached_input"),
                    "to": float(cached_val),
                }

        # Check optional context_window in /v1/models (update when present as a valid positive int; preserve existing when absent/invalid)
        oai_ctx = o_entry.get("context_window")
        if (
            not isinstance(oai_ctx, bool)
            and isinstance(oai_ctx, int)
            and oai_ctx > 0
            and model.get("context_window") != oai_ctx
        ):
            changes["context_window"] = {"from": model.get("context_window"), "to": oai_ctx}

        # Check deprecation status in /v1/models
        if o_entry.get("deprecated") is True:
            if model.get("deprecated") is not True:
                changes["deprecated"] = {"from": model.get("deprecated"), "to": True}
            dep_date = o_entry.get("deprecationDate")
            if isinstance(dep_date, str) and ISO_DATE_RE.match(dep_date.strip()):
                if model.get("deprecation_date") != dep_date.strip():
                    changes["deprecation_date"] = {
                        "from": model.get("deprecation_date"),
                        "to": dep_date.strip(),
                    }
            if (model.get("routing") or {}).get("private_attested") == "cleared":
                sim_model = copy.deepcopy(model)
                demote_changes = _demote_routing_and_preserve_evidence(sim_model, new_status="candidate")
                changes.update(demote_changes)
                notes.append("Demoted routing.private_attested to blocked due to upstream deprecation")

        if changes:
            report.updated_models.append(
                ModelDriftItem(
                    model_id=model_id,
                    served_model_id=served_id,
                    action=action,
                    changes=changes,
                    notes=notes,
                    weights_changed=weights_changed,
                )
            )

    # Discover new coding models (type == 'chat' and tool_calling == True and healthy >= 1)
    if discover_new_coding_models:
        ignore_set = (
            set(DEFAULT_IGNORED_SERVED_IDS)
            if ignored_served_ids is None
            else set(ignored_served_ids)
        )
        for served_id in sorted(oai_map.keys()):
            if served_id in registered_served_ids or served_id in ignore_set:
                continue
            o_entry = oai_map[served_id]
            if o_entry.get("type") != "chat" or o_entry.get("tool_calling") is not True:
                continue
            if o_entry.get("deprecated") is True:
                continue
            r_entry = router_map.get(served_id)
            if r_entry is None:
                continue
            healthy_count = int((r_entry.get("verification") or {}).get("healthy") or 0)
            enclave_repo = str(r_entry.get("repo") or "").strip()
            enclave_tag = str(r_entry.get("tag") or "").strip()
            if healthy_count < 1 or not enclave_tag:
                continue
            candidate_id = served_id if served_id.startswith("tinfoil-") else f"tinfoil-{served_id}"
            if candidate_id in all_existing_by_id:
                colliding = all_existing_by_id[candidate_id]
                raise CatalogSyncError(
                    f"Discovered Tinfoil model '{served_id}' (candidate id '{candidate_id}') collides with "
                    f"existing non-Tinfoil catalog entry id='{colliding.get('id')}' "
                    f"(repo='{colliding.get('repo')}', runtime='{colliding.get('runtime')}')"
                )
            if served_id in all_existing_by_repo:
                colliding_r = all_existing_by_repo[served_id]
                raise CatalogSyncError(
                    f"Discovered Tinfoil model '{served_id}' collides with existing non-Tinfoil catalog entry "
                    f"id='{colliding_r.get('id')}' sharing repo='{served_id}'"
                )
            enclave_meta = _resolve_verified_enclave_meta(
                served_id,
                enclave_repo,
                enclave_tag,
                r_entry.get("host_code_tags"),
            )
            candidate_entry = _build_candidate_model_entry(
                served_id,
                r_entry,
                o_entry,
                enclave_meta,
                today_str,
            )
            report.new_models.append(candidate_entry)

    return report


_YAML_RESERVED_SCALARS = frozenset(
    {
        "null",
        "~",
        "true",
        "false",
        "yes",
        "no",
        "on",
        "off",
        "y",
        "n",
        ".inf",
        "+.inf",
        "-.inf",
        ".nan",
        "=",
        "<<",
    }
)


def _needs_yaml_quoting(val: str) -> bool:
    if not val:
        return True
    if val != val.strip():
        return True
    if val.lower() in _YAML_RESERVED_SCALARS:
        return True
    if val[0] in ("'", '"', "{", "}", "[", "]", "&", "*", "!", "|", ">", "%", "@", "`", ",", "?", "-", ":"):
        return True
    if any(ch in val for ch in ("\t", "\n", "\r", "#")):
        return True
    if ": " in val or val.endswith(":"):
        return True
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:[Tt ].*)?", val):
        return True
    if re.fullmatch(r"[+-]?(?:\d[\d_]*|\d*\.\d[\d_]*|\d[\d_]*\.|[0-9a-fA-FxXoObB_]+)", val):
        return True
    if re.fullmatch(r"[+-]?\d+(?::[0-5]?\d)+(?:\.\d+)?", val):
        return True
    return False


def _format_yaml_scalar(val: Any) -> str:
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        return str(val)
    if isinstance(val, float):
        if not math.isfinite(val):
            raise ValueError(f"Non-finite float not allowed in YAML: {val!r}")
        return str(val)
    if isinstance(val, datetime.date) and not isinstance(val, datetime.datetime):
        return json.dumps(val.isoformat())
    s = str(val)
    if _needs_yaml_quoting(s):
        return json.dumps(s, ensure_ascii=False)
    return s


def _dump_yaml_node(node: Any, indent: int) -> list[str]:
    prefix = " " * indent
    lines: list[str] = []
    if isinstance(node, dict):
        if not node:
            return [f"{prefix}{{}}"]
        for k, v in node.items():
            key_str = str(k)
            if _needs_yaml_quoting(key_str):
                key_str = json.dumps(key_str, ensure_ascii=False)
            if isinstance(v, str) and "\n" in v:
                has_trailing_nl = v.endswith("\n")
                indicator = "|" if has_trailing_nl else "|-"
                lines.append(f"{prefix}{key_str}: {indicator}")
                body = v[:-1] if has_trailing_nl else v
                for bline in body.split("\n"):
                    if bline:
                        lines.append(f"{' ' * (indent + 2)}{bline}")
                    else:
                        lines.append("")
            elif isinstance(v, dict):
                if not v:
                    lines.append(f"{prefix}{key_str}: {{}}")
                else:
                    lines.append(f"{prefix}{key_str}:")
                    lines.extend(_dump_yaml_node(v, indent + 2))
            elif isinstance(v, list):
                if not v:
                    lines.append(f"{prefix}{key_str}: []")
                else:
                    lines.append(f"{prefix}{key_str}:")
                    lines.extend(_dump_yaml_node(v, indent + 2))
            else:
                lines.append(f"{prefix}{key_str}: {_format_yaml_scalar(v)}")
        return lines

    if isinstance(node, list):
        if not node:
            return [f"{prefix}[]"]
        for idx, item in enumerate(node):
            if isinstance(item, dict) and item:
                items_iter = list(item.items())
                first_k, first_v = items_iter[0]
                fk_str = str(first_k)
                if _needs_yaml_quoting(fk_str):
                    fk_str = json.dumps(fk_str, ensure_ascii=False)
                if isinstance(first_v, (dict, list)) and first_v:
                    lines.append(f"{prefix}- {fk_str}:")
                    lines.extend(_dump_yaml_node(first_v, indent + 4))
                elif isinstance(first_v, str) and "\n" in first_v:
                    has_trailing_nl = first_v.endswith("\n")
                    indicator = "|" if has_trailing_nl else "|-"
                    lines.append(f"{prefix}- {fk_str}: {indicator}")
                    body = first_v[:-1] if has_trailing_nl else first_v
                    for bline in body.split("\n"):
                        lines.append(f"{' ' * (indent + 4)}{bline}" if bline else "")
                else:
                    lines.append(f"{prefix}- {fk_str}: {_format_yaml_scalar(first_v)}")
                rest_dict = dict(items_iter[1:])
                if rest_dict:
                    lines.extend(_dump_yaml_node(rest_dict, indent + 2))
                if indent == 2 and idx + 1 < len(node):
                    lines.append("")
            else:
                lines.append(f"{prefix}- {_format_yaml_scalar(item)}")
        return lines

    return [f"{prefix}{_format_yaml_scalar(node)}"]


def extract_leading_yaml_comments(raw_text: str) -> str:
    comment_lines: list[str] = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            comment_lines.append(line)
        else:
            break
    while comment_lines and comment_lines[-1].strip() == "":
        comment_lines.pop()
    if not comment_lines:
        return ""
    return "\n".join(comment_lines) + "\n\n"


def dump_models_yaml(data: dict[str, Any], header_comments: str = "") -> str:
    body_lines = _dump_yaml_node(data, 0)
    rendered = header_comments + "\n".join(body_lines) + "\n"
    mini_reloaded = _MiniYamlParser(rendered).parse()
    if mini_reloaded != data:
        raise CatalogSyncError("Rendered models.yaml failed _MiniYamlParser round-trip parity check")
    try:
        import yaml as pyyaml  # type: ignore[import-untyped]
    except ImportError:
        pyyaml = None
    if pyyaml is not None:
        py_reloaded = pyyaml.safe_load(rendered)
        if py_reloaded != data:
            raise CatalogSyncError("Rendered models.yaml failed PyYAML round-trip parity check")
    return rendered


def _get_nested_field_value(target: dict[str, Any], field_path: str) -> Any:
    if field_path == "status":
        return target.get("status")
    if field_path == "routing.private_attested":
        return (target.get("routing") or {}).get("private_attested")
    if field_path == "eval_evidence_artifact":
        ev = target.get("eval_evidence_artifact")
        if ev is None and isinstance(target.get("routing"), dict):
            ev = target["routing"].get("eval_evidence_artifact")
        return ev
    cur: Any = target
    for p in field_path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def apply_catalog_healing(
    models_path: Path,
    report: CatalogDriftReport,
    *,
    quarantine_disagreements: bool = False,
    append_new_models: bool = True,
) -> dict[str, Any]:
    """Apply a validated CatalogDriftReport to models.yaml atomically after endpoint validation."""
    if report.disagreements and not quarantine_disagreements:
        reasons = "; ".join(d.reason for d in report.disagreements)
        raise CatalogSyncError(
            f"Refusing to mutate {models_path} while primary feeds disagree: {reasons}. "
            "Pass --quarantine-disagreements to conservatively block routing on disagreeing entries."
        )

    if not models_path.exists():
        raise CatalogSyncError(f"models.yaml not found at {models_path}")

    with catalog_file_lock(models_path):
        initial_bytes = models_path.read_bytes()
        raw_text = initial_bytes.decode("utf-8")
        header_comments = extract_leading_yaml_comments(raw_text)
        data = safe_load(raw_text)
        if not isinstance(data, dict) or not isinstance(data.get("models"), list):
            raise CatalogSyncError(f"Expected top-level 'models' list in {models_path}")

        current_digest = compute_models_data_digest(data)
        if report.base_catalog_sha256 is not None and current_digest != report.base_catalog_sha256:
            raise CatalogSyncError(
                f"Refusing to apply stale catalog drift report to {models_path}: "
                f"catalog digest changed from {report.base_catalog_sha256[:12]} to {current_digest[:12]}"
            )

        models_list: list[dict[str, Any]] = data["models"]
        by_id: dict[str, dict[str, Any]] = {
            str(m.get("id")): m for m in models_list if isinstance(m, dict) and m.get("id")
        }

        # Verify all precondition 'from' values against unmodified catalog entries before mutating
        for item in report.updated_models + report.removed_models:
            target = by_id.get(item.model_id)
            if target is None:
                raise CatalogSyncError(
                    f"Refusing to apply catalog drift report: model '{item.model_id}' not found in {models_path}"
                )
            for field_path, diff in item.changes.items():
                expected_from = diff.get("from")
                actual_cur = _get_nested_field_value(target, field_path)
                if actual_cur != expected_from:
                    raise CatalogSyncError(
                        f"Refusing to apply stale catalog drift report for '{item.model_id}': "
                        f"field '{field_path}' is {actual_cur!r}, expected {expected_from!r}"
                    )

        for item in report.updated_models + report.removed_models:
            target = by_id[item.model_id]
            has_weight_change = (
                item.weights_changed
                or item.action == "demote_weights_changed"
                or "remote_trust.provider_manifest_weights_hash" in item.changes
                or "remote_trust.provider_manifest_weights_source" in item.changes
            )
            if item.action == "archive_removed":
                _demote_routing_and_preserve_evidence(target, new_status="archived")
            elif item.action == "demote_zero_health" or has_weight_change:
                _demote_routing_and_preserve_evidence(target, new_status="candidate")

            for field_path, diff in item.changes.items():
                new_val = diff.get("to")
                if field_path in ("status", "routing.private_attested", "eval_evidence_artifact"):
                    if field_path == "status":
                        if not has_weight_change or new_val in ("candidate", "archived"):
                            target["status"] = new_val
                    elif field_path == "routing.private_attested":
                        if not has_weight_change or new_val == "blocked":
                            target.setdefault("routing", {})["private_attested"] = new_val
                    elif field_path == "eval_evidence_artifact" and new_val is None:
                        _demote_routing_and_preserve_evidence(
                            target, new_status=str(target.get("status") or "candidate")
                        )
                    continue
                parts = field_path.split(".")
                cur: dict[str, Any] = target
                for p in parts[:-1]:
                    nxt = cur.get(p)
                    if not isinstance(nxt, dict):
                        nxt = {}
                        cur[p] = nxt
                    cur = nxt
                cur[parts[-1]] = new_val
            target["verified_date"] = report.observed_date

        if report.disagreements and quarantine_disagreements:
            for d in report.disagreements:
                target = by_id.get(d.model_id)
                if target is not None:
                    _demote_routing_and_preserve_evidence(target, new_status="candidate")

        if append_new_models:
            by_repo: dict[str, dict[str, Any]] = {
                str(m.get("repo")).strip(): m
                for m in models_list
                if isinstance(m, dict) and str(m.get("repo") or "").strip()
            }
            for new_entry in report.new_models:
                new_id = str(new_entry.get("id") or "").strip()
                new_repo = str(new_entry.get("repo") or "").strip()
                if not new_id:
                    raise CatalogSyncError("Discovered candidate model entry is missing 'id'")
                if new_id in by_id:
                    colliding = by_id[new_id]
                    raise CatalogSyncError(
                        f"Cannot append discovered candidate model '{new_id}': ID already exists in {models_path} "
                        f"(existing repo='{colliding.get('repo')}', runtime='{colliding.get('runtime')}')"
                    )
                if new_repo and new_repo in by_repo:
                    colliding = by_repo[new_repo]
                    raise CatalogSyncError(
                        f"Cannot append discovered candidate model '{new_id}': repo '{new_repo}' already exists in {models_path} "
                        f"(existing id='{colliding.get('id')}', runtime='{colliding.get('runtime')}')"
                    )
                models_list.append(copy.deepcopy(new_entry))
                by_id[new_id] = models_list[-1]
                if new_repo:
                    by_repo[new_repo] = models_list[-1]

        # Validate every model entry in the resulting catalog before writing
        for m in models_list:
            try:
                resolve_endpoint(m, require_api_key=False)
            except RegistryError as exc:
                raise CatalogSyncError(
                    f"Healed catalog failed endpoint validation for model '{m.get('id')}': {exc}"
                ) from exc

        rendered = dump_models_yaml(data, header_comments)
        parent_dir = models_path.parent
        fd, tmp_path_str = tempfile.mkstemp(
            prefix=".models-sync-", suffix=".yaml", dir=str(parent_dir)
        )
        tmp_path = Path(tmp_path_str)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(rendered)
                handle.flush()
                os.fsync(handle.fileno())
            if models_path.read_bytes() != initial_bytes:
                raise CatalogSyncError(
                    f"Aborting catalog update: {models_path} was modified concurrently outside catalog_file_lock during validation"
                )
            os.replace(str(tmp_path), str(models_path))
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

        return data


# --- Trial Spend & Completeness Accounting (PLAN-R2-MAJOR-2, PLAN-R3-MAJOR-1) ---

@dataclass(frozen=True)
class StepReservationSpec:
    step_name: str
    step_kind: str  # "eval" or "smoke"
    expected_suite_requests: int
    expected_probe_requests: int
    reserved_input_tokens: int
    reserved_output_tokens: int

    @property
    def expected_total_requests(self) -> int:
        return self.expected_suite_requests + self.expected_probe_requests

    def reserved_cost_usd(self, input_price_per_m: float, output_price_per_m: float) -> float:
        return (
            self.reserved_input_tokens * (input_price_per_m / 1_000_000.0)
            + self.reserved_output_tokens * (output_price_per_m / 1_000_000.0)
        )


PHASE2_STEP_RESERVATIONS: dict[str, StepReservationSpec] = {
    "sanity": StepReservationSpec(
        step_name="sanity",
        step_kind="eval",
        expected_suite_requests=1,
        expected_probe_requests=1,
        reserved_input_tokens=200,
        reserved_output_tokens=140,
    ),
    "v1": StepReservationSpec(
        step_name="v1",
        step_kind="eval",
        expected_suite_requests=10,
        expected_probe_requests=1,
        reserved_input_tokens=31100,
        reserved_output_tokens=7080,
    ),
    "tools": StepReservationSpec(
        step_name="tools",
        step_kind="eval",
        expected_suite_requests=4,
        expected_probe_requests=2,
        reserved_input_tokens=2500,
        reserved_output_tokens=2200,
    ),
    "opencode-smoke": StepReservationSpec(
        step_name="opencode-smoke",
        step_kind="smoke",
        expected_suite_requests=3,
        expected_probe_requests=0,
        reserved_input_tokens=4500,
        reserved_output_tokens=768,
    ),
}


@dataclass(frozen=True)
class StepAccountingResult:
    step_name: str
    run_dir: str
    accounting_complete: bool
    observed_requests: int
    observed_input_tokens: int
    observed_output_tokens: int
    charged_requests: int
    charged_input_tokens: int
    charged_output_tokens: int
    charged_cost_usd: float
    reason: str | None = None


@dataclass(frozen=True)
class PreStepBudgetDecision:
    allowed: bool
    cumulative_charged_requests: int
    cumulative_charged_cost_usd: float
    next_step_expected_requests: int
    next_step_reserved_cost_usd: float
    projected_requests: int
    projected_cost_usd: float
    budget_ceiling_usd: float
    max_chat_requests: int
    reason: str | None = None


def evaluate_step_accounting(
    run_dir: Path,
    spec: StepReservationSpec,
    *,
    input_price_per_m: float,
    output_price_per_m: float,
) -> StepAccountingResult:
    """Evaluate token/request accounting for an eval or opencode-smoke run directory, retaining full reservations on incomplete usage."""
    if spec.step_kind == "eval":
        metrics_path = run_dir / "metrics.json"
        if not metrics_path.is_file():
            cost = spec.reserved_cost_usd(input_price_per_m, output_price_per_m)
            return StepAccountingResult(
                step_name=spec.step_name,
                run_dir=str(run_dir),
                accounting_complete=False,
                observed_requests=0,
                observed_input_tokens=0,
                observed_output_tokens=0,
                charged_requests=spec.expected_total_requests,
                charged_input_tokens=spec.reserved_input_tokens,
                charged_output_tokens=spec.reserved_output_tokens,
                charged_cost_usd=cost,
                reason="metrics.json is missing",
            )
        try:
            metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        except Exception as exc:
            cost = spec.reserved_cost_usd(input_price_per_m, output_price_per_m)
            return StepAccountingResult(
                step_name=spec.step_name,
                run_dir=str(run_dir),
                accounting_complete=False,
                observed_requests=0,
                observed_input_tokens=0,
                observed_output_tokens=0,
                charged_requests=spec.expected_total_requests,
                charged_input_tokens=spec.reserved_input_tokens,
                charged_output_tokens=spec.reserved_output_tokens,
                charged_cost_usd=cost,
                reason=f"metrics.json is unreadable: {exc}",
            )

        ta = (metrics.get("token_accounting") if isinstance(metrics, dict) else None) or {}
        suite_reqs = int(ta.get("suite_requests") or 0)
        suite_toks = ta.get("suite_tokens") if isinstance(ta.get("suite_tokens"), dict) else {}
        suite_prompt = int(suite_toks.get("prompt") or 0)
        suite_comp = int(suite_toks.get("completion") or 0)

        probe_reqs = int(ta.get("timing_probe_requests") or 0)
        probe_toks = (
            ta.get("timing_probe_tokens")
            if isinstance(ta.get("timing_probe_tokens"), dict)
            else {}
        )
        probe_prompt = int(probe_toks.get("prompt") or 0)
        probe_comp = int(probe_toks.get("completion") or 0)
        probe_fallback = bool(probe_toks.get("used_fallback_reservation", True))

        tot_toks = (
            ta.get("total_eval_tokens")
            if isinstance(ta.get("total_eval_tokens"), dict)
            else {}
        )
        obs_reqs = int(ta.get("total_eval_requests") or (suite_reqs + probe_reqs))
        obs_in = int(tot_toks.get("prompt") or (suite_prompt + probe_prompt))
        obs_out = int(tot_toks.get("completion") or (suite_comp + probe_comp))

        complete = (
            suite_reqs >= spec.expected_suite_requests
            and suite_prompt > 0
            and suite_comp > 0
            and probe_reqs >= spec.expected_probe_requests
            and not probe_fallback
            and probe_prompt > 0
            and probe_comp > 0
        )
        if complete:
            charged_reqs = obs_reqs
            charged_in = obs_in
            charged_out = obs_out
            reason = None
        else:
            charged_reqs = max(obs_reqs, spec.expected_total_requests)
            charged_in = max(obs_in, spec.reserved_input_tokens)
            charged_out = max(obs_out, spec.reserved_output_tokens)
            reason = (
                "Incomplete or zero-filled eval token accounting in metrics.json; "
                "retained step reservation"
            )
        charged_cost = (
            charged_in * (input_price_per_m / 1_000_000.0)
            + charged_out * (output_price_per_m / 1_000_000.0)
        )
        return StepAccountingResult(
            step_name=spec.step_name,
            run_dir=str(run_dir),
            accounting_complete=complete,
            observed_requests=obs_reqs,
            observed_input_tokens=obs_in,
            observed_output_tokens=obs_out,
            charged_requests=charged_reqs,
            charged_input_tokens=charged_in,
            charged_output_tokens=charged_out,
            charged_cost_usd=charged_cost,
            reason=reason,
        )

    if spec.step_kind == "smoke":
        summary_path = run_dir / "summary.json"
        if not summary_path.is_file():
            cost = spec.reserved_cost_usd(input_price_per_m, output_price_per_m)
            return StepAccountingResult(
                step_name=spec.step_name,
                run_dir=str(run_dir),
                accounting_complete=False,
                observed_requests=0,
                observed_input_tokens=0,
                observed_output_tokens=0,
                charged_requests=spec.expected_total_requests,
                charged_input_tokens=spec.reserved_input_tokens,
                charged_output_tokens=spec.reserved_output_tokens,
                charged_cost_usd=cost,
                reason="summary.json is missing",
            )
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception as exc:
            cost = spec.reserved_cost_usd(input_price_per_m, output_price_per_m)
            return StepAccountingResult(
                step_name=spec.step_name,
                run_dir=str(run_dir),
                accounting_complete=False,
                observed_requests=0,
                observed_input_tokens=0,
                observed_output_tokens=0,
                charged_requests=spec.expected_total_requests,
                charged_input_tokens=spec.reserved_input_tokens,
                charged_output_tokens=spec.reserved_output_tokens,
                charged_cost_usd=cost,
                reason=f"summary.json is unreadable: {exc}",
            )

        ta = (summary.get("token_accounting") if isinstance(summary, dict) else None) or {}
        chat_reqs_raw = ta.get("forwarded_chat_requests")
        obs_http = (
            ta.get("observed_http_tokens")
            if isinstance(ta.get("observed_http_tokens"), dict)
            else {}
        )
        missing_usage_raw = obs_http.get("requests_missing_usage")
        obs_prompt = int(obs_http.get("prompt") or 0)
        obs_comp = int(obs_http.get("completion") or 0)

        res_ceil = (
            ta.get("reserved_ceiling_tokens")
            if isinstance(ta.get("reserved_ceiling_tokens"), dict)
            else {}
        )
        res_in = int(res_ceil.get("input") or 0)
        res_out = int(res_ceil.get("output") or 0)

        chat_reqs = int(chat_reqs_raw) if isinstance(chat_reqs_raw, int) and not isinstance(chat_reqs_raw, bool) else 0
        missing_usage = (
            int(missing_usage_raw)
            if isinstance(missing_usage_raw, int) and not isinstance(missing_usage_raw, bool)
            else -1
        )

        complete = (
            chat_reqs >= 1
            and missing_usage == 0
            and obs_prompt > 0
            and obs_comp > 0
        )
        if complete:
            charged_reqs = chat_reqs
            charged_in = obs_prompt
            charged_out = obs_comp
            reason = None
        else:
            charged_reqs = max(chat_reqs, spec.expected_total_requests)
            charged_in = max(obs_prompt, res_in, spec.reserved_input_tokens)
            charged_out = max(obs_comp, res_out, spec.reserved_output_tokens)
            reason = (
                "Incomplete or missing usage in opencode-smoke summary.json; "
                "retained maximum of observed, producer ceiling, and step reservation"
            )
        charged_cost = (
            charged_in * (input_price_per_m / 1_000_000.0)
            + charged_out * (output_price_per_m / 1_000_000.0)
        )
        return StepAccountingResult(
            step_name=spec.step_name,
            run_dir=str(run_dir),
            accounting_complete=complete,
            observed_requests=chat_reqs,
            observed_input_tokens=obs_prompt,
            observed_output_tokens=obs_comp,
            charged_requests=charged_reqs,
            charged_input_tokens=charged_in,
            charged_output_tokens=charged_out,
            charged_cost_usd=charged_cost,
            reason=reason,
        )

    raise CatalogSyncError(f"Unsupported step_kind '{spec.step_kind}'")


def check_pre_step_budget(
    completed_steps: list[StepAccountingResult],
    next_spec: StepReservationSpec,
    *,
    input_price_per_m: float,
    output_price_per_m: float,
    budget_ceiling_usd: float = 1.00,
    max_chat_requests: int = 40,
) -> PreStepBudgetDecision:
    cum_reqs = sum(s.charged_requests for s in completed_steps)
    cum_cost = sum(s.charged_cost_usd for s in completed_steps)
    next_reqs = next_spec.expected_total_requests
    next_cost = next_spec.reserved_cost_usd(input_price_per_m, output_price_per_m)
    proj_reqs = cum_reqs + next_reqs
    proj_cost = cum_cost + next_cost

    if proj_cost > budget_ceiling_usd + 1e-9:
        return PreStepBudgetDecision(
            allowed=False,
            cumulative_charged_requests=cum_reqs,
            cumulative_charged_cost_usd=cum_cost,
            next_step_expected_requests=next_reqs,
            next_step_reserved_cost_usd=next_cost,
            projected_requests=proj_reqs,
            projected_cost_usd=proj_cost,
            budget_ceiling_usd=budget_ceiling_usd,
            max_chat_requests=max_chat_requests,
            reason=(
                f"Projected cost ${proj_cost:.4f} exceeds budget ceiling ${budget_ceiling_usd:.4f}"
            ),
        )
    if proj_reqs > max_chat_requests:
        return PreStepBudgetDecision(
            allowed=False,
            cumulative_charged_requests=cum_reqs,
            cumulative_charged_cost_usd=cum_cost,
            next_step_expected_requests=next_reqs,
            next_step_reserved_cost_usd=next_cost,
            projected_requests=proj_reqs,
            projected_cost_usd=proj_cost,
            budget_ceiling_usd=budget_ceiling_usd,
            max_chat_requests=max_chat_requests,
            reason=(
                f"Projected chat requests ({proj_reqs}) exceed session max_chat_requests ({max_chat_requests})"
            ),
        )
    return PreStepBudgetDecision(
        allowed=True,
        cumulative_charged_requests=cum_reqs,
        cumulative_charged_cost_usd=cum_cost,
        next_step_expected_requests=next_reqs,
        next_step_reserved_cost_usd=next_cost,
        projected_requests=proj_reqs,
        projected_cost_usd=proj_cost,
        budget_ceiling_usd=budget_ceiling_usd,
        max_chat_requests=max_chat_requests,
        reason=None,
    )


CATALOG_DRIFT_ISSUE_TITLE = "[catalog-drift] Upstream model catalog drift detected"
GITHUB_BOT_AUTHOR_LOGINS: frozenset[str] = frozenset(
    {"app/github-actions", "github-actions[bot]", "github-actions"}
)


def format_human_drift_report(report: CatalogDriftReport, *, applied: bool = False) -> str:
    if not report.has_drift:
        return f"Catalog check ({report.observed_date}): clean (0 drift items)."

    lines: list[str] = []
    header_verb = (
        "Applied self-healing catalog updates" if applied else "Detected catalog drift"
    )
    lines.append(f"{header_verb} ({report.observed_date}):")

    for item in report.updated_models:
        lines.append(f"  [update:{item.action}] {item.model_id} (served={item.served_model_id})")
        for k, diff in sorted(item.changes.items()):
            lines.append(f"    - {k}: {diff.get('from')!r} -> {diff.get('to')!r}")
        for note in item.notes:
            lines.append(f"    * note: {note}")

    for m in report.new_models:
        rt = m.get("remote_trust") or {}
        pricing = rt.get("pricing_per_m_tokens") or {}
        lines.append(
            f"  [new:candidate] {m.get('id')} (served={m.get('repo')}, "
            f"upstream={m.get('upstream')}, "
            f"hash={rt.get('provider_manifest_weights_hash')}, "
            f"pricing=${pricing.get('input')}/${pricing.get('output')} per 1M)"
        )

    for item in report.removed_models:
        lines.append(f"  [removed:{item.action}] {item.model_id} (served={item.served_model_id})")
        for k, diff in sorted(item.changes.items()):
            lines.append(f"    - {k}: {diff.get('from')!r} -> {diff.get('to')!r}")

    for d in report.disagreements:
        lines.append(
            f"  [disagreement] {d.model_id} (served={d.served_model_id}): {d.reason}"
        )

    return "\n".join(lines)


def _code_fence_for(*payloads: str) -> str:
    longest = 2
    for payload in payloads:
        for match in re.finditer(r"`+", payload):
            run_len = len(match.group(0))
            if run_len > longest:
                longest = run_len
    return "`" * (longest + 1)


def render_github_issue_body(
    report_dict: dict[str, Any],
    *,
    exit_code: int,
    human_output: str,
    run_url: str | None = None,
    checked_ref: str | None = None,
    checked_sha: str | None = None,
) -> str:
    check_status = str(report_dict.get("check_status") or "")
    observed_date = str(report_dict.get("observed_date") or "")
    base_digest = str(report_dict.get("base_catalog_sha256") or "")
    json_payload = json.dumps(report_dict, indent=2, sort_keys=True)
    clean_human = human_output.rstrip()
    fence = _code_fence_for(clean_human, json_payload)

    if check_status == "disagreement" or (exit_code == 1 and report_dict.get("disagreements")):
        heading = "## Upstream Catalog Feed Disagreement Detected"
        summary_line = (
            "Primary upstream catalog feeds (`router_manifest` vs `/v1/models`) disagreed. "
            "No automatic catalog mutation was performed."
        )
    elif check_status == "drift" or exit_code == 2 or report_dict.get("has_drift"):
        heading = "## Upstream Model Catalog Drift Detected"
        summary_line = (
            "The scheduled `sync-model-catalog --check` job detected upstream model metadata, "
            "pricing, enclave tag/hash, deprecation, or candidate model drift against `models.yaml`."
        )
    else:
        heading = "## Upstream Model Catalog Check: Clean"
        summary_line = "No catalog drift detected (`0` drift items)."

    meta_lines: list[str] = [
        f"- **Observed date**: `{observed_date}`",
        f"- **Check status**: `{check_status or ('clean' if exit_code == 0 else 'drift')}` (exit code `{exit_code}`)",
    ]
    if base_digest:
        meta_lines.append(f"- **Catalog SHA-256**: `{base_digest}`")
    if checked_ref:
        meta_lines.append(f"- **Checked ref**: `{checked_ref}`")
    if checked_sha:
        meta_lines.append(f"- **Checked commit**: `{checked_sha}`")
    if run_url:
        meta_lines.append(f"- **Workflow run**: {run_url}")

    body_parts = [
        heading,
        "",
        summary_line,
        "",
        "\n".join(meta_lines),
        "",
        "### Human-Readable Drift Summary",
        "",
        f"{fence}text",
        clean_human,
        fence,
        "",
        "### Local Remediation Steps (in `lab/`)",
        "",
        "```bash",
        "cd lab",
        "./scripts/sync-model-catalog --check",
        "./scripts/sync-model-catalog --apply",
        ".venv/bin/python ./scripts/generate-eval-manifest --check",
        ".venv/bin/python -m unittest discover -s tests -v",
        "```",
        "",
        "> Note: Newly discovered models are scaffolded as `status: candidate` with `routing.private_attested: blocked` and require operator-approved 4-gate evaluation (`sanity`, `v1`, `tools`, `opencode-smoke`) before promotion.",
        "",
        "<details>",
        "<summary>Structured Drift Report JSON</summary>",
        "",
        f"{fence}json",
        json_payload,
        fence,
        "",
        "</details>",
    ]
    return "\n".join(body_parts) + "\n"


def _default_run_gh(args: list[str]) -> str:
    try:
        proc = subprocess.run(
            ["gh", *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise CatalogSyncError("GitHub CLI ('gh') is not installed or not on PATH") from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        stdout = (exc.stdout or "").strip()
        detail = stderr or stdout or f"exit status {exc.returncode}"
        raise CatalogSyncError(f"gh {' '.join(args[:2])} failed: {detail}") from exc
    return proc.stdout


def reconcile_github_drift_issue(
    *,
    repo: str,
    exit_code: int,
    json_report_path: Path,
    markdown_body_path: Path,
    is_default_branch: bool,
    expected_attempt_id: str | None = None,
    run_gh_fn: Callable[[list[str]], str] | None = None,
) -> dict[str, Any]:
    """Reconcile the single bot-owned GitHub tracking issue for catalog drift."""
    if not repo or "/" not in repo:
        raise CatalogSyncError(f"Invalid GitHub repository identifier: {repo!r}")
    if exit_code not in (0, 1, 2):
        raise CatalogSyncError(
            f"Refusing issue reconciliation for unexpected check exit code {exit_code}"
        )
    if not json_report_path.is_file():
        raise CatalogSyncError(
            f"Missing structured catalog drift report at {json_report_path} (check_rc={exit_code}); "
            "leaving GitHub issues untouched"
        )
    if not markdown_body_path.is_file():
        raise CatalogSyncError(
            f"Missing rendered Markdown issue body at {markdown_body_path} (check_rc={exit_code}); "
            "leaving GitHub issues untouched"
        )

    try:
        report_dict = json.loads(json_report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise CatalogSyncError(
            f"Malformed JSON in {json_report_path}: {exc}"
        ) from exc

    if not isinstance(report_dict, dict):
        raise CatalogSyncError(f"Expected JSON object in {json_report_path}")

    if expected_attempt_id is not None:
        actual_attempt_id = report_dict.get("attempt_id")
        if not isinstance(actual_attempt_id, str) or actual_attempt_id != expected_attempt_id:
            raise CatalogSyncError(
                f"Stale or mismatched catalog drift report at {json_report_path}: "
                f"expected attempt_id={expected_attempt_id!r}, got {actual_attempt_id!r}"
            )

    try:
        md_bytes = markdown_body_path.read_bytes()
        md_text = md_bytes.decode("utf-8")
    except Exception as exc:
        raise CatalogSyncError(
            f"Failed to read rendered Markdown issue body at {markdown_body_path}: {exc}"
        ) from exc

    expected_md_sha256 = report_dict.get("markdown_sha256")
    if not isinstance(expected_md_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_md_sha256):
        raise CatalogSyncError(
            f"Structured report at {json_report_path} is missing valid 'markdown_sha256' completion digest"
        )
    actual_md_sha256 = hashlib.sha256(md_bytes).hexdigest()
    if actual_md_sha256 != expected_md_sha256 or not md_text.endswith("</details>\n"):
        raise CatalogSyncError(
            f"Rendered Markdown issue body at {markdown_body_path} is incomplete or does not match "
            f"report 'markdown_sha256' (expected {expected_md_sha256}, got {actual_md_sha256})"
        )

    check_status = report_dict.get("check_status")
    has_drift = report_dict.get("has_drift")
    disagreements = report_dict.get("disagreements")
    if not isinstance(disagreements, list):
        raise CatalogSyncError("Invalid 'disagreements' field in structured report")

    if exit_code == 0:
        if check_status != "clean" or has_drift is not False or len(disagreements) > 0:
            raise CatalogSyncError(
                f"Inconsistent clean report state: exit_code=0, check_status={check_status!r}, "
                f"has_drift={has_drift!r}, disagreements={len(disagreements)}"
            )
    elif exit_code == 2:
        if check_status != "drift" or has_drift is not True or len(disagreements) > 0:
            raise CatalogSyncError(
                f"Inconsistent drift report state: exit_code=2, check_status={check_status!r}, "
                f"has_drift={has_drift!r}, disagreements={len(disagreements)}"
            )
    elif exit_code == 1:
        if check_status != "disagreement" or len(disagreements) == 0:
            raise CatalogSyncError(
                f"Refusing issue mutation on exit_code=1 without structured disagreement "
                f"(check_status={check_status!r})"
            )

    if not is_default_branch:
        return {
            "action": "skipped_non_default_branch",
            "issue_number": None,
            "exit_code": 1 if exit_code == 1 else 0,
        }

    gh_runner = run_gh_fn or _default_run_gh
    raw_issues = gh_runner(
        [
            "issue",
            "list",
            "--repo",
            repo,
            "--state",
            "open",
            "--app",
            "github-actions",
            "--search",
            f'"{CATALOG_DRIFT_ISSUE_TITLE}" in:title',
            "--limit",
            "100",
            "--json",
            "number,title,author",
        ]
    )
    try:
        open_issues = json.loads(raw_issues)
    except Exception as exc:
        raise CatalogSyncError(f"Failed to parse 'gh issue list' JSON output: {exc}") from exc
    if not isinstance(open_issues, list):
        raise CatalogSyncError("Expected JSON list from 'gh issue list'")

    matching_issue_number: int | None = None
    for item in open_issues:
        if not isinstance(item, dict):
            continue
        title = item.get("title")
        author = item.get("author")
        login = author.get("login") if isinstance(author, dict) else None
        number = item.get("number")
        if (
            title == CATALOG_DRIFT_ISSUE_TITLE
            and isinstance(login, str)
            and login in GITHUB_BOT_AUTHOR_LOGINS
            and isinstance(number, int)
            and not isinstance(number, bool)
        ):
            matching_issue_number = number
            break

    if matching_issue_number is None and len(open_issues) >= 100:
        raise CatalogSyncError(
            "gh issue list returned 100 filtered candidate issues without an exact match; "
            "refusing to create a duplicate tracking issue or declare clean no-op"
        )

    if check_status in ("drift", "disagreement"):
        result_exit = 0 if check_status == "drift" else 1
        if matching_issue_number is not None:
            gh_runner(
                [
                    "issue",
                    "edit",
                    str(matching_issue_number),
                    "--repo",
                    repo,
                    "--body-file",
                    str(markdown_body_path),
                ]
            )
            return {
                "action": "updated_issue",
                "issue_number": matching_issue_number,
                "exit_code": result_exit,
            }
        created_out = gh_runner(
            [
                "issue",
                "create",
                "--repo",
                repo,
                "--title",
                CATALOG_DRIFT_ISSUE_TITLE,
                "--body-file",
                str(markdown_body_path),
            ]
        ).strip()
        return {
            "action": "created_issue",
            "issue_url": created_out,
            "issue_number": None,
            "exit_code": result_exit,
        }

    # check_status == "clean"
    if matching_issue_number is not None:
        gh_runner(
            [
                "issue",
                "close",
                str(matching_issue_number),
                "--repo",
                repo,
                "--comment",
                "Catalog check passed cleanly with 0 drift items; closing tracking issue.",
            ]
        )
        return {
            "action": "closed_issue",
            "issue_number": matching_issue_number,
            "exit_code": 0,
        }

    return {
        "action": "noop_clean",
        "issue_number": None,
        "exit_code": 0,
    }
