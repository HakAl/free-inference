from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import (
    HTTPRedirectHandler,
    OpenerDirector,
    ProxyHandler,
    Request,
    build_opener,
)

from .errors import EndpointUnavailable, LocalAssistError, ModelTimeout
from .registry import (
    ATTESTED_ENCLAVE_TIERS,
    EndpointConfig,
    LOCAL_HOSTS,
    RegistryError,
    canonical_endpoint_key,
    find_model_by_id_or_repo,
    load_models,
    resolve_endpoint,
)
from .routing import MODEL_TO_REGISTRY_ID


DEFAULT_BASE_URL = "http://127.0.0.1:8080/v1"
DEFAULT_API_KEY = "none"
DEFAULT_TIMEOUT_SECONDS = 120

EOS_RE = re.compile(r"(<\|im_end\|>|<\|eot_id\|>|</s>)\s*$")
THINK_RE = re.compile(r"<think>[\s\S]*?</think>\s*")
FENCE_RE = re.compile(r"^\s*```(?:json)?\s*([\s\S]*?)\s*```\s*$", re.IGNORECASE)


@dataclass(frozen=True)
class ChatResult:
    text: str
    raw_text: str
    served_model: str | None
    usage: dict[str, Any] | None
    latency_ms: int
    finish_reason: str | None


def _lookup_registry_entry(
    model: str | None, models_list: list[dict[str, Any]] | None = None
) -> dict[str, Any] | None:
    if not model:
        return None
    registry_id = MODEL_TO_REGISTRY_ID.get(model, model)
    if models_list is not None:
        for candidate_id in (registry_id, model):
            for entry in models_list:
                if entry.get("id") == candidate_id:
                    return entry
        matches = [m for m in models_list if m.get("repo") in (registry_id, model)]
        if len(matches) == 1:
            return matches[0]
        for m in matches:
            if (m.get("runtime") or "mlx-lm") not in ("proxy", "remote"):
                return m
        return matches[0] if matches else None
    return find_model_by_id_or_repo(registry_id) or find_model_by_id_or_repo(model)


def check_private_coding_admission(endpoint: EndpointConfig) -> None:
    if not endpoint.is_local_host:
        raise LocalAssistError(
            "trust_tier_blocked",
            f"Model '{endpoint.model_id}' points to non-localhost endpoint '{endpoint.api_base_url}', which is blocked for private coding workflows.",
            details={
                "model_id": endpoint.model_id,
                "trust_tier": endpoint.trust_tier,
                "api_base_url": endpoint.api_base_url,
            },
        )
    if endpoint.trust_tier == "local":
        return
    if (
        endpoint.trust_tier in ATTESTED_ENCLAVE_TIERS
        and endpoint.runtime == "proxy"
        and endpoint.attestation_method
    ):
        if os.environ.get("LOCAL_ASSIST_ALLOW_ATTESTED_TEE") != "1":
            raise LocalAssistError(
                "trust_tier_blocked",
                f"Model '{endpoint.model_id}' uses trust_tier='{endpoint.trust_tier}'; set LOCAL_ASSIST_ALLOW_ATTESTED_TEE=1 to explicitly opt in for private coding workflows.",
                details={
                    "model_id": endpoint.model_id,
                    "trust_tier": endpoint.trust_tier,
                    "attestation_method": endpoint.attestation_method,
                    "weights_hash": endpoint.weights_hash,
                },
            )
        if (
            endpoint.routing_private_attested != "cleared"
            and os.environ.get("LOCAL_ASSIST_ALLOW_UNCLEARED_TEE") != "1"
        ):
            raise LocalAssistError(
                "routing_gate_blocked",
                f"Model '{endpoint.model_id}' is not cleared for private-attested routing "
                f"(routing.private_attested={endpoint.routing_private_attested!r}). "
                "Set routing.private_attested: cleared in models.yaml after passing the capability gate, "
                "or pass --allow-uncleared-model (or set LOCAL_ASSIST_ALLOW_UNCLEARED_TEE=1) to explicitly allow an uncleared candidate.",
                details={
                    "model_id": endpoint.model_id,
                    "trust_tier": endpoint.trust_tier,
                    "routing_private_attested": endpoint.routing_private_attested,
                },
            )
        return
    raise LocalAssistError(
        "trust_tier_blocked",
        f"Refusing to send private workspace context to model '{endpoint.model_id}' with trust_tier='{endpoint.trust_tier}'. Only 'local' (or 'enclave_weights_attested'/'enclave_runtime_attested' via localhost proxy with LOCAL_ASSIST_ALLOW_ATTESTED_TEE=1) is permitted.",
        details={
            "model_id": endpoint.model_id,
            "trust_tier": endpoint.trust_tier,
        },
    )


def _model_matches_entry(model: str, entry: dict[str, Any]) -> bool:
    registry_id = MODEL_TO_REGISTRY_ID.get(model, model)
    return entry.get("id") in (model, registry_id) or entry.get("repo") in (model, registry_id)


def _resolve_effective_connection(model: str | None = None) -> tuple[str, str]:
    try:
        all_models = load_models()
    except RegistryError as exc:
        raise LocalAssistError(
            "trust_tier_blocked",
            f"Cannot verify endpoint trust because models.yaml could not be loaded: {exc}",
            details={"model": model},
        ) from exc

    selected_entry = _lookup_registry_entry(model, all_models)
    selected_ep: EndpointConfig | None = None
    if selected_entry is not None:
        try:
            selected_ep = resolve_endpoint(selected_entry, require_api_key=False)
        except RegistryError as exc:
            raise LocalAssistError(
                "trust_tier_blocked",
                str(exc),
                details={"model": model},
            ) from exc
        check_private_coding_admission(selected_ep)

    env_url = os.environ.get("LOCAL_ASSIST_BASE_URL")
    if env_url is not None and env_url.strip() != "":
        effective_url = env_url.strip().rstrip("/")
        parsed_env = urlparse(effective_url)
        scheme = (parsed_env.scheme or "").lower()
        host = (parsed_env.hostname or "").lower()
        if (
            scheme not in ("http", "https")
            or host not in LOCAL_HOSTS
            or parsed_env.username is not None
            or parsed_env.password is not None
        ):
            raise LocalAssistError(
                "trust_tier_blocked",
                f"LOCAL_ASSIST_BASE_URL must be an http(s) localhost URL without credentials, got '{effective_url}'.",
                details={"api_base_url": effective_url},
            )
    elif selected_ep is not None:
        effective_url = selected_ep.api_base_url
    else:
        effective_url = DEFAULT_BASE_URL

    target_key = canonical_endpoint_key(effective_url)
    default_key = canonical_endpoint_key(DEFAULT_BASE_URL)
    dest_endpoints_all: list[EndpointConfig] = []
    dest_endpoints_for_model: list[EndpointConfig] = []

    for entry in all_models:
        provider = entry.get("promptfoo_provider") or {}
        raw_entry_url = (
            str(provider.get("apiBaseUrl")).rstrip("/")
            if isinstance(provider, dict) and provider.get("apiBaseUrl")
            else DEFAULT_BASE_URL
        )
        if canonical_endpoint_key(raw_entry_url) != target_key:
            continue
        try:
            dest_ep = resolve_endpoint(entry, require_api_key=False)
        except RegistryError as exc:
            raise LocalAssistError(
                "trust_tier_blocked",
                str(exc),
                details={"api_base_url": effective_url, "entry_id": entry.get("id")},
            ) from exc
        check_private_coding_admission(dest_ep)
        dest_endpoints_all.append(dest_ep)
        if model and _model_matches_entry(model, entry):
            dest_endpoints_for_model.append(dest_ep)

    effective_ep = selected_ep
    if env_url is not None and env_url.strip() != "":
        if selected_ep is not None:
            if canonical_endpoint_key(selected_ep.api_base_url) != target_key:
                if not dest_endpoints_for_model:
                    ipv6_hint = (
                        " (note: local servers bind IPv4 127.0.0.1; use 127.0.0.1 instead of [::1])"
                        if target_key[1] == "::1"
                        else ""
                    )
                    raise LocalAssistError(
                        "trust_tier_blocked",
                        f"Refusing LOCAL_ASSIST_BASE_URL override '{effective_url}' because it changes the admitted destination '{selected_ep.api_base_url}' for model '{selected_ep.model_id}'{ipv6_hint}.",
                        details={
                            "model_id": selected_ep.model_id,
                            "admitted_api_base_url": selected_ep.api_base_url,
                            "override_api_base_url": effective_url,
                        },
                    )
                effective_ep = dest_endpoints_for_model[0]
        else:
            # Model was not found in models.yaml (or model is None):
            # Only allow the fixed trusted local default (http://127.0.0.1:8080/v1)
            # unless the override URL has a positive admitted registry entry matching the request.
            if target_key != default_key:
                admitted_Pool = dest_endpoints_for_model if model else dest_endpoints_all
                if not admitted_Pool:
                    raise LocalAssistError(
                        "trust_tier_blocked",
                        f"Refusing unadmitted LOCAL_ASSIST_BASE_URL override '{effective_url}' for '{model or 'default'}'. Non-default endpoints must be registered and admitted in models.yaml.",
                        details={
                            "model": model,
                            "override_api_base_url": effective_url,
                        },
                    )
                effective_ep = admitted_Pool[0]
            elif dest_endpoints_all:
                effective_ep = (
                    dest_endpoints_for_model[0]
                    if dest_endpoints_for_model
                    else dest_endpoints_all[0]
                )
    elif dest_endpoints_for_model and effective_ep is None:
        effective_ep = dest_endpoints_for_model[0]

    env_key = os.environ.get("LOCAL_ASSIST_API_KEY")
    if env_key:
        effective_key = env_key
    elif effective_ep is not None:
        effective_key = effective_ep.api_key
    else:
        effective_key = DEFAULT_API_KEY

    return effective_url, effective_key


def base_url(model: str | None = None) -> str:
    url, _ = _resolve_effective_connection(model)
    return url


def api_key(model: str | None = None) -> str:
    _, key = _resolve_effective_connection(model)
    return key


def default_timeout_seconds() -> int:
    raw = os.environ.get("LOCAL_ASSIST_TIMEOUT_SECONDS")
    if raw is None:
        return DEFAULT_TIMEOUT_SECONDS
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS
    return max(1, value)


def normalize_text(text: str) -> str:
    text = THINK_RE.sub("", text)
    text = EOS_RE.sub("", text).strip()
    match = FENCE_RE.match(text)
    if match:
        text = match.group(1).strip()
    return text


def get_models(timeout_seconds: int = 5, *, model: str | None = None) -> list[str]:
    payload = _request_json(
        "GET",
        f"{base_url(model)}/models",
        timeout_seconds=timeout_seconds,
        model=model,
    )
    return [
        item.get("id")
        for item in payload.get("data", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    ]


def chat(
    model: str,
    system: str,
    prompt: str,
    *,
    response_format: str | None = None,
    max_tokens: int = 2048,
    temperature: float = 0.7,
    timeout_seconds: int | None = None,
) -> ChatResult:
    if timeout_seconds is None:
        timeout_seconds = default_timeout_seconds()
    body: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
    }
    if response_format == "json":
        body["response_format"] = {"type": "json_object"}

    started = time.perf_counter()
    payload = _request_json(
        "POST",
        f"{base_url(model)}/chat/completions",
        body,
        timeout_seconds,
        model=model,
    )
    latency_ms = int(round((time.perf_counter() - started) * 1000))

    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise LocalAssistError(
            "malformed_chat_response",
            "Chat response had no choices.",
            details={"response_keys": sorted(payload.keys())},
        )
    first = choices[0]
    if not isinstance(first, dict):
        raise LocalAssistError("malformed_chat_response", "Chat response choice was not an object.")
    message = first.get("message")
    if not isinstance(message, dict) or not isinstance(message.get("content"), str):
        raise LocalAssistError("malformed_chat_response", "Chat response had no message.content.")

    raw_text = message["content"]
    return ChatResult(
        text=normalize_text(raw_text),
        raw_text=raw_text,
        served_model=payload.get("model") if isinstance(payload.get("model"), str) else None,
        usage=payload.get("usage") if isinstance(payload.get("usage"), dict) else None,
        latency_ms=latency_ms,
        finish_reason=first.get("finish_reason") if isinstance(first.get("finish_reason"), str) else None,
    )


class _LoopbackNoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Request | None:
        raise HTTPError(
            req.full_url,
            code,
            f"Refusing HTTP redirect ({code}) from loopback endpoint",
            headers,
            fp,
        )


def _build_loopback_opener() -> OpenerDirector:
    return build_opener(ProxyHandler({}), _LoopbackNoRedirectHandler())


def open_loopback_http(req: Request, *, timeout: float | int) -> Any:
    parsed = urlparse(req.full_url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    if (
        scheme not in ("http", "https")
        or host not in LOCAL_HOSTS
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise URLError(f"Refusing non-loopback HTTP request to {req.full_url!r}")
    return _build_loopback_opener().open(req, timeout=timeout)


def _request_json(
    method: str,
    url: str,
    body: dict[str, Any] | None = None,
    timeout_seconds: int | None = None,
    *,
    model: str | None = None,
) -> dict[str, Any]:
    if timeout_seconds is None:
        timeout_seconds = default_timeout_seconds()
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key(model)}",
        },
        method=method,
    )
    try:
        with open_loopback_http(req, timeout=timeout_seconds) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except TimeoutError as exc:
        raise ModelTimeout(
            "timeout",
            f"Timed out calling {url}.",
            details={"url": url, "timeout_seconds": timeout_seconds},
        ) from exc
    except HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        raise LocalAssistError(
            "http_error",
            f"HTTP {exc.code} from {url}.",
            details={"url": url, "status": exc.code, "body": body_text[:2000]},
        ) from exc
    except (OSError, URLError) as exc:
        raise EndpointUnavailable(
            "endpoint_unavailable",
            f"Could not reach local model endpoint at {url}.",
            details={"url": url, "error": str(exc)},
        ) from exc
    except json.JSONDecodeError as exc:
        raise LocalAssistError(
            "invalid_json_response",
            f"Endpoint returned invalid JSON from {url}.",
            details={"url": url},
        ) from exc

