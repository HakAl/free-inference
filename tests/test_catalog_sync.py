from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from local_assist._miniyaml import _MiniYamlParser, safe_load
from local_assist.catalog_sync import (
    CATALOG_DRIFT_ISSUE_TITLE,
    PHASE2_STEP_RESERVATIONS,
    CatalogSyncError,
    apply_catalog_healing,
    catalog_file_lock,
    check_pre_step_budget,
    compute_catalog_drift,
    compute_models_data_digest,
    dump_models_yaml,
    evaluate_step_accounting,
    extract_enclave_manifest_metadata,
    parse_mpk_descriptor,
    parse_tinfoil_config_yaml,
    reconcile_github_drift_issue,
    render_github_issue_body,
    validate_router_manifest,
)
from local_assist.registry import resolve_endpoint

# Realistic published Tinfoil enclave release manifests (PLAN-MAJOR-1)
KIMI_K3_V0_0_16_YAML = """\
cvm-version: 0.14.17
cpus: 32
memory: 524288
gpus: 8

models:
  - name: "kimi-k3"
    repo: "moonshotai/Kimi-K3@a590ce090cb049c93a33dfe8c208ec652aa20503"
    mpk: "58d5e74ba6c814d4cc4511df093ede786bfbc95f766eee7a96379687ce455792_1560999034880_b59ef1dc-a9a1-5af6-8210-988d9d9d610c"
  - name: kimi-k3-dspark
    repo: RedHatAI/Kimi-K3-speculator.dspark@38a88101e0d46bb22134b9da340f381b954d40d4
    mpk: e99380779c9921cfdf2dff4ca3b711cda3cc0195e25d9b17633fd191f0ed849c_9489838080_e0171adb-1eda-58a2-aec6-b53125a821dd
    schema: 1

containers:
  - name: "kimi-k3"
    image: "ghcr.io/tinfoilsh/confidential-kimi-k3@sha256:c6d77e02dd1dba6fd81124ac5c5cbfb470d9ab0298d225c9ae83021dc79393ac" # v0.0.16
    runtime: nvidia
    gpus: all
    restart: always
    env:
      - VLLM_DISABLE_UVA: "1"
      - VLLM_USE_V2_MODEL_RUNNER: "1"
    command:
      [
        "--model",
        "/tinfoil/mpk/mpk-58d5e74ba6c814d4cc4511df093ede786bfbc95f766eee7a96379687ce455792",
        "--speculative-config",
        '{"model":"/tinfoil/mpk/mpk-e99380779c9921cfdf2dff4ca3b711cda3cc0195e25d9b17633fd191f0ed849c","method":"dspark","num_speculative_tokens":8}',
        "--kv-cache-dtype",
        "fp8",
        "--tool-call-parser",
        "kimi_k3",
        "--reasoning-parser",
        "kimi_k3",
        "--served-model-name",
        "kimi-k3",
        "--max-model-len",
        "262144",
        "--port",
        "8001",
      ]
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:8001/health"]
      interval: 30s
      timeout: 5s
"""

GPT_OSS_120B_V0_0_29_YAML = """\
cvm-version: 0.14.17
cpus: 16
memory: 65536
gpus: 1

networks:
  nvidia:
    egress: allowlist
    allow:
      - edge.urm.nvidia.com
      - openaipublic.blob.core.windows.net

models:
  - name: "gpt-oss-120b"
    repo: "openai/gpt-oss-120b@b5c939de8f754692c1647ca79fbf85e8c1e70f8a"
    mpk: "db5daddec41a3be3b51d1f4d009fb0e9b1243c2765e2bc5121acac79ab070a72_195764056064_0eefa619-50b7-588f-a072-d405fb439d36"

containers:
  - name: "gpt-oss-120b"
    image: "ghcr.io/tinfoilsh/confidential-gpt-oss-120b@sha256:020264e6f71b4f3f03eb80b4b94014ea20c8c7dad0baca7ac71ee5ced5b98ecc" # v0.0.29
    runtime: nvidia
    gpus: all
    restart: always
    command: ["--model", "/tinfoil/mpk/mpk-db5daddec41a3be3b51d1f4d009fb0e9b1243c2765e2bc5121acac79ab070a72", "--served-model-name",
      "gpt-oss-120b", "--enable-auto-tool-choice", "--tool-call-parser", "openai", "--gpu-memory-utilization", "0.95", "--scheduling-policy",
      "priority", "--enable-prompt-tokens-details", "--enable-force-include-usage", "--port", "8001"]
    networks: ["nvidia"]
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:8001/health"]
      interval: 30s
      timeout: 5s
"""

KIMI_K3_1_PRO_V0_0_3_YAML = """\
cvm-version: 0.14.17
cpus: 32
memory: 524288
gpus: 8
models:
- name: kimi-k3-1-pro
  repo: moonshotai/Kimi-K3.1-Pro@6d0a0202956796543364d666ab19c6ad1a494ee1
  mpk: 8d9c355a94e60f43598713759028328bbe795336f2700799d0ff4f3898e785e0_1561355993088_97fb42e4-45a9-5745-813b-61cb6ddb043d
  schema: 1
- name: kimi-k3-1-pro-dspark
  repo: Inferact/Kimi-K3.1-Pro-DSpark-preview@5e654fbe920278f228a89519b06b2680aa56480f
  mpk: 37e89ad461fa86eddb78d2552fc7ddcfff6a5543086c08c8d03164609b2a65ba_5373530112_7541c4f3-f223-5637-a64d-70970f59d421
  schema: 1
containers:
- name: kimi-k3-1-pro
  image: "ghcr.io/tinfoilsh/confidential-kimi-k31-pro@sha256:a74bdc3660cd5aaca97528e8e07930e7117b9f0d0cdb6dbde84745d02a09ffde" # v0.0.3
  runtime: nvidia
  read_only: true
  gpus: all
  restart: always
  command:
  - --model
  - /tinfoil/mpk/mpk-8d9c355a94e60f43598713759028328bbe795336f2700799d0ff4f3898e785e0
  - --served-model-name
  - kimi-k3-1-pro
  - --kv-cache-dtype
  - fp8
  - --tool-call-parser
  - kimi_k3
  - --reasoning-parser
  - kimi_k3
  - --max-model-len
  - '1048576'
  - --port
  - '8001'
"""

DEEPSEEK_V4_1_FLASH_YAML = """\
cvm-version: 0.14.17
cpus: 32
memory: 524288
gpus: 4
models:
- name: deepseek-v4-1-flash
  repo: deepseek-ai/DeepSeek-V4.1-Flash-1017@1bae0e1088993b9b82de08f59de5be5a34e42170
  mpk: 6c4a2b637f7f45d9e48d1bdc38c12e0454584f48d3759851f7ee4471cd90b2e7_510311071744_27a6c072-8626-550d-a130-c888e25902cb
  schema: 2
containers:
- name: deepseek-v4-1-flash
  image: "ghcr.io/tinfoilsh/confidential-deepseek-v4-1-flash@sha256:b98ca8cc6ace7ecc00eb08b5e550992175f46766a69a68508ca8227490101af5"
  runtime: nvidia
  command:
  - --model
  - /tinfoil/mpk/mpk-6c4a2b637f7f45d9e48d1bdc38c12e0454584f48d3759851f7ee4471cd90b2e7
  - --served-model-name
  - deepseek-v4-1-flash
  - --kv-cache-dtype
  - fp8
  - --tool-call-parser
  - deepseek_v41
  - --reasoning-parser
  - deepseek_v41
  - --max-model-len
  - '1048576'
"""


def _make_base_models_fixture() -> dict:
    return {
        "models": [
            {
                "id": "qwen3-1.7b-mlx-4bit",
                "status": "candidate",
                "repo": "Qwen/Qwen3-1.7B-MLX-4bit",
                "upstream": "Qwen/Qwen3-1.7B",
                "runtime": "mlx-lm",
                "serve_command": None,
                "promptfoo_provider": {
                    "id": "openai:chat:Qwen/Qwen3-1.7B-MLX-4bit",
                    "apiBaseUrl": "http://127.0.0.1:8080/v1",
                    "apiKey": "none",
                },
                "capabilities": {"tool_calling": True},
                "routing": {"private_local": "blocked"},
                "remote_trust": None,
                "context_window": 32768,
            },
            {
                "id": "tinfoil-deepseek-v4-1-flash",
                "status": "active",
                "repo": "deepseek-v4-1-flash",
                "upstream": "deepseek-ai/DeepSeek-V4.1-Flash-1017",
                "runtime": "proxy",
                "serve_command": "./bin/tinfoil-proxy --bind {host} --port {port} -e inference.tinfoil.sh --repo tinfoilsh/confidential-model-router",
                "promptfoo_provider": {
                    "id": "openai:chat:deepseek-v4-1-flash",
                    "apiBaseUrl": "http://127.0.0.1:8081/v1",
                    "apiKeyKeychainService": "free-inference.tinfoil",
                },
                "capabilities": {"tool_calling": True},
                "routing": {"private_local": "blocked", "private_attested": "cleared"},
                "eval_evidence_artifact": "docs/evals/tinfoil-deepseek-v4-1-flash.json",
                "remote_trust": {
                    "tier": "enclave_runtime_attested",
                    "attestation_method": "tinfoil-proxy-sigstore",
                    "weights_hash": None,
                    "weights_source": None,
                    "provider_manifest_weights_hash": "dmverity:sha256:6c4a2b637f7f45d9e48d1bdc38c12e0454584f48d3759851f7ee4471cd90b2e7",
                    "provider_manifest_weights_source": "deepseek-ai/DeepSeek-V4.1-Flash-1017@1bae0e1088993b9b82de08f59de5be5a34e42170",
                    "usage_policy": "provider_terms_apply",
                    "jurisdiction": "US",
                    "pricing_per_m_tokens": {"input": 0.65, "output": 1.45},
                },
                "verified_date": "2026-10-31",
                "context_window": 1048576,
                "review_notes": "Cleared after Phase 2 trial.\n",
                "eval_summary": "sanity 1/1, v1 9/10, tools 4/4",
            },
            {
                "id": "tinfoil-kimi-k3",
                "status": "candidate",
                "repo": "kimi-k3",
                "upstream": "moonshotai/Kimi-K3",
                "runtime": "proxy",
                "serve_command": "./bin/tinfoil-proxy --bind {host} --port {port} -e inference.tinfoil.sh --repo tinfoilsh/confidential-model-router",
                "promptfoo_provider": {
                    "id": "openai:chat:kimi-k3",
                    "apiBaseUrl": "http://127.0.0.1:8081/v1",
                    "apiKeyKeychainService": "free-inference.tinfoil",
                },
                "capabilities": {"tool_calling": True},
                "routing": {"private_local": "blocked", "private_attested": "blocked"},
                "remote_trust": {
                    "tier": "enclave_runtime_attested",
                    "attestation_method": "tinfoil-proxy-sigstore",
                    "weights_hash": None,
                    "weights_source": None,
                    "provider_manifest_weights_hash": "dmverity:sha256:58d5e74ba6c814d4cc4511df093ede786bfbc95f766eee7a96379687ce455792",
                    "provider_manifest_weights_source": "moonshotai/Kimi-K3@a590ce090cb049c93a33dfe8c208ec652aa20503",
                    "usage_policy": "provider_terms_apply",
                    "jurisdiction": "US",
                    "pricing_per_m_tokens": {"input": 4.0, "output": 20.0},
                },
                "verified_date": "2026-10-31",
                "context_window": 262144,
                "review_notes": "Evaluated on 2026-10-31.\n",
                "eval_summary": "sanity 1/1, v1 9/10, tools 4/4",
            },
        ]
    }


def _make_router_manifest_fixture() -> dict:
    return {
        "models": {
            "deepseek-v4-1-flash": {
                "repo": "tinfoilsh/confidential-deepseek-v4-1-flash",
                "tag": "v0.0.10+b200",
                "verification": {"configured": 6, "healthy": 6},
            },
            "kimi-k3": {
                "repo": "tinfoilsh/confidential-kimi-k3",
                "tag": "v0.0.16",
                "verification": {"configured": 1, "healthy": 1},
            },
            "kimi-k3-1-pro": {
                "repo": "tinfoilsh/confidential-kimi-k3-1-pro",
                "tag": "v0.0.3",
                "verification": {"configured": 3, "healthy": 3},
            },
        }
    }


def _make_openai_models_fixture() -> dict:
    return {
        "object": "list",
        "data": [
            {
                "id": "deepseek-v4-1-flash",
                "name": "DeepSeek V4.1 Flash",
                "type": "chat",
                "tool_calling": True,
                "multimodal": True,
                "context_window": 1048576,
                "pricing": {
                    "inputTokenPricePer1M": 0.6,
                    "cachedInputTokenPricePer1M": 0.01,
                    "outputTokenPricePer1M": 1.45,
                },
            },
            {
                "id": "kimi-k3",
                "name": "Kimi K3",
                "type": "chat",
                "tool_calling": True,
                "multimodal": True,
                "context_window": 262144,
                "deprecated": True,
                "deprecationDate": "2026-11-12",
                "pricing": {
                    "inputTokenPricePer1M": 4.0,
                    "cachedInputTokenPricePer1M": 0.6,
                    "outputTokenPricePer1M": 20.0,
                },
            },
            {
                "id": "kimi-k3-1-pro",
                "name": "Kimi K3.1 Pro",
                "type": "chat",
                "tool_calling": True,
                "multimodal": True,
                "context_window": 262144,
                "pricing": {
                    "inputTokenPricePer1M": 4.0,
                    "cachedInputTokenPricePer1M": 0.4,
                    "outputTokenPricePer1M": 20.0,
                },
            },
        ],
    }


class TestCatalogSync(unittest.TestCase):
    def test_manifest_parser_flow_sequences_and_pyyaml_parity(self) -> None:
        """PLAN-MAJOR-1: Realistic tinfoil-config.yml manifests with inline/multiline flow sequences parse identically with or without PyYAML."""
        try:
            import yaml as pyyaml  # type: ignore[import-untyped]
        except ImportError:
            pyyaml = None

        for label, raw_yaml, served_id in (
            ("kimi-k3@v0.0.16", KIMI_K3_V0_0_16_YAML, "kimi-k3"),
            ("gpt-oss-120b@v0.0.29", GPT_OSS_120B_V0_0_29_YAML, "gpt-oss-120b"),
            ("kimi-k3-1-pro@v0.0.3", KIMI_K3_1_PRO_V0_0_3_YAML, "kimi-k3-1-pro"),
            ("deepseek-v4-1-flash", DEEPSEEK_V4_1_FLASH_YAML, "deepseek-v4-1-flash"),
        ):
            parsed_default = parse_tinfoil_config_yaml(raw_yaml)
            with patch.dict(sys.modules, {"yaml": None}):
                parsed_no_pyyaml = parse_tinfoil_config_yaml(raw_yaml)
            self.assertEqual(parsed_default, parsed_no_pyyaml, f"Mismatch on {label}")
            if pyyaml is not None:
                self.assertEqual(parsed_default, pyyaml.safe_load(raw_yaml), f"PyYAML mismatch on {label}")

            meta = extract_enclave_manifest_metadata(parsed_no_pyyaml, served_id)
            self.assertTrue(meta["weights_hash"].startswith("dmverity:sha256:"))
            self.assertIn("@", meta["weights_source"])

        # Default _MiniYamlParser without allow_flow_sequences still rejects flow sequences
        with self.assertRaises(ValueError):
            _MiniYamlParser(KIMI_K3_V0_0_16_YAML).parse()

        # WORK-MAJOR-1: Multi-MPK manifest where draft model is first and primary model is second selects matching entry
        reordered_k31 = parse_tinfoil_config_yaml(KIMI_K3_1_PRO_V0_0_3_YAML)
        reordered_k31["models"] = list(reversed(reordered_k31["models"]))
        self.assertEqual(reordered_k31["models"][0]["name"], "kimi-k3-1-pro-dspark")
        meta_reordered = extract_enclave_manifest_metadata(reordered_k31, "kimi-k3-1-pro")
        self.assertEqual(
            meta_reordered["weights_source"],
            "moonshotai/Kimi-K3.1-Pro@6d0a0202956796543364d666ab19c6ad1a494ee1",
        )
        self.assertEqual(
            meta_reordered["weights_hash"],
            "dmverity:sha256:8d9c355a94e60f43598713759028328bbe795336f2700799d0ff4f3898e785e0",
        )

        # WORK-MAJOR-1: Valid config with wrong model name or missing model name fails closed and prevents write
        wrong_name_cfg = parse_tinfoil_config_yaml(KIMI_K3_1_PRO_V0_0_3_YAML)
        with self.assertRaises(CatalogSyncError):
            extract_enclave_manifest_metadata(wrong_name_cfg, "deepseek-v4-1-flash")

        missing_name_cfg = copy.deepcopy(wrong_name_cfg)
        missing_name_cfg["models"][0].pop("name", None)
        with self.assertRaises(CatalogSyncError):
            extract_enclave_manifest_metadata(missing_name_cfg, "kimi-k3-1-pro")

        models_data = _make_base_models_fixture()
        router_manifest = _make_router_manifest_fixture()
        openai_models = _make_openai_models_fixture()
        with self.assertRaises(CatalogSyncError):
            compute_catalog_drift(
                models_data,
                router_manifest,
                openai_models,
                {
                    "deepseek-v4-1-flash": wrong_name_cfg,
                    "kimi-k3": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
                    "kimi-k3-1-pro": wrong_name_cfg,
                },
                observed_date="2026-11-07",
            )

    def test_drift_detection_healing_and_idempotence(self) -> None:
        """Detect pricing drift, deprecation, enclave tags, and scaffold kimi-k3-1-pro; second check reports zero drift."""
        models_data = _make_base_models_fixture()
        router_manifest = _make_router_manifest_fixture()
        openai_models = _make_openai_models_fixture()
        enclave_configs = {
            "deepseek-v4-1-flash": parse_tinfoil_config_yaml(DEEPSEEK_V4_1_FLASH_YAML),
            "kimi-k3": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
            "kimi-k3-1-pro": parse_tinfoil_config_yaml(KIMI_K3_1_PRO_V0_0_3_YAML),
        }

        report = compute_catalog_drift(
            models_data,
            router_manifest,
            openai_models,
            enclave_configs,
            observed_date="2026-11-07",
        )
        self.assertTrue(report.has_drift)
        self.assertEqual(len(report.new_models), 1)
        new_k31 = report.new_models[0]
        self.assertEqual(new_k31["id"], "tinfoil-kimi-k3-1-pro")
        self.assertEqual(new_k31["status"], "candidate")
        self.assertEqual(new_k31["routing"]["private_attested"], "blocked")
        self.assertEqual(new_k31["remote_trust"]["tier"], "enclave_runtime_attested")
        self.assertEqual(new_k31["remote_trust"]["usage_policy"], "provider_terms_apply")
        self.assertEqual(
            new_k31["remote_trust"]["provider_manifest_weights_hash"],
            "dmverity:sha256:8d9c355a94e60f43598713759028328bbe795336f2700799d0ff4f3898e785e0",
        )
        self.assertEqual(
            new_k31["remote_trust"]["provider_manifest_weights_source"],
            "moonshotai/Kimi-K3.1-Pro@6d0a0202956796543364d666ab19c6ad1a494ee1",
        )
        # F2: Do not fabricate license or weight quantization from --kv-cache-dtype fp8
        self.assertIsNone(new_k31["license"])
        self.assertEqual(
            new_k31["quantization"],
            {"bits": None, "group_size": None, "tool": None, "tool_version": None},
        )
        self.assertEqual(new_k31["kv_cache_dtype"], "fp8")

        # Apply healing to a temp models.yaml and verify apply-then-check idempotence
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_models = Path(tmpdir) / "models.yaml"
            tmp_models.write_text(
                "# Header comment\n\n" + dump_models_yaml(models_data),
                encoding="utf-8",
            )
            healed = apply_catalog_healing(tmp_models, report)
            self.assertEqual(len(healed["models"]), 4)
            # Local Rung 1 model is untouched
            self.assertEqual(healed["models"][0]["id"], "qwen3-1.7b-mlx-4bit")
            # DeepSeek input price updated 0.65 -> 0.60 and cached_input -> 0.01, still active & cleared (weights unchanged)
            ds = next(m for m in healed["models"] if m["id"] == "tinfoil-deepseek-v4-1-flash")
            self.assertEqual(ds["status"], "active")
            self.assertEqual(ds["routing"]["private_attested"], "cleared")
            self.assertEqual(ds["remote_trust"]["pricing_per_m_tokens"]["input"], 0.6)
            self.assertEqual(ds["remote_trust"]["pricing_per_m_tokens"]["cached_input"], 0.01)
            # Kimi K3 marked deprecated with deprecation_date and cached_input
            k3 = next(m for m in healed["models"] if m["id"] == "tinfoil-kimi-k3")
            self.assertTrue(k3["deprecated"])
            self.assertEqual(k3["deprecation_date"], "2026-11-12")
            self.assertEqual(k3["enclave_tag"], "v0.0.16")
            self.assertEqual(k3["remote_trust"]["pricing_per_m_tokens"]["cached_input"], 0.6)
            k31 = next(m for m in healed["models"] if m["id"] == "tinfoil-kimi-k3-1-pro")
            self.assertEqual(k31["remote_trust"]["pricing_per_m_tokens"]["cached_input"], 0.4)

            # Re-run compute_catalog_drift on the healed file -> zero drift
            reloaded = safe_load(tmp_models.read_text(encoding="utf-8"))
            report2 = compute_catalog_drift(
                reloaded,
                router_manifest,
                openai_models,
                enclave_configs,
                observed_date="2026-11-07",
            )
            self.assertFalse(report2.has_drift, f"Expected zero drift after healing, got {report2.to_dict()}")

            # WORK-MINOR-1: Cached-price-only change is detected, healed, and idempotent; missing cached field preserves it
            oai_cached_change = copy.deepcopy(openai_models)
            oai_cached_change["data"][0]["pricing"]["cachedInputTokenPricePer1M"] = 0.05
            rep_cached = compute_catalog_drift(
                reloaded,
                router_manifest,
                oai_cached_change,
                enclave_configs,
                observed_date="2026-11-07",
            )
            self.assertTrue(rep_cached.has_drift)
            self.assertEqual(
                rep_cached.updated_models[0].changes["remote_trust.pricing_per_m_tokens.cached_input"],
                {"from": 0.01, "to": 0.05},
            )
            healed_cached = apply_catalog_healing(tmp_models, rep_cached)
            ds_c = next(m for m in healed_cached["models"] if m["id"] == "tinfoil-deepseek-v4-1-flash")
            self.assertEqual(ds_c["remote_trust"]["pricing_per_m_tokens"]["cached_input"], 0.05)

            reloaded_c = safe_load(tmp_models.read_text(encoding="utf-8"))
            rep_cached_clean = compute_catalog_drift(
                reloaded_c,
                router_manifest,
                oai_cached_change,
                enclave_configs,
                observed_date="2026-11-07",
            )
            self.assertFalse(rep_cached_clean.has_drift)

            # Removing cachedInputTokenPricePer1M preserves existing cached_input=0.05
            oai_no_cached = copy.deepcopy(oai_cached_change)
            oai_no_cached["data"][0]["pricing"].pop("cachedInputTokenPricePer1M", None)
            rep_no_cached = compute_catalog_drift(
                reloaded_c,
                router_manifest,
                oai_no_cached,
                enclave_configs,
                observed_date="2026-11-07",
            )
            self.assertFalse(rep_no_cached.has_drift)

    def test_weights_change_demotes_cleared_model_and_preserves_provenance(self) -> None:
        """PLAN-MAJOR-2: When an active/cleared model's weights hash changes, demote to candidate/blocked and preserve stale_eval_evidence_artifact."""
        models_data = _make_base_models_fixture()
        router_manifest = _make_router_manifest_fixture()
        openai_models = _make_openai_models_fixture()
        changed_ds_yaml = DEEPSEEK_V4_1_FLASH_YAML.replace(
            "6c4a2b637f7f45d9e48d1bdc38c12e0454584f48d3759851f7ee4471cd90b2e7",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        enclave_configs = {
            "deepseek-v4-1-flash": parse_tinfoil_config_yaml(changed_ds_yaml),
            "kimi-k3": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
            "kimi-k3-1-pro": parse_tinfoil_config_yaml(KIMI_K3_1_PRO_V0_0_3_YAML),
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_models = Path(tmpdir) / "models.yaml"
            tmp_models.write_text(dump_models_yaml(models_data), encoding="utf-8")
            report = compute_catalog_drift(
                models_data,
                router_manifest,
                openai_models,
                enclave_configs,
                observed_date="2026-11-07",
            )
            healed = apply_catalog_healing(tmp_models, report)
            ds = next(m for m in healed["models"] if m["id"] == "tinfoil-deepseek-v4-1-flash")
            self.assertEqual(ds["status"], "candidate")
            self.assertEqual(ds["routing"]["private_attested"], "blocked")
            self.assertNotIn("eval_evidence_artifact", ds)
            self.assertEqual(
                ds["stale_eval_evidence_artifact"],
                "docs/evals/tinfoil-deepseek-v4-1-flash.json",
            )
            self.assertIn("Cleared after Phase 2 trial", ds["review_notes"])
            # Endpoint resolution still succeeds
            ep = resolve_endpoint(ds, require_api_key=False)
            self.assertEqual(ep.routing_private_attested, "blocked")

    def test_source_completeness_disagreement_zero_health_and_optional_fields(self) -> None:
        """PLAN-MAJOR-2: Test feed disagreements, genuine both-feed removal, zero-health exemption before config fetch, and missing optional fields."""
        models_data = _make_base_models_fixture()
        router_manifest = _make_router_manifest_fixture()
        openai_models = _make_openai_models_fixture()
        enclave_configs = {
            "deepseek-v4-1-flash": parse_tinfoil_config_yaml(DEEPSEEK_V4_1_FLASH_YAML),
            "kimi-k3": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
            "kimi-k3-1-pro": parse_tinfoil_config_yaml(KIMI_K3_1_PRO_V0_0_3_YAML),
        }

        # 1. Missing optional pricing/context_window in /v1/models must NOT erase existing values
        oai_no_optional = copy.deepcopy(openai_models)
        oai_no_optional["data"][0].pop("pricing", None)
        oai_no_optional["data"][0].pop("context_window", None)
        rep_opt = compute_catalog_drift(
            models_data,
            router_manifest,
            oai_no_optional,
            enclave_configs,
            observed_date="2026-11-07",
        )
        ds_updates = [u for u in rep_opt.updated_models if u.model_id == "tinfoil-deepseek-v4-1-flash"]
        if ds_updates:
            self.assertNotIn("remote_trust.pricing_per_m_tokens.input", ds_updates[0].changes)
            self.assertNotIn("context_window", ds_updates[0].changes)

        # WORK-MINOR-2: Positive context_window decrease and increase on existing model are detected
        oai_ctx_dec = copy.deepcopy(openai_models)
        oai_ctx_dec["data"][0]["context_window"] = 131072
        rep_ctx_dec = compute_catalog_drift(
            models_data,
            router_manifest,
            oai_ctx_dec,
            enclave_configs,
            observed_date="2026-11-07",
        )
        ds_dec = next(u for u in rep_ctx_dec.updated_models if u.model_id == "tinfoil-deepseek-v4-1-flash")
        self.assertEqual(ds_dec.changes["context_window"], {"from": 1048576, "to": 131072})

        oai_ctx_inc = copy.deepcopy(openai_models)
        oai_ctx_inc["data"][0]["context_window"] = 2097152
        rep_ctx_inc = compute_catalog_drift(
            models_data,
            router_manifest,
            oai_ctx_inc,
            enclave_configs,
            observed_date="2026-11-07",
        )
        ds_inc = next(u for u in rep_ctx_inc.updated_models if u.model_id == "tinfoil-deepseek-v4-1-flash")
        self.assertEqual(ds_inc.changes["context_window"], {"from": 1048576, "to": 2097152})

        # 2. Zero-health model with empty tag does not attempt config fetch and demotes cleanly
        router_zero_health = copy.deepcopy(router_manifest)
        router_zero_health["models"]["deepseek-v4-1-flash"]["verification"]["healthy"] = 0
        router_zero_health["models"]["deepseek-v4-1-flash"]["tag"] = ""
        rep_zh = compute_catalog_drift(
            models_data,
            router_zero_health,
            openai_models,
            {"kimi-k3": enclave_configs["kimi-k3"], "kimi-k3-1-pro": enclave_configs["kimi-k3-1-pro"]},
            observed_date="2026-11-07",
        )
        ds_zh = next(u for u in rep_zh.updated_models if u.model_id == "tinfoil-deepseek-v4-1-flash")
        self.assertEqual(ds_zh.action, "demote_zero_health")
        self.assertEqual(ds_zh.changes["routing.private_attested"]["to"], "blocked")

        # 3. Feed disagreement (present in router with healthy>=1, absent in /v1/models) refuses mutation by default
        oai_missing_ds = copy.deepcopy(openai_models)
        oai_missing_ds["data"] = [m for m in oai_missing_ds["data"] if m["id"] != "deepseek-v4-1-flash"]
        rep_dis = compute_catalog_drift(
            models_data,
            router_manifest,
            oai_missing_ds,
            enclave_configs,
            observed_date="2026-11-07",
        )
        self.assertEqual(len(rep_dis.disagreements), 1)
        self.assertEqual(len(rep_dis.removed_models), 0)
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_models = Path(tmpdir) / "models.yaml"
            tmp_models.write_text(dump_models_yaml(models_data), encoding="utf-8")
            with self.assertRaises(CatalogSyncError):
                apply_catalog_healing(tmp_models, rep_dis, quarantine_disagreements=False)
            # With quarantine_disagreements=True, demotes routing to blocked without archiving
            healed_q = apply_catalog_healing(tmp_models, rep_dis, quarantine_disagreements=True)
            ds_q = next(m for m in healed_q["models"] if m["id"] == "tinfoil-deepseek-v4-1-flash")
            self.assertEqual(ds_q["status"], "candidate")
            self.assertEqual(ds_q["routing"]["private_attested"], "blocked")

        # 4. Absent from BOTH feeds -> archived in removed_models while preserving provenance
        router_no_k3 = copy.deepcopy(router_manifest)
        router_no_k3["models"].pop("kimi-k3", None)
        oai_no_k3 = copy.deepcopy(openai_models)
        oai_no_k3["data"] = [m for m in oai_no_k3["data"] if m["id"] != "kimi-k3"]
        rep_rem = compute_catalog_drift(
            models_data,
            router_no_k3,
            oai_no_k3,
            enclave_configs,
            observed_date="2026-11-07",
        )
        self.assertEqual(len(rep_rem.removed_models), 1)
        self.assertEqual(rep_rem.removed_models[0].model_id, "tinfoil-kimi-k3")
        self.assertEqual(rep_rem.removed_models[0].action, "archive_removed")

        # 5. Missing per-enclave config or malformed primary feeds raise CatalogSyncError
        with self.assertRaises(CatalogSyncError):
            compute_catalog_drift(models_data, {"models": {}}, openai_models, enclave_configs)
        with self.assertRaises(CatalogSyncError):
            compute_catalog_drift(models_data, router_manifest, {"object": "list", "data": []}, enclave_configs)
        with self.assertRaises(CatalogSyncError):
            compute_catalog_drift(models_data, router_manifest, openai_models, {})

    def test_trial_step_accounting_and_pre_step_budget_gate(self) -> None:
        """PLAN-R2-MAJOR-2 & PLAN-R3-MAJOR-1: Verify complete vs partial/zero-filled eval metrics, actual opencode-smoke schema, and budget refusal."""
        in_price = 4.0
        out_price = 20.0
        v1_spec = PHASE2_STEP_RESERVATIONS["v1"]
        smoke_spec = PHASE2_STEP_RESERVATIONS["opencode-smoke"]

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)

            # 1. Complete v1 metrics.json -> charges observed tokens
            v1_complete_dir = base / "v1_complete"
            v1_complete_dir.mkdir()
            (v1_complete_dir / "metrics.json").write_text(
                json.dumps(
                    {
                        "promptfoo_status": 0,
                        "token_accounting": {
                            "suite_requests": 10,
                            "suite_tokens": {"prompt": 23100, "completion": 2500, "total": 25600},
                            "timing_probe_requests": 1,
                            "timing_probe_tokens": {
                                "prompt": 174,
                                "completion": 35,
                                "total": 209,
                                "used_fallback_reservation": False,
                            },
                            "total_eval_requests": 11,
                            "total_eval_tokens": {"prompt": 23274, "completion": 2535, "total": 25809},
                        },
                    }
                ),
                encoding="utf-8",
            )
            res_v1_ok = evaluate_step_accounting(
                v1_complete_dir, v1_spec, input_price_per_m=in_price, output_price_per_m=out_price
            )
            self.assertTrue(res_v1_ok.accounting_complete)
            self.assertEqual(res_v1_ok.charged_requests, 11)
            self.assertEqual(res_v1_ok.charged_input_tokens, 23274)
            self.assertEqual(res_v1_ok.charged_output_tokens, 2535)
            self.assertAlmostEqual(res_v1_ok.charged_cost_usd, 23274 * 4e-6 + 2535 * 20e-6)

            # 2. Partial/zero-filled suite usage in metrics.json (write-metrics wrote 0 for suite, timing present) -> retains full step reservation
            v1_zero_dir = base / "v1_zero_suite"
            v1_zero_dir.mkdir()
            (v1_zero_dir / "metrics.json").write_text(
                json.dumps(
                    {
                        "promptfoo_status": 0,
                        "token_accounting": {
                            "suite_requests": 0,
                            "suite_tokens": {"prompt": 0, "completion": 0, "total": 0},
                            "timing_probe_requests": 1,
                            "timing_probe_tokens": {
                                "prompt": 174,
                                "completion": 35,
                                "total": 209,
                                "used_fallback_reservation": False,
                            },
                            "total_eval_requests": 1,
                            "total_eval_tokens": {"prompt": 174, "completion": 35, "total": 209},
                        },
                    }
                ),
                encoding="utf-8",
            )
            res_v1_zero = evaluate_step_accounting(
                v1_zero_dir, v1_spec, input_price_per_m=in_price, output_price_per_m=out_price
            )
            self.assertFalse(res_v1_zero.accounting_complete)
            self.assertEqual(res_v1_zero.charged_requests, 11)
            self.assertEqual(res_v1_zero.charged_input_tokens, 31100)
            self.assertEqual(res_v1_zero.charged_output_tokens, 7080)
            self.assertAlmostEqual(res_v1_zero.charged_cost_usd, 0.2660)

            # 3. Complete opencode-smoke summary.json using exact producer dictionary shape (PLAN-R3-MAJOR-1)
            smoke_ok_dir = base / "smoke_ok"
            smoke_ok_dir.mkdir()
            (smoke_ok_dir / "summary.json").write_text(
                json.dumps(
                    {
                        "token_accounting": {
                            "forwarded_chat_requests": 2,
                            "cumulative_request_bytes": 9100,
                            "observed_http_tokens": {
                                "prompt": 1691,
                                "completion": 133,
                                "total": 1824,
                                "requests_missing_usage": 0,
                            },
                            "reserved_ceiling_tokens": {
                                "input": 4500,
                                "output": 768,
                                "total": 5268,
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )
            res_smoke_ok = evaluate_step_accounting(
                smoke_ok_dir, smoke_spec, input_price_per_m=in_price, output_price_per_m=out_price
            )
            self.assertTrue(res_smoke_ok.accounting_complete)
            self.assertEqual(res_smoke_ok.charged_requests, 2)
            self.assertEqual(res_smoke_ok.charged_input_tokens, 1691)
            self.assertEqual(res_smoke_ok.charged_output_tokens, 133)

            # 4. Incomplete opencode-smoke summary.json (requests_missing_usage > 0) -> retains ceiling reservation
            smoke_missing_dir = base / "smoke_missing"
            smoke_missing_dir.mkdir()
            (smoke_missing_dir / "summary.json").write_text(
                json.dumps(
                    {
                        "token_accounting": {
                            "forwarded_chat_requests": 2,
                            "cumulative_request_bytes": 9100,
                            "observed_http_tokens": {
                                "prompt": 800,
                                "completion": 50,
                                "total": 850,
                                "requests_missing_usage": 1,
                            },
                            "reserved_ceiling_tokens": {
                                "input": 4500,
                                "output": 768,
                                "total": 5268,
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )
            res_smoke_inc = evaluate_step_accounting(
                smoke_missing_dir, smoke_spec, input_price_per_m=in_price, output_price_per_m=out_price
            )
            self.assertFalse(res_smoke_inc.accounting_complete)
            self.assertEqual(res_smoke_inc.charged_requests, 3)
            self.assertEqual(res_smoke_inc.charged_input_tokens, 4500)
            self.assertEqual(res_smoke_inc.charged_output_tokens, 768)

            # 5. Pre-step budget gate allows normal progression and refuses retry when budget or request cap is exceeded
            decision_ok = check_pre_step_budget(
                [res_v1_ok, res_smoke_ok],
                PHASE2_STEP_RESERVATIONS["tools"],
                input_price_per_m=in_price,
                output_price_per_m=out_price,
                budget_ceiling_usd=1.00,
                max_chat_requests=40,
            )
            self.assertTrue(decision_ok.allowed)

            # Refused retry when budget ceiling is tight ($0.35)
            decision_refused_cost = check_pre_step_budget(
                [res_v1_zero],
                v1_spec,
                input_price_per_m=in_price,
                output_price_per_m=out_price,
                budget_ceiling_usd=0.35,
                max_chat_requests=40,
            )
            self.assertFalse(decision_refused_cost.allowed)
            self.assertIn("exceeds budget ceiling", decision_refused_cost.reason or "")

            # Refused retry when request cap (40) would be exceeded
            decision_refused_reqs = check_pre_step_budget(
                [res_v1_zero, res_v1_zero, res_v1_zero],  # 33 requests
                v1_spec,  # +11 = 44 > 40
                input_price_per_m=in_price,
                output_price_per_m=out_price,
                budget_ceiling_usd=2.00,
                max_chat_requests=40,
            )
            self.assertFalse(decision_refused_reqs.allowed)
            self.assertIn("max_chat_requests", decision_refused_reqs.reason or "")

    def test_cli_exit_codes_and_error_handling(self) -> None:
        """PLAN-MAJOR-2: CLI returns 2 on drift, 0 with --exit-zero on drift, 0 after --apply, and 1 on source/disagreement errors even with --exit-zero."""
        import importlib.machinery
        import importlib.util

        script_path = ROOT / "scripts" / "sync-model-catalog"
        loader = importlib.machinery.SourceFileLoader("sync_model_catalog_cli", str(script_path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        assert spec is not None and spec.loader is not None
        cli_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli_mod)

        models_data = _make_base_models_fixture()
        router_manifest = _make_router_manifest_fixture()
        openai_models = _make_openai_models_fixture()
        enclave_configs = {
            "tinfoilsh/confidential-deepseek-v4-1-flash@v0.0.10+b200": parse_tinfoil_config_yaml(DEEPSEEK_V4_1_FLASH_YAML),
            "tinfoilsh/confidential-kimi-k3@v0.0.16": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
            "tinfoilsh/confidential-kimi-k3-1-pro@v0.0.3": parse_tinfoil_config_yaml(KIMI_K3_1_PRO_V0_0_3_YAML),
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_models = Path(tmpdir) / "models.yaml"
            tmp_models.write_text(dump_models_yaml(models_data), encoding="utf-8")

            with (
                patch.object(cli_mod, "fetch_tinfoil_router_manifest", return_value=router_manifest),
                patch.object(cli_mod, "fetch_tinfoil_openai_models", return_value=openai_models),
                patch.object(
                    cli_mod,
                    "fetch_tinfoil_enclave_config",
                    side_effect=lambda r, t, **kw: enclave_configs[f"{r}@{t}"],
                ),
            ):
                # Drift detected -> exit 2
                rc_drift = cli_mod.main(["--check", "--models-path", str(tmp_models)])
                self.assertEqual(rc_drift, 2)

                # Drift with --exit-zero -> exit 0
                rc_exit_zero = cli_mod.main(["--check", "--exit-zero", "--models-path", str(tmp_models)])
                self.assertEqual(rc_exit_zero, 0)

                # Apply -> exit 0
                rc_apply = cli_mod.main(["--apply", "--models-path", str(tmp_models)])
                self.assertEqual(rc_apply, 0)

                # Check after apply -> exit 0 (clean)
                rc_clean = cli_mod.main(["--check", "--models-path", str(tmp_models)])
                self.assertEqual(rc_clean, 0)

            # Operational error with --exit-zero -> still exits 1!
            with patch.object(
                cli_mod,
                "fetch_tinfoil_router_manifest",
                side_effect=CatalogSyncError("network down"),
            ):
                rc_err = cli_mod.main(["--check", "--exit-zero", "--models-path", str(tmp_models)])
                self.assertEqual(rc_err, 1)

            # WORK-MAJOR-2: Feed disagreement exits 1 across all --check flag combinations (including --quarantine-disagreements and --exit-zero)
            # and leaves models.yaml untouched; only --apply --quarantine-disagreements quarantines and exits 0.
            oai_disagree = copy.deepcopy(openai_models)
            oai_disagree["data"] = [m for m in oai_disagree["data"] if m["id"] != "deepseek-v4-1-flash"]
            before_bytes = tmp_models.read_bytes()
            with (
                patch.object(cli_mod, "fetch_tinfoil_router_manifest", return_value=router_manifest),
                patch.object(cli_mod, "fetch_tinfoil_openai_models", return_value=oai_disagree),
                patch.object(
                    cli_mod,
                    "fetch_tinfoil_enclave_config",
                    side_effect=lambda r, t, **kw: enclave_configs[f"{r}@{t}"],
                ),
            ):
                for check_argv in (
                    ["--check", "--models-path", str(tmp_models)],
                    ["--check", "--exit-zero", "--models-path", str(tmp_models)],
                    ["--check", "--quarantine-disagreements", "--models-path", str(tmp_models)],
                    ["--check", "--quarantine-disagreements", "--exit-zero", "--models-path", str(tmp_models)],
                    ["--apply", "--models-path", str(tmp_models)],
                ):
                    rc_dis = cli_mod.main(check_argv)
                    self.assertEqual(rc_dis, 1, f"Expected exit 1 for {check_argv}, got {rc_dis}")
                    self.assertEqual(tmp_models.read_bytes(), before_bytes)

                # Explicit --apply --quarantine-disagreements succeeds (exit 0) and blocks routing on disagreeing model
                rc_apply_q = cli_mod.main(
                    ["--apply", "--quarantine-disagreements", "--models-path", str(tmp_models)]
                )
                self.assertEqual(rc_apply_q, 0)
                quarantined_data = safe_load(tmp_models.read_text(encoding="utf-8"))
                ds_after = next(
                    m for m in quarantined_data["models"] if m["id"] == "tinfoil-deepseek-v4-1-flash"
                )
                self.assertEqual(ds_after["status"], "candidate")
                self.assertEqual(ds_after["routing"]["private_attested"], "blocked")

    def test_http_fetch_security_controls_and_side_by_side_pid_port(self) -> None:
        """WORK-MINOR-3: Test _http_get_text host allowlist, redirect blocking, size limit, and side-by-side port/PID preservation."""
        import http.server
        import socketserver
        import threading
        from local_assist.catalog_sync import _http_get_text
        from local_assist.registry import get_process_lstart

        # 1. Host allowlist & scheme checks
        with self.assertRaises(CatalogSyncError):
            _http_get_text("https://evil.example.com/v1/models")
        with self.assertRaises(CatalogSyncError):
            _http_get_text("http://inference.tinfoil.sh/v1/models")
        with self.assertRaises(CatalogSyncError):
            _http_get_text("file:///etc/passwd")

        # 2. Loopback HTTP test server for redirect blocking and response size cap
        target_hits: list[str] = []

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                pass

            def do_GET(self) -> None:
                server_port = self.server.server_address[1]
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{server_port}/target")
                    self.end_headers()
                elif self.path == "/target":
                    target_hits.append(self.path)
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{"followed_redirect": true}')
                elif self.path == "/oversized":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"x" * 128)
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{"ok": true}')

        with socketserver.TCPServer(("127.0.0.1", 0), _Handler) as httpd:
            port = httpd.server_address[1]
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                ok_text = _http_get_text(f"http://127.0.0.1:{port}/ok")
                self.assertEqual(ok_text, '{"ok": true}')
                with self.assertRaises(CatalogSyncError) as ctx_redir:
                    _http_get_text(f"http://127.0.0.1:{port}/redirect")
                self.assertIn("Refusing HTTP redirect (302)", str(ctx_redir.exception))
                self.assertEqual(target_hits, [])
                with self.assertRaises(CatalogSyncError) as ctx_size:
                    _http_get_text(f"http://127.0.0.1:{port}/oversized", max_bytes=64)
                self.assertIn("exceeded", str(ctx_size.exception).lower())
            finally:
                httpd.shutdown()

        # 3. Side-by-side PID port resolution in resolve_endpoint and default .serve.pid preservation in _write_pid_files
        import importlib.machinery
        import importlib.util
        from local_assist.registry import (
            get_process_lstart,
            pid_file_for_model,
            read_pid_record_for_model,
            session_token_file_for_model,
        )

        serve_script_path = ROOT / "scripts" / "serve-model"
        serve_loader = importlib.machinery.SourceFileLoader("serve_model_cli", str(serve_script_path))
        serve_spec = importlib.util.spec_from_loader(serve_loader.name, serve_loader)
        assert serve_spec is not None and serve_spec.loader is not None
        serve_mod = importlib.util.module_from_spec(serve_spec)
        serve_spec.loader.exec_module(serve_mod)

        models_data = _make_base_models_fixture()
        k3_entry = next(m for m in models_data["models"] if m["id"] == "tinfoil-kimi-k3")
        my_pid = os.getpid()
        my_lstart = get_process_lstart(my_pid)
        assert my_lstart is not None

        with tempfile.TemporaryDirectory() as tmpdir:
            runs_dir = Path(tmpdir)
            default_pid_file = runs_dir / ".serve.pid"
            ds_pid_file = pid_file_for_model("tinfoil-deepseek-v4-1-flash", runs_dir)
            k3_pid_file = pid_file_for_model("tinfoil-kimi-k3", runs_dir)
            k3_tok_file = session_token_file_for_model("tinfoil-kimi-k3", runs_dir)
            k3_tok_file.write_text("se-session-k38082-0123456789abcdef\n", encoding="utf-8")

            ds_record = {
                "pid": my_pid,
                "pid_lstart": my_lstart,
                "model_id": "tinfoil-deepseek-v4-1-flash",
                "port": 8081,
            }
            serve_mod._write_pid_files(ds_pid_file, default_pid_file, ds_record)
            self.assertEqual(json.loads(default_pid_file.read_text(encoding="utf-8"))["model_id"], "tinfoil-deepseek-v4-1-flash")

            k3_record = {
                "pid": my_pid,
                "pid_lstart": my_lstart,
                "model_id": "tinfoil-kimi-k3",
                "port": 8082,
                "session_token_file": str(k3_tok_file),
            }
            serve_mod._write_pid_files(k3_pid_file, default_pid_file, k3_record)
            # Default .serve.pid is preserved for the live DeepSeek server on 8081
            self.assertEqual(json.loads(default_pid_file.read_text(encoding="utf-8"))["model_id"], "tinfoil-deepseek-v4-1-flash")
            self.assertEqual(json.loads(default_pid_file.read_text(encoding="utf-8"))["port"], 8081)

            # Reading Kimi K3's PID record and passing it to resolve_endpoint resolves port 8082 and its session token
            loaded_k3_rec = read_pid_record_for_model("tinfoil-kimi-k3", runs_dir)
            assert loaded_k3_rec is not None
            ep = resolve_endpoint(k3_entry, pid_record=loaded_k3_rec, require_api_key=True)
            self.assertEqual(ep.api_base_url, "http://127.0.0.1:8082/v1")
            self.assertEqual(ep.port, 8082)
            self.assertEqual(ep.api_key, "se-session-k38082-0123456789abcdef")

            # F5 & P3-PLAN-MINOR-2: Verify all 5 default_pid_file start-time identity cases
            # Case (b): Live PID with mismatched pid_lstart (reused PID) -> default_pid_file is replaced
            reused_record = dict(ds_record, pid_lstart="Mon Jan  1 00:00:00 2024")
            default_pid_file.write_text(json.dumps(reused_record), encoding="utf-8")
            serve_mod._write_pid_files(k3_pid_file, default_pid_file, k3_record)
            self.assertEqual(json.loads(default_pid_file.read_text(encoding="utf-8"))["model_id"], "tinfoil-kimi-k3")

            # Case (c): Live PID with missing/empty pid_lstart -> preserved (do not clobber live process with unknown identity)
            no_lstart_record = {"pid": my_pid, "model_id": "tinfoil-deepseek-v4-1-flash", "port": 8081}
            default_pid_file.write_text(json.dumps(no_lstart_record), encoding="utf-8")
            serve_mod._write_pid_files(k3_pid_file, default_pid_file, k3_record)
            self.assertEqual(
                json.loads(default_pid_file.read_text(encoding="utf-8"))["model_id"],
                "tinfoil-deepseek-v4-1-flash",
            )

            # Case (d): Live PID where get_process_lstart returns None -> preserved
            default_pid_file.write_text(json.dumps(ds_record), encoding="utf-8")
            with patch.object(serve_mod, "get_process_lstart", return_value=None):
                serve_mod._write_pid_files(k3_pid_file, default_pid_file, k3_record)
            self.assertEqual(
                json.loads(default_pid_file.read_text(encoding="utf-8"))["model_id"],
                "tinfoil-deepseek-v4-1-flash",
            )

            # Case (e): Dead PID -> replaced
            default_pid_file.write_text(json.dumps(ds_record), encoding="utf-8")
            with patch.object(serve_mod, "pid_is_alive", return_value=False):
                serve_mod._write_pid_files(k3_pid_file, default_pid_file, k3_record)
            self.assertEqual(json.loads(default_pid_file.read_text(encoding="utf-8"))["model_id"], "tinfoil-kimi-k3")

    def test_stale_report_toctou_and_concurrent_lock(self) -> None:
        """F1 & P3-PLAN-MINOR-1: Stale report rejection, precondition check, unconditional weight-change demotion, CLI recompute, and advisory lock."""
        import importlib.machinery
        import importlib.util
        import threading
        import time

        models_data = _make_base_models_fixture()
        router_manifest = _make_router_manifest_fixture()
        openai_models = _make_openai_models_fixture()
        changed_k3_yaml = KIMI_K3_V0_0_16_YAML.replace(
            "58d5e74ba6c814d4cc4511df093ede786bfbc95f766eee7a96379687ce455792",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        enclave_configs = {
            "deepseek-v4-1-flash": parse_tinfoil_config_yaml(DEEPSEEK_V4_1_FLASH_YAML),
            "kimi-k3": parse_tinfoil_config_yaml(changed_k3_yaml),
            "kimi-k3-1-pro": parse_tinfoil_config_yaml(KIMI_K3_1_PRO_V0_0_3_YAML),
        }

        report = compute_catalog_drift(
            models_data,
            router_manifest,
            openai_models,
            enclave_configs,
            observed_date="2026-11-07",
        )
        self.assertEqual(report.base_catalog_sha256, compute_models_data_digest(models_data))
        k3_item = next(u for u in report.updated_models if u.model_id == "tinfoil-kimi-k3")
        self.assertTrue(k3_item.weights_changed)
        # Because tinfoil-kimi-k3 was candidate/blocked when report was computed, status/routing are not in k3_item.changes
        self.assertNotIn("status", k3_item.changes)
        self.assertNotIn("routing.private_attested", k3_item.changes)

        # Mutate catalog on disk to simulate concurrent promotion of tinfoil-kimi-k3 to active/cleared
        promoted_data = copy.deepcopy(models_data)
        k3_entry = next(m for m in promoted_data["models"] if m["id"] == "tinfoil-kimi-k3")
        k3_entry["status"] = "active"
        k3_entry["routing"]["private_attested"] = "cleared"
        k3_entry["eval_evidence_artifact"] = "docs/evals/tinfoil-kimi-k3.json"

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_models = Path(tmpdir) / "models.yaml"
            tmp_models.write_text(dump_models_yaml(promoted_data), encoding="utf-8")
            before_bytes = tmp_models.read_bytes()

            # 1. Direct apply_catalog_healing rejects stale base_catalog_sha256 without modifying disk
            with self.assertRaises(CatalogSyncError) as ctx_stale:
                apply_catalog_healing(tmp_models, report)
            self.assertIn("stale catalog drift report", str(ctx_stale.exception))
            self.assertEqual(tmp_models.read_bytes(), before_bytes)

            # 2. Even if base_catalog_sha256 is cleared (unpinned report), a mismatched 'from' precondition is rejected
            unpinned_bad_from = copy.deepcopy(report)
            unpinned_bad_from.base_catalog_sha256 = None
            mutated_price_data = copy.deepcopy(promoted_data)
            ds_entry = next(m for m in mutated_price_data["models"] if m["id"] == "tinfoil-deepseek-v4-1-flash")
            ds_entry["remote_trust"]["pricing_per_m_tokens"]["input"] = 0.99
            tmp_models.write_text(dump_models_yaml(mutated_price_data), encoding="utf-8")
            price_bytes = tmp_models.read_bytes()
            with self.assertRaises(CatalogSyncError) as ctx_pre:
                apply_catalog_healing(tmp_models, unpinned_bad_from)
            self.assertIn("expected 0.65", str(ctx_pre.exception))
            self.assertEqual(tmp_models.read_bytes(), price_bytes)

            # 3. Defense-in-depth: if base_catalog_sha256 is None and 'from' preconditions match, weights_changed=True
            # unconditionally demotes the newly cleared model to candidate/blocked and moves eval_evidence_artifact
            tmp_models.write_text(dump_models_yaml(promoted_data), encoding="utf-8")
            unpinned_report = copy.deepcopy(report)
            unpinned_report.base_catalog_sha256 = None
            healed = apply_catalog_healing(tmp_models, unpinned_report)
            healed_k3 = next(m for m in healed["models"] if m["id"] == "tinfoil-kimi-k3")
            self.assertEqual(healed_k3["status"], "candidate")
            self.assertEqual(healed_k3["routing"]["private_attested"], "blocked")
            self.assertNotIn("eval_evidence_artifact", healed_k3)
            self.assertEqual(healed_k3["stale_eval_evidence_artifact"], "docs/evals/tinfoil-kimi-k3.json")

            # 4. CLI main(["--apply", ...]) recomputes when models.yaml changes during remote manifest fetches
            script_path = ROOT / "scripts" / "sync-model-catalog"
            loader = importlib.machinery.SourceFileLoader("sync_model_catalog_cli_f1", str(script_path))
            spec = importlib.util.spec_from_loader(loader.name, loader)
            assert spec is not None and spec.loader is not None
            cli_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cli_mod)

            tmp_models.write_text(dump_models_yaml(models_data), encoding="utf-8")
            enclave_by_repo_tag = {
                "tinfoilsh/confidential-deepseek-v4-1-flash@v0.0.10+b200": enclave_configs["deepseek-v4-1-flash"],
                "tinfoilsh/confidential-kimi-k3@v0.0.16": enclave_configs["kimi-k3"],
                "tinfoilsh/confidential-kimi-k3-1-pro@v0.0.3": enclave_configs["kimi-k3-1-pro"],
            }

            def _fetch_enclave_and_mutate_catalog(repo: str, tag: str, **kw: object) -> dict:
                if repo == "tinfoilsh/confidential-kimi-k3":
                    # Simulate operator promoting tinfoil-kimi-k3 while network fetch is in flight
                    tmp_models.write_text(dump_models_yaml(promoted_data), encoding="utf-8")
                return enclave_by_repo_tag[f"{repo}@{tag}"]

            with (
                patch.object(cli_mod, "fetch_tinfoil_router_manifest", return_value=router_manifest),
                patch.object(cli_mod, "fetch_tinfoil_openai_models", return_value=openai_models),
                patch.object(cli_mod, "fetch_tinfoil_enclave_config", side_effect=_fetch_enclave_and_mutate_catalog),
            ):
                rc = cli_mod.main(["--apply", "--models-path", str(tmp_models)])
                self.assertEqual(rc, 0)

            recomputed_catalog = safe_load(tmp_models.read_text(encoding="utf-8"))
            k3_after_cli = next(m for m in recomputed_catalog["models"] if m["id"] == "tinfoil-kimi-k3")
            self.assertEqual(k3_after_cli["status"], "candidate")
            self.assertEqual(k3_after_cli["routing"]["private_attested"], "blocked")
            self.assertNotIn("eval_evidence_artifact", k3_after_cli)
            self.assertEqual(k3_after_cli["stale_eval_evidence_artifact"], "docs/evals/tinfoil-kimi-k3.json")

            # 5. P3-WORK-MINOR-2: Cooperating writer is blocked by apply_catalog_healing's lock across
            # validation/rendering and atomic publication, and observes the updated digest afterward
            import local_assist.catalog_sync as cs_mod

            tmp_models.write_text(dump_models_yaml(models_data), encoding="utf-8")
            initial_digest = compute_models_data_digest(models_data)
            events: list[str] = []
            in_render = threading.Event()
            waiter_attempted_lock = threading.Event()
            release_render = threading.Event()
            waiter_observed_digest: list[str] = []
            healed_holder: list[dict] = []
            real_dump = cs_mod.dump_models_yaml

            def _sync_dump(data: dict, header_comments: list[str] | None = None) -> str:
                events.append("apply_enter_render")
                in_render.set()
                assert release_render.wait(timeout=5.0), "Timed out waiting for release_render"
                rendered_out = real_dump(data, header_comments)
                events.append("apply_exit_render")
                return rendered_out

            def _run_apply() -> None:
                res = apply_catalog_healing(tmp_models, report)
                healed_holder.append(res)

            def _competing_writer() -> None:
                assert in_render.wait(timeout=5.0), "Timed out waiting for in_render"
                waiter_attempted_lock.set()
                with catalog_file_lock(tmp_models):
                    events.append("waiter_entered_lock")
                    disk_data = safe_load(tmp_models.read_text(encoding="utf-8"))
                    waiter_observed_digest.append(compute_models_data_digest(disk_data))

            with patch.object(cs_mod, "dump_models_yaml", side_effect=_sync_dump):
                t_apply = threading.Thread(target=_run_apply)
                t_waiter = threading.Thread(target=_competing_writer)
                t_apply.start()
                t_waiter.start()
                self.assertTrue(in_render.wait(timeout=5.0))
                self.assertTrue(waiter_attempted_lock.wait(timeout=5.0))
                # Give the waiter thread a brief yield to block on flock syscall while apply holds the lock
                time.sleep(0.02)
                self.assertNotIn("waiter_entered_lock", events)
                release_render.set()
                t_apply.join(timeout=5.0)
                t_waiter.join(timeout=5.0)

            self.assertEqual(events, ["apply_enter_render", "apply_exit_render", "waiter_entered_lock"])
            self.assertEqual(len(healed_holder), 1)
            expected_post_digest = compute_models_data_digest(healed_holder[0])
            self.assertNotEqual(expected_post_digest, initial_digest)
            self.assertEqual(waiter_observed_digest, [expected_post_digest])

            # 6. P3-WORK-MINOR-2 & P3-R2-WORK-MINOR-1: Non-cooperating edit during validation/rendering triggers
            # final byte-identity rejection before os.replace, preserves the edited bytes on disk, and unlinks the
            # .models-sync-*.yaml temporary output file created by tempfile.mkstemp
            tmp_models.write_text(dump_models_yaml(models_data), encoding="utf-8")
            non_coop_bytes = (dump_models_yaml(promoted_data) + "# non-cooperating edit\n").encode("utf-8")
            created_temps: list[Path] = []
            real_mkstemp = tempfile.mkstemp

            def _tracking_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
                fd, path_str = real_mkstemp(*args, **kwargs)  # type: ignore[arg-type]
                created_temps.append(Path(path_str))
                return fd, path_str

            def _SneakyDump(data: dict, header_comments: list[str] | None = None) -> str:
                rendered_out = real_dump(data, header_comments)
                tmp_models.write_bytes(non_coop_bytes)
                return rendered_out

            with (
                patch.object(cs_mod, "dump_models_yaml", side_effect=_SneakyDump),
                patch.object(tempfile, "mkstemp", side_effect=_tracking_mkstemp),
            ):
                with self.assertRaises(CatalogSyncError) as ctx_race:
                    apply_catalog_healing(tmp_models, report)
            self.assertIn("modified concurrently outside catalog_file_lock", str(ctx_race.exception))
            self.assertEqual(tmp_models.read_bytes(), non_coop_bytes)
            self.assertEqual(len(created_temps), 1)
            self.assertTrue(created_temps[0].name.startswith(".models-sync-"))
            self.assertFalse(created_temps[0].exists())
            leftover_temps = list(Path(tmpdir).glob(".models-sync-*.yaml"))
            self.assertEqual(leftover_temps, [])

    def test_f2_f3_f4_f6_remediations(self) -> None:
        """F2 (no fabricated metadata), F3 (negative healthy), F4 (flow quotes after '['/','), and F6 (unmanaged collisions)."""
        try:
            import yaml as pyyaml  # type: ignore[import-untyped]
        except ImportError:
            pyyaml = None

        # F4 & P3-WORK-MINOR-1: Flow sequence items quoted immediately after '[' or ',' with '#' inside,
        # plus ordinary plain scalars containing '[' or ',' followed by quotes outside a flow collection
        flow_hash_yaml = """\
containers:
  - name: test-enclave
    pattern: ^["']$
    csv_note: foo,"bar"
    prefixed_bracket: foo ["bar"]
    command: ["a # b",'c # d', "e # f", 'g # h'] # trailing comment
"""
        parsed_mini = _MiniYamlParser(flow_hash_yaml, allow_flow_sequences=True).parse()
        self.assertEqual(parsed_mini["containers"][0]["pattern"], '^["\']$')
        self.assertEqual(parsed_mini["containers"][0]["csv_note"], 'foo,"bar"')
        self.assertEqual(parsed_mini["containers"][0]["prefixed_bracket"], 'foo ["bar"]')
        self.assertEqual(
            parsed_mini["containers"][0]["command"],
            ["a # b", "c # d", "e # f", "g # h"],
        )
        if pyyaml is not None:
            self.assertEqual(parsed_mini, pyyaml.safe_load(flow_hash_yaml))
        with self.assertRaises(ValueError):
            _MiniYamlParser(flow_hash_yaml).parse()

        # F3: Negative verification.healthy or verification.configured raises CatalogSyncError
        bad_router = _make_router_manifest_fixture()
        bad_router["models"]["deepseek-v4-1-flash"]["verification"]["healthy"] = -1
        with self.assertRaises(CatalogSyncError) as ctx_neg:
            validate_router_manifest(bad_router)
        self.assertIn("negative 'verification.healthy'", str(ctx_neg.exception))

        bad_router_cfg = _make_router_manifest_fixture()
        bad_router_cfg["models"]["deepseek-v4-1-flash"]["verification"]["configured"] = -2
        with self.assertRaises(CatalogSyncError):
            validate_router_manifest(bad_router_cfg)

        # F2: Candidate without context_window / max-model-len / license has null fields; repo-name quantization vs kv_cache_dtype
        models_data = _make_base_models_fixture()
        router_manifest = _make_router_manifest_fixture()
        openai_models = _make_openai_models_fixture()
        # Strip context_window from /v1/models and --max-model-len from Kimi K3.1 Pro config
        oai_no_ctx = copy.deepcopy(openai_models)
        k31_oai = next(m for m in oai_no_ctx["data"] if m["id"] == "kimi-k3-1-pro")
        k31_oai.pop("context_window", None)
        k31_no_maxlen_yaml = "\n".join(
            line
            for line in KIMI_K3_1_PRO_V0_0_3_YAML.splitlines()
            if "--max-model-len" not in line and "'1048576'" not in line
        )
        rep_f2 = compute_catalog_drift(
            models_data,
            router_manifest,
            oai_no_ctx,
            {
                "deepseek-v4-1-flash": parse_tinfoil_config_yaml(DEEPSEEK_V4_1_FLASH_YAML),
                "kimi-k3": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
                "kimi-k3-1-pro": parse_tinfoil_config_yaml(k31_no_maxlen_yaml),
            },
            observed_date="2026-11-07",
        )
        cand_no_ctx = rep_f2.new_models[0]
        self.assertIsNone(cand_no_ctx["context_window"])
        self.assertIsNone(cand_no_ctx["license"])
        self.assertEqual(
            cand_no_ctx["quantization"],
            {"bits": None, "group_size": None, "tool": None, "tool_version": None},
        )
        self.assertEqual(cand_no_ctx["kv_cache_dtype"], "fp8")

        # When upstream repo explicitly indicates NVFP4, quantization records 4-bit nvfp4
        nvfp4_yaml = k31_no_maxlen_yaml.replace(
            "moonshotai/Kimi-K3.1-Pro@6d0a0202956796543364d666ab19c6ad1a494ee1",
            "nvidia/Kimi-K3.1-Pro-NVFP4@6d0a0202956796543364d666ab19c6ad1a494ee1",
        )
        rep_nvfp4 = compute_catalog_drift(
            models_data,
            router_manifest,
            oai_no_ctx,
            {
                "deepseek-v4-1-flash": parse_tinfoil_config_yaml(DEEPSEEK_V4_1_FLASH_YAML),
                "kimi-k3": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
                "kimi-k3-1-pro": parse_tinfoil_config_yaml(nvfp4_yaml),
            },
            observed_date="2026-11-07",
        )
        self.assertEqual(
            rep_nvfp4.new_models[0]["quantization"],
            {"bits": 4, "group_size": None, "tool": "nvfp4", "tool_version": None},
        )

        # F6: Unmanaged catalog entry colliding with candidate ID or served repo raises CatalogSyncError
        colliding_models = copy.deepcopy(models_data)
        colliding_models["models"].append(
            {
                "id": "tinfoil-kimi-k3-1-pro",
                "status": "candidate",
                "repo": "custom-unmanaged-repo",
                "runtime": "vllm",
                "remote_trust": None,
            }
        )
        with self.assertRaises(CatalogSyncError) as ctx_col:
            compute_catalog_drift(
                colliding_models,
                router_manifest,
                openai_models,
                {
                    "deepseek-v4-1-flash": parse_tinfoil_config_yaml(DEEPSEEK_V4_1_FLASH_YAML),
                    "kimi-k3": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
                    "kimi-k3-1-pro": parse_tinfoil_config_yaml(KIMI_K3_1_PRO_V0_0_3_YAML),
                },
                observed_date="2026-11-07",
            )
        self.assertIn("collides with existing", str(ctx_col.exception))

        # Also test repo collision (distinct id, same repo='kimi-k3-1-pro')
        colliding_repo_models = copy.deepcopy(models_data)
        colliding_repo_models["models"].append(
            {
                "id": "custom-unmanaged-kimi-id",
                "status": "candidate",
                "repo": "kimi-k3-1-pro",
                "runtime": "vllm",
                "remote_trust": None,
            }
        )
        with self.assertRaises(CatalogSyncError) as ctx_repo_col:
            compute_catalog_drift(
                colliding_repo_models,
                router_manifest,
                openai_models,
                {
                    "deepseek-v4-1-flash": parse_tinfoil_config_yaml(DEEPSEEK_V4_1_FLASH_YAML),
                    "kimi-k3": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
                    "kimi-k3-1-pro": parse_tinfoil_config_yaml(KIMI_K3_1_PRO_V0_0_3_YAML),
                },
                observed_date="2026-11-07",
            )
        self.assertIn("collides with existing", str(ctx_repo_col.exception))

        # Verify apply_catalog_healing rejects both ID and repo collisions in new_models without mutating disk
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_models = Path(tmpdir) / "models.yaml"
            tmp_models.write_text(dump_models_yaml(colliding_models), encoding="utf-8")
            col_bytes = tmp_models.read_bytes()
            synthetic_report = copy.deepcopy(rep_f2)
            synthetic_report.base_catalog_sha256 = compute_models_data_digest(colliding_models)
            with self.assertRaises(CatalogSyncError) as ctx_apply_col:
                apply_catalog_healing(tmp_models, synthetic_report)
            self.assertIn("ID already exists", str(ctx_apply_col.exception))
            self.assertEqual(tmp_models.read_bytes(), col_bytes)

            tmp_models.write_text(dump_models_yaml(colliding_repo_models), encoding="utf-8")
            repo_col_bytes = tmp_models.read_bytes()
            synthetic_repo_report = copy.deepcopy(rep_f2)
            synthetic_repo_report.base_catalog_sha256 = compute_models_data_digest(colliding_repo_models)
            with self.assertRaises(CatalogSyncError) as ctx_apply_repo_col:
                apply_catalog_healing(tmp_models, synthetic_repo_report)
            self.assertIn("repo 'kimi-k3-1-pro' already exists", str(ctx_apply_repo_col.exception))
            self.assertEqual(tmp_models.read_bytes(), repo_col_bytes)

    def test_github_workflow_and_issue_reconciliation(self) -> None:
        """Phase 4 (P4-PLAN-MAJOR-1 & P4-PLAN-MINOR-1..3): CLI --json-out/--markdown-out, fence escaping, issue reconciler lifecycle, and workflow YAML structure."""
        import importlib.machinery
        import importlib.util

        script_path = ROOT / "scripts" / "sync-model-catalog"
        loader = importlib.machinery.SourceFileLoader("sync_model_catalog_cli_p4", str(script_path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        assert spec is not None and spec.loader is not None
        cli_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli_mod)

        # 1. Fence containment against untrusted upstream strings containing triple/quadruple backticks, @mentions, and #123
        hostile_report = {
            "observed_date": "2026-11-07",
            "base_catalog_sha256": "deadbeef" * 8,
            "check_status": "drift",
            "has_drift": True,
            "updated_models": [
                {
                    "model_id": "tinfoil-deepseek-v4-1-flash",
                    "served_model_id": "deepseek-v4-1-flash",
                    "action": "update",
                    "weights_changed": False,
                    "changes": {"enclave_tag": {"from": "v0.0.1", "to": "v0.0.2\n```\n@admin #123\n````\ninjected"}},
                    "notes": [],
                }
            ],
            "new_models": [],
            "removed_models": [],
            "disagreements": [],
        }
        hostile_human = "Detected drift:\n```\n@security-team fixes #999\n````\nend"
        rendered_md = render_github_issue_body(
            hostile_report,
            exit_code=2,
            human_output=hostile_human,
            run_url="https://github.com/HakAl/free-inference/actions/runs/12345",
            checked_ref="refs/heads/main",
            checked_sha="71a8b0b65ef3d86c2245d5653ad81c92f548c6b3",
        )
        # Since payload contains a 4-backtick run (````), fence must be at least 5 backticks (`````)
        self.assertIn("`````text\n", rendered_md)
        self.assertIn("`````json\n", rendered_md)
        self.assertIn("- **Checked ref**: `refs/heads/main`", rendered_md)
        self.assertIn("- **Checked commit**: `71a8b0b65ef3d86c2245d5653ad81c92f548c6b3`", rendered_md)
        # Verify the hostile @mention only appears inside the 5-backtick fenced blocks
        parts_outside_fences = rendered_md.split("`````")
        # Even-indexed segments (0, 2, 4) are outside the ````` fences
        outside_text = "\n".join(parts_outside_fences[0::2])
        self.assertNotIn("@security-team", outside_text)
        self.assertNotIn("@admin", outside_text)

        # 2. CLI --json-out and --markdown-out across drift (rc=2), clean (rc=0), disagreement (rc=1), and source failure (rc=1)
        models_data = _make_base_models_fixture()
        router_manifest = _make_router_manifest_fixture()
        openai_models = _make_openai_models_fixture()
        enclave_configs = {
            "tinfoilsh/confidential-deepseek-v4-1-flash@v0.0.10+b200": parse_tinfoil_config_yaml(DEEPSEEK_V4_1_FLASH_YAML),
            "tinfoilsh/confidential-kimi-k3@v0.0.16": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
            "tinfoilsh/confidential-kimi-k3-1-pro@v0.0.3": parse_tinfoil_config_yaml(KIMI_K3_1_PRO_V0_0_3_YAML),
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_dir = Path(tmpdir)
            tmp_models = tmp_dir / "models.yaml"
            json_out = tmp_dir / "catalog-drift.json"
            md_out = tmp_dir / "issue-body.md"
            tmp_models.write_text(dump_models_yaml(models_data), encoding="utf-8")

            with (
                patch.object(cli_mod, "fetch_tinfoil_router_manifest", return_value=router_manifest),
                patch.object(cli_mod, "fetch_tinfoil_openai_models", return_value=openai_models),
                patch.object(
                    cli_mod,
                    "fetch_tinfoil_enclave_config",
                    side_effect=lambda r, t, **kw: enclave_configs[f"{r}@{t}"],
                ),
            ):
                # (a) Drift check -> rc=2, json_out has check_status='drift'
                rc_drift = cli_mod.main(
                    [
                        "--check",
                        "--models-path",
                        str(tmp_models),
                        "--json-out",
                        str(json_out),
                        "--markdown-out",
                        str(md_out),
                        "--run-url",
                        "https://github.com/HakAl/free-inference/actions/runs/1",
                        "--checked-ref",
                        "refs/heads/main",
                        "--checked-sha",
                        "abc1234",
                    ]
                )
                self.assertEqual(rc_drift, 2)
                self.assertTrue(json_out.is_file())
                self.assertTrue(md_out.is_file())
                drift_json = json.loads(json_out.read_text(encoding="utf-8"))
                self.assertEqual(drift_json["check_status"], "drift")
                self.assertEqual(drift_json["checked_ref"], "refs/heads/main")
                self.assertEqual(drift_json["checked_sha"], "abc1234")

                # Reconciler Case 1 & P4-WORK-MINOR-2: Populate >100 unrelated open issues before the target
                # bot issue (#142) and enforce --app, --search, and --limit in the fake transport so an
                # unfiltered --limit 100 query would miss #142 while server-side filtering finds it.
                gh_calls: list[list[str]] = []
                open_issues_state: list[dict] = [
                    {
                        "number": idx,
                        "title": f"Unrelated issue {idx}",
                        "author": {"login": "app/github-actions" if idx % 2 == 0 else "bob"},
                    }
                    for idx in range(1, 121)
                ] + [
                    {"number": 121, "title": CATALOG_DRIFT_ISSUE_TITLE, "author": {"login": "alice"}},
                ]

                def _fake_gh(args: list[str]) -> str:
                    gh_calls.append(list(args))
                    if args[:2] == ["issue", "list"]:
                        candidates = list(open_issues_state)
                        if "--app" in args:
                            app_val = args[args.index("--app") + 1]
                            if app_val == "github-actions":
                                candidates = [
                                    c
                                    for c in candidates
                                    if (c.get("author") or {}).get("login")
                                    in {"app/github-actions", "github-actions[bot]", "github-actions"}
                                ]
                        if "--search" in args:
                            search_val = args[args.index("--search") + 1]
                            if f'"{CATALOG_DRIFT_ISSUE_TITLE}" in:title' in search_val:
                                candidates = [
                                    c for c in candidates if CATALOG_DRIFT_ISSUE_TITLE in str(c.get("title") or "")
                                ]
                        limit_val = 30
                        if "--limit" in args:
                            limit_val = int(args[args.index("--limit") + 1])
                        return json.dumps(candidates[:limit_val])
                    if args[:2] == ["issue", "create"]:
                        open_issues_state.append(
                            {"number": 142, "title": CATALOG_DRIFT_ISSUE_TITLE, "author": {"login": "app/github-actions"}}
                        )
                        return "https://github.com/HakAl/free-inference/issues/142\n"
                    return ""

                res_create = reconcile_github_drift_issue(
                    repo="HakAl/free-inference",
                    exit_code=rc_drift,
                    json_report_path=json_out,
                    markdown_body_path=md_out,
                    is_default_branch=True,
                    run_gh_fn=_fake_gh,
                )
                self.assertEqual(res_create["action"], "created_issue")
                self.assertEqual(res_create["exit_code"], 0)
                self.assertEqual(len(gh_calls), 2)
                self.assertIn("--app", gh_calls[0])
                self.assertIn("--search", gh_calls[0])
                self.assertEqual(gh_calls[1][:2], ["issue", "create"])

                # Reconciler Case 2: Repeated drift with bot issue #142 at index 121 (beyond first 100 unfiltered issues)
                # edits only #142 (leaves #1..#120 and human #121 untouched)
                gh_calls.clear()
                res_edit = reconcile_github_drift_issue(
                    repo="HakAl/free-inference",
                    exit_code=rc_drift,
                    json_report_path=json_out,
                    markdown_body_path=md_out,
                    is_default_branch=True,
                    run_gh_fn=_fake_gh,
                )
                self.assertEqual(res_edit["action"], "updated_issue")
                self.assertEqual(res_edit["issue_number"], 142)
                self.assertEqual(res_edit["exit_code"], 0)
                self.assertEqual(gh_calls[1][:3], ["issue", "edit", "142"])

                # P4-R2-WORK-MINOR-1: Help-only invocation with existing --json-out/--markdown-out
                # returns 0, preserves preexisting report bytes, and makes no source requests
                saved_json_bytes = json_out.read_bytes()
                saved_md_bytes = md_out.read_bytes()
                with (
                    patch.object(
                        cli_mod,
                        "fetch_tinfoil_router_manifest",
                        side_effect=AssertionError("fetch should not be called on --help"),
                    ),
                    patch("sys.stdout"),
                ):
                    rc_help = cli_mod.main(
                        [
                            "--json-out",
                            str(json_out),
                            "--markdown-out",
                            str(md_out),
                            "--help",
                        ]
                    )
                self.assertEqual(rc_help, 0)
                self.assertTrue(json_out.exists())
                self.assertTrue(md_out.exists())
                self.assertEqual(json_out.read_bytes(), saved_json_bytes)
                self.assertEqual(md_out.read_bytes(), saved_md_bytes)

                # P4-WORK-MINOR-1: Invoke CLI with invalid arguments while valid drift json_out/md_out exist on disk;
                # verify CLI clears both files, returns exit 1 (not 2), and reconciler refuses with 0 gh calls
                rc_bad_arg = cli_mod.main(
                    [
                        "--check",
                        "--timeout",
                        "not-a-float",
                        "--json-out",
                        str(json_out),
                        "--markdown-out",
                        str(md_out),
                    ]
                )
                self.assertEqual(rc_bad_arg, 1)
                self.assertFalse(json_out.exists())
                self.assertFalse(md_out.exists())
                gh_calls.clear()
                with self.assertRaises(CatalogSyncError):
                    reconcile_github_drift_issue(
                        repo="HakAl/free-inference",
                        exit_code=rc_bad_arg,
                        json_report_path=json_out,
                        markdown_body_path=md_out,
                        is_default_branch=True,
                        run_gh_fn=_fake_gh,
                    )
                self.assertEqual(gh_calls, [])

                # Restore drift outputs for subsequent checks
                json_out.write_bytes(saved_json_bytes)
                md_out.write_bytes(saved_md_bytes)

                # Reconciler Case 6: Non-default branch dispatch -> skips issue mutations
                gh_calls.clear()
                res_branch = reconcile_github_drift_issue(
                    repo="HakAl/free-inference",
                    exit_code=rc_drift,
                    json_report_path=json_out,
                    markdown_body_path=md_out,
                    is_default_branch=False,
                    run_gh_fn=_fake_gh,
                )
                self.assertEqual(res_branch["action"], "skipped_non_default_branch")
                self.assertEqual(res_branch["exit_code"], 0)
                self.assertEqual(gh_calls, [])

                # (b) Apply and then check clean -> rc=0, check_status='clean'
                self.assertEqual(cli_mod.main(["--apply", "--models-path", str(tmp_models)]), 0)
                rc_clean = cli_mod.main(
                    [
                        "--check",
                        "--models-path",
                        str(tmp_models),
                        "--json-out",
                        str(json_out),
                        "--markdown-out",
                        str(md_out),
                    ]
                )
                self.assertEqual(rc_clean, 0)
                clean_json = json.loads(json_out.read_text(encoding="utf-8"))
                clean_md_bytes = md_out.read_bytes()
                self.assertEqual(clean_json["check_status"], "clean")

                # Non-default branch on clean run cannot close the default branch's open issue
                gh_calls.clear()
                res_branch_clean = reconcile_github_drift_issue(
                    repo="HakAl/free-inference",
                    exit_code=rc_clean,
                    json_report_path=json_out,
                    markdown_body_path=md_out,
                    is_default_branch=False,
                    run_gh_fn=_fake_gh,
                )
                self.assertEqual(res_branch_clean["action"], "skipped_non_default_branch")
                self.assertEqual(gh_calls, [])

                # Reconciler Case 3: Clean on default branch closes only bot issue #142
                res_close = reconcile_github_drift_issue(
                    repo="HakAl/free-inference",
                    exit_code=rc_clean,
                    json_report_path=json_out,
                    markdown_body_path=md_out,
                    is_default_branch=True,
                    run_gh_fn=_fake_gh,
                )
                self.assertEqual(res_close["action"], "closed_issue")
                self.assertEqual(res_close["issue_number"], 142)
                self.assertEqual(res_close["exit_code"], 0)
                self.assertEqual(gh_calls[1][:3], ["issue", "close", "142"])

                # Remove #142 from open_issues_state; subsequent clean run is noop_clean
                open_issues_state[:] = [i for i in open_issues_state if i["number"] != 142]
                gh_calls.clear()
                res_noop = reconcile_github_drift_issue(
                    repo="HakAl/free-inference",
                    exit_code=rc_clean,
                    json_report_path=json_out,
                    markdown_body_path=md_out,
                    is_default_branch=True,
                    run_gh_fn=_fake_gh,
                )
                self.assertEqual(res_noop["action"], "noop_clean")
                self.assertEqual(len(gh_calls), 1)

            # (c) Feed disagreement -> rc=1, writes check_status='disagreement', reconciler updates/creates issue and returns exit_code=1
            oai_disagree = copy.deepcopy(openai_models)
            oai_disagree["data"] = [m for m in oai_disagree["data"] if m["id"] != "deepseek-v4-1-flash"]
            with (
                patch.object(cli_mod, "fetch_tinfoil_router_manifest", return_value=router_manifest),
                patch.object(cli_mod, "fetch_tinfoil_openai_models", return_value=oai_disagree),
                patch.object(
                    cli_mod,
                    "fetch_tinfoil_enclave_config",
                    side_effect=lambda r, t, **kw: enclave_configs[f"{r}@{t}"],
                ),
            ):
                rc_dis = cli_mod.main(
                    [
                        "--check",
                        "--models-path",
                        str(tmp_models),
                        "--json-out",
                        str(json_out),
                        "--markdown-out",
                        str(md_out),
                    ]
                )
                self.assertEqual(rc_dis, 1)
                self.assertTrue(json_out.is_file())
                dis_json = json.loads(json_out.read_text(encoding="utf-8"))
                dis_md_bytes = md_out.read_bytes()
                self.assertEqual(dis_json["check_status"], "disagreement")

                gh_calls.clear()
                res_dis = reconcile_github_drift_issue(
                    repo="HakAl/free-inference",
                    exit_code=rc_dis,
                    json_report_path=json_out,
                    markdown_body_path=md_out,
                    is_default_branch=True,
                    run_gh_fn=_fake_gh,
                )
                self.assertEqual(res_dis["action"], "created_issue")
                self.assertEqual(res_dis["exit_code"], 1)

                # F1 (FREE-INFERENCE-CATALOG-P4-001): Controlled second-output partial-write failure with a
                # disagreement report: write valid JSON first, leave truncated Markdown and raise OSError;
                # require exit 1, unlinked outputs, and zero reconciliation mutations (even if cleanup fails).
                orig_atomic_write = cli_mod._atomic_write_text

                def _partial_second_write(target_path: Path, text: str) -> None:
                    if target_path == md_out:
                        orig_atomic_write(json_out, json.dumps(dis_json, indent=2) + "\n")
                        target_path.write_text("# Truncated disagreement body without closing fence", encoding="utf-8")
                        raise OSError("simulated disk full during markdown write")
                    orig_atomic_write(target_path, text)

                with patch.object(cli_mod, "_atomic_write_text", side_effect=_partial_second_write):
                    rc_partial = cli_mod.main(
                        [
                            "--check",
                            "--models-path",
                            str(tmp_models),
                            "--json-out",
                            str(json_out),
                            "--markdown-out",
                            str(md_out),
                        ]
                    )
                self.assertEqual(rc_partial, 1)
                self.assertFalse(json_out.exists())
                self.assertFalse(md_out.exists())
                gh_calls.clear()
                with self.assertRaises(CatalogSyncError):
                    reconcile_github_drift_issue(
                        repo="HakAl/free-inference",
                        exit_code=rc_partial,
                        json_report_path=json_out,
                        markdown_body_path=md_out,
                        is_default_branch=True,
                        run_gh_fn=_fake_gh,
                    )
                self.assertEqual(gh_calls, [])

                # F1 defense-in-depth: Even if cleanup failed and valid disagreement JSON remained beside
                # a truncated Markdown file, reconciler rejects via markdown_sha256 mismatch with 0 gh calls
                json_out.write_text(json.dumps(dis_json), encoding="utf-8")
                md_out.write_text("# Truncated disagreement body\n", encoding="utf-8")
                gh_calls.clear()
                with self.assertRaises(CatalogSyncError) as ctx_trunc_md:
                    reconcile_github_drift_issue(
                        repo="HakAl/free-inference",
                        exit_code=1,
                        json_report_path=json_out,
                        markdown_body_path=md_out,
                        is_default_branch=True,
                        run_gh_fn=_fake_gh,
                    )
                self.assertIn("markdown_sha256", str(ctx_trunc_md.exception))
                self.assertEqual(gh_calls, [])

                # P4-R3-WORK-MINOR-1: Start with a valid complete disagreement pair on disk (attempt-1),
                # force removal/truncation to fail and a new check (attempt-2) to fail before publishing
                # replacement outputs; assert exit 1 and 0 GitHub calls when reconciler runs for attempt-2.
                rc_dis_att1 = cli_mod.main(
                    [
                        "--check",
                        "--models-path",
                        str(tmp_models),
                        "--json-out",
                        str(json_out),
                        "--markdown-out",
                        str(md_out),
                        "--attempt-id",
                        "attempt-1",
                    ]
                )
                self.assertEqual(rc_dis_att1, 1)
                self.assertEqual(
                    json.loads(json_out.read_text(encoding="utf-8")).get("attempt_id"),
                    "attempt-1",
                )
                with (
                    patch.object(Path, "unlink", side_effect=PermissionError("unlink denied")),
                    patch.object(Path, "write_bytes", side_effect=PermissionError("truncate denied")),
                    patch.object(
                        cli_mod,
                        "fetch_tinfoil_router_manifest",
                        side_effect=AssertionError("fetch should not run after failed output invalidation"),
                    ),
                ):
                    rc_unlink_fail = cli_mod.main(
                        [
                            "--check",
                            "--models-path",
                            str(tmp_models),
                            "--json-out",
                            str(json_out),
                            "--markdown-out",
                            str(md_out),
                            "--attempt-id",
                            "attempt-2",
                        ]
                    )
                self.assertEqual(rc_unlink_fail, 1)
                # Intact attempt-1 disagreement pair still on disk, but reconciler for attempt-2 rejects it
                self.assertTrue(json_out.is_file())
                self.assertTrue(md_out.is_file())
                gh_calls.clear()
                with self.assertRaises(CatalogSyncError) as ctx_stale_att:
                    reconcile_github_drift_issue(
                        repo="HakAl/free-inference",
                        exit_code=rc_unlink_fail,
                        json_report_path=json_out,
                        markdown_body_path=md_out,
                        is_default_branch=True,
                        expected_attempt_id="attempt-2",
                        run_gh_fn=_fake_gh,
                    )
                self.assertIn("expected attempt_id='attempt-2'", str(ctx_stale_att.exception))
                self.assertEqual(gh_calls, [])

            # (d) Reconciler Case 5: Operational source failure -> CLI removes stale json_out/md_out and reconciler refuses without calling gh
            with patch.object(
                cli_mod,
                "fetch_tinfoil_router_manifest",
                side_effect=CatalogSyncError("upstream 502"),
            ):
                rc_err = cli_mod.main(
                    [
                        "--check",
                        "--models-path",
                        str(tmp_models),
                        "--json-out",
                        str(json_out),
                        "--markdown-out",
                        str(md_out),
                    ]
                )
                self.assertEqual(rc_err, 1)
                self.assertFalse(json_out.exists())
                self.assertFalse(md_out.exists())

            gh_calls.clear()
            with self.assertRaises(CatalogSyncError):
                reconcile_github_drift_issue(
                    repo="HakAl/free-inference",
                    exit_code=1,
                    json_report_path=json_out,
                    markdown_body_path=md_out,
                    is_default_branch=True,
                    run_gh_fn=_fake_gh,
                )
            with self.assertRaises(CatalogSyncError):
                reconcile_github_drift_issue(
                    repo="HakAl/free-inference",
                    exit_code=2,
                    json_report_path=json_out,
                    markdown_body_path=md_out,
                    is_default_branch=True,
                    run_gh_fn=_fake_gh,
                )
            self.assertEqual(gh_calls, [])

            # P4-WORK-MINOR-3: Existing files with contradictory (exit_code, check_status) pairs raise CatalogSyncError with 0 gh calls
            for bad_rc, bad_payload, matching_md in (
                (2, clean_json, clean_md_bytes),
                (0, drift_json, saved_md_bytes),
                (1, clean_json, clean_md_bytes),
                (1, drift_json, saved_md_bytes),
                (0, dis_json, dis_md_bytes),
            ):
                json_out.write_text(json.dumps(bad_payload), encoding="utf-8")
                md_out.write_bytes(matching_md)
                gh_calls.clear()
                with self.assertRaises(CatalogSyncError):
                    reconcile_github_drift_issue(
                        repo="HakAl/free-inference",
                        exit_code=bad_rc,
                        json_report_path=json_out,
                        markdown_body_path=md_out,
                        is_default_branch=True,
                        run_gh_fn=_fake_gh,
                    )
                self.assertEqual(gh_calls, [])

            # P4-WORK-MINOR-3: Post-lookup mutation failures (create, edit, close) propagate CatalogSyncError
            def _gh_fail_on_mutation(fail_subcmd: str):
                def _runner(args: list[str]) -> str:
                    if args[:2] == ["issue", "list"]:
                        return _fake_gh(args)
                    if args[:2] == ["issue", fail_subcmd]:
                        raise CatalogSyncError(f"gh issue {fail_subcmd} failed: HTTP 500")
                    return ""
                return _runner

            # Fail on edit (issue #142 is currently in open_issues_state)
            json_out.write_text(json.dumps(drift_json), encoding="utf-8")
            md_out.write_bytes(saved_md_bytes)
            with self.assertRaises(CatalogSyncError) as ctx_edit_fail:
                reconcile_github_drift_issue(
                    repo="HakAl/free-inference",
                    exit_code=2,
                    json_report_path=json_out,
                    markdown_body_path=md_out,
                    is_default_branch=True,
                    run_gh_fn=_gh_fail_on_mutation("edit"),
                )
            self.assertIn("gh issue edit failed", str(ctx_edit_fail.exception))

            # Fail on close (issue #142 is in open_issues_state)
            json_out.write_text(json.dumps(clean_json), encoding="utf-8")
            md_out.write_bytes(clean_md_bytes)
            with self.assertRaises(CatalogSyncError) as ctx_close_fail:
                reconcile_github_drift_issue(
                    repo="HakAl/free-inference",
                    exit_code=0,
                    json_report_path=json_out,
                    markdown_body_path=md_out,
                    is_default_branch=True,
                    run_gh_fn=_gh_fail_on_mutation("close"),
                )
            self.assertIn("gh issue close failed", str(ctx_close_fail.exception))

            # Fail on create (remove #142 first)
            open_issues_state[:] = [i for i in open_issues_state if i["number"] != 142]
            json_out.write_text(json.dumps(drift_json), encoding="utf-8")
            md_out.write_bytes(saved_md_bytes)
            with self.assertRaises(CatalogSyncError) as ctx_create_fail:
                reconcile_github_drift_issue(
                    repo="HakAl/free-inference",
                    exit_code=2,
                    json_report_path=json_out,
                    markdown_body_path=md_out,
                    is_default_branch=True,
                    run_gh_fn=_gh_fail_on_mutation("create"),
                )
            self.assertIn("gh issue create failed", str(ctx_create_fail.exception))

            # P4-WORK-MINOR-3: Exercise _default_run_gh subprocess error conversion directly
            import subprocess
            from local_assist.catalog_sync import _default_run_gh

            with patch(
                "local_assist.catalog_sync.subprocess.run",
                side_effect=subprocess.CalledProcessError(
                    1, ["gh", "issue", "edit"], stderr="HTTP 403: Resource not accessible by integration"
                ),
            ):
                with self.assertRaises(CatalogSyncError) as ctx_subproc:
                    _default_run_gh(["issue", "edit", "142"])
                self.assertIn("HTTP 403", str(ctx_subproc.exception))

            with patch(
                "local_assist.catalog_sync.subprocess.run",
                side_effect=FileNotFoundError("No such file: gh"),
            ):
                with self.assertRaises(CatalogSyncError) as ctx_notfound:
                    _default_run_gh(["issue", "list"])
                self.assertIn("not installed", str(ctx_notfound.exception))

        # 3. Structural validation of lab/.github/workflows/catalog-sync.yml
        wf_path = ROOT / ".github" / "workflows" / "catalog-sync.yml"
        self.assertTrue(wf_path.is_file())
        wf_data = safe_load(wf_path.read_text(encoding="utf-8"))
        self.assertEqual(wf_data["permissions"], {"contents": "read"})
        self.assertEqual(wf_data["on"]["schedule"], [{"cron": "0 9 * * 1"}])
        self.assertIn("workflow_dispatch", wf_data["on"])
        self.assertEqual(
            wf_data["concurrency"],
            {"group": "catalog-drift-check", "cancel-in-progress": False},
        )
        job = wf_data["jobs"]["check-catalog-drift"]
        self.assertEqual(job["runs-on"], "ubuntu-latest")
        self.assertEqual(job["permissions"], {"contents": "read", "issues": "write"})
        steps = job["steps"]
        self.assertEqual(
            steps[0]["uses"],
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        )
        self.assertEqual(steps[0]["with"], {"persist-credentials": False})
        self.assertEqual(
            steps[1]["uses"],
            "actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0",
        )
        # GH_TOKEN is confined strictly to the reconciliation step (step 3), not the check step (step 2)
        self.assertNotIn("GH_TOKEN", steps[2].get("env") or {})
        self.assertIn("GH_TOKEN", steps[3].get("env") or {})

        # 4. Multi-platform host_code_tags canonicalization and weight-consistency check
        models_multi = _make_base_models_fixture()
        models_multi["models"][1]["enclave_tag"] = "v0.0.10+b200"
        models_multi["models"][1]["remote_trust"]["pricing_per_m_tokens"] = {
            "input": 0.6,
            "cached_input": 0.01,
            "output": 1.45,
        }
        router_multi = _make_router_manifest_fixture()
        router_multi["models"]["deepseek-v4-1-flash"]["tag"] = "v0.0.10+b300"
        router_multi["models"]["deepseek-v4-1-flash"]["verification"]["hosts"] = {
            "host-tdx-0": {"code_tag": "v0.0.10+b200"},
            "host-snp-0": {"code_tag": "v0.0.10+b300"},
        }
        cfg_b200 = parse_tinfoil_config_yaml(DEEPSEEK_V4_1_FLASH_YAML)
        cfg_b300 = parse_tinfoil_config_yaml(DEEPSEEK_V4_1_FLASH_YAML)
        report_multi = compute_catalog_drift(
            models_multi,
            router_multi,
            _make_openai_models_fixture(),
            {
                "tinfoilsh/confidential-deepseek-v4-1-flash@v0.0.10+b200": cfg_b200,
                "tinfoilsh/confidential-deepseek-v4-1-flash@v0.0.10+b300": cfg_b300,
                "tinfoilsh/confidential-kimi-k3@v0.0.16": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
                "tinfoilsh/confidential-kimi-k3-1-pro@v0.0.3": parse_tinfoil_config_yaml(KIMI_K3_1_PRO_V0_0_3_YAML),
            },
            observed_date="2026-11-07",
        )
        ds_updates = [
            u for u in report_multi.updated_models if u.model_id == "tinfoil-deepseek-v4-1-flash"
        ]
        self.assertEqual(ds_updates, [])

        # Divergent weights across active host code_tags fail closed
        cfg_b300_bad = copy.deepcopy(cfg_b300)
        cfg_b300_bad["models"][0]["mpk"] = (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_510311071744_27a6c072-8626-550d-a130-c888e25902cb"
        )
        with self.assertRaises(CatalogSyncError) as ctx_multi_div:
            compute_catalog_drift(
                models_multi,
                router_multi,
                _make_openai_models_fixture(),
                {
                    "tinfoilsh/confidential-deepseek-v4-1-flash@v0.0.10+b200": cfg_b200,
                    "tinfoilsh/confidential-deepseek-v4-1-flash@v0.0.10+b300": cfg_b300_bad,
                    "tinfoilsh/confidential-kimi-k3@v0.0.16": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
                    "tinfoilsh/confidential-kimi-k3-1-pro@v0.0.3": parse_tinfoil_config_yaml(KIMI_K3_1_PRO_V0_0_3_YAML),
                },
                observed_date="2026-11-07",
            )
        self.assertIn("inconsistent weights across active host code_tags", str(ctx_multi_div.exception))

        # F2 (FREE-INFERENCE-CATALOG-P4-001): Legacy served-ID-only cache cannot bypass cross-tag verification
        with self.assertRaises(CatalogSyncError) as ctx_f2_ambig:
            compute_catalog_drift(
                models_multi,
                router_multi,
                _make_openai_models_fixture(),
                {
                    "deepseek-v4-1-flash": cfg_b200,
                    "kimi-k3": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
                    "kimi-k3-1-pro": parse_tinfoil_config_yaml(KIMI_K3_1_PRO_V0_0_3_YAML),
                },
                observed_date="2026-11-07",
            )
        self.assertIn("Ambiguous served-ID-only cache", str(ctx_f2_ambig.exception))

        # Mixed cache/fetcher fixture 1: b200 qualified + served_id alias, fetcher supplies divergent b300 config
        fetched_pairs: list[tuple[str, str]] = []

        def _mixed_fetcher(repo: str, tag: str) -> dict:
            fetched_pairs.append((repo, tag))
            if (repo, tag) == ("tinfoilsh/confidential-deepseek-v4-1-flash", "v0.0.10+b300"):
                return cfg_b300_bad
            raise AssertionError(f"Unexpected fetch for {repo}@{tag}")

        with self.assertRaises(CatalogSyncError) as ctx_f2_mixed:
            compute_catalog_drift(
                models_multi,
                router_multi,
                _make_openai_models_fixture(),
                {
                    "deepseek-v4-1-flash": cfg_b200,
                    "tinfoilsh/confidential-deepseek-v4-1-flash@v0.0.10+b200": cfg_b200,
                    "kimi-k3": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
                    "kimi-k3-1-pro": parse_tinfoil_config_yaml(KIMI_K3_1_PRO_V0_0_3_YAML),
                },
                enclave_config_fetcher=_mixed_fetcher,
                observed_date="2026-11-07",
            )
        self.assertEqual(
            fetched_pairs,
            [("tinfoilsh/confidential-deepseek-v4-1-flash", "v0.0.10+b300")],
        )
        self.assertIn("inconsistent weights across active host code_tags", str(ctx_f2_mixed.exception))

        # P4-R3-WORK-MINOR-2: Mirrored mixed-cache fixture: unqualified alias and qualified b300 agree,
        # while primary b200 has no qualified cache entry and fetcher supplies divergent b200 weights.
        cfg_b200_bad = copy.deepcopy(cfg_b200)
        cfg_b200_bad["models"][0]["mpk"] = (
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee_510311071744_27a6c072-8626-550d-a130-c888e25902cb"
        )
        mirrored_fetches: list[tuple[str, str]] = []

        def _mirrored_fetcher(repo: str, tag: str) -> dict:
            mirrored_fetches.append((repo, tag))
            if (repo, tag) == ("tinfoilsh/confidential-deepseek-v4-1-flash", "v0.0.10+b200"):
                return cfg_b200_bad
            raise AssertionError(f"Unexpected fetch for {repo}@{tag}")

        with self.assertRaises(CatalogSyncError) as ctx_f2_mirrored:
            compute_catalog_drift(
                models_multi,
                router_multi,
                _make_openai_models_fixture(),
                {
                    "deepseek-v4-1-flash": cfg_b300,
                    "tinfoilsh/confidential-deepseek-v4-1-flash@v0.0.10+b300": cfg_b300,
                    "kimi-k3": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
                    "kimi-k3-1-pro": parse_tinfoil_config_yaml(KIMI_K3_1_PRO_V0_0_3_YAML),
                },
                enclave_config_fetcher=_mirrored_fetcher,
                observed_date="2026-11-07",
            )
        self.assertEqual(
            mirrored_fetches,
            [("tinfoilsh/confidential-deepseek-v4-1-flash", "v0.0.10+b200")],
        )
        self.assertIn("inconsistent weights across active host code_tags", str(ctx_f2_mirrored.exception))

    def test_review_20261107_catalog_sync_hardening(self) -> None:
        from local_assist.catalog_sync import (
            ENCLAVE_REPO_RE,
            MAX_GITHUB_ISSUE_BODY_CHARS,
            SERVED_ID_RE,
            _strict_json_loads,
        )

        # A3a: Registered already-demoted candidate model (routing.private_attested=blocked)
        # with healthy=0 in router manifest and absent from /v1/models must still emit a
        # FeedDisagreementItem so weekly --check does not report clean and close the issue.
        models_a3a = _make_base_models_fixture()
        router_a3a = _make_router_manifest_fixture()
        router_a3a["models"]["kimi-k3"]["verification"]["healthy"] = 0
        oai_a3a = _make_openai_models_fixture()
        oai_a3a["data"] = [m for m in oai_a3a["data"] if m["id"] != "kimi-k3"]
        enclaves_base = {
            "tinfoilsh/confidential-deepseek-v4-1-flash@v0.0.10+b200": parse_tinfoil_config_yaml(
                DEEPSEEK_V4_1_FLASH_YAML
            ),
            "tinfoilsh/confidential-kimi-k3@v0.0.16": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
            "tinfoilsh/confidential-kimi-k3-1-pro@v0.0.3": parse_tinfoil_config_yaml(
                KIMI_K3_1_PRO_V0_0_3_YAML
            ),
        }
        rep_a3a = compute_catalog_drift(
            models_a3a,
            router_a3a,
            oai_a3a,
            enclaves_base,
            observed_date="2026-11-08",
        )
        self.assertEqual(len(rep_a3a.disagreements), 1)
        self.assertEqual(rep_a3a.disagreements[0].model_id, "tinfoil-kimi-k3")
        self.assertEqual(rep_a3a.disagreements[0].router_healthy, 0)
        self.assertTrue(rep_a3a.has_drift)

        # A3b: Registered model with status='archived' stays at status='archived' (one-way ratchet)
        # whether healthy > 0 or healthy == 0.
        models_a3b = _make_base_models_fixture()
        models_a3b["models"][2]["status"] = "archived"
        rep_a3b_healthy = compute_catalog_drift(
            models_a3b,
            _make_router_manifest_fixture(),
            _make_openai_models_fixture(),
            enclaves_base,
            observed_date="2026-11-08",
        )
        kimi_up_h = [u for u in rep_a3b_healthy.updated_models if u.model_id == "tinfoil-kimi-k3"]
        for u in kimi_up_h:
            self.assertNotIn("status", u.changes)
        rep_a3b_zero = compute_catalog_drift(
            models_a3b,
            router_a3a,
            _make_openai_models_fixture(),
            enclaves_base,
            observed_date="2026-11-08",
        )
        kimi_up_z = [u for u in rep_a3b_zero.updated_models if u.model_id == "tinfoil-kimi-k3"]
        for u in kimi_up_z:
            self.assertNotIn("status", u.changes)

        # A3c: ENCLAVE_REPO_RE and SERVED_ID_RE reject non-tinfoilsh owners, dot segments, and slashes
        for bad_repo in ("evil/repo", "tinfoilsh/..", "tinfoilsh/.", "tinfoilsh/.hidden"):
            self.assertIsNone(ENCLAVE_REPO_RE.match(bad_repo), f"Accepted {bad_repo!r}")
            router_bad_repo = _make_router_manifest_fixture()
            router_bad_repo["models"]["kimi-k3"]["repo"] = bad_repo
            with self.assertRaises(CatalogSyncError):
                validate_router_manifest(router_bad_repo)
        for bad_sid in ("../bad", "bad/slash", ".hidden", ""):
            self.assertIsNone(SERVED_ID_RE.match(bad_sid), f"Accepted {bad_sid!r}")

        # A3d & PLAN-MINOR-1 & WORK-MINOR-2: Symmetric discovery disagreement in both directions
        # Direction 1: Unregistered model in router manifest absent from /v1/models:
        # healthy=2 is included as a disagreement; healthy=0 is excluded
        router_d1_healthy = _make_router_manifest_fixture()
        router_d1_healthy["models"]["mystery-router-only"] = {
            "repo": "tinfoilsh/confidential-mystery",
            "tag": "v0.0.1",
            "verification": {"configured": 2, "healthy": 2},
        }
        rep_d1_healthy = compute_catalog_drift(
            _make_base_models_fixture(),
            router_d1_healthy,
            _make_openai_models_fixture(),
            enclaves_base,
            observed_date="2026-11-08",
        )
        self.assertIn(
            "mystery-router-only",
            [d.served_model_id for d in rep_d1_healthy.disagreements],
        )

        router_d1_zero = _make_router_manifest_fixture()
        router_d1_zero["models"]["mystery-router-only"] = {
            "repo": "tinfoilsh/confidential-mystery",
            "tag": "v0.0.1",
            "verification": {"configured": 2, "healthy": 0},
        }
        rep_d1_zero = compute_catalog_drift(
            _make_base_models_fixture(),
            router_d1_zero,
            _make_openai_models_fixture(),
            enclaves_base,
            observed_date="2026-11-08",
        )
        self.assertNotIn(
            "mystery-router-only",
            [d.served_model_id for d in rep_d1_zero.disagreements],
        )

        # Direction 2: Unregistered coding model (type='chat', tool_calling=True) in /v1/models
        # absent from router manifest is included regardless of owned_by, while non-coding or deprecated models are excluded
        for owner_val in ("tinfoil", "other-org"):
            oai_d2 = _make_openai_models_fixture()
            oai_d2["data"].append(
                {
                    "id": "mystery-oai-only",
                    "owned_by": owner_val,
                    "type": "chat",
                    "tool_calling": True,
                }
            )
            rep_d2 = compute_catalog_drift(
                _make_base_models_fixture(),
                _make_router_manifest_fixture(),
                oai_d2,
                enclaves_base,
                observed_date="2026-11-08",
            )
            dis_ids_d2 = [d.served_model_id for d in rep_d2.disagreements]
            self.assertIn("mystery-oai-only", dis_ids_d2)

        oai_d2_excluded = _make_openai_models_fixture()
        oai_d2_excluded["data"].extend(
            [
                {"id": "mystery-embed-only", "type": "embedding", "tool_calling": False},
                {"id": "mystery-dep-only", "type": "chat", "tool_calling": True, "deprecated": True},
            ]
        )
        rep_d2_excl = compute_catalog_drift(
            _make_base_models_fixture(),
            _make_router_manifest_fixture(),
            oai_d2_excluded,
            enclaves_base,
            observed_date="2026-11-08",
        )
        dis_ids_excl = [d.served_model_id for d in rep_d2_excl.disagreements]
        self.assertNotIn("mystery-embed-only", dis_ids_excl)
        self.assertNotIn("mystery-dep-only", dis_ids_excl)

        # A3e: --apply --quarantine-disagreements records quarantine_disagreement in updated_models
        # and CLI emits check_status == 'quarantined'
        models_a3e = _make_base_models_fixture()
        oai_dis_ds = _make_openai_models_fixture()
        oai_dis_ds["data"] = [m for m in oai_dis_ds["data"] if m["id"] != "deepseek-v4-1-flash"]
        rep_a3e = compute_catalog_drift(
            models_a3e,
            _make_router_manifest_fixture(),
            oai_dis_ds,
            enclaves_base,
            observed_date="2026-11-08",
        )
        self.assertEqual(len(rep_a3e.disagreements), 1)
        with tempfile.TemporaryDirectory() as td_e:
            p_e = Path(td_e) / "models.yaml"
            p_e.write_text(dump_models_yaml(models_a3e), encoding="utf-8")
            os.chmod(p_e, 0o640)
            healed_e = apply_catalog_healing(
                p_e,
                rep_a3e,
                quarantine_disagreements=True,
            )
            # Mode 0o640 preserved across atomic write
            self.assertEqual(os.stat(p_e).st_mode & 0o777, 0o640)
            q_items = [u for u in rep_a3e.updated_models if u.action == "quarantine_disagreement"]
            self.assertEqual(len(q_items), 1)
            self.assertEqual(q_items[0].model_id, "tinfoil-deepseek-v4-1-flash")
            ds_healed = [m for m in healed_e["models"] if m["id"] == "tinfoil-deepseek-v4-1-flash"][0]
            self.assertEqual(ds_healed["routing"]["private_attested"], "blocked")
            self.assertEqual(ds_healed["status"], "candidate")
            self.assertIn("Quarantined due to feed disagreement", q_items[0].notes[0])
            self.assertEqual(
                ds_healed["stale_eval_evidence_artifact"],
                "docs/evals/tinfoil-deepseek-v4-1-flash.json",
            )

            import importlib.machinery
            import importlib.util

            script_path = ROOT / "scripts" / "sync-model-catalog"
            loader = importlib.machinery.SourceFileLoader("sync_model_catalog_cli_a3e", str(script_path))
            spec = importlib.util.spec_from_loader(loader.name, loader)
            assert spec is not None and spec.loader is not None
            cli_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cli_mod)
            p_e2 = Path(td_e) / "models2.yaml"
            p_e2.write_text(dump_models_yaml(models_a3e), encoding="utf-8")
            json_e2 = Path(td_e) / "out.json"
            with (
                patch.object(cli_mod, "fetch_tinfoil_router_manifest", return_value=_make_router_manifest_fixture()),
                patch.object(cli_mod, "fetch_tinfoil_openai_models", return_value=oai_dis_ds),
                patch.object(
                    cli_mod,
                    "fetch_tinfoil_enclave_config",
                    side_effect=lambda r, t, **kw: enclaves_base[f"{r}@{t}"],
                ),
            ):
                rc_q = cli_mod.main(
                    [
                        "--apply",
                        "--quarantine-disagreements",
                        "--models-path",
                        str(p_e2),
                        "--json-out",
                        str(json_e2),
                    ]
                )
            self.assertEqual(rc_q, 0)
            q_payload = json.loads(json_e2.read_text(encoding="utf-8"))
            self.assertEqual(q_payload["check_status"], "quarantined")

            # A3f: _strict_json_loads rejects NaN, Infinity, and 1e999; apply_catalog_healing rejects non-finite numbers
            for bad_json in ('{"p": NaN}', '{"p": Infinity}', '{"p": -Infinity}', '{"p": 1e999}'):
                with self.assertRaises(CatalogSyncError):
                    _strict_json_loads(bad_json, context="test")

            p_nan = Path(td_e) / "models_nan.yaml"
            p_nan.write_text(dump_models_yaml(_make_base_models_fixture()), encoding="utf-8")
            rep_nan = copy.deepcopy(rep_a3e)
            rep_nan.disagreements.clear()
            rep_nan.updated_models.clear()
            rep_nan.new_models[0]["remote_trust"]["pricing_per_m_tokens"]["input"] = float("inf")
            with self.assertRaises(CatalogSyncError):
                apply_catalog_healing(p_nan, rep_nan)

        # A3g & WORK-MINOR-5: host_code_tags > 8 and enclave_config_fetches > 32 (including across a 2-pass --apply recomputation)
        # raise CatalogSyncError; catalog-sync.yml has timeout-minutes: 5
        wf_data = safe_load((ROOT / ".github" / "workflows" / "catalog-sync.yml").read_text(encoding="utf-8"))
        self.assertEqual(wf_data["jobs"]["check-catalog-drift"].get("timeout-minutes"), 5)

        router_many_tags = _make_router_manifest_fixture()
        router_many_tags["models"]["deepseek-v4-1-flash"]["verification"]["hosts"] = {
            f"host-{i}": {"code_tag": f"v0.0.{i}"} for i in range(10)
        }
        with self.assertRaises(CatalogSyncError) as ctx_tags:
            validate_router_manifest(router_many_tags)
        self.assertIn("exceeds cap of 8", str(ctx_tags.exception))

        # Two-pass shared fetch budget: Pass 1 performs 32 uncached fetches, then a concurrent catalog change
        # triggers Pass 2 which attempts a 33rd uncached fetch and fails closed (WORK-MINOR-5)
        with tempfile.TemporaryDirectory() as td_g:
            p_g = Path(td_g) / "models_budget.yaml"
            models_32 = _make_base_models_fixture()
            router_33 = _make_router_manifest_fixture()
            oai_33 = _make_openai_models_fixture()
            base_ds_tmpl = copy.deepcopy(
                [m for m in models_32["models"] if m["id"] == "tinfoil-deepseek-v4-1-flash"][0]
            )
            base_ds_tmpl["status"] = "candidate"
            base_ds_tmpl["routing"]["private_attested"] = "blocked"
            base_ds_tmpl.pop("eval_evidence_artifact", None)
            models_32["models"] = []
            for idx in range(33):
                sid = f"budget-model-{idx:02d}"
                er = f"tinfoilsh/confidential-{sid}"
                et = "v0.0.1"
                router_33["models"][sid] = {
                    "repo": er,
                    "tag": et,
                    "verification": {"configured": 1, "healthy": 1},
                }
                oai_33["data"].append(
                    {
                        "id": sid,
                        "name": f"Budget {idx}",
                        "type": "chat",
                        "tool_calling": True,
                        "context_window": 32768,
                        "pricing": {"inputTokenPricePer1M": 1.0, "outputTokenPricePer1M": 2.0},
                    }
                )
                if idx < 32:
                    m_entry = copy.deepcopy(base_ds_tmpl)
                    m_entry["id"] = f"tinfoil-{sid}"
                    m_entry["repo"] = sid
                    m_entry["enclave_repo"] = er
                    m_entry["enclave_tag"] = et
                    models_32["models"].append(m_entry)

            # Mutated catalog on disk has all 33 models so when CLI re-reads models.yaml before healing,
            # the digest differs and triggers Pass 2 (which hits the 33rd uncached model)
            models_33 = copy.deepcopy(models_32)
            m_33 = copy.deepcopy(base_ds_tmpl)
            m_33["id"] = "tinfoil-budget-model-32"
            m_33["repo"] = "budget-model-32"
            m_33["enclave_repo"] = "tinfoilsh/confidential-budget-model-32"
            m_33["enclave_tag"] = "v0.0.1"
            models_33["models"].append(m_33)
            # Initially write 32 models to disk; during Pass 1's 32nd config fetch,
            # concurrently write the 33-model catalog to p_g so Pass 2 is triggered and attempts a 33rd fetch
            p_g.write_text(dump_models_yaml(models_32), encoding="utf-8")

            ds_cfg_parsed = parse_tinfoil_config_yaml(DEEPSEEK_V4_1_FLASH_YAML)
            fetch_calls = [0]

            def _concurrent_fetch_enclave(repo: str, _t: str, **_kw: object) -> dict:
                fetch_calls[0] += 1
                if fetch_calls[0] == 32:
                    p_g.write_text(dump_models_yaml(models_33), encoding="utf-8")
                sid = repo.removeprefix("tinfoilsh/confidential-")
                return parse_tinfoil_config_yaml(
                    DEEPSEEK_V4_1_FLASH_YAML.replace("deepseek-v4-1-flash", sid)
                )

            with (
                patch.object(cli_mod, "fetch_tinfoil_router_manifest", return_value=router_33),
                patch.object(cli_mod, "fetch_tinfoil_openai_models", return_value=oai_33),
                patch.object(
                    cli_mod,
                    "fetch_tinfoil_enclave_config",
                    side_effect=_concurrent_fetch_enclave,
                ),
            ):
                rc_budget = cli_mod.main(
                    [
                        "--apply",
                        "--no-discover-new",
                        "--models-path",
                        str(p_g),
                    ]
                )
            self.assertEqual(rc_budget, 1)
            self.assertEqual(fetch_calls[0], 32)

        # A3h & WORK-MINOR-3: render_github_issue_body truncates oversized reports AND long backtick runs
        # cleanly within MAX_GITHUB_ISSUE_BODY_CHARS while preserving </details>\n
        huge_report = copy.deepcopy(rep_a3e)
        huge_report.new_models.append(
            {
                "id": "tinfoil-backtick-bomb",
                "repo": "backtick-bomb",
                "enclave_repo": "tinfoilsh/confidential-backtick-bomb",
                "enclave_tag": "v0.0.1",
                "license": "MIT " + ("`" * 25000),
                "fit_notes": "Model name with " + ("`" * 25000),
                "disk_gb_estimate": 100.0,
                "remote_trust": {
                    "provider_manifest_weights_source": "org/model@" + ("a" * 40),
                    "provider_manifest_weights_hash": "dmverity:sha256:" + ("b" * 64),
                    "pricing_per_m_tokens": {"input": 1.0, "output": 2.0},
                },
            }
        )
        for i in range(500):
            huge_report.new_models.append(
                {
                    "id": f"tinfoil-huge-model-{i:04d}",
                    "repo": f"huge-model-{i:04d}",
                    "enclave_repo": f"tinfoilsh/confidential-huge-{i:04d}",
                    "enclave_tag": "v0.0.1",
                    "disk_gb_estimate": 100.0,
                    "remote_trust": {
                        "provider_manifest_weights_source": "org/model@" + ("a" * 40),
                        "provider_manifest_weights_hash": "dmverity:sha256:" + ("b" * 64),
                        "pricing_per_m_tokens": {"input": 1.0, "output": 2.0},
                    },
                }
            )
        rendered_huge = render_github_issue_body(
            huge_report.to_dict(),
            exit_code=2,
            human_output=("`" * 25000) + "\n" + ("huge human output line\n" * 4000),
        )
        self.assertLessEqual(len(rendered_huge), MAX_GITHUB_ISSUE_BODY_CHARS)
        self.assertTrue(rendered_huge.endswith("</details>\n"))
        self.assertIn("truncated to fit GitHub 65536-char issue body limit", rendered_huge)
        self.assertIn("backticks]", rendered_huge)

        # FREE-INFERENCE-V013-001 F1: Unregistered discovery disagreements cannot collide with or quarantine a registered model
        from local_assist.catalog_sync import CatalogDriftReport, FeedDisagreementItem

        # 1. Colliding OpenAI-only served_id ('tinfoil-deepseek-v4-1-flash') while original ('deepseek-v4-1-flash') is healthy in both feeds
        models_f1_base = _make_base_models_fixture()
        router_f1_base = _make_router_manifest_fixture()
        oai_f1_base = _make_openai_models_fixture()
        oai_f1_collide = copy.deepcopy(oai_f1_base)
        oai_f1_collide["data"].append(
            {
                "id": "tinfoil-deepseek-v4-1-flash",
                "type": "chat",
                "tool_calling": True,
                "deprecated": False,
                "pricing": {"prompt": 0.5, "completion": 1.0},
            }
        )
        with self.assertRaises(CatalogSyncError) as ctx_f1_oai:
            compute_catalog_drift(
                models_f1_base,
                router_f1_base,
                oai_f1_collide,
                enclaves_base,
                observed_date="2026-11-08",
            )
        self.assertIn("collides with existing catalog entry id='tinfoil-deepseek-v4-1-flash'", str(ctx_f1_oai.exception))

        # 2. Colliding router-only served_id ('tinfoil-deepseek-v4-1-flash') while original ('deepseek-v4-1-flash') is healthy in both feeds
        router_f1_collide = copy.deepcopy(router_f1_base)
        router_f1_collide["models"]["tinfoil-deepseek-v4-1-flash"] = {
            "repo": "tinfoilsh/confidential-colliding",
            "tag": "v0.0.1",
            "verification": {"healthy": 1, "configured": 1},
        }
        with self.assertRaises(CatalogSyncError) as ctx_f1_rtr:
            compute_catalog_drift(
                models_f1_base,
                router_f1_collide,
                oai_f1_base,
                enclaves_base,
                observed_date="2026-11-08",
            )
        self.assertIn("collides with existing catalog entry id='tinfoil-deepseek-v4-1-flash'", str(ctx_f1_rtr.exception))

        # 3. CLI --apply --quarantine-disagreements refuses colliding discovery disagreement and leaves models.yaml untouched,
        # and apply_catalog_healing rejects any synthetic registered disagreement with mismatched served_model_id or non-Tinfoil target
        with tempfile.TemporaryDirectory() as tmpdir_f1:
            p_f1 = Path(tmpdir_f1) / "models.yaml"
            p_f1.write_text(dump_models_yaml(models_f1_base), encoding="utf-8")
            orig_bytes_f1 = p_f1.read_bytes()

            with (
                patch.object(cli_mod, "fetch_tinfoil_router_manifest", return_value=router_f1_base),
                patch.object(cli_mod, "fetch_tinfoil_openai_models", return_value=oai_f1_collide),
                patch.object(
                    cli_mod,
                    "fetch_tinfoil_enclave_config",
                    side_effect=lambda r, t, **kw: enclaves_base[f"{r}@{t}"],
                ),
            ):
                rc_f1_cli = cli_mod.main(
                    [
                        "--apply",
                        "--quarantine-disagreements",
                        "--models-path",
                        str(p_f1),
                    ]
                )
            self.assertEqual(rc_f1_cli, 1)
            self.assertEqual(p_f1.read_bytes(), orig_bytes_f1)

            # Synthetic registered=True disagreement with mismatched served_model_id refuses before publication
            synth_mismatch = CatalogDriftReport(
                observed_date="2026-11-08",
                base_catalog_sha256=compute_models_data_digest(models_f1_base),
                disagreements=[
                    FeedDisagreementItem(
                        model_id="tinfoil-deepseek-v4-1-flash",
                        served_model_id="tinfoil-deepseek-v4-1-flash",
                        in_router_manifest=False,
                        in_openai_models=True,
                        router_healthy=None,
                        reason="synthetic collision",
                        registered=True,
                    )
                ],
            )
            with self.assertRaises(CatalogSyncError) as ctx_f1_synth:
                apply_catalog_healing(
                    p_f1,
                    synth_mismatch,
                    append_new_models=False,
                    quarantine_disagreements=True,
                )
            self.assertIn("served_model_id 'deepseek-v4-1-flash' does not match", str(ctx_f1_synth.exception))
            self.assertEqual(p_f1.read_bytes(), orig_bytes_f1)

            # Non-colliding unregistered disagreement (registered=False) does not quarantine any registered model
            unreg_rep = CatalogDriftReport(
                observed_date="2026-11-08",
                base_catalog_sha256=compute_models_data_digest(models_f1_base),
                disagreements=[
                    FeedDisagreementItem(
                        model_id="tinfoil-new-unreg-coder",
                        served_model_id="new-unreg-coder",
                        in_router_manifest=False,
                        in_openai_models=True,
                        router_healthy=None,
                        reason="unregistered coding model",
                        registered=False,
                    )
                ],
            )
            healed_unreg = apply_catalog_healing(
                p_f1,
                unreg_rep,
                append_new_models=False,
                quarantine_disagreements=True,
            )
            ds_after = next(m for m in healed_unreg["models"] if m["id"] == "tinfoil-deepseek-v4-1-flash")
            self.assertEqual(ds_after["status"], "active")
            self.assertEqual(ds_after["routing"]["private_attested"], "cleared")
            self.assertEqual(ds_after["eval_evidence_artifact"], "docs/evals/tinfoil-deepseek-v4-1-flash.json")
            self.assertNotIn("stale_eval_evidence_artifact", ds_after)

    def test_privatemode_entries_ignored_by_tinfoil_catalog_sync(self) -> None:
        from local_assist.catalog_sync import is_tinfoil_managed_model

        models_with_pm = _make_base_models_fixture()
        pm_entries = [
            {
                "id": "privatemode-glm-5-3-flash",
                "status": "candidate",
                "repo": "glm-5.3-flash",
                "upstream": "nvidia/GLM-5.3-Flash-NVFP4",
                "runtime": "proxy",
                "serve_command": "./bin/privatemode-proxy --listen-address {host} --port {port} --api-key-fallback=never --manifest-path config/privatemode-manifest-v1.63.0.json --workspace .home/privatemode-proxy --disable-prompt-cache=false --prompt-cache-salt=random --nvidia-ocsp-allow-unknown=false --nvidia-ocsp-revoked-grace-period=0",
                "promptfoo_provider": {
                    "id": "openai:chat:glm-5.3-flash",
                    "apiBaseUrl": "http://127.0.0.1:8082/v1",
                    "apiKeyKeychainService": "free-inference.privatemode",
                },
                "capabilities": {"tool_calling": True},
                "routing": {"private_local": "blocked", "private_attested": "blocked"},
                "remote_trust": {
                    "tier": "enclave_runtime_attested",
                    "attestation_method": "privatemode-proxy-contrast",
                    "weights_hash": None,
                    "weights_source": None,
                    "provider_manifest_weights_hash": "dmverity:sha256:c5dcd713fffc38c956bbd41fb299c360ed07d60de61938a6ff2729f6c3acd245",
                    "provider_manifest_weights_source": "nvidia/GLM-5.3-Flash-NVFP4@da920bb0b9f4a06727223a349e55468e38352348",
                    "usage_policy": "provider_terms_apply",
                    "jurisdiction": "EU",
                    "pricing_per_m_tokens": {"input": 0.22, "output": 0.71},
                },
            },
            {
                "id": "privatemode-gpt-oss-120b",
                "status": "candidate",
                "repo": "openai/gpt-oss-120b",
                "upstream": "openai/gpt-oss-120b",
                "runtime": "proxy",
                "serve_command": "./bin/privatemode-proxy --listen-address {host} --port {port} --api-key-fallback=never --manifest-path config/privatemode-manifest-v1.63.0.json --workspace .home/privatemode-proxy --disable-prompt-cache=false --prompt-cache-salt=random --nvidia-ocsp-allow-unknown=false --nvidia-ocsp-revoked-grace-period=0",
                "promptfoo_provider": {
                    "id": "openai:chat:openai/gpt-oss-120b",
                    "apiBaseUrl": "http://127.0.0.1:8082/v1",
                    "apiKeyKeychainService": "free-inference.privatemode",
                },
                "capabilities": {"tool_calling": True},
                "routing": {"private_local": "blocked", "private_attested": "blocked"},
                "remote_trust": {
                    "tier": "enclave_runtime_attested",
                    "attestation_method": "privatemode-proxy-contrast",
                    "weights_hash": None,
                    "weights_source": None,
                    "provider_manifest_weights_hash": "dmverity:sha256:a19e31d4c7da198b4905539ac00e55b93f377ecc4048e287810b2cf3a197cb29",
                    "provider_manifest_weights_source": "openai/gpt-oss-120b@b5c939de8f754692c1647ca79fbf85e8c1e70f8a",
                    "usage_policy": "provider_terms_apply",
                    "jurisdiction": "EU",
                    "pricing_per_m_tokens": {"input": 0.22, "output": 0.71},
                },
            },
        ]
        for entry in pm_entries:
            self.assertFalse(is_tinfoil_managed_model(entry))
        models_with_pm["models"].extend(pm_entries)

        enclaves_base = {
            "tinfoilsh/confidential-deepseek-v4-1-flash@v0.0.10+b200": parse_tinfoil_config_yaml(
                DEEPSEEK_V4_1_FLASH_YAML
            ),
            "tinfoilsh/confidential-kimi-k3@v0.0.16": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
            "tinfoilsh/confidential-kimi-k3-1-pro@v0.0.3": parse_tinfoil_config_yaml(
                KIMI_K3_1_PRO_V0_0_3_YAML
            ),
        }
        with tempfile.TemporaryDirectory() as td_pm:
            p_pm = Path(td_pm) / "models.yaml"
            p_pm.write_text(dump_models_yaml(_make_base_models_fixture()), encoding="utf-8")
            initial_rep = compute_catalog_drift(
                _make_base_models_fixture(),
                _make_router_manifest_fixture(),
                _make_openai_models_fixture(),
                enclaves_base,
                observed_date="2026-11-13",
            )
            synced_base = apply_catalog_healing(p_pm, initial_rep)
            synced_base["models"].extend(copy.deepcopy(pm_entries))

            report = compute_catalog_drift(
                synced_base,
                _make_router_manifest_fixture(),
                _make_openai_models_fixture(),
                enclaves_base,
                observed_date="2026-11-13",
            )
            self.assertFalse(report.has_drift)
            self.assertEqual(report.updated_models, [])
            self.assertEqual(report.removed_models, [])
            self.assertEqual(report.disagreements, [])
            self.assertEqual(report.new_models, [])

    def test_demote_clears_default_private_attested_pin(self) -> None:
        from local_assist.catalog_sync import _demote_routing_and_preserve_evidence
        from local_assist.registry import resolve_endpoint

        pinned = next(
            copy.deepcopy(m)
            for m in _make_base_models_fixture()["models"]
            if m["id"] == "tinfoil-deepseek-v4-1-flash"
        )
        pinned["routing"]["default_private_attested"] = True

        changes = _demote_routing_and_preserve_evidence(pinned, new_status="candidate")
        self.assertEqual(pinned["status"], "candidate")
        self.assertEqual(pinned["routing"]["private_attested"], "blocked")
        self.assertNotIn("default_private_attested", pinned["routing"])
        self.assertEqual(
            changes.get("routing.default_private_attested"),
            {"from": True, "to": False},
        )
        ep = resolve_endpoint(pinned, require_api_key=False)
        self.assertEqual(ep.routing_private_attested, "blocked")
        self.assertFalse(ep.default_private_attested)

        # End-to-end compute_catalog_drift + apply_catalog_healing when a pinned default model's weights change
        models_fixture = _make_base_models_fixture()
        for m in models_fixture["models"]:
            if m["id"] == "tinfoil-deepseek-v4-1-flash":
                m["routing"]["default_private_attested"] = True
        ds_new_hash = "9" * 64
        ds_old_hash = "6c4a2b637f7f45d9e48d1bdc38c12e0454584f48d3759851f7ee4471cd90b2e7"
        ds_changed_yaml = DEEPSEEK_V4_1_FLASH_YAML.replace(ds_old_hash, ds_new_hash)
        enclaves_changed = {
            "deepseek-v4-1-flash": parse_tinfoil_config_yaml(ds_changed_yaml),
            "kimi-k3": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
            "kimi-k3-1-pro": parse_tinfoil_config_yaml(KIMI_K3_1_PRO_V0_0_3_YAML),
        }
        with tempfile.TemporaryDirectory() as td_str:
            p_models = Path(td_str) / "models.yaml"
            p_models.write_text(dump_models_yaml(models_fixture), encoding="utf-8")
            drift = compute_catalog_drift(
                models_fixture,
                _make_router_manifest_fixture(),
                _make_openai_models_fixture(),
                enclaves_changed,
                observed_date="2026-11-14",
            )
            self.assertTrue(drift.has_drift)
            healed = apply_catalog_healing(p_models, drift)
            ds_healed = next(m for m in healed["models"] if m["id"] == "tinfoil-deepseek-v4-1-flash")
            self.assertEqual(ds_healed["status"], "candidate")
            self.assertEqual(ds_healed["routing"]["private_attested"], "blocked")
            self.assertNotIn("default_private_attested", ds_healed["routing"])
            ep_healed = resolve_endpoint(ds_healed, require_api_key=False)
            self.assertFalse(ep_healed.default_private_attested)
            drift_after = compute_catalog_drift(
                safe_load(p_models.read_text(encoding="utf-8")),
                _make_router_manifest_fixture(),
                _make_openai_models_fixture(),
                enclaves_changed,
                observed_date="2026-11-14",
            )
            self.assertFalse(drift_after.has_drift)

    def test_router_only_nonchat_qwen3_tts_base_exemption_and_cli_paths(self) -> None:
        """Router-only non-chat TTS enclave qwen3-tts-base does not trigger feed disagreement across API and CLI paths."""
        import importlib.machinery
        import importlib.util

        models_data = _make_base_models_fixture()
        router_manifest = _make_router_manifest_fixture()
        router_manifest["models"]["qwen3-tts-base"] = {
            "repo": "tinfoilsh/confidential-small-models",
            "tag": "v0.0.5",
            "verification": {"healthy": 1, "verified": 1, "configured": 1},
            "enclaves": {},
        }
        openai_models = _make_openai_models_fixture()
        enclave_configs = {
            "tinfoilsh/confidential-deepseek-v4-1-flash@v0.0.10+b200": parse_tinfoil_config_yaml(DEEPSEEK_V4_1_FLASH_YAML),
            "tinfoilsh/confidential-kimi-k3@v0.0.16": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
            "tinfoilsh/confidential-kimi-k3-1-pro@v0.0.3": parse_tinfoil_config_yaml(KIMI_K3_1_PRO_V0_0_3_YAML),
        }

        # 1. Default policy exempts unregistered router-only qwen3-tts-base (zero disagreements)
        rep_default = compute_catalog_drift(
            models_data,
            router_manifest,
            openai_models,
            enclave_configs,
            observed_date="2026-11-20",
        )
        self.assertEqual(rep_default.disagreements, [])

        # 2. Explicit empty ignored_router_only_nonchat_ids restores disagreement detection
        rep_strict = compute_catalog_drift(
            models_data,
            router_manifest,
            openai_models,
            enclave_configs,
            observed_date="2026-11-20",
            ignored_router_only_nonchat_ids=set(),
        )
        self.assertEqual(len(rep_strict.disagreements), 1)
        self.assertEqual(rep_strict.disagreements[0].served_model_id, "qwen3-tts-base")

        # 3. If /v1/models ever advertises qwen3-tts-base as tool-capable chat, discovery still picks it up
        oai_as_chat = copy.deepcopy(openai_models)
        oai_as_chat["data"].append(
            {
                "id": "qwen3-tts-base",
                "type": "chat",
                "tool_calling": True,
                "context_window": 32768,
                "pricing": {
                    "inputTokenPricePer1M": 0.1,
                    "outputTokenPricePer1M": 0.2,
                },
            }
        )
        enclaves_with_tts_chat = dict(enclave_configs)
        enclaves_with_tts_chat["tinfoilsh/confidential-small-models@v0.0.5"] = parse_tinfoil_config_yaml(
            KIMI_K3_1_PRO_V0_0_3_YAML.replace("kimi-k3-1-pro", "qwen3-tts-base")
        )
        rep_chat = compute_catalog_drift(
            models_data,
            router_manifest,
            oai_as_chat,
            enclaves_with_tts_chat,
            observed_date="2026-11-20",
        )
        self.assertEqual(rep_chat.disagreements, [])
        self.assertIn("tinfoil-qwen3-tts-base", [m["id"] for m in rep_chat.new_models])

        # 4. Registered-model feed disagreement checks remain active
        models_with_reg_disagree = copy.deepcopy(models_data)
        rm_missing_ds = copy.deepcopy(router_manifest)
        rm_missing_ds["models"].pop("deepseek-v4-1-flash")
        rep_reg_dis = compute_catalog_drift(
            models_with_reg_disagree,
            rm_missing_ds,
            openai_models,
            enclave_configs,
            observed_date="2026-11-20",
        )
        self.assertTrue(any(d.served_model_id == "deepseek-v4-1-flash" for d in rep_reg_dis.disagreements))

        # 5. End-to-end CLI regression across --check, --apply, and --include-all-chat
        script_path = ROOT / "scripts" / "sync-model-catalog"
        loader = importlib.machinery.SourceFileLoader("sync_model_catalog_cli_tts", str(script_path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        assert spec is not None and spec.loader is not None
        cli_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli_mod)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_models = Path(tmpdir) / "models.yaml"
            tmp_models.write_text(dump_models_yaml(models_data), encoding="utf-8")
            with (
                patch.object(cli_mod, "fetch_tinfoil_router_manifest", return_value=router_manifest),
                patch.object(cli_mod, "fetch_tinfoil_openai_models", return_value=openai_models),
                patch.object(
                    cli_mod,
                    "fetch_tinfoil_enclave_config",
                    side_effect=lambda r, t, **kw: enclave_configs[f"{r}@{t}"],
                ),
            ):
                self.assertEqual(cli_mod.main(["--check", "--models-path", str(tmp_models)]), 2)
                self.assertEqual(cli_mod.main(["--apply", "--models-path", str(tmp_models)]), 0)
                self.assertEqual(cli_mod.main(["--check", "--models-path", str(tmp_models)]), 0)
                self.assertEqual(
                    cli_mod.main(["--check", "--include-all-chat", "--models-path", str(tmp_models)]),
                    0,
                )

    def test_miniyaml_block_scalars_strict_keys_and_multi_document_parity(self) -> None:
        import datetime
        import hashlib
        from local_assist._miniyaml import (
            parse_yaml_documents,
            parse_yaml_with_flow_sequences,
            yaml_values_strictly_equal,
        )

        try:
            import yaml as pyyaml  # type: ignore[import-untyped]
        except ImportError:
            pyyaml = None
        if os.environ.get("FREE_INFERENCE_REQUIRE_PYYAML_PARITY") == "1":
            self.assertIsNotNone(pyyaml, "FREE_INFERENCE_REQUIRE_PYYAML_PARITY=1 requires PyYAML")

        # 1. Type-aware strict equality
        self.assertFalse(yaml_values_strictly_equal(True, 1))
        self.assertFalse(yaml_values_strictly_equal(1, 1.0))
        self.assertFalse(yaml_values_strictly_equal(datetime.date(2026, 11, 21), "2026-11-21"))
        self.assertFalse(yaml_values_strictly_equal({True: "a"}, {1: "a"}))
        self.assertTrue(yaml_values_strictly_equal({"k": [1, "x", None, True]}, {"k": [1, "x", None, True]}))

        # 2. Block scalars: empty clip/strip, single-line & multiline EOF with and without terminal newline, folded & blank lines
        block_cases = [
            ("a: |\n", {"a": ""}),
            ("a: |-\n", {"a": ""}),
            ("a: >\n", {"a": ""}),
            ("a: >-\n", {"a": ""}),
            ("a: |\n  \n  \n", {"a": ""}),
            ("a: |\n  hi", {"a": "hi"}),
            ("a: |\n  hi\n", {"a": "hi\n"}),
            ("a: |\n  first\n  last", {"a": "first\nlast"}),
            ("a: |\n  first\n  last\n", {"a": "first\nlast\n"}),
            ("a: |\n  first\n  last\n\n", {"a": "first\nlast\n"}),
            ("a: |-\n  first\n  last\n\n", {"a": "first\nlast"}),
            ("a: >\n  first\n  last", {"a": "first last"}),
            ("a: >\n  first\n  last\n", {"a": "first last\n"}),
            ("a: >\n  first\n  last\n\n", {"a": "first last\n"}),
            ("a: >-\n  first\n  last\n", {"a": "first last"}),
            ("a: |\n  text\n   \n", {"a": "text\n \n"}),
            ("a: |\n  text\n   \n\n", {"a": "text\n \n"}),
            ("a: |-\n  text\n   \n", {"a": "text\n "}),
            ("a: |\n  text\n   ", {"a": "text\n "}),
            ("a: >\n  line1\n   \n  line2\n", {"a": "line1\n \nline2\n"}),
            ("a: >\n  line1\n  \n  line2\n", {"a": "line1\nline2\n"}),
            ("a: >\n  line1\n   \n", {"a": "line1\n \n"}),
            ("a: |\n  \tword\n  next\n", {"a": "\tword\nnext\n"}),
            ("a: |\n  text\n  \tword\n  next\n", {"a": "text\n\tword\nnext\n"}),
            ("a: >\n  \tword\n  next\n", {"a": "\tword\nnext\n"}),
            ("a: >\n  text\n  \tword\n  next\n", {"a": "text\n\tword\nnext\n"}),
            ("a: >\n  text\n\n  \tword\n\n  next\n", {"a": "text\n\n\tword\n\nnext\n"}),
            ("a: |\n  \n  text\n", {"a": "\ntext\n"}),
            ("a: |\n   \n   \n", {"a": ""}),
            ("a: >\n\n  lead\n\n  mid\n    more\n  end\n", {"a": "\nlead\nmid\n  more\nend\n"}),
            ("items:\n  - |\n    line1\n    line2\n  - |-\n    strip1\n  - >\n    fold1\n    fold2\n",
             {"items": ["line1\nline2\n", "strip1", "fold1 fold2\n"]}),
            ("items:\n  - &s |\n    anchored\n  - *s\n", {"items": ["anchored\n", "anchored\n"]}),
        ]
        for raw_yaml, expected in block_cases:
            got = parse_yaml_with_flow_sequences(
                raw_yaml,
                reject_duplicate_keys=True,
                strict_plain_scalars=True,
            )
            self.assertTrue(
                yaml_values_strictly_equal(got, expected),
                f"Block scalar mismatch for {raw_yaml!r}: got={got!r}, expected={expected!r}",
            )
            if pyyaml is not None:
                py_got = pyyaml.safe_load(raw_yaml)
                self.assertTrue(
                    yaml_values_strictly_equal(got, py_got),
                    f"PyYAML parity mismatch for {raw_yaml!r}: stdlib={got!r}, pyyaml={py_got!r}",
                )

        # Under-indented continuation, over-indented leading blank line, and unsupported block indicators fail closed
        for bad_block in (
            "a: |\n    line1\n  line2\n",
            "a: |\n    \n  text\n",
            "a: >\n    \n  text\n",
            "a: |+\n  hi\n",
            "a: |2\n  hi\n",
            "a: >+\n  hi\n",
            "items:\n  - |+\n    hi\n",
            "items:\n  - >2\n    hi\n",
        ):
            with self.assertRaises(ValueError, msg=f"Should reject {bad_block!r}"):
                parse_yaml_with_flow_sequences(
                    bad_block,
                    reject_duplicate_keys=True,
                    strict_plain_scalars=True,
                )

        # 3. Duplicate mapping keys + strict ASCII plain keys/scalars + mixed-script parity
        for bad_strict in (
            "a: 1\na: 2\n",
            "items:\n  - x: 1\n    x: 2\n",
            "2026-11-21: val\n",
            "2026-1-2: val\n",
            "2026-1-2 03:04:05: val\n",
            "1_0.0e+2: val\n",
            "12:30: val\n",
            "0x1f: val\n",
            "val: 2026-1-2\n",
            "val: 2026-1-2 03:04:05\n",
            "val: 1_0.0e+2\n",
            "val: 12:30\n",
            "val: 0o755\n",
            "val: +5\n",
        ):
            with self.assertRaises(ValueError, msg=f"Strict YAML should reject {bad_strict!r}"):
                parse_yaml_with_flow_sequences(
                    bad_strict,
                    reject_duplicate_keys=True,
                    strict_plain_scalars=True,
                )

        mixed_script = "1\u0662: 1\u0662\n"
        got_mixed = parse_yaml_with_flow_sequences(
            mixed_script,
            reject_duplicate_keys=True,
            strict_plain_scalars=True,
        )
        self.assertTrue(yaml_values_strictly_equal(got_mixed, {"1\u0662": "1\u0662"}))
        if pyyaml is not None:
            self.assertTrue(yaml_values_strictly_equal(got_mixed, pyyaml.safe_load(mixed_script)))

        # 4. Multi-document streams and edge cases
        multi_cases = [
            ("", []),
            ("# comment only\n\n", []),
            ("a: 1\n", [{"a": 1}]),
            ("---\na: 1\n", [{"a": 1}]),
            ("---\na: 1\n...\n# trailing comment\n", [{"a": 1}]),
            ("---\n---\na: 1\n", [None, {"a": 1}]),
            ("---\n...\n", [None]),
            ("a: 1\n---\nb: |\n  keep --- indented\n  and ...\n...\n", [{"a": 1}, {"b": "keep --- indented\nand ...\n"}]),
            ("a: |\n  clip-before-doc\n---\nb: |-\n  strip-before-eof", [{"a": "clip-before-doc\n"}, {"b": "strip-before-eof"}]),
        ]
        for raw_stream, expected_docs in multi_cases:
            got_docs = parse_yaml_documents(
                raw_stream,
                allow_flow_sequences=True,
                reject_duplicate_keys=True,
                strict_plain_scalars=True,
            )
            self.assertTrue(
                yaml_values_strictly_equal(got_docs, expected_docs),
                f"Multi-doc mismatch for {raw_stream!r}: got={got_docs!r}, expected={expected_docs!r}",
            )
            if pyyaml is not None:
                py_docs = list(pyyaml.safe_load_all(raw_stream))
                self.assertTrue(
                    yaml_values_strictly_equal(got_docs, py_docs),
                    f"Multi-doc PyYAML mismatch for {raw_stream!r}: stdlib={got_docs!r}, pyyaml={py_docs!r}",
                )

        # Per-document anchor isolation, unfinished flow at doc boundary, directives, inline doc start
        for bad_multi in (
            "a: &x 1\n---\nb: *x\n",
            "a: [1,\n---\nb: 2\n",
            "%YAML 1.2\n---\na: 1\n",
            "--- foo\n",
            "...\n--- {a: 1}\n",
        ):
            with self.assertRaises(ValueError, msg=f"Multi-doc should reject {bad_multi!r}"):
                parse_yaml_documents(
                    bad_multi,
                    allow_flow_sequences=True,
                    reject_duplicate_keys=True,
                    strict_plain_scalars=True,
                )

        # 5. Pinned real v1.64.0 fixtures provenance SHA-256 + full stdlib vs PyYAML parity
        fix_dir = ROOT / "tests" / "fixtures" / "privatemode_v1_64_0"
        prov = json.loads((fix_dir / "PROVENANCE.json").read_text(encoding="utf-8"))
        self.assertEqual(prov["repo"], "edgelesssys/privatemode-public")
        self.assertEqual(prov["tag"], "v1.64.0")
        self.assertEqual(prov["commit_sha"], "3c98e0abf3219a6ebcc29112867a5f004605041b")
        for fname in ("models.yaml", "deployment.yaml"):
            raw_bytes = (fix_dir / fname).read_bytes()
            self.assertEqual(hashlib.sha256(raw_bytes).hexdigest(), prov["files"][fname]["sha256"])
            self.assertEqual(len(raw_bytes), prov["files"][fname]["bytes"])

        models_text = (fix_dir / "models.yaml").read_text(encoding="utf-8")
        deploy_text = (fix_dir / "deployment.yaml").read_text(encoding="utf-8")
        parsed_m = parse_yaml_with_flow_sequences(
            models_text, reject_duplicate_keys=True, strict_plain_scalars=True
        )
        parsed_d = parse_yaml_documents(
            deploy_text,
            allow_flow_sequences=True,
            reject_duplicate_keys=True,
            strict_plain_scalars=True,
        )
        self.assertEqual(len(parsed_d), 13)
        if pyyaml is not None:
            self.assertTrue(yaml_values_strictly_equal(parsed_m, pyyaml.safe_load(models_text)))
            self.assertTrue(yaml_values_strictly_equal(parsed_d, list(pyyaml.safe_load_all(deploy_text))))

    def test_privatemode_fetchers_url_binding_and_rollback_guard(self) -> None:
        import importlib.machinery
        import importlib.util
        from local_assist.catalog_sync import (
            fetch_privatemode_deployment_yaml,
            fetch_privatemode_latest_release,
            fetch_privatemode_models_yaml,
            fetch_privatemode_tag_commit,
        )

        valid_release = {
            "tag_name": "v1.64.0",
            "draft": False,
            "prerelease": False,
            "published_at": "2026-11-14T16:36:05Z",
            "assets": [
                {
                    "name": "manifest.json",
                    "size": 12345,
                    "browser_download_url": "https://github.com/edgelesssys/privatemode-public/releases/download/v1.64.0/manifest.json",
                }
            ],
        }
        rel = fetch_privatemode_latest_release(http_get=lambda _u: json.dumps(valid_release))
        self.assertEqual(rel["tag_name"], "v1.64.0")
        self.assertEqual(rel["manifest_asset_size"], 12345)

        # Reject bad URLs: userinfo, port, query, fragment, wrong path, wrong host, plaintext loopback without opt-in
        for bad_url in (
            "https://user@api.github.com/repos/edgelesssys/privatemode-public/releases/latest",
            "https://api.github.com:443/repos/edgelesssys/privatemode-public/releases/latest",
            "https://api.github.com/repos/edgelesssys/privatemode-public/releases/latest?x=1",
            "https://api.github.com/repos/edgelesssys/privatemode-public/releases/latest#frag",
            "https://api.github.com/repos/evil/privatemode-public/releases/latest",
            "https://evil.example/repos/edgelesssys/privatemode-public/releases/latest",
            "http://127.0.0.1:8080/repos/edgelesssys/privatemode-public/releases/latest",
        ):
            with self.assertRaises(CatalogSyncError, msg=f"Should reject {bad_url}"):
                fetch_privatemode_latest_release(url=bad_url, http_get=lambda _u: json.dumps(valid_release))

        # Loopback fixture opt-in works only on exact path
        rel_lb = fetch_privatemode_latest_release(
            url="http://127.0.0.1:9999/repos/edgelesssys/privatemode-public/releases/latest",
            http_get=lambda _u: json.dumps(valid_release),
            allow_loopback_fixture=True,
        )
        self.assertEqual(rel_lb["tag_name"], "v1.64.0")

        # Strict release metadata checks
        for mutate in (
            lambda d: d.update({"draft": True}),
            lambda d: d.update({"draft": None}),
            lambda d: d.update({"prerelease": True}),
            lambda d: d.update({"prerelease": "false"}),
            lambda d: d.update({"tag_name": "../v1.64.0"}),
            lambda d: d.update({"assets": []}),
            lambda d: d["assets"].append(dict(d["assets"][0])),
            lambda d: d["assets"][0].update({"size": 0}),
            lambda d: d["assets"][0].update({"size": True}),
            lambda d: d["assets"][0].update({"browser_download_url": "https://evil.example/manifest.json"}),
        ):
            bad_rel = copy.deepcopy(valid_release)
            mutate(bad_rel)
            with self.assertRaises(CatalogSyncError):
                fetch_privatemode_latest_release(http_get=lambda _u: json.dumps(bad_rel))

        # Duplicate JSON key in release payload fails closed
        with self.assertRaises(CatalogSyncError):
            fetch_privatemode_latest_release(
                http_get=lambda _u: '{"tag_name":"v1.64.0","tag_name":"v1.65.0","draft":false,"prerelease":false,"assets":[]}'
            )

        # Tag-to-commit resolution
        sha = fetch_privatemode_tag_commit(
            "v1.64.0",
            http_get=lambda _u: json.dumps({"sha": "3c98e0abf3219a6ebcc29112867a5f004605041b"}),
        )
        self.assertEqual(sha, "3c98e0abf3219a6ebcc29112867a5f004605041b")
        with self.assertRaises(CatalogSyncError):
            fetch_privatemode_tag_commit("v1.64.0", http_get=lambda _u: json.dumps({"sha": "not-a-sha"}))
        with self.assertRaises(CatalogSyncError):
            fetch_privatemode_models_yaml("v1.64.0", http_get=lambda _u: "")
        with self.assertRaises(CatalogSyncError):
            fetch_privatemode_deployment_yaml("v1.64.0", http_get=lambda _u: "")

        # CLI --privatemode-tag --apply is refused fail-closed without touching models.yaml
        script_path = ROOT / "scripts" / "sync-model-catalog"
        loader = importlib.machinery.SourceFileLoader("sync_model_catalog_cli_pm_ro", str(script_path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        assert spec is not None and spec.loader is not None
        cli_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli_mod)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "models.yaml"
            p.write_text(dump_models_yaml(_make_base_models_fixture()), encoding="utf-8")
            orig = p.read_bytes()
            rc = cli_mod.main(
                ["--provider", "privatemode", "--privatemode-tag", "v1.63.0", "--apply", "--models-path", str(p)]
            )
            self.assertEqual(rc, 1)
            self.assertEqual(p.read_bytes(), orig)

    def test_privatemode_parsers_disk_binding_and_overlapping_slugs(self) -> None:
        from local_assist.catalog_sync import (
            compute_privatemode_catalog_drift,
            parse_privatemode_deployment_yaml,
            parse_privatemode_models_yaml,
        )

        fix_dir = ROOT / "tests" / "fixtures" / "privatemode_v1_64_0"
        models_yaml_text = (fix_dir / "models.yaml").read_text(encoding="utf-8")
        deploy_yaml_text = (fix_dir / "deployment.yaml").read_text(encoding="utf-8")

        disk_map = parse_privatemode_models_yaml(models_yaml_text)
        self.assertEqual(len(disk_map), 11)
        dep_data = parse_privatemode_deployment_yaml(deploy_yaml_text)
        self.assertEqual(dep_data["partial_deployments"], [])
        self.assertEqual(
            sorted(dep_data["workloads"].keys()),
            [
                "deepseek-ocr-2",
                "glm-5.3",
                "glm-5.3-flash",
                "openai/gpt-oss-120b",
                "openai/whisper-large-v3",
                "qwen3-embedding-4b",
                "voxtral-mini-3b",
            ],
        )

        # Forged disk_key, duplicate root_hash, duplicate JSON key in models.yaml fail closed
        forged_models = models_yaml_text.replace("openai-gpt-oss-120b:", "forged-disk-key:")
        with self.assertRaises(CatalogSyncError):
            parse_privatemode_models_yaml(forged_models)

        dup_root_models = models_yaml_text.replace(
            "df66c4cfc7f34c4f7aefd710795a511cde8384677cd041220a04b55541a07d75",
            "c5dcd713fffc38c956bbd41fb299c360ed07d60de61938a6ff2729f6c3acd245",
        )
        with self.assertRaises(CatalogSyncError):
            parse_privatemode_models_yaml(dup_root_models)

        dup_json_key_models = models_yaml_text.replace(
            '"file_size_bytes": 206086352896',
            '"file_size_bytes": 206086352896, "file_size_bytes": 1',
        )
        self.assertNotEqual(dup_json_key_models, models_yaml_text)
        with self.assertRaises(CatalogSyncError):
            parse_privatemode_models_yaml(dup_json_key_models)

        # Helper to build a minimal valid single-workload deployment YAML for negative tests
        def _make_single_dep(
            *,
            dep_name: str = "workload-nova-2",
            disk_name: str = "nova-2",
            root_hash: str = "1" * 64,
            served_args: list[str] | None = None,
            extra_args: list[str] | None = None,
            replicas: int | None = None,
            include_workload_ctr: bool = True,
            h2c_mount: bool = True,
            bidi_mount: bool = True,
            pvc_claim: str | None = None,
            ctr_args_override: list[Any] | None = None,
        ) -> str:
            k8s_slug = disk_name.replace(".", "-")
            claim = pvc_claim or k8s_slug
            s_args = served_args if served_args is not None else ["--served-model-name", disk_name]
            args_list = ctr_args_override if ctr_args_override is not None else [
                f"/mnt/modelweights-{disk_name}-0",
                *s_args,
                *(extra_args or []),
            ]
            ctr_mounts = (
                [{"name": "mount-dir", "mountPath": "/mnt", "mountPropagation": "HostToContainer"}]
                if h2c_mount
                else []
            )
            ic_mounts = (
                [{"name": "mount-dir", "mountPath": "/mnt", "mountPropagation": "Bidirectional"}]
                if bidi_mount
                else []
            )
            doc: dict[str, Any] = {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": dep_name},
                "spec": {
                    "template": {
                        "spec": {
                            "initContainers": [
                                {
                                    "name": f"disk-mounter-{k8s_slug}-0",
                                    "args": [disk_name, "0", root_hash],
                                    "volumeDevices": [
                                        {
                                            "name": f"modelweights-{k8s_slug}-0",
                                            "devicePath": f"/dev/modelweights-{disk_name}-0",
                                        }
                                    ],
                                    "volumeMounts": ic_mounts,
                                }
                            ],
                            "containers": (
                                [
                                    {
                                        "name": f"workload-{k8s_slug}-0",
                                        "args": args_list,
                                        "volumeMounts": ctr_mounts,
                                    }
                                ]
                                if include_workload_ctr
                                else []
                            ),
                            "volumes": [
                                {"name": "mount-dir", "emptyDir": {"medium": "Memory"}},
                                {
                                    "name": f"modelweights-{k8s_slug}-0",
                                    "persistentVolumeClaim": {"claimName": claim},
                                },
                            ],
                        }
                    }
                },
            }
            if replicas is not None:
                doc["spec"]["replicas"] = replicas
            return dump_models_yaml(doc)

        # Missing backing mounts, PVC mismatch, non-string args, conflicting flags, independently varying served ID vs pod slug
        for bad_dep in (
            _make_single_dep(h2c_mount=False),
            _make_single_dep(bidi_mount=False),
            _make_single_dep(pvc_claim="wrong-pvc"),
            _make_single_dep(ctr_args_override=["/mnt/modelweights-nova-2-0", 123, "--served-model-name", "nova-2"]),
            _make_single_dep(extra_args=["--max-model-len", "0"]),
            _make_single_dep(extra_args=["--max-model-len", "1024", "--max-model-len", "2048"]),
            _make_single_dep(extra_args=["--enable-auto-tool-choice=false"]),
            _make_single_dep(extra_args=["--tool-call-parser", "a", "--tool-call-parser", "b"]),
            _make_single_dep(disk_name="glm-5.3-flash", served_args=["--served-model-name", "other-model"]),
        ):
            with self.assertRaises(CatalogSyncError):
                parse_privatemode_deployment_yaml(bad_dep)

        # Alias-vs-alias collision across Deployments fails closed
        dep_a = _make_single_dep(
            dep_name="workload-nova-a",
            disk_name="nova-a",
            served_args=["--served-model-name", "nova-a", "shared-alias"],
        )
        dep_b = _make_single_dep(
            dep_name="workload-nova-b",
            disk_name="nova-b",
            served_args=["--served-model-name", "nova-b", "shared-alias"],
        )
        with self.assertRaises(CatalogSyncError):
            parse_privatemode_deployment_yaml(dep_a + "---\n" + dep_b)

        # Partial deployments (replicas == 0 and orphan disk-mounter) emit partial_deployments
        p_zero = parse_privatemode_deployment_yaml(_make_single_dep(replicas=0))
        self.assertEqual(len(p_zero["partial_deployments"]), 1)
        p_orphan = parse_privatemode_deployment_yaml(_make_single_dep(include_workload_ctr=False))
        self.assertEqual(len(p_orphan["partial_deployments"]), 1)

        # Overlapping-slug cross-feed mismatch on REGISTERED path:
        # Coherent glm-5-3 pod mounting nvidia-glm-5-3-flash-nvfp4's valid root_hash -> registered FeedDisagreementItem!
        flash_root = "c5dcd713fffc38c956bbd41fb299c360ed07d60de61938a6ff2729f6c3acd245"
        glm_dep_with_flash_root = parse_privatemode_deployment_yaml(
            _make_single_dep(
                dep_name="workload-glm-5-3",
                disk_name="glm-5.3",
                root_hash=flash_root,
                served_args=["--served-model-name", "glm-5.3"],
                extra_args=["--tool-call-parser", "glm47", "--max-model-len", "1048576"],
            )
        )
        real_models_data = safe_load((ROOT / "models.yaml").read_text(encoding="utf-8"))
        only_glm_5_3 = {
            "models": [copy.deepcopy(m) for m in real_models_data["models"] if m.get("id") == "privatemode-glm-5-3"]
        }
        rep_overlap_reg = compute_privatemode_catalog_drift(
            only_glm_5_3,
            "v1.63.0",
            disk_map,
            glm_dep_with_flash_root,
            observed_date="2026-11-21",
        )
        self.assertEqual(len(rep_overlap_reg.disagreements), 1)
        self.assertTrue(rep_overlap_reg.disagreements[0].registered)
        self.assertIn("cross-feed disk identity mismatch", rep_overlap_reg.disagreements[0].reason)
        self.assertEqual(rep_overlap_reg.updated_models, [])

        # Overlapping-slug cross-feed mismatch on UNKNOWN DISCOVERY path:
        # Truly unknown nova-2 pod mounting acme/Nova-2-Flash-NVFP4's valid root_hash -> unregistered FeedDisagreementItem!
        nova_flash_root = "a" * 64
        nova_exact_root = "b" * 64
        custom_disks = {
            nova_flash_root: {
                "disk_key": "acme-nova-2-flash-nvfp4",
                "upstream": "acme/Nova-2-Flash-NVFP4",
                "commit_hash": "c" * 40,
                "weights_source": f"acme/Nova-2-Flash-NVFP4@{'c' * 40}",
                "root_hash": nova_flash_root,
                "weights_hash": f"dmverity:sha256:{nova_flash_root}",
                "file_size_bytes": 100_000_000_000,
                "disk_gb_estimate": 100.0,
            },
            nova_exact_root: {
                "disk_key": "acme-nova-2-nvfp4",
                "upstream": "acme/Nova-2-NVFP4",
                "commit_hash": "d" * 40,
                "weights_source": f"acme/Nova-2-NVFP4@{'d' * 40}",
                "root_hash": nova_exact_root,
                "weights_hash": f"dmverity:sha256:{nova_exact_root}",
                "file_size_bytes": 120_000_000_000,
                "disk_gb_estimate": 120.0,
            },
        }
        nova_overlap_dep = parse_privatemode_deployment_yaml(
            _make_single_dep(
                dep_name="workload-nova-2",
                disk_name="nova-2",
                root_hash=nova_flash_root,
                served_args=["--served-model-name", "nova-2"],
                extra_args=["--tool-call-parser", "glm47", "--max-model-len", "131072"],
            )
        )
        rep_overlap_disc = compute_privatemode_catalog_drift(
            {"models": []},
            "v1.64.0",
            custom_disks,
            nova_overlap_dep,
            observed_date="2026-11-21",
        )
        self.assertEqual(rep_overlap_disc.new_models, [])
        self.assertEqual(len(rep_overlap_disc.disagreements), 1)
        self.assertFalse(rep_overlap_disc.disagreements[0].registered)
        self.assertIn("mismatched models.yaml disk 'acme-nova-2-flash-nvfp4'", rep_overlap_disc.disagreements[0].reason)

        # Valid exact match unknown coding model IS discovered as manual_onboarding_required at Rung 3
        nova_ok_dep = parse_privatemode_deployment_yaml(
            _make_single_dep(
                dep_name="workload-nova-2",
                disk_name="nova-2",
                root_hash=nova_exact_root,
                served_args=["--served-model-name", "nova-2"],
                extra_args=["--tool-call-parser", "glm47", "--max-model-len", "131072"],
            )
        )
        rep_nova_ok = compute_privatemode_catalog_drift(
            {"models": []},
            "v1.64.0",
            custom_disks,
            nova_ok_dep,
            observed_date="2026-11-21",
        )
        self.assertEqual(rep_nova_ok.disagreements, [])
        self.assertEqual(len(rep_nova_ok.new_models), 1)
        cand = rep_nova_ok.new_models[0]
        self.assertEqual(cand["id"], "privatemode-nova-2")
        self.assertTrue(cand["manual_onboarding_required"])
        self.assertIsNone(cand["remote_trust"]["pricing_per_m_tokens"])
        self.assertEqual(cand["remote_trust"]["tier"], "enclave_runtime_attested")
        self.assertIsNone(cand["remote_trust"]["weights_hash"])

        # Missing deployment: disk still in models.yaml -> registered disagreement; absent from BOTH -> confirmed archive_removed
        rep_missing_dep_disk_present = compute_privatemode_catalog_drift(
            only_glm_5_3,
            "v1.64.0",
            disk_map,
            nova_ok_dep,
            observed_date="2026-11-21",
            discover_new_coding_models=False,
        )
        self.assertEqual(len(rep_missing_dep_disk_present.disagreements), 1)
        self.assertEqual(rep_missing_dep_disk_present.removed_models, [])

        rep_confirmed_removal = compute_privatemode_catalog_drift(
            only_glm_5_3,
            "v1.64.0",
            custom_disks,
            nova_ok_dep,
            observed_date="2026-11-21",
            discover_new_coding_models=False,
        )
        self.assertEqual(rep_confirmed_removal.disagreements, [])
        self.assertEqual(len(rep_confirmed_removal.removed_models), 1)
        self.assertEqual(rep_confirmed_removal.removed_models[0].action, "archive_removed")

        # voxtral-mini-3b ignored by default, included when ignored_served_ids=set()
        pm_only_catalog = {
            "models": [copy.deepcopy(m) for m in real_models_data["models"] if str(m.get("id", "")).startswith("privatemode-")]
        }
        rep_vox_default = compute_privatemode_catalog_drift(
            pm_only_catalog, "v1.64.0", disk_map, dep_data, observed_date="2026-11-21"
        )
        self.assertEqual(rep_vox_default.new_models, [])
        rep_vox_all = compute_privatemode_catalog_drift(
            pm_only_catalog,
            "v1.64.0",
            disk_map,
            dep_data,
            observed_date="2026-11-21",
            ignored_served_ids=set(),
        )
        self.assertEqual([m["repo"] for m in rep_vox_all.new_models], ["voxtral-mini-3b"])

    def test_privatemode_drift_merge_committed_manifest_and_safety_only_apply(self) -> None:
        import hashlib
        import shutil
        import subprocess
        from local_assist.catalog_sync import (
            CatalogDriftReport,
            FeedDisagreementItem,
            ModelDriftItem,
            compute_privatemode_catalog_drift,
            merge_drift_reports,
            parse_privatemode_deployment_yaml,
            parse_privatemode_models_yaml,
        )

        fix_dir = ROOT / "tests" / "fixtures" / "privatemode_v1_64_0"
        prov = json.loads((fix_dir / "PROVENANCE.json").read_text(encoding="utf-8"))
        v164_commit = prov["commit_sha"]
        disk_map = parse_privatemode_models_yaml((fix_dir / "models.yaml").read_text(encoding="utf-8"))
        dep_data = parse_privatemode_deployment_yaml((fix_dir / "deployment.yaml").read_text(encoding="utf-8"))

        real_models_data = safe_load((ROOT / "models.yaml").read_text(encoding="utf-8"))
        pm_entries = [
            copy.deepcopy(m)
            for m in real_models_data["models"]
            if str(m.get("id", "")).startswith("privatemode-")
        ]
        # Pin flash as default_private_attested for testing default clearance removal
        for m in pm_entries:
            if m["id"] == "privatemode-glm-5-3-flash":
                m["routing"]["default_private_attested"] = True

        # 1. Clean pinned v1.64.0 state -> has_drift=False & non-null base_catalog_sha256
        clean_pm_data = {"models": copy.deepcopy(pm_entries)}
        for m in clean_pm_data["models"]:
            m["enclave_tag"] = "v1.64.0"
            m["serve_command"] = m["serve_command"].replace("v1.63.0", "v1.64.0")
        rep_clean = compute_privatemode_catalog_drift(
            clean_pm_data,
            "v1.64.0",
            disk_map,
            dep_data,
            observed_date="2026-11-21",
            provenance={"tag": "v1.64.0", "commit_sha": v164_commit},
        )
        self.assertFalse(rep_clean.has_drift)
        self.assertIsNotNone(rep_clean.base_catalog_sha256)
        self.assertEqual(rep_clean.providers, ["privatemode"])

        # 2. Release-tag drift v1.63.0 -> v1.64.0 projects serve_command + mandatory clearance demotion
        v163_pm_data = {"models": copy.deepcopy(pm_entries)}
        rep_upgrade = compute_privatemode_catalog_drift(
            v163_pm_data,
            "v1.64.0",
            disk_map,
            dep_data,
            observed_date="2026-11-21",
            provenance={"tag": "v1.64.0", "commit_sha": v164_commit},
        )
        self.assertTrue(rep_upgrade.has_drift)
        self.assertEqual(len(rep_upgrade.updated_models), 3)
        flash_upd = next(u for u in rep_upgrade.updated_models if u.model_id == "privatemode-glm-5-3-flash")
        self.assertEqual(flash_upd.action, "manifest_upgrade_required")
        self.assertEqual(flash_upd.changes["enclave_tag"], {"from": "v1.63.0", "to": "v1.64.0"})
        self.assertIn("config/privatemode-manifest-v1.64.0.json", flash_upd.changes["serve_command"]["to"])
        self.assertEqual(flash_upd.changes["routing.private_attested"], {"from": "cleared", "to": "blocked"})
        self.assertEqual(flash_upd.changes["routing.default_private_attested"], {"from": True, "to": False})

        # 3. Committed-manifest proof when git is available (dedicated test_privatemode_committed_manifest_git_proof also covers full git flow)
        if shutil.which("git"):
            with tempfile.TemporaryDirectory() as td:
                repo_dir = Path(td)
                subprocess.run(["git", "init", "-q", str(repo_dir)], check=True)
                subprocess.run(["git", "-C", str(repo_dir), "config", "user.email", "test@example.com"], check=True)
                subprocess.run(["git", "-C", str(repo_dir), "config", "user.name", "Test"], check=True)
                (repo_dir / "config").mkdir()
                (repo_dir / "scripts").mkdir()
                models_p = repo_dir / "models.yaml"
                models_p.write_text(dump_models_yaml(v163_pm_data), encoding="utf-8")
                orig_bytes = models_p.read_bytes()

                # (a) Missing v1.64.0 manifest/builder -> fails closed
                with self.assertRaises(CatalogSyncError):
                    apply_catalog_healing(models_p, rep_upgrade)
                self.assertEqual(models_p.read_bytes(), orig_bytes)

                # (b) Untracked v1.64.0 manifest & builder -> fails closed
                manifest_bytes = json.dumps({"ReferenceValues": {"a": 1}, "Policies": {"b": 2}}, indent=2).encode("utf-8")
                manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
                manifest_p = repo_dir / "config" / "privatemode-manifest-v1.64.0.json"
                manifest_p.write_bytes(manifest_bytes)
                builder_p = repo_dir / "scripts" / "build-privatemode-proxy"

                def _write_builder(*, ver: str = "1.64.0", commit: str = v164_commit, sha: str = manifest_sha, fname: str = "privatemode-manifest-v1.64.0.json") -> None:
                    builder_p.write_text(
                        "from pathlib import Path\n"
                        "ROOT = Path(__file__).resolve().parents[1]\n"
                        f'COMMITTED_MANIFEST_PATH = ROOT / "config" / "{fname}"\n'
                        f'PRIVATEMODE_VERSION = "{ver}"\n'
                        f'PRIVATEMODE_SOURCE_COMMIT = "{commit}"\n'
                        f'EXPECTED_MANIFEST_SHA256 = "{sha}"\n',
                        encoding="utf-8",
                    )

                _write_builder()
                with self.assertRaises(CatalogSyncError) as ctx_untracked:
                    apply_catalog_healing(models_p, rep_upgrade)
                self.assertIn("uncommitted or untracked", str(ctx_untracked.exception))
                self.assertEqual(models_p.read_bytes(), orig_bytes)

                # Commit manifest and builder
                subprocess.run(
                    ["git", "-C", str(repo_dir), "add", "config/privatemode-manifest-v1.64.0.json", "scripts/build-privatemode-proxy"],
                    check=True,
                )
                subprocess.run(["git", "-C", str(repo_dir), "commit", "-q", "-m", "commit v1.64.0 pins"], check=True)

                # (c) Locally modified manifest -> fails closed
                manifest_p.write_bytes(manifest_bytes + b"\n")
                with self.assertRaises(CatalogSyncError):
                    apply_catalog_healing(models_p, rep_upgrade)
                manifest_p.write_bytes(manifest_bytes)

                # (d) Symlinked manifest -> fails closed
                outside_p = repo_dir / "outside.json"
                outside_p.write_bytes(manifest_bytes)
                manifest_p.unlink()
                manifest_p.symlink_to(outside_p)
                with self.assertRaises(CatalogSyncError):
                    apply_catalog_healing(models_p, rep_upgrade)
                manifest_p.unlink()
                manifest_p.write_bytes(manifest_bytes)

                # (e) Tampered projected serve_command (duplicate --manifest-path or post-`--` option) -> fails closed
                rep_dup_opt = copy.deepcopy(rep_upgrade)
                rep_dup_opt.updated_models[0].changes["serve_command"]["to"] += " --manifest-path config/privatemode-manifest-v1.64.0.json"
                with self.assertRaises(CatalogSyncError):
                    apply_catalog_healing(models_p, rep_dup_opt)
                rep_post_dd = copy.deepcopy(rep_upgrade)
                rep_post_dd.updated_models[0].changes["serve_command"]["to"] += " -- --manifest-path config/privatemode-manifest-v1.64.0.json"
                with self.assertRaises(CatalogSyncError):
                    apply_catalog_healing(models_p, rep_post_dd)

                # (f) Wrong PRIVATEMODE_SOURCE_COMMIT -> fails closed
                _write_builder(commit="0" * 40)
                subprocess.run(["git", "-C", str(repo_dir), "commit", "-qam", "wrong commit pin"], check=True)
                with self.assertRaises(CatalogSyncError) as ctx_bad_commit:
                    apply_catalog_healing(models_p, rep_upgrade)
                self.assertIn("PRIVATEMODE_SOURCE_COMMIT", str(ctx_bad_commit.exception))

                # (g) Restore matching pins and commit -> atomic apply succeeds AND demotes cleared flash model
                _write_builder()
                subprocess.run(["git", "-C", str(repo_dir), "commit", "-qam", "correct v1.64.0 pins"], check=True)
                healed = apply_catalog_healing(models_p, rep_upgrade)
                flash_after = next(m for m in healed["models"] if m["id"] == "privatemode-glm-5-3-flash")
                self.assertEqual(flash_after["enclave_tag"], "v1.64.0")
                self.assertIn("config/privatemode-manifest-v1.64.0.json", flash_after["serve_command"])
                self.assertEqual(flash_after["status"], "candidate")
                self.assertEqual(flash_after["routing"]["private_attested"], "blocked")
                self.assertNotIn("default_private_attested", flash_after["routing"])
                self.assertEqual(flash_after["stale_eval_evidence_artifact"], "docs/evals/privatemode-glm-5-3-flash.json")

        # 4. Real producer -> merge_drift_reports -> apply + strict rejection checks
        combined_catalog = _make_base_models_fixture()
        combined_catalog["models"].extend(copy.deepcopy(pm_entries))
        enclaves_base = {
            "tinfoilsh/confidential-deepseek-v4-1-flash@v0.0.10+b200": parse_tinfoil_config_yaml(DEEPSEEK_V4_1_FLASH_YAML),
            "tinfoilsh/confidential-kimi-k3@v0.0.16": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
            "tinfoilsh/confidential-kimi-k3-1-pro@v0.0.3": parse_tinfoil_config_yaml(KIMI_K3_1_PRO_V0_0_3_YAML),
        }
        rep_tf = compute_catalog_drift(
            combined_catalog,
            _make_router_manifest_fixture(),
            _make_openai_models_fixture(),
            enclaves_base,
            observed_date="2026-11-21",
        )
        rep_pm = compute_privatemode_catalog_drift(
            combined_catalog,
            "v1.64.0",
            disk_map,
            dep_data,
            observed_date="2026-11-21",
            provenance={"tag": "v1.64.0", "commit_sha": v164_commit},
        )
        merged = merge_drift_reports([rep_tf, rep_pm])
        self.assertEqual(merged.providers, ["tinfoil", "privatemode"])
        self.assertEqual(merged.base_catalog_sha256, rep_tf.base_catalog_sha256)
        self.assertEqual(merged.base_catalog_sha256, rep_pm.base_catalog_sha256)

        # Merge rejects null/mismatched digest, mismatched date, duplicate proposed repo/id, duplicate target
        rep_no_sha = copy.deepcopy(rep_pm)
        rep_no_sha.base_catalog_sha256 = None
        with self.assertRaises(CatalogSyncError):
            merge_drift_reports([rep_tf, rep_no_sha])
        rep_bad_date = copy.deepcopy(rep_pm)
        rep_bad_date.observed_date = "2026-11-22"
        with self.assertRaises(CatalogSyncError):
            merge_drift_reports([rep_tf, rep_bad_date])
        rep_dup_repo = copy.deepcopy(rep_pm)
        rep_dup_repo.new_models.append({"id": "privatemode-dup", "repo": "kimi-k3-1-pro"})
        with self.assertRaises(CatalogSyncError):
            merge_drift_reports([rep_tf, rep_dup_repo])

        # Direct apply_catalog_healing rejects null digest on Privatemode report, duplicate target in bucket, wrong provider quarantine
        with tempfile.TemporaryDirectory() as td_rej:
            p_rej = Path(td_rej) / "models.yaml"
            p_rej.write_text(dump_models_yaml(combined_catalog), encoding="utf-8")
            with self.assertRaises(CatalogSyncError):
                apply_catalog_healing(p_rej, rep_no_sha)

            rep_dup_target = copy.deepcopy(rep_pm)
            rep_dup_target.updated_models.append(copy.deepcopy(rep_dup_target.updated_models[0]))
            with self.assertRaises(CatalogSyncError):
                apply_catalog_healing(p_rej, rep_dup_target)

            rep_wrong_prov_q = CatalogDriftReport(
                observed_date="2026-11-21",
                base_catalog_sha256=compute_models_data_digest(combined_catalog),
                providers=["privatemode"],
                disagreements=[
                    FeedDisagreementItem(
                        model_id="tinfoil-deepseek-v4-1-flash",
                        served_model_id="deepseek-v4-1-flash",
                        in_router_manifest=None,
                        in_openai_models=None,
                        router_healthy=None,
                        reason="wrong provider quarantine",
                        registered=True,
                        provider="privatemode",
                    )
                ],
            )
            with self.assertRaises(CatalogSyncError):
                apply_catalog_healing(p_rej, rep_wrong_prov_q, quarantine_disagreements=True)

        # 5. Mixed-provider safety-only transactions (with/without quarantine, unregistered disagreements, demotion-only, no-write)
        with tempfile.TemporaryDirectory() as td_safe:
            # Build mixed report:
            # - privatemode-glm-5-3-flash: weights changed across v1.63.0 -> v1.64.0 (active/cleared/default)
            # - privatemode-glm-5-3: registered disagreement
            # - unregistered disagreement (privatemode-ghost)
            # - unpriced manual Privatemode candidate (privatemode-nova-2)
            base_mix = copy.deepcopy(combined_catalog)
            for m in base_mix["models"]:
                if m["id"] == "privatemode-glm-5-3":
                    m["status"] = "active"
                    m["routing"]["private_attested"] = "blocked"
            p_mix = Path(td_safe) / "models.yaml"
            p_mix.write_text(dump_models_yaml(base_mix), encoding="utf-8")
            orig_mix = p_mix.read_bytes()

            mix_sha = compute_models_data_digest(base_mix)
            flash_orig = next(m for m in base_mix["models"] if m["id"] == "privatemode-glm-5-3-flash")
            mixed_rep = CatalogDriftReport(
                observed_date="2026-11-21",
                base_catalog_sha256=mix_sha,
                providers=["tinfoil", "privatemode"],
                provenance={"privatemode": {"tag": "v1.64.0", "commit_sha": v164_commit}},
                updated_models=[
                    ModelDriftItem(
                        model_id="privatemode-glm-5-3-flash",
                        served_model_id="glm-5.3-flash",
                        action="demote_weights_changed",
                        weights_changed=True,
                        provider="privatemode",
                        changes={
                            "enclave_tag": {"from": "v1.63.0", "to": "v1.64.0"},
                            "serve_command": {
                                "from": flash_orig["serve_command"],
                                "to": flash_orig["serve_command"].replace("v1.63.0", "v1.64.0"),
                            },
                            "remote_trust.provider_manifest_weights_hash": {
                                "from": flash_orig["remote_trust"]["provider_manifest_weights_hash"],
                                "to": "dmverity:sha256:" + ("9" * 64),
                            },
                            "status": {"from": "active", "to": "candidate"},
                            "routing.private_attested": {"from": "cleared", "to": "blocked"},
                            "routing.default_private_attested": {"from": True, "to": False},
                            "eval_evidence_artifact": {
                                "from": "docs/evals/privatemode-glm-5-3-flash.json",
                                "to": None,
                            },
                        },
                    )
                ],
                new_models=[
                    {
                        "id": "privatemode-nova-2",
                        "provider": "privatemode",
                        "manual_onboarding_required": True,
                        "repo": "nova-2",
                        "upstream": "acme/Nova-2-NVFP4",
                        "status": "candidate",
                        "remote_trust": {
                            "tier": "enclave_runtime_attested",
                            "attestation_method": "privatemode-proxy-contrast",
                            "pricing_per_m_tokens": None,
                        },
                    }
                ],
                disagreements=[
                    FeedDisagreementItem(
                        model_id="privatemode-glm-5-3",
                        served_model_id="glm-5.3",
                        in_router_manifest=None,
                        in_openai_models=None,
                        router_healthy=None,
                        reason="missing deployment for glm-5.3",
                        registered=True,
                        provider="privatemode",
                        feed_summary="deployment.yaml vs models.yaml",
                    ),
                    FeedDisagreementItem(
                        model_id="privatemode-ghost",
                        served_model_id="ghost-1",
                        in_router_manifest=None,
                        in_openai_models=None,
                        router_healthy=None,
                        reason="unregistered ghost workload missing disk",
                        registered=False,
                        provider="privatemode",
                        feed_summary="deployment.yaml vs models.yaml",
                    ),
                ],
            )

            # (a) Ordinary full apply fails closed leaving models.yaml byte-identical
            with self.assertRaises(CatalogSyncError):
                apply_catalog_healing(p_mix, mixed_rep)
            self.assertEqual(p_mix.read_bytes(), orig_mix)

            # (b) safety_only=True WITHOUT quarantine: demotes flash ONLY (no v1.64.0, no new hash, no new candidate), defers disagreements
            summary_no_q: dict[str, Any] = {}
            res_no_q = apply_catalog_healing(
                p_mix,
                mixed_rep,
                quarantine_disagreements=False,
                safety_only=True,
                apply_summary_out=summary_no_q,
            )
            self.assertTrue(summary_no_q["wrote_file"])
            self.assertEqual(len(summary_no_q["applied_actions"]), 1)
            self.assertEqual(len(summary_no_q["outstanding_disagreements"]), 2)
            self.assertEqual(summary_no_q["deferred_new_models"], ["privatemode-nova-2"])
            f_no_q = next(m for m in res_no_q["models"] if m["id"] == "privatemode-glm-5-3-flash")
            self.assertEqual(f_no_q["status"], "candidate")
            self.assertEqual(f_no_q["routing"]["private_attested"], "blocked")
            self.assertNotIn("default_private_attested", f_no_q["routing"])
            self.assertEqual(f_no_q["stale_eval_evidence_artifact"], "docs/evals/privatemode-glm-5-3-flash.json")
            self.assertEqual(f_no_q["enclave_tag"], "v1.63.0")
            self.assertEqual(
                f_no_q["remote_trust"]["provider_manifest_weights_hash"],
                flash_orig["remote_trust"]["provider_manifest_weights_hash"],
            )
            self.assertFalse(any(m["id"] == "privatemode-nova-2" for m in res_no_q["models"]))
            g_no_q = next(m for m in res_no_q["models"] if m["id"] == "privatemode-glm-5-3")
            self.assertEqual(g_no_q["status"], "active")
            self.assertEqual(g_no_q["routing"]["private_attested"], "blocked")

            # (c) safety_only=True WITH quarantine on fresh copy: quarantines glm-5-3 AND retains unregistered ghost in outstanding_disagreements
            p_mix2 = Path(td_safe) / "models2.yaml"
            p_mix2.write_bytes(orig_mix)
            summary_with_q: dict[str, Any] = {}
            res_with_q = apply_catalog_healing(
                p_mix2,
                mixed_rep,
                quarantine_disagreements=True,
                safety_only=True,
                apply_summary_out=summary_with_q,
            )
            self.assertTrue(summary_with_q["wrote_file"])
            self.assertEqual(len(summary_with_q["quarantined_disagreements"]), 1)
            self.assertEqual(len(summary_with_q["outstanding_disagreements"]), 1)
            self.assertFalse(summary_with_q["outstanding_disagreements"][0]["registered"])
            g_with_q = next(m for m in res_with_q["models"] if m["id"] == "privatemode-glm-5-3")
            self.assertEqual(g_with_q["routing"]["private_attested"], "blocked")
            self.assertEqual(g_with_q["status"], "candidate")

            # (d) No-write disagreement-only case (unregistered only) leaves file untouched (wrote_file=False)
            p_mix3 = Path(td_safe) / "models3.yaml"
            p_mix3.write_bytes(orig_mix)
            unreg_only_rep = CatalogDriftReport(
                observed_date="2026-11-21",
                base_catalog_sha256=mix_sha,
                providers=["privatemode"],
                disagreements=[mixed_rep.disagreements[1]],
            )
            summary_nowrite: dict[str, Any] = {}
            apply_catalog_healing(
                p_mix3,
                unreg_only_rep,
                quarantine_disagreements=True,
                safety_only=True,
                apply_summary_out=summary_nowrite,
            )
            self.assertFalse(summary_nowrite["wrote_file"])
            self.assertEqual(p_mix3.read_bytes(), orig_mix)
            self.assertEqual(len(summary_nowrite["outstanding_disagreements"]), 1)

            # (e) Failed full apply with quarantine leaves both catalog AND report unchanged, so retry succeeds
            p_retry = Path(td_safe) / "models_retry.yaml"
            p_retry.write_bytes(orig_mix)
            retry_rep = CatalogDriftReport(
                observed_date="2026-11-21",
                base_catalog_sha256=mix_sha,
                providers=["privatemode"],
                disagreements=[
                    FeedDisagreementItem(
                        model_id="privatemode-glm-5-3-flash",
                        served_model_id="glm-5.3-flash",
                        in_router_manifest=None,
                        in_openai_models=None,
                        router_healthy=None,
                        reason="transient write failure retry test",
                        registered=True,
                        provider="privatemode",
                        feed_summary="deployment.yaml vs models.yaml",
                    )
                ],
            )
            with patch("local_assist.catalog_sync.os.replace", side_effect=OSError("simulated replace EIO")):
                with self.assertRaises(OSError):
                    apply_catalog_healing(p_retry, retry_rep, quarantine_disagreements=True)
            self.assertEqual(p_retry.read_bytes(), orig_mix)
            self.assertEqual(retry_rep.updated_models, [])
            # Replay same report after transient failure clears -> succeeds cleanly!
            healed_retry = apply_catalog_healing(p_retry, retry_rep, quarantine_disagreements=True)
            self.assertEqual(len(retry_rep.updated_models), 1)
            self.assertEqual(retry_rep.updated_models[0].action, "quarantine_disagreement")
            flash_retried = next(m for m in healed_retry["models"] if m["id"] == "privatemode-glm-5-3-flash")
            self.assertEqual(flash_retried["status"], "candidate")
            self.assertEqual(flash_retried["routing"]["private_attested"], "blocked")
            self.assertEqual(flash_retried["stale_eval_evidence_artifact"], "docs/evals/privatemode-glm-5-3-flash.json")

    def test_privatemode_and_all_provider_cli_and_workflow(self) -> None:
        import contextlib
        import importlib.machinery
        import importlib.util
        import io
        from local_assist.catalog_sync import (
            parse_privatemode_deployment_yaml,
            parse_privatemode_models_yaml,
        )

        script_path = ROOT / "scripts" / "sync-model-catalog"
        loader = importlib.machinery.SourceFileLoader("sync_model_catalog_cli_pm_all", str(script_path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        assert spec is not None and spec.loader is not None
        cli_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli_mod)

        fix_dir = ROOT / "tests" / "fixtures" / "privatemode_v1_64_0"
        prov = json.loads((fix_dir / "PROVENANCE.json").read_text(encoding="utf-8"))
        v164_commit = prov["commit_sha"]
        disk_map = parse_privatemode_models_yaml((fix_dir / "models.yaml").read_text(encoding="utf-8"))
        dep_data = parse_privatemode_deployment_yaml((fix_dir / "deployment.yaml").read_text(encoding="utf-8"))
        rel_fixture = {
            "repo": "edgelesssys/privatemode-public",
            "tag_name": "v1.64.0",
            "published_at": "2026-11-14T16:36:05Z",
            "manifest_asset_name": "manifest.json",
            "manifest_asset_size": 12345,
            "manifest_asset_url": "https://github.com/edgelesssys/privatemode-public/releases/download/v1.64.0/manifest.json",
            "manifest_asset_digest": None,
        }

        real_models_data = safe_load((ROOT / "models.yaml").read_text(encoding="utf-8"))
        combined_models = _make_base_models_fixture()
        combined_models["models"].extend(
            copy.deepcopy(m) for m in real_models_data["models"] if str(m.get("id", "")).startswith("privatemode-")
        )
        enclaves_base = {
            "tinfoilsh/confidential-deepseek-v4-1-flash@v0.0.10+b200": parse_tinfoil_config_yaml(DEEPSEEK_V4_1_FLASH_YAML),
            "tinfoilsh/confidential-kimi-k3@v0.0.16": parse_tinfoil_config_yaml(KIMI_K3_V0_0_16_YAML),
            "tinfoilsh/confidential-kimi-k3-1-pro@v0.0.3": parse_tinfoil_config_yaml(KIMI_K3_1_PRO_V0_0_3_YAML),
        }

        with tempfile.TemporaryDirectory() as td:
            p_models = Path(td) / "models.yaml"
            p_models.write_text(dump_models_yaml(combined_models), encoding="utf-8")
            j_out = Path(td) / "out.json"
            m_out = Path(td) / "out.md"

            # 1. --provider privatemode --check --json agrees across stdout JSON, file JSON, and Markdown
            buf = io.StringIO()
            with (
                patch.object(cli_mod, "fetch_privatemode_latest_release", return_value=rel_fixture),
                patch.object(cli_mod, "fetch_privatemode_tag_commit", return_value=v164_commit),
                patch.object(cli_mod, "fetch_privatemode_models_yaml", return_value=disk_map),
                patch.object(cli_mod, "fetch_privatemode_deployment_yaml", return_value=dep_data),
                contextlib.redirect_stdout(buf),
            ):
                rc_pm = cli_mod.main(
                    [
                        "--check",
                        "--provider",
                        "privatemode",
                        "--json",
                        "--models-path",
                        str(p_models),
                        "--json-out",
                        str(j_out),
                        "--markdown-out",
                        str(m_out),
                    ]
                )
            self.assertEqual(rc_pm, 2)
            stdout_obj = json.loads(buf.getvalue())
            file_obj = json.loads(j_out.read_text(encoding="utf-8"))
            md_text = m_out.read_text(encoding="utf-8")
            self.assertEqual(stdout_obj["providers"], ["privatemode"])
            self.assertEqual(file_obj["providers"], ["privatemode"])
            self.assertEqual(stdout_obj["provenance"]["privatemode"]["commit_sha"], v164_commit)
            self.assertEqual(file_obj["provenance"]["privatemode"]["commit_sha"], v164_commit)
            self.assertTrue(all(u["provider"] == "privatemode" for u in stdout_obj["updated_models"]))
            self.assertIn("**Providers**: `privatemode`", md_text)
            self.assertIn("[privatemode]", md_text)

            # 2. --provider all with partial-provider failure (Tinfoil healthy, Privatemode fails):
            # exits 1, unlinks outputs, reconciler refuses with 0 gh calls
            gh_calls: list[list[str]] = []
            with (
                patch.object(cli_mod, "fetch_tinfoil_router_manifest", return_value=_make_router_manifest_fixture()),
                patch.object(cli_mod, "fetch_tinfoil_openai_models", return_value=_make_openai_models_fixture()),
                patch.object(
                    cli_mod,
                    "fetch_tinfoil_enclave_config",
                    side_effect=lambda r, t, **kw: enclaves_base[f"{r}@{t}"],
                ),
                patch.object(
                    cli_mod,
                    "fetch_privatemode_latest_release",
                    side_effect=CatalogSyncError("Privatemode GitHub API 503"),
                ),
            ):
                rc_fail = cli_mod.main(
                    [
                        "--check",
                        "--provider",
                        "all",
                        "--models-path",
                        str(p_models),
                        "--json-out",
                        str(j_out),
                        "--markdown-out",
                        str(m_out),
                    ]
                )
            self.assertEqual(rc_fail, 1)
            self.assertFalse(j_out.exists())
            self.assertFalse(m_out.exists())
            with self.assertRaises(CatalogSyncError):
                reconcile_github_drift_issue(
                    repo="HakAl/free-inference",
                    exit_code=rc_fail,
                    json_report_path=j_out,
                    markdown_body_path=m_out,
                    is_default_branch=True,
                    run_gh_fn=lambda a: (gh_calls.append(a), "[]")[1],
                )
            self.assertEqual(gh_calls, [])

            # 3. Demotion-only --apply --safety-only (zero quarantines, zero deferred items, zero disagreements) -> safety_applied + exit 0
            pm_same_tag_weight_drift = {
                "models": [
                    copy.deepcopy(m)
                    for m in real_models_data["models"]
                    if m.get("id") == "privatemode-glm-5-3-flash"
                ]
            }
            pm_same_tag_weight_drift["models"][0]["enclave_tag"] = "v1.64.0"
            pm_same_tag_weight_drift["models"][0]["serve_command"] = (
                pm_same_tag_weight_drift["models"][0]["serve_command"].replace("v1.63.0", "v1.64.0")
            )
            p_demote = Path(td) / "models_demote.yaml"
            p_demote.write_text(dump_models_yaml(pm_same_tag_weight_drift), encoding="utf-8")
            j_demote = Path(td) / "demote.json"
            # Remove flash from both deployment.yaml and models.yaml -> pure archive_removed (zero deferred items!)
            dep_no_flash = copy.deepcopy(dep_data)
            dep_no_flash["workloads"].pop("glm-5.3-flash")
            disk_no_flash = {
                k: v for k, v in disk_map.items() if v["disk_key"] != "nvidia-glm-5-3-flash-nvfp4"
            }
            with (
                patch.object(cli_mod, "fetch_privatemode_latest_release", return_value=rel_fixture),
                patch.object(cli_mod, "fetch_privatemode_tag_commit", return_value=v164_commit),
                patch.object(cli_mod, "fetch_privatemode_models_yaml", return_value=disk_no_flash),
                patch.object(cli_mod, "fetch_privatemode_deployment_yaml", return_value=dep_no_flash),
            ):
                rc_dem = cli_mod.main(
                    [
                        "--apply",
                        "--safety-only",
                        "--no-discover-new",
                        "--provider",
                        "privatemode",
                        "--models-path",
                        str(p_demote),
                        "--json-out",
                        str(j_demote),
                    ]
                )
            self.assertEqual(rc_dem, 0)
            dem_payload = json.loads(j_demote.read_text(encoding="utf-8"))
            self.assertEqual(dem_payload["check_status"], "safety_applied")
            self.assertTrue(dem_payload["apply_summary"]["wrote_file"])
            self.assertEqual(dem_payload["apply_summary"]["deferred_updates"], [])
            self.assertEqual(dem_payload["apply_summary"]["outstanding_disagreements"], [])

            # 4. --apply --safety-only --quarantine-disagreements with surviving unregistered disagreement returns exit 1
            p_unreg = Path(td) / "models_unreg.yaml"
            p_unreg.write_text(dump_models_yaml(pm_same_tag_weight_drift), encoding="utf-8")
            j_unreg = Path(td) / "unreg.json"
            dep_with_orphan = copy.deepcopy(dep_no_flash)
            dep_with_orphan["partial_deployments"] = [
                {
                    "deployment_name": "workload-orphan",
                    "container_name": None,
                    "served_model_id": "orphan-1",
                    "disk_name": "orphan-1",
                    "root_hash": "e" * 64,
                    "reason": "unregistered orphan disk-mounter",
                }
            ]
            with (
                patch.object(cli_mod, "fetch_privatemode_latest_release", return_value=rel_fixture),
                patch.object(cli_mod, "fetch_privatemode_tag_commit", return_value=v164_commit),
                patch.object(cli_mod, "fetch_privatemode_models_yaml", return_value=disk_no_flash),
                patch.object(cli_mod, "fetch_privatemode_deployment_yaml", return_value=dep_with_orphan),
            ):
                rc_unreg = cli_mod.main(
                    [
                        "--apply",
                        "--safety-only",
                        "--quarantine-disagreements",
                        "--no-discover-new",
                        "--provider",
                        "privatemode",
                        "--models-path",
                        str(p_unreg),
                        "--json-out",
                        str(j_unreg),
                    ]
                )
            self.assertEqual(rc_unreg, 1)
            unreg_payload = json.loads(j_unreg.read_text(encoding="utf-8"))
            self.assertEqual(unreg_payload["check_status"], "safety_applied_with_disagreements")
            self.assertEqual(len(unreg_payload["apply_summary"]["outstanding_disagreements"]), 1)

            # 5. CLI --provider all Pass 2 concurrent-edit digest recomputation across both providers
            p_pass2 = Path(td) / "models_pass2.yaml"
            cat_pass2 = _make_base_models_fixture()
            pm_clean_entry = copy.deepcopy(pm_same_tag_weight_drift["models"][0])
            cat_pass2["models"].append(pm_clean_entry)
            p_pass2.write_text(dump_models_yaml(cat_pass2), encoding="utf-8")

            cat_mutated = copy.deepcopy(cat_pass2)
            cat_mutated["models"][-1]["verified_date"] = "2026-11-19"
            triggered = [False]

            def _mutating_enclave_fetch(repo: str, tag: str, **_kw: object) -> dict[str, Any]:
                if not triggered[0]:
                    triggered[0] = True
                    p_pass2.write_text(dump_models_yaml(cat_mutated), encoding="utf-8")
                return enclaves_base[f"{repo}@{tag}"]

            with (
                patch.object(cli_mod, "fetch_tinfoil_router_manifest", return_value=_make_router_manifest_fixture()),
                patch.object(cli_mod, "fetch_tinfoil_openai_models", return_value=_make_openai_models_fixture()),
                patch.object(cli_mod, "fetch_tinfoil_enclave_config", side_effect=_mutating_enclave_fetch),
                patch.object(cli_mod, "fetch_privatemode_latest_release", return_value=rel_fixture),
                patch.object(cli_mod, "fetch_privatemode_tag_commit", return_value=v164_commit),
                patch.object(cli_mod, "fetch_privatemode_models_yaml", return_value=disk_map),
                patch.object(cli_mod, "fetch_privatemode_deployment_yaml", return_value=dep_data),
            ):
                rc_p2 = cli_mod.main(
                    [
                        "--apply",
                        "--no-discover-new",
                        "--provider",
                        "all",
                        "--models-path",
                        str(p_pass2),
                    ]
                )
            self.assertEqual(rc_p2, 0)
            self.assertTrue(triggered[0])

        # 6. Workflow structural check: --provider all and zero GH_TOKEN in check step
        wf_data = safe_load((ROOT / ".github" / "workflows" / "catalog-sync.yml").read_text(encoding="utf-8"))
        steps = wf_data["jobs"]["check-catalog-drift"]["steps"]
        self.assertIn("--provider all", steps[2]["run"])
        self.assertNotIn("GH_TOKEN", steps[2].get("env") or {})
        self.assertIn("GH_TOKEN", steps[3].get("env") or {})

    def test_lookout_track3_r1_fixes_partial_attribution_builder_toctou_json_strict_and_markdown(self) -> None:
        """Regression tests for FREE-INFERENCE-TRACK3-001 F1, F2, F3, Minor 1, and Minor 2."""
        import hashlib
        import shutil
        import subprocess
        from local_assist import catalog_sync as cs_mod
        from local_assist._miniyaml import parse_yaml_with_flow_sequences
        from local_assist.catalog_sync import (
            compute_privatemode_catalog_drift,
            parse_privatemode_models_yaml,
        )

        # --- F1: Partial deployment attribution must not quarantine unrelated models sharing a leaf ---
        h_good = "1" * 64
        h_other = "2" * 64
        h_unknown = "3" * 64
        h_gpt = "4" * 64
        disk_map = {
            h_good: {
                "disk_key": "acme-shared-leaf",
                "upstream": "acme/shared-leaf",
                "commit_hash": "a" * 40,
                "weights_source": f"acme/shared-leaf@{'a' * 40}",
                "root_hash": h_good,
                "weights_hash": f"dmverity:sha256:{h_good}",
                "file_size_bytes": 10_000_000_000,
                "disk_gb_estimate": 10.0,
            },
            h_other: {
                "disk_key": "rival-shared-leaf",
                "upstream": "rival/shared-leaf",
                "commit_hash": "b" * 40,
                "weights_source": f"rival/shared-leaf@{'b' * 40}",
                "root_hash": h_other,
                "weights_hash": f"dmverity:sha256:{h_other}",
                "file_size_bytes": 10_000_000_000,
                "disk_gb_estimate": 10.0,
            },
            h_gpt: {
                "disk_key": "openai-gpt-oss-120b",
                "upstream": "openai/gpt-oss-120b",
                "commit_hash": "c" * 40,
                "weights_source": f"openai/gpt-oss-120b@{'c' * 40}",
                "root_hash": h_gpt,
                "weights_hash": f"dmverity:sha256:{h_gpt}",
                "file_size_bytes": 65_000_000_000,
                "disk_gb_estimate": 65.0,
            },
        }
        base_pm = {
            "models": [
                {
                    "id": "privatemode-acme-shared-leaf",
                    "repo": "acme/shared-leaf",
                    "runtime": "proxy",
                    "host": "127.0.0.1",
                    "port": 8082,
                    "endpoint_url": "http://127.0.0.1:8082/v1",
                    "status": "active",
                    "data_control_rung": "enclave_runtime_attested",
                    "usage_policy": "enclave_no_inspection",
                    "enclave_repo": "edgelesssys/privatemode-public",
                    "enclave_tag": "v1.64.0",
                    "serve_command": "./bin/privatemode-proxy --listen-address {host} --port {port} --api-key-fallback=never --manifest-path config/privatemode-manifest-v1.64.0.json --workspace .home/privatemode-proxy --nvidia-ocsp-allow-unknown=false --nvidia-ocsp-revoked-grace-period=0",
                    "promptfoo_provider": {"apiKeyKeychainService": "free-inference.privatemode"},
                    "routing": {"private_local": "blocked", "private_attested": "blocked"},
                    "remote_trust": {
                        "tier": "enclave_runtime_attested",
                        "attestation_method": "privatemode-proxy-contrast",
                        "usage_policy": "enclave_no_inspection",
                        "provider_manifest_weights_hash": f"dmverity:sha256:{h_good}",
                        "provider_manifest_weights_source": f"acme/shared-leaf@{'a' * 40}",
                    },
                    "verified_date": "2026-11-21",
                },
                {
                    "id": "privatemode-unqual-shared-leaf",
                    "repo": "shared-leaf",
                    "runtime": "proxy",
                    "host": "127.0.0.1",
                    "port": 8082,
                    "endpoint_url": "http://127.0.0.1:8082/v1",
                    "status": "active",
                    "data_control_rung": "enclave_runtime_attested",
                    "usage_policy": "enclave_no_inspection",
                    "enclave_repo": "edgelesssys/privatemode-public",
                    "enclave_tag": "v1.64.0",
                    "serve_command": "./bin/privatemode-proxy --listen-address {host} --port {port} --api-key-fallback=never --manifest-path config/privatemode-manifest-v1.64.0.json --workspace .home/privatemode-proxy --nvidia-ocsp-allow-unknown=false --nvidia-ocsp-revoked-grace-period=0",
                    "promptfoo_provider": {"apiKeyKeychainService": "free-inference.privatemode"},
                    "routing": {"private_local": "blocked", "private_attested": "blocked"},
                    "remote_trust": {
                        "tier": "enclave_runtime_attested",
                        "attestation_method": "privatemode-proxy-contrast",
                        "usage_policy": "enclave_no_inspection",
                        "provider_manifest_weights_hash": f"dmverity:sha256:{h_good}",
                        "provider_manifest_weights_source": f"acme/shared-leaf@{'a' * 40}",
                    },
                    "verified_date": "2026-11-21",
                },
                {
                    "id": "privatemode-gpt-oss-120b",
                    "repo": "openai/gpt-oss-120b",
                    "runtime": "proxy",
                    "host": "127.0.0.1",
                    "port": 8082,
                    "endpoint_url": "http://127.0.0.1:8082/v1",
                    "status": "active",
                    "data_control_rung": "enclave_runtime_attested",
                    "usage_policy": "enclave_no_inspection",
                    "enclave_repo": "edgelesssys/privatemode-public",
                    "enclave_tag": "v1.64.0",
                    "serve_command": "./bin/privatemode-proxy --listen-address {host} --port {port} --api-key-fallback=never --manifest-path config/privatemode-manifest-v1.64.0.json --workspace .home/privatemode-proxy --nvidia-ocsp-allow-unknown=false --nvidia-ocsp-revoked-grace-period=0",
                    "promptfoo_provider": {"apiKeyKeychainService": "free-inference.privatemode"},
                    "routing": {"private_local": "blocked", "private_attested": "blocked"},
                    "remote_trust": {
                        "tier": "enclave_runtime_attested",
                        "attestation_method": "privatemode-proxy-contrast",
                        "usage_policy": "enclave_no_inspection",
                        "provider_manifest_weights_hash": f"dmverity:sha256:{h_gpt}",
                        "provider_manifest_weights_source": f"openai/gpt-oss-120b@{'c' * 40}",
                    },
                    "verified_date": "2026-11-21",
                },
            ]
        }
        dep_f1 = {
            "workloads": {
                "acme/shared-leaf": {
                    "served_model_id": "acme/shared-leaf",
                    "aliases": [],
                    "deployment_name": "dep-acme",
                    "container_name": "workload-acme",
                    "disk_name": "shared-leaf",
                    "k8s_slug": "shared-leaf",
                    "root_hash": h_good,
                    "weights_hash": f"dmverity:sha256:{h_good}",
                    "max_model_len": 32768,
                    "tool_call_parser": None,
                    "reasoning_parser": None,
                    "kv_cache_dtype": None,
                    "enable_auto_tool_choice": False,
                    "tool_calling_hint": None,
                },
                "shared-leaf": {
                    "served_model_id": "shared-leaf",
                    "aliases": [],
                    "deployment_name": "dep-unqual",
                    "container_name": "workload-unqual",
                    "disk_name": "shared-leaf",
                    "k8s_slug": "shared-leaf",
                    "root_hash": h_good,
                    "weights_hash": f"dmverity:sha256:{h_good}",
                    "max_model_len": 32768,
                    "tool_call_parser": None,
                    "reasoning_parser": None,
                    "kv_cache_dtype": None,
                    "enable_auto_tool_choice": False,
                    "tool_calling_hint": None,
                },
            },
            "partial_deployments": [
                # 1) Zero-replica unregistered rival/shared-leaf shares leaf 'shared-leaf': must stay unregistered
                {
                    "kind": "zero_replicas",
                    "deployment_name": "dep-rival-zero",
                    "container_name": "workload-rival",
                    "served_model_id": "rival/shared-leaf",
                    "disk_name": "shared-leaf",
                    "k8s_slug": "shared-leaf",
                    "root_hash": h_other,
                    "reason": "zero replicas for rival/shared-leaf",
                },
                # 2) Orphan disk-mounter for rival/shared-leaf (different upstream org): must NOT match unqualified shared-leaf
                {
                    "kind": "orphan_disk_mounter",
                    "deployment_name": "dep-rival-orphan",
                    "container_name": None,
                    "served_model_id": None,
                    "disk_name": "shared-leaf",
                    "k8s_slug": "shared-leaf",
                    "root_hash": h_other,
                    "reason": "orphan disk-mounter for rival/shared-leaf",
                },
                # 3) Orphan disk-mounter with unknown root_hash: must stay unregistered
                {
                    "kind": "orphan_disk_mounter",
                    "deployment_name": "dep-unknown-orphan",
                    "container_name": None,
                    "served_model_id": None,
                    "disk_name": "shared-leaf",
                    "k8s_slug": "shared-leaf",
                    "root_hash": h_unknown,
                    "reason": "orphan disk-mounter with unknown root_hash",
                },
                # 4) Orphan disk-mounter matching BOTH registered shared-leaf models (acme/shared-leaf + shared-leaf): ambiguous -> unregistered
                {
                    "kind": "orphan_disk_mounter",
                    "deployment_name": "dep-ambig-orphan",
                    "container_name": None,
                    "served_model_id": None,
                    "disk_name": "shared-leaf",
                    "k8s_slug": "shared-leaf",
                    "root_hash": h_good,
                    "reason": "orphan disk-mounter for acme/shared-leaf",
                },
                # 5) Orphan disk-mounter uniquely supported by authoritative disk identity (openai/gpt-oss-120b): registered=True
                {
                    "kind": "orphan_disk_mounter",
                    "deployment_name": "dep-gpt-orphan",
                    "container_name": None,
                    "served_model_id": None,
                    "disk_name": "gpt-oss-120b",
                    "k8s_slug": "gpt-oss-120b",
                    "root_hash": h_gpt,
                    "reason": "orphan disk-mounter for openai/gpt-oss-120b",
                },
            ],
        }
        rep_f1 = compute_privatemode_catalog_drift(
            base_pm,
            release_tag="v1.64.0",
            models_disk_map=disk_map,
            deployment_data=dep_f1,
            observed_date="2026-11-21",
        )
        reg_dis = [d for d in rep_f1.disagreements if d.registered]
        unreg_dis = [d for d in rep_f1.disagreements if not d.registered]
        self.assertEqual([d.model_id for d in reg_dis], ["privatemode-gpt-oss-120b"])
        self.assertEqual(len(unreg_dis), 4)
        self.assertTrue(any("coherent primary workload exists" in d.reason for d in unreg_dis))
        self.assertTrue(all(d.model_id not in ("privatemode-acme-shared-leaf", "privatemode-unqual-shared-leaf") for d in reg_dis))

        # Ambiguous orphan when TWO registered models share disk identity and NEITHER has a coherent primary workload
        dep_f1_ambig = copy.deepcopy(dep_f1)
        dep_f1_ambig["workloads"] = {}
        rep_f1_ambig = compute_privatemode_catalog_drift(
            base_pm,
            release_tag="v1.64.0",
            models_disk_map=disk_map,
            deployment_data=dep_f1_ambig,
            observed_date="2026-11-21",
        )
        self.assertTrue(
            any(not d.registered and "ambiguous across registered models" in d.reason for d in rep_f1_ambig.disagreements)
        )

        # Apply with --safety-only --quarantine-disagreements: healthy shared-leaf models remain untouched (status='active')
        with tempfile.TemporaryDirectory() as td:
            mpath = Path(td) / "models.yaml"
            mpath.write_text(dump_models_yaml(base_pm), encoding="utf-8")
            summary_f1: dict[str, Any] = {}
            after_f1 = apply_catalog_healing(
                mpath,
                rep_f1,
                quarantine_disagreements=True,
                append_new_models=False,
                safety_only=True,
                apply_summary_out=summary_f1,
            )
            by_id_after = {m["id"]: m for m in after_f1["models"]}
            self.assertEqual(by_id_after["privatemode-acme-shared-leaf"]["status"], "active")
            self.assertEqual(by_id_after["privatemode-unqual-shared-leaf"]["status"], "active")
            self.assertEqual(by_id_after["privatemode-gpt-oss-120b"]["status"], "candidate")
            self.assertEqual(len(summary_f1["outstanding_disagreements"]), 4)

        # --- F2: Single-read builder proof + concurrent builder/HEAD mutation aborts before os.replace ---
        if shutil.which("git"):
            with tempfile.TemporaryDirectory() as td:
                repo = Path(td) / "pm_toctou_repo"
                (repo / "config").mkdir(parents=True)
                (repo / "scripts").mkdir(parents=True)
                subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
                subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test User"], check=True)
                subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)

                manifest_bytes = json.dumps({"ReferenceValues": {"a": 1}, "Policies": {"b": 2}}, indent=2).encode("utf-8")
                manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
                commit_sha = "d" * 40
                (repo / "config" / "privatemode-manifest-v1.64.0.json").write_bytes(manifest_bytes)
                builder_path = repo / "scripts" / "build-privatemode-proxy"
                builder_good = (
                    "from pathlib import Path\n"
                    "ROOT = Path(__file__).resolve().parents[1]\n"
                    'PRIVATEMODE_VERSION = "1.64.0"\n'
                    f'PRIVATEMODE_SOURCE_COMMIT = "{commit_sha}"\n'
                    'COMMITTED_MANIFEST_PATH = ROOT / "config" / "privatemode-manifest-v1.64.0.json"\n'
                    f'EXPECTED_MANIFEST_SHA256 = "{manifest_sha}"\n'
                )
                builder_path.write_text(builder_good, encoding="utf-8")

                pm_upgrade_cat = {
                    "models": [
                        {
                            "id": "privatemode-gpt-oss-120b",
                            "repo": "openai/gpt-oss-120b",
                            "runtime": "proxy",
                            "host": "127.0.0.1",
                            "port": 8082,
                            "endpoint_url": "http://127.0.0.1:8082/v1",
                            "status": "active",
                            "data_control_rung": "enclave_runtime_attested",
                            "usage_policy": "enclave_no_inspection",
                            "enclave_repo": "edgelesssys/privatemode-public",
                            "enclave_tag": "v1.63.0",
                            "serve_command": "./bin/privatemode-proxy --listen-address {host} --port {port} --api-key-fallback=never --manifest-path config/privatemode-manifest-v1.63.0.json --workspace .home/privatemode-proxy --nvidia-ocsp-allow-unknown=false --nvidia-ocsp-revoked-grace-period=0",
                            "promptfoo_provider": {"apiKeyKeychainService": "free-inference.privatemode"},
                            "routing": {"private_local": "blocked", "private_attested": "blocked"},
                            "remote_trust": {
                                "tier": "enclave_runtime_attested",
                                "attestation_method": "privatemode-proxy-contrast",
                                "usage_policy": "enclave_no_inspection",
                                "provider_manifest_weights_hash": f"dmverity:sha256:{h_gpt}",
                                "provider_manifest_weights_source": f"openai/gpt-oss-120b@{'c' * 40}",
                            },
                            "verified_date": "2026-11-20",
                        }
                    ]
                }
                models_path = repo / "models.yaml"
                models_path.write_text(dump_models_yaml(pm_upgrade_cat), encoding="utf-8")
                subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
                subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "init"], check=True)

                dep_gpt = {
                    "workloads": {
                        "openai/gpt-oss-120b": {
                            "served_model_id": "openai/gpt-oss-120b",
                            "aliases": [],
                            "deployment_name": "dep-gpt",
                            "container_name": "workload-gpt",
                            "disk_name": "gpt-oss-120b",
                            "k8s_slug": "gpt-oss-120b",
                            "root_hash": h_gpt,
                            "weights_hash": f"dmverity:sha256:{h_gpt}",
                            "max_model_len": 131072,
                            "tool_call_parser": "openai",
                            "reasoning_parser": "openai_gptoss",
                            "kv_cache_dtype": None,
                            "enable_auto_tool_choice": True,
                            "tool_calling_hint": "vLLM tool_call_parser=openai",
                        }
                    },
                    "partial_deployments": [],
                }
                rep_f2 = compute_privatemode_catalog_drift(
                    pm_upgrade_cat,
                    release_tag="v1.64.0",
                    models_disk_map=disk_map,
                    deployment_data=dep_gpt,
                    observed_date="2026-11-21",
                    provenance={"tag": "v1.64.0", "commit_sha": commit_sha},
                )
                before_bytes = models_path.read_bytes()

                # Simulate concurrent in-place builder edit between initial proof and os.replace
                orig_dump = cs_mod.dump_models_yaml

                def _race_dirty_edit_during_dump(*a: Any, **kw: Any) -> str:
                    builder_path.write_text(
                        builder_good.replace('PRIVATEMODE_VERSION = "1.64.0"', 'PRIVATEMODE_VERSION = "1.63.0"'),
                        encoding="utf-8",
                    )
                    return orig_dump(*a, **kw)

                with patch.object(cs_mod, "dump_models_yaml", side_effect=_race_dirty_edit_during_dump):
                    with self.assertRaises(CatalogSyncError) as ctx_dirty:
                        apply_catalog_healing(models_path, rep_f2, append_new_models=False)
                self.assertIn("became dirty concurrently", str(ctx_dirty.exception))
                self.assertEqual(models_path.read_bytes(), before_bytes)

                # Restore clean builder, then simulate concurrent commit advancing HEAD before os.replace
                builder_path.write_text(builder_good, encoding="utf-8")

                def _race_commit_during_dump(*a: Any, **kw: Any) -> str:
                    builder_path.write_text(
                        builder_good.replace('PRIVATEMODE_VERSION = "1.64.0"', 'PRIVATEMODE_VERSION = "1.63.0"'),
                        encoding="utf-8",
                    )
                    subprocess.run(["git", "-C", str(repo), "add", "scripts/build-privatemode-proxy"], check=True)
                    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "concurrent builder swap"], check=True)
                    return orig_dump(*a, **kw)

                with patch.object(cs_mod, "dump_models_yaml", side_effect=_race_commit_during_dump):
                    with self.assertRaises(CatalogSyncError) as ctx_race:
                        apply_catalog_healing(models_path, rep_f2, append_new_models=False)
                self.assertIn("HEAD changed concurrently", str(ctx_race.exception))
                self.assertEqual(models_path.read_bytes(), before_bytes)

                # Reset to the good commit and test mutations injected DURING final reverification:
                # (a) outside-lock models.yaml mutation during _reverify_committed_privatemode_proof
                subprocess.run(["git", "-C", str(repo), "reset", "--hard", "-q", "HEAD~1"], check=True)
                before_bytes_reverify = models_path.read_bytes()
                orig_reverify = cs_mod._reverify_committed_privatemode_proof

                def _mutate_models_during_reverify(proof: dict[str, Any]) -> None:
                    orig_reverify(proof)
                    models_path.write_bytes(before_bytes_reverify + b"# outside-lock concurrent edit\n")

                with patch.object(
                    cs_mod, "_reverify_committed_privatemode_proof", side_effect=_mutate_models_during_reverify
                ):
                    with self.assertRaises(CatalogSyncError) as ctx_cat_race:
                        apply_catalog_healing(models_path, rep_f2, append_new_models=False)
                self.assertIn("modified concurrently outside catalog_file_lock", str(ctx_cat_race.exception))
                self.assertEqual(
                    models_path.read_bytes(),
                    before_bytes_reverify + b"# outside-lock concurrent edit\n",
                )

                # (b) HEAD advance during git status inside final reverification (leaving proof paths clean/unchanged)
                models_path.write_bytes(before_bytes_reverify)
                orig_subproc_run = cs_mod.subprocess.run
                status_calls = [0]

                def _advance_head_during_reverify_status(cmd: list[str], *a: Any, **kw: Any) -> Any:
                    res = orig_subproc_run(cmd, *a, **kw)
                    if len(cmd) >= 4 and cmd[3] == "status":
                        status_calls[0] += 1
                        if status_calls[0] == 2:
                            # Second status call is inside _reverify_committed_privatemode_proof
                            (repo / "unrelated.txt").write_text("concurrent commit\n", encoding="utf-8")
                            orig_subproc_run(["git", "-C", str(repo), "add", "unrelated.txt"], check=True)
                            orig_subproc_run(
                                ["git", "-C", str(repo), "commit", "-q", "-m", "advance HEAD during status"],
                                check=True,
                            )
                    return res

                with patch.object(cs_mod.subprocess, "run", side_effect=_advance_head_during_reverify_status):
                    with self.assertRaises(CatalogSyncError) as ctx_head_during_status:
                        apply_catalog_healing(models_path, rep_f2, append_new_models=False)
                self.assertIn("HEAD changed concurrently", str(ctx_head_during_status.exception))
                self.assertEqual(models_path.read_bytes(), before_bytes_reverify)

        # --- F3: Strict models.yaml rejects top-level JSON ConfigMap (including 1e3) on both stdlib & PyYAML ---
        json_configmap = json.dumps(
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "model-disks", "extra_num": 1000},
                "data": {
                    "openai-gpt-oss-120b": json.dumps(
                        {
                            "model_source": f"https://huggingface.co/openai/gpt-oss-120b/tree/{'c' * 40}",
                            "root_hash": h_gpt,
                            "file_size_bytes": 65000000000,
                        }
                    )
                },
            }
        ).replace("1000", "1e3")
        with self.assertRaises(CatalogSyncError) as ctx_json_cm:
            parse_privatemode_models_yaml(json_configmap)
        self.assertIn("Strict YAML mode rejects top-level flow/JSON", str(ctx_json_cm.exception))
        # Legacy non-strict path still parses JSON documents (Tinfoil models.yaml compatibility)
        legacy_parsed = parse_yaml_with_flow_sequences('{"a": 1, "b": [2, 3]}', strict_plain_scalars=False)
        self.assertEqual(legacy_parsed, {"a": 1, "b": [2, 3]})

        # --- Minor 1 & Minor 2: Deferred safety-only Markdown heading & provider-matched remediation commands ---
        deferred_md = render_github_issue_body(
            {
                "check_status": "safety_applied",
                "observed_date": "2026-11-21",
                "providers": ["privatemode"],
                "has_drift": True,
                "apply_summary": {
                    "safety_only": True,
                    "wrote_file": False,
                    "applied_actions": [],
                    "deferred_updates": [{"model_id": "privatemode-gpt-oss-120b", "changes": ["enclave_tag"]}],
                    "deferred_new_models": [],
                    "outstanding_disagreements": [],
                },
            },
            human_output="deferred only",
            exit_code=0,
        )
        self.assertIn("## Safety-Only Catalog Check: Updates Deferred (No File Written)", deferred_md)
        self.assertNotIn("Demotions Applied", deferred_md)
        self.assertIn("./scripts/sync-model-catalog --provider privatemode --check", deferred_md)
        self.assertIn("./scripts/sync-model-catalog --provider privatemode --apply --safety-only", deferred_md)

        applied_md = render_github_issue_body(
            {
                "check_status": "safety_applied",
                "observed_date": "2026-11-21",
                "providers": ["tinfoil", "privatemode"],
                "has_drift": True,
                "apply_summary": {
                    "safety_only": True,
                    "wrote_file": True,
                    "applied_actions": [{"model_id": "privatemode-gpt-oss-120b", "action": "demote_weights_changed"}],
                    "deferred_updates": [],
                    "deferred_new_models": [],
                    "outstanding_disagreements": [],
                },
            },
            human_output="demotion applied",
            exit_code=0,
        )
        self.assertIn("## Safety-Only Catalog Demotions Applied", applied_md)
        self.assertIn("./scripts/sync-model-catalog --provider all --check", applied_md)
        self.assertIn("./scripts/sync-model-catalog --provider all --apply --safety-only", applied_md)
        self.assertIn("./scripts/sync-model-catalog --provider tinfoil --apply", applied_md)

    def test_lookout_track3_r2_fixes_detached_glm_orphan_last_git_edit_and_nbsp_strict_parity(self) -> None:
        """Regression tests for FREE-INFERENCE-TRACK3-001 Round 2 F1, F2, and F3."""
        import hashlib
        import shutil
        import subprocess
        from local_assist import catalog_sync as cs_mod
        from local_assist._miniyaml import parse_yaml_with_flow_sequences
        from local_assist.catalog_sync import (
            compute_privatemode_catalog_drift,
            parse_privatemode_deployment_yaml,
            parse_privatemode_models_yaml,
        )

        fixture_dir = ROOT / "tests" / "fixtures" / "privatemode_v1_64_0"
        models_yaml_text = (fixture_dir / "models.yaml").read_text(encoding="utf-8")
        dep_yaml_text = (fixture_dir / "deployment.yaml").read_text(encoding="utf-8")
        disk_map_v164 = parse_privatemode_models_yaml(models_yaml_text)
        dep_v164 = parse_privatemode_deployment_yaml(dep_yaml_text)

        # --- R2-F1: Healthy NVIDIA glm-5.3-flash primary + detached orphan on alternate Z.ai root ---
        glm_wl = dep_v164["workloads"]["glm-5.3-flash"]
        nvidia_root = glm_wl["root_hash"]
        nvidia_disk = disk_map_v164[nvidia_root]
        self.assertEqual(nvidia_disk["disk_key"], "nvidia-glm-5-3-flash-nvfp4")
        zai_disks = [d for d in disk_map_v164.values() if d["disk_key"] == "zai-org-glm-5-3-flash"]
        self.assertEqual(len(zai_disks), 1)
        zai_root = zai_disks[0]["root_hash"]
        self.assertNotEqual(zai_root, nvidia_root)

        glm_cat = {
            "models": [
                {
                    "id": "privatemode-glm-5-3-flash",
                    "repo": "glm-5.3-flash",
                    "runtime": "proxy",
                    "host": "127.0.0.1",
                    "port": 8082,
                    "endpoint_url": "http://127.0.0.1:8082/v1",
                    "status": "active",
                    "data_control_rung": "enclave_runtime_attested",
                    "usage_policy": "enclave_no_inspection",
                    "enclave_repo": "edgelesssys/privatemode-public",
                    "enclave_tag": "v1.64.0",
                    "serve_command": "./bin/privatemode-proxy --listen-address {host} --port {port} --api-key-fallback=never --manifest-path config/privatemode-manifest-v1.64.0.json --workspace .home/privatemode-proxy --nvidia-ocsp-allow-unknown=false --nvidia-ocsp-revoked-grace-period=0",
                    "promptfoo_provider": {"apiKeyKeychainService": "free-inference.privatemode"},
                    "routing": {"private_local": "blocked", "private_attested": "blocked"},
                    "remote_trust": {
                        "tier": "enclave_runtime_attested",
                        "attestation_method": "privatemode-proxy-contrast",
                        "usage_policy": "enclave_no_inspection",
                        "provider_manifest_weights_hash": nvidia_disk["weights_hash"],
                        "provider_manifest_weights_source": nvidia_disk["weights_source"],
                    },
                    "verified_date": "2026-11-21",
                }
            ]
        }
        dep_with_zai_orphan = copy.deepcopy(dep_v164)
        dep_with_zai_orphan["partial_deployments"].append(
            {
                "kind": "orphan_disk_mounter",
                "deployment_name": "workload-glm-zai-orphan",
                "container_name": None,
                "served_model_id": None,
                "disk_name": "glm-5.3-flash",
                "k8s_slug": "glm-5-3-flash",
                "root_hash": zai_root,
                "reason": "orphan disk-mounter mounting alternate Z.ai glm-5.3-flash root",
            }
        )
        rep_r2f1 = compute_privatemode_catalog_drift(
            glm_cat,
            release_tag="v1.64.0",
            models_disk_map=disk_map_v164,
            deployment_data=dep_with_zai_orphan,
            observed_date="2026-11-21",
            discover_new_coding_models=False,
        )
        self.assertEqual([d for d in rep_r2f1.disagreements if d.registered], [])
        self.assertEqual(len(rep_r2f1.disagreements), 1)
        self.assertFalse(rep_r2f1.disagreements[0].registered)
        self.assertIn("coherent primary workload exists", rep_r2f1.disagreements[0].reason)
        with tempfile.TemporaryDirectory() as td:
            mpath = Path(td) / "models.yaml"
            mpath.write_text(dump_models_yaml(glm_cat), encoding="utf-8")
            before_glm = mpath.read_bytes()
            summary_r2f1: dict[str, Any] = {}
            after_glm = apply_catalog_healing(
                mpath,
                rep_r2f1,
                quarantine_disagreements=True,
                append_new_models=False,
                safety_only=True,
                apply_summary_out=summary_r2f1,
            )
            self.assertEqual(after_glm["models"][0]["status"], "active")
            self.assertFalse(summary_r2f1["wrote_file"])
            self.assertEqual(mpath.read_bytes(), before_glm)
            self.assertEqual(len(summary_r2f1["outstanding_disagreements"]), 1)

        # Normal Step B registered-workload checks STILL run alongside the unscoped orphan (e.g. primary weight drift)
        glm_cat_stale_hash = copy.deepcopy(glm_cat)
        glm_cat_stale_hash["models"][0]["remote_trust"]["provider_manifest_weights_hash"] = "dmverity:sha256:" + ("f" * 64)
        rep_r2f1_drift = compute_privatemode_catalog_drift(
            glm_cat_stale_hash,
            release_tag="v1.64.0",
            models_disk_map=disk_map_v164,
            deployment_data=dep_with_zai_orphan,
            observed_date="2026-11-21",
            discover_new_coding_models=False,
        )
        self.assertEqual([u.model_id for u in rep_r2f1_drift.updated_models], ["privatemode-glm-5-3-flash"])
        self.assertTrue(rep_r2f1_drift.updated_models[0].weights_changed)

        # --- R2-F2: Proof-file edit during the LAST git rev-parse subprocess is caught before os.replace ---
        if shutil.which("git"):
            with tempfile.TemporaryDirectory() as td:
                repo = Path(td) / "pm_r2f2_repo"
                (repo / "config").mkdir(parents=True)
                (repo / "scripts").mkdir(parents=True)
                subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
                subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test User"], check=True)
                subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)

                manifest_bytes = json.dumps({"ReferenceValues": {"a": 1}, "Policies": {"b": 2}}, indent=2).encode("utf-8")
                manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
                commit_sha = "d" * 40
                (repo / "config" / "privatemode-manifest-v1.64.0.json").write_bytes(manifest_bytes)
                builder_path = repo / "scripts" / "build-privatemode-proxy"
                builder_good = (
                    "from pathlib import Path\n"
                    "ROOT = Path(__file__).resolve().parents[1]\n"
                    'PRIVATEMODE_VERSION = "1.64.0"\n'
                    f'PRIVATEMODE_SOURCE_COMMIT = "{commit_sha}"\n'
                    'COMMITTED_MANIFEST_PATH = ROOT / "config" / "privatemode-manifest-v1.64.0.json"\n'
                    f'EXPECTED_MANIFEST_SHA256 = "{manifest_sha}"\n'
                )
                builder_path.write_text(builder_good, encoding="utf-8")
                cat_r2f2 = copy.deepcopy(glm_cat)
                cat_r2f2["models"][0]["enclave_tag"] = "v1.63.0"
                cat_r2f2["models"][0]["serve_command"] = cat_r2f2["models"][0]["serve_command"].replace(
                    "v1.64.0", "v1.63.0"
                )
                models_path = repo / "models.yaml"
                models_path.write_text(dump_models_yaml(cat_r2f2), encoding="utf-8")
                subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
                subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "init"], check=True)

                rep_r2f2 = compute_privatemode_catalog_drift(
                    cat_r2f2,
                    release_tag="v1.64.0",
                    models_disk_map=disk_map_v164,
                    deployment_data=dep_v164,
                    observed_date="2026-11-21",
                    provenance={"tag": "v1.64.0", "commit_sha": commit_sha},
                    discover_new_coding_models=False,
                )
                before_r2f2 = models_path.read_bytes()
                orig_subproc_run = cs_mod.subprocess.run
                rev_parse_calls = [0]

                def _dirty_builder_during_final_rev_parse(cmd: list[str], *a: Any, **kw: Any) -> Any:
                    res = orig_subproc_run(cmd, *a, **kw)
                    if len(cmd) >= 4 and cmd[3] == "rev-parse":
                        rev_parse_calls[0] += 1
                        # Call 1: initial proof; Call 2: reverify pre-status; Call 3: reverify final post-status
                        if rev_parse_calls[0] == 3:
                            builder_path.write_text(builder_good + "# dirty edit during final git rev-parse\n", encoding="utf-8")
                    return res

                with patch.object(cs_mod.subprocess, "run", side_effect=_dirty_builder_during_final_rev_parse):
                    with self.assertRaises(CatalogSyncError) as ctx_last_git:
                        apply_catalog_healing(models_path, rep_r2f2, append_new_models=False)
                self.assertEqual(rev_parse_calls[0], 3)
                self.assertIn("changed concurrently before catalog replacement", str(ctx_last_git.exception))
                self.assertEqual(models_path.read_bytes(), before_r2f2)

        # --- R2-F3: Strict block YAML preserves trailing U+00A0 (matching PyYAML 6.0.3) ---
        nbsp_models_yaml = models_yaml_text.replace("  name: model-disks\n", "  name: model-disks\u00a0\n", 1)
        self.assertNotEqual(nbsp_models_yaml, models_yaml_text)
        parsed_nbsp = parse_yaml_with_flow_sequences(
            nbsp_models_yaml, reject_duplicate_keys=True, strict_plain_scalars=True
        )
        self.assertEqual(parsed_nbsp["metadata"]["name"], "model-disks\u00a0")
        try:
            import yaml as _pyyaml  # type: ignore
        except ImportError:
            _pyyaml = None
        if _pyyaml is not None:
            self.assertEqual(parsed_nbsp, _pyyaml.safe_load(nbsp_models_yaml))
        with self.assertRaises(CatalogSyncError) as ctx_nbsp:
            parse_privatemode_models_yaml(nbsp_models_yaml)
        self.assertIn("metadata.name='model-disks'", str(ctx_nbsp.exception))
        # Strict anchor splitting must NOT consume U+00A0 in mapping, sequence, or flow-start anchors
        nbsp_anchor_models = models_yaml_text.replace("  name: model-disks\n", "  name: &a\u00a0model-disks\n", 1)
        self.assertNotEqual(nbsp_anchor_models, models_yaml_text)
        with self.assertRaises(CatalogSyncError):
            parse_privatemode_models_yaml(nbsp_anchor_models)
        if _pyyaml is not None:
            with self.assertRaises(_pyyaml.YAMLError):
                _pyyaml.safe_load(nbsp_anchor_models)
        for bad_anchor_yaml in (
            "items:\n  - &a\u00a0foo\n",
            "items: &a\u00a0[1, 2]\n",
        ):
            with self.assertRaises(ValueError, msg=bad_anchor_yaml):
                parse_yaml_with_flow_sequences(bad_anchor_yaml, strict_plain_scalars=True)
            if _pyyaml is not None:
                with self.assertRaises(_pyyaml.YAMLError, msg=bad_anchor_yaml):
                    _pyyaml.safe_load(bad_anchor_yaml)
        # Strict alias lookup: valid adjacent *a succeeds with PyYAML parity; spaced '* a' rejected on both runners
        adjacent_alias_models = models_yaml_text.replace(
            "  name: model-disks\n",
            "  note: &a model-disks\n  name: *a\n",
            1,
        )
        spaced_alias_models = models_yaml_text.replace(
            "  name: model-disks\n",
            "  note: &a model-disks\n  name: * a\n",
            1,
        )
        self.assertEqual(parse_privatemode_models_yaml(adjacent_alias_models), disk_map_v164)
        with self.assertRaises(CatalogSyncError):
            parse_privatemode_models_yaml(spaced_alias_models)
        if _pyyaml is not None:
            with self.assertRaises(_pyyaml.YAMLError):
                _pyyaml.safe_load(spaced_alias_models)
        # Legacy non-strict path remains intact
        self.assertEqual(
            parse_yaml_with_flow_sequences("name: legacy\u00a0\n", strict_plain_scalars=False),
            {"name": "legacy"},
        )


if __name__ == "__main__":
    unittest.main()
