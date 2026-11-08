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


if __name__ == "__main__":
    unittest.main()
