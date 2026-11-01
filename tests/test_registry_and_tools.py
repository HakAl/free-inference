from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

from local_assist._miniyaml import safe_load
from local_assist.client import base_url as client_base_url, check_private_coding_admission
from local_assist.errors import LocalAssistError
from local_assist.registry import (
    RegistryError,
    build_base_url,
    build_promptfoo_provider_entry,
    canonical_endpoint_key,
    legacy_pid_file,
    list_pid_records,
    load_model,
    pid_file_for_model,
    read_pid_record_for_model,
    resolve_endpoint,
    validate_custom_command_localhost,
)


ROOT = Path(__file__).resolve().parents[1]
TOOLS_SUITE = ROOT / "evals" / "suites" / "tools.yaml"


def _load_script_module(name: str, rel_path: str):
    path = ROOT / rel_path
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def run_js_assertion(assertion_code: str, output_value: object) -> bool:
    script = textwrap.dedent(
        f"""
        const output = {json.dumps(output_value)};
        const fn = new Function("output", {json.dumps(assertion_code)});
        const result = Boolean(fn(output));
        process.stdout.write(JSON.stringify(result));
        """
    )
    proc = subprocess.run(
        ["node", "-e", script],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return bool(json.loads(proc.stdout))


class RegistryAndToolsTests(unittest.TestCase):
    def test_starter_model_loads_and_resolves_endpoint(self) -> None:
        model = load_model("qwen3-1.7b-mlx-4bit")
        endpoint = resolve_endpoint(model)
        self.assertEqual(endpoint.model_id, "qwen3-1.7b-mlx-4bit")
        self.assertEqual(endpoint.served_model_id, "Qwen/Qwen3-1.7B-MLX-4bit")
        self.assertEqual(endpoint.api_base_url, "http://127.0.0.1:8080/v1")
        self.assertEqual(endpoint.host, "127.0.0.1")
        self.assertEqual(endpoint.port, 8080)
        self.assertEqual(endpoint.api_key, "none")
        self.assertEqual(endpoint.trust_tier, "local")
        self.assertTrue(endpoint.is_local_host)

    def test_resolve_endpoint_supports_custom_port_and_keychain_service(self) -> None:
        model = {
            "id": "custom-proxy-model",
            "repo": "org/model-v1",
            "runtime": "proxy",
            "serve_command": "tinfoil-proxy -h {host} -p {port}",
            "promptfoo_provider": {
                "id": "openai:chat:org/model-v1",
                "apiBaseUrl": "http://127.0.0.1:8081/v1/",
                "apiKeyKeychainService": "free-inference.custom-proxy",
            },
            "remote_trust": {
                "tier": "enclave_runtime_attested",
                "attestation_method": "sev-snp",
                "jurisdiction": "US",
            },
        }
        os.environ.pop("LOCAL_ASSIST_SESSION_TOKEN", None)
        with self.assertRaises(RegistryError):
            resolve_endpoint(model, require_api_key=True)

        non_strict = resolve_endpoint(model, require_api_key=False)
        self.assertEqual(non_strict.api_base_url, "http://127.0.0.1:8081/v1")
        self.assertEqual(non_strict.port, 8081)
        self.assertEqual(non_strict.trust_tier, "enclave_runtime_attested")
        self.assertEqual(non_strict.data_control_rung, 3)
        self.assertEqual(non_strict.attestation_method, "sev-snp")
        self.assertEqual(non_strict.usage_policy, "unknown")
        self.assertEqual(non_strict.api_key_keychain_service, "free-inference.custom-proxy")

        with tempfile.TemporaryDirectory() as tmp:
            tok_file = Path(tmp) / ".se-session-custom.token"
            tok_val = "se-session-" + ("a" * 64)
            tok_file.write_text(tok_val, encoding="utf-8")
            resolved = resolve_endpoint(
                model,
                require_api_key=True,
                pid_record={"session_token_file": str(tok_file)},
            )
            self.assertEqual(resolved.api_key, tok_val)
            provider_entry = build_promptfoo_provider_entry(model, max_tokens=500)
            self.assertEqual(provider_entry["config"]["apiKeyEnvar"], "LOCAL_ASSIST_SESSION_TOKEN")
            self.assertNotIn("apiKey", provider_entry["config"])

        # Legacy apiKeyEnvar and plaintext apiKey on non-local rungs are rejected
        for bad_provider in (
            {"apiBaseUrl": "http://127.0.0.1:8081/v1", "apiKeyEnvar": "TEST_LAB_PROXY_KEY"},
            {"apiBaseUrl": "http://127.0.0.1:8081/v1", "apiKey": "sk-plaintext"},
            {"apiBaseUrl": "http://127.0.0.1:8081/v1", "apiKey": "none"},
        ):
            bad_model = dict(model)
            bad_model["promptfoo_provider"] = bad_provider
            with self.assertRaises(RegistryError):
                resolve_endpoint(bad_model, require_api_key=False)

    def test_trust_validation_and_private_coding_admission(self) -> None:
        # 1. Missing remote_trust on remote or proxy is rejected
        with self.assertRaises(RegistryError):
            resolve_endpoint(
                {
                    "id": "missing-trust",
                    "repo": "org/m",
                    "runtime": "remote",
                    "promptfoo_provider": {"apiBaseUrl": "https://api.example.com/v1"},
                },
                require_api_key=False,
            )

        # 2. Invalid tier string or ambiguous data_control key is rejected
        with self.assertRaises(RegistryError):
            resolve_endpoint(
                {
                    "id": "bad-tier",
                    "repo": "org/m",
                    "runtime": "remote",
                    "promptfoo_provider": {"apiBaseUrl": "https://api.example.com/v1"},
                    "remote_trust": {"tier": "bogus_tier"},
                },
                require_api_key=False,
            )
        with self.assertRaises(RegistryError):
            resolve_endpoint(
                {
                    "id": "ambiguous-key",
                    "repo": "org/m",
                    "runtime": "proxy",
                    "promptfoo_provider": {"apiBaseUrl": "http://127.0.0.1:8081/v1"},
                    "remote_trust": {
                        "tier": "standard_api",
                        "data_control": "enclave_runtime_attested",
                    },
                },
                require_api_key=False,
            )

        # 3. Enclave tiers without attestation_method or non-localhost or runtime=remote are rejected
        with self.assertRaises(RegistryError):
            resolve_endpoint(
                {
                    "id": "tee-no-method",
                    "repo": "org/m",
                    "runtime": "proxy",
                    "promptfoo_provider": {"apiBaseUrl": "http://127.0.0.1:8081/v1"},
                    "remote_trust": {"tier": "enclave_runtime_attested", "attestation_method": None},
                },
                require_api_key=False,
            )
        with self.assertRaises(RegistryError):
            resolve_endpoint(
                {
                    "id": "tee-remote-direct",
                    "repo": "org/m",
                    "runtime": "remote",
                    "promptfoo_provider": {"apiBaseUrl": "https://tee.example.com/v1"},
                    "remote_trust": {"tier": "enclave_runtime_attested", "attestation_method": "sev-snp"},
                },
                require_api_key=False,
            )
        # 3b. enclave_weights_attested requires 64-hex weights_hash, weights_source (<org>/<repo>@<40-hex>),
        # weights_verified_by, weights_verified_date (YYYY-MM-DD), and weights_verification_artifact
        # (committed relative path, not under gitignored runs/)
        valid_hash = "dmverity:sha256:" + ("a" * 64)
        valid_source = "zai-org/GLM-5@" + ("b" * 40)
        valid_artifact = "docs/attestations/glm5-tinfoil.json"
        for bad_trust in (
            {"tier": "enclave_weights_attested", "attestation_method": "tinfoil-proxy"},
            {
                "tier": "enclave_weights_attested",
                "attestation_method": "tinfoil-proxy",
                "weights_hash": "TODO",
                "weights_source": valid_source,
                "weights_verified_by": "modelwrap --verify",
                "weights_verified_date": "2026-10-29",
                "weights_verification_artifact": valid_artifact,
            },
            {
                "tier": "enclave_weights_attested",
                "attestation_method": "tinfoil-proxy",
                "weights_hash": valid_hash,
                "weights_source": "zai-org/GLM-5@main",
                "weights_verified_by": "modelwrap --verify",
                "weights_verified_date": "2026-10-29",
                "weights_verification_artifact": valid_artifact,
            },
            {
                "tier": "enclave_weights_attested",
                "attestation_method": "tinfoil-proxy",
                "weights_hash": valid_hash,
                "weights_source": valid_source,
                "weights_verified_by": "",
                "weights_verified_date": "2026-10-29",
                "weights_verification_artifact": valid_artifact,
            },
            {
                "tier": "enclave_weights_attested",
                "attestation_method": "tinfoil-proxy",
                "weights_hash": valid_hash,
                "weights_source": valid_source,
                "weights_verified_by": "modelwrap --verify",
                "weights_verified_date": "not-a-date",
                "weights_verification_artifact": valid_artifact,
            },
            {
                "tier": "enclave_weights_attested",
                "attestation_method": "tinfoil-proxy",
                "weights_hash": valid_hash,
                "weights_source": valid_source,
                "weights_verified_by": "modelwrap --verify",
                "weights_verified_date": "2026-13-45",
                "weights_verification_artifact": valid_artifact,
            },
            {
                "tier": "enclave_weights_attested",
                "attestation_method": "tinfoil-proxy",
                "weights_hash": valid_hash,
                "weights_source": valid_source,
                "weights_verified_by": "modelwrap --verify",
                "weights_verified_date": "2026-10-29",
            },
            {
                "tier": "enclave_weights_attested",
                "attestation_method": "tinfoil-proxy",
                "weights_hash": valid_hash,
                "weights_source": valid_source,
                "weights_verified_by": "modelwrap --verify",
                "weights_verified_date": "2026-10-29",
                "weights_verification_artifact": "/opt/outside-repo.json",
            },
            {
                "tier": "enclave_weights_attested",
                "attestation_method": "tinfoil-proxy",
                "weights_hash": valid_hash,
                "weights_source": valid_source,
                "weights_verified_by": "modelwrap --verify",
                "weights_verified_date": "2026-10-29",
                "weights_verification_artifact": "../outside-repo.json",
            },
            {
                "tier": "enclave_weights_attested",
                "attestation_method": "tinfoil-proxy",
                "weights_hash": valid_hash,
                "weights_source": valid_source,
                "weights_verified_by": "modelwrap --verify",
                "weights_verified_date": "2026-10-29",
                "weights_verification_artifact": "runs/2026-10-29-ephemeral/verify.json",
            },
            {
                "tier": "enclave_weights_attested",
                "attestation_method": "tinfoil-proxy",
                "weights_hash": valid_hash,
                "weights_source": valid_source,
                "weights_verified_by": "modelwrap --verify",
                "weights_verified_date": "2026-10-29",
                "weights_verification_artifact": "lab/runs/2026-10-29-ephemeral/verify.json",
            },
            {
                "tier": "enclave_weights_attested",
                "attestation_method": "tinfoil-proxy",
                "weights_hash": valid_hash,
                "weights_source": valid_source,
                "weights_verified_by": "modelwrap --verify",
                "weights_verified_date": "2026-10-29",
                "weights_verification_artifact": "Runs/2026-10-29-ephemeral/verify.json",
            },
            {
                "tier": "enclave_weights_attested",
                "attestation_method": "tinfoil-proxy",
                "weights_hash": valid_hash,
                "weights_source": valid_source,
                "weights_verified_by": "modelwrap --verify",
                "weights_verified_date": "2026-10-29",
                "weights_verification_artifact": ".home/attestation.json",
            },
            {
                "tier": "enclave_weights_attested",
                "attestation_method": "tinfoil-proxy",
                "weights_hash": valid_hash,
                "weights_source": valid_source,
                "weights_verified_by": "modelwrap --verify",
                "weights_verified_date": "2026-10-29",
                "weights_verification_artifact": "docs/attestations/.hidden.json",
            },
            {
                "tier": "enclave_weights_attested",
                "attestation_method": "tinfoil-proxy",
                "weights_hash": valid_hash,
                "weights_source": valid_source,
                "weights_verified_by": "modelwrap --verify",
                "weights_verified_date": "2026-10-29",
                "weights_verification_artifact": "reviews/other-dir.json",
            },
            {
                "tier": "enclave_runtime_attested",
                "attestation_method": "tinfoil-proxy",
                "weights_hash": valid_hash,
            },
            {
                "tier": "enclave_runtime_attested",
                "attestation_method": "tinfoil-proxy",
                "weights_source": valid_source,
            },
        ):
            with self.assertRaises(RegistryError):
                resolve_endpoint(
                    {
                        "id": "tee-weights-invalid",
                        "repo": "org/m",
                        "runtime": "proxy",
                        "promptfoo_provider": {"apiBaseUrl": "http://127.0.0.1:8081/v1"},
                        "remote_trust": bad_trust,
                    },
                    require_api_key=False,
                )

        yaml_rung2_entry = safe_load(
            textwrap.dedent(
                f"""\
                id: tee-weights-pinned
                repo: org/m
                runtime: proxy
                serve_command: tinfoil-proxy -h {{host}} -p {{port}}
                promptfoo_provider:
                  apiBaseUrl: http://127.0.0.1:8081/v1
                  apiKeyKeychainService: free-inference.tinfoil
                remote_trust:
                  tier: enclave_weights_attested
                  attestation_method: tinfoil-proxy
                  weights_hash: {valid_hash}
                  weights_source: {valid_source}
                  weights_verified_by: modelwrap --verify
                  weights_verified_date: 2026-10-29
                  weights_verification_artifact: {valid_artifact}
                  usage_policy: enclave_no_inspection
                """
            )
        )
        weights_ep = resolve_endpoint(yaml_rung2_entry, require_api_key=False)
        self.assertEqual(weights_ep.trust_tier, "enclave_weights_attested")
        self.assertEqual(weights_ep.data_control_rung, 2)
        self.assertEqual(weights_ep.weights_hash, valid_hash)
        self.assertEqual(weights_ep.weights_source, valid_source)
        self.assertEqual(weights_ep.weights_verified_by, "modelwrap --verify")
        self.assertEqual(weights_ep.weights_verified_date, "2026-10-29")
        self.assertEqual(weights_ep.weights_verification_artifact, valid_artifact)
        self.assertEqual(weights_ep.usage_policy, "enclave_no_inspection")

        # 3c. usage_policy validation: reject unrestricted_local off Rung 1, enclave_no_inspection off Rung 2/3,
        # and provider_filtered on Rung 1
        with self.assertRaises(RegistryError):
            resolve_endpoint(
                {
                    "id": "zdr-claiming-local-policy",
                    "repo": "org/m",
                    "runtime": "proxy",
                    "promptfoo_provider": {
                        "apiBaseUrl": "http://127.0.0.1:8083/v1",
                        "apiKeyKeychainService": "free-inference.zdr",
                        "upstreamBaseUrl": "https://zdr.example.com/v1",
                    },
                    "remote_trust": {"tier": "zdr_contract", "usage_policy": "unrestricted_local"},
                },
                require_api_key=False,
            )
        with self.assertRaises(RegistryError):
            resolve_endpoint(
                {
                    "id": "zdr-claiming-enclave-policy",
                    "repo": "org/m",
                    "runtime": "proxy",
                    "promptfoo_provider": {
                        "apiBaseUrl": "http://127.0.0.1:8083/v1",
                        "apiKeyKeychainService": "free-inference.zdr",
                        "upstreamBaseUrl": "https://zdr.example.com/v1",
                    },
                    "remote_trust": {"tier": "zdr_contract", "usage_policy": "enclave_no_inspection"},
                },
                require_api_key=False,
            )
        with self.assertRaises(RegistryError):
            resolve_endpoint(
                {
                    "id": "local-claiming-provider-filtered",
                    "repo": "org/m",
                    "runtime": "mlx-lm",
                    "promptfoo_provider": {"apiBaseUrl": "http://127.0.0.1:8080/v1"},
                    "remote_trust": {"tier": "local", "usage_policy": "provider_filtered"},
                },
                require_api_key=False,
            )

        # 4. Private coding admission blocks standard_api (Rung 5) AND zdr_contract / zero_data_retention (Rung 4),
        # even when LOCAL_ASSIST_ALLOW_ATTESTED_TEE=1
        std_model = {
            "id": "std-proxy",
            "repo": "org/std",
            "runtime": "proxy",
            "promptfoo_provider": {
                "apiBaseUrl": "http://127.0.0.1:8082/v1",
                "apiKeyKeychainService": "free-inference.std",
                "upstreamBaseUrl": "https://std.example.com/v1",
            },
            "remote_trust": {"tier": "standard_api"},
        }
        std_ep = resolve_endpoint(std_model, require_api_key=False)
        self.assertEqual(std_ep.data_control_rung, 5)
        with self.assertRaises(LocalAssistError) as ctx:
            check_private_coding_admission(std_ep)
        self.assertEqual(ctx.exception.code, "trust_tier_blocked")

        for zdr_tier in ("zdr_contract", "zero_data_retention"):
            zdr_ep = resolve_endpoint(
                {
                    "id": f"zdr-{zdr_tier}",
                    "repo": "org/zdr",
                    "runtime": "proxy",
                    "promptfoo_provider": {
                        "apiBaseUrl": "http://127.0.0.1:8083/v1",
                        "apiKeyKeychainService": "free-inference.zdr",
                        "upstreamBaseUrl": "https://zdr.example.com/v1",
                    },
                    "remote_trust": {"tier": zdr_tier, "usage_policy": "provider_terms_apply"},
                },
                require_api_key=False,
            )
            self.assertEqual(zdr_ep.trust_tier, "zdr_contract")
            self.assertEqual(zdr_ep.data_control_rung, 4)
            saved_opt = os.environ.get("LOCAL_ASSIST_ALLOW_ATTESTED_TEE")
            os.environ["LOCAL_ASSIST_ALLOW_ATTESTED_TEE"] = "1"
            try:
                with self.assertRaises(LocalAssistError) as zdr_ctx:
                    check_private_coding_admission(zdr_ep)
                self.assertEqual(zdr_ctx.exception.code, "trust_tier_blocked")
            finally:
                if saved_opt is not None:
                    os.environ["LOCAL_ASSIST_ALLOW_ATTESTED_TEE"] = saved_opt
                else:
                    os.environ.pop("LOCAL_ASSIST_ALLOW_ATTESTED_TEE", None)

        # 5. Private coding admission requires LOCAL_ASSIST_ALLOW_ATTESTED_TEE=1 AND
        # (routing.private_attested == 'cleared' or LOCAL_ASSIST_ALLOW_UNCLEARED_TEE=1) for Rung 2 and Rung 3
        tee_model = {
            "id": "tee-proxy",
            "repo": "org/tee",
            "runtime": "proxy",
            "serve_command": "tinfoil-proxy -h {host} -p {port}",
            "capabilities": {"tool_calling": True},
            "promptfoo_provider": {
                "apiBaseUrl": "http://127.0.0.1:8081/v1",
                "apiKeyKeychainService": "free-inference.tinfoil",
            },
            "remote_trust": {"tier": "enclave_runtime_attested", "attestation_method": "sev-snp"},
        }
        tee_ep = resolve_endpoint(tee_model, require_api_key=False)
        saved_opt_in = os.environ.pop("LOCAL_ASSIST_ALLOW_ATTESTED_TEE", None)
        saved_uncleared = os.environ.pop("LOCAL_ASSIST_ALLOW_UNCLEARED_TEE", None)
        try:
            for ep_under_test in (tee_ep, weights_ep):
                with self.assertRaises(LocalAssistError) as no_opt_ctx:
                    check_private_coding_admission(ep_under_test)
                self.assertEqual(no_opt_ctx.exception.code, "trust_tier_blocked")
            os.environ["LOCAL_ASSIST_ALLOW_ATTESTED_TEE"] = "1"
            # Uncleared by default -> blocked with routing_gate_blocked unless cleared or LOCAL_ASSIST_ALLOW_UNCLEARED_TEE=1
            for ep_under_test in (tee_ep, weights_ep):
                with self.assertRaises(LocalAssistError) as uncleared_ctx:
                    check_private_coding_admission(ep_under_test)
                self.assertEqual(uncleared_ctx.exception.code, "routing_gate_blocked")
            os.environ["LOCAL_ASSIST_ALLOW_UNCLEARED_TEE"] = "1"
            for ep_under_test in (tee_ep, weights_ep):
                check_private_coding_admission(ep_under_test)
        finally:
            if saved_opt_in is not None:
                os.environ["LOCAL_ASSIST_ALLOW_ATTESTED_TEE"] = saved_opt_in
            else:
                os.environ.pop("LOCAL_ASSIST_ALLOW_ATTESTED_TEE", None)
            if saved_uncleared is not None:
                os.environ["LOCAL_ASSIST_ALLOW_UNCLEARED_TEE"] = saved_uncleared
            else:
                os.environ.pop("LOCAL_ASSIST_ALLOW_UNCLEARED_TEE", None)

        # 6. client.base_url blocks standard_api model looked up from registry
        with patch("local_assist.client._lookup_registry_entry", return_value=std_model):
            with self.assertRaises(LocalAssistError) as ctx2:
                client_base_url("org/std")
            self.assertEqual(ctx2.exception.code, "trust_tier_blocked")

        # 7. LOCAL_ASSIST_BASE_URL override cannot redirect an admitted local model
        # to a standard_api proxy, an unopted attested_tee proxy, or a mismatched destination.
        local_model = {
            "id": "local-qwen",
            "repo": "Qwen/Qwen3-1.7B-MLX-4bit",
            "runtime": "mlx-lm",
            "promptfoo_provider": {
                "id": "openai:chat:Qwen/Qwen3-1.7B-MLX-4bit",
                "apiBaseUrl": "http://127.0.0.1:8080/v1",
                "apiKey": "none",
            },
        }
        tee_model_cleared = {
            **tee_model,
            "routing": {"private_attested": "cleared"},
        }
        registry_fixture = [local_model, tee_model_cleared, std_model]
        saved_base_url = os.environ.pop("LOCAL_ASSIST_BASE_URL", None)
        saved_tee = os.environ.pop("LOCAL_ASSIST_ALLOW_ATTESTED_TEE", None)
        try:
            with patch("local_assist.client.load_models", return_value=registry_fixture):
                # Redirecting local model to standard_api proxy on :8082 -> blocked
                os.environ["LOCAL_ASSIST_BASE_URL"] = "http://127.0.0.1:8082/v1"
                with self.assertRaises(LocalAssistError) as std_override_ctx:
                    client_base_url("local-qwen")
                self.assertEqual(std_override_ctx.exception.code, "trust_tier_blocked")

                # Redirecting local model to unopted attested_tee proxy on :8081 -> blocked
                os.environ["LOCAL_ASSIST_BASE_URL"] = "http://127.0.0.1:8081/v1"
                with self.assertRaises(LocalAssistError) as tee_override_ctx:
                    client_base_url("local-qwen")
                self.assertEqual(tee_override_ctx.exception.code, "trust_tier_blocked")

                # Even with opt-in, redirecting local-qwen (:8080) to tee-proxy (:8081, which serves org/tee) is blocked
                os.environ["LOCAL_ASSIST_ALLOW_ATTESTED_TEE"] = "1"
                with self.assertRaises(LocalAssistError) as mismatch_ctx:
                    client_base_url("local-qwen")
                self.assertEqual(mismatch_ctx.exception.code, "trust_tier_blocked")

                # Matching override to the model's own admitted local endpoint succeeds
                os.environ["LOCAL_ASSIST_BASE_URL"] = "http://127.0.0.1:8080/v1"
                self.assertEqual(client_base_url("local-qwen"), "http://127.0.0.1:8080/v1")

                # 8. Portless http://127.0.0.1/v1 uses HTTP default port 80 (not 8080)
                # and must not inherit approval from :8080 or bypass a blocked :80 proxy.
                self.assertEqual(
                    canonical_endpoint_key("http://127.0.0.1/v1"),
                    canonical_endpoint_key("http://127.0.0.1:80/v1"),
                )
                self.assertNotEqual(
                    canonical_endpoint_key("http://127.0.0.1/v1"),
                    canonical_endpoint_key("http://127.0.0.1:8080/v1"),
                )
                os.environ["LOCAL_ASSIST_BASE_URL"] = "http://127.0.0.1/v1"
                with self.assertRaises(LocalAssistError) as portless_ctx:
                    client_base_url("local-qwen")
                self.assertEqual(portless_ctx.exception.code, "trust_tier_blocked")

                # 9. Unknown model with unregistered LOCAL_ASSIST_BASE_URL (:9099) is blocked
                os.environ["LOCAL_ASSIST_BASE_URL"] = "http://127.0.0.1:9099/v1"
                with self.assertRaises(LocalAssistError) as unknown_override_ctx:
                    client_base_url("org/not-registered")
                self.assertEqual(unknown_override_ctx.exception.code, "trust_tier_blocked")

            # 10. Registry load failure (RegistryError) blocks requests rather than falling back to empty list
            with patch(
                "local_assist.client.load_models",
                side_effect=RegistryError("models.yaml missing"),
            ):
                os.environ.pop("LOCAL_ASSIST_BASE_URL", None)
                with self.assertRaises(LocalAssistError) as reg_err_ctx:
                    client_base_url("org/not-registered")
                self.assertEqual(reg_err_ctx.exception.code, "trust_tier_blocked")
        finally:
            if saved_base_url is not None:
                os.environ["LOCAL_ASSIST_BASE_URL"] = saved_base_url
            else:
                os.environ.pop("LOCAL_ASSIST_BASE_URL", None)
            if saved_tee is not None:
                os.environ["LOCAL_ASSIST_ALLOW_ATTESTED_TEE"] = saved_tee
            else:
                os.environ.pop("LOCAL_ASSIST_ALLOW_ATTESTED_TEE", None)

    def test_pid_files_do_not_collide_between_slash_and_dash_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            p_slash = pid_file_for_model("org/model", runs)
            p_dash = pid_file_for_model("org-model", runs)
            self.assertNotEqual(p_slash, p_dash)

            rec_slash = {"model_id": "org/model", "port": 8080, "pid": 999991}
            rec_dash = {"model_id": "org-model", "port": 8081, "pid": 999992}
            p_slash.write_text(json.dumps(rec_slash))
            p_dash.write_text(json.dumps(rec_dash))
            legacy_pid_file(runs).write_text(json.dumps(rec_dash))

            self.assertEqual(read_pid_record_for_model("org/model", runs), rec_slash)
            self.assertEqual(read_pid_record_for_model("org-model", runs), rec_dash)
            self.assertEqual(len(list_pid_records(runs)), 3)

            # Even if an unhashed legacy file for org/model was overwritten by org-model,
            # stopping org/model must NOT kill org-model's PID.
            p_slash.unlink()
            unhashed = runs / ".serve-org-model.pid"
            unhashed.write_text(json.dumps(rec_dash))
            self.assertIsNone(read_pid_record_for_model("org/model", runs))

            stop_mod = _load_script_module("stop_model_script", "scripts/stop-model")
            stop_mod.RUNS = runs
            with patch("os.kill") as mock_kill:
                rc = stop_mod.main(["scripts/stop-model", "org/model"])
                self.assertEqual(rc, 0)
                mock_kill.assert_not_called()
                self.assertTrue(p_dash.exists())

                rc2 = stop_mod.main(["scripts/stop-model", "org-model"])
                self.assertEqual(rc2, 0)
                mock_kill.assert_called_once_with(999992, stop_mod.signal.SIGTERM)
                self.assertFalse(p_dash.exists())

    def test_serve_model_rejects_non_localhost_proxy_bind_and_preserves_ipv6(self) -> None:
        # IPv6 bracket preservation
        ipv6_model = {
            "id": "ipv6-local",
            "repo": "org/ipv6",
            "runtime": "mlx-lm",
            "promptfoo_provider": {"apiBaseUrl": "http://[::1]:8081/v1"},
        }
        ep = resolve_endpoint(ipv6_model, require_api_key=False)
        self.assertEqual(ep.host, "::1")
        self.assertEqual(ep.port, 8081)
        self.assertTrue(ep.is_local_host)
        self.assertEqual(build_base_url(ep.host, ep.port), "http://[::1]:8081/v1")

        # Custom proxy command validation
        self.assertIsNotNone(
            validate_custom_command_localhost(
                ["proxy-server", "--host", "0.0.0.0", "--port", "8081"],
                expected_port=8081,
            )
        )
        self.assertIsNotNone(
            validate_custom_command_localhost(
                ["proxy-server", "--bind=0.0.0.0:8081"],
                expected_port=8081,
            )
        )
        self.assertIsNotNone(
            validate_custom_command_localhost(
                ["proxy-server", "--port", "8081"],
                expected_port=8081,
            )
        )
        # Unrelated option whose argument happens to be 127.0.0.1 or localhost must NOT satisfy the bind check
        self.assertIsNotNone(
            validate_custom_command_localhost(
                ["python3", "-m", "http.server", "8080", "--directory", "127.0.0.1"],
                expected_port=8080,
            )
        )
        self.assertIsNotNone(
            validate_custom_command_localhost(
                ["proxy-server", "--port", "8081", "--config", "localhost"],
                expected_port=8081,
            )
        )
        serve_mod = _load_script_module("serve_model_script", "scripts/serve-model")
        cmd_bad, err_bad = serve_mod.build_command(
            {
                "id": "bad-http-server",
                "repo": "org/m",
                "runtime": "proxy",
                "serve_command": "python3 -m http.server {port} --directory 127.0.0.1",
            },
            runtime="proxy",
            host="127.0.0.1",
            port=8080,
            chat_template_args_override=None,
        )
        self.assertIsNone(cmd_bad)
        self.assertIsNotNone(err_bad)
        self.assertIsNotNone(
            validate_custom_command_localhost(
                ["proxy-server", "--host", "127.0.0.1", "--port", "9090"],
                expected_port=8081,
            )
        )
        self.assertIsNone(
            validate_custom_command_localhost(
                ["proxy-server", "--host", "127.0.0.1", "--port", "8081"],
                expected_port=8081,
            )
        )
        self.assertIsNone(
            validate_custom_command_localhost(
                ["proxy-server", "--bind", "127.0.0.1:8081"],
                expected_port=8081,
            )
        )

    def test_render_suite_binds_to_selected_model_and_rejects_ambiguous_multi_merge(self) -> None:
        render_mod = _load_script_module("render_suite_script", "scripts/render-suite")
        models = [
            {
                "id": "same-local",
                "repo": "org/model",
                "runtime": "mlx-lm",
                "promptfoo_provider": {
                    "id": "openai:chat:org/model",
                    "apiBaseUrl": "http://127.0.0.1:8080/v1",
                    "apiKey": "none",
                },
            },
            {
                "id": "same-remote",
                "repo": "org/model",
                "runtime": "proxy",
                "promptfoo_provider": {
                    "id": "openai:chat:org/model",
                    "apiBaseUrl": "http://127.0.0.1:8082/v1",
                    "apiKeyKeychainService": "free-inference.remote",
                    "upstreamBaseUrl": "https://remote.example/v1",
                },
                "remote_trust": {"tier": "standard_api"},
            },
        ]

        suite_local = {"providers": [], "tests": []}
        render_mod.merge_registry_providers(
            suite_local, "tools", model_id="same-local", models_list=models
        )
        self.assertEqual(len(suite_local["providers"]), 1)
        self.assertEqual(
            suite_local["providers"][0]["config"]["apiBaseUrl"],
            "http://127.0.0.1:8080/v1",
        )
        self.assertEqual(suite_local["providers"][0]["config"]["apiKey"], "none")
        self.assertNotIn("apiKeyEnvar", suite_local["providers"][0]["config"])

        suite_remote = {"providers": [], "tests": []}
        render_mod.merge_registry_providers(
            suite_remote, "tools", model_id="same-remote", models_list=models
        )
        self.assertEqual(len(suite_remote["providers"]), 1)
        self.assertEqual(
            suite_remote["providers"][0]["config"]["apiBaseUrl"],
            "http://127.0.0.1:8082/v1",
        )
        self.assertEqual(
            suite_remote["providers"][0]["config"]["apiKeyEnvar"],
            "LOCAL_ASSIST_SESSION_TOKEN",
        )

        # Unscoped merge across colliding provider IDs with different endpoints must fail loudly
        suite_unscoped = {"providers": [], "tests": []}
        with self.assertRaises(RegistryError):
            render_mod.merge_registry_providers(
                suite_unscoped, "tools", model_id=None, models_list=models
            )

        # Distinct model IDs that sanitize to the same slug (org/model vs org-model)
        # must produce distinct rendered filenames and support explicit --output paths.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            slash_vs_dash_models = [
                {
                    "id": "org/model",
                    "repo": "org/model",
                    "runtime": "mlx-lm",
                    "promptfoo_provider": {
                        "id": "openai:chat:org/model",
                        "apiBaseUrl": "http://127.0.0.1:8080/v1",
                        "apiKey": "none",
                    },
                },
                {
                    "id": "org-model",
                    "repo": "org/model",
                    "runtime": "proxy",
                    "promptfoo_provider": {
                        "id": "openai:chat:org/model",
                        "apiBaseUrl": "http://127.0.0.1:8082/v1",
                        "apiKeyKeychainService": "free-inference.remote",
                        "upstreamBaseUrl": "https://remote.example/v1",
                    },
                    "remote_trust": {"tier": "standard_api"},
                },
            ]
            with patch.object(render_mod, "load_model", side_effect=lambda mid: next(m for m in slash_vs_dash_models if m["id"] == mid)):
                p_slash = render_mod.render_suite("tools", model_id="org/model")
                p_dash = render_mod.render_suite("tools", model_id="org-model")
                try:
                    self.assertNotEqual(p_slash, p_dash)
                    slash_cfg = safe_load(p_slash.read_text())
                    dash_cfg = safe_load(p_dash.read_text())
                    self.assertEqual(
                        slash_cfg["providers"][0]["config"]["apiBaseUrl"],
                        "http://127.0.0.1:8080/v1",
                    )
                    self.assertEqual(
                        dash_cfg["providers"][0]["config"]["apiBaseUrl"],
                        "http://127.0.0.1:8082/v1",
                    )
                finally:
                    p_slash.unlink(missing_ok=True)
                    p_dash.unlink(missing_ok=True)

                explicit_out = tmp_path / "run-1" / "suite.yaml"
                p_explicit = render_mod.render_suite(
                    "tools", model_id="org/model", output_path=explicit_out
                )
                self.assertEqual(p_explicit, explicit_out)
                self.assertTrue(explicit_out.exists())

                # Concurrent eval run-directory allocation uses mktemp -d so two same-second
                # invocations for the same model and suite never share a run directory.
                eval_script = (ROOT / "scripts" / "eval").read_text()
                self.assertIn('mktemp -d "runs/${STAMP}-${SUITE}-${SAFE_MODEL}-${MODEL_HASH}-XXXXXX"', eval_script)
                self.assertNotIn("mkdir -p \"$OUT_DIR\"", eval_script)
                runs_dir = tmp_path / "runs"
                runs_dir.mkdir(parents=True, exist_ok=True)
                d1 = subprocess.check_output(
                    ["mktemp", "-d", str(runs_dir / "2026-10-29-190000-tools-model-12345678-XXXXXX")],
                    text=True,
                ).strip()
                d2 = subprocess.check_output(
                    ["mktemp", "-d", str(runs_dir / "2026-10-29-190000-tools-model-12345678-XXXXXX")],
                    text=True,
                ).strip()
                self.assertNotEqual(d1, d2)

        for suite in ("sanity", "v1", "tools"):
            proc = subprocess.run(
                ["scripts/render-suite", suite, "qwen3-1.7b-mlx-4bit"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=True,
            )
            out_path = Path(proc.stdout.strip())
            try:
                self.assertTrue(out_path.exists())
                rendered = safe_load(out_path.read_text())
                self.assertEqual(len(rendered["providers"]), 1)
                self.assertEqual(
                    rendered["providers"][0]["id"],
                    "openai:chat:Qwen/Qwen3-1.7B-MLX-4bit",
                )
                if suite == "v1":
                    needle_tests = [
                        t
                        for t in rendered["tests"]
                        if t.get("description") == "needle-middle-delta-restore-token"
                    ]
                    self.assertEqual(len(needle_tests), 1)
                    self.assertIn("DELTA-RESTORE-74B2", needle_tests[0]["vars"]["document"])
                if suite == "tools":
                    first_provider = rendered["providers"][0]
                    tool_names = [t["function"]["name"] for t in first_provider["config"]["tools"]]
                    self.assertEqual(tool_names, ["read_file", "search_repo", "run_tests"])
            finally:
                out_path.unlink(missing_ok=True)

    def test_tools_suite_assertions_pass_and_fail_appropriately(self) -> None:
        suite = safe_load(TOOLS_SUITE.read_text())
        by_desc = {test["description"]: test["assert"][0]["value"] for test in suite["tests"]}

        # 1. single-tool-read-file
        single_assert = by_desc["single-tool-read-file"]
        valid_single = [
            {
                "id": "call_1",
                "type": "function",
                "function": {"name": "read_file", "arguments": '{"path":"models.yaml"}'},
            }
        ]
        self.assertTrue(run_js_assertion(single_assert, valid_single))
        self.assertTrue(
            run_js_assertion(
                single_assert,
                {
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "read_file", "arguments": '{"path":"./models.yaml"}'},
                        }
                    ],
                },
            )
        )
        # Reject plain text or JSON-encoded string pretending to be tool_calls
        self.assertFalse(run_js_assertion(single_assert, "I will read models.yaml for you."))
        self.assertFalse(run_js_assertion(single_assert, json.dumps(valid_single)))
        self.assertFalse(
            run_js_assertion(single_assert, json.dumps({"tool_calls": valid_single}))
        )
        # Reject non-string (object-valued) function.arguments
        self.assertFalse(
            run_js_assertion(
                single_assert,
                [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "read_file", "arguments": {"path": "models.yaml"}},
                    }
                ],
            )
        )
        # Reject extra forbidden arguments or missing id/type
        self.assertFalse(
            run_js_assertion(
                single_assert,
                [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "read_file",
                            "arguments": '{"path":"models.yaml","extra":true}',
                        },
                    }
                ],
            )
        )
        self.assertFalse(
            run_js_assertion(
                single_assert,
                [
                    {
                        "function": {"name": "read_file", "arguments": '{"path":"models.yaml"}'},
                    }
                ],
            )
        )

        # 2. parallel-tool-calls-diff-check
        parallel_assert = by_desc["parallel-tool-calls-diff-check"]
        valid_parallel = [
            {
                "id": "call_1",
                "type": "function",
                "function": {"name": "read_file", "arguments": '{"path":"scripts/serve-model"}'},
            },
            {
                "id": "call_2",
                "type": "function",
                "function": {
                    "name": "read_file",
                    "arguments": '{"path":"scripts/verify-served-model"}',
                },
            },
        ]
        self.assertTrue(run_js_assertion(parallel_assert, valid_parallel))
        # Reject stringified JSON pretending to be parallel tool calls
        self.assertFalse(run_js_assertion(parallel_assert, json.dumps(valid_parallel)))
        # Reject non-string (object-valued) function.arguments in parallel calls
        self.assertFalse(
            run_js_assertion(
                parallel_assert,
                [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "read_file", "arguments": {"path": "scripts/serve-model"}},
                    },
                    {
                        "id": "call_2",
                        "type": "function",
                        "function": {
                            "name": "read_file",
                            "arguments": {"path": "scripts/verify-served-model"},
                        },
                    },
                ],
            )
        )
        # Reject duplicate tool call IDs
        self.assertFalse(
            run_js_assertion(
                parallel_assert,
                [
                    {
                        "id": "call_dup",
                        "type": "function",
                        "function": {"name": "read_file", "arguments": '{"path":"scripts/serve-model"}'},
                    },
                    {
                        "id": "call_dup",
                        "type": "function",
                        "function": {
                            "name": "read_file",
                            "arguments": '{"path":"scripts/verify-served-model"}',
                        },
                    },
                ],
            )
        )
        # Reject extra forbidden arguments in parallel calls
        self.assertFalse(
            run_js_assertion(
                parallel_assert,
                [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "read_file",
                            "arguments": '{"path":"scripts/serve-model","extra":1}',
                        },
                    },
                    {
                        "id": "call_2",
                        "type": "function",
                        "function": {
                            "name": "read_file",
                            "arguments": '{"path":"scripts/verify-served-model"}',
                        },
                    },
                ],
            )
        )

        # 3. tool-result-followup
        followup_assert = by_desc["tool-result-followup"]
        self.assertTrue(
            run_js_assertion(
                followup_assert,
                "The starter model in `models.yaml` has id `qwen3-1.7b-mlx-4bit` and license `apache-2.0`.",
            )
        )
        self.assertFalse(run_js_assertion(followup_assert, valid_single))

        # 4. no-tool-when-unnecessary
        no_tool_assert = by_desc["no-tool-when-unnecessary"]
        self.assertTrue(
            run_js_assertion(
                no_tool_assert,
                "Binary search requires a sorted array because it compares the target to the middle element and eliminates half of the remaining elements based on order.",
            )
        )
        self.assertFalse(
            run_js_assertion(
                no_tool_assert,
                [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "search_repo", "arguments": '{"query":"binary search"}'},
                    }
                ],
            )
        )

    def test_timing_script_text_and_tools_streaming_modes(self) -> None:
        import http.server
        import io
        import threading
        from contextlib import redirect_stdout

        timing_mod = _load_script_module("timing_script", ROOT / "scripts" / "timing")
        received_requests: list[dict] = []

        class MockSSEHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                received_requests.append(body)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                if "tools" in body:
                    chunks = [
                        {
                            "choices": [
                                {
                                    "delta": {
                                        "tool_calls": [
                                            {
                                                "index": 0,
                                                "id": "call_read_1",
                                                "type": "function",
                                                "function": {"name": "read_file", "arguments": '{"path":'},
                                            }
                                        ]
                                    }
                                }
                            ]
                        },
                        {
                            "choices": [
                                {
                                    "delta": {
                                        "tool_calls": [
                                            {
                                                "index": 0,
                                                "function": {"arguments": '"README.md"}'},
                                            }
                                        ]
                                    }
                                }
                            ]
                        },
                    ]
                else:
                    chunks = [
                        {"choices": [{"delta": {"content": "The ocean "}}]},
                        {"choices": [{"delta": {"content": "is vast.<|im_end|>"}}]},
                        {
                            "choices": [],
                            "usage": {
                                "prompt_tokens": 17,
                                "completion_tokens": 6,
                                "total_tokens": 23,
                            },
                        },
                    ]
                for c in chunks:
                    self.wfile.write(f"data: {json.dumps(c)}\n\n".encode("utf-8"))
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()

        server = http.server.HTTPServer(("127.0.0.1", 0), MockSSEHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            mock_model = {
                "id": "mock-local",
                "repo": "mlx-community/mock-local",
                "runtime": "mlx-lm",
                "promptfoo_provider": {
                    "apiBaseUrl": f"http://127.0.0.1:{port}/v1",
                    "config": {
                        "showThinking": False,
                        "extraBody": {"chat_template_args": {"enable_thinking": False}},
                        "passthrough": {"include_reasoning": False, "reasoning_effort": "low"},
                    },
                },
            }
            entry = build_promptfoo_provider_entry(mock_model)
            self.assertIs(entry["config"]["showThinking"], False)
            self.assertEqual(
                entry["config"]["passthrough"],
                {"include_reasoning": False, "reasoning_effort": "low"},
            )
            with (
                patch.object(timing_mod, "load_model", return_value=mock_model),
                patch.object(timing_mod, "read_pid_record_for_model", return_value=None),
            ):
                buf_text = io.StringIO()
                with redirect_stdout(buf_text):
                    rc_text = timing_mod.main(["scripts/timing", "mock-local"])
                self.assertEqual(rc_text, 0)
                text_out = json.loads(buf_text.getvalue())
                self.assertEqual(text_out["mode"], "text")
                self.assertEqual(text_out["stream_chunks"], 2)
                self.assertEqual(text_out["tool_call_chunks"], 0)
                self.assertEqual(text_out["normalized_output_preview"], "The ocean is vast.")
                self.assertEqual(
                    text_out["usage"],
                    {"prompt_tokens": 17, "completion_tokens": 6, "total_tokens": 23},
                )
                self.assertEqual(
                    text_out["reserved_token_budget"],
                    {
                        "estimated_prompt_tokens": 100,
                        "max_completion_tokens": 80,
                        "reserved_total_tokens": 180,
                        "effective_total_tokens": 23,
                        "used_fallback_reservation": False,
                    },
                )
                self.assertNotIn("tools", received_requests[0])
                self.assertEqual(
                    received_requests[0]["stream_options"], {"include_usage": True}
                )
                self.assertEqual(
                    received_requests[0]["chat_template_args"], {"enable_thinking": False}
                )
                self.assertIs(received_requests[0]["include_reasoning"], False)
                self.assertEqual(received_requests[0]["reasoning_effort"], "low")

                buf_tools = io.StringIO()
                with redirect_stdout(buf_tools):
                    rc_tools = timing_mod.main(
                        ["scripts/timing", "mock-local", "--tools", "Custom tool prompt"]
                    )
                self.assertEqual(rc_tools, 0)
                tools_out = json.loads(buf_tools.getvalue())
                self.assertEqual(tools_out["mode"], "tools")
                self.assertEqual(tools_out["prompt"], "Custom tool prompt")
                self.assertEqual(tools_out["stream_chunks"], 2)
                self.assertEqual(tools_out["tool_call_chunks"], 2)
                self.assertEqual(
                    tools_out["reserved_token_budget"],
                    {
                        "estimated_prompt_tokens": 400,
                        "max_completion_tokens": 120,
                        "reserved_total_tokens": 520,
                        "effective_total_tokens": 520,
                        "used_fallback_reservation": True,
                    },
                )
                self.assertEqual(
                    tools_out["tool_calls_emitted"],
                    [{"id": "call_read_1", "name": "read_file", "arguments": '{"path":"README.md"}'}],
                )
                self.assertIn("tools", received_requests[1])
                self.assertEqual(
                    received_requests[1]["stream_options"], {"include_usage": True}
                )
                self.assertEqual(received_requests[1]["tools"][0]["function"]["name"], "read_file")
        finally:
            server.shutdown()
            server.server_close()

    def test_opencode_smoke_event_and_socket_validators(self) -> None:
        smoke_mod = _load_script_module("opencode_smoke_script", ROOT / "scripts" / "opencode-smoke")
        self.assertTrue(smoke_mod.is_localhost_lsof_name("127.0.0.1:54321->127.0.0.1:8080 (ESTABLISHED)"))
        self.assertTrue(smoke_mod.is_localhost_lsof_name("localhost:51234 (LISTEN)"))
        self.assertTrue(smoke_mod.is_localhost_lsof_name("[::1]:51234->[::1]:8080 (ESTABLISHED)"))
        self.assertFalse(smoke_mod.is_localhost_lsof_name("192.168.1.10:54321->104.18.12.34:443 (ESTABLISHED)"))
        # F2: Reject wildcard listeners and wildcard endpoints
        self.assertFalse(smoke_mod.is_localhost_lsof_name("*:8080 (LISTEN)"))
        self.assertFalse(smoke_mod.is_localhost_lsof_name("0.0.0.0:8080 (LISTEN)"))
        self.assertFalse(smoke_mod.is_localhost_lsof_name("[::]:8080 (LISTEN)"))
        self.assertFalse(smoke_mod.is_localhost_lsof_name("*:*"))

        # E2: classify_lsof_socket_line separates localhost, unconnected_udp, and non_localhost
        self.assertEqual(
            smoke_mod.classify_lsof_socket_line(
                "opencode 123 user 10u IPv4 0x0 0t0 TCP 127.0.0.1:54321->127.0.0.1:8080 (ESTABLISHED)"
            ),
            "localhost",
        )
        self.assertEqual(
            smoke_mod.classify_lsof_socket_line(
                "opencode 123 user 11u IPv4 0x0 0t0 UDP *:*"
            ),
            "unconnected_udp",
        )
        self.assertEqual(
            smoke_mod.classify_lsof_socket_line(
                "opencode 123 user 12u IPv4 0x0 0t0 TCP *:8080 (LISTEN)"
            ),
            "non_localhost",
        )
        self.assertEqual(
            smoke_mod.classify_lsof_socket_line(
                "opencode 123 user 13u IPv4 0x0 0t0 TCP 192.168.1.10:54321->104.18.12.34:443 (ESTABLISHED)"
            ),
            "non_localhost",
        )

        # E3: _record_stderr_lines separates benign lsof warnings from observer errors
        warnings_list: list[str] = []
        errors_list: list[str] = []
        smoke_mod._record_stderr_lines(
            "lsof: WARNING: can't stat() smbfs file system\nlsof: status error on /dev/disk0",
            source="lsof-pid",
            observer_warnings=warnings_list,
            observer_errors=errors_list,
        )
        self.assertEqual(len(warnings_list), 1)
        self.assertEqual(len(errors_list), 1)

        # F1 / E1 / E2 / E3: evaluate_smoke_gate fail-closed checks
        good_events_summary = {
            "llm_step_count": 2,
            "read_tool_called": True,
            "only_read_tool_called": True,
            "read_target_only": True,
            "token_in_tool_output": True,
            "token_verified": True,
            "denied_or_error_count": 0,
        }
        good_gate = smoke_mod.evaluate_smoke_gate(
            returncode=0,
            opencode_host_dirs_unchanged=True,
            observer_available=True,
            observer_errors=[],
            run_poll_count=5,
            run_positive_socket_samples=2,
            run_parsed_socket_lines=3,
            non_localhost_lines=[],
            unconnected_udp_lines=[],
            forwarder_bound_localhost=True,
            server_request_count=3,
            blocked_chat_requests=0,
            max_chat_requests=3,
            parsed_events=good_events_summary,
        )
        self.assertTrue(good_gate["network_observation_ok"])
        self.assertTrue(good_gate["request_budget_ok"])
        self.assertTrue(good_gate["passed"])

        # Fail if observer_available is False, observer_errors non-empty, or 0 positive socket samples
        for bad_kwargs in (
            {"observer_available": False},
            {"observer_errors": ["lsof-pid-timeout"]},
            {"run_positive_socket_samples": 0},
            {"run_parsed_socket_lines": 0},
            {"non_localhost_lines": ["opencode 123 u 12u IPv4 0x0 0t0 TCP *:8080 (LISTEN)"]},
            {"unconnected_udp_lines": ["opencode 123 u 11u IPv4 0x0 0t0 UDP *:*"]},
            {"blocked_chat_requests": 1},
            {"server_request_count": 4},
            {"server_request_count": 0},
            {"opencode_host_dirs_unchanged": False},
        ):
            merged = {
                "returncode": 0,
                "opencode_host_dirs_unchanged": True,
                "observer_available": True,
                "observer_errors": [],
                "run_poll_count": 5,
                "run_positive_socket_samples": 2,
                "run_parsed_socket_lines": 3,
                "non_localhost_lines": [],
                "unconnected_udp_lines": [],
                "forwarder_bound_localhost": True,
                "server_request_count": 3,
                "blocked_chat_requests": 0,
                "max_chat_requests": 3,
                "parsed_events": good_events_summary,
            }
            merged.update(bad_kwargs)
            res = smoke_mod.evaluate_smoke_gate(**merged)
            self.assertFalse(res["passed"], f"Expected gate to fail for {bad_kwargs}")

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            good_events = "\n".join(
                [
                    json.dumps(
                        {
                            "type": "tool_use",
                            "part": {
                                "tool": "read",
                                "state": {
                                    "status": "completed",
                                    "input": {"filePath": str(ws / "target.txt")},
                                    "output": "1: OPENCODE-LOCAL-SMOKE-TOKEN-9F4A",
                                },
                            },
                        }
                    ),
                    json.dumps(
                        {
                            "type": "text",
                            "part": {"text": "The token is OPENCODE-LOCAL-SMOKE-TOKEN-9F4A."},
                        }
                    ),
                ]
            )
            parsed = smoke_mod.parse_events(good_events, ws)
            self.assertTrue(parsed["read_tool_called"])
            self.assertTrue(parsed["only_read_tool_called"])
            self.assertTrue(parsed["read_target_only"])
            self.assertTrue(parsed["token_in_tool_output"])
            self.assertTrue(parsed["token_verified"])
            self.assertEqual(parsed["denied_or_error_count"], 0)

            bad_events = "\n".join(
                [
                    good_events,
                    json.dumps(
                        {
                            "type": "tool_use",
                            "part": {
                                "tool": "bash",
                                "state": {
                                    "status": "completed",
                                    "input": {"command": "ls"},
                                    "output": "",
                                },
                            },
                        }
                    ),
                ]
            )
            bad_parsed = smoke_mod.parse_events(bad_events, ws)
            self.assertFalse(bad_parsed["only_read_tool_called"])

            traversal_events = json.dumps(
                {
                    "type": "tool_use",
                    "part": {
                        "tool": "read",
                        "state": {
                            "status": "completed",
                            "input": {"filePath": "../../outside/target.txt"},
                            "output": "1: OPENCODE-LOCAL-SMOKE-TOKEN-9F4A",
                        },
                    },
                }
            )
            traversal_parsed = smoke_mod.parse_events(traversal_events, ws)
            self.assertFalse(traversal_parsed["read_target_only"])

            # Verify render_opencode_config supports api_key_envar via {env:VAR} and api_base_url_override
            tmpl = (ROOT / "evals" / "opencode_smoke" / "opencode.json.tmpl").read_text()
            local_ep = resolve_endpoint(load_model("qwen3-1.7b-mlx-4bit"))
            local_cfg = json.loads(smoke_mod.render_opencode_config(local_ep, tmpl))
            self.assertEqual(local_cfg["provider"]["local_mlx"]["options"]["apiKey"], "none")
            self.assertEqual(local_cfg["agent"]["build"]["steps"], 3)

            override_cfg = json.loads(
                smoke_mod.render_opencode_config(
                    local_ep, tmpl, api_base_url_override="http://127.0.0.1:59999/v1"
                )
            )
            self.assertEqual(
                override_cfg["provider"]["local_mlx"]["options"]["baseURL"],
                "http://127.0.0.1:59999/v1",
            )

            tok_file = ws / ".se-session-tinfoil.token"
            tok_val = "se-session-" + ("b" * 64)
            tok_file.write_text(tok_val, encoding="utf-8")
            proxy_ep = resolve_endpoint(
                {
                    "id": "tinfoil-proxy-test",
                    "repo": "org/model",
                    "runtime": "proxy",
                    "serve_command": "tinfoil-proxy -h {host} -p {port}",
                    "promptfoo_provider": {
                        "apiBaseUrl": "http://127.0.0.1:8081/v1",
                        "apiKeyKeychainService": "free-inference.tinfoil",
                    },
                    "remote_trust": {
                        "tier": "enclave_runtime_attested",
                        "attestation_method": "tinfoil-proxy",
                    },
                },
                require_api_key=True,
                pid_record={"session_token_file": str(tok_file)},
            )
            proxy_cfg = json.loads(smoke_mod.render_opencode_config(proxy_ep, tmpl))
            self.assertEqual(
                proxy_cfg["provider"]["local_mlx"]["options"]["apiKey"],
                "{env:LOCAL_ASSIST_SESSION_TOKEN}",
            )

            # Verify build_isolated_env uses an allowlist and excludes unreferenced parent secrets
            os.environ["UNRELATED_SECRET_TOKEN"] = "should-not-leak"
            os.environ["LOCAL_ASSIST_SESSION_TOKEN"] = "ambient-token-should-not-leak"
            try:
                env_local = smoke_mod.build_isolated_env(
                    workspace_dir=ws / "workspace",
                    isolated_home=ws / ".home",
                    opencode_config_path=ws / "opencode.json",
                    endpoint=local_ep,
                )
                self.assertNotIn("UNRELATED_SECRET_TOKEN", env_local)
                self.assertNotIn("LOCAL_ASSIST_SESSION_TOKEN", env_local)
                self.assertEqual(env_local["PWD"], str(ws / "workspace"))

                env_proxy = smoke_mod.build_isolated_env(
                    workspace_dir=ws / "workspace",
                    isolated_home=ws / ".home",
                    opencode_config_path=ws / "opencode.json",
                    endpoint=proxy_ep,
                )
                self.assertNotIn("UNRELATED_SECRET_TOKEN", env_proxy)
                self.assertEqual(env_proxy["LOCAL_ASSIST_SESSION_TOKEN"], tok_val)
            finally:
                os.environ.pop("UNRELATED_SECRET_TOKEN", None)
                os.environ.pop("LOCAL_ASSIST_SESSION_TOKEN", None)

    def test_metering_forwarder_clamps_tokens_caps_requests_and_redacts_secrets(self) -> None:
        import http.server
        import threading
        import urllib.error
        import urllib.request

        smoke_mod = _load_script_module("opencode_smoke_script_fwd", ROOT / "scripts" / "opencode-smoke")
        upstream_bodies: list[dict] = []

        class UpstreamMockHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                if body.get("trigger_redirect"):
                    self.send_response(302)
                    self.send_header("Location", "http://127.0.0.1:9/v1/chat/completions")
                    self.end_headers()
                    return
                upstream_bodies.append(body)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                chunks = [
                    {"choices": [{"delta": {"content": "ok"}}]},
                    {
                        "choices": [],
                        "usage": {
                            "prompt_tokens": 100,
                            "completion_tokens": 10,
                            "total_tokens": 110,
                        },
                    },
                ]
                for c in chunks:
                    self.wfile.write(f"data: {json.dumps(c)}\n\n".encode("utf-8"))
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()

        upstream = http.server.HTTPServer(("127.0.0.1", 0), UpstreamMockHandler)
        upstream_port = upstream.server_address[1]
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        fwd = smoke_mod.MeteringForwarder(
            f"http://127.0.0.1:{upstream_port}/v1",
            max_chat_requests=3,
            max_tokens_per_request=256,
            max_request_bytes=1024,
        )
        fwd.start()
        try:
            # K2a: Malformed JSON chat body must be rejected locally with HTTP 400 before forwarding
            req_bad_json = urllib.request.Request(
                f"{fwd.base_url}/chat/completions",
                data=b"{not-valid-json",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as bad_json_ctx:
                urllib.request.urlopen(req_bad_json, timeout=10)
            self.assertEqual(bad_json_ctx.exception.code, 400)
            bad_json_ctx.exception.close()
            self.assertEqual(len(upstream_bodies), 0)

            # K4: Oversized chat body (> max_request_bytes) must be rejected locally with HTTP 413
            req_oversized = urllib.request.Request(
                f"{fwd.base_url}/chat/completions",
                data=json.dumps({"model": "test-model", "padding": "x" * 2000}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as oversized_ctx:
                urllib.request.urlopen(req_oversized, timeout=10)
            self.assertEqual(oversized_ctx.exception.code, 413)
            oversized_ctx.exception.close()
            self.assertEqual(len(upstream_bodies), 0)

            for i in range(3):
                payload = json.dumps(
                    {
                        "model": "test-model",
                        "stream": True,
                        "max_tokens": 4096,
                        "max_completion_tokens": 8192,
                        "maxOutputTokens": 2048,
                        "messages": [{"role": "user", "content": f"hello {i}"}],
                    }
                ).encode("utf-8")
                req = urllib.request.Request(
                    f"{fwd.base_url}/chat/completions",
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": "Bearer super-secret-token-value",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    self.assertEqual(resp.status, 200)
                    _ = resp.read()

            # 4th request must be blocked locally with HTTP 429 before hitting upstream
            req4 = urllib.request.Request(
                f"{fwd.base_url}/chat/completions",
                data=json.dumps({"model": "test-model", "messages": []}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer super-secret-token-value",
                },
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as err_ctx:
                urllib.request.urlopen(req4, timeout=10)
            self.assertEqual(err_ctx.exception.code, 429)
            err_ctx.exception.close()

            self.assertEqual(len(upstream_bodies), 3)
            for ub in upstream_bodies:
                self.assertEqual(ub["max_tokens"], 256)
                self.assertNotIn("max_completion_tokens", ub)
                self.assertNotIn("maxOutputTokens", ub)
                self.assertEqual(ub["stream_options"], {"include_usage": True})

            summary = fwd.summarize_tokens()
            self.assertEqual(summary["forwarded_chat_requests"], 3)
            self.assertEqual(summary["blocked_chat_requests"], 3)
            self.assertEqual(summary["max_request_bytes_enforced"], 1024)
            self.assertEqual(
                summary["observed_http_tokens"],
                {
                    "prompt": 300,
                    "completion": 30,
                    "total": 330,
                    "requests_missing_usage": 0,
                },
            )
            serialized_log = json.dumps(fwd.requests_log)
            self.assertNotIn("super-secret-token-value", serialized_log)
            self.assertNotIn("hello 0", serialized_log)
        finally:
            fwd.stop()

        # K2b & L1: Verify upstream HTTP 302 redirect is refused and cumulative max_total_request_bytes is enforced
        fwd_redir = smoke_mod.MeteringForwarder(
            f"http://127.0.0.1:{upstream_port}/v1",
            max_chat_requests=3,
            max_tokens_per_request=256,
            max_request_bytes=1024,
            max_total_request_bytes=120,
        )
        fwd_redir.start()
        try:
            req_redir = urllib.request.Request(
                f"{fwd_redir.base_url}/chat/completions",
                data=json.dumps({"model": "test-model", "trigger_redirect": True}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as redir_ctx:
                urllib.request.urlopen(req_redir, timeout=10)
            self.assertEqual(redir_ctx.exception.code, 302)
            redir_ctx.exception.close()

            # Second request fits per-request max_request_bytes (1024) but exceeds cumulative max_total_request_bytes (120)
            req_cum = urllib.request.Request(
                f"{fwd_redir.base_url}/chat/completions",
                data=json.dumps({"model": "test-model", "pad": "y" * 80}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as cum_ctx:
                urllib.request.urlopen(req_cum, timeout=10)
            self.assertEqual(cum_ctx.exception.code, 413)
            cum_ctx.exception.close()
        finally:
            fwd_redir.stop()
            upstream.shutdown()
            upstream.server_close()

    def test_promptfoo_max_retries_and_serve_env_offline_and_write_metrics_accounting(self) -> None:
        # E5: build_promptfoo_provider_entry disables automatic retries (maxRetries: 0)
        model = load_model("qwen3-1.7b-mlx-4bit")
        entry = build_promptfoo_provider_entry(model, max_tokens=500)
        self.assertEqual(entry["config"]["maxRetries"], 0)

        # E9 / Z4: serve-model build_serve_env forces HF_HUB_OFFLINE=1 for local models even if HF_HUB_OFFLINE=0
        serve_mod = _load_script_module("serve_model_env_script", "scripts/serve-model")
        local_ep = resolve_endpoint(model)
        forced_env = serve_mod.build_serve_env(
            local_ep, allow_hf_online=False, base_env={"HF_HUB_OFFLINE": "0", "PATH": "/usr/bin"}
        )
        self.assertEqual(forced_env["HF_HUB_OFFLINE"], "1")

        online_env = serve_mod.build_serve_env(
            local_ep, allow_hf_online=True, base_env={"HF_HUB_OFFLINE": "0", "PATH": "/usr/bin"}
        )
        self.assertEqual(online_env["HF_HUB_OFFLINE"], "0")

        # F3 / E4: write-metrics aggregates suite and timing probe requests and tokens
        write_metrics_mod = _load_script_module("write_metrics_script", "scripts/write-metrics")
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "output.json").write_text(
                json.dumps(
                    {
                        "results": {
                            "results": [
                                {"success": True, "score": 1.0, "latencyMs": 1200},
                                {"success": True, "score": 1.0, "latencyMs": 1400},
                            ],
                            "stats": {
                                "tokenUsage": {
                                    "prompt": 1485,
                                    "completion": 165,
                                    "total": 1650,
                                    "numRequests": 4,
                                }
                            },
                        }
                    }
                )
            )
            (run_dir / "timing.json").write_text(
                json.dumps(
                    {
                        "ttft_seconds": 0.25,
                        "tps": 40.0,
                        "total_seconds": 1.1,
                        "usage": {"prompt_tokens": 17, "completion_tokens": 60, "total_tokens": 77},
                        "reserved_token_budget": {"reserved_total_tokens": 180},
                    }
                )
            )
            (run_dir / "tools_timing.json").write_text(
                json.dumps(
                    {
                        "ttft_seconds": 0.30,
                        "tps": 35.0,
                        "total_seconds": 0.9,
                        "usage": {"prompt_tokens": 260, "completion_tokens": 20, "total_tokens": 280},
                        "reserved_token_budget": {"reserved_total_tokens": 520},
                    }
                )
            )
            rc = write_metrics_mod.main(
                [
                    "scripts/write-metrics",
                    "tools",
                    "qwen3-1.7b-mlx-4bit",
                    "openai:chat:Qwen/Qwen3-1.7B-MLX-4bit",
                    "evals/suites/tools.yaml",
                    "0",
                    str(run_dir),
                ]
            )
            self.assertEqual(rc, 0)
            metrics = json.loads((run_dir / "metrics.json").read_text())
            acct = metrics["token_accounting"]
            self.assertEqual(acct["suite_requests"], 4)
            self.assertEqual(acct["timing_probe_requests"], 2)
            self.assertEqual(acct["total_eval_requests"], 6)
            self.assertEqual(acct["total_eval_tokens"]["prompt"], 1485 + 17 + 260)
            self.assertEqual(acct["total_eval_tokens"]["completion"], 165 + 60 + 20)
            self.assertEqual(acct["total_eval_tokens"]["total"], 1650 + 77 + 280)

    def test_mcp_server_dual_framing_and_protocol_negotiation(self) -> None:
        import io
        from local_assist import server as mcp_server

        messages = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {}},
            },
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            },
            {
                "jsonrpc": "2.0",
                "method": "notifications/roots/list_changed",
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {},
            },
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "extract_fields",
                    "arguments": {
                        "text": "Server port is 8080",
                        "fields": {"port": {"type": "integer", "description": "Port"}},
                    },
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "ping",
            },
        ]

        # 1. Line-delimited framing (used by opencode 2.0.32 StdioClientTransport)
        line_input = b"".join((json.dumps(m) + "\n").encode("utf-8") for m in messages)
        in_buf = io.BytesIO(line_input)
        out_buf = io.BytesIO()
        with patch(
            "local_assist.server.extract_fields",
            return_value={"fields": {"port": 8080}, "model": "mock"},
        ):
            rc = mcp_server.serve_stdio(in_stream=in_buf, out_stream=out_buf)
        self.assertEqual(rc, 0)
        raw_out = out_buf.getvalue().decode("utf-8")
        self.assertNotIn("Content-Length:", raw_out)
        out_lines = [ln for ln in raw_out.splitlines() if ln.strip()]
        # 4 request ids (1, 2, 3, 4); the 2 notifications produce no output
        self.assertEqual(len(out_lines), 4)
        parsed_line_resps = [json.loads(ln) for ln in out_lines]
        self.assertEqual([r["id"] for r in parsed_line_resps], [1, 2, 3, 4])
        self.assertEqual(parsed_line_resps[0]["result"]["protocolVersion"], "2025-11-25")
        self.assertEqual(
            [t["name"] for t in parsed_line_resps[1]["result"]["tools"]],
            ["propose_eval_prompts", "extract_fields", "compress_context", "delegate_task"],
        )
        # Ensure structuredContent is present and serialized text in line mode has no literal newlines in frame
        self.assertFalse(parsed_line_resps[2]["result"]["isError"])
        self.assertEqual(parsed_line_resps[2]["result"]["structuredContent"]["fields"]["port"], 8080)
        self.assertEqual(parsed_line_resps[3]["result"], {})

        # 2. Content-Length framing (legacy LSP-style framing) with fallback protocolVersion
        cl_messages = [
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "initialize",
                "params": {"protocolVersion": "1999-01-01"},
            },
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            },
            {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "ping",
            },
        ]
        cl_chunks = []
        for m in cl_messages:
            b = json.dumps(m).encode("utf-8")
            cl_chunks.append(f"Content-Length: {len(b)}\r\n\r\n".encode("ascii") + b)
        cl_in = io.BytesIO(b"".join(cl_chunks))
        cl_out = io.BytesIO()
        rc2 = mcp_server.serve_stdio(in_stream=cl_in, out_stream=cl_out)
        self.assertEqual(rc2, 0)
        cl_out.seek(0)
        resp1, framing1 = mcp_server.read_message_with_framing(
            stream=cl_out, session_framing="content-length"
        )
        resp2, framing2 = mcp_server.read_message_with_framing(
            stream=cl_out, session_framing="content-length"
        )
        self.assertEqual(framing1, "content-length")
        self.assertEqual(framing2, "content-length")
        assert resp1 is not None and resp2 is not None
        self.assertEqual(resp1["id"], 10)
        self.assertEqual(resp1["result"]["protocolVersion"], "2024-11-05")
        self.assertEqual(resp2["id"], 11)
        self.assertEqual(resp2["result"], {})

        # 3. Malformed line, JSON-RPC batch array, and Content-Length: 0 emit -32700 parse error and continue
        bad_line_stream = io.BytesIO(
            b"not-valid-json\n"
            b'[{"jsonrpc":"2.0","id":1,"method":"ping"}]\n'
            b'{"jsonrpc":"2.0","id":99,"method":"ping"}\n'
        )
        bad_line_out = io.BytesIO()
        rc3 = mcp_server.serve_stdio(in_stream=bad_line_stream, out_stream=bad_line_out)
        self.assertEqual(rc3, 0)
        bad_line_resps = [
            json.loads(ln)
            for ln in bad_line_out.getvalue().decode("utf-8").splitlines()
            if ln.strip()
        ]
        self.assertEqual(len(bad_line_resps), 3)
        self.assertEqual(bad_line_resps[0]["error"]["code"], -32700)
        self.assertEqual(bad_line_resps[1]["error"]["code"], -32700)
        self.assertEqual(bad_line_resps[2]["id"], 99)
        self.assertEqual(bad_line_resps[2]["result"], {})

        ping_bytes = json.dumps({"jsonrpc": "2.0", "id": 42, "method": "ping"}).encode("utf-8")
        cl_zero_stream = io.BytesIO(
            b"Content-Length: 0\r\n\r\n"
            + f"Content-Length: {len(ping_bytes)}\r\n\r\n".encode("ascii")
            + ping_bytes
        )
        cl_zero_out = io.BytesIO()
        rc4 = mcp_server.serve_stdio(in_stream=cl_zero_stream, out_stream=cl_zero_out)
        self.assertEqual(rc4, 0)
        cl_zero_out.seek(0)
        err_resp, _ = mcp_server.read_message_with_framing(
            stream=cl_zero_out, session_framing="content-length"
        )
        ok_resp, _ = mcp_server.read_message_with_framing(
            stream=cl_zero_out, session_framing="content-length"
        )
        assert err_resp is not None and ok_resp is not None
        self.assertEqual(err_resp["error"]["code"], -32700)
        self.assertEqual(ok_resp["id"], 42)
        self.assertEqual(ok_resp["result"], {})

    def test_verify_served_model_exit_codes(self) -> None:
        import http.server
        import threading

        verify_mod = _load_script_module("verify_served_model_script", "scripts/verify-served-model")
        served_list = ["mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit"]

        class ModelsHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                pass

            def do_GET(self) -> None:
                body = json.dumps({"data": [{"id": m} for m in served_list]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = http.server.HTTPServer(("127.0.0.1", 0), ModelsHandler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            model_entry = {
                "id": "qwen3-30b-a3b-2507-mlx-4bit",
                "repo": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
                "runtime": "mlx-lm",
                "promptfoo_provider": {"apiBaseUrl": f"http://127.0.0.1:{port}/v1"},
            }
            with (
                patch.object(verify_mod, "load_model", return_value=model_entry),
                patch.object(verify_mod, "read_pid_record_for_model", return_value=None),
                patch.object(verify_mod, "verify_local_listener_matches", return_value=(True, None)),
            ):
                # 1. Exact match -> exit 0
                rc_ok = verify_mod.main(["scripts/verify-served-model", "qwen3-30b-a3b-2507-mlx-4bit"])
                self.assertEqual(rc_ok, 0)

                # 2. Different model served -> exit 3 (EXIT_MODEL_MISMATCH)
                served_list[:] = ["Qwen/Qwen3-1.7B-MLX-4bit"]
                rc_mismatch = verify_mod.main(
                    ["scripts/verify-served-model", "qwen3-30b-a3b-2507-mlx-4bit"]
                )
                self.assertEqual(rc_mismatch, verify_mod.EXIT_MODEL_MISMATCH)
                self.assertEqual(rc_mismatch, 3)

            # 2b. Even when /v1/models lists all cached HF models (mlx_lm.server behavior),
            # a conflicting PID record or listener --model flag on the port returns EXIT_MODEL_MISMATCH (3)
            served_list[:] = [
                "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
                "Qwen/Qwen3-1.7B-MLX-4bit",
            ]
            with (
                patch.object(verify_mod, "load_model", return_value=model_entry),
                patch.object(verify_mod, "read_pid_record_for_model", return_value=None),
                patch.object(
                    verify_mod,
                    "list_pid_records",
                    return_value=[
                        (
                            Path("runs/.serve-fake.pid"),
                            {
                                "model_id": "qwen3-1.7b-mlx-4bit",
                                "repo": "Qwen/Qwen3-1.7B-MLX-4bit",
                                "port": port,
                                "pid": os.getpid(),
                            },
                        )
                    ],
                ),
            ):
                rc_pid_conflict = verify_mod.main(
                    ["scripts/verify-served-model", "qwen3-30b-a3b-2507-mlx-4bit"]
                )
                self.assertEqual(rc_pid_conflict, verify_mod.EXIT_MODEL_MISMATCH)

            with (
                patch.object(verify_mod, "load_model", return_value=model_entry),
                patch.object(verify_mod, "read_pid_record_for_model", return_value=None),
                patch.object(verify_mod, "list_pid_records", return_value=[]),
                patch.object(
                    verify_mod,
                    "inspect_port_listeners",
                    return_value=[
                        (
                            99999,
                            "python -m mlx_lm.server --model Qwen/Qwen3-1.7B-MLX-4bit --host 127.0.0.1 --port 8080",
                        )
                    ],
                ),
            ):
                rc_cmd_conflict = verify_mod.main(
                    ["scripts/verify-served-model", "qwen3-30b-a3b-2507-mlx-4bit"]
                )
                self.assertEqual(rc_cmd_conflict, verify_mod.EXIT_MODEL_MISMATCH)

            # 2c. V2: Unidentifiable listener (empty list) or listener without --model fails closed with EXIT_MODEL_MISMATCH (3)
            with (
                patch.object(verify_mod, "load_model", return_value=model_entry),
                patch.object(verify_mod, "read_pid_record_for_model", return_value=None),
                patch.object(verify_mod, "list_pid_records", return_value=[]),
                patch.object(verify_mod, "inspect_port_listeners", return_value=[]),
            ):
                rc_no_listener = verify_mod.main(
                    ["scripts/verify-served-model", "qwen3-30b-a3b-2507-mlx-4bit"]
                )
                self.assertEqual(rc_no_listener, verify_mod.EXIT_MODEL_MISMATCH)

            with (
                patch.object(verify_mod, "load_model", return_value=model_entry),
                patch.object(verify_mod, "read_pid_record_for_model", return_value=None),
                patch.object(verify_mod, "list_pid_records", return_value=[]),
                patch.object(
                    verify_mod,
                    "inspect_port_listeners",
                    return_value=[(99999, "python -m mlx_lm server --host 127.0.0.1 --port 8080")],
                ),
            ):
                rc_no_model_flag = verify_mod.main(
                    ["scripts/verify-served-model", "qwen3-30b-a3b-2507-mlx-4bit"]
                )
                self.assertEqual(rc_no_model_flag, verify_mod.EXIT_MODEL_MISMATCH)
        finally:
            srv.shutdown()
            srv.server_close()

        # 3. Unreachable port -> exit 1 (EXIT_UNREACHABLE)
        unreachable_entry = {
            "id": "qwen3-30b-a3b-2507-mlx-4bit",
            "repo": "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
            "runtime": "mlx-lm",
            "promptfoo_provider": {"apiBaseUrl": f"http://127.0.0.1:{port}/v1"},
        }
        with (
            patch.object(verify_mod, "load_model", return_value=unreachable_entry),
            patch.object(verify_mod, "read_pid_record_for_model", return_value=None),
        ):
            rc_down = verify_mod.main(["scripts/verify-served-model", "qwen3-30b-a3b-2507-mlx-4bit"])
            self.assertEqual(rc_down, verify_mod.EXIT_UNREACHABLE)
            self.assertEqual(rc_down, 1)

    def test_opencode_local_admission_routing_config_and_env(self) -> None:
        import io

        oc_local = _load_script_module("opencode_local_script", "scripts/opencode-local")

        # 1. Primary cleared Rung 1 model passes validation
        cleared_model = load_model("qwen3-30b-a3b-2507-mlx-4bit")
        cleared_ep = resolve_endpoint(cleared_model)
        self.assertEqual(cleared_ep.routing_private_local, "cleared")
        self.assertTrue(cleared_ep.capabilities.get("tool_calling"))
        oc_local.validate_private_local_endpoint(cleared_ep)

        # 2. Uncleared Rung 1 models are blocked by default, allowed with warning when allow_uncleared_model=True
        for uncleared_id in (
            "qwen3-coder-30b-a3b-mlx-4bit",
            "gemma-4-26b-a4b-it-optiq-mlx-4bit",
            "qwen3-1.7b-mlx-4bit",
        ):
            ep = resolve_endpoint(load_model(uncleared_id))
            self.assertEqual(ep.routing_private_local, "blocked")
            with self.assertRaises(LocalAssistError) as ctx:
                oc_local.validate_private_local_endpoint(ep, allow_uncleared_model=False)
            self.assertEqual(ctx.exception.code, "routing_gate_blocked")

            warn_buf = io.StringIO()
            oc_local.validate_private_local_endpoint(
                ep, allow_uncleared_model=True, err_stream=warn_buf
            )
            self.assertIn("WARNING: Running private-local with uncleared model", warn_buf.getvalue())

        # 3. Enclave proxy (Rung 3) is rejected by opencode-local even with LOCAL_ASSIST_ALLOW_ATTESTED_TEE=1
        tee_ep = resolve_endpoint(
            {
                "id": "tee-proxy",
                "repo": "org/tee",
                "runtime": "proxy",
                "serve_command": "tinfoil-proxy -h {host} -p {port}",
                "capabilities": {"tool_calling": True},
                "promptfoo_provider": {
                    "apiBaseUrl": "http://127.0.0.1:8081/v1",
                    "apiKeyKeychainService": "free-inference.tinfoil",
                },
                "remote_trust": {
                    "tier": "enclave_runtime_attested",
                    "attestation_method": "tinfoil-proxy-sigstore",
                },
            },
            require_api_key=False,
        )
        with patch.dict(os.environ, {"LOCAL_ASSIST_ALLOW_ATTESTED_TEE": "1"}):
            with self.assertRaises(LocalAssistError) as tee_ctx:
                oc_local.validate_private_local_endpoint(tee_ep, allow_uncleared_model=True)
            self.assertEqual(tee_ctx.exception.code, "trust_tier_blocked")

        # 4. Local model missing tool_calling capability is rejected
        no_tools_ep = resolve_endpoint(
            {
                "id": "local-no-tools",
                "repo": "org/no-tools",
                "runtime": "mlx-lm",
                "capabilities": {"tool_calling": False},
                "routing": {"private_local": "cleared"},
                "promptfoo_provider": {"apiBaseUrl": "http://127.0.0.1:8080/v1"},
            }
        )
        with self.assertRaises(LocalAssistError) as cap_ctx:
            oc_local.validate_private_local_endpoint(no_tools_ep)
        self.assertEqual(cap_ctx.exception.code, "capability_missing")

        # 5. Rendered config has lsp: false, formatter: false, enabled_providers: ["private-local"],
        # model & small_model -> private-local/<id>, and mcp.local_assist with timeout 120000
        cfg_str = oc_local.render_private_local_config(cleared_ep)
        cfg = json.loads(cfg_str)
        self.assertIs(cfg["autoupdate"], False)
        self.assertEqual(cfg["share"], "disabled")
        self.assertIs(cfg["snapshot"], False)
        self.assertIs(cfg["lsp"], False)
        self.assertIs(cfg["formatter"], False)
        self.assertEqual(cfg["enabled_providers"], ["private-local"])
        self.assertEqual(cfg["model"], "private-local/qwen3-30b-a3b-2507-mlx-4bit")
        self.assertEqual(cfg["small_model"], "private-local/qwen3-30b-a3b-2507-mlx-4bit")
        self.assertEqual(cfg["mcp"]["servers"]["local_assist"]["type"], "local")
        self.assertIs(cfg["mcp"]["servers"]["local_assist"]["disabled"], False)
        self.assertIs(cfg["mcp"]["servers"]["local_assist"]["codemode"], False)
        self.assertEqual(cfg["mcp"]["servers"]["local_assist"]["timeout"], 180000)
        self.assertEqual(cfg["permission"]["*"], "ask")
        self.assertEqual(cfg["permission"]["edit"], "ask")
        self.assertEqual(cfg["permission"]["webfetch"], "deny")
        self.assertEqual(cfg["permission"]["websearch"], "deny")
        self.assertEqual(cfg["permission"]["codesearch"], "deny")
        self.assertEqual(cfg["permission"]["lsp"], "deny")
        self.assertEqual(cfg["permission"]["context7*"], "deny")
        self.assertIs(cfg["tools"]["context7*"], False)

        # 6. Isolated env sets OPENCODE_DISABLE_PROJECT_CONFIG=1, drops nonexistent vars, strips cloud keys
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = oc_local.build_private_local_env(
                tmp_path / "ws",
                tmp_path / "home",
                tmp_path / "home" / "opencode.json",
                cleared_ep,
                preserve_host_home=False,
                base_env={
                    "PATH": "/usr/bin:/bin",
                    "HOME": "/opt/mockhome",
                    "OPENAI_API_KEY": "sk-secret",
                    "ANTHROPIC_API_KEY": "sk-ant-secret",
                },
            )
            self.assertEqual(env["HOME"], str(tmp_path / "home"))
            self.assertEqual(env["OPENCODE_TEST_HOME"], str(tmp_path / "home"))
            self.assertEqual(env["OPENCODE_DISABLE_PROJECT_CONFIG"], "1")
            self.assertEqual(env["OPENCODE_DISABLE_AUTOUPDATE"], "1")
            self.assertEqual(env["OPENCODE_DISABLE_MODELS_FETCH"], "1")
            self.assertEqual(env["HF_HUB_OFFLINE"], "1")
            self.assertNotIn("OPENCODE_DISABLE_LSP_DOWNLOAD", env)
            self.assertNotIn("OPENCODE_DISABLE_DEFAULT_PLUGINS", env)
            self.assertNotIn("OPENAI_API_KEY", env)
            self.assertNotIn("ANTHROPIC_API_KEY", env)

            env_preserve = oc_local.build_private_local_env(
                tmp_path / "ws",
                tmp_path / "home",
                tmp_path / "home" / "opencode.json",
                cleared_ep,
                preserve_host_home=True,
                base_env={"PATH": "/usr/bin:/bin", "HOME": "/opt/mockhome"},
            )
            self.assertEqual(env_preserve["HOME"], "/opt/mockhome")
            self.assertEqual(env_preserve["XDG_CONFIG_HOME"], str(tmp_path / "home" / ".config"))
            self.assertEqual(env_preserve["XDG_DATA_HOME"], str(tmp_path / "home" / ".local" / "share"))

        # 7. ensure_model_served fails closed on exit code 3 (model mismatch) without calling serve-model
        calls: list[list[str]] = []

        def fake_run_mismatch(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(cmd)
            return subprocess.CompletedProcess(
                cmd, 3, stdout="", stderr="served model mismatch: got other-model"
            )

        ok_m, err_m = oc_local.ensure_model_served(
            cleared_ep, no_serve=False, run_cmd=fake_run_mismatch
        )
        self.assertFalse(ok_m)
        assert err_m is not None
        self.assertIn("another model is already serving", err_m)
        self.assertEqual(len(calls), 1)

    def test_lifecycle_ensure_local_model_served_and_auto_serve_gates(self) -> None:
        from local_assist.lifecycle import ensure_local_model_served

        # 1. Model mismatch (exit code 3) fails closed BEFORE any chat call or auto-serve attempt
        mismatch_calls: list[list[str]] = []

        def run_exit_3(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            mismatch_calls.append(cmd)
            return subprocess.CompletedProcess(
                cmd, 3, stdout="", stderr="listener on port 8080 was started with --model Qwen/Qwen3-1.7B-MLX-4bit"
            )

        with self.assertRaises(LocalAssistError) as ctx_mm:
            ensure_local_model_served(
                "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
                auto_serve=True,
                run_cmd=run_exit_3,
            )
        self.assertEqual(ctx_mm.exception.code, "model_mismatch")
        self.assertEqual(len(mismatch_calls), 1)

        # 2. Port down (exit code 1) with auto_serve=False fails closed with model_unavailable
        def run_exit_1(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="unreachable")

        with self.assertRaises(LocalAssistError) as ctx_down:
            ensure_local_model_served(
                "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
                auto_serve=False,
                run_cmd=run_exit_1,
            )
        self.assertEqual(ctx_down.exception.code, "model_unavailable")
        self.assertIn("LOCAL_ASSIST_AUTO_SERVE=1", ctx_down.exception.details.get("remediation", ""))

        # 3. Uncleared Rung 1 model with auto_serve=True fails closed with routing_gate_blocked
        with self.assertRaises(LocalAssistError) as ctx_uncleared:
            ensure_local_model_served(
                "Qwen/Qwen3-1.7B-MLX-4bit",
                auto_serve=True,
                run_cmd=run_exit_1,
            )
        self.assertEqual(ctx_uncleared.exception.code, "routing_gate_blocked")

        # 4. Cleared Rung 1 model with auto_serve=True runs verify -> serve-model --started-by local_assist -> verify --wait 120
        seq_calls: list[list[str]] = []

        def run_cold_start(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            seq_calls.append(cmd)
            if len(seq_calls) == 1:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not running yet")
            return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

        ensure_local_model_served(
            "mlx-community/Qwen3-30B-A3B-Instruct-2507-4bit",
            auto_serve=True,
            run_cmd=run_cold_start,
        )
        self.assertEqual(len(seq_calls), 3)
        self.assertIn("verify-served-model", seq_calls[0][1])
        self.assertIn("serve-model", seq_calls[1][1])
        self.assertIn("--started-by", seq_calls[1])
        self.assertIn("auto-serve", seq_calls[1])
        self.assertIn("verify-served-model", seq_calls[2][1])
        self.assertIn("--wait", seq_calls[2])

        # 5. V1: Two sequential serve-model calls for the same model when the first PID is alive
        # do NOT double-spawn a second Popen process even while health() is still False.
        serve_mod = _load_script_module("serve_model_dedupe_script", "scripts/serve-model")
        with tempfile.TemporaryDirectory() as tmp_runs:
            runs_dir = Path(tmp_runs)
            serve_mod.RUNS = runs_dir

            class FakePopen:
                def __init__(self, *args: object, **kwargs: object) -> None:
                    self.pid = os.getpid()

            popen_calls: list[ tuple[object, ...] ] = []

            def track_popen(*args: object, **kwargs: object) -> FakePopen:
                popen_calls.append(args)
                return FakePopen(*args, **kwargs)

            with (
                patch.object(serve_mod, "health", return_value=False),
                patch.object(serve_mod.subprocess, "Popen", side_effect=track_popen),
            ):
                rc1 = serve_mod.main(
                    ["scripts/serve-model", "qwen3-30b-a3b-2507-mlx-4bit", "--started-by", "auto-serve"]
                )
                rc2 = serve_mod.main(
                    ["scripts/serve-model", "qwen3-30b-a3b-2507-mlx-4bit", "--started-by", "auto-serve"]
                )
                self.assertEqual(rc1, 0)
                self.assertEqual(rc2, 0)
                self.assertEqual(len(popen_calls), 1)

    def test_routing_private_attested_validation_by_tier(self) -> None:
        # 1. Rung 3 and Rung 2 models default to routing_private_attested='blocked' and accept 'cleared' when tool_calling=true
        ep_ds = resolve_endpoint(load_model("tinfoil-deepseek-v4-1-flash"), require_api_key=False)
        self.assertEqual(ep_ds.routing_private_attested, "cleared")
        self.assertEqual(ep_ds.trust_tier, "enclave_runtime_attested")

        for model_id in (
            "tinfoil-gpt-oss-120b",
            "tinfoil-glm-5-3",
            "tinfoil-kimi-k3",
        ):
            ep = resolve_endpoint(load_model(model_id), require_api_key=False)
            self.assertEqual(ep.routing_private_attested, "blocked")
            self.assertEqual(ep.trust_tier, "enclave_runtime_attested")

        cleared_rung3 = resolve_endpoint(
            {
                "id": "tee-cleared",
                "repo": "org/tee",
                "runtime": "proxy",
                "serve_command": "tinfoil-proxy --bind {host} --port {port}",
                "capabilities": {"tool_calling": True},
                "routing": {"private_local": "blocked", "private_attested": "cleared"},
                "promptfoo_provider": {
                    "apiBaseUrl": "http://127.0.0.1:8081/v1",
                    "apiKeyKeychainService": "free-inference.tinfoil",
                },
                "remote_trust": {
                    "tier": "enclave_runtime_attested",
                    "attestation_method": "tinfoil-proxy-sigstore",
                    "usage_policy": "provider_terms_apply",
                },
            },
            require_api_key=False,
        )
        self.assertEqual(cleared_rung3.routing_private_attested, "cleared")

        # 2. Invalid routing.private_attested values or 'cleared' on Rung 1 / Rung 4 / Rung 5 or without tool_calling=true are rejected
        for bad_entry in (
            {
                "id": "local-claiming-attested",
                "repo": "org/local",
                "runtime": "mlx-lm",
                "capabilities": {"tool_calling": True},
                "routing": {"private_attested": "cleared"},
                "promptfoo_provider": {"apiBaseUrl": "http://127.0.0.1:8080/v1"},
            },
            {
                "id": "zdr-claiming-attested",
                "repo": "org/zdr",
                "runtime": "proxy",
                "capabilities": {"tool_calling": True},
                "routing": {"private_attested": "cleared"},
                "promptfoo_provider": {
                    "apiBaseUrl": "http://127.0.0.1:8083/v1",
                    "apiKeyKeychainService": "free-inference.zdr",
                    "upstreamBaseUrl": "https://zdr.example.com/v1",
                },
                "remote_trust": {"tier": "zdr_contract", "usage_policy": "provider_terms_apply"},
            },
            {
                "id": "tee-no-tools-cleared",
                "repo": "org/tee",
                "runtime": "proxy",
                "serve_command": "tinfoil-proxy --bind {host} --port {port}",
                "capabilities": {"tool_calling": False},
                "routing": {"private_attested": "cleared"},
                "promptfoo_provider": {
                    "apiBaseUrl": "http://127.0.0.1:8081/v1",
                    "apiKeyKeychainService": "free-inference.tinfoil",
                },
                "remote_trust": {
                    "tier": "enclave_runtime_attested",
                    "attestation_method": "tinfoil-proxy-sigstore",
                },
            },
            {
                "id": "tee-invalid-routing-val",
                "repo": "org/tee",
                "runtime": "proxy",
                "serve_command": "tinfoil-proxy --bind {host} --port {port}",
                "capabilities": {"tool_calling": True},
                "routing": {"private_attested": "maybe"},
                "promptfoo_provider": {
                    "apiBaseUrl": "http://127.0.0.1:8081/v1",
                    "apiKeyKeychainService": "free-inference.tinfoil",
                },
                "remote_trust": {
                    "tier": "enclave_runtime_attested",
                    "attestation_method": "tinfoil-proxy-sigstore",
                },
            },
        ):
            with self.assertRaises(RegistryError):
                resolve_endpoint(bad_entry, require_api_key=False)

    def test_private_coding_admission_requires_cleared_routing_or_override(self) -> None:
        oc_attested = _load_script_module("opencode_attested_gate", "scripts/opencode-attested")
        uncleared_ep = resolve_endpoint(
            load_model("tinfoil-kimi-k3"), require_api_key=False
        )
        cleared_ep = resolve_endpoint(
            load_model("tinfoil-deepseek-v4-1-flash"),
            require_api_key=False,
        )

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LOCAL_ASSIST_ALLOW_ATTESTED_TEE", None)
            os.environ.pop("LOCAL_ASSIST_ALLOW_UNCLEARED_TEE", None)

            # Without LOCAL_ASSIST_ALLOW_ATTESTED_TEE=1, even cleared Rung 3 is blocked in client.py
            with self.assertRaises(LocalAssistError) as ctx_no_tee:
                check_private_coding_admission(cleared_ep)
            self.assertEqual(ctx_no_tee.exception.code, "trust_tier_blocked")

            # With LOCAL_ASSIST_ALLOW_ATTESTED_TEE=1 alone, cleared is admitted and uncleared is blocked (M1)
            os.environ["LOCAL_ASSIST_ALLOW_ATTESTED_TEE"] = "1"
            check_private_coding_admission(cleared_ep)
            with self.assertRaises(LocalAssistError) as ctx_uncleared:
                check_private_coding_admission(uncleared_ep)
            self.assertEqual(ctx_uncleared.exception.code, "routing_gate_blocked")

            # With LOCAL_ASSIST_ALLOW_UNCLEARED_TEE=1 as well, uncleared is admitted
            os.environ["LOCAL_ASSIST_ALLOW_UNCLEARED_TEE"] = "1"
            check_private_coding_admission(uncleared_ep)

        # Launcher resolve_default_attested_model_id resolves the single cleared model (tinfoil-deepseek-v4-1-flash)
        self.assertEqual(oc_attested.resolve_default_attested_model_id(), "tinfoil-deepseek-v4-1-flash")

        # And refuses when no model is cleared in models_list
        with self.assertRaises(LocalAssistError) as ctx_default:
            oc_attested.resolve_default_attested_model_id(
                [load_model("tinfoil-gpt-oss-120b"), load_model("tinfoil-kimi-k3")]
            )
        self.assertEqual(ctx_default.exception.code, "routing_gate_blocked")

        # Launcher validate_private_attested_endpoint admits cleared and refuses uncleared without --allow-uncleared-model
        oc_attested.validate_private_attested_endpoint(cleared_ep, allow_uncleared_model=False)
        with self.assertRaises(LocalAssistError) as ctx_launcher:
            oc_attested.validate_private_attested_endpoint(
                uncleared_ep, allow_uncleared_model=False
            )
        self.assertEqual(ctx_launcher.exception.code, "routing_gate_blocked")

        import io

        warn_buf = io.StringIO()
        oc_attested.validate_private_attested_endpoint(
            uncleared_ep, allow_uncleared_model=True, err_stream=warn_buf
        )
        self.assertIn("WARNING: Running private-attested with uncleared candidate", warn_buf.getvalue())

    def test_verify_served_model_port_occupancy_across_proxy_models(self) -> None:
        verify_mod = _load_script_module("verify_served_model_proxy_test", "scripts/verify-served-model")
        ep_gpt = resolve_endpoint(load_model("tinfoil-gpt-oss-120b"), require_api_key=False)
        ep_deepseek = resolve_endpoint(
            load_model("tinfoil-deepseek-v4-1-flash"), require_api_key=False
        )

        with tempfile.TemporaryDirectory() as tmp_runs_str:
            tmp_runs = Path(tmp_runs_str)
            gpt_pid_file = pid_file_for_model("tinfoil-gpt-oss-120b", tmp_runs)
            gpt_rec = {
                "model_id": "tinfoil-gpt-oss-120b",
                "repo": "gpt-oss-120b",
                "port": 8081,
                "pid": os.getpid(),
                "status": "ready",
                "startup_nonce": "nonce-1",
            }
            gpt_pid_file.write_text(json.dumps(gpt_rec))
            legacy_pid_file(tmp_runs).write_text(json.dumps(gpt_rec))

            # 1. Duplicate legacy .serve.pid for the same model is de-duplicated and does not conflict (M2)
            deduped = verify_mod.deduplicated_pid_records(tmp_runs)
            self.assertEqual(len(deduped), 1)
            ok_same, err_same = verify_mod.verify_pid_record_matches(ep_gpt, runs_dir=tmp_runs)
            self.assertTrue(ok_same)
            self.assertIsNone(err_same)

            # 2. Another proxy model checking port 8081 fails closed with mismatch (L3)
            ok_diff, err_diff = verify_mod.verify_pid_record_matches(
                ep_deepseek, runs_dir=tmp_runs
            )
            self.assertFalse(ok_diff)
            assert err_diff is not None
            self.assertIn("served model mismatch on port 8081", err_diff)
            self.assertIn("tinfoil-gpt-oss-120b", err_diff)

            # 3. check_once_detailed returns (False, ..., is_mismatch=True) before touching /v1/models
            ok_once, msg_once, is_mm = verify_mod.check_once_detailed(
                ep_deepseek, 1.0, runs_dir=tmp_runs
            )
            self.assertFalse(ok_once)
            self.assertTrue(is_mm)
            self.assertIn("served model mismatch on port 8081", msg_once)

            # 4. A 'status: starting' record (Touch ID pending, pid=None) also occupies port 8081 (M2)
            gpt_starting = dict(gpt_rec, pid=None, status="starting")
            gpt_pid_file.write_text(json.dumps(gpt_starting))
            legacy_pid_file(tmp_runs).write_text(json.dumps(gpt_starting))
            ok_start, err_start = verify_mod.verify_pid_record_matches(
                ep_deepseek, runs_dir=tmp_runs
            )
            self.assertFalse(ok_start)
            assert err_start is not None
            self.assertIn("status=starting", err_start)

    def test_opencode_attested_worst_case_usd_and_attached_session_caps(self) -> None:
        oc_attested = _load_script_module("opencode_attested_spend", "scripts/opencode-attested")
        ep_gpt = resolve_endpoint(load_model("tinfoil-gpt-oss-120b"), require_api_key=False)
        ep_deepseek = resolve_endpoint(
            load_model("tinfoil-deepseek-v4-1-flash"), require_api_key=False
        )
        ep_glm = resolve_endpoint(load_model("tinfoil-glm-5-3"), require_api_key=False)
        ep_kimi = resolve_endpoint(load_model("tinfoil-kimi-k3"), require_api_key=False)

        # At bounded 25-req / 128 KB / 2048-token caps (131072 bytes -> 43691 input tokens/req):
        bounded_kwargs = {
            "max_chat_requests": 25,
            "max_request_bytes": 131072,
            "max_tokens_cap": 2048,
        }
        est_gpt = oc_attested.compute_worst_case_session_usd(ep_gpt, **bounded_kwargs)
        est_ds = oc_attested.compute_worst_case_session_usd(ep_deepseek, **bounded_kwargs)
        est_glm = oc_attested.compute_worst_case_session_usd(ep_glm, **bounded_kwargs)
        est_kimi = oc_attested.compute_worst_case_session_usd(ep_kimi, **bounded_kwargs)

        self.assertEqual(est_ds["worst_input_tokens_per_req"], 43691)
        self.assertAlmostEqual(est_gpt["worst_total_usd"], 0.194561, places=4)
        self.assertAlmostEqual(est_ds["worst_total_usd"], 0.784219, places=4)
        self.assertAlmostEqual(est_glm["worst_total_usd"], 2.260495, places=4)
        self.assertAlmostEqual(est_kimi["worst_total_usd"], 5.3931, places=4)

        # Interactive default (max_session_usd=None) allows all four models without blocking
        for ep in (ep_gpt, ep_deepseek, ep_glm, ep_kimi):
            oc_attested.check_session_spend_ceiling(ep, max_session_usd=None)

        # Explicit $2.00 ceiling at bounded caps allows gpt-oss-120b and deepseek-v4-1-flash, and refuses glm-5-3 and kimi-k3
        oc_attested.check_session_spend_ceiling(ep_gpt, max_session_usd=2.00, **bounded_kwargs)
        oc_attested.check_session_spend_ceiling(ep_deepseek, max_session_usd=2.00, **bounded_kwargs)
        with self.assertRaises(LocalAssistError) as ctx_glm:
            oc_attested.check_session_spend_ceiling(ep_glm, max_session_usd=2.00, **bounded_kwargs)
        self.assertEqual(ctx_glm.exception.code, "spend_ceiling_exceeded")
        with self.assertRaises(LocalAssistError) as ctx_kimi:
            oc_attested.check_session_spend_ceiling(ep_kimi, max_session_usd=2.00, **bounded_kwargs)
        self.assertEqual(ctx_kimi.exception.code, "spend_ceiling_exceeded")

        # M3: Attaching to an existing session with large caps recomputes cost from the PID record and refuses
        with tempfile.TemporaryDirectory() as tmp_runs_str:
            tmp_runs = Path(tmp_runs_str)
            ds_pid_path = pid_file_for_model("tinfoil-deepseek-v4-1-flash", tmp_runs)
            ds_pid_path.write_text(
                json.dumps(
                    {
                        "model_id": "tinfoil-deepseek-v4-1-flash",
                        "repo": "deepseek-v4-1-flash",
                        "port": 8081,
                        "pid": os.getpid(),
                        "status": "ready",
                        "max_chat_requests": 200,
                        "max_tokens_cap": 8192,
                        "max_request_bytes": 524288,
                        "ttl_seconds": 7200,
                    }
                )
            )

            def fake_verify_ok(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                return subprocess.CompletedProcess(cmd, 0, stdout="deepseek-v4-1-flash\n", stderr="")

            ok_att, err_att, meta_att = oc_attested.ensure_model_served(
                ep_deepseek,
                no_serve=True,
                max_session_usd=2.00,
                runs_dir=tmp_runs,
                run_cmd=fake_verify_ok,
                **bounded_kwargs,
            )
            self.assertFalse(ok_att)
            self.assertIsNone(meta_att)
            assert err_att is not None
            self.assertIn("Refusing to attach to active proxy session", err_att)
            self.assertIn("stop-model tinfoil-deepseek-v4-1-flash", err_att)

            # Y2: Attaching to a session started with max_tokens_cap=0 (no clamp) or missing cap fields must also be refused
            ds_pid_path.write_text(
                json.dumps(
                    {
                        "model_id": "tinfoil-deepseek-v4-1-flash",
                        "repo": "deepseek-v4-1-flash",
                        "port": 8081,
                        "pid": os.getpid(),
                        "status": "ready",
                        "max_chat_requests": 25,
                        "max_tokens_cap": 0,
                        "max_request_bytes": 131072,
                        "ttl_seconds": 1800,
                    }
                )
            )
            ok_zero, err_zero, meta_zero = oc_attested.ensure_model_served(
                ep_deepseek,
                no_serve=True,
                max_session_usd=2.00,
                runs_dir=tmp_runs,
                run_cmd=fake_verify_ok,
                **bounded_kwargs,
            )
            self.assertFalse(ok_zero)
            self.assertIsNone(meta_zero)
            assert err_zero is not None
            self.assertIn("max_tokens_cap=0 means unclamped output tokens", err_zero)

            ds_pid_path.write_text(
                json.dumps(
                    {
                        "model_id": "tinfoil-deepseek-v4-1-flash",
                        "repo": "deepseek-v4-1-flash",
                        "port": 8081,
                        "pid": os.getpid(),
                        "status": "ready",
                    }
                )
            )
            ok_missing, err_missing, meta_missing = oc_attested.ensure_model_served(
                ep_deepseek,
                no_serve=True,
                max_session_usd=2.00,
                runs_dir=tmp_runs,
                run_cmd=fake_verify_ok,
                **bounded_kwargs,
            )
            self.assertFalse(ok_missing)
            self.assertIsNone(meta_missing)
            assert err_missing is not None
            self.assertIn("unbounded or missing spend caps", err_missing)

    def test_opencode_attested_renders_single_provider_and_env_token_placeholder(self) -> None:
        oc_attested = _load_script_module("opencode_attested_render", "scripts/opencode-attested")
        ep_ds = resolve_endpoint(
            load_model("tinfoil-deepseek-v4-1-flash"),
            pid_record={"session_token_file": "/nonexistent"},
            require_api_key=False,
        )
        cfg_str = oc_attested.render_private_attested_config(ep_ds)
        self.assertNotIn("se-session-", cfg_str)
        cfg = json.loads(cfg_str)
        self.assertEqual(cfg["enabled_providers"], ["private-attested"])
        self.assertEqual(list(cfg["provider"].keys()), ["private-attested"])
        self.assertEqual(cfg["model"], "private-attested/tinfoil-deepseek-v4-1-flash")
        self.assertEqual(cfg["small_model"], "private-attested/tinfoil-deepseek-v4-1-flash")
        prov = cfg["provider"]["private-attested"]
        self.assertEqual(prov["options"]["baseURL"], "http://127.0.0.1:8081/v1")
        self.assertEqual(prov["options"]["apiKey"], "{env:LOCAL_ASSIST_SESSION_TOKEN}")
        model_cfg = prov["models"]["tinfoil-deepseek-v4-1-flash"]
        self.assertEqual(model_cfg["id"], "deepseek-v4-1-flash")
        self.assertEqual(model_cfg["modalities"], {"input": ["text"], "output": ["text"]})
        self.assertEqual(model_cfg["limit"]["context"], 1048576)
        self.assertEqual(model_cfg["limit"]["output"], 16384)
        self.assertEqual(
            cfg["mcp"]["servers"]["local_assist"]["environment"]["LOCAL_ASSIST_BASE_URL"],
            "http://127.0.0.1:8080/v1",
        )
        self.assertEqual(cfg["permission"]["*"], "ask")
        self.assertEqual(cfg["permission"]["webfetch"], "deny")
        self.assertEqual(cfg["permission"]["websearch"], "deny")

    def test_opencode_attested_env_isolation_and_no_tee_escalation(self) -> None:
        oc_attested = _load_script_module("opencode_attested_env", "scripts/opencode-attested")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            tok_file = tmp_path / ".se-session-test.token"
            tok_val = "se-session-" + ("f" * 64)
            tok_file.write_text(tok_val, encoding="utf-8")
            ep_ds = resolve_endpoint(
                load_model("tinfoil-deepseek-v4-1-flash"),
                pid_record={"session_token_file": str(tok_file)},
                require_api_key=True,
            )
            env = oc_attested.build_private_attested_env(
                tmp_path / "ws",
                tmp_path / "home",
                tmp_path / "home" / "opencode.json",
                ep_ds,
                preserve_host_home=False,
                base_env={
                    "PATH": "/usr/bin:/bin",
                    "HOME": "/opt/mockhome",
                    "OPENAI_API_KEY": "sk-secret",
                    "TINFOIL_API_KEY": "tf-secret",
                    "LOCAL_ASSIST_ALLOW_ATTESTED_TEE": "1",
                    "LOCAL_ASSIST_ALLOW_UNCLEARED_TEE": "1",
                },
            )
            self.assertEqual(env["HOME"], str(tmp_path / "home"))
            self.assertEqual(env["OPENCODE_TEST_HOME"], str(tmp_path / "home"))
            self.assertEqual(env["XDG_CONFIG_HOME"], str(tmp_path / "home" / ".config"))
            self.assertEqual(env["XDG_DATA_HOME"], str(tmp_path / "home" / ".local" / "share"))
            self.assertEqual(env["XDG_CACHE_HOME"], str(tmp_path / "home" / ".cache"))
            self.assertEqual(env["XDG_STATE_HOME"], str(tmp_path / "home" / ".local" / "state"))
            self.assertEqual(env["OPENCODE_DISABLE_AUTOUPDATE"], "1")
            self.assertEqual(env["OPENCODE_DISABLE_MODELS_FETCH"], "1")
            self.assertEqual(env["OPENCODE_DISABLE_PROJECT_CONFIG"], "1")
            self.assertEqual(env["LOCAL_ASSIST_BASE_URL"], "http://127.0.0.1:8080/v1")
            self.assertEqual(env["LOCAL_ASSIST_SESSION_TOKEN"], tok_val)
            self.assertNotIn("LOCAL_ASSIST_ALLOW_ATTESTED_TEE", env)
            self.assertNotIn("LOCAL_ASSIST_ALLOW_UNCLEARED_TEE", env)
            self.assertNotIn("OPENAI_API_KEY", env)
            self.assertNotIn("TINFOIL_API_KEY", env)

    def test_online_bootstrap_handoff_refused_until_restarted_offline(self) -> None:
        serve_mod = _load_script_module("serve_model_handoff", "scripts/serve-model")
        verify_mod = _load_script_module("verify_served_handoff", "scripts/verify-served-model")
        oc_local = _load_script_module("opencode_local_handoff", "scripts/opencode-local")

        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = Path(tmp) / "runs"
            runs_dir.mkdir(parents=True, exist_ok=True)
            serve_mod.RUNS = runs_dir
            model_id = "qwen3-30b-a3b-2507-mlx-4bit"
            ep = resolve_endpoint(load_model(model_id), require_api_key=True)

            class FakePopen:
                def __init__(self, *args: object, **kwargs: object) -> None:
                    self.pid = os.getpid()

                def poll(self) -> None:
                    return None

            # 1. Start local server with --allow-hf-online (simulating initial weight download)
            with (
                patch.object(serve_mod, "health", return_value=False),
                patch.object(serve_mod.subprocess, "Popen", side_effect=FakePopen),
            ):
                rc_online = serve_mod.main(["scripts/serve-model", model_id, "--allow-hf-online"])
            self.assertEqual(rc_online, 0)

            online_rec = json.loads(pid_file_for_model(model_id, runs_dir).read_text(encoding="utf-8"))
            self.assertIs(online_rec.get("hf_offline"), False)

            # Plain verify-served-model (without --require-offline) accepts the online bootstrap server
            ok_plain, _ = verify_mod.verify_pid_record_matches(ep, runs_dir=runs_dir, require_offline=False)
            self.assertTrue(ok_plain)

            # verify-served-model --require-offline (used by opencode-local and local_assist) rejects it
            ok_req, err_req = verify_mod.verify_pid_record_matches(ep, runs_dir=runs_dir, require_offline=True)
            self.assertFalse(ok_req)
            self.assertIn("--allow-hf-online", str(err_req))

            # opencode-local ensure_model_served refuses to reuse the online-enabled server
            def _run_verify_against_tmp(cmd: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
                req_off = "--require-offline" in cmd
                ok, err = verify_mod.verify_pid_record_matches(ep, runs_dir=runs_dir, require_offline=req_off)
                return subprocess.CompletedProcess(
                    cmd,
                    0 if ok else verify_mod.EXIT_MODEL_MISMATCH,
                    stdout="" if not ok else ep.served_model_id,
                    stderr=str(err or ""),
                )

            served_ok, served_err = oc_local.ensure_model_served(ep, run_cmd=_run_verify_against_tmp)
            self.assertFalse(served_ok)
            self.assertIn("--allow-hf-online", str(served_err))

            # 2. Stop the online server (remove PID files), then start offline (default serve-model without --allow-hf-online)
            for p in runs_dir.glob(".serve*.pid"):
                p.unlink(missing_ok=True)

            with (
                patch.object(serve_mod, "health", return_value=False),
                patch.object(serve_mod.subprocess, "Popen", side_effect=FakePopen),
            ):
                rc_offline = serve_mod.main(["scripts/serve-model", model_id])
            self.assertEqual(rc_offline, 0)

            offline_rec = json.loads(pid_file_for_model(model_id, runs_dir).read_text(encoding="utf-8"))
            self.assertIs(offline_rec.get("hf_offline"), True)

            served_ok2, served_err2 = oc_local.ensure_model_served(ep, run_cmd=_run_verify_against_tmp)
            self.assertTrue(served_ok2, msg=served_err2)


if __name__ == "__main__":
    unittest.main()
