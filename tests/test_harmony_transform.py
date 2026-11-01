from __future__ import annotations

import json
import subprocess
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TRANSFORM = ROOT / "evals" / "transforms" / "harmony.js"


def run_transform(output: str) -> str:
    script = textwrap.dedent(
        f"""
        (async () => {{
          const module = await import({json.dumps(TRANSFORM.as_uri())});
          const transform = module.default;
          const input = {json.dumps(output)};
          process.stdout.write(JSON.stringify(transform(input)));
        }})().catch((error) => {{
          console.error(error);
          process.exit(1);
        }});
        """
    )
    proc = subprocess.run(
        ["node", "-e", script],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(proc.stdout)


class HarmonyTransformTests(unittest.TestCase):
    def test_extracts_final_channel_and_strips_return(self) -> None:
        raw = (
            "<|channel|>analysis<|message|>hidden<|end|>"
            "<|start|>assistant<|channel|>final<|message|>The ocean is wide.<|return|>"
        )
        self.assertEqual(run_transform(raw), "The ocean is wide.")

    def test_missing_final_channel_drops_harmony_output(self) -> None:
        raw = "<|channel|>analysis<|message|>hidden reasoning only<|end|>"
        self.assertEqual(run_transform(raw), "")

    def test_strips_truncated_return_residue(self) -> None:
        raw = "<|channel|>final<|message|>The ocean is blue.<|ret"
        self.assertEqual(run_transform(raw), "The ocean is blue.")

    def test_no_channel_markers_falls_back_to_trimmed_text(self) -> None:
        self.assertEqual(run_transform(" Plain answer. <|return|> "), "Plain answer.")

    def test_passes_through_tool_calls_array_and_object(self) -> None:
        script = textwrap.dedent(
            f"""
            (async () => {{
              const module = await import({json.dumps(TRANSFORM.as_uri())});
              const transform = module.default;
              const calls = [{{ id: "call_1", type: "function", function: {{ name: "read_file", arguments: "{{\\"path\\":\\"models.yaml\\"}}" }} }}];
              const wrapped = {{
                content: "<|channel|>analysis<|message|>hidden<|end|><|start|>assistant<|channel|>final<|message|>Done.<|return|>",
                tool_calls: calls,
              }};
              process.stdout.write(JSON.stringify({{
                arrayResult: transform(calls),
                objectResult: transform(wrapped),
              }}));
            }})().catch((error) => {{
              console.error(error);
              process.exit(1);
            }});
            """
        )
        proc = subprocess.run(
            ["node", "-e", script],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["arrayResult"][0]["function"]["name"], "read_file")
        self.assertEqual(payload["objectResult"]["content"], "Done.")
        self.assertEqual(payload["objectResult"]["tool_calls"][0]["id"], "call_1")


if __name__ == "__main__":
    unittest.main()
