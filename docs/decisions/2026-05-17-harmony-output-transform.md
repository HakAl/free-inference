# Harmony Output Transform Decision

## Outcome

`gpt-oss-20b-mxfp4-q4` uses the promptfoo-level harmony output transform as its operational normalization path.

The recommended ordinary-task serving knob is `reasoning_effort=low` plus the harmony transform. This is a settled decision from the 2026-05-17 probe: `reasoning_effort` changes analysis-channel length and token-budget behavior, but it does not remove the harmony channel structure. The effort knob is therefore a tuning parameter, not a normalization mechanism.

## Model Context

- Registry id: `gpt-oss-20b-mxfp4-q4`
- Repo: `mlx-community/gpt-oss-20b-MXFP4-Q4`
- Upstream: `openai/gpt-oss-20b`
- Runtime: `mlx-lm`
- Output format: harmony channel format
- Provenance source: `reviews/candidates/2026-05-14-milestone-2-provenance.md`
- Sanity review: `reviews/evals/2026-05-17-gpt-oss-20b-sanity.md`

## Evidence

Primary run notes:

- `runs/2026-05-17-073608-gpt-oss-reasoning-effort-probe/notes.md`

The reasoning-effort probe used the normal server lifecycle path:

- `scripts/serve-model gpt-oss-20b-mxfp4-q4 --chat-template-args '{"reasoning_effort":"..."}'`
- `scripts/verify-served-model gpt-oss-20b-mxfp4-q4 --wait 60`

Observed effort comparison, copied from the primary notes:

| `reasoning_effort` | Channel behavior | Timing / reachability |
| --- | --- | --- |
| `low` | analysis channel present but short; no `<|return|>` residue in streamed sample | TTFT `0.4009s`, total `0.7555s`, 31 chunks, coherent final |
| `medium` | analysis channel present and longer; `<|return|>` residue observed in non-streaming full sample | TTFT `0.4041s`, total `1.2928s`, 79 chunks at 80-token cap; coherent final when sampled with 200-token non-streaming call |
| `high` | analysis channel present; can consume the full tested budget before final | TTFT `0.4319s`, total `1.3202s`, 79 chunks at 80-token cap; final not reached in the 200-token non-streaming sample |

The implementation landed in:

- `evals/transforms/harmony.js`
- `tests/test_harmony_transform.py`
- `promptfooconfig.yaml`
- `evals/suites/v1.yaml`
- `scripts/serve-model`

`evals/transforms/harmony.js` extracts the last `<|channel|>final<|message|>` segment, stops at `<|return|>`, strips full or truncated `<|return|>` residue, drops harmony outputs with no final channel, and falls back to trimmed text for non-harmony output.

`tests/test_harmony_transform.py` covers:

- final-channel extraction with `<|return|>` stripping;
- harmony output with no final channel;
- truncated `<|return|>` residue;
- no-marker fallback.

Verification command run for this decision:

```bash
.venv/bin/python -m unittest tests/test_harmony_transform.py
```

Result: 4 tests passed.

## Why Not `reasoning_effort` Suppression Alone

The provenance review identified two possible paths: suppress analysis at the server/template level, or normalize harmony output at promptfoo level. The 2026-05-17 probe resolved that choice.

`reasoning_effort=low` does not suppress the analysis channel structure. It only shortens the analysis content in the observed sample. `reasoning_effort=medium` still emitted longer analysis and exposed `<|return|>` residue. `reasoning_effort=high` can spend the full tested budget before reaching the final channel on a short prompt.

Because the harmony structure remains visible across effort settings, the transform is required for promptfoo consumption. `reasoning_effort` remains useful, but only as a cost/latency/reasoning-depth knob.

## Status Implications

`gpt-oss-20b-mxfp4-q4` is unblocked for v1 suite participation as of this decision.

Wiring is present in:

- `promptfooconfig.yaml`: provider `openai:chat:mlx-community/gpt-oss-20b-MXFP4-Q4` uses `transform: file://evals/transforms/harmony.js`.
- `evals/suites/v1.yaml`: the v1 provider entry uses the same harmony transform.
- `scripts/serve-model`: supports `--chat-template-args JSON`, including `{"reasoning_effort":"low"}`.

The May 14 v1 run set predates this model and remains a 3-model regime:

- `phi-4-mlx-4bit`
- `qwen3-30b-a3b-2507-mlx-4bit`
- `qwen3-coder-30b-a3b-mlx-4bit`

A separate `gpt-oss-20b-mxfp4-q4` v1 run can be scheduled when convenient. It does not need to be folded into the Milestone 1 headline set retroactively.

## Caveats

The provenance review's four documented caveats now stand as:

- Channel-marker leakage: resolved operationally by `evals/transforms/harmony.js`.
- EOS trim residue: resolved operationally by the same transform, including truncated `<|return|>` residue.
- Context window: resolved in the sanity review at 131072 max positions.
- `reasoning_effort`: better understood and exposed through `scripts/serve-model`, but not a normalization mechanism. Other effort/template knobs may still be worth exploring later.

The transform handles the documented harmony shapes: analysis plus final channel, truncated `<|return|>`, and no-marker fallback. Untested shapes remain:

- nested channels;
- multiple final channels beyond the current last-final behavior;
- unexpected channel names;
- malformed marker ordering.

The memory footprint of `gpt-oss-20b-mxfp4-q4` under heavy multilingual generation is still uncharacterized. The ongoing cross-family pass should surface practical server or memory issues if they exist.

## Open Questions

- Should v1 run `gpt-oss-20b-mxfp4-q4` with `reasoning_effort=low` only, or include one medium-effort side run for hard reasoning prompts?
- Does `reasoning_effort=medium` materially improve quality on the existing v1 prompts enough to justify higher token use?
- Should promptfoo summaries explicitly record the effort setting beside provider id for all future gpt-oss runs?
- Should the transform grow stricter around malformed harmony output, or is empty-output-on-no-final sufficient for v1?

## Next Decision

Run `gpt-oss-20b-mxfp4-q4` through v1 with `reasoning_effort=low` and the harmony transform when the next eval window opens. Treat high effort as an explicit experiment only, not a default quality setting.
