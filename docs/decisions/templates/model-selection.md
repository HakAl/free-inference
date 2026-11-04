# Model Selection Decision

## Context

- Eval suite:
- Date:
- Candidate models:

## Winners By Role

- Everyday default:
- Coding specialist:
- Fast helper:
- Deep reasoning:
- Archive:

## Quality Summary

For each model:

- Strengths:
- Failures:
- Fatal flags:
- Best-fit role:

## Latency And Throughput

Record per model:

- TTFT:
- Total generation time:
- Tokens/sec:
- Resident memory notes:
- Load time:

## MoE vs Dense Comparison

Compare sparse/MoE models against dense baselines explicitly.

Questions:

- Does the 30B-class MoE beat the smaller dense model on tokens/sec?
- Does the MoE also win or tie on quality?
- Does MoE routing introduce instability, formatting issues, or task-specific regressions?
- Is the quality/latency tradeoff strong enough to make the MoE the everyday default?

Current planned comparison:

- `qwen3-30b-a3b-2507-mlx-4bit` vs `gemma-4-26b-a4b-it-optiq-mlx-4bit`
- `qwen3-coder-30b-a3b-mlx-4bit` vs `qwen3-30b-a3b-2507-mlx-4bit` for coding tasks

## Decision

- Selected defaults:
- Models to keep:
- Models to archive:
- Follow-up evals:
