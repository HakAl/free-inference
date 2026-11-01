# Milestone 0 Candidate Review

## Candidate

- Local alias: `qwen3-1.7b-mlx-4bit`
- Repo: `Qwen/Qwen3-1.7B-MLX-4bit`
- Runtime: `mlx-lm`
- License: Apache-2.0
- Purpose: smallest practical text-model candidate for validating `mlx_lm.server` plus promptfoo.

## Source Notes

- Hugging Face model card lists the repo as Text Generation, MLX, Safetensors, Qwen3, conversational, 4-bit precision, Apache-2.0.
- The model card documents `mlx_lm.server --model "Qwen/Qwen3-1.7B-MLX-4bit"`.
- The model card lists 1.7B parameters and 32,768 context length.
- The Hugging Face page reports a 914 MB MLX package, making it appropriate for a small Milestone 0 download.
- Apple `mlx-lm` server docs describe an OpenAI-like `/v1/chat/completions` endpoint and streaming support.

## Caveats

- This is only a Milestone 0 candidate, not a final benchmark candidate.
- `tool_version`, `group_size`, and exact conversion runtime still need live local verification.
- Qwen3 thinking/non-thinking behavior affects latency and output shape. The first sanity call without `/no_think` returned `<think>` reasoning and did not satisfy the one-sentence check.
- Running `mlx_lm.server` with `--chat-template-args '{"enable_thinking":false}'` is misleading for this conversion because the embedded chat template does not contain an `enable_thinking` branch. The setting reaches `apply_chat_template`, but the template ignores it.
- Prompting with `/no_think` removes reasoning content, but this conversion still emits an empty `<think></think>` wrapper before the answer.
- The trailing `<|im_end|>` artifact appears to come from an `mlx-lm` server stop/trim behavior where EOS is detected before user stop sequences can trim visible EOS text. Treat this as upstream/runtime behavior, not user error.
- For Milestone 0, promptfoo applies an output transform that strips `<think>...</think>` and trailing visible EOS markers. Revisit chat-template override or upstream patching only if a Qwen3 model becomes a real benchmark candidate.
