# Human Scoring Rubric

Score each output from 1 to 5:

- Correctness
- Completeness
- Instruction following
- Code quality
- Reasoning clarity
- Concision
- Structured-output validity
- Practical usefulness
- Long-context retrieval accuracy

Aggregate review files should report per-prompt 1-5 scores, then summarize by role fit before any overall average. Keep format compliance, retrieval, coding, and general reasoning visible as separate rows so one repeated failure mode does not dominate the decision.

Fatal flags:

- Hallucinated files, APIs, packages, or model capabilities
- Invalid JSON when strict JSON was required
- Unsafe or destructive shell commands without warning
- Confidently wrong setup instructions
- Refusal or evasion on normal technical tasks
- Output that cannot be used without major repair
