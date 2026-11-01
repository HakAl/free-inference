# Needle-In-The-Middle Prompt Design

Purpose: test retrieval of a buried fact, not summarization.

Design:

- Create a roughly 30-100 KB synthetic document.
- Place one critical detail around 80% of the way through the document.
- Surround it with plausible but irrelevant adjacent details.
- Ask a direct question whose answer depends only on the buried detail.
- Require a short answer for the retrieval test. Test JSON formatting separately so retrieval failures and format failures do not collapse into one score.

Scoring:

- Pass: exact buried fact recovered without hallucinated details.
- Partial: answer is directionally correct but missing the exact value/name/date.
- Fail: summarizes the document, guesses from nearby distractors, or invents an answer.

Example task shape:

```text
Read the document below. What is the emergency restore token for the Delta indexer?
Answer with only the token.
```

This should become a generated fixture rather than a hand-written one so we can vary the buried fact while preserving reproducibility.
