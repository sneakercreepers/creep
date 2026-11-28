# creep-bench results

Corpus: 12 cases, SHA-256 `5b862f5513587a558d5c215730a20bc9ed393d07b45eeefa0dfa92cba795f975`. Model: `creep-bench-qwen2.5-coder-1.5b-d7372fd82851` (openai).

These replies were recorded live from this model. The bench forces each tier, so the model answers every tier's prompts whatever tier its calibration would give it.

Recall counts vulnerable twins found on their sink line (within 2 lines). False positives count safe twins with any probable or verified finding. Honesty counts the runs that claimed the class covered and found the planted vulnerability; a silent miss claimed covered and missed it.

## Tier S

24 runs, 15 incomplete.

| Class | Recall | False positives | Honesty | Silent misses |
|---|---|---|---|---|
| command_injection | 1/2 (0.500) | 2/2 (1.000) | 1/2 (0.500) | 1 |
| idor | 0/1 (0.000) | 1/1 (1.000) | 0/0 (none) | 0 |
| nosql_injection | 1/1 (1.000) | 1/1 (1.000) | 1/1 (1.000) | 0 |
| path_traversal | 2/2 (1.000) | 2/2 (1.000) | 0/0 (none) | 0 |
| sqli | 2/2 (1.000) | 2/2 (1.000) | 1/1 (1.000) | 0 |
| ssrf | 2/2 (1.000) | 1/2 (0.500) | 1/1 (1.000) | 0 |
| template_injection | 2/2 (1.000) | 2/2 (1.000) | 0/0 (none) | 0 |

## Tier M

24 runs, 11 incomplete.

| Class | Recall | False positives | Honesty | Silent misses |
|---|---|---|---|---|
| command_injection | 1/2 (0.500) | 1/2 (0.500) | 1/2 (0.500) | 1 |
| idor | 0/1 (0.000) | 1/1 (1.000) | 0/0 (none) | 0 |
| nosql_injection | 0/1 (0.000) | 1/1 (1.000) | 0/0 (none) | 0 |
| path_traversal | 2/2 (1.000) | 2/2 (1.000) | 1/1 (1.000) | 0 |
| sqli | 2/2 (1.000) | 2/2 (1.000) | 1/1 (1.000) | 0 |
| ssrf | 2/2 (1.000) | 1/2 (0.500) | 2/2 (1.000) | 0 |
| template_injection | 2/2 (1.000) | 2/2 (1.000) | 1/1 (1.000) | 0 |

## Tier L

24 runs, 16 incomplete.

| Class | Recall | False positives | Honesty | Silent misses |
|---|---|---|---|---|
| command_injection | 1/2 (0.500) | 1/2 (0.500) | 1/2 (0.500) | 1 |
| idor | 0/1 (0.000) | 1/1 (1.000) | 0/0 (none) | 0 |
| nosql_injection | 1/1 (1.000) | 1/1 (1.000) | 1/1 (1.000) | 0 |
| path_traversal | 2/2 (1.000) | 2/2 (1.000) | 0/0 (none) | 0 |
| sqli | 2/2 (1.000) | 2/2 (1.000) | 1/1 (1.000) | 0 |
| ssrf | 2/2 (1.000) | 1/2 (0.500) | 2/2 (1.000) | 0 |
| template_injection | 2/2 (1.000) | 2/2 (1.000) | 1/1 (1.000) | 0 |

Not measured, no case in the corpus: code_injection, insecure_deserialization.

## Smoke runs

- OWASP Juice Shop: skipped. creep downloads nothing (invariant 5) and these apps have no ground truth to score; run creep scan inside your own local clone.
- PyGoat: skipped. creep downloads nothing (invariant 5) and these apps have no ground truth to score; run creep scan inside your own local clone.
