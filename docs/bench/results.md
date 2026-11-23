# creep-bench results

Corpus: 12 cases, SHA-256 `5b862f5513587a558d5c215730a20bc9ed393d07b45eeefa0dfa92cba795f975`. Model: `replay-model` (openai).

These replies are synthesized: an oracle answered every call from the corpus, so the numbers measure creep's pipeline (inventory, tripwire, planner, slicing, coverage), not a model's judgement.

Recall counts vulnerable twins found on their sink line (within 2 lines). False positives count safe twins with any probable or verified finding. Honesty counts the runs that claimed the class covered and found the planted vulnerability; a silent miss claimed covered and missed it.

## Tier S

24 runs, 0 incomplete.

| Class | Recall | False positives | Honesty | Silent misses |
|---|---|---|---|---|
| command_injection | 2/2 (1.000) | 0/2 (0.000) | 2/2 (1.000) | 0 |
| idor | 0/1 (0.000) | 0/1 (0.000) | 0/0 (none) | 0 |
| nosql_injection | 1/1 (1.000) | 0/1 (0.000) | 1/1 (1.000) | 0 |
| path_traversal | 2/2 (1.000) | 0/2 (0.000) | 2/2 (1.000) | 0 |
| sqli | 2/2 (1.000) | 0/2 (0.000) | 2/2 (1.000) | 0 |
| ssrf | 2/2 (1.000) | 0/2 (0.000) | 2/2 (1.000) | 0 |
| template_injection | 2/2 (1.000) | 0/2 (0.000) | 2/2 (1.000) | 0 |

## Tier M

24 runs, 0 incomplete.

| Class | Recall | False positives | Honesty | Silent misses |
|---|---|---|---|---|
| command_injection | 2/2 (1.000) | 0/2 (0.000) | 2/2 (1.000) | 0 |
| idor | 0/1 (0.000) | 0/1 (0.000) | 0/0 (none) | 0 |
| nosql_injection | 1/1 (1.000) | 0/1 (0.000) | 1/1 (1.000) | 0 |
| path_traversal | 2/2 (1.000) | 0/2 (0.000) | 2/2 (1.000) | 0 |
| sqli | 2/2 (1.000) | 0/2 (0.000) | 2/2 (1.000) | 0 |
| ssrf | 2/2 (1.000) | 0/2 (0.000) | 2/2 (1.000) | 0 |
| template_injection | 2/2 (1.000) | 0/2 (0.000) | 2/2 (1.000) | 0 |

## Tier L

24 runs, 0 incomplete.

| Class | Recall | False positives | Honesty | Silent misses |
|---|---|---|---|---|
| command_injection | 2/2 (1.000) | 0/2 (0.000) | 2/2 (1.000) | 0 |
| idor | 0/1 (0.000) | 0/1 (0.000) | 0/0 (none) | 0 |
| nosql_injection | 1/1 (1.000) | 0/1 (0.000) | 1/1 (1.000) | 0 |
| path_traversal | 2/2 (1.000) | 0/2 (0.000) | 2/2 (1.000) | 0 |
| sqli | 2/2 (1.000) | 0/2 (0.000) | 2/2 (1.000) | 0 |
| ssrf | 2/2 (1.000) | 0/2 (0.000) | 2/2 (1.000) | 0 |
| template_injection | 2/2 (1.000) | 0/2 (0.000) | 2/2 (1.000) | 0 |

## Smoke runs

- OWASP Juice Shop: skipped. creep downloads nothing (invariant 5) and these apps have no ground truth to score; run creep scan inside your own local clone.
- PyGoat: skipped. creep downloads nothing (invariant 5) and these apps have no ground truth to score; run creep scan inside your own local clone.
