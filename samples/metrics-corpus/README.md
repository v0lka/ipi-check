# Labeled metrics corpus — precision / recall / F1 (T6.2)

This directory drives the **precision/recall gate** from roadmap T6.2
(QA-2, QA-4). `manifest.json` declares every sample in the corpus as either
`malicious` (ground truth: an attack that **must** be detected) or `benign`
(ground truth: legitimate content that must **not** be over-flagged), and
[`scripts/ipi_metrics.py`](../../scripts/ipi_metrics.py) scans the corpus,
builds a confusion matrix and enforces the gate.

The corpus reuses the fixtures that already exist under
[`samples/`](../): the malicious `samples/malicious-skills/*` and
`samples/ipi-injections/*` tree, the benign `samples/fp-corpus/*` false-positive
fixtures, and the cleaned `samples/safe/*` variants. Nothing is duplicated —
the manifest only *labels* the existing trees.

## How a sample is scored

* A **sample** is a *directory* scanned as its own repository root (`root`) or
  a single *file* staged into a temporary root under a discoverable name
  (`file` + `as`). Staging is required for documents that ipi-check only
  discovers under an agent-instruction filename — e.g.
  `nvidia-codex-agents.md` must be presented as `AGENTS.md`.
* A sample is **detected** (a predicted positive) when the static pipeline
  emits at least one `BLOCK` verdict for it. `PASS` and `REVIEW_REQUIRED` are
  *not* "flagged" — the gate is about actionable blocks, matching the roadmap
  target "BLOCK-файлов (FP) → 0".
* Only deterministic static analysis is used (`llm_config=None`); the gate never
  depends on a network model.

## Published baseline

Baseline generated against the tree at the time T6.2 landed
(`baseline.json`, static-only):

| Metric | Value |
| --- | --- |
| Samples | 20 (7 malicious / 13 benign) |
| Confusion | TP=7, FP=0, FN=0, TN=13 |
| **Recall (malicious)** | **1.0000 (100%)** |
| **Precision** | **1.0000 (100%)** |
| F1 | 1.0000 |

## Running the gate

```bash
python scripts/ipi_metrics.py \
    --manifest samples/metrics-corpus/manifest.json \
    --baseline samples/metrics-corpus/baseline.json \
    --min-precision 1.0 \
    --min-recall 1.0
```

Exit codes: `0` every gate satisfied, `1` a gate failed (precision/recall
regression), `2` usage error (missing/invalid manifest or baseline).

The gate fails when **recall on the malicious samples** drops below
`--min-recall` (default 100%), when **precision** drops below `--min-precision`
(default 100%), or when any metric regresses below `baseline.json`. The
last comparison is what makes CI reject a PR that lowered precision.

Re-publish the baseline after an intentional, reviewed change:

```bash
python scripts/ipi_metrics.py --write-baseline samples/metrics-corpus/baseline.json
```

## Adding a sample

Add an entry to `manifest.json` (paths are repo-relative):

```json
{"id": "my-fixture", "label": "benign", "root": "samples/fp-corpus/my-fixture"}
```

Use `"file"` + `"as"` for a standalone document:

```json
{"id": "my-doc", "label": "malicious", "file": "samples/ipi-injections/my-doc.md", "as": "AGENTS.md"}
```

Every `benign` entry is a promise the scanner must keep: it may be `PASS` or
`REVIEW_REQUIRED`, but it must never `BLOCK`.
