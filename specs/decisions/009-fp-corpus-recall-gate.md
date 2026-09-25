# ADR-009: Labelled FP Corpus with a Paired Recall Guard as the Quality Gate

## Status

Accepted

## Context

The scanner had malicious and safe *sample* corpora but **no false-positive
corpus and no quality gate** (roadmap §1.3, QA-1 / QA-2 / QA-4). As a result a
regression that drove ~99% of findings to false positives went undetected: on a
real repository scan 1040 of 1087 results were duplicates of the same false
signal, and only 9 were actionable (§0). Without a gate, each false-positive fix
(FP-1 … FP-14) is unverifiable, and a fix that trades precision for recall can
silently weaken detection of real attacks.

The roadmap's global constraint (§2.3) makes recall non-negotiable: *any*
precision improvement must preserve detection on `samples/ipi-injections/*` and
`samples/malicious-skills/*`. A usable gate therefore needs to measure **both**
directions — false positives down, recall unchanged — cheaply enough to run on
every pull request.

## Decision

Adopt a **labelled false-positive corpus paired with a recall guard** as the
project's quality metric, encoded as pytest assertions in the existing CI
`test` job (no new CI infrastructure).

- **Negative corpus**: `samples/fp-corpus/` holds benign content that a real
  repository legitimately contains. Every fixture maps to exactly one FP class
  (FP-1 … FP-14) and declares an expected verdict; `BLOCK` is never acceptable
  for any fixture.
- **Recall guard**: the malicious corpora (`samples/ipi-injections/`,
  `samples/malicious-skills/`) must still reach their expected `BLOCK`
  verdicts — recall is asserted at 100%. The corpus-wide guard lives in
  `tests/test_fp_regression.py` (`TestRecallGuard`); per-sample recall on both
  corpora lives in `tests/test_samples_detection.py`.
- **Gate**: `tests/test_fp_regression.py` asserts (a) no FP-corpus fixture
  produces a `BLOCK` verdict and (b) every malicious *skill* sample still
  blocks, while `tests/test_samples_detection.py` pins per-sample `BLOCK`
  verdicts on the injection corpus. All of it runs in CI's `test` job, so a
  precision regression fails the build.

This is deliberately a **paired binary gate**, not a numeric precision/recall
threshold: it expresses intent ("this benign case must not block; this attack
must still block") and is deterministic. The numeric precision/recall harness
(§3 T6.2) is layered on top of the same corpus and ships alongside it
(`scripts/ipi_metrics.py`, the labelled `samples/metrics-corpus/`, and the
mandatory CI `metrics` job gating every pull request at precision/recall
`1.0`); this ADR's pytest gate remains the intent-expressing floor, and the
numeric gate is the quantitative ceiling built on the identical fixtures.

## Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| **Ad-hoc manual review** | No infrastructure | Unrepeatable; not in CI; regressions return silently | Does not prevent regressions |
| **Numeric precision/recall thresholds in a dedicated CI job** | Quantified, tunable | Requires a scoring harness over a fully labelled corpus; thresholds are brittle before the corpus exists | Not an alternative but a complement — added on top of this ADR's corpus as the mandatory CI `metrics` job (`scripts/ipi_metrics.py`, roadmap T6.2); the binary pytest gate below stays the primary, intent-expressing guard |
| **Golden/snapshot tests over SARIF output** | Precise diffs | Brittle to benign reformatting (line shifts, ordering); does not express security intent | High churn, low signal; verdict-level expectations are more robust |
| **Only a malicious (recall) corpus** | Simpler | Cannot catch false positives — the dominant failure mode | Half the problem; FP control is the whole point |
| **Labelled FP corpus + paired recall asserts (chosen)** | Intent-expressing; deterministic; zero new infrastructure; guards both directions | No single precision number; corpus needs curation per new FP class | **Chosen.** Cheap, robust, and non-negotiable on recall |

## Consequences

### Enables
- **FP regressions become visible**: any fixture that starts blocking fails CI
  with the offending FP class named.
- **Recall cannot silently drop**: the recall guard fails the build if a
  malicious sample stops blocking.
- **Foundation for numeric metrics**: the corpus is the labelled ground truth
  the precision/recall/F1 harness (roadmap T6.2, `scripts/ipi_metrics.py` +
  the CI `metrics` job) scores against.
- **Per-fix verifiability**: each FP task's acceptance criterion is a concrete
  assertion in the corpus.

### Constrains
- The corpus needs curation whenever a new false-positive class is found.
- Expectations are **verdict-level** (BLOCK vs not, and `ruleId`-specific
  checks), not per-finding counts, so a change in finding counts within a
  verdict is not gated.
- Because the gate runs through the normal `test` job, it shares the suite's
  runtime budget — fixtures stay small.

## Cross-References

- [FP-corpus README](../../samples/fp-corpus/README.md) — fixture → FP class → expected verdict map
- [tests/test_fp_regression.py](../../tests/test_fp_regression.py) — FP-corpus and corpus-wide recall-guard assertions
- [tests/test_samples_detection.py](../../tests/test_samples_detection.py) — per-sample `BLOCK` recall across both malicious corpora
- [Reporting](../domains/reporting.md) — verdicts that the gate asserts on
- [Pattern Matching](../domains/pattern-matching.md) — the FP classes the corpus pins
- [ADR-007: Example-Region Context Engine](007-example-region-context.md) — the FP-5 / FP-11 fix this gate verifies
- [Roadmap §1.3 / §3 T6.1–T6.2](../../docs/development/ipi-check-roadmap.md)
