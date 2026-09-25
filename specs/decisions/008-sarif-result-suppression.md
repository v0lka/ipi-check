# ADR-008: Deterministic Result Suppression and Limiting in SARIF

## Status

Accepted

## Context

Before this decision the reporter emitted one SARIF result per raw finding,
with no deduplication and no bound on output size. On a real repository scan
this produced **1040 `IPI006` results out of 1087 total** — the vast majority
repeats of the same false-positive signal — collapsing signal-to-noise to
roughly 9 actionable results per 1087 (roadmap §0).

Three distinct problems share one root cause — the reporter had no notion of
which results are worth keeping:

- **FP-4**: identical findings (same rule, same location, same payload) were
  emitted repeatedly; no per-file limit existed.
- **FP-13**: standalone heuristic notices (`IPI201`–`IPI204`) were emitted even
  for `PASS` verdicts, surfacing noise on clean files.
- **IN-5**: there was no severity floor, so a caller could not ask for
  "CRITICAL/HIGH only" without post-processing the SARIF.

Constraints: the funnel must be **deterministic** (invariant F003) and must
never *silently* discard results, and the SARIF output must stay a valid v2.1.0
document (ADR-002).

## Decision

Apply four ordered, deterministic transforms to the `results` array immediately
before the SARIF document is assembled:

1. **Severity threshold.** A finding whose severity falls below
   `severity_threshold` (CLI `--severity-threshold`; default
   `DEFAULT_SEVERITY_THRESHOLD = NONE`, i.e. keep everything) is dropped
   *before* deduplication, so it is never miscounted as a duplicate. Skill-level
   aggregate results are exempt.
2. **Heuristic gating.** Standalone heuristic notices (`IPI201`–`IPI204`) are
   emitted only for non-`PASS` verdicts. A `PASS` decision means the fused
   analysis found nothing actionable, so heuristic notices are suppressed to
   keep clean files quiet.
3. **Deduplication.** Results identical in
   `(ruleId, artifactLocation.uri, startLine, startColumn, snippet)` collapse to
   their first occurrence. The snippet component is the raw finding payload
   (`snippet_hex` for byte findings, `matched_text` for pattern findings,
   `category`/`explanation` for LLM findings).
4. **Per-file cap.** Each artifact contributes at most
   `DEFAULT_MAX_FINDINGS_PER_FILE` (50) results — CLI
   `--max-findings-per-file`; `0` disables the limit. The first occurrence of
   every distinct `ruleId` in the file is always retained, so the set of
   emitted rule IDs stays stable.

Every suppressed result is counted in a `SarifLimitStats`
(`duplicates_removed`, `capped_removed`, `below_threshold_removed`) returned by
`generate_sarif_with_stats()` and printed to stderr by the CLI — suppression is
observable, never silent.

## Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| **No limiting (status quo)** | Trivial | ~1000 duplicate results; unusable signal-to-noise; consumers drown | The problem this ADR exists to solve |
| **Drop findings at detection time** | Smaller intermediate data | Loses information before fusion; couples suppression policy into every scanner layer; harder to report counts | Suppression is a *reporting* concern; keeping findings until the reporter preserves layer independence |
| **Rely on the SARIF `suppressions` array only** | Standards-shaped | Consumer support for `suppressions` varies; does not bound output size (duplicates still emitted) | Does not solve output bloat; kept as a possible future complement |
| **Greedy per-file cap (first N results)** | Simple | The emitted `ruleId` set becomes position-dependent and unstable across runs | Violates determinism/stability; the rule-ID preservation rule avoids it |
| **Four-rule ordered funnel (chosen)** | Bounded output; deterministic; counts visible; skill results preserved | Fixed default cap (50) may hide low-priority findings; rule order matters | **Chosen.** Bounds noise while keeping every distinct signal and surfacing counts |

## Consequences

### Enables
- **Bounded, signal-rich output**: a scan emits tens of meaningful results
  instead of thousands of duplicates (target ~30–60, roadmap §5).
- **Configurable severity floor**: `--severity-threshold` lets CI surface only
  what matters without post-processing.
- **Quiet clean files**: `PASS` files carry no heuristic noise.
- **Auditability**: `SarifLimitStats` on stderr makes every suppression
  countable.

### Constrains
- Result order is significant: the threshold runs before dedup so a
  below-threshold finding is never miscounted as a duplicate.
- The default cap (`50`) is a policy choice; callers who want everything pass
  `--max-findings-per-file 0`.
- Skill-level aggregate results bypass the threshold, so a skill can still be
  reported even under a high threshold.

## Cross-References

- [Reporting](../domains/reporting.md) — invariants R009 (dedup + cap) and R010 (severity threshold)
- [CLI Interface](../contracts/cli-interface.md) — `--max-findings-per-file`, `--severity-threshold`
- [ADR-002: SARIF Format](002-sarif-format.md) — output stays a valid SARIF v2.1.0 document
- [Roadmap §1.1 / §3 T0.4, T5.4](../../docs/development/ipi-check-roadmap.md)
