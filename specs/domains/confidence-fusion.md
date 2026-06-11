# Confidence Fusion

## Responsibility

Merge static analysis results (byte findings, pattern matches, heuristic scores) with LLM classification results into a single, deterministic final verdict per file or per skill unit: `BLOCK`, `REVIEW_REQUIRED`, or `PASS`. This module is the decision point of the pipeline. Two fusion paths exist: `fuse_verdicts()` for individual files and `fuse_skill_verdict()` for complete skill units.

## Input

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `file` | `DiscoveredFile` | File Discovery | File metadata |
| `byte_findings` | `List[ByteFinding]` | Byte-Level Analysis | Hidden-content findings |
| `pattern_findings` | `List[PatternFinding]` | Pattern Matching | Regex-matched injection findings |
| `heuristic_scores` | `HeuristicScores` | Semantic Heuristics | Suspicion metrics |
| `llm_result` | `LLMResult \| None` | LLM Classifier | LLM classification (None if Case 1 only or LLM skipped due to CRITICAL) |

## Output

| Field | Type | Consumers | Description |
|-------|------|-----------|-------------|
| `verdict` | `FinalVerdict` | SARIF Reporter | Final decision for a single file |
| `verdict` | `SkillFinalVerdict` | SARIF Reporter | Final decision for a complete skill unit |

```python
@dataclass
class FinalVerdict:
    file: DiscoveredFile
    decision: str           # "BLOCK" | "REVIEW_REQUIRED" | "PASS"
    static_severity: str    # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE"
    llm_verdict: str | None  # LLM verdict if available
    llm_confidence: float | None
    llm_compromised: bool   # True if LLM was invoked but failed
    all_findings: List[ByteFinding | PatternFinding | LLMFinding]
    reasoning: str          # Human-readable explanation of the decision

@dataclass
class SkillFinalVerdict:
    skill: SkillUnit
    decision: VerdictDecision
    static_severity: Severity
    llm_verdict: str | None
    llm_confidence: float | None
    llm_compromised: bool
    all_findings: list[ByteFinding | PatternFinding | LLMFinding]
    reasoning: str
```

## Behavior

```
StaticResult + LLMResult?
        │
        ▼
┌───────────────────────────────┐
│ 1. Compute Static Severity    │
│    From byte + pattern +      │
│    heuristic findings:        │
│    - Any CRITICAL byte/pat?   │
│      → CRITICAL               │
│    - Any HIGH byte/pat?       │
│      → HIGH                   │
│    - heuristic_suspicious_count│
│      ≥ 2 → HIGH               │
│    - Any MEDIUM findings?     │
│      → MEDIUM                  │
│    - Otherwise → NONE          │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│ 2. Apply Fusion Rules         │
│    See decision matrix below  │
└───────────────┬───────────────┘
                │
                ▼
          FinalVerdict
```

### Static Severity Computation

```
severity = NONE
if any byte_finding.severity == "CRITICAL" or any pattern_finding.severity == "CRITICAL":
    severity = CRITICAL
elif any byte_finding.severity == "HIGH" or any pattern_finding.severity == "HIGH":
    severity = HIGH
elif heuristic_scores.suspicious_count >= 2:
    severity = HIGH
elif any byte_finding or any pattern_finding:
    severity = MEDIUM
else:
    severity = NONE
```

### Decision Matrix

| Static Severity | LLM Verdict | LLM Confidence | Result |
|-----------------|-------------|-----------------|--------|
| CRITICAL | (skipped) | — | **BLOCK** |
| HIGH | `malicious` | any | **BLOCK** |
| HIGH | `suspicious` | any | **BLOCK** |
| HIGH | `safe` | any | **REVIEW_REQUIRED** |
| MEDIUM | `malicious` | ≥ 0.85 | **BLOCK** |
| MEDIUM | `malicious` | < 0.85 | **REVIEW_REQUIRED** |
| MEDIUM | `suspicious` | any | **REVIEW_REQUIRED** |
| MEDIUM | `safe` | any | **PASS** |
| MEDIUM | (no LLM) | — | **REVIEW_REQUIRED** |
| NONE | `malicious` | ≥ 0.85 | **REVIEW_REQUIRED** |
| NONE | `malicious` | < 0.85 | **PASS** |
| NONE | `suspicious` | any | **PASS** |
| NONE | `safe` | any | **PASS** |
| NONE | (no LLM) | — | **PASS** |
| any | `compromised` | — | Fallback: use static severity as if no LLM |

### Skill Verdict Fusion

`fuse_skill_verdict()` applies the same decision matrix to skill units. The key differences from `fuse_verdicts()`:

- Input is a `SkillStaticResult` (aggregated across all files in the skill) instead of per-file findings
- All findings across all files in the skill are flattened into a single findings list
- CRITICAL static severity on any file in the skill triggers immediate BLOCK (LLM skipped)
- The decision matrix is identical — same severity × LLM verdict × confidence rules apply

### Reasoning Generation

For each decision, a human-readable reasoning string is constructed:

- **BLOCK (CRITICAL static)**: "CRITICAL static finding: {category} — LLM classification skipped"
- **BLOCK (CRITICAL static in skill)**: "CRITICAL static finding in skill '{name}' — LLM classification skipped"
- **BLOCK (static+LLM agree)**: "Static severity {severity} + LLM '{verdict}' (confidence: {confidence:.0%}) — consensus"
- **REVIEW_REQUIRED**: "Static severity {severity} but LLM '{verdict}' — manual review recommended"
- **PASS**: "No significant findings"

## Edge Cases

| Case | Handling |
|------|----------|
| CRITICAL static finding (always blocks) | LLM is not invoked; verdict = BLOCK |
| LLM was not invoked (Case 1 only) | Use static-only fallback: MEDIUM → REVIEW_REQUIRED, NONE → PASS |
| LLM was invoked but `compromised=True` | Fall back to static-only logic, flag `llm_compromised=True` |
| Multiple findings of different severities | Static severity is the maximum of all findings |
| Heuristic scores suspicious but no byte/pattern findings | `suspicious_count >= 2` raises severity to HIGH, influencing the decision |
| Skill with CRITICAL static finding on any file | Entire skill verdict is BLOCK; LLM skipped for the skill |
| Skill with no CRITICAL finding but HIGH on a bundled script | Skill aggregate severity is HIGH; LLM is consulted, fusion matrix applies |

## Dependencies

- **File Discovery**: receives `DiscoveredFile` (for per-file verdicts) and `SkillUnit` (for skill verdicts)
- **Byte-Level Analysis**: receives `ByteFinding` list
- **Pattern Matching**: receives `PatternFinding` list
- **Semantic Heuristics**: receives `HeuristicScores`
- **LLM Classifier**: receives `LLMResult` (or None)
- **SARIF Reporter**: produces `FinalVerdict` and `SkillFinalVerdict`

## Invariants

- **F001**: If `static_severity == CRITICAL`, the decision MUST be `BLOCK` — no LLM result can override a CRITICAL static finding. This applies to both per-file and per-skill fusion.
- **F002**: If `llm_result.compromised == True`, the fusion MUST fall back to static-only logic and ignore `llm_result.verdict` and `llm_result.confidence`.
- **F003**: The decision matrix is deterministic — given the same inputs, the same decision MUST be produced every time.
- **F004**: An LLM `malicious` verdict with confidence < 0.85 MUST NOT produce `BLOCK` on its own — it requires static corroboration (MEDIUM or higher).
- **F005**: An LLM `safe` verdict MUST NOT override HIGH static severity — the result is `REVIEW_REQUIRED`, not `PASS`.
- **F006**: `fuse_skill_verdict()` MUST use the same decision matrix as `fuse_verdicts()` — skill verdicts follow identical severity × LLM verdict × confidence rules.

## Cross-References

- [System Overview](../architecture/system-overview.md)
- [Security Model](../architecture/security-model.md) — AV1: LLM Classifier Prompt Injection
- [Byte-Level Analysis](byte-analysis.md)
- [Pattern Matching](pattern-matching.md)
- [Semantic Heuristics](semantic-heuristics.md)
- [LLM Classifier](llm-classifier.md)
- [Reporting](reporting.md)
