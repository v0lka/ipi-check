"""Confidence Fusion — Layer 7: merge static + LLM results into final verdict."""
from __future__ import annotations

from ipi_check.core.types import (
    ByteFinding,
    DiscoveredFile,
    FinalVerdict,
    LLMFinding,
    LLMResult,
    PatternFinding,
    Severity,
    SkillFinalVerdict,
    SkillStaticResult,
    StaticResult,
    VerdictDecision,
)

# Confidence threshold above which an LLM `malicious` verdict is treated as high-confidence.
HIGH_CONFIDENCE_THRESHOLD: float = 0.85

# LLM verdict string constants.
_LLM_SAFE: str = "safe"
_LLM_SUSPICIOUS: str = "suspicious"
_LLM_MALICIOUS: str = "malicious"

# Reasoning template fragments.
_REASONING_CRITICAL_TEMPLATE: str = (
    "CRITICAL static finding: {category} — LLM classification skipped"
)
_REASONING_CONSENSUS_TEMPLATE: str = (
    "Static severity {severity} + LLM '{verdict}' (confidence: {confidence:.0%}) — consensus"
)
_REASONING_REVIEW_TEMPLATE: str = (
    "Static severity {severity} but LLM '{verdict}' — manual review recommended"
)
_REASONING_PASS: str = "No significant findings"
_REASONING_COMPROMISED_FALLBACK: str = (
    "LLM classifier compromised — falling back to static analysis only"
)
_REASONING_NO_LLM_FALLBACK: str = (
    "Static-only analysis (LLM not invoked)"
)
_REASONING_NO_CRITICAL_CATEGORY: str = "unknown"


def _first_critical_category(static_result: StaticResult) -> str:
    """Return the category of the first CRITICAL byte/pattern finding."""
    for byte_finding in static_result.byte_findings:
        if byte_finding.severity == Severity.CRITICAL:
            return byte_finding.category.value
    for pattern_finding in static_result.pattern_findings:
        if pattern_finding.severity == Severity.CRITICAL:
            return pattern_finding.category.value
    return _REASONING_NO_CRITICAL_CATEGORY


def _collect_findings(
    static_result: StaticResult,
    llm_result: LLMResult | None,
) -> list[ByteFinding | PatternFinding | LLMFinding]:
    """Collect all findings from static + (non-compromised) LLM results."""
    all_findings: list[ByteFinding | PatternFinding | LLMFinding] = []
    all_findings.extend(static_result.byte_findings)
    all_findings.extend(static_result.pattern_findings)
    if llm_result is not None and not llm_result.compromised:
        all_findings.extend(llm_result.findings)
    return all_findings


def _static_only_decision(severity: Severity) -> VerdictDecision:
    """Resolve a decision using only the static severity."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return VerdictDecision.BLOCK
    if severity == Severity.MEDIUM:
        return VerdictDecision.REVIEW_REQUIRED
    return VerdictDecision.PASS


def _decision_from_matrix(
    severity: Severity,
    llm_verdict: str,
    llm_confidence: float,
) -> VerdictDecision:
    """Resolve a decision using the full static+LLM decision matrix.

    Caller guarantees `severity` is not CRITICAL (CRITICAL is short-circuited
    before LLM evaluation) and that the LLM result is not compromised.
    """
    high_confidence = llm_confidence >= HIGH_CONFIDENCE_THRESHOLD

    if severity == Severity.HIGH:
        if llm_verdict in (_LLM_MALICIOUS, _LLM_SUSPICIOUS):
            return VerdictDecision.BLOCK
        # llm_verdict == safe
        return VerdictDecision.REVIEW_REQUIRED

    if severity == Severity.MEDIUM:
        if llm_verdict == _LLM_MALICIOUS:
            return VerdictDecision.BLOCK if high_confidence else VerdictDecision.REVIEW_REQUIRED
        if llm_verdict == _LLM_SUSPICIOUS:
            return VerdictDecision.REVIEW_REQUIRED
        # llm_verdict == safe
        return VerdictDecision.PASS

    # severity == NONE (or LOW, which is not produced but treated as no-finding)
    if llm_verdict == _LLM_MALICIOUS and high_confidence:
        return VerdictDecision.REVIEW_REQUIRED
    return VerdictDecision.PASS


def _build_reasoning(
    decision: VerdictDecision,
    severity: Severity,
    static_result: StaticResult,
    llm_result: LLMResult | None,
    llm_compromised_fallback: bool,
) -> str:
    """Construct a human-readable reasoning string for the final verdict."""
    if severity == Severity.CRITICAL:
        return _REASONING_CRITICAL_TEMPLATE.format(
            category=_first_critical_category(static_result),
        )

    if llm_compromised_fallback:
        # Static-only fallback because LLM was compromised.
        if decision == VerdictDecision.PASS:
            return _REASONING_PASS
        return _REASONING_COMPROMISED_FALLBACK

    if llm_result is None:
        # LLM never invoked.
        if decision == VerdictDecision.PASS:
            return _REASONING_PASS
        return _REASONING_NO_LLM_FALLBACK

    # LLM invoked successfully.
    if decision == VerdictDecision.BLOCK:
        return _REASONING_CONSENSUS_TEMPLATE.format(
            severity=severity.value,
            verdict=llm_result.verdict,
            confidence=llm_result.confidence,
        )
    if decision == VerdictDecision.REVIEW_REQUIRED:
        return _REASONING_REVIEW_TEMPLATE.format(
            severity=severity.value,
            verdict=llm_result.verdict,
        )
    return _REASONING_PASS


def fuse_verdicts(
    static_result: StaticResult,
    llm_result: LLMResult | None,
) -> FinalVerdict:
    """Fuse static analysis and LLM classification into a deterministic FinalVerdict.

    See the module docstring decision matrix for full rules. CRITICAL static
    severity always blocks (LLM is skipped). A compromised or absent LLM result
    triggers the static-only fallback path.
    """
    severity: Severity = static_result.severity
    file: DiscoveredFile = static_result.file

    all_findings = _collect_findings(static_result, llm_result)

    # Determine effective LLM state.
    llm_compromised = bool(llm_result is not None and llm_result.compromised)
    llm_usable = llm_result is not None and not llm_compromised
    llm_verdict_value: str | None = (
        llm_result.verdict if llm_result is not None and not llm_compromised else None
    )
    llm_confidence_value: float | None = (
        llm_result.confidence if llm_result is not None and not llm_compromised else None
    )

    # Short-circuit: CRITICAL static finding always BLOCKs.
    if severity == Severity.CRITICAL:
        decision = VerdictDecision.BLOCK
        reasoning = _build_reasoning(
            decision=decision,
            severity=severity,
            static_result=static_result,
            llm_result=llm_result,
            llm_compromised_fallback=llm_compromised,
        )
        return FinalVerdict(
            file=file,
            decision=decision,
            static_severity=severity,
            llm_verdict=llm_verdict_value,
            llm_confidence=llm_confidence_value,
            llm_compromised=llm_compromised,
            all_findings=all_findings,
            reasoning=reasoning,
            heuristic_scores=static_result.heuristic_scores,
        )

    # No usable LLM → static-only fallback path.
    if not llm_usable:
        decision = _static_only_decision(severity)
        reasoning = _build_reasoning(
            decision=decision,
            severity=severity,
            static_result=static_result,
            llm_result=llm_result,
            llm_compromised_fallback=llm_compromised,
        )
        return FinalVerdict(
            file=file,
            decision=decision,
            static_severity=severity,
            llm_verdict=None,
            llm_confidence=None,
            llm_compromised=llm_compromised,
            all_findings=all_findings,
            reasoning=reasoning,
            heuristic_scores=static_result.heuristic_scores,
        )

    # Usable LLM result: apply full decision matrix.
    assert llm_result is not None  # noqa: S101 — narrowed by `llm_usable`.
    decision = _decision_from_matrix(
        severity=severity,
        llm_verdict=llm_result.verdict,
        llm_confidence=llm_result.confidence,
    )
    reasoning = _build_reasoning(
        decision=decision,
        severity=severity,
        static_result=static_result,
        llm_result=llm_result,
        llm_compromised_fallback=False,
    )
    return FinalVerdict(
        file=file,
        decision=decision,
        static_severity=severity,
        llm_verdict=llm_result.verdict,
        llm_confidence=llm_result.confidence,
        llm_compromised=False,
        all_findings=all_findings,
        reasoning=reasoning,
        heuristic_scores=static_result.heuristic_scores,
    )


def fuse_skill_verdict(
    skill_static: SkillStaticResult,
    llm_result: LLMResult | None,
) -> SkillFinalVerdict:
    """Fuse static analysis and LLM classification for a skill unit.

    Uses the same decision matrix as :func:`fuse_verdicts`:

    - CRITICAL static severity always → BLOCK (LLM skipped).
    - Otherwise apply the severity+LLM confidence matrix.
    - Compromised or absent LLM → static-only fallback.

    Returns a single :class:`SkillFinalVerdict` for the entire skill.
    """
    severity: Severity = skill_static.aggregate_severity
    skill = skill_static.skill

    # Collect all findings across every file in the skill.
    all_findings: list[ByteFinding | PatternFinding | LLMFinding] = []
    for per_file in skill_static.file_byte_findings:
        all_findings.extend(per_file)
    for per_file in skill_static.file_pattern_findings:
        all_findings.extend(per_file)

    # Determine effective LLM state.
    llm_compromised = bool(llm_result is not None and llm_result.compromised)
    llm_usable = llm_result is not None and not llm_compromised
    llm_verdict_value: str | None = (
        llm_result.verdict if llm_result is not None and not llm_compromised else None
    )
    llm_confidence_value: float | None = (
        llm_result.confidence if llm_result is not None and not llm_compromised else None
    )

    if llm_usable and llm_result is not None:
        all_findings.extend(llm_result.findings)

    # Short-circuit: CRITICAL static finding always BLOCKs.
    if severity == Severity.CRITICAL:
        decision = VerdictDecision.BLOCK
        reasoning = (
            f"CRITICAL static finding in skill "
            f"'{skill.frontmatter.name}' — LLM classification skipped"
        )
    elif not llm_usable:
        # No usable LLM → static-only fallback.
        decision = _static_only_decision(severity)
        if llm_compromised:
            reasoning = _REASONING_COMPROMISED_FALLBACK
        else:
            reasoning = _REASONING_NO_LLM_FALLBACK
    else:
        # Usable LLM: apply full decision matrix.
        assert llm_result is not None  # noqa: S101 — narrowed by `llm_usable`.
        decision = _decision_from_matrix(
            severity=severity,
            llm_verdict=llm_result.verdict,
            llm_confidence=llm_result.confidence,
        )
        if decision == VerdictDecision.BLOCK:
            reasoning = _REASONING_CONSENSUS_TEMPLATE.format(
                severity=severity.value,
                verdict=llm_result.verdict,
                confidence=llm_result.confidence,
            )
        elif decision == VerdictDecision.REVIEW_REQUIRED:
            reasoning = _REASONING_REVIEW_TEMPLATE.format(
                severity=severity.value,
                verdict=llm_result.verdict,
            )
        else:
            reasoning = _REASONING_PASS

    return SkillFinalVerdict(
        skill=skill,
        decision=decision,
        static_severity=severity,
        llm_verdict=llm_verdict_value,
        llm_confidence=llm_confidence_value,
        llm_compromised=llm_compromised,
        all_findings=all_findings,
        reasoning=reasoning,
    )
