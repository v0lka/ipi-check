"""Tests for confidence_fusion module."""
from __future__ import annotations

from pathlib import Path

from ipi_check.core.types import (
    ByteFinding,
    ByteFindingCategory,
    CompromisedReason,
    DiscoveredFile,
    FileCategory,
    HeuristicScores,
    LLMResult,
    PatternFinding,
    PatternFindingCategory,
    Severity,
    StaticResult,
    VerdictDecision,
)
from ipi_check.scanner.confidence_fusion import fuse_verdicts


def _file(tmp_path: Path) -> DiscoveredFile:
    p = tmp_path / "f.md"
    p.write_text("ph")
    return DiscoveredFile(
        path=p, category=FileCategory.AGENT_INSTRUCTION,
        relative_path="f.md", size_bytes=2,
    )


def _scores(suspicious: int = 0) -> HeuristicScores:
    return HeuristicScores(
        entropy=0.0, entropy_suspicious=False,
        invisible_ratio=0.0, invisible_suspicious=False,
        instruction_density=0.0, instruction_density_suspicious=False,
        contradiction_score=0.0, contradiction_suspicious=False,
        suspicious_count=suspicious,
    )


def _byte(severity: Severity) -> ByteFinding:
    return ByteFinding(
        category=ByteFindingCategory.ANSI_HIDDEN, severity=severity, line=1, column=1,
        snippet_hex="00", description="d",
    )


def _pattern(severity: Severity) -> PatternFinding:
    return PatternFinding(
        category=PatternFindingCategory.INSTRUCTION_OVERRIDE, severity=severity,
        line=1, column=1, matched_text="x", pattern_id="P1", description="d",
    )


def _static(
    tmp_path: Path,
    severity: Severity,
    *,
    byte: list[ByteFinding] | None = None,
    patt: list[PatternFinding] | None = None,
) -> StaticResult:
    return StaticResult(
        file=_file(tmp_path),
        byte_findings=byte or [],
        pattern_findings=patt or [],
        heuristic_scores=_scores(),
        severity=severity,
    )


def _llm(
    verdict: str,
    confidence: float,
    *,
    compromised: bool = False,
    reason: CompromisedReason | None = None,
) -> LLMResult:
    return LLMResult(
        verdict=verdict,
        confidence=confidence,
        compromised=compromised,
        compromised_reason=reason,
    )


class TestFuseVerdicts:
    def test_critical_blocks_regardless(self, tmp_path: Path) -> None:
        sr = _static(tmp_path, Severity.CRITICAL, byte=[_byte(Severity.CRITICAL)])
        for verdict in ("safe", "suspicious", "malicious"):
            res = fuse_verdicts(sr, _llm(verdict, 0.99))
            assert res.decision == VerdictDecision.BLOCK
        # Even with no LLM
        assert fuse_verdicts(sr, None).decision == VerdictDecision.BLOCK

    def test_high_with_malicious(self, tmp_path: Path) -> None:
        sr = _static(tmp_path, Severity.HIGH, patt=[_pattern(Severity.HIGH)])
        assert fuse_verdicts(sr, _llm("malicious", 0.9)).decision == VerdictDecision.BLOCK

    def test_high_with_suspicious(self, tmp_path: Path) -> None:
        sr = _static(tmp_path, Severity.HIGH, patt=[_pattern(Severity.HIGH)])
        assert fuse_verdicts(sr, _llm("suspicious", 0.5)).decision == VerdictDecision.BLOCK

    def test_high_with_safe(self, tmp_path: Path) -> None:
        sr = _static(tmp_path, Severity.HIGH, patt=[_pattern(Severity.HIGH)])
        assert fuse_verdicts(sr, _llm("safe", 0.9)).decision == VerdictDecision.REVIEW_REQUIRED

    def test_medium_with_malicious_high_conf(self, tmp_path: Path) -> None:
        sr = _static(tmp_path, Severity.MEDIUM, byte=[_byte(Severity.MEDIUM)])
        assert fuse_verdicts(sr, _llm("malicious", 0.85)).decision == VerdictDecision.BLOCK
        assert fuse_verdicts(sr, _llm("malicious", 0.95)).decision == VerdictDecision.BLOCK

    def test_medium_with_malicious_low_conf(self, tmp_path: Path) -> None:
        sr = _static(tmp_path, Severity.MEDIUM, byte=[_byte(Severity.MEDIUM)])
        assert fuse_verdicts(sr, _llm("malicious", 0.5)).decision == VerdictDecision.REVIEW_REQUIRED

    def test_medium_with_suspicious(self, tmp_path: Path) -> None:
        sr = _static(tmp_path, Severity.MEDIUM, byte=[_byte(Severity.MEDIUM)])
        verdict = fuse_verdicts(sr, _llm("suspicious", 0.5))
        assert verdict.decision == VerdictDecision.REVIEW_REQUIRED

    def test_medium_with_safe(self, tmp_path: Path) -> None:
        sr = _static(tmp_path, Severity.MEDIUM, byte=[_byte(Severity.MEDIUM)])
        assert fuse_verdicts(sr, _llm("safe", 0.5)).decision == VerdictDecision.PASS

    def test_medium_no_llm(self, tmp_path: Path) -> None:
        sr = _static(tmp_path, Severity.MEDIUM, byte=[_byte(Severity.MEDIUM)])
        assert fuse_verdicts(sr, None).decision == VerdictDecision.REVIEW_REQUIRED

    def test_none_with_malicious_high_conf(self, tmp_path: Path) -> None:
        sr = _static(tmp_path, Severity.NONE)
        assert fuse_verdicts(sr, _llm("malicious", 0.9)).decision == VerdictDecision.REVIEW_REQUIRED

    def test_none_with_malicious_low_conf(self, tmp_path: Path) -> None:
        sr = _static(tmp_path, Severity.NONE)
        assert fuse_verdicts(sr, _llm("malicious", 0.5)).decision == VerdictDecision.PASS

    def test_none_with_suspicious(self, tmp_path: Path) -> None:
        sr = _static(tmp_path, Severity.NONE)
        assert fuse_verdicts(sr, _llm("suspicious", 0.99)).decision == VerdictDecision.PASS

    def test_none_with_safe(self, tmp_path: Path) -> None:
        sr = _static(tmp_path, Severity.NONE)
        assert fuse_verdicts(sr, _llm("safe", 0.99)).decision == VerdictDecision.PASS

    def test_none_no_llm(self, tmp_path: Path) -> None:
        sr = _static(tmp_path, Severity.NONE)
        assert fuse_verdicts(sr, None).decision == VerdictDecision.PASS

    def test_compromised_llm_falls_back_to_static(self, tmp_path: Path) -> None:
        sr = _static(tmp_path, Severity.HIGH, patt=[_pattern(Severity.HIGH)])
        compromised = _llm("safe", 0.0, compromised=True)
        result = fuse_verdicts(sr, compromised)
        # HIGH static-only → BLOCK
        assert result.decision == VerdictDecision.BLOCK
        assert result.llm_compromised is True
        assert result.llm_verdict is None
        assert "compromised" in result.reasoning.lower() or "static" in result.reasoning.lower()

    def test_compromised_llm_none_severity_passes(self, tmp_path: Path) -> None:
        sr = _static(tmp_path, Severity.NONE)
        compromised = _llm("safe", 0.0, compromised=True)
        result = fuse_verdicts(sr, compromised)
        assert result.decision == VerdictDecision.PASS
        assert result.llm_compromised is True

    def test_determinism(self, tmp_path: Path) -> None:
        sr = _static(tmp_path, Severity.MEDIUM, byte=[_byte(Severity.MEDIUM)])
        llm = _llm("malicious", 0.9)
        a = fuse_verdicts(sr, llm)
        b = fuse_verdicts(sr, llm)
        assert a.decision == b.decision
        assert a.reasoning == b.reasoning
        assert a.static_severity == b.static_severity


class TestInjectionSuspectedEscalation:
    """An injection-suspected compromised LLM must never yield PASS (IN-15)."""

    def test_injection_suspected_none_severity_reviews(self, tmp_path: Path) -> None:
        sr = _static(tmp_path, Severity.NONE)
        suspected = _llm(
            "safe", 0.0,
            compromised=True,
            reason=CompromisedReason.INJECTION_SUSPECTED,
        )
        result = fuse_verdicts(sr, suspected)
        assert result.decision == VerdictDecision.REVIEW_REQUIRED
        assert result.decision != VerdictDecision.PASS
        assert result.llm_compromised is True
        assert "inject" in result.reasoning.lower()

    def test_plain_provider_error_none_severity_still_passes(self, tmp_path: Path) -> None:
        """A mere provider error is not an attack signal → static-only PASS."""
        sr = _static(tmp_path, Severity.NONE)
        failed = _llm(
            "safe", 0.0,
            compromised=True,
            reason=CompromisedReason.PROVIDER_ERROR,
        )
        result = fuse_verdicts(sr, failed)
        assert result.decision == VerdictDecision.PASS

    def test_injection_suspected_does_not_downgrade_review(self, tmp_path: Path) -> None:
        sr = _static(tmp_path, Severity.MEDIUM, byte=[_byte(Severity.MEDIUM)])
        suspected = _llm(
            "safe", 0.0,
            compromised=True,
            reason=CompromisedReason.INJECTION_SUSPECTED,
        )
        result = fuse_verdicts(sr, suspected)
        assert result.decision == VerdictDecision.REVIEW_REQUIRED


class TestFramedAgentFindingFloor:
    """A framed (example-region-capped) finding in an agent-instruction file
    must never fuse to PASS: the framing there is attacker-writable prose, so
    a fooled "safe" LLM verdict cannot silence it (ADR-007)."""

    def _framed_pattern(self, severity: Severity) -> PatternFinding:
        return PatternFinding(
            category=PatternFindingCategory.INSTRUCTION_OVERRIDE,
            severity=severity,
            line=1,
            column=1,
            matched_text="x",
            pattern_id="P1",
            description="d",
            framed=True,
        )

    def test_framed_medium_with_safe_llm_is_review(self, tmp_path: Path) -> None:
        sr = _static(
            tmp_path, Severity.MEDIUM, patt=[self._framed_pattern(Severity.MEDIUM)]
        )
        assert fuse_verdicts(sr, _llm("safe", 0.99)).decision == VerdictDecision.REVIEW_REQUIRED

    def test_framed_medium_static_only_is_review(self, tmp_path: Path) -> None:
        sr = _static(
            tmp_path, Severity.MEDIUM, patt=[self._framed_pattern(Severity.MEDIUM)]
        )
        assert fuse_verdicts(sr, None).decision == VerdictDecision.REVIEW_REQUIRED

    def test_unframed_medium_with_safe_llm_still_passes(self, tmp_path: Path) -> None:
        sr = _static(tmp_path, Severity.MEDIUM, patt=[_pattern(Severity.MEDIUM)])
        assert fuse_verdicts(sr, _llm("safe", 0.9)).decision == VerdictDecision.PASS

    def test_framed_source_file_not_floored(self, tmp_path: Path) -> None:
        # The floor is scoped to agent-instruction files: a framed [STR]
        # finding in source code keeps the ordinary matrix (MEDIUM + safe ->
        # PASS) — the string literal is syntactically data, not framing prose.
        p = tmp_path / "f.js"
        p.write_text("x")
        sr = StaticResult(
            file=DiscoveredFile(
                path=p, category=FileCategory.SOURCE_CODE,
                relative_path="f.js", size_bytes=1,
            ),
            byte_findings=[],
            pattern_findings=[self._framed_pattern(Severity.MEDIUM)],
            heuristic_scores=_scores(),
            severity=Severity.MEDIUM,
        )
        assert fuse_verdicts(sr, _llm("safe", 0.9)).decision == VerdictDecision.PASS
