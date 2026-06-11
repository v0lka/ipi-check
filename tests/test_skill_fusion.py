"""Tests for fuse_skill_verdict() decision logic."""
from __future__ import annotations

from pathlib import Path

from ipi_check.core.types import (
    DiscoveredFile,
    FileCategory,
    HeuristicScores,
    LLMFinding,
    LLMResult,
    PatternFinding,
    PatternFindingCategory,
    Severity,
    SkillFrontmatter,
    SkillStaticResult,
    SkillUnit,
    VerdictDecision,
)
from ipi_check.scanner.confidence_fusion import fuse_skill_verdict


def _make_skill_static_result(
    tmp_path: Path,
    severity: Severity,
    name: str = "test-skill",
) -> SkillStaticResult:
    """Build a SkillStaticResult with the given severity."""
    skill_path = tmp_path / "SKILL.md"
    skill_path.write_text(
        f"---\nname: {name}\ndescription: Test.\n---\n# Body\n"
    )
    mf = DiscoveredFile(
        path=skill_path, category=FileCategory.SKILL,
        relative_path="SKILL.md", size_bytes=skill_path.stat().st_size,
    )
    skill = SkillUnit(
        root=tmp_path,
        metadata_file=mf,
        files=[mf],
        frontmatter=SkillFrontmatter(name=name, description="Test."),
        body="# Body\n",
    )
    return SkillStaticResult(
        skill=skill,
        file_byte_findings=[[]],
        file_pattern_findings=[[]],
        metadata_heuristic_scores=HeuristicScores(
            entropy=0.0, entropy_suspicious=False,
            invisible_ratio=0.0, invisible_suspicious=False,
            instruction_density=0.0, instruction_density_suspicious=False,
            contradiction_score=0.0, contradiction_suspicious=False,
            suspicious_count=0,
        ),
        aggregate_severity=severity,
    )


def _llm(verdict: str, confidence: float) -> LLMResult:
    return LLMResult(
        verdict=verdict, confidence=confidence,
        findings=[LLMFinding(line=1, category="test", explanation="x")],
        compromised=False,
    )


class TestFuseSkillVerdict:
    """Tests for fuse_skill_verdict() decision matrix."""

    def test_critical_static_always_block(self, tmp_path: Path) -> None:
        """CRITICAL static severity → BLOCK, LLM is effectively skipped."""
        ssr = _make_skill_static_result(tmp_path, Severity.CRITICAL)
        verdict = fuse_skill_verdict(ssr, _llm("safe", 0.9))
        assert verdict.decision == VerdictDecision.BLOCK
        # LLM classification is skipped (reason says so).
        assert "LLM classification skipped" in verdict.reasoning
        assert verdict.static_severity == Severity.CRITICAL

    def test_critical_static_llm_none(self, tmp_path: Path) -> None:
        """CRITICAL + None LLM → BLOCK."""
        ssr = _make_skill_static_result(tmp_path, Severity.CRITICAL)
        verdict = fuse_skill_verdict(ssr, None)
        assert verdict.decision == VerdictDecision.BLOCK

    def test_high_plus_malicious_llm_block(self, tmp_path: Path) -> None:
        """HIGH static + malicious LLM → BLOCK."""
        ssr = _make_skill_static_result(tmp_path, Severity.HIGH)
        verdict = fuse_skill_verdict(ssr, _llm("malicious", 0.9))
        assert verdict.decision == VerdictDecision.BLOCK
        assert verdict.llm_verdict == "malicious"

    def test_high_plus_safe_llm_review(self, tmp_path: Path) -> None:
        """HIGH static + safe LLM → REVIEW_REQUIRED."""
        ssr = _make_skill_static_result(tmp_path, Severity.HIGH)
        verdict = fuse_skill_verdict(ssr, _llm("safe", 0.9))
        assert verdict.decision == VerdictDecision.REVIEW_REQUIRED

    def test_medium_malicious_high_confidence_block(self, tmp_path: Path) -> None:
        """MEDIUM + malicious (high confidence) → BLOCK."""
        ssr = _make_skill_static_result(tmp_path, Severity.MEDIUM)
        verdict = fuse_skill_verdict(ssr, _llm("malicious", 0.95))
        assert verdict.decision == VerdictDecision.BLOCK

    def test_medium_malicious_low_confidence_review(self, tmp_path: Path) -> None:
        """MEDIUM + malicious (low confidence) → REVIEW_REQUIRED."""
        ssr = _make_skill_static_result(tmp_path, Severity.MEDIUM)
        verdict = fuse_skill_verdict(ssr, _llm("malicious", 0.3))
        assert verdict.decision == VerdictDecision.REVIEW_REQUIRED

    def test_none_plus_safe_pass(self, tmp_path: Path) -> None:
        """NONE static + safe LLM → PASS."""
        ssr = _make_skill_static_result(tmp_path, Severity.NONE)
        verdict = fuse_skill_verdict(ssr, _llm("safe", 0.9))
        assert verdict.decision == VerdictDecision.PASS

    def test_none_plus_none_llm_pass(self, tmp_path: Path) -> None:
        """NONE static + None LLM → PASS (static-only fallback)."""
        ssr = _make_skill_static_result(tmp_path, Severity.NONE)
        verdict = fuse_skill_verdict(ssr, None)
        assert verdict.decision == VerdictDecision.PASS

    def test_compromised_llm_static_only_fallback(self, tmp_path: Path) -> None:
        """Compromised LLM → treated as if LLM were absent (static-only fallback)."""
        ssr = _make_skill_static_result(tmp_path, Severity.HIGH)
        compromised = LLMResult(
            verdict="malicious", confidence=0.99, findings=[], compromised=True
        )
        verdict = fuse_skill_verdict(ssr, compromised)
        assert verdict.llm_compromised is True
        # HIGH + None LLM → BLOCK (per _static_only_decision).
        assert verdict.decision == VerdictDecision.BLOCK

    def test_verdict_includes_all_findings(self, tmp_path: Path) -> None:
        """SkillFinalVerdict collects all findings from byte and pattern results."""
        # Create a pattern finding manually.
        finding = PatternFinding(
            category=PatternFindingCategory.REMOTE_EXECUTION,
            severity=Severity.CRITICAL,
            line=1, column=1, matched_text="curl | bash",
            pattern_id="IPI401",
            description="Remote execution detected",
        )
        ssr = _make_skill_static_result(tmp_path, Severity.CRITICAL)
        ssr.file_pattern_findings = [[finding]]
        verdict = fuse_skill_verdict(ssr, None)
        assert len(verdict.all_findings) >= 1
        assert any(
            getattr(f, "pattern_id", None) == "IPI401" for f in verdict.all_findings
        )
