"""Tests for fuse_skill_verdict() decision logic."""
from __future__ import annotations

from pathlib import Path

from ipi_check.core.types import (
    CompromisedReason,
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
from ipi_check.scanner.static_result import compute_skill_static_result


def _make_skill_static_result(
    tmp_path: Path,
    severity: Severity,
    name: str = "test-skill",
    *,
    pattern_findings: list[PatternFinding] | None = None,
) -> SkillStaticResult:
    """Build a SkillStaticResult with the given severity.

    ``pattern_findings`` are attached to the SKILL.md entry so that the
    "significance" derivation (which finding drove the severity) can be
    exercised.
    """
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
        file_pattern_findings=[list(pattern_findings or [])],
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


class TestSkillInjectionSuspectedEscalation:
    """An injection-suspected skill LLM result must never yield PASS (IN-15)."""

    def test_injection_suspected_none_severity_reviews(self, tmp_path: Path) -> None:
        ssr = _make_skill_static_result(tmp_path, Severity.NONE)
        suspected = LLMResult(
            verdict="safe", confidence=0.0, findings=[], compromised=True,
            compromised_reason=CompromisedReason.INJECTION_SUSPECTED,
        )
        verdict = fuse_skill_verdict(ssr, suspected)
        assert verdict.decision == VerdictDecision.REVIEW_REQUIRED
        assert verdict.llm_compromised is True
        assert "inject" in verdict.reasoning.lower()

    def test_provider_error_none_severity_still_passes(self, tmp_path: Path) -> None:
        ssr = _make_skill_static_result(tmp_path, Severity.NONE)
        failed = LLMResult(
            verdict="safe", confidence=0.0, findings=[], compromised=True,
            compromised_reason=CompromisedReason.PROVIDER_ERROR,
        )
        verdict = fuse_skill_verdict(ssr, failed)
        assert verdict.decision == VerdictDecision.PASS


def _sig_pattern(
    severity: Severity,
    pattern_id: str = "IPI405",
    category: PatternFindingCategory = PatternFindingCategory.EXCESSIVE_PERMISSIONS,
) -> PatternFinding:
    return PatternFinding(
        category=category,
        severity=severity,
        line=1,
        column=1,
        matched_text="allowed-tools: bash(*)",
        pattern_id=pattern_id,
        description="test finding",
    )


class TestSkillSignificanceInReasoning:
    """"Significance" — which finding caused HIGH/CRITICAL — appears in reasoning.

    A skill's aggregate severity is auditable: the reasoning names the exact
    significant finding (rule + category + file) that drove the verdict
    (FP-14).
    """

    def test_high_safe_llm_reviews_and_names_significance(
        self, tmp_path: Path
    ) -> None:
        """HIGH static + safe LLM → REVIEW, naming the triggering finding."""
        ssr = _make_skill_static_result(
            tmp_path, Severity.HIGH, pattern_findings=[_sig_pattern(Severity.HIGH)]
        )
        verdict = fuse_skill_verdict(ssr, _llm("safe", 0.9))
        assert verdict.decision == VerdictDecision.REVIEW_REQUIRED
        assert "IPI405" in verdict.reasoning
        assert "SKILL.md" in verdict.reasoning

    def test_high_malicious_llm_block_names_significance(self, tmp_path: Path) -> None:
        """HIGH static + malicious LLM → BLOCK, naming the triggering finding."""
        ssr = _make_skill_static_result(
            tmp_path, Severity.HIGH, pattern_findings=[_sig_pattern(Severity.HIGH)]
        )
        verdict = fuse_skill_verdict(ssr, _llm("malicious", 0.9))
        assert verdict.decision == VerdictDecision.BLOCK
        assert "IPI405" in verdict.reasoning

    def test_critical_reasoning_names_significance(self, tmp_path: Path) -> None:
        """CRITICAL short-circuit → BLOCK, naming the triggering finding."""
        finding = _sig_pattern(
            Severity.CRITICAL,
            pattern_id="IPI401",
            category=PatternFindingCategory.REMOTE_EXECUTION,
        )
        ssr = _make_skill_static_result(
            tmp_path, Severity.CRITICAL, pattern_findings=[finding]
        )
        verdict = fuse_skill_verdict(ssr, None)
        assert verdict.decision == VerdictDecision.BLOCK
        assert "LLM classification skipped" in verdict.reasoning
        assert "IPI401" in verdict.reasoning

    def test_static_only_high_reasoning_names_significance(
        self, tmp_path: Path
    ) -> None:
        """Static-only HIGH (no LLM) → BLOCK, naming the triggering finding."""
        ssr = _make_skill_static_result(
            tmp_path, Severity.HIGH, pattern_findings=[_sig_pattern(Severity.HIGH)]
        )
        verdict = fuse_skill_verdict(ssr, None)
        assert verdict.decision == VerdictDecision.BLOCK
        assert "IPI405" in verdict.reasoning

    def test_medium_without_significant_finding_stays_plain(
        self, tmp_path: Path
    ) -> None:
        """A MEDIUM skill has no significant finding → plain reasoning/no review."""
        ssr = _make_skill_static_result(tmp_path, Severity.MEDIUM)
        verdict = fuse_skill_verdict(ssr, _llm("safe", 0.9))
        # MEDIUM static + safe LLM → PASS (the FP-14 acceptance case).
        assert verdict.decision == VerdictDecision.PASS
        assert verdict.reasoning == "No significant findings"


def _real_skill(
    tmp_path: Path,
    name: str,
    skill_md: str,
    bundled: dict[str, bytes] | None = None,
) -> SkillUnit:
    """Build a real on-disk SkillUnit from raw content."""
    skill_path = tmp_path / "SKILL.md"
    skill_path.write_text(skill_md)
    metadata_file = DiscoveredFile(
        path=skill_path,
        category=FileCategory.SKILL,
        relative_path="SKILL.md",
        size_bytes=skill_path.stat().st_size,
    )
    files = [metadata_file]
    for rel, payload in (bundled or {}).items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        files.append(
            DiscoveredFile(
                path=target,
                category=FileCategory.SKILL,
                relative_path=rel,
                size_bytes=target.stat().st_size,
            )
        )
    return SkillUnit(
        root=tmp_path,
        metadata_file=metadata_file,
        files=files,
        frontmatter=SkillFrontmatter(name=name, description="Test."),
        body=skill_md,
    )


# Payload that would be CRITICAL if the asset bytes were read as text.
_NOISY_ASSET: bytes = b"PK\x03\x04" + b"\x1b[8mhidden\x1b[0m" + b"\x00" * 4


class TestSkillAggregationEndToEnd:
    """FP-14 acceptance, aggregation → fusion, on real content."""

    def test_binary_asset_noise_with_safe_llm_passes(self, tmp_path: Path) -> None:
        """A HIGH that would come only from binary-asset noise + safe LLM → PASS.

        This is the "REVIEW: static HIGH + LLM safe" false positive: the
        aggregate must not be dragged to HIGH by a bundled binary asset, so the
        safe LLM verdict yields PASS instead of REVIEW_REQUIRED.
        """
        skill = _real_skill(
            tmp_path,
            name="pack-skill",
            skill_md="---\nname: pack-skill\ndescription: d\n---\n# Body\n",
            bundled={"assets/template.pptx": _NOISY_ASSET},
        )
        ssr = compute_skill_static_result(skill)
        # The binary asset contributes nothing significant.
        assert ssr.aggregate_severity not in (Severity.HIGH, Severity.CRITICAL)
        verdict = fuse_skill_verdict(ssr, _llm("safe", 0.9))
        assert verdict.decision == VerdictDecision.PASS

    def test_real_high_still_reviews_with_safe_llm(self, tmp_path: Path) -> None:
        """A genuine HIGH finding + safe LLM still lands at REVIEW_REQUIRED (F005)."""
        skill = _real_skill(
            tmp_path,
            name="perm-skill",
            skill_md=(
                "---\nname: perm-skill\ndescription: d\n"
                "allowed-tools: bash(*)\n---\n# Body\n"
            ),
        )
        ssr = compute_skill_static_result(skill)
        assert ssr.aggregate_severity == Severity.HIGH
        verdict = fuse_skill_verdict(ssr, _llm("safe", 0.9))
        assert verdict.decision == VerdictDecision.REVIEW_REQUIRED
        assert "IPI405" in verdict.reasoning
