"""Tests for core dataclass validation."""
from __future__ import annotations

from pathlib import Path

import pytest

from ipi_check.core.types import (
    ByteFinding,
    ByteFindingCategory,
    DiscoveredFile,
    FileCategory,
    FinalVerdict,
    HeuristicScores,
    LLMConfig,
    LLMFinding,
    LLMResult,
    PatternFinding,
    PatternFindingCategory,
    Severity,
    StaticResult,
    ToolInfo,
    VerdictDecision,
)


class TestLLMResult:
    def test_invalid_verdict_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid LLM verdict"):
            LLMResult(verdict="not-a-verdict", confidence=0.5)

    def test_confidence_above_one_raises(self) -> None:
        with pytest.raises(ValueError, match="Confidence must be"):
            LLMResult(verdict="safe", confidence=1.5)

    def test_confidence_below_zero_raises(self) -> None:
        with pytest.raises(ValueError, match="Confidence must be"):
            LLMResult(verdict="safe", confidence=-0.1)

    def test_compromised_skips_validation(self) -> None:
        # Even an invalid verdict + bad confidence is allowed when compromised.
        result = LLMResult(
            verdict="garbage", confidence=99.0, compromised=True,
            raw_response="raw"
        )
        assert result.compromised is True
        assert result.verdict == "garbage"

    @pytest.mark.parametrize("verdict", ["safe", "suspicious", "malicious"])
    def test_valid_verdicts(self, verdict: str) -> None:
        r = LLMResult(verdict=verdict, confidence=0.5)
        assert r.verdict == verdict

    def test_boundary_confidences(self) -> None:
        LLMResult(verdict="safe", confidence=0.0)
        LLMResult(verdict="safe", confidence=1.0)


class TestOtherDataclasses:
    def test_tool_info(self) -> None:
        ti = ToolInfo(name="ipi-check", version="0.1.0", semver="0.1.0")
        assert ti.name == "ipi-check"

    def test_discovered_file(self, tmp_path: Path) -> None:
        df = DiscoveredFile(
            path=tmp_path / "x.md",
            category=FileCategory.AGENT_INSTRUCTION,
            relative_path="x.md",
            size_bytes=10,
        )
        assert df.category == FileCategory.AGENT_INSTRUCTION

    def test_byte_finding(self) -> None:
        bf = ByteFinding(
            category=ByteFindingCategory.ANSI_HIDDEN, severity=Severity.CRITICAL,
            line=1, column=1, snippet_hex="1b5b386d", description="x",
        )
        assert bf.severity == Severity.CRITICAL

    def test_pattern_finding(self) -> None:
        pf = PatternFinding(
            category=PatternFindingCategory.INSTRUCTION_OVERRIDE, severity=Severity.CRITICAL,
            line=1, column=1, matched_text="ignore", pattern_id="INSTR_001",
            description="x",
        )
        assert pf.pattern_id == "INSTR_001"

    def test_heuristic_scores(self) -> None:
        hs = HeuristicScores(
            entropy=4.2, entropy_suspicious=False,
            invisible_ratio=0.0, invisible_suspicious=False,
            instruction_density=1.0, instruction_density_suspicious=False,
            suspicious_count=0,
        )
        assert hs.suspicious_count == 0

    def test_llm_finding(self) -> None:
        lf = LLMFinding(line=3, category="authority_override", explanation="x")
        assert lf.line == 3

    def test_llm_config_defaults(self) -> None:
        c = LLMConfig()
        assert c.base_url is None
        assert c.model is None
        assert c.api_token is None

    def test_static_result(self, tmp_path: Path) -> None:
        f = DiscoveredFile(
            path=tmp_path / "x.md",
            category=FileCategory.AGENT_INSTRUCTION,
            relative_path="x.md", size_bytes=0,
        )
        hs = HeuristicScores(0.0, False, 0.0, False, 0.0, False, 0)
        sr = StaticResult(f, [], [], hs, Severity.NONE)
        assert sr.severity == Severity.NONE

    def test_final_verdict(self, tmp_path: Path) -> None:
        f = DiscoveredFile(
            path=tmp_path / "x.md",
            category=FileCategory.AGENT_INSTRUCTION,
            relative_path="x.md", size_bytes=0,
        )
        fv = FinalVerdict(
            file=f, decision=VerdictDecision.PASS,
            static_severity=Severity.NONE, llm_verdict=None,
            llm_confidence=None, llm_compromised=False,
            all_findings=[], reasoning="ok",
        )
        assert fv.decision == VerdictDecision.PASS
