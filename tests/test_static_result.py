"""Tests for static_result module."""
from __future__ import annotations

from pathlib import Path

from ipi_check.core.types import (
    ByteFinding,
    ByteFindingCategory,
    DiscoveredFile,
    FileCategory,
    HeuristicScores,
    PatternFinding,
    PatternFindingCategory,
    Severity,
)
from ipi_check.scanner.static_result import (
    assemble_static_result,
    compute_static_severity,
)


def _zero_scores(suspicious_count: int = 0) -> HeuristicScores:
    return HeuristicScores(
        entropy=0.0, entropy_suspicious=False,
        invisible_ratio=0.0, invisible_suspicious=False,
        instruction_density=0.0, instruction_density_suspicious=False,
        suspicious_count=suspicious_count,
    )


def _byte(severity: Severity) -> ByteFinding:
    return ByteFinding(
        category=ByteFindingCategory.ANSI_HIDDEN, severity=severity, line=1, column=1,
        snippet_hex="00", description="d",
    )


def _pattern(severity: Severity) -> PatternFinding:
    return PatternFinding(
        category=PatternFindingCategory.INSTRUCTION_OVERRIDE, severity=severity, line=1, column=1,
        matched_text="x", pattern_id="P1", description="d",
    )


def _file(tmp_path: Path) -> DiscoveredFile:
    p = tmp_path / "f.md"
    p.write_text("ph")
    return DiscoveredFile(
        path=p, category=FileCategory.AGENT_INSTRUCTION,
        relative_path="f.md", size_bytes=2,
    )


class TestComputeStaticSeverity:
    def test_critical_byte(self) -> None:
        sev = compute_static_severity([_byte(Severity.CRITICAL)], [], _zero_scores())
        assert sev == Severity.CRITICAL

    def test_critical_pattern(self) -> None:
        sev = compute_static_severity([], [_pattern(Severity.CRITICAL)], _zero_scores())
        assert sev == Severity.CRITICAL

    def test_high_pattern(self) -> None:
        sev = compute_static_severity([], [_pattern(Severity.HIGH)], _zero_scores())
        assert sev == Severity.HIGH

    def test_high_via_heuristic_count(self) -> None:
        sev = compute_static_severity([], [], _zero_scores(suspicious_count=2))
        assert sev == Severity.HIGH

    def test_medium_only(self) -> None:
        sev = compute_static_severity(
            [_byte(Severity.MEDIUM)], [], _zero_scores()
        )
        assert sev == Severity.MEDIUM

    def test_no_findings(self) -> None:
        sev = compute_static_severity([], [], _zero_scores())
        assert sev == Severity.NONE

    def test_critical_takes_precedence_over_high(self) -> None:
        sev = compute_static_severity(
            [_byte(Severity.CRITICAL), _byte(Severity.HIGH)], [], _zero_scores()
        )
        assert sev == Severity.CRITICAL


class TestAssembleStaticResult:
    def test_assembly_populates_fields(self, tmp_path: Path) -> None:
        f = _file(tmp_path)
        bf = [_byte(Severity.CRITICAL)]
        pf = [_pattern(Severity.HIGH)]
        hs = _zero_scores()
        result = assemble_static_result(f, bf, pf, hs)
        assert result.file is f
        assert result.byte_findings is bf
        assert result.pattern_findings is pf
        assert result.heuristic_scores is hs
        assert result.severity == Severity.CRITICAL

    def test_assembly_no_findings(self, tmp_path: Path) -> None:
        f = _file(tmp_path)
        result = assemble_static_result(f, [], [], _zero_scores())
        assert result.severity == Severity.NONE
