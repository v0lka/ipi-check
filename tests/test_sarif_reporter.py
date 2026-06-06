"""Tests for sarif_reporter module."""
from __future__ import annotations

from pathlib import Path

from ipi_check import TOOL_INFO
from ipi_check.core.types import (
    ByteFinding,
    ByteFindingCategory,
    DiscoveredFile,
    FileCategory,
    FinalVerdict,
    LLMFinding,
    PatternFinding,
    PatternFindingCategory,
    Severity,
    VerdictDecision,
)
from ipi_check.reporter.sarif_reporter import (
    LLM_COMPROMISE_RULE_ID,
    LLM_FINDING_RULE_ID,
    SARIF_SCHEMA_URL,
    SARIF_VERSION,
    generate_sarif,
)

START = "2024-01-01T00:00:00Z"
END = "2024-01-01T00:00:01Z"


def _file(relative_path: str = "AGENTS.md") -> DiscoveredFile:
    return DiscoveredFile(
        path=Path("/tmp") / relative_path,
        category=FileCategory.AGENT_INSTRUCTION,
        relative_path=relative_path,
        size_bytes=10,
    )


def _verdict(
    findings: list,
    *,
    relative_path: str = "AGENTS.md",
    severity: Severity = Severity.HIGH,
    decision: VerdictDecision = VerdictDecision.BLOCK,
    llm_compromised: bool = False,
) -> FinalVerdict:
    return FinalVerdict(
        file=_file(relative_path),
        decision=decision,
        static_severity=severity,
        llm_verdict=None,
        llm_confidence=None,
        llm_compromised=llm_compromised,
        all_findings=findings,
        reasoning="r",
    )


class TestGenerateSarif:
    def test_empty_verdicts(self, tmp_path: Path) -> None:
        sarif = generate_sarif([], tmp_path, TOOL_INFO, START, END)
        assert sarif["$schema"] == SARIF_SCHEMA_URL
        assert sarif["version"] == SARIF_VERSION
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_single_byte_finding(self, tmp_path: Path) -> None:
        bf = ByteFinding(
            category=ByteFindingCategory.ANSI_HIDDEN, severity=Severity.CRITICAL,
            line=1, column=2, snippet_hex="1b5b386d",
            description="ANSI escape detected",
        )
        sarif = generate_sarif([_verdict([bf])], tmp_path, TOOL_INFO, START, END)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "IPI001"
        assert results[0]["level"] == "error"
        loc = results[0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "AGENTS.md"
        assert loc["region"]["startLine"] == 1
        assert loc["region"]["startColumn"] == 2

    def test_multiple_findings_same_file(self, tmp_path: Path) -> None:
        bf = ByteFinding(
            category=ByteFindingCategory.ZERO_WIDTH, severity=Severity.MEDIUM,
            line=1, column=1, snippet_hex="00", description="zw",
        )
        pf = PatternFinding(
            category=PatternFindingCategory.INSTRUCTION_OVERRIDE, severity=Severity.CRITICAL,
            line=2, column=3, matched_text="ignore", pattern_id="P1",
            description="i",
        )
        sarif = generate_sarif(
            [_verdict([bf, pf])], tmp_path, TOOL_INFO, START, END
        )
        results = sarif["runs"][0]["results"]
        assert len(results) == 2
        uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                for r in results}
        assert uris == {"AGENTS.md"}

    def test_special_chars_uri_encoded(self, tmp_path: Path) -> None:
        bf = ByteFinding(
            category=ByteFindingCategory.ANSI_HIDDEN, severity=Severity.CRITICAL,
            line=1, column=1, snippet_hex="00", description="d",
        )
        verdict = _verdict([bf], relative_path="path with spaces/file#1.md")
        sarif = generate_sarif([verdict], tmp_path, TOOL_INFO, START, END)
        uri = sarif["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"]["artifactLocation"]["uri"]
        # Slashes preserved; spaces and # encoded.
        assert "%20" in uri or "+" in uri or " " not in uri.replace("%20", " ")
        assert "/" in uri  # path separator unescaped

    def test_llm_compromise_note(self, tmp_path: Path) -> None:
        verdict = _verdict([], severity=Severity.NONE,
                           decision=VerdictDecision.PASS,
                           llm_compromised=True)
        sarif = generate_sarif([verdict], tmp_path, TOOL_INFO, START, END)
        results = sarif["runs"][0]["results"]
        compromise = [r for r in results if r["ruleId"] == LLM_COMPROMISE_RULE_ID]
        assert len(compromise) == 1
        assert compromise[0]["level"] == "note"

    def test_llm_finding_rule_id(self, tmp_path: Path) -> None:
        lf = LLMFinding(line=4, category="authority_override", explanation="x")
        sarif = generate_sarif(
            [_verdict([lf])], tmp_path, TOOL_INFO, START, END
        )
        results = sarif["runs"][0]["results"]
        assert results[0]["ruleId"] == LLM_FINDING_RULE_ID
        assert results[0]["level"] == "warning"

    def test_invocations_timestamps(self, tmp_path: Path) -> None:
        sarif = generate_sarif([], tmp_path, TOOL_INFO, START, END)
        invocations = sarif["runs"][0]["invocations"]
        assert len(invocations) == 1
        assert invocations[0]["startTimeUtc"] == START
        assert invocations[0]["endTimeUtc"] == END
        assert invocations[0]["executionSuccessful"] is True

    def test_driver_metadata(self, tmp_path: Path) -> None:
        sarif = generate_sarif([], tmp_path, TOOL_INFO, START, END)
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == TOOL_INFO.name
        assert driver["version"] == TOOL_INFO.version
        assert driver["semanticVersion"] == TOOL_INFO.semver

    def test_rules_array_unique(self, tmp_path: Path) -> None:
        # Two byte findings with same category produce one rule entry.
        bf1 = ByteFinding(
            category=ByteFindingCategory.ANSI_HIDDEN, severity=Severity.CRITICAL,
            line=1, column=1, snippet_hex="00", description="d",
        )
        bf2 = ByteFinding(
            category=ByteFindingCategory.ANSI_HIDDEN, severity=Severity.CRITICAL,
            line=2, column=1, snippet_hex="00", description="d",
        )
        sarif = generate_sarif(
            [_verdict([bf1, bf2])], tmp_path, TOOL_INFO, START, END
        )
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert rule_ids.count("IPI001") == 1
