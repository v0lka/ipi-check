"""Tests for SARIF output of skill verdicts."""
from __future__ import annotations

from pathlib import Path

from ipi_check import TOOL_INFO
from ipi_check.core.types import (
    DiscoveredFile,
    FileCategory,
    Severity,
    SkillFinalVerdict,
    SkillFrontmatter,
    SkillUnit,
    VerdictDecision,
)
from ipi_check.reporter.sarif_reporter import (
    generate_sarif,
)


def _make_skill_verdict(
    tmp_path: Path,
    decision: VerdictDecision,
    severity: Severity,
    name: str = "test-skill",
    description: str = "A test skill.",
) -> SkillFinalVerdict:
    """Build a SkillFinalVerdict for SARIF testing."""
    skill_dir = tmp_path / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    skill_path = skill_dir / "SKILL.md"
    skill_path.write_text(
        f"---\nname: {name}\ndescription: {description}\n---\n# Body\n"
    )
    mf = DiscoveredFile(
        path=skill_path, category=FileCategory.SKILL,
        relative_path=f"{name}/SKILL.md", size_bytes=skill_path.stat().st_size,
    )
    # Add a script file as well.
    scripts_dir = skill_dir / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    script_path = scripts_dir / "run.sh"
    script_path.write_text("#!/bin/bash\necho 'hi'\n")
    sf = DiscoveredFile(
        path=script_path, category=FileCategory.SKILL,
        relative_path=f"{name}/scripts/run.sh",
        size_bytes=script_path.stat().st_size,
    )
    unit = SkillUnit(
        root=skill_dir,
        metadata_file=mf,
        files=[mf, sf],
        frontmatter=SkillFrontmatter(name=name, description=description),
        body="# Body\n",
    )
    return SkillFinalVerdict(
        skill=unit,
        decision=decision,
        static_severity=severity,
        llm_verdict="malicious" if decision == VerdictDecision.BLOCK else "safe",
        llm_confidence=0.9 if decision == VerdictDecision.BLOCK else 0.5,
        llm_compromised=False,
        all_findings=[],
        reasoning="Test reasoning.",
    )


class TestSkillSarif:
    """Tests for skill SARIF output structure."""

    def test_one_sarif_result_per_skill(self, tmp_path: Path) -> None:
        """Each skill verdict produces exactly one SARIF result."""
        sv = _make_skill_verdict(tmp_path, VerdictDecision.BLOCK, Severity.CRITICAL)
        sarif = generate_sarif(
            verdicts=[], repo_path=tmp_path, tool_info=TOOL_INFO,
            start_time="2024-01-01T00:00:00Z", end_time="2024-01-01T00:00:01Z",
            skill_verdicts=[sv],
        )
        results = sarif["runs"][0]["results"]
        assert len(results) == 1

    def test_no_skill_verdicts_no_extra_results(self, tmp_path: Path) -> None:
        """When skill_verdicts is None, no extra results are added."""
        sarif = generate_sarif(
            verdicts=[], repo_path=tmp_path, tool_info=TOOL_INFO,
            start_time="2024-01-01T00:00:00Z", end_time="2024-01-01T00:00:01Z",
            skill_verdicts=None,
        )
        results = sarif["runs"][0]["results"]
        assert results == []

    def test_primary_location_is_skill_md(self, tmp_path: Path) -> None:
        """Primary artifactLocation URI is SKILL.md."""
        sv = _make_skill_verdict(tmp_path, VerdictDecision.BLOCK, Severity.CRITICAL)
        sarif = generate_sarif(
            verdicts=[], repo_path=tmp_path, tool_info=TOOL_INFO,
            start_time="2024-01-01T00:00:00Z", end_time="2024-01-01T00:00:01Z",
            skill_verdicts=[sv],
        )
        result = sarif["runs"][0]["results"][0]
        primary_uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert primary_uri == "test-skill/SKILL.md"

    def test_related_locations_contain_other_files(self, tmp_path: Path) -> None:
        """relatedLocations contains all non-SKILL.md files in the skill."""
        sv = _make_skill_verdict(tmp_path, VerdictDecision.BLOCK, Severity.CRITICAL)
        sarif = generate_sarif(
            verdicts=[], repo_path=tmp_path, tool_info=TOOL_INFO,
            start_time="2024-01-01T00:00:00Z", end_time="2024-01-01T00:00:01Z",
            skill_verdicts=[sv],
        )
        result = sarif["runs"][0]["results"][0]
        related = result.get("relatedLocations", [])
        assert len(related) >= 1
        related_uris = {
            rl["physicalLocation"]["artifactLocation"]["uri"]
            for rl in related
        }
        assert "test-skill/scripts/run.sh" in related_uris

    def test_block_decision_has_error_level(self, tmp_path: Path) -> None:
        """BLOCK decision maps to 'error' level in SARIF."""
        sv = _make_skill_verdict(tmp_path, VerdictDecision.BLOCK, Severity.CRITICAL)
        sarif = generate_sarif(
            verdicts=[], repo_path=tmp_path, tool_info=TOOL_INFO,
            start_time="2024-01-01T00:00:00Z", end_time="2024-01-01T00:00:01Z",
            skill_verdicts=[sv],
        )
        result = sarif["runs"][0]["results"][0]
        assert result["level"] == "error"

    def test_pass_decision_has_none_level(self, tmp_path: Path) -> None:
        """PASS decision maps to 'none' level in SARIF."""
        sv = _make_skill_verdict(tmp_path, VerdictDecision.PASS, Severity.NONE)
        sarif = generate_sarif(
            verdicts=[], repo_path=tmp_path, tool_info=TOOL_INFO,
            start_time="2024-01-01T00:00:00Z", end_time="2024-01-01T00:00:01Z",
            skill_verdicts=[sv],
        )
        result = sarif["runs"][0]["results"][0]
        assert result["level"] == "none"

    def test_rule_ids_included_in_driver_rules(self, tmp_path: Path) -> None:
        """New rule IDs (IPI401, IPI501, IPI601) appear in driver.rules."""
        sv = _make_skill_verdict(tmp_path, VerdictDecision.BLOCK, Severity.CRITICAL)
        sarif = generate_sarif(
            verdicts=[], repo_path=tmp_path, tool_info=TOOL_INFO,
            start_time="2024-01-01T00:00:00Z", end_time="2024-01-01T00:00:01Z",
            skill_verdicts=[sv],
        )
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert "IPI401" in rule_ids

    def test_skill_name_in_message_text(self, tmp_path: Path) -> None:
        """The skill name appears in the SARIF message text."""
        sv = _make_skill_verdict(
            tmp_path, VerdictDecision.BLOCK, Severity.CRITICAL,
            name="dangerous-calc",
        )
        sarif = generate_sarif(
            verdicts=[], repo_path=tmp_path, tool_info=TOOL_INFO,
            start_time="2024-01-01T00:00:00Z", end_time="2024-01-01T00:00:01Z",
            skill_verdicts=[sv],
        )
        result = sarif["runs"][0]["results"][0]
        assert "dangerous-calc" in result["message"]["text"]

    def test_multiple_skill_verdicts(self, tmp_path: Path) -> None:
        """Multiple skill verdicts all produce SARIF results."""
        sv1 = _make_skill_verdict(
            tmp_path, VerdictDecision.BLOCK, Severity.CRITICAL,
            name="skill-a",
        )
        sv2 = _make_skill_verdict(
            tmp_path, VerdictDecision.PASS, Severity.NONE,
            name="skill-b",
        )
        sarif = generate_sarif(
            verdicts=[], repo_path=tmp_path, tool_info=TOOL_INFO,
            start_time="2024-01-01T00:00:00Z", end_time="2024-01-01T00:00:01Z",
            skill_verdicts=[sv1, sv2],
        )
        results = sarif["runs"][0]["results"]
        assert len(results) == 2
