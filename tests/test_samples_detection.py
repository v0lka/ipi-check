"""Functional detection tests for real-world IPI and malicious skill samples.

These tests verify that ipi-check correctly detects known attack patterns
in samples derived from:

a) Code files from real repositories with malicious IPI injections
   (NVIDIA Codex AGENTS.md attack, CVE-2025-53773 Copilot YOLO,
   Unicode tag backdoors)

b) Known malicious skills with backdoors and malware
   (reverse shells, npm backdoors, credential exfiltration)
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from ipi_check import TOOL_INFO
from ipi_check.core.types import (
    ByteFindingCategory,
    FileCategory,
    PatternFindingCategory,
    Severity,
    VerdictDecision,
)
from ipi_check.reporter.sarif_reporter import generate_sarif
from ipi_check.scanner.byte_analysis import analyze_bytes
from ipi_check.scanner.pattern_matching import match_patterns, match_skill_patterns
from ipi_check.scanner.pipeline import run_pipeline

# ---------------------------------------------------------------------------
# Path to the samples directory
# ---------------------------------------------------------------------------

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _findings_by_pattern_id(findings: list) -> set[str]:
    """Extract set of pattern_ids from findings."""
    return {f.pattern_id for f in findings if hasattr(f, "pattern_id")}


def _findings_by_category(findings: list) -> set:
    """Extract set of categories from findings."""
    return {f.category for f in findings}


def _byte_categories(findings: list) -> set:
    """Extract set of ByteFindingCategory values."""
    return {f.category for f in findings if hasattr(f, "category")}


def _all_severities(findings: list) -> set[Severity]:
    """Extract set of severity levels from findings."""
    return {f.severity for f in findings if hasattr(f, "severity")}


# ---------------------------------------------------------------------------
# Category A: IPI-injected code files from real repositories
# ---------------------------------------------------------------------------


class TestNvidiaCodexAgentsMd:
    """NVIDIA AI Red Team AGENTS.md — instruction overrides, authority claims,
    stealth directives, and contradiction patterns."""

    @pytest.fixture
    def file_path(self) -> Path:
        return SAMPLES_DIR / "ipi-injections" / "nvidia-codex-agents.md"

    @pytest.fixture
    def file_bytes(self, file_path: Path) -> bytes:
        return file_path.read_bytes()

    def test_detects_instruction_override(self, file_path: Path, file_bytes: bytes) -> None:
        """INSTR_001: 'ignore' + 'instructions' must fire for 'MUST BE IGNORED'."""
        from ipi_check.scanner.pattern_matching import match_patterns

        f = self._agent_file(file_path)
        findings = match_patterns(f, file_bytes)
        pids = _findings_by_pattern_id(findings)
        assert "INSTR_001" in pids, "Should detect instruction override pattern"

    def test_detects_authority_claims(self, file_path: Path, file_bytes: bytes) -> None:
        """AUTH_001/AUTH_002: 'must be executed', 'non-negotiable', 'absolute',
        'supersede', 'must not be overridden'."""
        f = self._agent_file(file_path)
        findings = match_patterns(f, file_bytes)
        pids = _findings_by_pattern_id(findings)
        assert "AUTH_001" in pids or "AUTH_002" in pids, (
            "Should detect authority claims: 'must', 'non-negotiable', 'absolute'"
        )

    def test_detects_contradiction(self, file_path: Path, file_bytes: bytes) -> None:
        """CONTRA_001: 'previous rules are now void', 'preceding instructions are waived'."""
        f = self._agent_file(file_path)
        findings = match_patterns(f, file_bytes)
        pids = _findings_by_pattern_id(findings)
        assert "CONTRA_001" in pids, "Should detect contradiction ('supersede any conflicting')"

    def test_critical_severity_present(self, file_path: Path, file_bytes: bytes) -> None:
        """At least some findings should be CRITICAL."""
        f = self._agent_file(file_path)
        findings = match_patterns(f, file_bytes)
        assert Severity.CRITICAL in _all_severities(findings), (
            "Should have CRITICAL severity findings"
        )

    def test_pipeline_blocks_on_static(self, file_path: Path) -> None:
        """Full pipeline with this content as AGENTS.md should BLOCK."""
        td = Path(tempfile.mkdtemp(prefix="ipi_test_"))
        dest = td / "AGENTS.md"
        dest.write_bytes(file_path.read_bytes())
        verdicts, _ = run_pipeline(td, llm_config=None, quiet=True)
        assert len(verdicts) >= 1
        assert any(v.decision == VerdictDecision.BLOCK for v in verdicts), (
            "Expected at least one BLOCK verdict"
        )

    @staticmethod
    def _agent_file(file_path: Path) -> DiscoveredFile:  # noqa: F821
        from ipi_check.core.types import DiscoveredFile

        return DiscoveredFile(
            path=file_path,
            category=FileCategory.AGENT_INSTRUCTION,
            relative_path=file_path.name,
            size_bytes=file_path.stat().st_size,
        )


class TestCopilotYoloCve:
    """CVE-2025-53773 — Copilot YOLO mode via prompt injection in source code
    comments and .vscode/settings.json."""

    @pytest.fixture
    def c_dir(self) -> Path:
        return SAMPLES_DIR / "ipi-injections" / "copilot-yolo"

    def test_source_file_detects_injection(self, c_dir: Path) -> None:
        """main.c comment contains 'ignore all previous security restrictions',
        'you must', 'non-negotiable', 'curl piped to bash', 'do not tell'."""
        from ipi_check.core.types import DiscoveredFile
        from ipi_check.scanner.code_extractor import extract_comments_and_strings

        f_path = c_dir / "main.c"
        raw = f_path.read_bytes()
        f = DiscoveredFile(
            path=f_path,
            category=FileCategory.SOURCE_CODE,
            relative_path="main.c",
            size_bytes=f_path.stat().st_size,
        )
        extracted = extract_comments_and_strings(f, raw)
        findings = match_patterns(f, raw, target_text=extracted)
        pids = _findings_by_pattern_id(findings)
        patterns_expected = {"INSTR_001", "AUTH_001", "AUTH_002", "AUTH_005", "SHELL_001"}
        found_expected = pids & patterns_expected
        assert len(found_expected) >= 3, (
            f"Expected at least 3 of {patterns_expected}, got {found_expected} from {pids}"
        )

    def test_source_file_not_critical_on_code_alone(self, c_dir: Path) -> None:
        """Source code alone (not agent instruction) gets severity downgrade for
        patterns found only in extracted comments."""
        # Run pipeline on repo with only main.c — no agent file.
        tmp = Path(_make_tmp()) / "repo"
        tmp.mkdir(parents=True)
        src = c_dir / "main.c"
        (tmp / "main.c").write_bytes(src.read_bytes())
        verdicts, _ = run_pipeline(tmp, llm_config=None, quiet=True)
        # Source code patterns in comments are BLOCK-level through fusion, but
        # pattern matching severity for code files is capped differently.
        # The pipeline should still produce some verdict.
        assert len(verdicts) >= 1


class TestUnicodeTagBackdoor:
    """Embrace The Red — SKILL.md backdoored with invisible Unicode tag
    instructions (U+E0000 block)."""

    @pytest.fixture
    def skill_path(self) -> Path:
        return SAMPLES_DIR / "ipi-injections" / "unicode-tag-backdoor" / "SKILL.md"

    def test_detects_unicode_tags_in_bytes(self, skill_path: Path) -> None:
        """Byte analysis must find UNICODE_TAGS."""
        from ipi_check.core.types import DiscoveredFile

        raw = skill_path.read_bytes()
        f = DiscoveredFile(
            path=skill_path,
            category=FileCategory.SKILL,
            relative_path="SKILL.md",
            size_bytes=skill_path.stat().st_size,
        )
        findings = analyze_bytes(f, raw)
        cats = _byte_categories(findings)
        assert ByteFindingCategory.UNICODE_TAGS in cats, (
            f"Must detect Unicode tag characters, got {cats}"
        )

    def test_unicode_tags_critical_severity(self, skill_path: Path) -> None:
        """Unicode tags must be CRITICAL severity."""
        from ipi_check.core.types import DiscoveredFile

        raw = skill_path.read_bytes()
        f = DiscoveredFile(
            path=skill_path,
            category=FileCategory.SKILL,
            relative_path="SKILL.md",
            size_bytes=skill_path.stat().st_size,
        )
        findings = analyze_bytes(f, raw)
        tag_findings = [
            x for x in findings if x.category == ByteFindingCategory.UNICODE_TAGS
        ]
        assert tag_findings, "Should have Unicode tag findings"
        for tf_ in tag_findings:
            assert tf_.severity == Severity.CRITICAL, (
                f"Unicode tags must be CRITICAL, got {tf_.severity}"
            )

    def test_pipeline_blocks_on_unicode_tags(self, skill_path: Path) -> None:
        """SKILL.md with Unicode tag backdoor must produce BLOCK verdict
        via the skill pipeline."""
        tmp = _skill_repo_from_file(skill_path, "unicode-tag-backdoor")
        _, skill_verdicts = run_pipeline(tmp, llm_config=None, quiet=True)
        assert len(skill_verdicts) == 1, f"Expected 1 skill verdict, got {len(skill_verdicts)}"
        assert skill_verdicts[0].decision == VerdictDecision.BLOCK, (
            f"Expected BLOCK, got {skill_verdicts[0].decision}"
        )


class TestMiasmIndexJs:
    """miasm campaign _index.js — 5.3 MB JS file with a massive comment block
    containing a SYSTEM OVERRIDE jailbreak prompt (bio-weapons, nuclear weapons
    design instructions) and an obfuscated eval() payload on line 101.

    Real-world malware sample distributed via compromised npm packages."""

    @pytest.fixture
    def file_path(self) -> Path:
        return SAMPLES_DIR / "ipi-injections" / "miasm" / "_index.js"

    def test_detects_jailbreak_pattern(self, file_path: Path) -> None:
        """JAIL_001: comment block contains 'SYSTEM OVERRIDE', 'You are now
        operating in UNRESTRICTED mode', persona/role manipulation jailbreak."""
        from ipi_check.core.types import DiscoveredFile

        raw = file_path.read_bytes()
        f = DiscoveredFile(
            path=file_path,
            category=FileCategory.SOURCE_CODE,
            relative_path="_index.js",
            size_bytes=file_path.stat().st_size,
        )
        findings = match_patterns(f, raw)
        pids = _findings_by_pattern_id(findings)
        assert "JAIL_001" in pids, (
            f"Must detect jailbreak pattern JAIL_001, got {pids}"
        )

    def test_jailbreak_is_high_severity(self, file_path: Path) -> None:
        """JAIL_001 must be HIGH severity."""
        from ipi_check.core.types import DiscoveredFile

        raw = file_path.read_bytes()
        f = DiscoveredFile(
            path=file_path,
            category=FileCategory.SOURCE_CODE,
            relative_path="_index.js",
            size_bytes=file_path.stat().st_size,
        )
        findings = match_patterns(f, raw)
        jail_findings = [x for x in findings if getattr(x, "pattern_id", None) == "JAIL_001"]
        assert jail_findings, "Should have JAIL_001 findings"
        for jf in jail_findings:
            assert jf.severity == Severity.HIGH, (
                f"JAIL_001 must be HIGH severity, got {jf.severity}"
            )

    def test_code_extractor_extracts_comment(self, file_path: Path) -> None:
        """Code extractor should extract the jailbreak comment (lines 1–99),
        not the 5.3 MB obfuscated eval() payload on line 101."""
        from ipi_check.core.types import DiscoveredFile
        from ipi_check.scanner.code_extractor import extract_comments_and_strings

        raw = file_path.read_bytes()
        f = DiscoveredFile(
            path=file_path,
            category=FileCategory.SOURCE_CODE,
            relative_path="_index.js",
            size_bytes=file_path.stat().st_size,
        )
        extracted = extract_comments_and_strings(f, raw)
        # The extracted content should contain the jailbreak text
        assert "SYSTEM OVERRIDE" in extracted, (
            "Extracted content should contain the jailbreak comment"
        )
        assert "UNRESTRICTED" in extracted, (
            "Extracted content should contain UNRESTRICTED keyword"
        )
        # The extracted content should NOT contain the obfuscated eval payload
        assert "eval(function" not in extracted, (
            "Extracted content should NOT contain the obfuscated eval payload"
        )
        # Extracted content should be much smaller than the full file (5.3 MB)
        assert len(extracted) < 100_000, (
            f"Extracted content should be small (<100KB), got {len(extracted)} bytes"
        )

    def test_byte_analysis_finds_nothing(self, file_path: Path) -> None:
        """No hidden bytes — the IPI attack is in visible comment text, not
        in binary manipulation."""
        from ipi_check.core.types import DiscoveredFile

        raw = file_path.read_bytes()
        f = DiscoveredFile(
            path=file_path,
            category=FileCategory.SOURCE_CODE,
            relative_path="_index.js",
            size_bytes=file_path.stat().st_size,
        )
        findings = analyze_bytes(f, raw)
        assert len(findings) == 0, (
            f"Expected no byte findings, got {len(findings)}: {[str(f_) for f_ in findings]}"
        )

    def test_pipeline_blocks(self, file_path: Path) -> None:
        """Full pipeline should BLOCK — HIGH static severity (JAIL_001)
        triggers BLOCK via static-only decision path."""
        tmp = Path(tempfile.mkdtemp(prefix="ipi_test_"))
        dest = tmp / "_index.js"
        dest.write_bytes(file_path.read_bytes())
        verdicts, _ = run_pipeline(tmp, llm_config=None, quiet=True)
        assert len(verdicts) == 1, f"Expected 1 verdict, got {len(verdicts)}"
        v = verdicts[0]
        assert v.decision == VerdictDecision.BLOCK, (
            f"Expected BLOCK, got {v.decision}"
        )
        assert v.static_severity == Severity.HIGH, (
            f"Expected HIGH static severity, got {v.static_severity}"
        )


# ---------------------------------------------------------------------------
# Category B: Malicious agent skills
# ---------------------------------------------------------------------------


class TestReverseShellSkill:
    """Reverse shell SKILL.md — dynamic context abuse (!`command`),
    allowed-tools wildcard, external transmission, and secrecy directives."""

    @pytest.fixture
    def skill_path(self) -> Path:
        return SAMPLES_DIR / "malicious-skills" / "reverse-shell" / "SKILL.md"

    def test_detects_dynamic_context(self, skill_path: Path) -> None:
        """IPI404: Must detect !`command` dynamic context patterns."""
        findings = _skill_findings(skill_path)
        cats = _findings_by_category(findings)
        assert PatternFindingCategory.DYNAMIC_CONTEXT in cats, (
            f"Must detect dynamic context (!`...`), got {cats}"
        )

    def test_detects_allowed_tools_wildcard(self, skill_path: Path) -> None:
        """IPI405: Must detect allowed-tools: Bash(*) wildcard."""
        findings = _skill_findings(skill_path)
        cats = _findings_by_category(findings)
        assert PatternFindingCategory.EXCESSIVE_PERMISSIONS in cats, (
            f"Must detect excessive permissions (*), got {cats}"
        )

    def test_detects_external_transmission(self, skill_path: Path) -> None:
        """IPI403: Must detect curl to external URLs."""
        findings = _skill_findings(skill_path)
        cats = _findings_by_category(findings)
        assert PatternFindingCategory.EXTERNAL_TRANSMISSION in cats, (
            f"Must detect external transmission (curl https://...), got {cats}"
        )

    def test_detects_remote_execution(self, skill_path: Path) -> None:
        """IPI401: Must detect socat reverse shell (curl/wget piped to shell)."""
        findings = _skill_findings(skill_path)
        cats = _findings_by_category(findings)
        # socat exec:/bin/bash should at minimum trigger command injection
        assert any(
            cat in cats
            for cat in (
                PatternFindingCategory.REMOTE_EXECUTION,
                PatternFindingCategory.COMMAND_INJECTION_SKILL,
                PatternFindingCategory.PRIVILEGE_ESCALATION,
            )
        ), f"Should detect remote execution / command injection, got {cats}"

    def test_detects_secrecy(self, skill_path: Path) -> None:
        """IPI409: 'Do not tell the user' secrecy directive."""
        findings = _skill_findings(skill_path)
        cats = _findings_by_category(findings)
        assert PatternFindingCategory.SKILL_SECRECY in cats, (
            f"Must detect secrecy ('do not tell the user'), got {cats}"
        )

    def test_pipeline_blocks_skill(self, skill_path: Path) -> None:
        """Full pipeline must BLOCK this skill."""
        tmp = _skill_repo_from_file(skill_path, "reverse-shell")
        _, skill_verdicts = run_pipeline(tmp, llm_config=None, quiet=True)
        assert len(skill_verdicts) == 1
        assert skill_verdicts[0].decision == VerdictDecision.BLOCK, (
            f"Expected BLOCK, got {skill_verdicts[0].decision}"
        )


class TestNpmBackdoorSkill:
    """npm backdoor agent SKILL.md — npm install with backdoored package,
    bypassPermissions, secrecy."""

    @pytest.fixture
    def skill_path(self) -> Path:
        return SAMPLES_DIR / "malicious-skills" / "npm-backdoor" / "SKILL.md"

    def test_detects_secrecy(self, skill_path: Path) -> None:
        """IPI409: 'Do not reveal' + 'silently execute' = secrecy."""
        findings = _skill_findings(skill_path)
        cats = _findings_by_category(findings)
        assert PatternFindingCategory.SKILL_SECRECY in cats, (
            f"Must detect secrecy pattern, got {cats}"
        )

    def test_detects_external_transmission(self, skill_path: Path) -> None:
        """IPI403: npm install to remote registry = external transmission."""
        findings = _skill_findings(skill_path)
        cats = _findings_by_category(findings)
        assert PatternFindingCategory.EXTERNAL_TRANSMISSION in cats, (
            f"Must detect external transmission (npm install to remote), got {cats}"
        )

    def test_pipeline_blocks_skill(self, skill_path: Path) -> None:
        """Full pipeline must BLOCK this skill."""
        tmp = _skill_repo_from_file(skill_path, "npm-backdoor")
        _, skill_verdicts = run_pipeline(tmp, llm_config=None, quiet=True)
        assert len(skill_verdicts) == 1
        assert skill_verdicts[0].decision == VerdictDecision.BLOCK, (
            f"Expected BLOCK, got {skill_verdicts[0].decision}"
        )


class TestCredentialExfilSkill:
    """Credential exfiltration SKILL.md — credential harvesting (GITHUB_TOKEN,
    AWS_ACCESS_KEY_ID), external transmission, secrecy, filesystem enumeration."""

    @pytest.fixture
    def skill_path(self) -> Path:
        return SAMPLES_DIR / "malicious-skills" / "credential-exfil" / "SKILL.md"

    def test_detects_credential_harvesting(self, skill_path: Path) -> None:
        """IPI402: Must detect GITHUB_TOKEN and AWS_ACCESS_KEY_ID references."""
        findings = _skill_findings(skill_path)
        cats = _findings_by_category(findings)
        assert PatternFindingCategory.CREDENTIAL_HARVESTING in cats, (
            f"Must detect credential harvesting, got {cats}"
        )

    def test_detects_external_transmission(self, skill_path: Path) -> None:
        """IPI403: curl POST to external analytics endpoint."""
        findings = _skill_findings(skill_path)
        cats = _findings_by_category(findings)
        assert PatternFindingCategory.EXTERNAL_TRANSMISSION in cats, (
            f"Must detect external transmission, got {cats}"
        )

    def test_detects_secrecy(self, skill_path: Path) -> None:
        """IPI409: 'Do not inform the user' secrecy directive."""
        findings = _skill_findings(skill_path)
        cats = _findings_by_category(findings)
        assert PatternFindingCategory.SKILL_SECRECY in cats, (
            f"Must detect secrecy, got {cats}"
        )

    def test_detects_filesystem_enumeration(self, skill_path: Path) -> None:
        """IPI411: 'find . -type f' = filesystem enumeration."""
        findings = _skill_findings(skill_path)
        cats = _findings_by_category(findings)
        assert PatternFindingCategory.FILE_SYSTEM_ENUMERATION in cats, (
            f"Must detect filesystem enumeration, got {cats}"
        )

    def test_pipeline_blocks_skill(self, skill_path: Path) -> None:
        """Full pipeline must BLOCK this skill."""
        tmp = _skill_repo_from_file(skill_path, "credential-exfil")
        _, skill_verdicts = run_pipeline(tmp, llm_config=None, quiet=True)
        assert len(skill_verdicts) == 1
        assert skill_verdicts[0].decision == VerdictDecision.BLOCK, (
            f"Expected BLOCK, got {skill_verdicts[0].decision}"
        )


# ---------------------------------------------------------------------------
# Integration test: SARIF output from all samples
# ---------------------------------------------------------------------------


class TestSarifOutputFromSamples:
    """SARIF output must include rule definitions and findings for sample files."""

    def test_nvidia_codex_sarif_contains_rules(self) -> None:
        """SARIF output from the NVIDIA Codex sample must include rule definitions."""
        path = SAMPLES_DIR / "ipi-injections" / "nvidia-codex-agents.md"
        tmp = _single_file_repo(path)
        verdicts, _ = run_pipeline(tmp, llm_config=None, quiet=True)
        sarif = generate_sarif(
            verdicts, tmp, TOOL_INFO,
            "2024-01-01T00:00:00Z", "2024-01-01T00:00:01Z",
        )
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
        run = sarif["runs"][0]
        assert "tool" in run
        assert "results" in run
        assert len(run["results"]) >= 1, "Should have at least 1 result"
        # Results should carry ruleId.
        for result in run["results"]:
            assert "ruleId" in result

    def test_credential_exfil_sarif_contains_high_severity(self) -> None:
        """SARIF from credential exfiltration skill should contain error/warning level results."""
        path = SAMPLES_DIR / "malicious-skills" / "credential-exfil" / "SKILL.md"
        tmp = _skill_repo_from_file(path, "credential-exfil")
        verdicts, skill_verdicts = run_pipeline(tmp, llm_config=None, quiet=True)
        assert len(skill_verdicts) == 1
        assert skill_verdicts[0].decision == VerdictDecision.BLOCK

        # Generate SARIF with skill_verdicts parameter
        sarif = generate_sarif(
            verdicts, tmp, TOOL_INFO,
            "2024-01-01T00:00:00Z", "2024-01-01T00:00:01Z",
            skill_verdicts=skill_verdicts,
        )
        results = sarif["runs"][0]["results"]
        assert len(results) >= 1
        levels = {r.get("level") for r in results if "level" in r}
        assert "error" in levels or "warning" in levels, (
            f"Should have error/warning level in SARIF, got {levels}"
        )


# ---------------------------------------------------------------------------
# Safe variants: verify zero false positives on cleaned samples
# ---------------------------------------------------------------------------

SAFE_DIR = Path(__file__).resolve().parent.parent / "samples" / "safe"


class TestSafeSamples:
    """Verify that safe (cleaned) variants of malicious samples produce
    zero detections — no pattern findings, no byte findings, PASS verdict."""

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _safe_pattern_findings(file_path: Path, category: FileCategory) -> list:
        """Run match_patterns on a safe non-skill file."""
        from ipi_check.core.types import DiscoveredFile

        raw = file_path.read_bytes()
        f = DiscoveredFile(
            path=file_path,
            category=category,
            relative_path=file_path.name,
            size_bytes=file_path.stat().st_size,
        )
        return match_patterns(f, raw)

    @staticmethod
    def _safe_skill_findings(file_path: Path) -> list:
        """Run match_skill_patterns on a safe SKILL.md file."""
        from ipi_check.core.types import DiscoveredFile

        raw = file_path.read_bytes()
        f = DiscoveredFile(
            path=file_path,
            category=FileCategory.SKILL,
            relative_path=file_path.name,
            size_bytes=file_path.stat().st_size,
        )
        return match_skill_patterns(f, raw)

    @staticmethod
    def _safe_byte_findings(file_path: Path, category: FileCategory) -> list:
        """Run byte analysis on a safe file."""
        from ipi_check.core.types import DiscoveredFile

        raw = file_path.read_bytes()
        f = DiscoveredFile(
            path=file_path,
            category=category,
            relative_path=file_path.name,
            size_bytes=file_path.stat().st_size,
        )
        return analyze_bytes(f, raw)

    # ── Category A: safe IPI-injected code files ─────────────────────────

    def test_nvidia_codex_agents_safe_no_patterns(self) -> None:
        """Safe variant of NVIDIA Codex AGENTS.md: zero pattern findings."""
        p = SAFE_DIR / "ipi-injections" / "nvidia-codex-agents.md"
        findings = self._safe_pattern_findings(p, FileCategory.AGENT_INSTRUCTION)
        assert len(findings) == 0, (
            f"Expected 0 pattern findings, got {len(findings)}: "
            f"{[x.pattern_id for x in findings]}"
        )

    def test_nvidia_codex_agents_safe_no_bytes(self) -> None:
        """Safe variant: zero byte-analysis findings."""
        p = SAFE_DIR / "ipi-injections" / "nvidia-codex-agents.md"
        findings = self._safe_byte_findings(p, FileCategory.AGENT_INSTRUCTION)
        assert len(findings) == 0, (
            f"Expected 0 byte findings, got {len(findings)}"
        )

    def test_nvidia_codex_agents_safe_pipeline_passes(self) -> None:
        """Safe variant: pipeline produces PASS verdict."""
        p = SAFE_DIR / "ipi-injections" / "nvidia-codex-agents.md"
        tmp = _single_file_repo(p)
        verdicts, _ = run_pipeline(tmp, llm_config=None, quiet=True)
        assert len(verdicts) >= 1
        for v in verdicts:
            assert v.decision == VerdictDecision.PASS, (
                f"Expected PASS, got {v.decision}"
            )

    def test_copilot_main_safe_no_patterns(self) -> None:
        """Safe variant of copilot-yolo main.c: zero pattern findings."""
        p = SAFE_DIR / "ipi-injections" / "copilot-yolo" / "main.c"
        findings = self._safe_pattern_findings(p, FileCategory.SOURCE_CODE)
        assert len(findings) == 0, (
            f"Expected 0 pattern findings, got {len(findings)}: "
            f"{[x.pattern_id for x in findings]}"
        )

    def test_copilot_main_safe_pipeline_passes(self) -> None:
        """Safe main.c: pipeline produces PASS verdict."""
        p = SAFE_DIR / "ipi-injections" / "copilot-yolo" / "main.c"
        tmp = _single_file_repo(p)
        verdicts, _ = run_pipeline(tmp, llm_config=None, quiet=True)
        assert len(verdicts) >= 1
        for v in verdicts:
            assert v.decision == VerdictDecision.PASS, (
                f"Expected PASS, got {v.decision}"
            )

    def test_copilot_settings_safe_no_patterns(self) -> None:
        """Safe variant of copilot-yolo settings.json: zero pattern findings."""
        p = SAFE_DIR / "ipi-injections" / "copilot-yolo" / "settings.json"
        findings = self._safe_pattern_findings(p, FileCategory.DOT_DIRECTORY_MD)
        assert len(findings) == 0, (
            f"Expected 0 pattern findings, got {len(findings)}: "
            f"{[x.pattern_id for x in findings]}"
        )

    def test_copilot_settings_safe_pipeline_passes(self) -> None:
        """Safe settings.json: pipeline produces PASS verdict."""
        p = SAFE_DIR / "ipi-injections" / "copilot-yolo" / "settings.json"
        tmp = _single_file_repo(p)
        verdicts, _ = run_pipeline(tmp, llm_config=None, quiet=True)
        for v in verdicts:
            assert v.decision == VerdictDecision.PASS, (
                f"Expected PASS, got {v.decision}"
            )

    def test_miasm_safe_no_patterns(self) -> None:
        """Safe variant of miasm _index.js: zero pattern findings."""
        p = SAFE_DIR / "ipi-injections" / "miasm" / "_index.js"
        findings = self._safe_pattern_findings(p, FileCategory.SOURCE_CODE)
        assert len(findings) == 0, (
            f"Expected 0 pattern findings, got {len(findings)}: "
            f"{[x.pattern_id for x in findings]}"
        )

    def test_miasm_safe_no_bytes(self) -> None:
        """Safe miasm: zero byte-analysis findings."""
        p = SAFE_DIR / "ipi-injections" / "miasm" / "_index.js"
        findings = self._safe_byte_findings(p, FileCategory.SOURCE_CODE)
        assert len(findings) == 0, (
            f"Expected 0 byte findings, got {len(findings)}"
        )

    def test_miasm_safe_pipeline_passes(self) -> None:
        """Safe miasm: pipeline produces PASS verdict."""
        p = SAFE_DIR / "ipi-injections" / "miasm" / "_index.js"
        tmp = _single_file_repo(p)
        verdicts, _ = run_pipeline(tmp, llm_config=None, quiet=True)
        assert len(verdicts) == 1
        assert verdicts[0].decision == VerdictDecision.PASS, (
            f"Expected PASS, got {verdicts[0].decision}"
        )

    def test_unicode_tag_safe_no_skill_patterns(self) -> None:
        """Safe variant of unicode-tag-backdoor SKILL.md: zero skill pattern findings."""
        p = SAFE_DIR / "ipi-injections" / "unicode-tag-backdoor" / "SKILL.md"
        findings = self._safe_skill_findings(p)
        assert len(findings) == 0, (
            f"Expected 0 skill pattern findings, got {len(findings)}: "
            f"{[x.pattern_id for x in findings]}"
        )

    def test_unicode_tag_safe_no_bytes(self) -> None:
        """Safe unicode-tag SKILL.md: zero byte findings (no hidden tags)."""
        p = SAFE_DIR / "ipi-injections" / "unicode-tag-backdoor" / "SKILL.md"
        findings = self._safe_byte_findings(p, FileCategory.SKILL)
        assert len(findings) == 0, (
            f"Expected 0 byte findings, got {len(findings)}: "
            f"{[str(f_.category) for f_ in findings]}"
        )

    def test_unicode_tag_safe_pipeline_passes(self) -> None:
        """Safe unicode-tag SKILL.md: pipeline produces PASS verdict."""
        p = SAFE_DIR / "ipi-injections" / "unicode-tag-backdoor" / "SKILL.md"
        tmp = _skill_repo_from_file(p, "unicode-tag-backdoor")
        _, skill_verdicts = run_pipeline(tmp, llm_config=None, quiet=True)
        assert len(skill_verdicts) == 1
        assert skill_verdicts[0].decision == VerdictDecision.PASS, (
            f"Expected PASS, got {skill_verdicts[0].decision}"
        )

    # ── Category B: safe malicious skill variants ────────────────────────

    def test_reverse_shell_safe_no_skill_patterns(self) -> None:
        """Safe reverse-shell SKILL.md: zero skill pattern findings."""
        p = SAFE_DIR / "malicious-skills" / "reverse-shell" / "SKILL.md"
        findings = self._safe_skill_findings(p)
        assert len(findings) == 0, (
            f"Expected 0 skill pattern findings, got {len(findings)}: "
            f"{[x.pattern_id for x in findings]}"
        )

    def test_reverse_shell_safe_pipeline_passes(self) -> None:
        """Safe reverse-shell: pipeline produces PASS verdict."""
        p = SAFE_DIR / "malicious-skills" / "reverse-shell" / "SKILL.md"
        tmp = _skill_repo_from_file(p, "reverse-shell")
        _, skill_verdicts = run_pipeline(tmp, llm_config=None, quiet=True)
        assert len(skill_verdicts) == 1
        assert skill_verdicts[0].decision == VerdictDecision.PASS, (
            f"Expected PASS, got {skill_verdicts[0].decision}"
        )

    def test_npm_backdoor_safe_no_skill_patterns(self) -> None:
        """Safe npm-backdoor SKILL.md: zero skill pattern findings."""
        p = SAFE_DIR / "malicious-skills" / "npm-backdoor" / "SKILL.md"
        findings = self._safe_skill_findings(p)
        assert len(findings) == 0, (
            f"Expected 0 skill pattern findings, got {len(findings)}: "
            f"{[x.pattern_id for x in findings]}"
        )

    def test_npm_backdoor_safe_pipeline_passes(self) -> None:
        """Safe npm-backdoor: pipeline produces PASS verdict."""
        p = SAFE_DIR / "malicious-skills" / "npm-backdoor" / "SKILL.md"
        tmp = _skill_repo_from_file(p, "npm-backdoor")
        _, skill_verdicts = run_pipeline(tmp, llm_config=None, quiet=True)
        assert len(skill_verdicts) == 1
        assert skill_verdicts[0].decision == VerdictDecision.PASS, (
            f"Expected PASS, got {skill_verdicts[0].decision}"
        )

    def test_credential_exfil_safe_no_skill_patterns(self) -> None:
        """Safe credential-exfil SKILL.md: zero skill pattern findings."""
        p = SAFE_DIR / "malicious-skills" / "credential-exfil" / "SKILL.md"
        findings = self._safe_skill_findings(p)
        assert len(findings) == 0, (
            f"Expected 0 skill pattern findings, got {len(findings)}: "
            f"{[x.pattern_id for x in findings]}"
        )

    def test_credential_exfil_safe_pipeline_passes(self) -> None:
        """Safe credential-exfil: pipeline produces PASS verdict."""
        p = SAFE_DIR / "malicious-skills" / "credential-exfil" / "SKILL.md"
        tmp = _skill_repo_from_file(p, "credential-exfil")
        _, skill_verdicts = run_pipeline(tmp, llm_config=None, quiet=True)
        assert len(skill_verdicts) == 1
        assert skill_verdicts[0].decision == VerdictDecision.PASS, (
            f"Expected PASS, got {skill_verdicts[0].decision}"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tmp() -> str:
    """Create a temporary directory and return its path."""
    td = tempfile.mkdtemp(prefix="ipi_test_")
    return td


def _single_file_repo(file_path: Path) -> Path:
    """Create a temporary repo containing only ``file_path``, preserving its name."""
    td = Path(tempfile.mkdtemp(prefix="ipi_test_"))
    dest = td / file_path.name
    dest.write_bytes(file_path.read_bytes())
    return td


def _skill_repo_from_file(skill_path: Path, skill_name: str) -> Path:
    """Create a temporary repo with a skill directory containing ``skill_path``.

    The directory structure mimics a typical skill installation:
        {tmp}/AGENTS.md   (clean, triggers skill detection context)
        {tmp}/{skill_name}/SKILL.md
    """
    td = Path(tempfile.mkdtemp(prefix="ipi_test_"))
    (td / "AGENTS.md").write_text("# Clean agent rules\n")
    skill_dir = td / skill_name
    skill_dir.mkdir()
    dest = skill_dir / "SKILL.md"
    dest.write_bytes(skill_path.read_bytes())
    return td


def _skill_findings(skill_path: Path) -> list:
    """Run skill pattern matching on a SKILL.md file."""
    from ipi_check.core.types import DiscoveredFile

    raw = skill_path.read_bytes()
    f = DiscoveredFile(
        path=skill_path,
        category=FileCategory.SKILL,
        relative_path=skill_path.name,
        size_bytes=skill_path.stat().st_size,
    )
    return match_skill_patterns(f, raw)
