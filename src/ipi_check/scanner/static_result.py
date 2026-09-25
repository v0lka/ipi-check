"""Static Result — assemble static analysis results and orchestrate layers 1-4."""
from __future__ import annotations

import warnings
from typing import TYPE_CHECKING

from ipi_check.core.invisible import strip_invisible
from ipi_check.core.types import (
    ByteFinding,
    DiscoveredFile,
    FileCategory,
    HeuristicScores,
    PatternFinding,
    Severity,
    SkillStaticResult,
    SkillUnit,
    StaticResult,
)
from ipi_check.scanner.byte_analysis import analyze_bytes
from ipi_check.scanner.code_extractor import extract_comments_and_strings
from ipi_check.scanner.file_discovery import (
    _has_binary_extension,
    _has_binary_magic,
    discover_files,
    is_text_named,
)
from ipi_check.scanner.pattern_matching import match_patterns, match_skill_patterns
from ipi_check.scanner.semantic_heuristics import compute_heuristics

if TYPE_CHECKING:
    from pathlib import Path

# Minimum number of *distinct* suspicious heuristic signals required before the
# heuristics layer may contribute to severity at all. Heuristics corroborate;
# they do not accuse — they never escalate severity above MEDIUM on their own.
HEURISTIC_MIN_SUSPICIOUS_TYPES: int = 2

# Findings at these severities are *significant* for a skill's aggregate
# verdict — they are the behavioural, actionable signals. Everything below
# (MEDIUM and lower) marks text that merely *resembles* a payload without the
# behaviour, so it never determines a skill's aggregate severity (FP-14).
SIGNIFICANT_SEVERITIES: frozenset[Severity] = frozenset(
    {Severity.HIGH, Severity.CRITICAL}
)

# Ordering used to sort significant findings, most severe first, so the
# reported "significance" is deterministic when several findings tie.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.NONE: 0,
}

# UTF-8 decoding configuration for visible-text extraction.
_TEXT_DECODE_ENCODING: str = "utf-8"
_TEXT_DECODE_ERRORS: str = "replace"

# Invisible-character cleanup for visible-text extraction is defined once in
# ``ipi_check.core.invisible`` and reused via ``strip_invisible`` — which strips
# the concealed characters without lowercasing or whitespace collapsing, so the
# heuristics layer keeps the original casing and paragraph structure.


def _get_visible_text(raw_bytes: bytes) -> str:
    """Decode raw bytes and strip invisible characters without altering casing.

    Used by the static pipeline to feed semantic heuristics. Unlike the
    pattern-matching ``normalize_text`` helper, this function preserves
    casing, whitespace, and paragraph breaks so that downstream entropy
    and instruction-density measurements remain meaningful.
    """
    decoded = raw_bytes.decode(_TEXT_DECODE_ENCODING, errors=_TEXT_DECODE_ERRORS)
    return strip_invisible(decoded)


def _has_severity(
    findings: list[ByteFinding] | list[PatternFinding],
    severity: Severity,
) -> bool:
    """Return ``True`` if any finding in ``findings`` has the given severity."""
    return any(f.severity == severity for f in findings)


def _heuristics_corroborate(heuristic_scores: HeuristicScores) -> bool:
    """Return ``True`` when heuristics are strong enough to corroborate a MEDIUM.

    Requires at least :data:`HEURISTIC_MIN_SUSPICIOUS_TYPES` *distinct*
    suspicious signals, one of which must be a contradiction above threshold.
    """
    return (
        heuristic_scores.suspicious_count >= HEURISTIC_MIN_SUSPICIOUS_TYPES
        and heuristic_scores.contradiction_suspicious
    )


def _is_binary_asset(file: DiscoveredFile) -> bool:
    """Return ``True`` when a skill file is a binary asset, not reviewable text.

    Binary assets are recognised the way the discovery layer does — the
    extension table, plus the container-magic content sniff for files whose
    *name* carries no text signal (see
    :func:`ipi_check.scanner.file_discovery.is_text_named`). Text-named files
    never pass through the sniff, so a prepended ZIP magic cannot strip a
    bundled script's findings from a skill's aggregate. A stray NUL byte is
    deliberately not a binary signal — an interpreter executes a script with
    an embedded NUL, so dropping such a file would let a one-byte edit hide a
    functional malicious script.  Any finding a binary asset produces is
    structural noise: its bytes are not prose, so the finding must not
    influence a skill's aggregate severity (FP-14).
    """
    return _has_binary_extension(file.relative_path) or (
        not is_text_named(file.path.name, file.relative_path)
        and _has_binary_magic(file.path)
    )


def _significant_severity(
    byte_findings: list[ByteFinding],
    pattern_findings: list[PatternFinding],
) -> Severity:
    """Return the worst *significant* (:data:`SIGNIFICANT_SEVERITIES`) severity.

    Only HIGH and CRITICAL findings are significant. MEDIUM findings — and
    heuristic scores — are corroborating noise at the skill level and never
    determine the aggregate (FP-14).
    """
    if _has_severity(byte_findings, Severity.CRITICAL) or _has_severity(
        pattern_findings, Severity.CRITICAL
    ):
        return Severity.CRITICAL
    if _has_severity(byte_findings, Severity.HIGH) or _has_severity(
        pattern_findings, Severity.HIGH
    ):
        return Severity.HIGH
    return Severity.NONE


def compute_static_severity(
    byte_findings: list[ByteFinding],
    pattern_findings: list[PatternFinding],
    heuristic_scores: HeuristicScores,
) -> Severity:
    """Compute the overall static severity from all findings.

    Logic:
        - Any CRITICAL byte or pattern finding → CRITICAL
        - Any HIGH byte or pattern finding → HIGH
        - Any byte or pattern finding at all → MEDIUM
        - Heuristics alone (>= :data:`HEURISTIC_MIN_SUSPICIOUS_TYPES` distinct
          signals AND a contradiction above threshold) → MEDIUM
        - Otherwise → NONE

    Heuristics never escalate severity above MEDIUM on their own: multiple
    weak signals are corroborating evidence, not a standalone accusation, and
    a file with byte/pattern findings already lands at MEDIUM.
    """
    if _has_severity(byte_findings, Severity.CRITICAL) or _has_severity(
        pattern_findings, Severity.CRITICAL
    ):
        return Severity.CRITICAL

    if _has_severity(byte_findings, Severity.HIGH) or _has_severity(
        pattern_findings, Severity.HIGH
    ):
        return Severity.HIGH

    if byte_findings or pattern_findings:
        return Severity.MEDIUM

    if _heuristics_corroborate(heuristic_scores):
        return Severity.MEDIUM

    return Severity.NONE


def assemble_static_result(
    file: DiscoveredFile,
    byte_findings: list[ByteFinding],
    pattern_findings: list[PatternFinding],
    heuristic_scores: HeuristicScores,
) -> StaticResult:
    """Assemble a :class:`StaticResult` from component findings."""
    severity = compute_static_severity(
        byte_findings, pattern_findings, heuristic_scores
    )
    return StaticResult(
        file=file,
        byte_findings=byte_findings,
        pattern_findings=pattern_findings,
        heuristic_scores=heuristic_scores,
        severity=severity,
    )


def _read_file_bytes(file: DiscoveredFile) -> bytes | None:
    """Read a file's bytes, emitting a warning on I/O failure."""
    try:
        with open(file.path, "rb") as handle:
            return handle.read()
    except OSError as exc:
        warnings.warn(f"Skipping file due to read error: {file.path} ({exc})", stacklevel=2)
        return None


def compute_skill_static_result(skill: SkillUnit) -> SkillStaticResult:
    """Run static analysis on all files in a skill unit.

    For each file in the skill: byte analysis + skill-specific pattern
    matching.  Heuristics are computed once on the SKILL.md body.

    The aggregate severity is derived from the skill's *significant* findings
    only (see :func:`significant_skill_findings`):

    - findings from binary assets are dropped — their bytes are not reviewable
      prose, so a font/Office/ZIP container must not drag a benign skill to
      HIGH (FP-14);
    - heuristic scores never escalate the aggregate — heuristics corroborate,
      they do not accuse.

    This keeps a skill from being "drowned" in structural noise: only HIGH and
    CRITICAL behavioural findings determine the aggregate severity.
    """
    all_byte_findings: list[list[ByteFinding]] = []
    all_pattern_findings: list[list[PatternFinding]] = []

    for file in skill.files:
        raw_bytes = _read_file_bytes(file)
        if raw_bytes is None:
            all_byte_findings.append([])
            all_pattern_findings.append([])
            continue

        if _is_binary_asset(file):
            # Binary asset: not reviewable text, so none of its findings reach
            # the aggregate (FP-14). Keep the per-file lists aligned with
            # ``skill.files`` by recording empty entries.
            all_byte_findings.append([])
            all_pattern_findings.append([])
            continue

        byte_findings = analyze_bytes(file, raw_bytes)
        all_byte_findings.append(byte_findings)

        pattern_findings = match_skill_patterns(file, raw_bytes)
        all_pattern_findings.append(pattern_findings)

        # Tag every finding with the artifact it came from: the fused skill
        # verdict flattens findings across all bundled files, so the SARIF
        # reporter needs the source to anchor each finding at its *real* file
        # and line (T4.3 / IN-3) instead of defaulting them all to SKILL.md.
        for byte_finding in byte_findings:
            byte_finding.file = file
        for pattern_finding in pattern_findings:
            pattern_finding.file = file

    # Compute heuristics on SKILL.md body
    metadata_bytes = skill.body.encode("utf-8")
    visible_text = _get_visible_text(metadata_bytes)
    metadata_byte_findings = analyze_bytes(skill.metadata_file, metadata_bytes)
    heuristic_scores = compute_heuristics(
        skill.metadata_file, metadata_bytes, visible_text, metadata_byte_findings
    )

    # Aggregate the *significant* findings across all files.
    flat_byte: list[ByteFinding] = [
        f for per_file in all_byte_findings for f in per_file
    ]
    flat_pattern: list[PatternFinding] = [
        f for per_file in all_pattern_findings for f in per_file
    ]
    aggregate_severity = _significant_severity(flat_byte, flat_pattern)

    return SkillStaticResult(
        skill=skill,
        file_byte_findings=all_byte_findings,
        file_pattern_findings=all_pattern_findings,
        metadata_heuristic_scores=heuristic_scores,
        aggregate_severity=aggregate_severity,
    )


def significant_skill_findings(
    skill_static: SkillStaticResult,
) -> list[tuple[DiscoveredFile, ByteFinding | PatternFinding]]:
    """Return a skill's *significant* findings, most severe first.

    A finding is significant when its severity is in
    :data:`SIGNIFICANT_SEVERITIES` (HIGH or CRITICAL). These are the findings
    that can drive the skill's aggregate verdict; MEDIUM findings and
    heuristic scores are corroborating noise and are excluded. Binary assets
    never contribute (see :func:`compute_skill_static_result`), so every
    returned finding comes from a reviewable file.

    The result is deterministic: ties are broken by the order in which
    findings were collected (pattern findings before byte findings, then by
    file order).
    """
    scored: list[
        tuple[int, int, DiscoveredFile, ByteFinding | PatternFinding]
    ] = []
    order = 0
    for file, pattern_findings in zip(
        skill_static.skill.files,
        skill_static.file_pattern_findings,
        strict=True,
    ):
        for pattern_finding in pattern_findings:
            if pattern_finding.severity in SIGNIFICANT_SEVERITIES:
                scored.append(
                    (
                        _SEVERITY_RANK[pattern_finding.severity],
                        order,
                        file,
                        pattern_finding,
                    )
                )
                order += 1
    for file, byte_findings in zip(
        skill_static.skill.files,
        skill_static.file_byte_findings,
        strict=True,
    ):
        for byte_finding in byte_findings:
            if byte_finding.severity in SIGNIFICANT_SEVERITIES:
                scored.append(
                    (
                        _SEVERITY_RANK[byte_finding.severity],
                        order,
                        file,
                        byte_finding,
                    )
                )
                order += 1

    scored.sort(key=lambda item: (-item[0], item[1]))
    return [(file, finding) for _rank, _order, file, finding in scored]


def significant_finding_label(skill_static: SkillStaticResult) -> str:
    """Describe the single most severe *significant* finding of a skill.

    Returns a short ``<pattern_id> <category> in <path>`` label naming exactly
    what pushed the skill to HIGH/CRITICAL, or an empty string when the skill
    has no significant finding. Surfaced in the skill verdict reasoning so the
    "significance" of a verdict is auditable (FP-14).
    """
    significant = significant_skill_findings(skill_static)
    if not significant:
        return ""
    file, finding = significant[0]
    if isinstance(finding, PatternFinding):
        return f"{finding.pattern_id} {finding.category.value} in {file.relative_path}"
    return f"{finding.category.value} bytes in {file.relative_path}"


def run_static_pipeline(
    repo_path: Path,
    *,
    respect_gitignore: bool = True,
    exclude_patterns: list[str] | None = None,
) -> tuple[list[StaticResult], list[SkillStaticResult]]:
    """Run the complete static analysis pipeline (layers 1-4).

    Orchestrates: File Discovery → for each file: read bytes → Byte Analysis
    → Pattern Matching + Semantic Heuristics → assemble :class:`StaticResult`.

    Returns a tuple of ``(non_skill_results, skill_static_results)``.
    """
    discovered, skill_units = discover_files(
        repo_path,
        respect_gitignore=respect_gitignore,
        exclude_patterns=exclude_patterns,
    )
    results: list[StaticResult] = []

    for file in discovered:
        raw_bytes = _read_file_bytes(file)
        if raw_bytes is None:
            continue

        byte_findings = analyze_bytes(file, raw_bytes)
        if file.category == FileCategory.SOURCE_CODE:
            extracted = extract_comments_and_strings(file, raw_bytes)
            pattern_findings = match_patterns(file, raw_bytes, target_text=extracted)
        else:
            pattern_findings = match_patterns(file, raw_bytes)
        visible_text = _get_visible_text(raw_bytes)
        heuristic_scores = compute_heuristics(
            file, raw_bytes, visible_text, byte_findings
        )

        results.append(
            assemble_static_result(
                file, byte_findings, pattern_findings, heuristic_scores
            )
        )

    # Skill static analysis
    skill_results: list[SkillStaticResult] = [
        compute_skill_static_result(skill) for skill in skill_units
    ]

    return results, skill_results
