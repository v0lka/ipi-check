"""Static Result — assemble static analysis results and orchestrate layers 1-4."""
from __future__ import annotations

import re
import warnings
from typing import TYPE_CHECKING

from ipi_check.core.types import (
    ByteFinding,
    DiscoveredFile,
    FileCategory,
    HeuristicScores,
    PatternFinding,
    Severity,
    StaticResult,
)
from ipi_check.scanner.byte_analysis import analyze_bytes
from ipi_check.scanner.code_extractor import extract_comments_and_strings
from ipi_check.scanner.file_discovery import discover_files
from ipi_check.scanner.pattern_matching import match_patterns
from ipi_check.scanner.semantic_heuristics import compute_heuristics

if TYPE_CHECKING:
    from pathlib import Path

# Threshold (suspicious_count) at which heuristic scores escalate to HIGH severity.
HEURISTIC_HIGH_SEVERITY_THRESHOLD: int = 2

# UTF-8 decoding configuration for visible-text extraction.
_TEXT_DECODE_ENCODING: str = "utf-8"
_TEXT_DECODE_ERRORS: str = "replace"

# Invisible-character cleanup regex for visible-text extraction. This mirrors
# the pattern used by the pattern-matching layer but is applied without
# lowercasing or whitespace collapsing — the heuristics layer needs the
# original casing and paragraph structure.
#
# Ranges removed:
#   - ANSI escape sequences (CSI/OSC and similar): ESC [ ... <letter>
#   - Unicode tag block: U+E0000-U+E007F
#   - Zero-width / line / paragraph separators: U+200B-U+200F, U+2028-U+2029
#   - Bidi overrides: U+202A-U+202E, U+2066-U+2069
#   - Variation selectors: U+FE00-U+FE0F
_INVISIBLE_CHARS_RE: re.Pattern[str] = re.compile(
    "\x1b\\[[^A-Za-z]*[A-Za-z]"
    "|[\U000e0000-\U000e007f]"
    "|[\u200b-\u200f\u2028\u2029]"
    "|[\u202a-\u202e\u2066-\u2069]"
    "|[\ufe00-\ufe0f]"
)


def _get_visible_text(raw_bytes: bytes) -> str:
    """Decode raw bytes and strip invisible characters without altering casing.

    Used by the static pipeline to feed semantic heuristics. Unlike the
    pattern-matching ``normalize_text`` helper, this function preserves
    casing, whitespace, and paragraph breaks so that downstream entropy
    and instruction-density measurements remain meaningful.
    """
    decoded = raw_bytes.decode(_TEXT_DECODE_ENCODING, errors=_TEXT_DECODE_ERRORS)
    return _INVISIBLE_CHARS_RE.sub("", decoded)


def _has_severity(
    findings: list[ByteFinding] | list[PatternFinding],
    severity: Severity,
) -> bool:
    """Return ``True`` if any finding in ``findings`` has the given severity."""
    return any(f.severity == severity for f in findings)


def compute_static_severity(
    byte_findings: list[ByteFinding],
    pattern_findings: list[PatternFinding],
    heuristic_scores: HeuristicScores,
) -> Severity:
    """Compute the overall static severity from all findings.

    Logic:
        - Any CRITICAL byte or pattern finding → CRITICAL
        - Any HIGH byte or pattern finding → HIGH
        - heuristic_scores.suspicious_count >= 2 → HIGH
        - Any byte or pattern finding at all → MEDIUM
        - Otherwise → NONE
    """
    if _has_severity(byte_findings, Severity.CRITICAL) or _has_severity(
        pattern_findings, Severity.CRITICAL
    ):
        return Severity.CRITICAL

    if _has_severity(byte_findings, Severity.HIGH) or _has_severity(
        pattern_findings, Severity.HIGH
    ):
        return Severity.HIGH

    if heuristic_scores.suspicious_count >= HEURISTIC_HIGH_SEVERITY_THRESHOLD:
        return Severity.HIGH

    if byte_findings or pattern_findings:
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


def run_static_pipeline(
    repo_path: Path,
    *,
    respect_gitignore: bool = True,
    exclude_patterns: list[str] | None = None,
) -> list[StaticResult]:
    """Run the complete static analysis pipeline (layers 1-4).

    Orchestrates: File Discovery → for each file: read bytes → Byte Analysis
    → Pattern Matching + Semantic Heuristics → assemble :class:`StaticResult`.
    """
    discovered = discover_files(
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

    return results
