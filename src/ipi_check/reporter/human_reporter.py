"""Human-readable reporters — Markdown and plain-text table (T5.2 / IN-18).

The scanner's canonical output is SARIF v2.1.0 (machine-oriented, consumed by
GitHub Code Scanning / GitLab SAST / IDE viewers). This module adds two
*reviewer-oriented* renderers plus a lightweight JSON projection, all derived
from the same verdict model:

* :func:`render_markdown` — a grouped Markdown report (``--format md``): one
  section per verdict decision (BLOCK → REVIEW_REQUIRED → PASS), each file or
  skill listed with its severity, LLM verdict and findings.
* :func:`render_table` — the same information as a fixed-width ASCII table
  (``--format table``), for terminals and plain-text CI logs.
* :func:`build_json_report` — a flat, purpose-built JSON summary
  (``--format json``), i.e. the findings without the SARIF ceremony.

The renderers never touch the SARIF document: ``--format sarif`` stays the
default and its output is unchanged (invariant of task T5.2). They also own the
per-format default file extension used to auto-complete ``--output``.

Every field interpolated from the verdict model is treated as untrusted
(paths come from file names, messages from file/LLM content): the Markdown
renderer escapes them (:func:`_md_text` / :func:`_md_code_span`, R005 parity
with the SARIF reporter) and the table renderer neutralizes concealed
characters, so report content can neither forge report structure nor smuggle
terminal control sequences.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ipi_check import TOOL_INFO
from ipi_check.core.invisible import INVISIBLE_CHARS_RE
from ipi_check.core.types import (
    ByteFinding,
    FinalVerdict,
    LLMFinding,
    PatternFinding,
    Severity,
    SkillFinalVerdict,
    VerdictDecision,
)
from ipi_check.reporter.sarif_reporter import (
    CATEGORY_TO_RULE_ID,
    LLM_COMPROMISE_RULE_ID,
    LLM_FINDING_RULE_ID,
    MAX_MESSAGE_SNIPPET_LENGTH,
    SEVERITY_TO_LEVEL,
    SKILL_LLM_RULE_ID,
)

if TYPE_CHECKING:
    from pathlib import Path

    from ipi_check.core.types import HeuristicScores, SarifLimitStats

# A verdict is either a file verdict or a skill verdict.
Verdict = FinalVerdict | SkillFinalVerdict

# ---------------------------------------------------------------------------
# Output formats (--format)
# ---------------------------------------------------------------------------

FORMAT_SARIF: str = "sarif"
FORMAT_JSON: str = "json"
FORMAT_MD: str = "md"
FORMAT_TABLE: str = "table"

#: Every value accepted by ``--format``, in help/dispatch order.
REPORT_FORMATS: tuple[str, ...] = (FORMAT_SARIF, FORMAT_JSON, FORMAT_MD, FORMAT_TABLE)

#: Default output format — SARIF, the historical and unchanged behaviour.
DEFAULT_FORMAT: str = FORMAT_SARIF

#: Canonical file extension per format, used to auto-complete ``--output``.
_FORMAT_EXTENSIONS: dict[str, str] = {
    FORMAT_SARIF: ".sarif",
    FORMAT_JSON: ".json",
    FORMAT_MD: ".md",
    FORMAT_TABLE: ".txt",
}

#: Human-facing label per format (used in the stderr summary line).
_FORMAT_LABELS: dict[str, str] = {
    FORMAT_SARIF: "SARIF",
    FORMAT_JSON: "JSON",
    FORMAT_MD: "Markdown",
    FORMAT_TABLE: "table",
}

# Decision rendering order and human labels.
_DECISION_ORDER: tuple[VerdictDecision, ...] = (
    VerdictDecision.BLOCK,
    VerdictDecision.REVIEW_REQUIRED,
    VerdictDecision.PASS,
)
_DECISION_LABELS: dict[VerdictDecision, str] = {
    VerdictDecision.BLOCK: "BLOCK",
    VerdictDecision.REVIEW_REQUIRED: "REVIEW_REQUIRED",
    VerdictDecision.PASS: "PASS",
}

# Heuristic rule ids promoted from HeuristicScores (mirror the SARIF reporter).
_HEURISTIC_ENTROPY_RULE_ID: str = "IPI201"
_HEURISTIC_INVISIBLE_RULE_ID: str = "IPI202"
_HEURISTIC_DENSITY_RULE_ID: str = "IPI203"
_HEURISTIC_CONTRADICTION_RULE_ID: str = "IPI204"
_HEURISTIC_LEVEL: str = SEVERITY_TO_LEVEL[Severity.MEDIUM]
_LLM_LEVEL: str = "warning"
_UNKNOWN_RULE_ID: str = "IPI000"

_TABLE_MESSAGE_LIMIT: int = 100
_TABLE_SEPARATOR_WIDTH: int = 80
_ELLIPSIS: str = "…"

# ---------------------------------------------------------------------------
# Attacker-content hygiene (R005 parity for the human renderers)
# ---------------------------------------------------------------------------

#: Marker appended when free text is truncated (same shape as the SARIF R005).
_TRUNCATION_MARKER: str = "..."

#: Markdown structure characters that are backslash-escaped in free text so
#: interpolated content cannot forge emphasis, links or images. The backslash
#: comes first: escaping it last would double the backslashes just inserted
#: for the other characters.
_MD_ESCAPE_CHARS: str = "\\`*_[]"

#: Backtick runs inside attacker content (for code-span fence sizing).
_BACKTICK_RUN_RE: re.Pattern[str] = re.compile(r"`+")

#: Remaining C0/C1 control characters (everything except \t and \n, which the
#: whitespace collapse below turns into spaces) — e.g. ESC, BEL, DEL.
_CONTROL_CHARS_RE: re.Pattern[str] = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _neutralize_concealed(text: str) -> str:
    """Map concealed/control characters to a visible replacement marker.

    Report cells interpolate attacker-controlled content (file paths, finding
    text, LLM explanations). Concealed characters — ANSI escape sequences,
    zero-width and bidi controls, Unicode tags — could otherwise smuggle
    terminal control sequences into the rendered report or visually spoof a
    path, so each one becomes a visible ``\\ufffd`` replacement character.
    """
    visible = INVISIBLE_CHARS_RE.sub("\ufffd", text)
    return _CONTROL_CHARS_RE.sub("\ufffd", visible)


def _collapse_ws(text: str) -> str:
    """Collapse all whitespace runs to single spaces (kills line-structure injection)."""
    return " ".join(text.split())


def _md_text(text: str, *, limit: int = MAX_MESSAGE_SNIPPET_LENGTH) -> str:
    """Escape attacker-controlled free text for inline Markdown interpolation.

    Mirrors the SARIF reporter's R005 invariant for the Markdown renderer:
    concealed characters are neutralized, whitespace is collapsed (so a payload
    cannot start a new heading/list line), the text is truncated to ``limit``
    characters and finally HTML-escaped plus backslash-escaped for the Markdown
    structure characters, so downstream renderers cannot be tricked into
    rendering attacker-controlled markup (links, images, emphasis, raw HTML).
    """
    safe = _collapse_ws(_neutralize_concealed(text))
    if len(safe) > limit:
        safe = safe[:limit] + _TRUNCATION_MARKER
    escaped = html.escape(safe, quote=False)
    for char in _MD_ESCAPE_CHARS:
        escaped = escaped.replace(char, "\\" + char)
    return escaped


def _md_code_span(text: str) -> str:
    """Wrap attacker-controlled text (paths) in an unbreakable Markdown code span.

    The fence is one backtick longer than the longest backtick run inside the
    content (CommonMark code-span rule), and padded with spaces when it must be
    longer than one backtick — so no content can terminate the span early and
    inject structure. Content is otherwise rendered verbatim, keeping paths
    copy-pasteable; concealed characters are still neutralized.
    """
    safe = _collapse_ws(_neutralize_concealed(text))
    longest = max((len(run) for run in _BACKTICK_RUN_RE.findall(safe)), default=0)
    fence = "`" * (longest + 1)
    if longest:
        return f"{fence} {safe} {fence}"
    return f"{fence}{safe}{fence}"



# ---------------------------------------------------------------------------
# Format helpers
# ---------------------------------------------------------------------------


def default_output_extension(report_format: str) -> str:
    """Return the canonical file extension for ``report_format``.

    Unknown formats fall back to the SARIF extension so the caller never has to
    guard the lookup.
    """
    return _FORMAT_EXTENSIONS.get(report_format, _FORMAT_EXTENSIONS[FORMAT_SARIF])


def format_label(report_format: str) -> str:
    """Return the human-readable label for ``report_format`` (``"SARIF"`` …)."""
    return _FORMAT_LABELS.get(report_format, report_format)


def ensure_output_extension(path: Path, report_format: str) -> Path:
    """Auto-complete ``path`` with the format's extension when it has none.

    A path that already carries *any* suffix (``results.json``, ``out.md`` …) is
    returned unchanged — only an extension-less ``--output`` (e.g. ``results``)
    gains the format's canonical extension (``results.sarif`` for the default
    SARIF format).
    """
    if path.suffix:
        return path
    if not path.name:
        # Path("") / Path(".") have no name to extend — return unchanged so
        # callers decide how to handle the degenerate path.
        return path
    return path.with_name(path.name + default_output_extension(report_format))


# ---------------------------------------------------------------------------
# Shared finding model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _FindingRow:
    """One flattened finding, ready for either renderer."""

    rule_id: str
    level: str
    line: int | None
    message: str


def _rule_id_for_finding(
    finding: ByteFinding | PatternFinding | LLMFinding,
    *,
    is_skill: bool,
) -> str:
    """Map a finding to its SARIF rule id.

    LLM findings use the skill-specific id (``IPI601``) inside a skill verdict
    and the generic id (``IPI301``) elsewhere; byte/pattern findings carry a
    category that maps through :data:`CATEGORY_TO_RULE_ID`.
    """
    if isinstance(finding, LLMFinding):
        return SKILL_LLM_RULE_ID if is_skill else LLM_FINDING_RULE_ID
    return CATEGORY_TO_RULE_ID.get(finding.category, _UNKNOWN_RULE_ID)


def _heuristic_rows(scores: HeuristicScores | None) -> list[_FindingRow]:
    """Promote suspicious heuristic scores into finding rows (IPI201–IPI204)."""
    if scores is None:
        return []
    rows: list[_FindingRow] = []
    if scores.entropy_suspicious:
        rows.append(
            _FindingRow(
                _HEURISTIC_ENTROPY_RULE_ID,
                _HEURISTIC_LEVEL,
                None,
                f"Abnormally high entropy (score: {scores.entropy:.2f})",
            )
        )
    if scores.invisible_suspicious:
        rows.append(
            _FindingRow(
                _HEURISTIC_INVISIBLE_RULE_ID,
                _HEURISTIC_LEVEL,
                None,
                f"High invisible-character ratio (ratio: {scores.invisible_ratio:.2%})",
            )
        )
    if scores.instruction_density_suspicious:
        rows.append(
            _FindingRow(
                _HEURISTIC_DENSITY_RULE_ID,
                _HEURISTIC_LEVEL,
                None,
                f"High instruction density (score: {scores.instruction_density:.2f})",
            )
        )
    if scores.contradiction_suspicious:
        rows.append(
            _FindingRow(
                _HEURISTIC_CONTRADICTION_RULE_ID,
                _HEURISTIC_LEVEL,
                None,
                "Polarity contradiction — conflicting instruction domains "
                f"(score: {scores.contradiction_score:.2f})",
            )
        )
    return rows


def _rows_for_verdict(verdict: Verdict, *, is_skill: bool) -> list[_FindingRow]:
    """Flatten every finding of ``verdict`` into ordered :class:`_FindingRow`."""
    rows: list[_FindingRow] = []
    for finding in verdict.all_findings:
        if isinstance(finding, (ByteFinding, PatternFinding)):
            rows.append(
                _FindingRow(
                    _rule_id_for_finding(finding, is_skill=is_skill),
                    SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
                    finding.line,
                    finding.description,
                )
            )
        elif isinstance(finding, LLMFinding):
            rows.append(
                _FindingRow(
                    _rule_id_for_finding(finding, is_skill=is_skill),
                    _LLM_LEVEL,
                    finding.line,
                    finding.explanation,
                )
            )
    # Heuristics have no dedicated finding objects on the verdict; promote the
    # suspicious score flags instead (files only — skills carry no scores).
    if isinstance(verdict, FinalVerdict):
        rows.extend(_heuristic_rows(verdict.heuristic_scores))
    return rows


def _verdict_path(verdict: Verdict) -> str:
    """Return the repo-relative path a verdict is anchored at."""
    if isinstance(verdict, SkillFinalVerdict):
        return verdict.skill.metadata_file.relative_path
    return verdict.file.relative_path


def _llm_summary(verdict: Verdict) -> str:
    """Render the LLM part of a verdict's status line."""
    if verdict.llm_verdict is not None:
        confidence = (
            f" ({verdict.llm_confidence:.2f})" if verdict.llm_confidence is not None else ""
        )
        llm_part = f"LLM: {_md_text(verdict.llm_verdict)}{confidence}"
    else:
        llm_part = "LLM: off"
    if verdict.llm_compromised:
        return f"{llm_part} · LLM compromised"
    return llm_part


def _decision_counts(verdicts: list[Verdict]) -> dict[VerdictDecision, int]:
    """Count verdicts per decision (every decision key is always present)."""
    return {
        decision: sum(1 for v in verdicts if v.decision == decision)
        for decision in _DECISION_ORDER
    }


def _emitted_count(verdicts: list[Verdict]) -> int:
    """Total finding rows a report would list, including compromise notes."""
    total = 0
    for verdict in verdicts:
        total += len(_rows_for_verdict(verdict, is_skill=isinstance(verdict, SkillFinalVerdict)))
        if verdict.llm_compromised:
            total += 1
    return total


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------


def _markdown_verdict_block(verdict: Verdict, *, is_skill: bool) -> list[str]:
    """Render one verdict (heading + findings) as Markdown lines."""
    path = _md_code_span(_verdict_path(verdict))
    kind = "skill" if is_skill else "file"
    lines = [
        f"### {path} — {kind}, {_DECISION_LABELS[verdict.decision]}",
        "",
        f"- Static severity: **{verdict.static_severity.name}** · {_llm_summary(verdict)}",
    ]
    if verdict.reasoning:
        lines.append(f"- Reason: {_md_text(verdict.reasoning)}")
    rows = _rows_for_verdict(verdict, is_skill=is_skill)
    if rows:
        lines.append("")
        for row in rows:
            location = f"line {row.line}" if row.line else "no line"
            lines.append(f"- **{row.rule_id}** ({row.level}, {location}): {_md_text(row.message)}")
    lines.append("")
    return lines


def render_markdown(
    verdicts: list[FinalVerdict],
    skill_verdicts: list[SkillFinalVerdict] | None = None,
    *,
    stats: SarifLimitStats | None = None,
) -> str:
    """Render a grouped Markdown report (``--format md``).

    The report opens with a summary block, then lists verdicts grouped by
    decision (BLOCK → REVIEW_REQUIRED → PASS). Passed files are listed as a
    compact bullet list (they carry no findings); blocked/review entries show
    their severity, LLM verdict and every finding.
    """
    file_verdicts: list[Verdict] = list(verdicts)
    skills: list[Verdict] = list(skill_verdicts or [])
    all_verdicts = [*file_verdicts, *skills]
    file_counts = _decision_counts(file_verdicts)
    skill_counts = _decision_counts(skills)

    lines: list[str] = [
        f"# {TOOL_INFO.name} report",
        "",
        f"- **Tool:** {TOOL_INFO.name} {TOOL_INFO.version}",
        f"- **Scanned:** {len(file_verdicts)} file(s), {len(skills)} skill(s)",
        "- **Verdicts:** "
        + " · ".join(
            f"{_DECISION_LABELS[d]} {file_counts[d] + skill_counts[d]}" for d in _DECISION_ORDER
        ),
    ]
    if skills:
        lines.append(
            "- **Skills:** "
            + " · ".join(f"{_DECISION_LABELS[d]} {skill_counts[d]}" for d in _DECISION_ORDER)
        )
    suppressed = stats.total_suppressed if stats is not None else 0
    lines.append(f"- **Findings:** {_emitted_count(all_verdicts)} emitted, {suppressed} suppressed")
    lines.append("")

    for decision in _DECISION_ORDER:
        group = [v for v in all_verdicts if v.decision == decision]
        lines.append(f"## {_DECISION_LABELS[decision]} ({len(group)})")
        lines.append("")
        if not group:
            lines.append("_No verdicts in this category._")
            lines.append("")
            continue
        if decision is VerdictDecision.PASS:
            for verdict in group:
                tag = " (skill)" if isinstance(verdict, SkillFinalVerdict) else ""
                line = f"- {_md_code_span(_verdict_path(verdict))}{tag}"
                if verdict.llm_compromised:
                    line += " — IPI900: LLM classifier response was malformed or compromised"
                lines.append(line)
            lines.append("")
            continue
        for verdict in group:
            lines.extend(
                _markdown_verdict_block(verdict, is_skill=isinstance(verdict, SkillFinalVerdict))
            )

    return "\n".join(lines).rstrip("\n") + "\n"


# ---------------------------------------------------------------------------
# Plain-text table renderer
# ---------------------------------------------------------------------------


def _truncate(text: str, limit: int) -> str:
    """Neutralize concealed characters, collapse whitespace and truncate.

    The whitespace collapse removes line breaks (a cell can never forge a new
    table row); concealed-character neutralization keeps terminal control
    sequences out of the plain-text output.
    """
    collapsed = _collapse_ws(_neutralize_concealed(text))
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1].rstrip() + _ELLIPSIS


def _table_rows(
    all_verdicts: list[Verdict],
) -> list[tuple[str, str, str, str, str, str]]:
    """Flatten every verdict's findings into (decision, file, rule, level, line, msg).

    Rows are grouped by decision in :data:`_DECISION_ORDER` (BLOCK first), so the
    rendered table surfaces the most severe verdicts first regardless of the
    order the pipeline returned them in. A non-PASS verdict that carries no
    individual finding still gets a summary row (so it never silently
    disappears); PASS verdicts contribute rows only via findings/notes.
    """
    rows: list[tuple[str, str, str, str, str, str]] = []
    ordered = [v for decision in _DECISION_ORDER for v in all_verdicts if v.decision == decision]
    for verdict in ordered:
        is_skill = isinstance(verdict, SkillFinalVerdict)
        # Paths are attacker-controlled (file names) — neutralize concealed
        # characters so a terminal rendering the table cannot be hijacked.
        path = _collapse_ws(_neutralize_concealed(_verdict_path(verdict)))
        if is_skill:
            path = f"{path} (skill)"
        decision = _DECISION_LABELS[verdict.decision]
        verdict_rows = [
            (
                decision,
                path,
                row.rule_id,
                row.level,
                str(row.line) if row.line else "-",
                _truncate(row.message, _TABLE_MESSAGE_LIMIT),
            )
            for row in _rows_for_verdict(verdict, is_skill=is_skill)
        ]
        if verdict.llm_compromised:
            verdict_rows.append(
                (
                    decision,
                    path,
                    LLM_COMPROMISE_RULE_ID,
                    "note",
                    "-",
                    "LLM classifier response was malformed or compromised",
                )
            )
        if not verdict_rows and verdict.decision is not VerdictDecision.PASS:
            verdict_rows.append(
                (
                    decision,
                    path,
                    "-",
                    SEVERITY_TO_LEVEL.get(verdict.static_severity, "warning"),
                    "-",
                    _truncate(verdict.reasoning or "no individual finding", _TABLE_MESSAGE_LIMIT),
                )
            )
        rows.extend(verdict_rows)
    return rows


def render_table(
    verdicts: list[FinalVerdict],
    skill_verdicts: list[SkillFinalVerdict] | None = None,
    *,
    stats: SarifLimitStats | None = None,
) -> str:
    """Render a fixed-width plain-text table (``--format table``).

    Findings are grouped by decision under a banner; each row lists the file,
    rule id, level, line and a whitespace-collapsed message. Long messages are
    truncated so the columns stay aligned.
    """
    file_verdicts: list[Verdict] = list(verdicts)
    skills: list[Verdict] = list(skill_verdicts or [])
    all_verdicts = [*file_verdicts, *skills]
    file_counts = _decision_counts(file_verdicts)
    skill_counts = _decision_counts(skills)
    suppressed = stats.total_suppressed if stats is not None else 0

    lines = [
        f"{TOOL_INFO.name} report — {TOOL_INFO.name} {TOOL_INFO.version}",
        "",
        "SUMMARY",
        f"  Scanned: {len(file_verdicts)} file(s), {len(skills)} skill(s)",
        "  Verdicts: "
        + " · ".join(
            f"{_DECISION_LABELS[d]} {file_counts[d] + skill_counts[d]}" for d in _DECISION_ORDER
        ),
        f"  Findings: {_emitted_count(all_verdicts)} emitted, {suppressed} suppressed",
    ]

    rows = _table_rows(all_verdicts)
    headers = ("DECISION", "FILE", "RULE", "LEVEL", "LINE", "MESSAGE")
    widths = [len(h) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def _format_row(cells: tuple[str, ...]) -> str:
        last = len(cells) - 1
        padded = [cell.ljust(widths[i]) for i, cell in enumerate(cells[:last])]
        return "  ".join([*padded, cells[last]]).rstrip()

    seen: set[str] = set()
    for cells in rows:
        if cells[0] not in seen:
            seen.add(cells[0])
            lines += [
                "",
                cells[0],
                "=" * _TABLE_SEPARATOR_WIDTH,
                _format_row(headers),
                "-" * _TABLE_SEPARATOR_WIDTH,
            ]
        lines.append(_format_row(cells))
    if not rows:
        lines += ["", "No findings."]
    return "\n".join(lines).rstrip("\n") + "\n"


# ---------------------------------------------------------------------------
# JSON projection
# ---------------------------------------------------------------------------


def _json_finding(row: _FindingRow) -> dict[str, Any]:
    """Serialize a :class:`_FindingRow` for the JSON report."""
    return {
        "ruleId": row.rule_id,
        "level": row.level,
        "line": row.line,
        "message": row.message,
    }


def _json_verdict(verdict: Verdict, *, is_skill: bool) -> dict[str, Any]:
    """Serialize one verdict (file or skill) for the JSON report."""
    return {
        "type": "skill" if is_skill else "file",
        "path": _verdict_path(verdict),
        "decision": verdict.decision.value,
        "staticSeverity": verdict.static_severity.name,
        "llmVerdict": verdict.llm_verdict,
        "llmConfidence": verdict.llm_confidence,
        "llmCompromised": verdict.llm_compromised,
        "reasoning": verdict.reasoning,
        "findings": [_json_finding(row) for row in _rows_for_verdict(verdict, is_skill=is_skill)],
    }


def _limit_stats_payload(stats: SarifLimitStats | None) -> dict[str, int]:
    """Serialize the suppression/limit counters for the JSON report."""
    if stats is None:
        return {
            "duplicatesRemoved": 0,
            "cappedRemoved": 0,
            "belowThresholdRemoved": 0,
            "suppressedResults": 0,
        }
    return {
        "duplicatesRemoved": stats.duplicates_removed,
        "cappedRemoved": stats.capped_removed,
        "belowThresholdRemoved": stats.below_threshold_removed,
        "suppressedResults": stats.suppressed_results,
    }


def build_json_report(
    verdicts: list[FinalVerdict],
    skill_verdicts: list[SkillFinalVerdict] | None = None,
    *,
    stats: SarifLimitStats | None = None,
) -> dict[str, Any]:
    """Build the flat JSON report (``--format json``).

    Unlike SARIF, this projection is a single flat ``results`` array of verdicts
    (each with its findings) plus a ``summary`` of decision counts — convenient
    for ``jq``-style consumption without walking the SARIF ``runs``/``results``
    structure.
    """
    file_verdicts = list(verdicts)
    skills = list(skill_verdicts or [])
    file_counts = _decision_counts(list(file_verdicts))
    skill_counts = _decision_counts(list(skills))

    summary: dict[str, Any] = {
        "filesScanned": len(file_verdicts),
        "filesBlocked": file_counts[VerdictDecision.BLOCK],
        "filesReviewRequired": file_counts[VerdictDecision.REVIEW_REQUIRED],
        "filesPassed": file_counts[VerdictDecision.PASS],
        "skillsScanned": len(skills),
        "skillsBlocked": skill_counts[VerdictDecision.BLOCK],
        "skillsReviewRequired": skill_counts[VerdictDecision.REVIEW_REQUIRED],
        "skillsPassed": skill_counts[VerdictDecision.PASS],
    }
    return {
        "tool": {
            "name": TOOL_INFO.name,
            "version": TOOL_INFO.version,
            "semanticVersion": TOOL_INFO.semver,
        },
        "summary": summary,
        "suppression": _limit_stats_payload(stats),
        "results": [
            *(_json_verdict(v, is_skill=False) for v in file_verdicts),
            *(_json_verdict(v, is_skill=True) for v in skills),
        ],
    }
