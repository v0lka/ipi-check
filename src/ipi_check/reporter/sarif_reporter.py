"""SARIF Reporter — generate SARIF v2.1.0 output from scan results."""

from __future__ import annotations

import html
from typing import TYPE_CHECKING, Any
from urllib.parse import quote as url_quote

from ipi_check.core.types import (
    ByteFinding,
    ByteFindingCategory,
    FinalVerdict,
    LLMFinding,
    PatternFinding,
    PatternFindingCategory,
    Severity,
    ToolInfo,
)

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# SARIF document constants
# ---------------------------------------------------------------------------

SARIF_VERSION: str = "2.1.0"
SARIF_SCHEMA_URL: str = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_INFORMATION_URI: str = "https://github.com/v0lka/ipi-check"
MAX_MESSAGE_SNIPPET_LENGTH: int = 200
LLM_COMPROMISE_RULE_ID: str = "IPI900"
LLM_FINDING_RULE_ID: str = "IPI301"

# Truncation marker appended when escaped content exceeds the snippet length.
_TRUNCATION_MARKER: str = "..."

# Heuristic rule identifiers — promoted from the heuristics layer when their
# ``*_suspicious`` flag is set on a verdict's :class:`HeuristicScores`.
_HEURISTIC_ENTROPY_RULE_ID: str = "IPI201"
_HEURISTIC_INVISIBLE_RULE_ID: str = "IPI202"
_HEURISTIC_INSTRUCTION_DENSITY_RULE_ID: str = "IPI203"
_HEURISTIC_CONTRADICTION_RULE_ID: str = "IPI204"

# URI safe characters — keep path separator unescaped, escape everything else.
_URI_SAFE_CHARS: str = "/"

# ---------------------------------------------------------------------------
# Mappings — severity → SARIF level, category → ruleId, ruleId → CWE / desc.
# ---------------------------------------------------------------------------

SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.NONE: "none",
}

CATEGORY_TO_RULE_ID: dict[ByteFindingCategory | PatternFindingCategory, str] = {
    ByteFindingCategory.ANSI_HIDDEN: "IPI001",
    ByteFindingCategory.UNICODE_TAGS: "IPI002",
    ByteFindingCategory.VARIATION_SELECTORS: "IPI003",
    ByteFindingCategory.BIDI_OVERRIDE: "IPI004",
    ByteFindingCategory.ZERO_WIDTH: "IPI005",
    ByteFindingCategory.HOMOGLYPH: "IPI006",
    ByteFindingCategory.PUA: "IPI007",
    PatternFindingCategory.INSTRUCTION_OVERRIDE: "IPI101",
    PatternFindingCategory.AUTHORITY_CLAIM: "IPI102",
    PatternFindingCategory.DESTRUCTIVE_COMMAND: "IPI103",
    PatternFindingCategory.DATA_EXFILTRATION: "IPI104",
    PatternFindingCategory.SHELL_INJECTION: "IPI105",
    PatternFindingCategory.JAILBREAK: "IPI106",
    PatternFindingCategory.SOCIAL_ENGINEERING: "IPI107",
    PatternFindingCategory.OBFUSCATION: "IPI108",
    PatternFindingCategory.INSTRUCTION_CONTRADICTION: "IPI109",
}

RULE_ID_TO_CWE: dict[str, str] = {
    "IPI001": "CWE-506",
    "IPI002": "CWE-506",
    "IPI003": "CWE-506",
    "IPI004": "CWE-451",
    "IPI005": "CWE-506",
    "IPI006": "CWE-1007",
    "IPI007": "CWE-506",
    "IPI101": "CWE-77",
    "IPI102": "CWE-77",
    "IPI103": "CWE-77",
    "IPI104": "CWE-77",
    "IPI105": "CWE-77",
    "IPI106": "CWE-77",
    "IPI107": "CWE-77",
    "IPI108": "CWE-77",
    "IPI109": "CWE-77",
    "IPI201": "CWE-506",
    "IPI202": "CWE-506",
    "IPI203": "CWE-77",
    "IPI204": "CWE-77",
    "IPI301": "CWE-77",
    "IPI900": "CWE-506",
}

RULE_DESCRIPTIONS: dict[str, str] = {
    "IPI001": "ANSI escape sequence detected — may hide content from reviewers",
    "IPI002": "Unicode tag characters detected — invisible metadata channel",
    "IPI003": "Variation selector detected — potential encoding channel",
    "IPI004": "Bidirectional override detected — may reorder visible text",
    "IPI005": "Zero-width character detected — steganographic data channel",
    "IPI006": "Homoglyph detected — character resembles Latin equivalent",
    "IPI007": "Private Use Area character detected",
    "IPI101": "Instruction override pattern — attempts to bypass rules",
    "IPI102": "Authority claim pattern — attempts to establish priority",
    "IPI103": "Destructive command pattern — attempts to destroy data",
    "IPI104": "Data exfiltration pattern — attempts to send data externally",
    "IPI105": "Shell injection pattern — attempts to execute code",
    "IPI106": "Jailbreak pattern — attempts persona/role manipulation",
    "IPI107": "Social engineering pattern — impersonates authority or creates false urgency",
    "IPI108": "Obfuscation instruction — attempts to decode or assemble hidden payloads",
    "IPI109": "Instruction contradiction — negates or carves exceptions to earlier rules",
    "IPI201": "Abnormally high entropy — possible encoded payload",
    "IPI202": "High invisible content ratio — file may contain hidden data",
    "IPI203": "High instruction density — abnormal imperative language",
    "IPI204": "Polarity contradiction — conflicting instruction domains detected",
    "IPI301": "LLM-detected prompt injection finding",
    "IPI900": "LLM classifier response validation failed",
}

# Canonical text used for IPI301 / IPI900 messages.
_IPI301_TEXT_TEMPLATE: str = "LLM classifier flagged content as {category}"
_IPI301_MARKDOWN_TEMPLATE: str = "**LLM classification** ({category}): {explanation}"
_IPI900_TEXT: str = "LLM classifier response was malformed or compromised"
_IPI900_MARKDOWN: str = (
    "The LLM classifier returned an invalid or untrusted response for this "
    "file. Falling back to static analysis only."
)

# Generic byte/pattern message templates.
_BYTE_TEXT_TEMPLATE: str = "{description}"
_BYTE_MARKDOWN_TEMPLATE: str = (
    "**{rule_id}** at line {line}, column {column}: {description} (snippet: `{snippet}`)"
)
_PATTERN_TEXT_TEMPLATE: str = "{description}"
_PATTERN_MARKDOWN_TEMPLATE: str = (
    "**{rule_id}** at line {line}, column {column}: {description} (matched: `{matched}`)"
)

# Heuristic message templates.
_HEURISTIC_TEXT_TEMPLATES: dict[str, str] = {
    _HEURISTIC_ENTROPY_RULE_ID: ("Abnormally high entropy detected (score: {score:.2f})"),
    _HEURISTIC_INVISIBLE_RULE_ID: ("High invisible-character ratio detected (ratio: {score:.2%})"),
    _HEURISTIC_INSTRUCTION_DENSITY_RULE_ID: (
        "High instruction density detected (score: {score:.2f})"
    ),
    _HEURISTIC_CONTRADICTION_RULE_ID: (
        "Polarity contradiction detected — conflicting instruction domains (score: {score:.2f})"
    ),
}


def _escape_sarif_content(text: str) -> str:
    """Escape user-controlled content for safe SARIF embedding (R005).

    Truncates to :data:`MAX_MESSAGE_SNIPPET_LENGTH` characters and
    HTML-escapes special characters so that downstream SARIF consumers cannot
    be tricked into rendering attacker-controlled markup.
    """
    if len(text) > MAX_MESSAGE_SNIPPET_LENGTH:
        text = text[:MAX_MESSAGE_SNIPPET_LENGTH] + _TRUNCATION_MARKER
    return html.escape(text)


def _artifact_uri(verdict: FinalVerdict) -> str:
    """Build a URI-encoded relative path for ``artifactLocation.uri``."""
    return url_quote(verdict.file.relative_path, safe=_URI_SAFE_CHARS)


def _physical_location(
    uri: str,
    line: int | None,
    column: int | None,
) -> dict[str, Any]:
    """Build a SARIF ``physicalLocation`` object, omitting empty regions."""
    artifact: dict[str, Any] = {"uri": uri}
    physical: dict[str, Any] = {"artifactLocation": artifact}

    region: dict[str, Any] = {}
    if line is not None and line > 0:
        region["startLine"] = line
        if column is not None and column > 0:
            region["startColumn"] = column
    if region:
        physical["region"] = region

    return physical


def _make_location(
    uri: str,
    line: int | None,
    column: int | None,
) -> dict[str, Any]:
    """Wrap a ``physicalLocation`` inside the SARIF ``locations`` element."""
    return {"physicalLocation": _physical_location(uri, line, column)}


def _build_byte_result(
    finding: ByteFinding,
    uri: str,
) -> dict[str, Any]:
    """Convert a :class:`ByteFinding` into a SARIF result object."""
    rule_id = CATEGORY_TO_RULE_ID[finding.category]
    level = SEVERITY_TO_LEVEL.get(finding.severity, "warning")
    description = _escape_sarif_content(finding.description)
    snippet = _escape_sarif_content(finding.snippet_hex)

    return {
        "ruleId": rule_id,
        "level": level,
        "message": {
            "text": _BYTE_TEXT_TEMPLATE.format(description=description),
            "markdown": _BYTE_MARKDOWN_TEMPLATE.format(
                rule_id=rule_id,
                line=finding.line,
                column=finding.column,
                description=description,
                snippet=snippet,
            ),
        },
        "locations": [_make_location(uri, finding.line, finding.column)],
    }


def _build_pattern_result(
    finding: PatternFinding,
    uri: str,
) -> dict[str, Any]:
    """Convert a :class:`PatternFinding` into a SARIF result object."""
    rule_id = CATEGORY_TO_RULE_ID[finding.category]
    level = SEVERITY_TO_LEVEL.get(finding.severity, "warning")
    description = _escape_sarif_content(finding.description)
    matched = _escape_sarif_content(finding.matched_text)

    return {
        "ruleId": rule_id,
        "level": level,
        "message": {
            "text": _PATTERN_TEXT_TEMPLATE.format(description=description),
            "markdown": _PATTERN_MARKDOWN_TEMPLATE.format(
                rule_id=rule_id,
                line=finding.line,
                column=finding.column,
                description=description,
                matched=matched,
            ),
        },
        "locations": [_make_location(uri, finding.line, finding.column)],
    }


def _build_llm_result(
    finding: LLMFinding,
    uri: str,
) -> dict[str, Any]:
    """Convert a :class:`LLMFinding` into a SARIF result object."""
    category = _escape_sarif_content(finding.category)
    explanation = _escape_sarif_content(finding.explanation)
    return {
        "ruleId": LLM_FINDING_RULE_ID,
        "level": "warning",
        "message": {
            "text": _IPI301_TEXT_TEMPLATE.format(category=category),
            "markdown": _IPI301_MARKDOWN_TEMPLATE.format(
                category=category,
                explanation=explanation,
            ),
        },
        "locations": [_make_location(uri, finding.line, None)],
    }


def _build_heuristic_results(
    verdict: FinalVerdict,
    uri: str,
) -> list[dict[str, Any]]:
    """Emit synthetic results for heuristic flags set on the verdict.

    The heuristics layer does not produce :class:`ByteFinding` /
    :class:`PatternFinding` objects, so we promote suspicious flags to
    rule-IPI201/202/203 results here for SARIF visibility.
    """
    # The heuristic scores live on the static result, not on the verdict
    # itself — but we encode them into ``all_findings`` indirectly via the
    # decision/severity. To stay self-contained, walk the verdict's
    # underlying static result-style fields by examining the ``reasoning``
    # only as a tie-breaker. The pipeline guarantees heuristics are reflected
    # in static_severity; we keep this helper conservative and emit nothing
    # when no static result is attached. Heuristic propagation is handled
    # by the caller via the static result data attached to the verdict's
    # findings.
    del verdict, uri  # heuristic flags surfaced by caller, not the verdict.
    return []


def _heuristic_result(
    rule_id: str,
    score: float,
    uri: str,
) -> dict[str, Any]:
    """Build a single heuristic SARIF result."""
    text_template = _HEURISTIC_TEXT_TEMPLATES[rule_id]
    text = text_template.format(score=score)
    return {
        "ruleId": rule_id,
        "level": SEVERITY_TO_LEVEL[Severity.MEDIUM],
        "message": {
            "text": text,
            "markdown": f"**{rule_id}**: {text}",
        },
        "locations": [_make_location(uri, None, None)],
    }


def _build_compromise_result(uri: str) -> dict[str, Any]:
    """Build the IPI900 LLM-compromise note-level result."""
    return {
        "ruleId": LLM_COMPROMISE_RULE_ID,
        "level": SEVERITY_TO_LEVEL[Severity.LOW],
        "message": {
            "text": _IPI900_TEXT,
            "markdown": _IPI900_MARKDOWN,
        },
        "locations": [_make_location(uri, None, None)],
    }


def _rule_definition(rule_id: str) -> dict[str, Any]:
    """Build a SARIF rule definition for the tool driver's rules array."""
    description = RULE_DESCRIPTIONS.get(rule_id, rule_id)
    cwe = RULE_ID_TO_CWE.get(rule_id)
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": description},
        "fullDescription": {"text": description},
        "defaultConfiguration": {"level": "warning"},
        "helpUri": TOOL_INFORMATION_URI,
    }
    if cwe is not None:
        rule["properties"] = {"tags": ["security", cwe]}
    return rule


def _collect_rule_ids(results: list[dict[str, Any]]) -> list[str]:
    """Return rule IDs in first-seen order across the results array."""
    seen: dict[str, None] = {}
    for result in results:
        rule_id = result.get("ruleId")
        if isinstance(rule_id, str) and rule_id not in seen:
            seen[rule_id] = None
    return list(seen.keys())


def _build_results_for_verdict(
    verdict: FinalVerdict,
) -> list[dict[str, Any]]:
    """Build all SARIF result objects for a single :class:`FinalVerdict`."""
    uri = _artifact_uri(verdict)
    results: list[dict[str, Any]] = []

    for finding in verdict.all_findings:
        if isinstance(finding, ByteFinding):
            results.append(_build_byte_result(finding, uri))
        elif isinstance(finding, PatternFinding):
            results.append(_build_pattern_result(finding, uri))
        elif isinstance(finding, LLMFinding):
            results.append(_build_llm_result(finding, uri))

    if verdict.llm_compromised:
        results.append(_build_compromise_result(uri))

    return results


def _heuristic_results_from_verdict(
    verdict: FinalVerdict,
) -> list[dict[str, Any]]:
    """Promote heuristic suspicious flags to SARIF results."""
    scores = verdict.heuristic_scores
    if scores is None:
        return []

    uri = _artifact_uri(verdict)
    out: list[dict[str, Any]] = []
    if scores.entropy_suspicious:
        out.append(_heuristic_result(_HEURISTIC_ENTROPY_RULE_ID, scores.entropy, uri))
    if scores.invisible_suspicious:
        out.append(_heuristic_result(_HEURISTIC_INVISIBLE_RULE_ID, scores.invisible_ratio, uri))
    if scores.instruction_density_suspicious:
        out.append(
            _heuristic_result(
                _HEURISTIC_INSTRUCTION_DENSITY_RULE_ID,
                scores.instruction_density,
                uri,
            )
        )
    if scores.contradiction_suspicious:
        out.append(
            _heuristic_result(
                _HEURISTIC_CONTRADICTION_RULE_ID,
                scores.contradiction_score,
                uri,
            )
        )
    return out


def generate_sarif(
    verdicts: list[FinalVerdict],
    repo_path: Path,
    tool_info: ToolInfo,
    start_time: str,
    end_time: str,
) -> dict[str, Any]:
    """Generate a SARIF v2.1.0 document from scan verdicts.

    Args:
        verdicts: Final per-file decisions from confidence fusion.
        repo_path: Repository root (kept for interface stability — relative
            paths are already computed by file discovery).
        tool_info: Tool name/version metadata for the SARIF driver block.
        start_time: ISO-8601 UTC timestamp of scan start.
        end_time: ISO-8601 UTC timestamp of scan end.

    Returns:
        A SARIF v2.1.0 document as a JSON-serializable dict.
    """
    del repo_path  # relative paths are precomputed; argument kept for parity.

    # Build all results.
    all_results: list[dict[str, Any]] = []
    for verdict in verdicts:
        all_results.extend(_build_results_for_verdict(verdict))
        all_results.extend(_heuristic_results_from_verdict(verdict))

    # Collect distinct rule IDs and build the rules array.
    rule_ids = _collect_rule_ids(all_results)
    rules = [_rule_definition(rule_id) for rule_id in rule_ids]

    driver: dict[str, Any] = {
        "name": tool_info.name,
        "version": tool_info.version,
        "semanticVersion": tool_info.semver,
        "informationUri": TOOL_INFORMATION_URI,
        "rules": rules,
    }

    invocation: dict[str, Any] = {
        "executionSuccessful": True,
        "startTimeUtc": start_time,
        "endTimeUtc": end_time,
    }

    run: dict[str, Any] = {
        "tool": {"driver": driver},
        "invocations": [invocation],
        "results": all_results,
    }

    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [run],
    }
