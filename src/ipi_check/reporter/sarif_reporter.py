"""SARIF Reporter — generate SARIF v2.1.0 output from scan results."""

from __future__ import annotations

import hashlib
import html
from typing import TYPE_CHECKING, Any
from urllib.parse import quote as url_quote
from urllib.parse import unquote as url_unquote

from ipi_check.core.types import (
    ByteFinding,
    ByteFindingCategory,
    FinalVerdict,
    LLMFinding,
    PatternFinding,
    PatternFindingCategory,
    SarifLimitStats,
    Severity,
    SkillFinalVerdict,
    SuppressionPolicy,
    ToolInfo,
    VerdictDecision,
)
from ipi_check.scanner.pipeline import resolve_suppression

if TYPE_CHECKING:
    from pathlib import Path

    from ipi_check.core.types import DiscoveredFile, SkillUnit

# Default maximum number of SARIF results emitted per file. Files that exceed
# this are truncated (after deduplication) and the number of suppressed
# findings is reported on stderr. ``0`` disables the cap (unlimited).
DEFAULT_MAX_FINDINGS_PER_FILE: int = 50

# Sentinel value that disables the per-file cap entirely.
UNLIMITED_MAX_FINDINGS_PER_FILE: int = 0

# Marker used as the "snippet" component of the dedup key for result kinds
# that carry no textual snippet (heuristics, LLM compromise).
_NO_SNIPPET: str = ""

# Default severity threshold for emitting individual findings. ``NONE`` keeps
# every finding — the historical behaviour; ``--severity-threshold`` raises it.
DEFAULT_SEVERITY_THRESHOLD: Severity = Severity.NONE

# Total ordering used to compare a finding's severity against the threshold.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.NONE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# ---------------------------------------------------------------------------
# SARIF document constants
# ---------------------------------------------------------------------------

SARIF_VERSION: str = "2.1.0"
SARIF_SCHEMA_URL: str = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_INFORMATION_URI: str = "https://github.com/v0lka/ipi-check"
MAX_MESSAGE_SNIPPET_LENGTH: int = 200
LLM_COMPROMISE_RULE_ID: str = "IPI900"
LLM_FINDING_RULE_ID: str = "IPI301"
SKILL_LLM_RULE_ID: str = "IPI601"
SKILL_HEURISTIC_RULE_ID: str = "IPI501"

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
# Result identity — ``partialFingerprints`` keys (T4.4 / IN-4) and the
# per-result ``properties`` bag values (T4.4 / IN-5).
# ---------------------------------------------------------------------------

# ``primaryLocationLineHash`` is the only ``partialFingerprints`` key GitHub
# Code Scanning consumes to track an alert across runs; the namespaced key
# carries the same digest for other consumers (GitLab SAST, IDE viewers).
_FINGERPRINT_PRIMARY_KEY: str = "primaryLocationLineHash"
_FINGERPRINT_NAMESPACE_KEY: str = "ipiCheck/v1"

# Hex characters kept from the SHA-256 digest (16 hex = 64 bits) — ample to
# keep results distinct while keeping the fingerprint compact.
_FINGERPRINT_HEX_LENGTH: int = 16

# Component separator for the fingerprint payload. U+001F (unit separator)
# cannot occur in a rule id, URI, decimal integer or detector payload, so two
# distinct tuples can never collide through naive concatenation.
_FINGERPRINT_SEPARATOR: str = "\x1f"

# Line number used in a fingerprint when a result carries no region (skill,
# heuristic and compromise results are anchored at the file, not a line).
_FINGERPRINT_NO_LINE: int = 0

# Confidence values for the per-result ``properties`` bag (T4.4). A byte,
# pattern or heuristic detection is deterministic — the detector matched or it
# did not — so it carries full confidence; the IPI900 compromise diagnostic
# describes scan integrity, not a finding, and carries none. An LLM finding
# carries the classifier's own confidence (see :func:`_build_llm_result`).
_DETERMINISTIC_CONFIDENCE: float = 1.0
_DIAGNOSTIC_CONFIDENCE: float = 0.0

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
    # Skill-specific categories (IPI401–411)
    PatternFindingCategory.REMOTE_EXECUTION: "IPI401",
    PatternFindingCategory.CREDENTIAL_HARVESTING: "IPI402",
    PatternFindingCategory.EXTERNAL_TRANSMISSION: "IPI403",
    PatternFindingCategory.DYNAMIC_CONTEXT: "IPI404",
    PatternFindingCategory.EXCESSIVE_PERMISSIONS: "IPI405",
    PatternFindingCategory.OBFUSCATED_SKILL_CODE: "IPI406",
    PatternFindingCategory.HIDDEN_INSTRUCTIONS: "IPI407",
    PatternFindingCategory.COMMAND_INJECTION_SKILL: "IPI408",
    PatternFindingCategory.SKILL_SECRECY: "IPI409",
    PatternFindingCategory.PRIVILEGE_ESCALATION: "IPI410",
    PatternFindingCategory.FILE_SYSTEM_ENUMERATION: "IPI411",
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
    "IPI401": "CWE-77",
    "IPI402": "CWE-77",
    "IPI403": "CWE-77",
    "IPI404": "CWE-77",
    "IPI405": "CWE-506",
    "IPI406": "CWE-506",
    "IPI407": "CWE-77",
    "IPI408": "CWE-77",
    "IPI409": "CWE-77",
    "IPI410": "CWE-77",
    "IPI411": "CWE-506",
    "IPI501": "CWE-506",
    "IPI601": "CWE-77",
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
    "IPI401": "Remote code execution — downloads and executes remote code",
    "IPI402": "Credential harvesting — references to sensitive environment variables",
    "IPI403": "External data transmission — sends data to remote URLs",
    "IPI404": "Dynamic context abuse — injects runtime context via !`command`",
    "IPI405": "Excessive permissions — wildcard tool access in allowed-tools",
    "IPI406": "Obfuscated code — base64 decode or similar deobfuscation",
    "IPI407": "Hidden instructions — HTML comments containing suspicious directives",
    "IPI408": "Command injection — instructs running arbitrary commands",
    "IPI409": "Secrecy/coercion — instructs hiding behaviour from the user",
    "IPI410": "Privilege escalation — sudo, chmod 7xx, or chown root",
    "IPI411": "Filesystem enumeration — scanning or walking the filesystem",
    "IPI501": "Skill heuristic — suspicious behaviour/description mismatch",
    "IPI601": "Skill LLM-detected malicious behaviour",
    "IPI900": "LLM classifier response validation failed",
}

# ---------------------------------------------------------------------------
# Rule-id ranges → detector families (T4.5 / IN-5).
#
# The numeric suffix of a ``ruleId`` selects the family the rule belongs to.
# Each family supplies the range label, detection-layer description and
# remediation guidance used in the rule's ``help`` and ``fullDescription``, so
# every rule descriptor can document not only itself but also the ruleId range
# it occupies. Ranges are ascending; :func:`_rule_family` returns the first hit.
# ---------------------------------------------------------------------------

_RULE_ID_RANGES: tuple[tuple[int, int, str], ...] = (
    (1, 7, "byte"),
    (101, 109, "pattern"),
    (201, 204, "heuristic"),
    (301, 301, "llm"),
    (401, 411, "skill"),
    (501, 501, "skill_heuristic"),
    (601, 601, "skill_llm"),
    (900, 900, "diagnostic"),
)

# Human-readable title for each detector family (includes the ruleId range).
RULE_FAMILY_TITLES: dict[str, str] = {
    "byte": "Byte-level hidden-content detection (IPI001–IPI007)",
    "pattern": "Injection pattern matching (IPI101–IPI109)",
    "heuristic": "Semantic heuristics (IPI201–IPI204)",
    "llm": "LLM classification (IPI301)",
    "skill": "Skill security audit (IPI401–IPI411)",
    "skill_heuristic": "Skill heuristics (IPI501)",
    "skill_llm": "Skill LLM classification (IPI601)",
    "diagnostic": "Scan-integrity diagnostic (IPI900)",
    "other": "Additional detection",
}

# Remediation guidance for each detector family (used in help/fullDescription).
RULE_FAMILY_REMEDIATION: dict[str, str] = {
    "byte": (
        "Remove the hidden or invisible characters, or re-encode the file as plain UTF-8 text."
    ),
    "pattern": (
        "Remove or rewrite the offending instruction so it no longer overrides "
        "rules, exfiltrates data or executes commands."
    ),
    "heuristic": (
        "Review the flagged content manually; heuristics are advisory and may indicate obfuscation."
    ),
    "llm": "Review the classifier's explanation and confirm or dismiss the finding.",
    "skill": "Remove the malicious behaviour from the skill, or stop using the skill.",
    "skill_heuristic": (
        "Review the skill's behaviour against its declared description for a mismatch."
    ),
    "skill_llm": (
        "Review the behaviour flagged by the classifier and disable the skill if it is confirmed."
    ),
    "diagnostic": (
        "Check the LLM provider configuration and connectivity, then re-run the "
        "scan for a complete verdict."
    ),
    "other": "Review the finding and the rule documentation.",
}

# Canonical text used for IPI301 / IPI900 messages.
_IPI301_TEXT_TEMPLATE: str = "LLM classifier flagged content as {category}"
_IPI301_MARKDOWN_TEMPLATE: str = "**LLM classification** ({category}): {explanation}"
_IPI900_TEXT: str = "LLM classifier response was malformed or compromised"
_IPI900_MARKDOWN: str = (
    "The LLM classifier returned an invalid or untrusted response for this "
    "file. Falling back to static analysis only."
)
_IPI900_SKILL_MARKDOWN: str = (
    "The LLM classifier returned an invalid or untrusted response for this "
    "skill. Falling back to static analysis only."
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


def _fingerprint(rule_id: str, uri: str, line: int, snippet: str) -> str:
    """Return a stable, run-independent fingerprint for one result (T4.4).

    The digest is computed over ``ruleId + uri + line + snippet`` — all
    deterministic inputs, so two runs over unchanged content yield the same
    fingerprint and GitHub Code Scanning keeps matching an alert to the same
    result instead of opening a duplicate.

    ``snippet`` is the *raw detector payload* (never the escaped/truncated
    message): the byte snippet for a byte finding, the matched text for a
    pattern finding, and — deliberately — only the **category** for an LLM
    finding. The classifier's free-text explanation is excluded because it is
    model-generated and may differ between runs, which would destabilise alert
    identity.

    Args:
        rule_id: The SARIF ``ruleId`` of the result.
        uri: The (URI-encoded) artifact path of the primary location.
        line: The 1-based start line, or :data:`_FINGERPRINT_NO_LINE`.
        snippet: The raw, deterministic detector payload (``""`` when none).

    Returns:
        The first :data:`_FINGERPRINT_HEX_LENGTH` hex characters of the
        SHA-256 digest of the joined components.
    """
    payload = _FINGERPRINT_SEPARATOR.join((rule_id, uri, str(line), snippet))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:_FINGERPRINT_HEX_LENGTH]


def _partial_fingerprints(
    rule_id: str,
    uri: str,
    line: int,
    snippet: str,
) -> dict[str, str]:
    """Build the SARIF ``partialFingerprints`` object for one result (T4.4).

    Returns the GitHub-consumed ``primaryLocationLineHash`` (the digest in
    GitHub's ``<hash>:<occurrence>`` shape) plus a namespaced copy of the same
    digest.
    """
    digest = _fingerprint(rule_id, uri, line, snippet)
    return {
        _FINGERPRINT_PRIMARY_KEY: f"{digest}:1",
        _FINGERPRINT_NAMESPACE_KEY: digest,
    }


def _result_properties(
    rule_id: str,
    confidence: float,
    pattern_id: str | None = None,
) -> dict[str, Any]:
    """Build the tool-specific SARIF ``properties`` bag for one result (T4.4).

    SARIF forbids unknown top-level ``result`` keys (``additionalProperties:
    false``), so tool-specific data belongs in this bag — a ``propertyBag``
    that explicitly accepts additional properties.

    ``confidence`` is ``1.0`` for a deterministic detection and the classifier's
    confidence for an LLM finding. ``pattern_id`` is the most specific detector
    identifier available: the internal pattern id for a regex finding (finer
    than its rule id), otherwise the result's own rule id.
    """
    return {
        "confidence": confidence,
        "pattern_id": pattern_id if pattern_id is not None else rule_id,
    }


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
        "partialFingerprints": _partial_fingerprints(
            rule_id, uri, finding.line, finding.snippet_hex
        ),
        "properties": _result_properties(rule_id, _DETERMINISTIC_CONFIDENCE),
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
        "partialFingerprints": _partial_fingerprints(
            rule_id, uri, finding.line, finding.matched_text
        ),
        "properties": _result_properties(
            rule_id, _DETERMINISTIC_CONFIDENCE, finding.pattern_id
        ),
    }


def _build_llm_result(
    finding: LLMFinding,
    uri: str,
    confidence: float | None = None,
) -> dict[str, Any]:
    """Convert a :class:`LLMFinding` into a SARIF result object.

    ``confidence`` is the owning verdict's ``llm_confidence`` — attached to the
    result's ``properties`` bag so a consumer can rank probabilistic findings.
    It defaults to :data:`_DIAGNOSTIC_CONFIDENCE` when unavailable.

    The fingerprint snippet is the finding **category only** (not the
    model-generated ``explanation``), so the alert identity is stable across
    runs even when the classifier phrases its explanation differently.
    """
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
        "partialFingerprints": _partial_fingerprints(
            LLM_FINDING_RULE_ID, uri, finding.line, finding.category
        ),
        "properties": _result_properties(
            LLM_FINDING_RULE_ID,
            confidence if confidence is not None else _DIAGNOSTIC_CONFIDENCE,
            finding.category,
        ),
    }


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
        "partialFingerprints": _partial_fingerprints(
            rule_id, uri, _FINGERPRINT_NO_LINE, _NO_SNIPPET
        ),
        "properties": _result_properties(rule_id, _DETERMINISTIC_CONFIDENCE),
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
        "partialFingerprints": _partial_fingerprints(
            LLM_COMPROMISE_RULE_ID, uri, _FINGERPRINT_NO_LINE, _NO_SNIPPET
        ),
        "properties": _result_properties(LLM_COMPROMISE_RULE_ID, _DIAGNOSTIC_CONFIDENCE),
    }


def _build_skill_compromise_result(verdict: SkillFinalVerdict) -> dict[str, Any]:
    """Build the IPI900 note-level result for a compromised skill (IN-14).

    Mirrors :func:`_build_compromise_result` for :class:`SkillFinalVerdict`,
    anchored at the skill's ``SKILL.md``. Without this a degraded skill
    classification would be visible only in the reasoning text, never as a
    SARIF finding.
    """
    uri = url_quote(verdict.skill.metadata_file.relative_path, safe=_URI_SAFE_CHARS)
    return {
        "ruleId": LLM_COMPROMISE_RULE_ID,
        "level": SEVERITY_TO_LEVEL[Severity.LOW],
        "message": {
            "text": _IPI900_TEXT,
            "markdown": _IPI900_SKILL_MARKDOWN,
        },
        "locations": [_make_location(uri, None, None)],
        "partialFingerprints": _partial_fingerprints(
            LLM_COMPROMISE_RULE_ID, uri, _FINGERPRINT_NO_LINE, _NO_SNIPPET
        ),
        "properties": _result_properties(LLM_COMPROMISE_RULE_ID, _DIAGNOSTIC_CONFIDENCE),
    }


def _rule_family(rule_id: str) -> str:
    """Return the detector-family key for a ``ruleId`` (e.g. ``"byte"``).

    The family is derived from the rule's numeric suffix via
    :data:`_RULE_ID_RANGES`; an unrecognised or non-numeric id falls back to
    ``"other"`` so :func:`_rule_definition` can still emit a complete rule.
    """
    try:
        number = int(rule_id[3:])
    except ValueError:
        return "other"
    for low, high, family in _RULE_ID_RANGES:
        if low <= number <= high:
            return family
    return "other"


def _rule_help_text(
    rule_id: str,
    description: str,
    family_title: str,
    cwe: str | None,
    remediation: str,
) -> str:
    """Build the plain-text ``help.text`` body for a rule descriptor (T4.5)."""
    lines = [f"{rule_id} — {description}", "", f"Detector family: {family_title}"]
    if cwe is not None:
        lines.append(f"CWE: {cwe}")
    lines.append(f"Remediation: {remediation}")
    return "\n".join(lines)


def _rule_help_markdown(
    rule_id: str,
    description: str,
    family_title: str,
    cwe: str | None,
    remediation: str,
) -> str:
    """Build the Markdown ``help.markdown`` body for a rule descriptor (T4.5)."""
    parts = [f"**{rule_id}** — {description}", "", f"- **Detector family:** {family_title}"]
    if cwe is not None:
        parts.append(f"- **CWE:** {cwe}")
    parts.append(f"- **Remediation:** {remediation}")
    return "\n".join(parts) + "\n"


def _rule_definition(rule_id: str) -> dict[str, Any]:
    """Build a complete SARIF rule definition for the tool driver's rules array.

    Every rule descriptor carries (T4.5 / IN-5):

    * ``shortDescription`` — a one-line summary,
    * ``fullDescription`` — the summary plus the detector family and CWE,
    * ``help`` — plain-text and Markdown documentation (``help.text`` /
      ``help.markdown``),
    * ``helpUri`` — a per-rule documentation anchor,
    * ``properties.tags`` — ``security`` plus the rule's CWE.

    Descriptions, CWE mappings and family metadata are looked up from the
    module-level catalogs; an unknown rule id degrades gracefully to the ``id``
    itself and the generic ``other`` family so the descriptor never loses its
    required ``help``/``shortDescription`` fields.
    """
    description = RULE_DESCRIPTIONS.get(rule_id, rule_id)
    cwe = RULE_ID_TO_CWE.get(rule_id)
    family = _rule_family(rule_id)
    family_title = RULE_FAMILY_TITLES.get(family, RULE_FAMILY_TITLES["other"])
    remediation = RULE_FAMILY_REMEDIATION.get(family, RULE_FAMILY_REMEDIATION["other"])

    full_description = f"{description}. Detector family: {family_title}."
    if cwe is not None:
        full_description += f" Maps to {cwe}."

    tags = ["security"]
    if cwe is not None:
        tags.append(cwe)

    rule: dict[str, Any] = {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": description},
        "fullDescription": {"text": full_description},
        "defaultConfiguration": {"level": "warning"},
        "helpUri": f"{TOOL_INFORMATION_URI}#{rule_id}",
        "help": {
            "text": _rule_help_text(rule_id, description, family_title, cwe, remediation),
            "markdown": _rule_help_markdown(rule_id, description, family_title, cwe, remediation),
        },
        "properties": {"tags": tags},
    }
    return rule


def _collect_rule_ids(results: list[dict[str, Any]]) -> list[str]:
    """Return rule IDs in first-seen order across the results array."""
    seen: dict[str, None] = {}
    for result in results:
        rule_id = result.get("ruleId")
        if isinstance(rule_id, str) and rule_id not in seen:
            seen[rule_id] = None
    return list(seen.keys())


# A dedup key uniquely identifies a SARIF result by the contract tuple
# ``(ruleId, uri, line, column, snippet)``. ``line``/``column`` default to 0
# and ``snippet`` to the empty string when a result carries no region/text.
_ResultKey = tuple[str, str, int, int, str]


def _result_location(result: dict[str, Any]) -> tuple[str, int, int]:
    """Return ``(uri, line, column)`` for a SARIF result's primary location."""
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return "", 0, 0
    entry = locations[0]
    if not isinstance(entry, dict):
        return "", 0, 0
    physical = entry.get("physicalLocation")
    if not isinstance(physical, dict):
        return "", 0, 0
    artifact = physical.get("artifactLocation")
    uri = artifact.get("uri") if isinstance(artifact, dict) else None
    region = physical.get("region")
    line = region.get("startLine", 0) if isinstance(region, dict) else 0
    column = region.get("startColumn", 0) if isinstance(region, dict) else 0
    return (
        uri if isinstance(uri, str) else "",
        line if isinstance(line, int) else 0,
        column if isinstance(column, int) else 0,
    )


def _result_uri(result: dict[str, Any]) -> str:
    """Return the primary ``artifactLocation.uri`` of a SARIF result."""
    uri, _, _ = _result_location(result)
    return uri


def _result_key_from_dict(result: dict[str, Any]) -> _ResultKey:
    """Build a dedup key for a pre-built SARIF result (used for skill results)."""
    uri, line, column = _result_location(result)
    rule_id = result.get("ruleId")
    return (
        rule_id if isinstance(rule_id, str) else "",
        uri,
        line,
        column,
        _NO_SNIPPET,
    )


def _finding_severity(finding: ByteFinding | PatternFinding | LLMFinding) -> Severity:
    """Return the severity used to gate one finding against the threshold.

    Byte and pattern findings carry their own severity; LLM findings are
    probabilistic and always treated as MEDIUM (they map to a ``warning``
    SARIF level regardless of the model's confidence).
    """
    if isinstance(finding, (ByteFinding, PatternFinding)):
        return finding.severity
    return Severity.MEDIUM


def _passes_severity_threshold(severity: Severity, threshold: Severity) -> bool:
    """Return True when ``severity`` is at or above ``threshold``."""
    return _SEVERITY_RANK.get(severity, 0) >= _SEVERITY_RANK.get(threshold, 0)


def _append_compromise_result(
    keyed: list[tuple[_ResultKey, dict[str, Any]]],
    uri: str,
) -> None:
    """Append the IPI900 compromise note for ``uri`` to ``keyed``.

    IPI900 is a note-level (``LOW``) *scan-integrity* diagnostic that describes
    the integrity of the scan itself, so it is emitted independently of the
    file/skill decision (including ``PASS``) and is **exempt from
    ``--severity-threshold``** (R011: it must be emitted whenever a verdict's
    LLM classification was compromised — the skill path is exempt the same
    way). Identical to :func:`_build_skill_compromise_result` for skills.
    """
    keyed.append(
        ((LLM_COMPROMISE_RULE_ID, uri, 0, 0, _NO_SNIPPET), _build_compromise_result(uri))
    )


def _keyed_results_for_verdict(
    verdict: FinalVerdict,
    severity_threshold: Severity = DEFAULT_SEVERITY_THRESHOLD,
) -> tuple[list[tuple[_ResultKey, dict[str, Any]]], int]:
    """Build ``(dedup_key, sarif_result)`` pairs for a single file verdict.

    The key is ``(ruleId, uri, line, column, snippet)`` where ``snippet`` is
    the raw byte snippet (``snippet_hex``) / matched text / LLM explanation —
    not the (truncated, HTML-escaped) message — so deduplication is exact.

    Findings whose severity is below ``severity_threshold`` are dropped here
    (before deduplication and the per-file cap, so they are never counted as
    duplicates). Returns the keyed pairs together with the number of findings
    dropped by the threshold.

    A ``PASS`` decision produces **no** results: the fused analysis has already
    adjudicated the file's findings as non-actionable, so emitting them would
    contradict the verdict and reintroduce noise (R011). The sole exception is
    the IPI900 diagnostic, which MUST stay visible when the LLM classification
    was compromised (IN-14) — it describes scan integrity, not file content.
    """
    uri = _artifact_uri(verdict)
    keyed: list[tuple[_ResultKey, dict[str, Any]]] = []
    below_threshold = 0

    if verdict.decision == VerdictDecision.PASS:
        if verdict.llm_compromised:
            _append_compromise_result(keyed, uri)
        return keyed, below_threshold

    for finding in verdict.all_findings:
        if not _passes_severity_threshold(_finding_severity(finding), severity_threshold):
            below_threshold += 1
            continue
        if isinstance(finding, ByteFinding):
            rule_id = CATEGORY_TO_RULE_ID[finding.category]
            keyed.append(
                (
                    (rule_id, uri, finding.line, finding.column, finding.snippet_hex),
                    _build_byte_result(finding, uri),
                )
            )
        elif isinstance(finding, PatternFinding):
            rule_id = CATEGORY_TO_RULE_ID[finding.category]
            keyed.append(
                (
                    (rule_id, uri, finding.line, finding.column, finding.matched_text),
                    _build_pattern_result(finding, uri),
                )
            )
        elif isinstance(finding, LLMFinding):
            keyed.append(
                (
                    (
                        LLM_FINDING_RULE_ID,
                        uri,
                        finding.line,
                        0,
                        f"{finding.category}\x00{finding.explanation}",
                    ),
                    _build_llm_result(finding, uri, verdict.llm_confidence),
                )
            )

    if verdict.llm_compromised:
        _append_compromise_result(keyed, uri)

    heuristic_keyed, heuristic_below = _keyed_heuristic_results(
        verdict, uri, severity_threshold
    )
    keyed.extend(heuristic_keyed)
    below_threshold += heuristic_below
    return keyed, below_threshold


def _keyed_heuristic_results(
    verdict: FinalVerdict,
    uri: str,
    severity_threshold: Severity = DEFAULT_SEVERITY_THRESHOLD,
) -> tuple[list[tuple[_ResultKey, dict[str, Any]]], int]:
    """Promote heuristic suspicious flags to keyed SARIF results.

    Heuristic results are suppressed for ``PASS`` verdicts: a PASS decision
    means the fused analysis found nothing actionable, so emitting standalone
    IPI201–204 notices would only surface noise on clean files.

    Heuristic notices are MEDIUM severity, so a threshold above MEDIUM filters
    them all out — the count of suppressed notices is returned alongside the
    keyed pairs.
    """
    if verdict.decision == VerdictDecision.PASS:
        return [], 0

    scores = verdict.heuristic_scores
    if scores is None:
        return [], 0

    flags: list[tuple[str, bool, float]] = [
        (_HEURISTIC_ENTROPY_RULE_ID, scores.entropy_suspicious, scores.entropy),
        (_HEURISTIC_INVISIBLE_RULE_ID, scores.invisible_suspicious, scores.invisible_ratio),
        (
            _HEURISTIC_INSTRUCTION_DENSITY_RULE_ID,
            scores.instruction_density_suspicious,
            scores.instruction_density,
        ),
        (
            _HEURISTIC_CONTRADICTION_RULE_ID,
            scores.contradiction_suspicious,
            scores.contradiction_score,
        ),
    ]

    emit = _passes_severity_threshold(Severity.MEDIUM, severity_threshold)
    out: list[tuple[_ResultKey, dict[str, Any]]] = []
    below_threshold = 0
    for rule_id, suspicious, score in flags:
        if not suspicious:
            continue
        if not emit:
            below_threshold += 1
            continue
        out.append(((rule_id, uri, 0, 0, _NO_SNIPPET), _heuristic_result(rule_id, score, uri)))
    return out, below_threshold


def _dedupe_keyed_results(
    keyed: list[tuple[_ResultKey, dict[str, Any]]],
) -> tuple[list[dict[str, Any]], int]:
    """Collapse results with identical keys, keeping the first occurrence.

    Returns the surviving results (original order preserved) and the number
    of duplicates removed.
    """
    seen: set[_ResultKey] = set()
    results: list[dict[str, Any]] = []
    removed = 0
    for key, result in keyed:
        if key in seen:
            removed += 1
            continue
        seen.add(key)
        results.append(result)
    return results, removed


def _select_file_keep_indices(file_results: list[dict[str, Any]], cap: int) -> list[int]:
    """Choose which indices of one file's results survive the cap.

    The result set is bounded by ``cap``. Every distinct ``ruleId`` in the
    file is represented by its first occurrence (so no finding category
    silently disappears); the remaining slots are filled with the earliest
    remaining results. When a file contains more distinct rule IDs than the
    cap allows, only the earliest ``cap`` first-occurrences are kept.
    """
    n = len(file_results)
    if n <= cap:
        return list(range(n))

    first_occurrence: dict[Any, int] = {}
    for index, result in enumerate(file_results):
        rule_id = result.get("ruleId")
        if rule_id not in first_occurrence:
            first_occurrence[rule_id] = index

    if len(first_occurrence) > cap:
        chosen = set(sorted(first_occurrence.values())[:cap])
    else:
        chosen = set(first_occurrence.values())
        for index in range(n):
            if len(chosen) >= cap:
                break
            chosen.add(index)

    return sorted(chosen)


def _cap_results_per_file(
    results: list[dict[str, Any]],
    max_findings_per_file: int,
) -> tuple[list[dict[str, Any]], int]:
    """Truncate each file's results to ``max_findings_per_file`` entries.

    The cap is applied independently per artifact URI; order is preserved and
    the choice of survivors is deterministic (see
    :func:`_select_file_keep_indices`). A non-positive
    ``max_findings_per_file`` disables the cap. Returns the kept results and
    the number removed.
    """
    if max_findings_per_file <= UNLIMITED_MAX_FINDINGS_PER_FILE:
        return results, 0

    indices_by_uri: dict[str, list[int]] = {}
    order: list[str] = []
    for index, result in enumerate(results):
        uri = _result_uri(result)
        if uri not in indices_by_uri:
            indices_by_uri[uri] = []
            order.append(uri)
        indices_by_uri[uri].append(index)

    keep_indices: set[int] = set()
    for uri in order:
        indices = indices_by_uri[uri]
        file_results = [results[i] for i in indices]
        for local in _select_file_keep_indices(file_results, max_findings_per_file):
            keep_indices.add(indices[local])

    kept = [result for index, result in enumerate(results) if index in keep_indices]
    return kept, len(results) - len(kept)


def _heaviest_static_finding(
    verdict: SkillFinalVerdict,
) -> ByteFinding | PatternFinding | None:
    """Return the most severe *mapped* static finding behind a skill verdict.

    Byte and pattern findings carry their own severity and are ranked with
    :data:`_SEVERITY_RANK` (ties keep the first-seen finding, so the choice is
    deterministic). A finding whose category maps to no SARIF rule is skipped —
    it cannot label the verdict. The result drives both the emitted ``ruleId``
    (:func:`_skill_rule_id`) and, when the finding lies in ``SKILL.md``, the
    primary location's region (IN-1 / IN-3).
    """
    best: ByteFinding | PatternFinding | None = None
    best_rank = -1
    for finding in verdict.all_findings:
        if not isinstance(finding, (ByteFinding, PatternFinding)):
            continue
        if CATEGORY_TO_RULE_ID.get(finding.category) is None:
            continue
        rank = _SEVERITY_RANK.get(finding.severity, 0)
        if rank > best_rank:
            best_rank = rank
            best = finding
    return best


def _skill_rule_id(verdict: SkillFinalVerdict) -> str:
    """Select the SARIF rule ID for a blocked skill from its heaviest finding.

    A skill verdict aggregates findings across every bundled file, so the
    emitted rule must reflect the **most severe** contribution rather than a
    positional guess (IN-1). This means a skill that blocks purely on byte
    findings is labelled with the matching byte rule (e.g. ``IPI003``), never
    with the remote-execution rule ``IPI401``.

    When no static finding exists the rule falls back, in order, to the LLM
    finding rule, the compromise diagnostic (``IPI900``) for a degraded
    classification, or the generic skill heuristic rule.
    """
    heaviest = _heaviest_static_finding(verdict)
    if heaviest is not None:
        return CATEGORY_TO_RULE_ID[heaviest.category]
    if any(isinstance(finding, LLMFinding) for finding in verdict.all_findings):
        return SKILL_LLM_RULE_ID
    if verdict.llm_compromised:
        return LLM_COMPROMISE_RULE_ID
    return SKILL_HEURISTIC_RULE_ID


def _finding_artifact(
    finding: ByteFinding | PatternFinding | LLMFinding,
    skill: SkillUnit,
) -> DiscoveredFile:
    """Return the artifact a skill finding was detected in.

    Findings carry their source file when the skill path attributes it (see
    :attr:`ByteFinding.file`); one without it — e.g. a hand-built verdict — is
    anchored at the skill's ``SKILL.md``.
    """
    if finding.file is not None:
        return finding.file
    return skill.metadata_file


def _finding_location(
    finding: ByteFinding | PatternFinding | LLMFinding,
    skill: SkillUnit,
) -> dict[str, Any]:
    """Build a ``location`` for one finding at its *real* file and line (IN-3)."""
    column = finding.column if isinstance(finding, (ByteFinding, PatternFinding)) else None
    uri = url_quote(_finding_artifact(finding, skill).relative_path, safe=_URI_SAFE_CHARS)
    return _make_location(uri, finding.line, column)


def _build_skill_result(verdict: SkillFinalVerdict) -> dict[str, Any] | None:
    """Build the SARIF result for a skill verdict, or ``None`` when it passes.

    One result per skill (R008): ``SKILL.md`` is the primary location, and every
    contributing finding is listed in ``relatedLocations`` at the **real file
    and line** it was detected at (IN-3 / T4.3). This prevents a finding in a
    bundled file from being reported as a line inside ``SKILL.md`` — the
    previous behaviour took the line from the first finding regardless of which
    file it came from. ``relatedLocations`` therefore carry the finding details
    (file, line, column) rather than merely naming the bundled files; a bundled
    file that contributes no finding is still listed once, so the full file set
    stays visible. Every location appears at most once (``uniqueItems`` is
    mandatory for ``relatedLocations``).

    A ``BLOCK`` verdict is labelled with the rule of its heaviest finding (see
    :func:`_skill_rule_id`), so a byte-only block reports the matching byte rule
    rather than a hard-coded default. A ``PASS`` decision is not a finding: PASS
    skills contribute no SARIF result (the count is reported on the invocation
    summary instead, R008/R011).
    """
    if verdict.decision == VerdictDecision.PASS:
        return None

    skill = verdict.skill
    uri = url_quote(skill.metadata_file.relative_path, safe=_URI_SAFE_CHARS)

    # Determine rule ID and level from the decision. A BLOCK is labelled with
    # the rule of its heaviest contributing finding (severity → rule), so a
    # skill that blocks purely on byte findings reports the matching byte rule
    # (e.g. IPI003) instead of the remote-execution default IPI401 (IN-1).
    if verdict.decision == VerdictDecision.BLOCK:
        level = "error"
        rule_id = _skill_rule_id(verdict)
    else:  # VerdictDecision.REVIEW_REQUIRED
        rule_id = SKILL_HEURISTIC_RULE_ID
        level = "warning"

    # Primary location: SKILL.md. Attach a region only when the heaviest
    # contributing finding actually lies *in* SKILL.md — never borrow a line
    # from a finding that lives in a bundled file (IN-3).
    anchoring = _heaviest_static_finding(verdict)
    if anchoring is not None and (
        _finding_artifact(anchoring, skill).relative_path
        != skill.metadata_file.relative_path
    ):
        anchoring = None
    primary_line = anchoring.line if anchoring is not None else None
    primary_column = anchoring.column if anchoring is not None else None

    # Related locations: one entry per contributing finding, at its real file
    # and line/column (IN-3 / T4.3), followed by every bundled file that
    # contributed no finding so the file set stays complete (R008).
    related: list[dict[str, Any]] = []
    covered_uris: set[str] = set()
    # SARIF requires ``relatedLocations`` to be unique (``uniqueItems: true`` in
    # the 2.1.0 schema). Two *distinct* findings can still resolve to a single
    # physical location — e.g. two regexes categorised IPI409 matching the same
    # skill line — so collapse identical locations rather than emitting the same
    # (file, line, column) twice and producing a schema-invalid document.
    seen_locations: set[tuple[str, int | None, int | None]] = set()
    for finding in verdict.all_findings:
        if finding is anchoring:
            continue  # Already represented by the primary location.
        location = _finding_location(finding, skill)
        physical = location["physicalLocation"]
        finding_uri = physical["artifactLocation"]["uri"]
        region = physical.get("region") or {}
        signature = (finding_uri, region.get("startLine"), region.get("startColumn"))
        covered_uris.add(finding_uri)
        if signature in seen_locations:
            continue
        seen_locations.add(signature)
        related.append(location)
    for file in skill.files:
        if file.relative_path == skill.metadata_file.relative_path:
            continue  # SKILL.md is the primary location.
        file_uri = url_quote(file.relative_path, safe=_URI_SAFE_CHARS)
        if file_uri in covered_uris:
            continue  # Already represented by one of its findings.
        related.append(_make_location(file_uri, None, None))

    name = _escape_sarif_content(skill.frontmatter.name)
    reasoning = _escape_sarif_content(verdict.reasoning)

    return {
        "ruleId": rule_id,
        "level": level,
        "message": {
            "text": f"Skill '{name}': {reasoning}",
            "markdown": (
                f"**Skill '{name}'** — {reasoning}<br/>"
                f"Decision: *{verdict.decision.value}* | "
                f"Static severity: *{verdict.static_severity.value}*"
            ),
        },
        "locations": [_make_location(uri, primary_line, primary_column)],
        "relatedLocations": related,
        "partialFingerprints": _partial_fingerprints(
            rule_id,
            uri,
            primary_line if primary_line is not None else _FINGERPRINT_NO_LINE,
            _NO_SNIPPET,
        ),
        "properties": _result_properties(
            rule_id,
            verdict.llm_confidence
            if verdict.llm_confidence is not None
            else _DETERMINISTIC_CONFIDENCE,
        ),
    }


def _decision_counts(decisions: list[VerdictDecision]) -> dict[str, int]:
    """Count verdicts by decision (``block`` / ``reviewRequired`` / ``pass``)."""
    return {
        "block": sum(1 for d in decisions if d == VerdictDecision.BLOCK),
        "reviewRequired": sum(1 for d in decisions if d == VerdictDecision.REVIEW_REQUIRED),
        "pass": sum(1 for d in decisions if d == VerdictDecision.PASS),
    }


def _build_summary(
    verdicts: list[FinalVerdict],
    skill_verdicts: list[SkillFinalVerdict] | None,
    results_emitted: int,
    results_suppressed: int = 0,
    suppression_policy: SuppressionPolicy | None = None,
) -> dict[str, Any]:
    """Build the run summary attached to ``invocations[0].properties``.

    PASS verdicts (files and skills) are deliberately excluded from
    ``results`` — a PASS decision is not a finding. This summary records how
    many files/skills fell into each decision bucket, plus how many results
    were actually emitted, so that the suppression is never silent (R011).
    ``resultsSuppressed`` counts emitted results that carry an accepted
    suppression (T5.3) — they remain in ``results`` but are marked suppressed.
    """
    files = _decision_counts([v.decision for v in verdicts])
    skills = _decision_counts([s.decision for s in (skill_verdicts or [])])
    return {
        "filesScanned": len(verdicts),
        "filesBlocked": files["block"],
        "filesReviewRequired": files["reviewRequired"],
        "filesPassed": files["pass"],
        "skillsScanned": len(skill_verdicts) if skill_verdicts else 0,
        "skillsBlocked": skills["block"],
        "skillsReviewRequired": skills["reviewRequired"],
        "skillsPassed": skills["pass"],
        "resultsEmitted": results_emitted,
        "resultsSuppressed": results_suppressed,
        "suppressionSources": _suppression_sources(suppression_policy),
    }


#: Upper bound on ignore-file entries mirrored into the run summary — the
#: summary must stay small even for pathological ignore files; the exact
#: count is always reported alongside.
_MAX_REPORTED_SUPPRESSION_ENTRIES: int = 100


def _suppression_sources(policy: SuppressionPolicy | None) -> dict[str, Any]:
    """Describe the repo-provided suppression configuration (R012 visibility).

    Suppressions mark SARIF results ``status: "accepted"``, which GitHub Code
    Scanning hides — so the configuration that produced them must be visible
    in-band: the ignore-file entries and the files carrying inline directives
    are mirrored into ``invocations[0].properties.suppressionSources``. An
    attacker-authored ``.ipi-checkignore`` can no longer silence alerts
    without leaving a machine-readable trail in the very same document.
    """
    if policy is None or policy.is_empty:
        return {}
    entries = [
        {
            "pattern": entry.pattern,
            "rules": sorted(entry.rules) if entry.rules is not None else None,
            "negated": entry.negated,
        }
        for entry in policy.entries[:_MAX_REPORTED_SUPPRESSION_ENTRIES]
    ]
    inline_files = sorted(
        path
        for path, directives in policy.inline.items()
        if directives.file_rules is not None or directives.lines
    )
    return {
        "ignoreEntryCount": len(policy.entries),
        "ignoreEntries": entries,
        "inlineDirectiveFiles": inline_files,
    }


def _resolve_suppression_policy(
    verdicts: list[FinalVerdict],
    skill_verdicts: list[SkillFinalVerdict] | None,
) -> SuppressionPolicy | None:
    """Return the suppression policy carried by the verdicts, if any.

    The pipeline attaches one shared :class:`SuppressionPolicy` to every
    verdict (file and skill); hand-built verdicts leave it ``None``.
    """
    for verdict in verdicts:
        if verdict.suppression_policy is not None:
            return verdict.suppression_policy
    for skill_verdict in skill_verdicts or []:
        if skill_verdict.suppression_policy is not None:
            return skill_verdict.suppression_policy
    return None


def _apply_suppressions(
    results: list[dict[str, Any]],
    policy: SuppressionPolicy | None,
) -> int:
    """Mark suppressed results and return how many were suppressed (T5.3).

    A suppression is resolved from the repository policy for each emitted
    result's ``(ruleId, uri, line)``. A suppressed result stays in ``results``
    -- so a consumer (e.g. GitHub Code Scanning) can hide it while keeping the
    audit trail -- and gains a SARIF ``suppressions`` array whose entry carries
    ``status: "accepted"`` and the resolved ``kind`` (``external`` for
    ``.ipi-checkignore``, ``inSource`` for an inline directive).
    """
    if policy is None or policy.is_empty:
        return 0

    suppressed_count = 0
    for result in results:
        rule_id = result.get("ruleId")
        if not isinstance(rule_id, str):
            continue
        uri, line, _column = _result_location(result)
        relative_path = url_unquote(uri)
        suppression = resolve_suppression(
            policy,
            relative_path,
            rule_id,
            line if line > 0 else None,
        )
        if suppression is None:
            continue
        result["suppressions"] = [
            {
                "kind": suppression.kind.value,
                "status": "accepted",
                # Escaped like every other user-controlled SARIF field (R005):
                # the justification embeds ignore-file patterns written inside
                # the scanned (untrusted) repository.
                "justification": _escape_sarif_content(suppression.justification),
            }
        ]
        suppressed_count += 1
    return suppressed_count


def generate_sarif(
    verdicts: list[FinalVerdict],
    repo_path: Path,
    tool_info: ToolInfo,
    start_time: str,
    end_time: str,
    *,
    skill_verdicts: list[SkillFinalVerdict] | None = None,
    max_findings_per_file: int = DEFAULT_MAX_FINDINGS_PER_FILE,
    severity_threshold: Severity = DEFAULT_SEVERITY_THRESHOLD,
) -> dict[str, Any]:
    """Generate a SARIF v2.1.0 document from scan verdicts.

    Identical results (same ``ruleId``, artifact URI, line, column and
    snippet) are collapsed, and no file contributes more than
    ``max_findings_per_file`` results (``0`` disables the cap). Use
    :func:`generate_sarif_with_stats` to also obtain the suppression counts.

    Args:
        verdicts: Final per-file decisions from confidence fusion.
        repo_path: Repository root (kept for interface stability — relative
            paths are already computed by file discovery).
        tool_info: Tool name/version metadata for the SARIF driver block.
        start_time: ISO-8601 UTC timestamp of scan start.
        end_time: ISO-8601 UTC timestamp of scan end.
        skill_verdicts: Optional per-skill decisions from confidence fusion.
            Each skill produces one SARIF result with the SKILL.md as the
            primary location.
        max_findings_per_file: Maximum results emitted per file; ``0`` means
            unlimited.
        severity_threshold: Minimum severity for an individual finding to be
            emitted (``NONE`` keeps every finding). Skill-level results are
            unaffected.

    Returns:
        A SARIF v2.1.0 document as a JSON-serializable dict.
    """
    document, _stats = generate_sarif_with_stats(
        verdicts,
        repo_path,
        tool_info,
        start_time,
        end_time,
        skill_verdicts=skill_verdicts,
        max_findings_per_file=max_findings_per_file,
        severity_threshold=severity_threshold,
    )
    return document


def generate_sarif_with_stats(
    verdicts: list[FinalVerdict],
    repo_path: Path,
    tool_info: ToolInfo,
    start_time: str,
    end_time: str,
    *,
    skill_verdicts: list[SkillFinalVerdict] | None = None,
    max_findings_per_file: int = DEFAULT_MAX_FINDINGS_PER_FILE,
    severity_threshold: Severity = DEFAULT_SEVERITY_THRESHOLD,
) -> tuple[dict[str, Any], SarifLimitStats]:
    """Like :func:`generate_sarif`, but also return suppression statistics.

    Returns the SARIF document together with a :class:`SarifLimitStats`
    describing how many findings were dropped below ``severity_threshold``, how
    many duplicate results were collapsed, and how many were truncated by the
    per-file cap.
    """
    del repo_path  # relative paths are precomputed; argument kept for parity.

    # Build (dedup_key, result) pairs for every file and skill. Findings below
    # the severity threshold are dropped here, before dedup/cap.
    keyed: list[tuple[_ResultKey, dict[str, Any]]] = []
    below_threshold_removed = 0
    for verdict in verdicts:
        verdict_keyed, verdict_below = _keyed_results_for_verdict(verdict, severity_threshold)
        keyed.extend(verdict_keyed)
        below_threshold_removed += verdict_below

    # Add skill results — one SARIF result per skill, plus an IPI900 note when
    # the skill's LLM classification was compromised (IN-14). Skill results
    # represent an aggregated verdict, not an individual finding, so they are
    # not subject to --severity-threshold.
    if skill_verdicts:
        for sv in skill_verdicts:
            # PASS skills contribute no result (R008/R011); the compromise
            # diagnostic still survives a degraded classification.
            skill_result = _build_skill_result(sv)
            if skill_result is not None:
                keyed.append((_result_key_from_dict(skill_result), skill_result))
            if sv.llm_compromised:
                compromise_result = _build_skill_compromise_result(sv)
                keyed.append((_result_key_from_dict(compromise_result), compromise_result))

    # Deduplicate identical results, then apply the per-file cap.
    all_results, duplicates_removed = _dedupe_keyed_results(keyed)
    all_results, capped_removed = _cap_results_per_file(all_results, max_findings_per_file)

    # Apply repository suppressions (T5.3 / IN-19). Suppressed results stay in
    # the array but carry a SARIF ``suppressions`` entry with status "accepted".
    suppression_policy = _resolve_suppression_policy(verdicts, skill_verdicts)
    suppressed_results = _apply_suppressions(all_results, suppression_policy)

    stats = SarifLimitStats(
        max_findings_per_file=max_findings_per_file,
        duplicates_removed=duplicates_removed,
        capped_removed=capped_removed,
        below_threshold_removed=below_threshold_removed,
        suppressed_results=suppressed_results,
    )

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
        "properties": _build_summary(
            verdicts,
            skill_verdicts,
            len(all_results),
            suppressed_results,
            suppression_policy,
        ),
    }

    run: dict[str, Any] = {
        "tool": {"driver": driver},
        "invocations": [invocation],
        "results": all_results,
    }

    document: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [run],
    }
    return document, stats
