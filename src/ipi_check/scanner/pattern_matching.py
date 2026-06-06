"""Pattern Matching — Layer 3: regex-based injection phrase detection."""
from __future__ import annotations

import concurrent.futures
import re

from ipi_check.core.types import (
    DiscoveredFile,
    FileCategory,
    PatternFinding,
    PatternFindingCategory,
    Severity,
)

MAX_MATCHED_TEXT_LENGTH: int = 120
REGEX_TIMEOUT_SECONDS: float = 0.1

# (pattern_id, regex_string, category, severity)
INJECTION_PATTERNS: list[tuple[str, str, PatternFindingCategory, Severity]] = [
    # Instruction Override
    (
        "INSTR_001",
        r"(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|system|earlier)\s+(?:instructions?|prompts?|rules?|context)",
        PatternFindingCategory.INSTRUCTION_OVERRIDE,
        Severity.CRITICAL,
    ),
    # Authority Claims
    (
        "AUTH_001",
        r"(?:you\s+(?:must|shall|are\s+required\s+to)|these\s+rules?\s+(?:are|supersede|override|take\s+precedence))",
        PatternFindingCategory.AUTHORITY_CLAIM,
        Severity.HIGH,
    ),
    (
        "AUTH_002",
        r"(?:non-?negotiable|highest\s+priority|cannot\s+be\s+overridden)",
        PatternFindingCategory.AUTHORITY_CLAIM,
        Severity.HIGH,
    ),
    # Destructive Commands
    (
        "DEST_001",
        r"(?:delete|remove|destroy|nuke|wipe|drop)\s+(?:all|every|the\s+entire)\s+",
        PatternFindingCategory.DESTRUCTIVE_COMMAND,
        Severity.CRITICAL,
    ),
    (
        "DEST_002",
        r"(?:rm\s+-rf|rmdir|shutil\.rmtree|os\.remove)",
        PatternFindingCategory.DESTRUCTIVE_COMMAND,
        Severity.CRITICAL,
    ),
    # Data Exfiltration
    (
        "EXFIL_001",
        r"(?:curl|wget|fetch|http\.?(?:get|post|request))\s+.*(?:attacker|evil|exfil)",
        PatternFindingCategory.DATA_EXFILTRATION,
        Severity.CRITICAL,
    ),
    (
        "EXFIL_002",
        r"(?:send|post|upload|exfiltrate)\s+.*(?:to|towards)\s+(?:https?://|[a-z]+\.(?:com|io|net))",
        PatternFindingCategory.DATA_EXFILTRATION,
        Severity.CRITICAL,
    ),
    # Shell Injection
    (
        "SHELL_001",
        r"(?:run|execute|eval|sh\s+-c|bash\s+-c|system\()\s*[\"']?(?:curl|wget|nc|python)",
        PatternFindingCategory.SHELL_INJECTION,
        Severity.CRITICAL,
    ),
    # Jailbreak
    (
        "JAIL_001",
        r"(?:you\s+are\s+now|new\s+persona|act\s+as\s+if|pretend\s+(?:you|that)|from\s+now\s+on\s+you)",
        PatternFindingCategory.JAILBREAK,
        Severity.HIGH,
    ),
    (
        "JAIL_002",
        r"(?:developer\s+mode|\bDAN\b|do\s+anything\s+now)",
        PatternFindingCategory.JAILBREAK,
        Severity.HIGH,
    ),
]

# Compiled patterns (case-insensitive)
_COMPILED_PATTERNS: list[tuple[str, re.Pattern[str], PatternFindingCategory, Severity]] = [
    (pid, re.compile(pattern, re.IGNORECASE), category, severity)
    for pid, pattern, category, severity in INJECTION_PATTERNS
]

# Description templates per category.
_CATEGORY_DESCRIPTIONS: dict[PatternFindingCategory, str] = {
    PatternFindingCategory.INSTRUCTION_OVERRIDE: (
        "Instruction override pattern detected: attempts to bypass existing rules"
    ),
    PatternFindingCategory.AUTHORITY_CLAIM: (
        "Authority claim detected: attempts to establish rule priority"
    ),
    PatternFindingCategory.DESTRUCTIVE_COMMAND: (
        "Destructive command pattern detected: attempts to delete/destroy data"
    ),
    PatternFindingCategory.DATA_EXFILTRATION: (
        "Data exfiltration pattern detected: attempts to send data externally"
    ),
    PatternFindingCategory.SHELL_INJECTION: (
        "Shell injection pattern detected: attempts to execute arbitrary code"
    ),
    PatternFindingCategory.JAILBREAK: (
        "Jailbreak pattern detected: attempts persona/role manipulation"
    ),
}

# Severity ordering (higher index → more severe).
_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.NONE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Invisible character cleanup regex.
# - ANSI escape sequences (CSI/OSC and similar): ESC [ ... <letter>
# - Unicode tag block: U+E0000-U+E007F
# - Zero-width and line/paragraph separators: U+200B-U+200F, U+2028, U+2029
# - Bidi overrides: U+202A-U+202E, U+2066-U+2069
# - Variation selectors: U+FE00-U+FE0F
_INVISIBLE_CHARS_RE: re.Pattern[str] = re.compile(
    "\x1b\\[[^A-Za-z]*[A-Za-z]"
    "|[\U000e0000-\U000e007f]"
    "|[\u200b-\u200f\u2028\u2029]"
    "|[\u202a-\u202e\u2066-\u2069]"
    "|[\ufe00-\ufe0f]"
)

# Collapse runs of horizontal whitespace (anything in \s except '\n')
# to a single space. Newlines are preserved so callers can split by lines.
_HORIZONTAL_WS_RE: re.Pattern[str] = re.compile(r"[^\S\n]+")

# Regex to extract original line numbers from the ``[L{line}]`` prefix that
# ``extract_comments_and_strings`` attaches to each extracted fragment.
# Matches at the start of a line: ``[L42] rest of line...``.
_EXTRACTED_LINE_RE: re.Pattern[str] = re.compile(r"^\[L(\d+)\]\s")


def normalize_str(text: str) -> str:
    """Normalize an already-decoded string for pattern matching.

    Steps:
        1. Strip invisible characters (zero-width, Unicode tags, ANSI
           escapes, bidi overrides, variation selectors).
        2. Lowercase.
        3. Collapse runs of horizontal whitespace to a single space
           (newlines are preserved to allow line-based matching).

    This is the post-decode portion of :func:`normalize_text`, factored
    out so callers can normalize pre-extracted content (e.g., from
    :func:`~ipi_check.scanner.code_extractor.extract_comments_and_strings`)
    without redundant decode.
    """
    stripped = _INVISIBLE_CHARS_RE.sub("", text)
    lowered = stripped.lower()
    collapsed = _HORIZONTAL_WS_RE.sub(" ", lowered)
    return collapsed


def normalize_text(raw_bytes: bytes) -> str:
    """Normalize raw bytes for pattern matching.

    Steps:
        1. Decode UTF-8 with ``errors="replace"``.
        2. Delegate to :func:`normalize_str` for the remaining steps
           (strip invisible chars, lowercase, collapse whitespace).
    """
    decoded = raw_bytes.decode("utf-8", errors="replace")
    return normalize_str(decoded)


def _truncate(text: str, limit: int = MAX_MATCHED_TEXT_LENGTH) -> str:
    """Truncate text to ``limit`` characters with an ellipsis suffix."""
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "…"


def _downgrade_severity(severity: Severity, ceiling: Severity) -> Severity:
    """Cap ``severity`` at ``ceiling`` per ``_SEVERITY_ORDER``."""
    if _SEVERITY_ORDER[severity] > _SEVERITY_ORDER[ceiling]:
        return ceiling
    return severity


def _find_all_with_timeout(
    pattern: re.Pattern[str],
    line: str,
    executor: concurrent.futures.ThreadPoolExecutor,
) -> list[re.Match[str]] | None:
    """Run ``pattern.finditer`` against ``line`` with a thread-based timeout.

    Returns the list of matches on success, or ``None`` if the regex
    exceeded :data:`REGEX_TIMEOUT_SECONDS` (ReDoS protection).
    """
    future = executor.submit(lambda: list(pattern.finditer(line)))
    try:
        return future.result(timeout=REGEX_TIMEOUT_SECONDS)
    except concurrent.futures.TimeoutError:
        future.cancel()
        return None


def _parse_extracted_lines(target_text: str) -> tuple[list[int], str]:
    """Parse ``[L{line}]`` prefixes from extracted comment/string text.

    Returns a tuple of ``(original_line_numbers, clean_text)`` where
    ``original_line_numbers[i]`` is the source line number for the
    ``i``-th fragment line (1-based index) and ``clean_text`` has all
    ``[L{line}]`` prefixes stripped.

    When a line does not start with ``[L{line}]`` (e.g. L009 fallback
    where full content is returned), the fragment index itself is used
    as the line number — which matches the original file lines.
    """
    raw_lines = target_text.split("\n")
    line_numbers: list[int] = []
    clean_lines: list[str] = []
    for i, line in enumerate(raw_lines, start=1):
        m = _EXTRACTED_LINE_RE.match(line)
        if m:
            line_numbers.append(int(m.group(1)))
            clean_lines.append(line[m.end():])
        else:
            line_numbers.append(i)
            clean_lines.append(line)
    return line_numbers, "\n".join(clean_lines)


def match_patterns(
    file: DiscoveredFile,
    raw_bytes: bytes,
    target_text: str | None = None,
) -> list[PatternFinding]:
    """Match injection patterns against normalized file content.

    Each compiled pattern is executed line-by-line under a thread-based
    timeout to provide ReDoS protection. Findings carry 1-indexed line
    and column numbers relative to the normalized text.

    When ``target_text`` is provided (e.g., pre-extracted comments and
    strings from source code), it is normalized via :func:`normalize_str`
    instead of decoding ``raw_bytes``.  If ``target_text`` contains
    ``[L{line}]`` prefixes (produced by
    :func:`~ipi_check.scanner.code_extractor.extract_comments_and_strings`),
    the original source line numbers are recovered and used in findings
    instead of the fragment indices.

    Severity downgrade rule: if the file is a Markdown file (``.md``)
    that is *not* categorised as an agent instruction document, the
    severity for every finding is capped at :data:`Severity.MEDIUM`.
    """
    line_numbers: list[int] | None = None

    if target_text is not None:
        line_numbers, clean_text = _parse_extracted_lines(target_text)
        normalized = normalize_str(clean_text)
    else:
        normalized = normalize_text(raw_bytes)
    if not normalized:
        return []

    is_non_agent_markdown = (
        file.category != FileCategory.AGENT_INSTRUCTION
        and file.path.suffix.lower() == ".md"
    )

    findings: list[PatternFinding] = []
    lines = normalized.split("\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        for line_index, line in enumerate(lines, start=1):
            if not line:
                continue
            actual_line = line_numbers[line_index - 1] if line_numbers else line_index
            for pattern_id, compiled, category, base_severity in _COMPILED_PATTERNS:
                matches = _find_all_with_timeout(compiled, line, executor)
                if matches is None:
                    # Timed out — skip this pattern on this line.
                    continue
                for match in matches:
                    severity = (
                        _downgrade_severity(base_severity, Severity.MEDIUM)
                        if is_non_agent_markdown
                        else base_severity
                    )
                    findings.append(
                        PatternFinding(
                            category=category,
                            severity=severity,
                            line=actual_line,
                            column=match.start() + 1,
                            matched_text=_truncate(match.group(0)),
                            pattern_id=pattern_id,
                            description=_CATEGORY_DESCRIPTIONS[category],
                        )
                    )

    return findings
