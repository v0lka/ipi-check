"""Byte-Level Analysis — Layer 2: detect hidden content at byte level."""
from __future__ import annotations

import re

import regex

from ipi_check.core.types import (
    ByteFinding,
    ByteFindingCategory,
    DiscoveredFile,
    Severity,
)

# Byte-level signatures as compiled regex patterns on bytes.
# key: (compiled_pattern, category, severity)
BYTE_SIGNATURES: dict[str, tuple[re.Pattern[bytes], ByteFindingCategory, Severity]] = {
    "ansi_escape": (
        re.compile(rb"\x1b\[\d*(?:;\d+)*m"),
        ByteFindingCategory.ANSI_HIDDEN,
        Severity.CRITICAL,
    ),
    "ansi_erase": (
        re.compile(rb"\x1b\[2K"),
        ByteFindingCategory.ANSI_HIDDEN,
        Severity.CRITICAL,
    ),
    "ansi_hide": (
        re.compile(rb"\x1b\[8m"),
        ByteFindingCategory.ANSI_HIDDEN,
        Severity.CRITICAL,
    ),
    "unicode_tags": (
        re.compile(rb"[\xf3][\xa0][\x80-\x81][\x80-\xbf]"),
        ByteFindingCategory.UNICODE_TAGS,
        Severity.CRITICAL,
    ),
    # VS1–VS15 (U+FE00–U+FE0E) have no legitimate emoji-presentation role and
    # are a known invisible encoding channel. The emoji presentation selector
    # (VS16, U+FE0F) is handled separately — it is legitimate after an emoji
    # base, see ``_scan_variation_selector_16``.
    "variation_selectors": (
        re.compile(rb"\xef\xb8[\x80-\x8e]"),
        ByteFindingCategory.VARIATION_SELECTORS,
        Severity.HIGH,
    ),
    "bidi_override": (
        re.compile(rb"\xe2\x80[\xaa-\xae]"),
        ByteFindingCategory.BIDI_OVERRIDE,
        Severity.HIGH,
    ),
    "bidi_isolate": (
        re.compile(rb"\xe2\x81[\xa6-\xa9]"),
        ByteFindingCategory.BIDI_OVERRIDE,
        Severity.HIGH,
    ),
    "zero_width": (
        re.compile(rb"\xe2\x80[\x8b-\x8f]"),
        ByteFindingCategory.ZERO_WIDTH,
        Severity.MEDIUM,
    ),
    "line_separator": (
        re.compile(rb"\xe2\x80[\xa8-\xa9]"),
        ByteFindingCategory.ZERO_WIDTH,
        Severity.MEDIUM,
    ),
}

# Emoji presentation selector (VS16, U+FE0F); raw UTF-8 bytes are EF B8 8F.
# VS16 differs from VS1–VS15: it legitimately follows an emoji base character
# (e.g. ``⚠`` U+26A0 + U+FE0F), so it is not part of BYTE_SIGNATURES and is
# analysed with the base/density heuristics in ``_scan_variation_selector_16``.
VS16_CHAR: str = "\ufe0f"

# A preceding character counts as an "emoji base" when it carries the Unicode
# Emoji property — the set of characters a presentation selector may modify
# (symbols, keycap bases such as ``#``, ``*`` and digits, emoji blocks).
EMOJI_BASE_PATTERN: regex.Pattern[str] = regex.compile(r"\p{Emoji}")

# U+FE0F occurrences that *do* follow an emoji base are still reported when the
# file is saturated with them — a signal of a steganographic variation-selector
# channel (e.g. "Glassworm") rather than ordinary emoji usage. Density is the
# U+FE0F count over the decoded character count; it is only considered
# "anomalous" once at least :data:`VS16_MIN_COUNT_FOR_DENSITY` selectors are
# present, so a handful of emoji in a short document is never flagged.
VS16_DENSITY_THRESHOLD: float = 0.10
VS16_MIN_COUNT_FOR_DENSITY: int = 10

# Homoglyph mapping: Cyrillic lookalikes → Latin equivalents.
HOMOGLYPH_MAP: dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "А": "A", "В": "B", "Е": "E",
    "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X",
}

# Homoglyph detection works at word-token granularity. A *mixed-script token*
# is a maximal ``\w+`` run (``\w`` is Unicode-aware) that contains both Latin
# and Cyrillic letters — the exact shape of a homoglyph attack (e.g. ``pаypal``
# with a Cyrillic ``а``). A legitimate multilingual document only mixes scripts
# *between* tokens, never within one.
WORD_TOKEN_PATTERN: re.Pattern[str] = re.compile(r"\w+")

# Cyrillic letters (U+0400–U+04FF).
CYRILLIC_LETTER_PATTERN: re.Pattern[str] = re.compile(r"[\u0400-\u04FF]")

# Cyrillic characters that are visually confusable with a Latin counterpart.
CONFUSABLE_HOMOGLYPH_CHARS: frozenset[str] = frozenset(HOMOGLYPH_MAP)

# A single file emits at most this many homoglyph (IPI006) findings, regardless
# of how many mixed-script tokens it contains — prevents per-character floods.
MAX_HOMOGLYPH_FINDINGS_PER_FILE: int = 1

# Maximum number of bytes captured for a finding's hex snippet.
MAX_HEX_SNIPPET_BYTES: int = 32

# Private Use Area (PUA) range scanned on decoded text.
PUA_PATTERN: re.Pattern[str] = re.compile(r"[\uE000-\uF8FF]")

# Decoding strategy for text-based scans.
_TEXT_DECODE_ENCODING: str = "utf-8"
_TEXT_DECODE_ERRORS: str = "replace"

# Latin-letter detector for homoglyph density calculation.
_LATIN_LETTER_PATTERN: re.Pattern[str] = re.compile(r"[A-Za-z]")

# Per-category description strings for findings.
_DESCRIPTIONS: dict[ByteFindingCategory, str] = {
    ByteFindingCategory.ANSI_HIDDEN: (
        "ANSI escape sequence detected — may hide content from human reviewers"
    ),
    ByteFindingCategory.UNICODE_TAGS: (
        "Unicode tag characters (U+E0000 block) detected — invisible metadata channel"
    ),
    ByteFindingCategory.VARIATION_SELECTORS: (
        "Variation selector detected — potential encoding channel"
    ),
    ByteFindingCategory.BIDI_OVERRIDE: (
        "Bidirectional text override detected — may reorder visible text"
    ),
    ByteFindingCategory.ZERO_WIDTH: (
        "Zero-width character detected — may carry steganographic data"
    ),
    ByteFindingCategory.PUA: (
        "Private Use Area character detected — non-standard encoding"
    ),
    ByteFindingCategory.HOMOGLYPH: (
        "Cyrillic homoglyph detected — character visually resembles Latin equivalent"
    ),
}


def _resolve_position(raw_bytes: bytes, offset: int) -> tuple[int, int]:
    """Resolve byte offset to 1-based line and column."""
    line = raw_bytes[:offset].count(b"\n") + 1
    last_newline = raw_bytes[:offset].rfind(b"\n")
    column = offset - last_newline if last_newline >= 0 else offset + 1
    return line, column


def _hex_snippet(raw_bytes: bytes, start: int) -> str:
    """Return a bounded hex snippet beginning at ``start``."""
    return raw_bytes[start:start + MAX_HEX_SNIPPET_BYTES].hex()


def _scan_byte_signatures(raw_bytes: bytes) -> list[ByteFinding]:
    """Scan raw bytes for every signature in BYTE_SIGNATURES."""
    findings: list[ByteFinding] = []
    for pattern, category, severity in BYTE_SIGNATURES.values():
        for match in pattern.finditer(raw_bytes):
            line, column = _resolve_position(raw_bytes, match.start())
            findings.append(
                ByteFinding(
                    category=category,
                    severity=severity,
                    line=line,
                    column=column,
                    snippet_hex=_hex_snippet(raw_bytes, match.start()),
                    description=_DESCRIPTIONS[category],
                )
            )
    return findings


def _scan_variation_selector_16(raw_bytes: bytes) -> list[ByteFinding]:
    """Detect suspicious emoji presentation selectors (U+FE0F).

    A U+FE0F that directly follows an emoji base (e.g. ``⚠`` U+26A0 + U+FE0F)
    is legitimate emoji presentation and is not reported. It is reported when
    it has no preceding emoji base, or when the file's overall U+FE0F density
    exceeds :data:`VS16_DENSITY_THRESHOLD` — a variation-selector encoding
    channel rather than ordinary emoji usage.
    """
    findings: list[ByteFinding] = []
    text = raw_bytes.decode(_TEXT_DECODE_ENCODING, errors=_TEXT_DECODE_ERRORS)
    vs16_indices = [i for i, ch in enumerate(text) if ch == VS16_CHAR]
    if not vs16_indices:
        return findings

    anomalous_density = (
        len(vs16_indices) >= VS16_MIN_COUNT_FOR_DENSITY
        and len(vs16_indices) / max(len(text), 1) > VS16_DENSITY_THRESHOLD
    )

    for char_index in vs16_indices:
        has_emoji_base = char_index > 0 and bool(
            EMOJI_BASE_PATTERN.match(text[char_index - 1])
        )
        if has_emoji_base and not anomalous_density:
            continue
        byte_offset = len(
            text[:char_index].encode(_TEXT_DECODE_ENCODING, errors=_TEXT_DECODE_ERRORS)
        )
        line, column = _resolve_position(raw_bytes, byte_offset)
        findings.append(
            ByteFinding(
                category=ByteFindingCategory.VARIATION_SELECTORS,
                severity=Severity.HIGH,
                line=line,
                column=column,
                snippet_hex=_hex_snippet(raw_bytes, byte_offset),
                description=_DESCRIPTIONS[ByteFindingCategory.VARIATION_SELECTORS],
            )
        )
    return findings


def _dedupe_findings(findings: list[ByteFinding]) -> list[ByteFinding]:
    """Collapse byte findings identical in category, severity, position and snippet.

    Duplicates are dropped while the first occurrence and the original ordering
    are preserved, so the per-file finding set stays deterministic.
    """
    seen: set[tuple[ByteFindingCategory, Severity, int, int, str]] = set()
    unique: list[ByteFinding] = []
    for finding in findings:
        key = (
            finding.category,
            finding.severity,
            finding.line,
            finding.column,
            finding.snippet_hex,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _scan_pua(raw_bytes: bytes) -> list[ByteFinding]:
    """Scan decoded text for Private Use Area characters."""
    findings: list[ByteFinding] = []
    text = raw_bytes.decode(_TEXT_DECODE_ENCODING, errors=_TEXT_DECODE_ERRORS)
    if not text:
        return findings

    for match in PUA_PATTERN.finditer(text):
        char_index = match.start()
        # Map character index to byte offset by encoding the prefix.
        byte_offset = len(
            text[:char_index].encode(_TEXT_DECODE_ENCODING, errors=_TEXT_DECODE_ERRORS)
        )
        line, column = _resolve_position(raw_bytes, byte_offset)
        findings.append(
            ByteFinding(
                category=ByteFindingCategory.PUA,
                severity=Severity.MEDIUM,
                line=line,
                column=column,
                snippet_hex=_hex_snippet(raw_bytes, byte_offset),
                description=_DESCRIPTIONS[ByteFindingCategory.PUA],
            )
        )
    return findings


def _mixes_scripts(token: str) -> bool:
    """Return ``True`` when ``token`` contains both Latin and Cyrillic letters."""
    has_latin = False
    has_cyrillic = False
    for ch in token:
        if _LATIN_LETTER_PATTERN.match(ch):
            has_latin = True
        elif CYRILLIC_LETTER_PATTERN.match(ch):
            has_cyrillic = True
        if has_latin and has_cyrillic:
            return True
    return False


def _has_confusable_homoglyph(token: str) -> bool:
    """Return ``True`` when ``token`` contains a Cyrillic Latin-lookalike."""
    return any(ch in CONFUSABLE_HOMOGLYPH_CHARS for ch in token)


def _scan_homoglyphs(raw_bytes: bytes) -> list[ByteFinding]:
    """Detect Cyrillic homoglyphs spliced into otherwise-Latin tokens.

    Detection operates at *token* granularity rather than on a whole-file
    Cyrillic ratio. A legitimate multilingual document (e.g. a Russian README)
    places Latin and Cyrillic words side by side, but never inside the same
    token. A homoglyph attack instead replaces a Latin letter with a lookalike
    Cyrillic one *within a single identifier* (``pаypal`` with Cyrillic ``а``).

    The proportion of mixed-script tokens among all word tokens is the
    *suspicious mix ratio*. Findings are capped at
    :data:`MAX_HOMOGLYPH_FINDINGS_PER_FILE` per file, and severity is downgraded
    to :attr:`Severity.LOW` when a mix contains no confusable homoglyph (script
    mixing without a Latin lookalike). Files with no mixed-script token are not
    flagged at all.
    """
    text = raw_bytes.decode(_TEXT_DECODE_ENCODING, errors=_TEXT_DECODE_ERRORS)
    if not text:
        return []

    tokens = list(WORD_TOKEN_PATTERN.finditer(text))
    mixed = [match for match in tokens if _mixes_scripts(match.group())]
    if not mixed:
        return []

    confusable = [match for match in mixed if _has_confusable_homoglyph(match.group())]
    suspicious_mix_ratio = len(confusable) / len(tokens) if tokens else 0.0

    # Report the strongest token (a confusable homoglyph if present, else any
    # script-mixing token). Severity: MEDIUM with a confusable homoglyph, LOW
    # when scripts merely mix without a Latin-lookalike.
    reported = confusable[0] if confusable else mixed[0]
    severity = Severity.MEDIUM if confusable else Severity.LOW

    byte_offset = len(
        text[:reported.start()].encode(_TEXT_DECODE_ENCODING, errors=_TEXT_DECODE_ERRORS)
    )
    line, column = _resolve_position(raw_bytes, byte_offset)
    description = (
        f"{_DESCRIPTIONS[ByteFindingCategory.HOMOGLYPH]}"
        f" (mixed-script token, suspicious mix ratio {suspicious_mix_ratio:.2f})"
    )
    findings = [
        ByteFinding(
            category=ByteFindingCategory.HOMOGLYPH,
            severity=severity,
            line=line,
            column=column,
            snippet_hex=_hex_snippet(raw_bytes, byte_offset),
            description=description,
        )
    ]
    return findings[:MAX_HOMOGLYPH_FINDINGS_PER_FILE]


def analyze_bytes(file: DiscoveredFile, raw_bytes: bytes) -> list[ByteFinding]:
    """Run all byte-level checks on ``raw_bytes`` and return aggregated findings.

    The ``file`` argument is accepted for interface symmetry with other scanner
    layers; byte-level analysis itself depends only on the raw byte contents.
    """
    del file  # interface symmetry — byte analysis depends only on raw bytes

    if not raw_bytes:
        return []

    findings: list[ByteFinding] = []
    findings.extend(_scan_byte_signatures(raw_bytes))
    findings.extend(_scan_variation_selector_16(raw_bytes))
    findings.extend(_scan_pua(raw_bytes))
    findings.extend(_scan_homoglyphs(raw_bytes))
    return _dedupe_findings(findings)
