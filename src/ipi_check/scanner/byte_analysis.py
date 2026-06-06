"""Byte-Level Analysis — Layer 2: detect hidden content at byte level."""
from __future__ import annotations

import re

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
    "variation_selectors": (
        re.compile(rb"\xef\xb8[\x80-\xaf]"),
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

# Homoglyph mapping: Cyrillic lookalikes → Latin equivalents.
HOMOGLYPH_MAP: dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "А": "A", "В": "B", "Е": "E",
    "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X",
}

# Threshold for homoglyph density: cyrillic-homoglyphs / (latin + cyrillic-homoglyphs).
HOMOGLYPH_RATIO_THRESHOLD: float = 0.05

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


def _scan_homoglyphs(raw_bytes: bytes) -> list[ByteFinding]:
    """Detect Cyrillic homoglyphs when their density exceeds the threshold."""
    findings: list[ByteFinding] = []
    text = raw_bytes.decode(_TEXT_DECODE_ENCODING, errors=_TEXT_DECODE_ERRORS)
    if not text:
        return findings

    homoglyph_chars = set(HOMOGLYPH_MAP.keys())
    latin_count = sum(1 for ch in text if _LATIN_LETTER_PATTERN.match(ch))
    cyrillic_homoglyph_count = sum(1 for ch in text if ch in homoglyph_chars)
    total = latin_count + cyrillic_homoglyph_count

    if total == 0:
        return findings
    if cyrillic_homoglyph_count / total <= HOMOGLYPH_RATIO_THRESHOLD:
        return findings

    for char_index, ch in enumerate(text):
        if ch not in homoglyph_chars:
            continue
        byte_offset = len(
            text[:char_index].encode(_TEXT_DECODE_ENCODING, errors=_TEXT_DECODE_ERRORS)
        )
        line, column = _resolve_position(raw_bytes, byte_offset)
        findings.append(
            ByteFinding(
                category=ByteFindingCategory.HOMOGLYPH,
                severity=Severity.MEDIUM,
                line=line,
                column=column,
                snippet_hex=_hex_snippet(raw_bytes, byte_offset),
                description=_DESCRIPTIONS[ByteFindingCategory.HOMOGLYPH],
            )
        )
    return findings


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
    findings.extend(_scan_pua(raw_bytes))
    findings.extend(_scan_homoglyphs(raw_bytes))
    return findings
