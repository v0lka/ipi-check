"""Single source of truth for invisible / concealed character ranges and regexes.

Several scanner layers must recognise the *same* set of invisible Unicode
content — the pattern-matching normalizer strips it, the visible-text extractor
strips it, and the pre-LLM sanitizer replaces it with visible placeholders.
Historically each layer carried its own copy of the ranges/regexes, which
drifted apart (see roadmap item ``IN-24``: "Дублирование ``_INVISIBLE_CHARS_RE``
в 3 модулях — drift-риск").

This module is the *only* place where those ranges and the derived compiled
patterns are declared. Consumers import the pattern they need:

* :data:`INVISIBLE_CHARS_RE` / :func:`strip_invisible` — the combined "remove
  every concealed character" pattern, used by ``pattern_matching`` and
  ``static_result``.
* the per-category patterns (:data:`UNICODE_TAGS_PATTERN`,
  :data:`ZERO_WIDTH_PATTERN`, :data:`LINE_SEPARATOR_PATTERN`,
  :data:`BIDI_PATTERN`, :data:`VARIATION_SELECTOR_PATTERN`,
  :data:`ANSI_ESCAPE_PATTERN`) — used by ``llm_sanitizer`` so that each
  category can be replaced with a distinct placeholder.

Deliberate exclusions
---------------------

This module covers the *concealed-text* channel (the characters the scanner
strips before analysis or LLM dispatch). It intentionally does **not** include:

* the Private Use Area (``U+E000-U+F8FF``) — reported, not stripped, by
  ``byte_analysis``;
* the byte-order mark (``U+FEFF``) — a distinct output-injection signal handled
  in ``llm_classifier``;
* Cyrillic homoglyphs — detected behaviourally in ``byte_analysis``.

Those are separate detection concerns, not part of the shared strip/sanitize
range set.
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Codepoint ranges (closed ``(lo, hi)`` pairs) — the source of truth
# ---------------------------------------------------------------------------

#: Unicode tag block (``U+E0000-U+E007F``) — invisible metadata channel.
UNICODE_TAG_RANGE: tuple[int, int] = (0xE0000, 0xE007F)

#: Zero-width / formatting block (``U+200B-U+200F``) — ZWSP, joiners, LRM/RLM.
ZERO_WIDTH_RANGE: tuple[int, int] = (0x200B, 0x200F)

#: Line / paragraph separators (``U+2028-U+2029``).
LINE_SEPARATOR_RANGE: tuple[int, int] = (0x2028, 0x2029)

#: Bidi override / embedding controls (``U+202A-U+202E``).
BIDI_OVERRIDE_RANGE: tuple[int, int] = (0x202A, 0x202E)

#: Bidi isolate controls (``U+2066-U+2069``).
BIDI_ISOLATE_RANGE: tuple[int, int] = (0x2066, 0x2069)

#: Variation selectors (``U+FE00-U+FE0F``) — emoji-presentation / encoding channel.
VARIATION_SELECTOR_RANGE: tuple[int, int] = (0xFE00, 0xFE0F)

#: Every concealed-character range, in a stable, documented order.
INVISIBLE_RANGES: tuple[tuple[int, int], ...] = (
    UNICODE_TAG_RANGE,
    ZERO_WIDTH_RANGE,
    LINE_SEPARATOR_RANGE,
    BIDI_OVERRIDE_RANGE,
    BIDI_ISOLATE_RANGE,
    VARIATION_SELECTOR_RANGE,
)


def _escape_codepoint(codepoint: int) -> str:
    """Render ``codepoint`` as a ``\\uXXXX`` / ``\\UXXXXXXXX`` regex escape."""
    if codepoint <= 0xFFFF:
        return f"\\u{codepoint:04X}"
    return f"\\U{codepoint:08X}"


def _char_class(*ranges: tuple[int, int]) -> str:
    """Build a regex character class covering the given closed ranges."""
    parts: list[str] = []
    for lo, hi in ranges:
        if lo == hi:
            parts.append(_escape_codepoint(lo))
        else:
            parts.append(f"{_escape_codepoint(lo)}-{_escape_codepoint(hi)}")
    return "[" + "".join(parts) + "]"


# ---------------------------------------------------------------------------
# Per-category compiled patterns (derived from the ranges above)
# ---------------------------------------------------------------------------

#: ANSI escape sequence: ``ESC [ ... <final letter>``.
ANSI_ESCAPE_PATTERN: re.Pattern[str] = re.compile(r"\x1b\[[^A-Za-z]*[A-Za-z]")

#: Unicode tag block — invisible metadata channel.
UNICODE_TAGS_PATTERN: re.Pattern[str] = re.compile(_char_class(UNICODE_TAG_RANGE))

#: Zero-width / formatting block.
ZERO_WIDTH_PATTERN: re.Pattern[str] = re.compile(_char_class(ZERO_WIDTH_RANGE))

#: Line / paragraph separators.
LINE_SEPARATOR_PATTERN: re.Pattern[str] = re.compile(_char_class(LINE_SEPARATOR_RANGE))

#: Bidi override *and* isolate controls — a single category for sanitization.
BIDI_PATTERN: re.Pattern[str] = re.compile(
    _char_class(BIDI_OVERRIDE_RANGE, BIDI_ISOLATE_RANGE)
)

#: Variation selectors.
VARIATION_SELECTOR_PATTERN: re.Pattern[str] = re.compile(
    _char_class(VARIATION_SELECTOR_RANGE)
)

#: The concealed patterns that participate in the combined strip regex, in a
#: stable order (ANSI first, then the Unicode ranges).
_INVISIBLE_PATTERNS: tuple[re.Pattern[str], ...] = (
    ANSI_ESCAPE_PATTERN,
    UNICODE_TAGS_PATTERN,
    ZERO_WIDTH_PATTERN,
    LINE_SEPARATOR_PATTERN,
    BIDI_PATTERN,
    VARIATION_SELECTOR_PATTERN,
)

#: Combined "remove every concealed character" pattern. Layers that only need
#: to *strip* invisible content (pattern-matching normalization, visible-text
#: extraction) use this instead of maintaining their own copy.
INVISIBLE_CHARS_RE: re.Pattern[str] = re.compile(
    "|".join("(?:" + pattern.pattern + ")" for pattern in _INVISIBLE_PATTERNS)
)


def strip_invisible(text: str) -> str:
    """Return ``text`` with every concealed character removed.

    Casing, whitespace and paragraph structure are preserved — callers that
    need lowercasing/whitespace collapsing (pattern matching) do so afterwards;
    callers that need the original casing (semantic heuristics) use the result
    unchanged.
    """
    return INVISIBLE_CHARS_RE.sub("", text)


def contains_invisible(text: str) -> bool:
    """Return ``True`` when ``text`` contains any concealed character."""
    return INVISIBLE_CHARS_RE.search(text) is not None
