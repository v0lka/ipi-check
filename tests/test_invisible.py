"""Tests for the shared invisible-character definition (``core/invisible.py``).

Covers every concealed-codepoint range at its boundaries, the combined
strip pattern, and the three consumers (pattern matching, visible-text
extraction, pre-LLM sanitization) that must all reuse this single source of
truth instead of carrying their own copy (roadmap item IN-24).
"""
from __future__ import annotations

import inspect

import pytest

from ipi_check.core import invisible
from ipi_check.core.invisible import (
    ANSI_ESCAPE_PATTERN,
    BIDI_ISOLATE_RANGE,
    BIDI_OVERRIDE_RANGE,
    BIDI_PATTERN,
    INVISIBLE_CHARS_RE,
    INVISIBLE_RANGES,
    LINE_SEPARATOR_PATTERN,
    LINE_SEPARATOR_RANGE,
    UNICODE_TAG_RANGE,
    UNICODE_TAGS_PATTERN,
    VARIATION_SELECTOR_PATTERN,
    VARIATION_SELECTOR_RANGE,
    ZERO_WIDTH_PATTERN,
    ZERO_WIDTH_RANGE,
    contains_invisible,
    strip_invisible,
)
from ipi_check.scanner import llm_sanitizer, pattern_matching, static_result
from ipi_check.scanner.llm_sanitizer import sanitize_content
from ipi_check.scanner.pattern_matching import normalize_str, normalize_text
from ipi_check.scanner.static_result import _get_visible_text


def _boundary_chars(pair: tuple[int, int]) -> list[str]:
    """Return the lo/mid/hi codepoints of a closed range as characters."""
    lo, hi = pair
    points = {lo, hi}
    if hi - lo > 1:
        points.add((lo + hi) // 2)
    return [chr(cp) for cp in sorted(points)]


# Representative character per range, used by the parametrized consumer tests.
_RANGE_CASES = [(pair, ch) for pair in INVISIBLE_RANGES for ch in _boundary_chars(pair)]
_RANGE_IDS = [
    f"U+{ord(ch):04X}" for _, ch in _RANGE_CASES
]


class TestRangeConstants:
    def test_exact_range_boundaries(self) -> None:
        assert UNICODE_TAG_RANGE == (0xE0000, 0xE007F)
        assert ZERO_WIDTH_RANGE == (0x200B, 0x200F)
        assert LINE_SEPARATOR_RANGE == (0x2028, 0x2029)
        assert BIDI_OVERRIDE_RANGE == (0x202A, 0x202E)
        assert BIDI_ISOLATE_RANGE == (0x2066, 0x2069)
        assert VARIATION_SELECTOR_RANGE == (0xFE00, 0xFE0F)

    def test_invisible_ranges_aggregate_is_complete(self) -> None:
        for pair in (
            UNICODE_TAG_RANGE,
            ZERO_WIDTH_RANGE,
            LINE_SEPARATOR_RANGE,
            BIDI_OVERRIDE_RANGE,
            BIDI_ISOLATE_RANGE,
            VARIATION_SELECTOR_RANGE,
        ):
            assert pair in INVISIBLE_RANGES

    def test_bidi_pattern_covers_overrides_and_isolates(self) -> None:
        assert BIDI_PATTERN.search("\u202e") is not None
        assert BIDI_PATTERN.search("\u2066") is not None


class TestStripInvisible:
    @pytest.mark.parametrize(("pair", "ch"), _RANGE_CASES, ids=_RANGE_IDS)
    def test_every_range_boundary_is_stripped(
        self, pair: tuple[int, int], ch: str
    ) -> None:
        assert contains_invisible(f"a{ch}b")
        assert strip_invisible(f"a{ch}b") == "ab"

    def test_ansi_escape_stripped(self) -> None:
        assert strip_invisible("x\x1b[8my") == "xy"
        assert contains_invisible("x\x1b[8my")

    def test_visible_text_is_preserved_verbatim(self) -> None:
        # NB: deliberately no variation selector (U+FE0F) here — that codepoint
        # is concealed by design (see VARIATION_SELECTOR_RANGE) and IS stripped.
        text = "Hello  World\n\tTabbed\r\nCyrillic: Привет — emoji: \u26a0"
        assert strip_invisible(text) == text
        assert not contains_invisible(text)

    def test_empty_and_plain(self) -> None:
        assert strip_invisible("") == ""
        assert not contains_invisible("")


class TestCombinedPatternDerivation:
    """The combined pattern is derived from the per-category patterns."""

    def test_combined_pattern_includes_each_category(self) -> None:
        for pattern in (
            ANSI_ESCAPE_PATTERN,
            UNICODE_TAGS_PATTERN,
            ZERO_WIDTH_PATTERN,
            LINE_SEPARATOR_PATTERN,
            BIDI_PATTERN,
            VARIATION_SELECTOR_PATTERN,
        ):
            assert pattern.pattern in INVISIBLE_CHARS_RE.pattern

    def test_matches_union_of_categories(self) -> None:
        for _, ch in _RANGE_CASES:
            assert INVISIBLE_CHARS_RE.search(ch) is not None
        assert INVISIBLE_CHARS_RE.search("\x1b[8m") is not None


class TestSingleSourceOfTruth:
    """The three consumers must reuse ``core.invisible`` — not redefine it."""

    def test_pattern_matching_reuses_core(self) -> None:
        assert not hasattr(pattern_matching, "_INVISIBLE_CHARS_RE")
        assert pattern_matching.strip_invisible is invisible.strip_invisible

    def test_static_result_reuses_core(self) -> None:
        assert not hasattr(static_result, "_INVISIBLE_CHARS_RE")
        assert static_result.strip_invisible is invisible.strip_invisible

    def test_llm_sanitizer_reuses_core_patterns(self) -> None:
        assert llm_sanitizer.UNICODE_TAGS_PATTERN is invisible.UNICODE_TAGS_PATTERN
        assert llm_sanitizer.ZERO_WIDTH_PATTERN is invisible.ZERO_WIDTH_PATTERN
        assert llm_sanitizer.LINE_SEPARATOR_PATTERN is invisible.LINE_SEPARATOR_PATTERN
        assert llm_sanitizer.BIDI_PATTERN is invisible.BIDI_PATTERN
        assert (
            llm_sanitizer.VARIATION_SELECTOR_PATTERN
            is invisible.VARIATION_SELECTOR_PATTERN
        )
        assert llm_sanitizer.ANSI_ESCAPE_PATTERN is invisible.ANSI_ESCAPE_PATTERN

    @pytest.mark.parametrize(
        "module",
        [pattern_matching, static_result, llm_sanitizer],
        ids=["pattern_matching", "static_result", "llm_sanitizer"],
    )
    def test_no_duplicated_regex_literal_in_source(self, module: object) -> None:
        source = inspect.getsource(module)
        assert "_INVISIBLE_CHARS_RE" not in source
        assert "_BIDI_OVERRIDE_PATTERN" not in source


class TestConsumersStripAllRanges:
    """Every consumer must strip/sanitize every range from the shared source."""

    @pytest.mark.parametrize(("pair", "ch"), _RANGE_CASES, ids=_RANGE_IDS)
    def test_normalize_text_strips_range(self, pair: tuple[int, int], ch: str) -> None:
        assert ch not in normalize_text(f"HELLO{ch}WORLD".encode())

    @pytest.mark.parametrize(("pair", "ch"), _RANGE_CASES, ids=_RANGE_IDS)
    def test_normalize_str_strips_range(self, pair: tuple[int, int], ch: str) -> None:
        assert normalize_str(f"HELLO{ch}WORLD") == "helloworld"

    @pytest.mark.parametrize(("pair", "ch"), _RANGE_CASES, ids=_RANGE_IDS)
    def test_visible_text_extraction_strips_range(
        self, pair: tuple[int, int], ch: str
    ) -> None:
        assert _get_visible_text(f"A{ch}B".encode()) == "AB"


class TestSanitizerReplacesAllRanges:
    @pytest.mark.parametrize(("pair", "ch"), _RANGE_CASES, ids=_RANGE_IDS)
    def test_sanitize_removes_raw_codepoint(
        self, pair: tuple[int, int], ch: str
    ) -> None:
        out = sanitize_content(f"a{ch}b".encode(), [])
        assert ch not in out
        assert "a" in out and "b" in out

    def test_placeholder_by_category(self) -> None:
        # tags / zero-width / line-separator → [INVISIBLE:...]
        assert "[INVISIBLE:U+E0041]" in sanitize_content("a\U000e0041b".encode(), [])
        assert "[INVISIBLE:U+200B]" in sanitize_content("a\u200bb".encode(), [])
        assert "[INVISIBLE:U+2028]" in sanitize_content("a\u2028b".encode(), [])
        # bidi controls → [BIDI:...]
        assert "[BIDI:U+202E]" in sanitize_content("a\u202eb".encode(), [])
        # variation selectors → [VS:...]
        assert "[VS:U+FE0F]" in sanitize_content("a\ufe0fb".encode(), [])
        # ANSI escapes → [ANSI:ESC]
        assert "[ANSI:ESC]" in sanitize_content(b"a\x1b[8mb", [])

    def test_bidi_isolates_are_sanitized(self) -> None:
        """Regression guard for the drift IN-24 fixed.

        The former sanitizer-local bidi pattern covered only overrides
        (U+202A-U+202E); isolates (U+2066-U+2069) slipped through. The shared
        pattern now covers both.
        """
        for cp in range(BIDI_ISOLATE_RANGE[0], BIDI_ISOLATE_RANGE[1] + 1):
            ch = chr(cp)
            out = sanitize_content(f"a{ch}b".encode(), [])
            assert ch not in out
            assert f"[BIDI:U+{cp:04X}]" in out
