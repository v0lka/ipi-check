"""Tests for llm_sanitizer module."""
from __future__ import annotations

import base64

from ipi_check.scanner.llm_sanitizer import (
    CONTENT_TRUNCATED_MARKER,
    sanitize_content,
)


class TestSanitizeContent:
    def test_ansi_escape_replaced(self) -> None:
        out = sanitize_content(b"hi\x1b[8mhidden\x1b[0m", [])
        assert "[ANSI:ESC]" in out
        assert "\x1b" not in out

    def test_zero_width_replaced(self) -> None:
        # U+200B
        text = "hello\u200bworld".encode("utf-8")
        out = sanitize_content(text, [])
        assert "[INVISIBLE:U+200B]" in out

    def test_line_separator_replaced(self) -> None:
        """U+2028 and U+2029 line/paragraph separators are sanitized."""
        raw = "hello\u2028world\u2029end".encode("utf-8")
        result = sanitize_content(raw, [])
        assert "[INVISIBLE:U+2028]" in result
        assert "[INVISIBLE:U+2029]" in result
        assert "\u2028" not in result
        assert "\u2029" not in result

    def test_unicode_tag_replaced(self) -> None:
        # U+E0041 → tag Latin small letter A
        text = ("hi" + "\U000e0041" + "x").encode("utf-8")
        out = sanitize_content(text, [])
        assert "[INVISIBLE:U+E0041]" in out

    def test_bidi_override_replaced(self) -> None:
        text = ("a" + "\u202e" + "b").encode("utf-8")
        out = sanitize_content(text, [])
        assert "[BIDI:U+202E]" in out

    def test_variation_selector_replaced(self) -> None:
        text = ("a" + "\ufe0f" + "b").encode("utf-8")
        out = sanitize_content(text, [])
        assert "[VS:U+FE0F]" in out

    def test_base64_block_decoded(self) -> None:
        plaintext = "Decoded message that is long enough"
        b64 = base64.b64encode(plaintext.encode("utf-8")).decode("ascii")
        # Ensure ≥40 chars to match BASE64_PATTERN.
        assert len(b64) >= 40
        text = f"prefix {b64} suffix".encode()
        out = sanitize_content(text, [])
        assert "[DECODED_B64:" in out
        assert plaintext in out

    def test_invalid_base64_left_alone(self) -> None:
        # 41 valid b64-alphabet chars but length is not a multiple of 4 and
        # padding is absent → b64decode(validate=True) raises.
        candidate = "A" * 41
        text = f"x {candidate} y".encode()
        out = sanitize_content(text, [])
        assert "[DECODED_B64:" not in out
        assert candidate in out

    def test_content_passes_unchanged(self) -> None:
        text = b"# Heading\n\nSome description text here.\n"
        out = sanitize_content(text, [])
        assert out == text.decode("utf-8")

    def test_no_truncation_large_content(self) -> None:
        """Content larger than the old LLM_MAX_CHARS limit is NOT truncated."""
        # Build content significantly larger than the old 8000-char limit.
        text = ("A" * 79 + "\n") * 200
        raw = text.encode("utf-8")
        out = sanitize_content(raw, [])
        assert len(out) == len(text)
        assert CONTENT_TRUNCATED_MARKER not in out
