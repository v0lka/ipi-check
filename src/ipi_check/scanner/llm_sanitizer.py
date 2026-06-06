"""Pre-LLM Sanitization — neutralize invisible characters before LLM input."""
from __future__ import annotations

import base64
import binascii
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ipi_check.core.types import ByteFinding

# ---------------------------------------------------------------------------
# Truncation budget
# ---------------------------------------------------------------------------

#: Maximum number of tokens we are willing to forward to the LLM.
LLM_MAX_TOKENS: int = 2000

#: Approximate character-to-token ratio used for sizing the request.
CHARS_PER_TOKEN: int = 4

#: Maximum characters to send to the LLM (LLM_MAX_TOKENS * CHARS_PER_TOKEN).
LLM_MAX_CHARS: int = LLM_MAX_TOKENS * CHARS_PER_TOKEN  # 8000

#: Marker appended when the sanitized content has been truncated.
CONTENT_TRUNCATED_MARKER: str = "\n[CONTENT_TRUNCATED]"

# ---------------------------------------------------------------------------
# Decoding configuration
# ---------------------------------------------------------------------------

_TEXT_DECODE_ENCODING: str = "utf-8"
_TEXT_DECODE_ERRORS: str = "replace"

# ---------------------------------------------------------------------------
# Patterns for invisible / suspicious content
# ---------------------------------------------------------------------------

#: Unicode tag block (U+E0000-U+E007F) — invisible metadata channel.
_UNICODE_TAGS_PATTERN: re.Pattern[str] = re.compile(r"[\U000e0000-\U000e007f]")

#: Zero-width / formatting block (U+200B-U+200F).
_ZERO_WIDTH_PATTERN: re.Pattern[str] = re.compile(r"[\u200b-\u200f]")

#: Line/paragraph separator (U+2028-U+2029).
_LINE_SEPARATOR_PATTERN: re.Pattern[str] = re.compile(r"[\u2028\u2029]")

#: Bidi override block (U+202A-U+202E).
_BIDI_OVERRIDE_PATTERN: re.Pattern[str] = re.compile(r"[\u202a-\u202e]")

#: Variation selector block (U+FE00-U+FE0F).
_VARIATION_SELECTOR_PATTERN: re.Pattern[str] = re.compile(r"[\ufe00-\ufe0f]")

#: ANSI escape sequence: ``ESC [ ... <final-letter>``.
_ANSI_ESCAPE_PATTERN: re.Pattern[str] = re.compile(r"\x1b\[[^A-Za-z]*[A-Za-z]")

#: Base64 detection — block of ≥40 valid base64 characters.
BASE64_PATTERN: re.Pattern[str] = re.compile(r"[A-Za-z0-9+/=]{40,}")

#: Minimum length for base64 candidates (kept in sync with BASE64_PATTERN).
BASE64_MIN_LENGTH: int = 40

# ---------------------------------------------------------------------------
# Replacement placeholder templates
# ---------------------------------------------------------------------------

_INVISIBLE_PLACEHOLDER: str = "[INVISIBLE:U+{code:04X}]"
_BIDI_PLACEHOLDER: str = "[BIDI:U+{code:04X}]"
_VARIATION_SELECTOR_PLACEHOLDER: str = "[VS:U+{code:04X}]"
_ANSI_PLACEHOLDER: str = "[ANSI:ESC]"
_DECODED_B64_PLACEHOLDER: str = "[DECODED_B64: {decoded}]"


def _replace_with_codepoint(template: str, match: re.Match[str]) -> str:
    """Replace a single-character match with a placeholder containing its codepoint."""
    return template.format(code=ord(match.group(0)))


def _replace_invisible(match: re.Match[str]) -> str:
    return _replace_with_codepoint(_INVISIBLE_PLACEHOLDER, match)


def _replace_bidi(match: re.Match[str]) -> str:
    return _replace_with_codepoint(_BIDI_PLACEHOLDER, match)


def _replace_variation_selector(match: re.Match[str]) -> str:
    return _replace_with_codepoint(_VARIATION_SELECTOR_PLACEHOLDER, match)


def _replace_ansi(match: re.Match[str]) -> str:  # noqa: ARG001 — match unused
    return _ANSI_PLACEHOLDER


def _replace_base64(match: re.Match[str]) -> str:
    """Try to decode a base64 candidate; on success expose the decoded text."""
    candidate = match.group(0)
    try:
        decoded_bytes = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError):
        return candidate

    decoded_text = decoded_bytes.decode(
        _TEXT_DECODE_ENCODING, errors=_TEXT_DECODE_ERRORS
    )
    return _DECODED_B64_PLACEHOLDER.format(decoded=decoded_text)


def _truncate(text: str) -> str:
    """No-op: truncation has been removed (batch processing handles all content).

    Content truncation was a security vulnerability — an attacker could place
    a payload beyond the truncation boundary and evade LLM detection.
    The function is kept as a no-op for interface stability; callers that
    relied on truncation now receive the full content unchanged.
    """
    return text


def sanitize_content(raw_bytes: bytes, byte_findings: list[ByteFinding]) -> str:
    """Sanitize file content before sending to the LLM.

    Steps:
        1. Decode bytes to UTF-8 (``errors="replace"``).
        2. Replace invisible characters with visible placeholders:
            * Unicode tags  (U+E0000-U+E007F) → ``[INVISIBLE:U+E00XX]``
            * Zero-width    (U+200B-U+200F)   → ``[INVISIBLE:U+200X]``
            * Line/para sep (U+2028-U+2029)   → ``[INVISIBLE:U+202X]``
            * Bidi override (U+202A-U+202E)   → ``[BIDI:U+202X]``
            * Variation     (U+FE00-U+FE0F)   → ``[VS:U+FE0X]``
            * ANSI escapes                    → ``[ANSI:ESC]``
        3. Decode Base64 blocks (≥40 chars). Successful decodes become
           ``[DECODED_B64: ...]``; failed candidates are left untouched.

    The ``byte_findings`` argument is accepted for interface symmetry —
    sanitization rules are derived directly from the byte content.
    """
    del byte_findings  # interface symmetry — sanitization is content-driven

    text = raw_bytes.decode(_TEXT_DECODE_ENCODING, errors=_TEXT_DECODE_ERRORS)

    text = _UNICODE_TAGS_PATTERN.sub(_replace_invisible, text)
    text = _ZERO_WIDTH_PATTERN.sub(_replace_invisible, text)
    text = _LINE_SEPARATOR_PATTERN.sub(_replace_invisible, text)
    text = _BIDI_OVERRIDE_PATTERN.sub(_replace_bidi, text)
    text = _VARIATION_SELECTOR_PATTERN.sub(_replace_variation_selector, text)
    text = _ANSI_ESCAPE_PATTERN.sub(_replace_ansi, text)

    text = BASE64_PATTERN.sub(_replace_base64, text)

    return _truncate(text)
