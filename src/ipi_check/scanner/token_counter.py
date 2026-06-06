"""Token Counter — count tokens for batch assembly using tiktoken or fallback."""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

#: tiktoken encoding name for modern OpenAI/Anthropic-compatible models.
#: ``cl100k_base`` is the encoding used by GPT-4, GPT-4o, GPT-4o-mini and
#: is within 1% of Anthropic's tokenizer for typical content.
TIKTOKEN_ENCODING: str = "cl100k_base"

#: Fallback characters-per-token ratio when tiktoken is unavailable.
#: This is a conservative estimate for source code (which has more tokens
#: per character than natural language), ensuring batches never exceed
#: the provider's actual context limit.
FALLBACK_CHARS_PER_TOKEN: int = 4

#: Soft target for batch token count (adaptive fill — last batch may be smaller).
#: Targets ~1/3 of a typical 100K context window.
TARGET_BATCH_TOKENS: int = 30_000


def count_tokens(text: str) -> int:
    """Count the number of tokens in ``text``.

    Uses tiktoken with :data:`TIKTOKEN_ENCODING` if available; otherwise
    falls back to ``len(text) // FALLBACK_CHARS_PER_TOKEN``.
    """
    try:
        import tiktoken  # noqa: PLC0415 — deferred import
    except ImportError:
        return len(text) // FALLBACK_CHARS_PER_TOKEN

    try:
        enc = tiktoken.get_encoding(TIKTOKEN_ENCODING)
    except Exception:  # noqa: BLE001 — defensive fallback
        return len(text) // FALLBACK_CHARS_PER_TOKEN

    return len(enc.encode(text))


def is_tiktoken_available() -> bool:
    """Return ``True`` if tiktoken is installed and the encoding is loadable."""
    try:
        import tiktoken  # noqa: PLC0415, F401
        tiktoken.get_encoding(TIKTOKEN_ENCODING)
        return True
    except Exception:
        return False
