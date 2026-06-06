"""Tests for token_counter module."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

from ipi_check.scanner.token_counter import (
    TARGET_BATCH_TOKENS,
    count_tokens,
    is_tiktoken_available,
)


class TestCountTokens:
    def test_count_tokens_fallback(self) -> None:
        """When tiktoken is not importable, fall back to chars/4."""
        with patch.dict(sys.modules, {"tiktoken": None}):
            result = count_tokens("hello world")
        assert result == 11 // 4  # 2

    def test_count_tokens_empty_string(self) -> None:
        """Empty string produces 0 tokens."""
        with patch.dict(sys.modules, {"tiktoken": None}):
            result = count_tokens("")
        assert result == 0

    def test_count_tokens_with_tiktoken(self) -> None:
        """When tiktoken is available, it's used for accurate counting."""
        fake_tiktoken = MagicMock()
        fake_enc = MagicMock()
        fake_enc.encode.return_value = ["hello", " world"]
        fake_tiktoken.get_encoding.return_value = fake_enc

        with patch.dict(sys.modules, {"tiktoken": fake_tiktoken}):
            result = count_tokens("hello world")
        assert result == 2
        fake_tiktoken.get_encoding.assert_called_once()

    def test_count_tokens_tiktoken_encoding_fails(self) -> None:
        """When get_encoding raises, fall back to chars/4."""
        fake_tiktoken = MagicMock()
        fake_tiktoken.get_encoding.side_effect = ValueError("bad encoding")

        with patch.dict(sys.modules, {"tiktoken": fake_tiktoken}):
            result = count_tokens("hello")
        assert result == 5 // 4  # 1


class TestIsTiktokenAvailable:
    def test_available(self) -> None:
        fake_tiktoken = MagicMock()
        fake_tiktoken.get_encoding.return_value = MagicMock()
        with patch.dict(sys.modules, {"tiktoken": fake_tiktoken}):
            assert is_tiktoken_available() is True

    def test_not_available_import_fails(self) -> None:
        with patch.dict(sys.modules, {"tiktoken": None}):
            assert is_tiktoken_available() is False

    def test_not_available_encoding_fails(self) -> None:
        fake_tiktoken = MagicMock()
        fake_tiktoken.get_encoding.side_effect = ValueError("boom")
        with patch.dict(sys.modules, {"tiktoken": fake_tiktoken}):
            assert is_tiktoken_available() is False


def test_target_batch_tokens_is_positive() -> None:
    """TARGET_BATCH_TOKENS is a positive integer."""
    assert TARGET_BATCH_TOKENS > 0
    assert isinstance(TARGET_BATCH_TOKENS, int)
