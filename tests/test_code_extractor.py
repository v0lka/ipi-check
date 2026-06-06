"""Tests for code_extractor module."""
from __future__ import annotations

from pathlib import Path

from ipi_check.core.types import DiscoveredFile, FileCategory
from ipi_check.scanner.code_extractor import extract_comments_and_strings


def _file(tmp_path: Path, name: str, category: FileCategory) -> DiscoveredFile:
    p = tmp_path / name
    p.write_text("placeholder")
    return DiscoveredFile(
        path=p, category=category, relative_path=name, size_bytes=11,
    )


class TestExtractCommentsAndStrings:
    def test_non_source_returns_full_content(self, tmp_path: Path) -> None:
        f = _file(tmp_path, "AGENTS.md", FileCategory.AGENT_INSTRUCTION)
        content = b"# Hello\n\nNo comments here just markdown.\n"
        out = extract_comments_and_strings(f, content)
        assert out == content.decode("utf-8")

    def test_python_extracts_comments_and_strings(self, tmp_path: Path) -> None:
        src = (
            'import os\n'
            'x = 1 + 2\n'
            '# a special comment\n'
            'msg = "hello world"\n'
            'y = x + 3\n'
        )
        f = _file(tmp_path, "code.py", FileCategory.SOURCE_CODE)
        out = extract_comments_and_strings(f, src.encode("utf-8"))
        assert "# a special comment" in out
        assert "hello world" in out
        # Pure code identifiers not part of comments/strings should be absent.
        assert "import os" not in out
        assert "x = 1 + 2" not in out

    def test_no_comments_strings_fallback(self, tmp_path: Path) -> None:
        # Source with only identifiers and operators — no comments/strings.
        src = "a = 1\nb = a + 2\nc = b * 3\n"
        f = _file(tmp_path, "math.py", FileCategory.SOURCE_CODE)
        out = extract_comments_and_strings(f, src.encode("utf-8"))
        # L009 fallback returns the full decoded content.
        assert out == src

    def test_line_numbers_preserved(self, tmp_path: Path) -> None:
        src = (
            'a = 1\n'
            'b = 2\n'
            '# comment on line 3\n'
            'c = 3\n'
        )
        f = _file(tmp_path, "lines.py", FileCategory.SOURCE_CODE)
        out = extract_comments_and_strings(f, src.encode("utf-8"))
        assert "[L3]" in out

    def test_unknown_extension_uses_text_lexer(self, tmp_path: Path) -> None:
        # Fake source-code extension (.zsh is in SOURCE_CODE_EXTENSIONS).
        src = b"# zsh comment\necho hi\n"
        f = _file(tmp_path, "x.zsh", FileCategory.SOURCE_CODE)
        out = extract_comments_and_strings(f, src)
        assert isinstance(out, str)
        assert len(out) > 0
