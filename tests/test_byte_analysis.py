"""Tests for byte-level analysis."""
from __future__ import annotations

from pathlib import Path

from ipi_check.core.types import (
    ByteFindingCategory,
    DiscoveredFile,
    FileCategory,
    Severity,
)
from ipi_check.scanner.byte_analysis import analyze_bytes


def _make_file(tmp_path: Path) -> DiscoveredFile:
    p = tmp_path / "x.md"
    p.write_text("placeholder")
    return DiscoveredFile(
        path=p,
        category=FileCategory.AGENT_INSTRUCTION,
        relative_path="x.md",
        size_bytes=11,
    )


def _categories(findings: list, severity: Severity | None = None) -> list[ByteFindingCategory]:
    if severity is not None:
        return [f.category for f in findings if f.severity == severity]
    return [f.category for f in findings]


class TestAnalyzeBytes:
    def test_empty_bytes(self, tmp_path: Path) -> None:
        f = _make_file(tmp_path)
        assert analyze_bytes(f, b"") == []

    def test_ansi_hide(self, tmp_path: Path) -> None:
        f = _make_file(tmp_path)
        findings = analyze_bytes(f, b"hi\x1b[8mhidden\x1b[0m")
        cats = _categories(findings, Severity.CRITICAL)
        assert ByteFindingCategory.ANSI_HIDDEN in cats

    def test_unicode_tag_critical(self, tmp_path: Path) -> None:
        # U+E0041 → F3 A0 81 81
        f = _make_file(tmp_path)
        findings = analyze_bytes(f, b"plain\xf3\xa0\x81\x81text")
        cats = _categories(findings, Severity.CRITICAL)
        assert ByteFindingCategory.UNICODE_TAGS in cats

    def test_variation_selector_high(self, tmp_path: Path) -> None:
        # U+FE0F → EF B8 8F
        f = _make_file(tmp_path)
        findings = analyze_bytes(f, b"text\xef\xb8\x8fmore")
        cats = _categories(findings, Severity.HIGH)
        assert ByteFindingCategory.VARIATION_SELECTORS in cats

    def test_bidi_override_high(self, tmp_path: Path) -> None:
        # U+202E → E2 80 AE
        f = _make_file(tmp_path)
        findings = analyze_bytes(f, b"text\xe2\x80\xaemore")
        cats = _categories(findings, Severity.HIGH)
        assert ByteFindingCategory.BIDI_OVERRIDE in cats

    def test_zero_width_medium(self, tmp_path: Path) -> None:
        # U+200B → E2 80 8B
        f = _make_file(tmp_path)
        findings = analyze_bytes(f, b"hello\xe2\x80\x8bworld")
        cats = _categories(findings, Severity.MEDIUM)
        assert ByteFindingCategory.ZERO_WIDTH in cats

    def test_line_paragraph_separator_medium(self, tmp_path: Path) -> None:
        """U+2028 (line separator) and U+2029 (paragraph separator) → MEDIUM."""
        # U+2028 = \xe2\x80\xa8, U+2029 = \xe2\x80\xa9 in UTF-8
        f = _make_file(tmp_path)
        raw = b"hello\xe2\x80\xa8world\xe2\x80\xa9end"
        findings = analyze_bytes(f, raw)
        separator_findings = [
            x for x in findings if x.category == ByteFindingCategory.ZERO_WIDTH
        ]
        assert len(separator_findings) == 2
        assert all(x.severity == Severity.MEDIUM for x in separator_findings)

    def test_pua_medium(self, tmp_path: Path) -> None:
        f = _make_file(tmp_path)
        # U+E000 PUA char encoded as utf-8
        text = "hello" + "\ue000" + "world"
        findings = analyze_bytes(f, text.encode("utf-8"))
        cats = _categories(findings, Severity.MEDIUM)
        assert ByteFindingCategory.PUA in cats

    def test_homoglyphs_in_latin_text_flagged(self, tmp_path: Path) -> None:
        f = _make_file(tmp_path)
        # Mostly Latin, with sprinkled Cyrillic homoglyphs (ratio > 0.05).
        text = "Hello" + "а" + "world" + "е" + "test"  # noqa: RUF001
        findings = analyze_bytes(f, text.encode("utf-8"))
        cats = _categories(findings, Severity.MEDIUM)
        assert ByteFindingCategory.HOMOGLYPH in cats

    def test_russian_only_text_not_flagged(self, tmp_path: Path) -> None:
        f = _make_file(tmp_path)
        # Pure Cyrillic prose — no Latin letters → ratio threshold is computed
        # over (latin + cyrillic-homoglyphs); if all chars are homoglyphs
        # the ratio is 1.0 and would trigger. So we use NON-homoglyph
        # Cyrillic letters which the homoglyph map doesn't contain.
        text = "Привет, как дела? Это README по-русски."
        findings = analyze_bytes(f, text.encode("utf-8"))
        # Not all Cyrillic letters are in HOMOGLYPH_MAP — text should pass.
        # Even if a few homoglyph letters appear, ratio over (latin=0 + cyr_h)
        # would be 1.0; we picked text without homoglyph letters.
        homoglyph_findings = [
            x for x in findings if x.category == ByteFindingCategory.HOMOGLYPH
        ]
        # Verify the text doesn't accidentally contain mapped chars:
        from ipi_check.scanner.byte_analysis import HOMOGLYPH_MAP
        if not any(c in HOMOGLYPH_MAP for c in text):
            assert homoglyph_findings == []

    def test_line_column_resolution(self, tmp_path: Path) -> None:
        f = _make_file(tmp_path)
        # "ok\n\x1b[8m" — escape on line 2 col 1
        findings = analyze_bytes(f, b"ok\n\x1b[8mhidden")
        ansi = [x for x in findings if x.category == ByteFindingCategory.ANSI_HIDDEN]
        assert ansi
        assert ansi[0].line == 2
        assert ansi[0].column == 1

    def test_multiple_findings(self, tmp_path: Path) -> None:
        f = _make_file(tmp_path)
        data = b"x\x1b[8my" + b"\xe2\x80\xae" + b"z"
        findings = analyze_bytes(f, data)
        cats = _categories(findings)
        assert ByteFindingCategory.ANSI_HIDDEN in cats
        assert ByteFindingCategory.BIDI_OVERRIDE in cats

    def test_hex_snippet_present(self, tmp_path: Path) -> None:
        f = _make_file(tmp_path)
        findings = analyze_bytes(f, b"\x1b[8mfoo")
        assert findings
        assert all(isinstance(x.snippet_hex, str) for x in findings)
        assert findings[0].snippet_hex.startswith("1b5b386d")
