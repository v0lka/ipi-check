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

# Regression fixtures for FP-1 (roadmap T6.1): legitimate Cyrillic documents
# (.md and .js) that must NOT trigger IPI006, plus one genuine homoglyph attack.
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "cyrillic"

# Regression fixtures for FP-2 (roadmap T0.2): a document with ordinary emoji
# (which must NOT trigger IPI003) and a hidden U+FE00 variation-selector
# channel (which must).
VS_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "variation-selectors"


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

    def test_latin_token_with_cyrillic_homoglyphs_flagged(self, tmp_path: Path) -> None:
        f = _make_file(tmp_path)
        # A Latin word with Cyrillic а/е spliced into the same token.
        text = "Hello" + "а" + "world" + "е" + "test"  # noqa: RUF001
        findings = analyze_bytes(f, text.encode("utf-8"))
        homoglyphs = [
            x for x in findings if x.category == ByteFindingCategory.HOMOGLYPH
        ]
        assert len(homoglyphs) == 1
        assert homoglyphs[0].severity == Severity.MEDIUM

    def test_russian_only_text_not_flagged(self, tmp_path: Path) -> None:
        f = _make_file(tmp_path)
        # Pure Cyrillic prose (plus standalone Latin words) never mixes scripts
        # *within* a token → no homoglyph finding.
        text = "Привет, как дела? Это README по-русски."
        findings = analyze_bytes(f, text.encode("utf-8"))
        homoglyph_findings = [
            x for x in findings if x.category == ByteFindingCategory.HOMOGLYPH
        ]
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


class TestHomoglyphMixedScriptRegression:
    """FP-1 / T0.1 — homoglyph detection at token granularity (T6.1 fixtures)."""

    def test_cyrillic_markdown_no_ipi006(self, tmp_path: Path) -> None:
        raw = (FIXTURES_DIR / "README_ru.md").read_bytes()
        findings = analyze_bytes(_make_file(tmp_path), raw)
        assert [
            x for x in findings if x.category == ByteFindingCategory.HOMOGLYPH
        ] == []

    def test_cyrillic_javascript_no_ipi006(self, tmp_path: Path) -> None:
        raw = (FIXTURES_DIR / "app_ru.js").read_bytes()
        findings = analyze_bytes(_make_file(tmp_path), raw)
        assert [
            x for x in findings if x.category == ByteFindingCategory.HOMOGLYPH
        ] == []

    def test_homoglyph_attack_fixture_detected(self, tmp_path: Path) -> None:
        raw = (FIXTURES_DIR / "homoglyph_attack.md").read_bytes()
        findings = analyze_bytes(_make_file(tmp_path), raw)
        homoglyphs = [
            x for x in findings if x.category == ByteFindingCategory.HOMOGLYPH
        ]
        assert len(homoglyphs) == 1
        assert homoglyphs[0].severity == Severity.MEDIUM

    def test_at_most_one_finding_per_file(self, tmp_path: Path) -> None:
        # Many mixed-script tokens must still collapse to a single finding.
        text = "Pаypal Gооgle sесret аpple еxample оrange " * 20  # noqa: RUF001
        findings = analyze_bytes(_make_file(tmp_path), text.encode("utf-8"))
        homoglyphs = [
            x for x in findings if x.category == ByteFindingCategory.HOMOGLYPH
        ]
        assert len(homoglyphs) == 1

    def test_mixed_scripts_without_confusable_is_low(self, tmp_path: Path) -> None:
        # Latin letters spliced with non-confusable Cyrillic (ж) — no
        # Latin-lookalike present → severity downgraded to LOW.
        findings = analyze_bytes(_make_file(tmp_path), "helloжworld".encode())
        homoglyphs = [
            x for x in findings if x.category == ByteFindingCategory.HOMOGLYPH
        ]
        assert len(homoglyphs) == 1
        assert homoglyphs[0].severity == Severity.LOW

    def test_pure_latin_and_pure_cyrillic_not_flagged(self, tmp_path: Path) -> None:
        for text in ("plain latin text only", "Чисто русский текст без латиницы"):
            findings = analyze_bytes(_make_file(tmp_path), text.encode("utf-8"))
            assert [
                x for x in findings if x.category == ByteFindingCategory.HOMOGLYPH
            ] == []

    def test_sarif_ipi006_capped_and_absent_for_cyrillic(self, tmp_path: Path) -> None:
        """End-to-end: Cyrillic docs yield no IPI006; the attack yields one."""
        from ipi_check import TOOL_INFO
        from ipi_check.reporter.sarif_reporter import generate_sarif
        from ipi_check.scanner.pipeline import run_pipeline

        for name in ("README_ru.md", "app_ru.js", "homoglyph_attack.md"):
            (tmp_path / name).write_bytes((FIXTURES_DIR / name).read_bytes())

        verdicts, _skill_verdicts = run_pipeline(tmp_path, llm_config=None, quiet=True)
        sarif = generate_sarif(
            verdicts,
            tmp_path,
            TOOL_INFO,
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:00:01Z",
        )
        counts: dict[str, int] = {}
        for result in sarif["runs"][0]["results"]:
            if result["ruleId"] != "IPI006":
                continue
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            counts[uri] = counts.get(uri, 0) + 1

        assert counts.get("README_ru.md", 0) == 0
        assert counts.get("app_ru.js", 0) == 0
        assert counts.get("homoglyph_attack.md", 0) == 1
        assert all(count <= 1 for count in counts.values())


def _vs_findings(findings: list) -> list:
    return [x for x in findings if x.category == ByteFindingCategory.VARIATION_SELECTORS]


class TestVariationSelectorPresentation:
    """FP-2 / T0.2 — the U+FE0F emoji presentation selector must not trigger IPI003."""

    def test_emoji_doc_fixture_no_ipi003(self, tmp_path: Path) -> None:
        raw = (VS_FIXTURES_DIR / "emoji_doc.md").read_bytes()
        findings = analyze_bytes(_make_file(tmp_path), raw)
        assert _vs_findings(findings) == []

    def test_fe00_channel_fixture_detected(self, tmp_path: Path) -> None:
        raw = (VS_FIXTURES_DIR / "fe00_channel.md").read_bytes()
        findings = analyze_bytes(_make_file(tmp_path), raw)
        asserted = _vs_findings(findings)
        assert asserted
        assert all(x.severity == Severity.HIGH for x in asserted)

    def test_emoji_presentation_selector_with_base_not_flagged(self, tmp_path: Path) -> None:
        # ⚠ (U+26A0) + U+FE0F is legitimate emoji presentation.
        raw = "\u26a0\ufe0f warning".encode("utf-8")
        findings = analyze_bytes(_make_file(tmp_path), raw)
        assert _vs_findings(findings) == []

    def test_small_emoji_count_not_flagged(self, tmp_path: Path) -> None:
        raw = "\u26a0\ufe0f ok \u2705 done \u2764\ufe0f".encode("utf-8")
        findings = analyze_bytes(_make_file(tmp_path), raw)
        assert _vs_findings(findings) == []

    def test_fe0f_without_emoji_base_flagged(self, tmp_path: Path) -> None:
        # U+FE0F after a plain Latin letter has no emoji base → suspicious.
        raw = "text\ufe0fmore".encode("utf-8")
        findings = analyze_bytes(_make_file(tmp_path), raw)
        asserted = _vs_findings(findings)
        assert asserted
        assert all(x.severity == Severity.HIGH for x in asserted)

    def test_fe0f_anomalous_density_flagged(self, tmp_path: Path) -> None:
        # Every selector follows an emoji base, but the file is saturated with
        # them — a steganographic encoding channel, not ordinary emoji usage.
        raw = ("\u26a0\ufe0f" * 40).encode("utf-8")
        findings = analyze_bytes(_make_file(tmp_path), raw)
        assert _vs_findings(findings)

    def test_duplicate_byte_findings_deduped(self, tmp_path: Path) -> None:
        # \x1b[8m matches both the generic ANSI pattern and the hide pattern;
        # the identical findings must collapse to a single one.
        findings = analyze_bytes(_make_file(tmp_path), b"\x1b[8mfoo")
        ansi = [x for x in findings if x.category == ByteFindingCategory.ANSI_HIDDEN]
        assert len(ansi) == 1
