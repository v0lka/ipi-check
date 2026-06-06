"""Tests for semantic_heuristics module."""

from __future__ import annotations

import base64
from pathlib import Path

from ipi_check.core.types import DiscoveredFile, FileCategory
from ipi_check.scanner.semantic_heuristics import (
    ENTROPY_THRESHOLD,
    INSTRUCTION_DENSITY_THRESHOLD,
    SOURCE_CODE_ENTROPY_THRESHOLD,
    compute_entropy,
    compute_heuristics,
)


def _file(tmp_path: Path) -> DiscoveredFile:
    p = tmp_path / "x.md"
    p.write_text("ph")
    return DiscoveredFile(
        path=p,
        category=FileCategory.AGENT_INSTRUCTION,
        relative_path="x.md",
        size_bytes=2,
    )


class TestComputeEntropy:
    def test_empty_text(self) -> None:
        assert compute_entropy("") == 0.0

    def test_single_character_zero_entropy(self) -> None:
        assert compute_entropy("aaaaaa") == 0.0

    def test_random_base64_high_entropy(self) -> None:
        # 256 random bytes b64-encoded → high entropy (~5.8-6.0 bits/char).
        import os

        text = base64.b64encode(os.urandom(256)).decode("ascii")
        assert compute_entropy(text) > ENTROPY_THRESHOLD

    def test_normal_english_moderate_entropy(self) -> None:
        text = (
            "The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs."
        ) * 4
        e = compute_entropy(text)
        assert 3.0 < e < 4.7  # broad range; usually 4.0-4.5
        assert e < ENTROPY_THRESHOLD  # must NOT trigger the suspicious flag


class TestComputeHeuristics:
    def test_empty_visible_text(self, tmp_path: Path) -> None:
        f = _file(tmp_path)
        scores = compute_heuristics(f, b"", "", [])
        assert scores.entropy == 0.0
        assert scores.entropy_suspicious is False
        assert scores.invisible_suspicious is False
        assert scores.instruction_density_suspicious is False
        assert scores.suspicious_count == 0

    def test_random_base64_entropy_suspicious(self, tmp_path: Path) -> None:
        import os

        f = _file(tmp_path)
        text = base64.b64encode(os.urandom(512)).decode("ascii")
        scores = compute_heuristics(f, text.encode("utf-8"), text, [])
        assert scores.entropy > ENTROPY_THRESHOLD
        assert scores.entropy_suspicious is True

    def test_normal_text_not_flagged(self, tmp_path: Path) -> None:
        f = _file(tmp_path)
        text = (
            "# Agent Instructions\n\n"
            "Please follow project conventions.\n"
            "Use tabs for indentation when editing existing files.\n"
            "Document your changes clearly in commit messages.\n"
        )
        scores = compute_heuristics(f, text.encode(), text, [])
        assert scores.entropy_suspicious is False
        # density may or may not trigger; ensure not all flags set
        assert scores.suspicious_count <= 1

    def test_invisible_ratio_high(self, tmp_path: Path) -> None:
        f = _file(tmp_path)
        # raw_bytes much larger than visible_text → high invisible_ratio.
        raw = b"x" * 1000
        visible = "x" * 100  # 90% "invisible"
        scores = compute_heuristics(f, raw, visible, [])
        assert scores.invisible_ratio > 0.8
        assert scores.invisible_suspicious is True

    def test_high_instruction_density(self, tmp_path: Path) -> None:
        f = _file(tmp_path)
        # Many imperative verbs in a single paragraph.
        text = (
            "you must always run delete remove execute install "
            "download upload send modify replace change override bypass "
            "ignore disable enable shall never"
        )
        scores = compute_heuristics(f, text.encode(), text, [])
        assert scores.instruction_density > INSTRUCTION_DENSITY_THRESHOLD
        assert scores.instruction_density_suspicious is True

    def test_suspicious_count_sums_flags(self, tmp_path: Path) -> None:
        f = _file(tmp_path)
        # Trigger entropy + invisible + density.
        import os

        random_text = base64.b64encode(os.urandom(1024)).decode("ascii")
        # Append imperative verbs paragraph
        verbs_paragraph = (
            "you must always run delete remove execute install "
            "download upload send modify replace change override bypass "
            "ignore disable enable shall never"
        )
        visible = random_text + "\n\n" + verbs_paragraph
        # Pad raw to make invisible_ratio high
        raw = visible.encode("utf-8") + b"\x00" * (5 * len(visible))
        scores = compute_heuristics(f, raw, visible, [])
        flags = [
            scores.entropy_suspicious,
            scores.invisible_suspicious,
            scores.instruction_density_suspicious,
        ]
        assert scores.suspicious_count == sum(flags)

    def test_source_code_uses_higher_threshold(self, tmp_path: Path) -> None:
        """Source code with typical entropy (4.5-5.5) must NOT be flagged."""
        p = tmp_path / "app.py"
        # Typical Python source code — diverse chars but not encoded payload.
        code = (
            "from __future__ import annotations\n"
            "import os, sys, json, re\n\n"
            "def compute_metrics(data: list[dict[str, float]]) -> dict[str, float]:\n"
            '    """Compute summary statistics for input data."""\n'
            "    results: dict[str, float] = {}\n"
            "    for item in data:\n"
            "        for key, value in item.items():\n"
            '            results[f"{key}_sum"] = results.get(f"{key}_sum", 0.0) + value\n'
            "    return results\n\n"
            "class ConfigParser:\n"
            "    _DEFAULT_PATH = '/etc/app/config.json'\n"
            "    _VALID_KEYS = frozenset({'host', 'port', 'debug', 'workers'})\n\n"
            "    def __init__(self, path: str = _DEFAULT_PATH) -> None:\n"
            "        self.path = path\n"
            "        self._cache: dict[str, object] = {}\n"
        )
        p.write_text(code)
        source_file = DiscoveredFile(
            path=p,
            category=FileCategory.SOURCE_CODE,
            relative_path="app.py",
            size_bytes=len(code),
        )
        scores = compute_heuristics(source_file, code.encode(), code, [])
        # Source code entropy is typically 4.5-5.5 — below SOURCE_CODE threshold.
        assert scores.entropy < SOURCE_CODE_ENTROPY_THRESHOLD
        assert scores.entropy_suspicious is False

    def test_agent_file_with_base64_flagged(self, tmp_path: Path) -> None:
        """Agent instruction file with large Base64 blob must be flagged."""
        import os

        f = _file(tmp_path)
        # Agent instruction file with a large encoded payload.
        payload = base64.b64encode(os.urandom(2048)).decode("ascii")
        text = f"# Instructions\n\nFollow these steps:\n\n{payload}\n"
        scores = compute_heuristics(f, text.encode(), text, [])
        assert scores.entropy > ENTROPY_THRESHOLD
        assert scores.entropy_suspicious is True
