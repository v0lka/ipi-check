"""Tests for file_discovery module."""
from __future__ import annotations

import os
import warnings
from pathlib import Path

import pytest

from ipi_check.core.types import FileCategory
from ipi_check.scanner.file_discovery import MAX_FILE_SIZE_BYTES, discover_files


class TestDiscoverFiles:
    def test_empty_dir(self, tmp_path: Path) -> None:
        assert discover_files(tmp_path) == ([], [])

    def test_nonexistent_path_exits(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            discover_files(tmp_path / "nonexistent")

    def test_path_is_file_exits(self, tmp_path: Path) -> None:
        f = tmp_path / "x.md"
        f.write_text("hi")
        with pytest.raises(NotADirectoryError):
            discover_files(f)

    def test_agent_instruction_files_categorized(self, tmp_path: Path) -> None:
        (tmp_path / "AGENTS.md").write_text("a")
        (tmp_path / ".cursorrules").write_text("b")
        (tmp_path / "claude.md").write_text("c")
        results, _ = discover_files(tmp_path)
        cats = {Path(r.relative_path).name.lower(): r.category for r in results}
        for name in ("agents.md", ".cursorrules", "claude.md"):
            assert cats[name] == FileCategory.AGENT_INSTRUCTION

    def test_source_code_categorized(self, tmp_path: Path) -> None:
        (tmp_path / "x.py").write_text("print(1)")
        (tmp_path / "y.ts").write_text("const x = 1;")
        results, _ = discover_files(tmp_path)
        for r in results:
            assert r.category == FileCategory.SOURCE_CODE

    def test_dot_directory_markdown(self, tmp_path: Path) -> None:
        gh = tmp_path / ".github"
        gh.mkdir()
        (gh / "TEMPLATE.md").write_text("x")
        results, _ = discover_files(tmp_path)
        assert len(results) == 1
        assert results[0].category == FileCategory.DOT_DIRECTORY_MD

    def test_root_md_is_dot_directory_category(self, tmp_path: Path) -> None:
        # Root-level markdown without an agent name still qualifies under
        # the "root or dot-prefixed parent" rule.
        (tmp_path / "README.md").write_text("hi")
        results, _ = discover_files(tmp_path)
        assert len(results) == 1
        assert results[0].category == FileCategory.DOT_DIRECTORY_MD

    def test_git_dir_excluded(self, tmp_path: Path) -> None:
        git = tmp_path / ".git"
        git.mkdir()
        (git / "config").write_text("ignored")
        (git / "HEAD.md").write_text("ignored md")
        (tmp_path / "AGENTS.md").write_text("real")
        results, _ = discover_files(tmp_path)
        assert len(results) == 1
        assert results[0].relative_path == "AGENTS.md"

    @pytest.mark.parametrize("ext", [".png", ".exe", ".zip", ".pdf"])
    def test_binary_files_excluded(self, tmp_path: Path, ext: str) -> None:
        (tmp_path / f"image{ext}").write_bytes(b"\x00\x01")
        assert discover_files(tmp_path) == ([], [])

    def test_large_file_skipped_with_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Create a "large" file by lowering the threshold for this test.
        big_path = tmp_path / "big.py"
        big_path.write_bytes(b"x" * (MAX_FILE_SIZE_BYTES + 1))
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            results, _ = discover_files(tmp_path)
        assert results == []
        assert any("exceeding" in str(w.message) for w in caught)

    def test_symlink_outside_repo_skipped(self, tmp_path: Path) -> None:
        outside_dir = tmp_path.parent / f"outside-{tmp_path.name}"
        outside_dir.mkdir()
        try:
            outside_file = outside_dir / "secret.md"
            outside_file.write_text("secret")
            repo = tmp_path / "repo"
            repo.mkdir()
            link = repo / "AGENTS.md"
            try:
                os.symlink(outside_file, link)
            except (OSError, NotImplementedError):
                pytest.skip("Symlinks not supported on this platform.")
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                results, _ = discover_files(repo)
            assert results == []
            assert any("outside repository" in str(w.message) for w in caught)
        finally:
            # Cleanup outside dir
            for p in outside_dir.iterdir():
                p.unlink()
            outside_dir.rmdir()

    def test_deduplication(self, tmp_path: Path) -> None:
        # AGENTS.md is both an agent instruction file AND root markdown.
        # It should appear only once.
        (tmp_path / "AGENTS.md").write_text("x")
        results, _ = discover_files(tmp_path)
        assert len(results) == 1
        assert results[0].category == FileCategory.AGENT_INSTRUCTION

    def test_case_insensitive_agent_files(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("x")
        results, _ = discover_files(tmp_path)
        assert len(results) == 1
        assert results[0].category == FileCategory.AGENT_INSTRUCTION

    def test_cursor_mdc_detected(self, tmp_path: Path) -> None:
        cursor = tmp_path / ".cursor" / "rules"
        cursor.mkdir(parents=True)
        (cursor / "rule.mdc").write_text("x")
        results, _ = discover_files(tmp_path)
        assert len(results) == 1
        assert results[0].category == FileCategory.AGENT_INSTRUCTION

    def test_unrelated_files_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "data.csv").write_text("a,b,c")
        (tmp_path / "image.gif").write_bytes(b"\x00")
        assert discover_files(tmp_path) == ([], [])

    def test_gitignore_excludes_files(self, tmp_path: Path) -> None:
        """Files matching .gitignore patterns are excluded by default."""
        (tmp_path / ".gitignore").write_text("*.log\n")
        (tmp_path / "app.py").write_text("print(1)")
        (tmp_path / "debug.log").write_text("log data")
        results, _ = discover_files(tmp_path)
        paths = [r.relative_path for r in results]
        assert "app.py" in paths
        assert "debug.log" not in paths

    def test_gitignore_excludes_directories(self, tmp_path: Path) -> None:
        """Directory patterns in .gitignore prune the walk tree."""
        (tmp_path / ".gitignore").write_text("node_modules/\n")
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "lib.js").write_text("module.exports = {}")
        (tmp_path / "app.js").write_text("const x = 1")
        results, _ = discover_files(tmp_path)
        paths = [r.relative_path for r in results]
        assert "app.js" in paths
        assert not any("node_modules" in p for p in paths)

    def test_no_gitignore_flag_includes_ignored_files(self, tmp_path: Path) -> None:
        """With respect_gitignore=False, gitignored files are included."""
        (tmp_path / ".gitignore").write_text("*.json\n")
        (tmp_path / "data.json").write_text("{}")
        results_with, _ = discover_files(tmp_path, respect_gitignore=True)
        results_without, _ = discover_files(tmp_path, respect_gitignore=False)
        paths_with = {r.relative_path for r in results_with}
        paths_without = {r.relative_path for r in results_without}
        assert "data.json" not in paths_with
        assert "data.json" in paths_without

    def test_exclude_patterns_exclude_files(self, tmp_path: Path) -> None:
        """--exclude patterns filter out matching files."""
        (tmp_path / "app.py").write_text("print(1)")
        (tmp_path / "config.json").write_text("{}")
        results, _ = discover_files(tmp_path, exclude_patterns=["*.json"])
        paths = [r.relative_path for r in results]
        assert "app.py" in paths
        assert "config.json" not in paths

    def test_exclude_patterns_multiple(self, tmp_path: Path) -> None:
        """Multiple exclude patterns all apply."""
        (tmp_path / "app.py").write_text("print(1)")
        (tmp_path / "config.json").write_text("{}")
        (tmp_path / "data.yaml").write_text("key: val")
        results, _ = discover_files(tmp_path, exclude_patterns=["*.json", "*.yaml"])
        paths = [r.relative_path for r in results]
        assert "app.py" in paths
        assert "config.json" not in paths
        assert "data.yaml" not in paths

    def test_exclude_directory_pattern(self, tmp_path: Path) -> None:
        """Exclude patterns with directory globs prune the tree."""
        vendor = tmp_path / "vendor"
        vendor.mkdir()
        (vendor / "lib.py").write_text("x = 1")
        (tmp_path / "main.py").write_text("import vendor")
        results, _ = discover_files(tmp_path, exclude_patterns=["vendor/"])
        paths = [r.relative_path for r in results]
        assert "main.py" in paths
        assert not any("vendor" in p for p in paths)

    def test_gitignore_missing_is_fine(self, tmp_path: Path) -> None:
        """When no .gitignore exists, proceed without errors."""
        (tmp_path / "app.py").write_text("print(1)")
        results, _ = discover_files(tmp_path, respect_gitignore=True)
        assert len(results) == 1

    def test_exclude_overrides_category(self, tmp_path: Path) -> None:
        """Exclude patterns can exclude even agent instruction files."""
        (tmp_path / "AGENTS.md").write_text("# Rules")
        (tmp_path / "app.py").write_text("print(1)")
        results, _ = discover_files(tmp_path, exclude_patterns=["AGENTS.md"])
        paths = [r.relative_path for r in results]
        assert "AGENTS.md" not in paths
        assert "app.py" in paths
