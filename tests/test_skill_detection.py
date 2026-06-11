"""Tests for SKILL.md detection and skill unit grouping."""
from __future__ import annotations

from pathlib import Path

from ipi_check.core.types import FileCategory
from ipi_check.scanner.file_discovery import (
    _parse_skill_frontmatter,
    discover_files,
)


class TestSkillDetection:
    """Tests for SKILL.md auto-detection via discover_files()."""

    def test_skill_md_detected_in_subdirectory(self, skill_repo: Path) -> None:
        """SKILL.md in a subdirectory is detected as a skill unit."""
        discovered, skill_units = discover_files(skill_repo)
        # One non-skill file (AGENTS.md at root).
        assert len(discovered) == 1
        assert discovered[0].relative_path == "AGENTS.md"
        # One skill unit.
        assert len(skill_units) == 1
        skill = skill_units[0]
        assert skill.root.name == "my-skill"
        assert skill.frontmatter.name == "my-skill"
        # Skill files include SKILL.md + scripts/format.py.
        skill_paths = {f.relative_path for f in skill.files}
        assert "my-skill/SKILL.md" in skill_paths
        assert "my-skill/scripts/format.py" in skill_paths

    def test_files_in_skill_dir_become_skill_category(self, malicious_skill_repo: Path) -> None:
        """Files within a skill directory get FileCategory.SKILL."""
        discovered, skill_units = discover_files(malicious_skill_repo)
        assert len(skill_units) == 1
        skill = skill_units[0]
        for f in skill.files:
            assert f.category == FileCategory.SKILL

    def test_nested_skills_inner_takes_precedence(self, nested_skills_repo: Path) -> None:
        """Inner SKILL.md takes precedence — files under inner dir belong to inner skill."""
        discovered, skill_units = discover_files(nested_skills_repo)
        # Should have 2 skill units: outer (root) and inner (inner-skill/).
        assert len(skill_units) == 2
        skill_names = {s.frontmatter.name for s in skill_units}
        assert skill_names == {"outer-skill", "inner-skill"}

        # outer_util.py belongs to outer skill.
        outer_skill = next(s for s in skill_units if s.frontmatter.name == "outer-skill")
        outer_paths = {f.relative_path for f in outer_skill.files}
        assert "SKILL.md" in outer_paths
        assert "outer_util.py" in outer_paths
        assert "inner-skill/SKILL.md" not in outer_paths

        # inner_util.py belongs to inner skill (not outer).
        inner_skill = next(s for s in skill_units if s.frontmatter.name == "inner-skill")
        inner_paths = {f.relative_path for f in inner_skill.files}
        assert "inner-skill/SKILL.md" in inner_paths
        assert "inner-skill/inner_util.py" in inner_paths

    def test_mixed_repo_non_skill_files_remain(self, skill_repo: Path) -> None:
        """Non-skill files outside skill dirs remain in the non-skill stream."""
        discovered, skill_units = discover_files(skill_repo)
        assert len(discovered) >= 1
        for f in discovered:
            assert f.category != FileCategory.SKILL

    def test_no_skill_repo_returns_empty_skill_units(self, tmp_path: Path) -> None:
        """A repo without SKILL.md returns empty skill_units."""
        (tmp_path / "app.py").write_text("print(1)")
        discovered, skill_units = discover_files(tmp_path)
        assert len(discovered) == 1
        assert len(skill_units) == 0

    def test_skill_respects_exclude_patterns(self, tmp_path: Path) -> None:
        """Skill directories matching exclude patterns are pruned."""
        skill_dir = tmp_path / "vendor"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(
            "---\nname: vendor-skill\ndescription: Bad.\n---\n# Hi\n"
        )
        discovered, skill_units = discover_files(
            tmp_path, exclude_patterns=["vendor/"]
        )
        assert len(skill_units) == 0

    def test_skill_respects_gitignore(self, tmp_path: Path) -> None:
        """Skill directories in .gitignore are excluded."""
        (tmp_path / ".gitignore").write_text("ignored-skill/\n")
        skill_dir = tmp_path / "ignored-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(
            "---\nname: ignored\ndescription: x.\n---\n# Hi\n"
        )
        discovered, skill_units = discover_files(tmp_path, respect_gitignore=True)
        assert len(skill_units) == 0


class TestSkillFrontmatterParsing:
    """Tests for YAML frontmatter parsing from SKILL.md."""

    def test_valid_frontmatter(self) -> None:
        raw = (
            b"---\n"
            b"name: test-skill\n"
            b"description: A test skill.\n"
            b"---\n"
            b"# Body content\n"
            b"Some markdown.\n"
        )
        fm, body = _parse_skill_frontmatter(raw)
        assert fm.name == "test-skill"
        assert fm.description == "A test skill."
        assert "# Body content" in body
        assert "Some markdown" in body

    def test_empty_frontmatter_fields(self) -> None:
        raw = (
            b"---\n"
            b"name: minimal\n"
            b"description: Min.\n"
            b"---\n"
            b"Body only.\n"
        )
        fm, body = _parse_skill_frontmatter(raw)
        assert fm.name == "minimal"
        assert fm.license is None
        assert fm.compatibility is None
        assert fm.allowed_tools is None
        assert fm.metadata == {}

    def test_missing_frontmatter_uses_defaults(self) -> None:
        """File without YAML frontmatter returns defaults."""
        raw = b"Just a markdown file.\nNo frontmatter here.\n"
        fm, body = _parse_skill_frontmatter(raw)
        assert fm.name == ""
        assert fm.description == ""
        assert "Just a markdown file" in body

    def test_frontmatter_with_allowed_tools(self) -> None:
        raw = (
            b"---\n"
            b"name: tool-skill\n"
            b"description: Uses tools.\n"
            b"allowed-tools: Bash(git:*)\n"
            b"---\n"
            b"Body.\n"
        )
        fm, body = _parse_skill_frontmatter(raw)
        assert fm.allowed_tools == "Bash(git:*)"

    def test_frontmatter_with_extra_metadata(self) -> None:
        raw = (
            b"---\n"
            b"name: meta-skill\n"
            b"description: Has metadata.\n"
            b"metadata:\n"
            b"  version: 1.0\n"
            b"  author: test\n"
            b"---\n"
            b"Body.\n"
        )
        fm, body = _parse_skill_frontmatter(raw)
        assert fm.metadata == {"version": "1.0", "author": "test"}
