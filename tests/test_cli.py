"""Tests for the CLI entry point."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ipi_check.cli.main import expand_env_vars, main


class TestExpandEnvVars:
    def test_expansion(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MYVAR", "value123")
        assert expand_env_vars("token=${MYVAR}") == "token=value123"

    def test_undefined_collapses_to_empty(self) -> None:
        assert expand_env_vars("x=${UNDEFINED_XYZ}y") == "x=y"

    def test_no_pattern(self) -> None:
        assert expand_env_vars("plain text") == "plain text"


class TestCLIMain:
    def test_version_exits_zero(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        monkeypatch.setattr("sys.argv", ["ipi-check", "--version"])
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        out = capsys.readouterr()
        assert "ipi-check" in (out.out + out.err)

    def test_help_exits_zero(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("sys.argv", ["ipi-check", "--help"])
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0

    def test_no_arguments_exits_two(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("sys.argv", ["ipi-check"])
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 2

    def test_nonexistent_repo_exits_two(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        bad = tmp_path / "does-not-exist"
        monkeypatch.setattr("sys.argv", ["ipi-check", "scan", str(bad)])
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 2

    def test_path_is_file_exits_two(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        f = tmp_path / "x.md"
        f.write_text("hi")
        monkeypatch.setattr("sys.argv", ["ipi-check", "scan", str(f)])
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 2

    def test_env_var_expansion_in_arg(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        # Set env var pointing to tmp_path; pass via ${VAR} expansion.
        monkeypatch.setenv("REPO_PATH_FOR_TEST", str(tmp_path))
        monkeypatch.setattr(
            "sys.argv",
            ["ipi-check", "scan", "${REPO_PATH_FOR_TEST}", "--quiet"],
        )
        with pytest.raises(SystemExit) as exc:
            main()
        # Empty repo → no failures, exit 0.
        assert exc.value.code == 0

    def test_quiet_suppresses_progress(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture,
    ) -> None:
        monkeypatch.setattr(
            "sys.argv", ["ipi-check", "scan", str(tmp_path), "--quiet"]
        )
        with pytest.raises(SystemExit):
            main()
        captured = capsys.readouterr()
        # No banner / summary on stderr.
        assert "Prompt Injection Scanner" not in captured.err
        assert "RESULTS" not in captured.err
        assert "Scanned:" not in captured.err
        # SARIF still goes to stdout.
        assert captured.out.strip(), "SARIF must be emitted on stdout"
        sarif = json.loads(captured.out)
        assert sarif["version"] == "2.1.0"

    def test_progress_output_on_stderr(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture,
    ) -> None:
        monkeypatch.setattr("sys.argv", ["ipi-check", "scan", str(tmp_path)])
        with pytest.raises(SystemExit):
            main()
        captured = capsys.readouterr()
        # Banner appears on stderr.
        assert "ipi-check" in captured.err
        # Per-stage progress bars and results block per CLI contract.
        assert "[byte-analysis]" in captured.err
        assert "[pattern-matching]" in captured.err
        assert "[heuristics]" in captured.err
        assert "[llm]" in captured.err
        assert "RESULTS" in captured.err
        assert "Scanned:" in captured.err
        assert "BLOCK:" in captured.err
        assert "REVIEW_REQUIRED:" in captured.err
        assert "PASS:" in captured.err
        assert "SARIF report written to stdout" in captured.err


class TestBuildParser:
    def test_no_gitignore_flag_parsed(self) -> None:
        """--no-gitignore flag is recognized."""
        from ipi_check.cli.main import build_parser
        parser = build_parser()
        args = parser.parse_args(["scan", "/tmp", "--no-gitignore"])
        assert args.no_gitignore is True

    def test_exclude_single_pattern(self) -> None:
        """--exclude with a single pattern."""
        from ipi_check.cli.main import build_parser
        parser = build_parser()
        args = parser.parse_args(["scan", "/tmp", "--exclude", "*.log"])
        assert args.exclude == ["*.log"]

    def test_exclude_multiple_patterns(self) -> None:
        """--exclude can be repeated for multiple patterns."""
        from ipi_check.cli.main import build_parser
        parser = build_parser()
        args = parser.parse_args(
            ["scan", "/tmp", "--exclude", "*.log", "--exclude", "vendor/"]
        )
        assert args.exclude == ["*.log", "vendor/"]

    def test_exclude_default_is_none(self) -> None:
        """--exclude defaults to None when not specified."""
        from ipi_check.cli.main import build_parser
        parser = build_parser()
        args = parser.parse_args(["scan", "/tmp"])
        assert args.exclude is None
