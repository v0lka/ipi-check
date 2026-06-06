"""CLI entry point for ipi-check scanner."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ipi_check import TOOL_INFO, __version__
from ipi_check.core.types import FinalVerdict, LLMConfig, VerdictDecision
from ipi_check.reporter.sarif_reporter import generate_sarif
from ipi_check.scanner.pipeline import run_pipeline

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ENV_VAR_PATTERN: re.Pattern[str] = re.compile(r"\$\{([^}]+)\}")

BANNER_TEMPLATE: str = "{name} {version} — Prompt Injection Scanner"

# Results summary formatting (per CLI contract).
_RESULTS_HEADING: str = "RESULTS"
_RESULTS_RULE_CHAR: str = "═"
_RESULTS_RULE_WIDTH: int = 35
_SARIF_STDOUT_LABEL: str = "stdout"

# Exit codes (per CLI contract).
EXIT_SUCCESS: int = 0
EXIT_RUNTIME_ERROR: int = 1
EXIT_USAGE_ERROR: int = 2

# JSON output configuration.
_PRETTY_JSON_INDENT: int = 2
_COMPACT_JSON_SEPARATORS: tuple[str, str] = (",", ":")

# Subcommand names.
_SCAN_SUBCOMMAND: str = "scan"

# Suggested SARIF file extension (R006).
_SARIF_FILE_EXTENSION: str = ".sarif"

# Error message templates (stderr).
_ERR_REPO_NOT_FOUND: str = "Error: Repository path not found: {path}"
_ERR_REPO_NOT_DIR: str = "Error: Expected a directory: {path}"
_ERR_OUTPUT_DIR_MISSING: str = "Error: Output directory not found: {dir}"
_ERR_OUTPUT_WRITE_FAILED: str = "Error: Cannot write to output file: {path}"
_ERR_INTERNAL: str = "Error: Internal error: {message}"
_WARN_OUTPUT_EXTENSION: str = "Warning: --output file does not have a .sarif extension: {path}"


def expand_env_vars(value: str) -> str:
    """Expand ``${VAR_NAME}`` patterns in a string value.

    Rules:
        * Undefined variables → empty string.
        * Nested expansion is NOT supported.
    """

    def _replace(match: re.Match[str]) -> str:
        return os.environ.get(match.group(1), "")

    return ENV_VAR_PATTERN.sub(_replace, value)


def _expand_optional(value: str | None) -> str | None:
    """Apply :func:`expand_env_vars` to optional string arguments."""
    if value is None:
        return None
    return expand_env_vars(value)


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog=TOOL_INFO.name,
        description="Static analysis scanner for indirect prompt injection.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_INFO.name} {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan_parser = subparsers.add_parser(
        _SCAN_SUBCOMMAND,
        help="Scan a repository for prompt injection.",
        description="Scan a repository directory for indirect prompt injection.",
    )
    scan_parser.add_argument(
        "repo_path",
        type=str,
        help="Path to the repository directory to scan.",
    )
    scan_parser.add_argument(
        "--llm-base-url",
        type=str,
        default=None,
        help="LiteLLM base URL (optional).",
    )
    scan_parser.add_argument(
        "--llm-model",
        type=str,
        default=None,
        help="LLM model name, e.g. gpt-4o-mini (optional).",
    )
    scan_parser.add_argument(
        "--llm-api-token",
        type=str,
        default=None,
        help="LLM API token. Supports ${VAR} expansion.",
    )
    scan_parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to write the SARIF report (default: stdout).",
    )
    scan_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress and summary output (SARIF only).",
    )
    scan_parser.add_argument(
        "--no-gitignore",
        action="store_true",
        help="Disable .gitignore-aware file exclusion.",
    )
    scan_parser.add_argument(
        "--exclude",
        type=str,
        action="append",
        default=None,
        help="Glob pattern to exclude (gitignore syntax). Can be repeated.",
    )

    return parser


def _validate_repo_path(repo_path_str: str) -> Path:
    """Validate the positional ``repo_path`` argument.

    Exits with :data:`EXIT_USAGE_ERROR` (2) on validation failure.
    """
    repo_path = Path(repo_path_str)
    if not repo_path.exists():
        print(_ERR_REPO_NOT_FOUND.format(path=repo_path), file=sys.stderr)
        sys.exit(EXIT_USAGE_ERROR)
    if not repo_path.is_dir():
        print(_ERR_REPO_NOT_DIR.format(path=repo_path), file=sys.stderr)
        sys.exit(EXIT_USAGE_ERROR)
    return repo_path


def _validate_output_path(output_str: str | None) -> Path | None:
    """Validate the ``--output`` argument's parent directory.

    Exits with :data:`EXIT_USAGE_ERROR` (2) when the parent directory does
    not exist. Emits a warning when the file extension is not ``.sarif``.
    """
    if output_str is None:
        return None
    output_path = Path(output_str)
    parent = output_path.parent if str(output_path.parent) else Path(".")
    if not parent.exists() or not parent.is_dir():
        print(_ERR_OUTPUT_DIR_MISSING.format(dir=parent), file=sys.stderr)
        sys.exit(EXIT_USAGE_ERROR)
    if output_path.suffix.lower() != _SARIF_FILE_EXTENSION:
        print(_WARN_OUTPUT_EXTENSION.format(path=output_path), file=sys.stderr)
    return output_path


def _utc_now_iso8601() -> str:
    """Return the current UTC time as an ISO-8601 string with Z suffix."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _print_banner(quiet: bool) -> None:
    """Print the tool banner to stderr unless ``quiet``."""
    if quiet:
        return
    print(
        BANNER_TEMPLATE.format(name=TOOL_INFO.name, version=__version__),
        file=sys.stderr,
        flush=True,
    )


def _print_summary(
    verdicts: list[FinalVerdict],
    *,
    quiet: bool,
    output_path: Path | None,
) -> None:
    """Print the formatted results block to stderr unless ``quiet``."""
    if quiet:
        return
    block_count = sum(1 for v in verdicts if v.decision == VerdictDecision.BLOCK)
    review_count = sum(1 for v in verdicts if v.decision == VerdictDecision.REVIEW_REQUIRED)
    pass_count = sum(1 for v in verdicts if v.decision == VerdictDecision.PASS)
    total = len(verdicts)

    target = str(output_path) if output_path is not None else _SARIF_STDOUT_LABEL
    lines = [
        "",
        _RESULTS_HEADING,
        _RESULTS_RULE_CHAR * _RESULTS_RULE_WIDTH,
        f"Scanned: {total} files",
        f"  BLOCK:           {block_count}",
        f"  REVIEW_REQUIRED: {review_count}",
        f"  PASS:            {pass_count}",
        "",
        f"SARIF report written to {target}",
    ]
    for line in lines:
        print(line, file=sys.stderr)


def _emit_sarif(
    sarif_doc: dict[str, Any],
    output_path: Path | None,
) -> None:
    """Write the SARIF document either to a file (compact) or stdout (pretty)."""
    if output_path is None:
        json.dump(sarif_doc, sys.stdout, indent=_PRETTY_JSON_INDENT)
        sys.stdout.write("\n")
        sys.stdout.flush()
        return

    try:
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(
                sarif_doc,
                handle,
                separators=_COMPACT_JSON_SEPARATORS,
            )
    except OSError as exc:
        print(
            _ERR_OUTPUT_WRITE_FAILED.format(path=output_path),
            file=sys.stderr,
        )
        print(f"  ({exc})", file=sys.stderr)
        sys.exit(EXIT_RUNTIME_ERROR)


def main() -> None:
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command != _SCAN_SUBCOMMAND:
        parser.print_usage(sys.stderr)
        sys.exit(EXIT_USAGE_ERROR)

    # C001: expand ${VAR} in all string arguments before validation.
    repo_path_str: str = expand_env_vars(args.repo_path)
    llm_base_url: str | None = _expand_optional(args.llm_base_url)
    llm_model: str | None = _expand_optional(args.llm_model)
    llm_api_token: str | None = _expand_optional(args.llm_api_token)
    output_str: str | None = _expand_optional(args.output)
    quiet: bool = bool(args.quiet)
    no_gitignore: bool = bool(args.no_gitignore)
    exclude_patterns: list[str] | None = args.exclude

    # Validate inputs.
    repo_path = _validate_repo_path(repo_path_str)
    output_path = _validate_output_path(output_str)

    _print_banner(quiet)

    # Build LLM config — empty strings (e.g. unresolved ${VAR}) collapse to None.
    llm_config = LLMConfig(
        base_url=llm_base_url or None,
        model=llm_model or None,
        api_token=llm_api_token or None,
    )

    start_time = _utc_now_iso8601()
    try:
        verdicts = run_pipeline(
            repo_path,
            llm_config,
            quiet=quiet,
            respect_gitignore=not no_gitignore,
            exclude_patterns=exclude_patterns,
        )
    except Exception as exc:  # noqa: BLE001 — top-level CLI catch-all.
        print(_ERR_INTERNAL.format(message=exc), file=sys.stderr)
        sys.exit(EXIT_RUNTIME_ERROR)
    end_time = _utc_now_iso8601()

    sarif_doc = generate_sarif(
        verdicts=verdicts,
        repo_path=repo_path,
        tool_info=TOOL_INFO,
        start_time=start_time,
        end_time=end_time,
    )

    _emit_sarif(sarif_doc, output_path)
    _print_summary(verdicts, quiet=quiet, output_path=output_path)
    sys.exit(EXIT_SUCCESS)


if __name__ == "__main__":  # pragma: no cover — script entry point.
    main()
