"""CLI entry point for ipi-check scanner."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

from ipi_check import TOOL_INFO, __version__
from ipi_check.core.types import (
    FinalVerdict,
    LLMConfig,
    SarifLimitStats,
    Severity,
    SkillFinalVerdict,
    VerdictDecision,
)
from ipi_check.reporter.human_reporter import (
    DEFAULT_FORMAT,
    FORMAT_JSON,
    FORMAT_MD,
    FORMAT_SARIF,
    REPORT_FORMATS,
    build_json_report,
    ensure_output_extension,
    format_label,
    render_markdown,
    render_table,
)
from ipi_check.reporter.sarif_reporter import (
    DEFAULT_MAX_FINDINGS_PER_FILE,
    DEFAULT_SEVERITY_THRESHOLD,
    generate_sarif_with_stats,
)
from ipi_check.scanner.llm_classifier import LLM_MODEL_ENV, LLM_TIMEOUT_SECONDS
from ipi_check.scanner.pipeline import run_pipeline

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ENV_VAR_PATTERN: re.Pattern[str] = re.compile(r"\$\{([^}]+)\}")

BANNER_TEMPLATE: str = "{name} {version} — Prompt injection and skills security scanner"

# Results summary formatting (per CLI contract).
_RESULTS_HEADING: str = "RESULTS"
_RESULTS_RULE_CHAR: str = "═"
_RESULTS_RULE_WIDTH: int = 35
_SARIF_STDOUT_LABEL: str = "stdout"

# Exit codes (per CLI contract).
EXIT_SUCCESS: int = 0
EXIT_RUNTIME_ERROR: int = 1
EXIT_USAGE_ERROR: int = 2
#: ``--fail-on`` policy tripped by a BLOCK verdict.
EXIT_BLOCK: int = 3
#: ``--fail-on review`` policy tripped by a REVIEW_REQUIRED verdict (no BLOCK).
EXIT_REVIEW: int = 4

# --fail-on policy (IN-17).
#: ``--fail-on`` accepts these three policy levels.
_FAIL_ON_NONE: str = "none"
_FAIL_ON_BLOCK: str = "block"
_FAIL_ON_REVIEW: str = "review"
_FAIL_ON_CHOICES: tuple[str, ...] = (_FAIL_ON_NONE, _FAIL_ON_BLOCK, _FAIL_ON_REVIEW)
#: Message printed (unless --quiet) when the --fail-on policy trips.
_FAIL_ON_MESSAGE: str = (
    "ipi-check: --fail-on={policy} matched — {block} BLOCK and {review} "
    "REVIEW_REQUIRED verdict(s); exiting with code {code}."
)

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
_ERR_OUTPUT_EMPTY: str = "Error: --output path must not be empty"
_ERR_CACHE_DIR_EMPTY: str = "Error: --llm-cache-dir path must not be empty"
_ERR_REPO_PATH_EMPTY: str = (
    "Error: repo_path must not be empty (an undefined ${VAR} expands to '')"
)
_ERR_OUTPUT_WRITE_FAILED: str = "Error: Cannot write to output file: {path}"
_ERR_INTERNAL: str = "Error: Internal error: {message}"
_ERR_MAX_FINDINGS_NEGATIVE: str = "Error: --max-findings-per-file must be >= 0 (got {value})"
_ERR_MAX_LLM_CALLS_NEGATIVE: str = "Error: --max-llm-calls must be >= 0 (got {value})"
_ERR_CACHE_DIR_UNWRITABLE: str = "Error: Cannot create LLM cache directory: {path}"
# Warning emitted when --output does not carry a .sarif extension (R006).
_WARN_OUTPUT_EXTENSION: str = "Warning: --output file does not have a .sarif extension: {path}"

# Scalability / coverage flags (T5.4).
#: Default number of static-analysis worker processes (1 = sequential).
DEFAULT_JOBS: int = 1
#: Error templates for the scalability flags.
_ERR_JOBS_INVALID: str = "Error: --jobs must be >= 1 (got {value})"
_ERR_TIMEOUT_INVALID: str = "Error: --timeout must be a positive number of seconds (got {value})"
_ERR_MAX_FILE_SIZE_INVALID: str = "Error: --max-file-size must be a positive size (got {value})"
_ERR_SEVERITY_INVALID: str = (
    "Error: --severity-threshold must be one of CRITICAL, HIGH, MEDIUM, LOW, NONE (got {value})"
)
#: Size-unit suffix multipliers accepted by --max-file-size (binary multiples).
_SIZE_UNIT_MULTIPLIERS: dict[str, int] = {
    "": 1,
    "b": 1,
    "k": 1024,
    "kb": 1024,
    "kib": 1024,
    "m": 1024 * 1024,
    "mb": 1024 * 1024,
    "mib": 1024 * 1024,
    "g": 1024 * 1024 * 1024,
    "gb": 1024 * 1024 * 1024,
    "gib": 1024 * 1024 * 1024,
}
#: ``<number><optional unit>`` matcher for --max-file-size.
_SIZE_PATTERN: re.Pattern[str] = re.compile(r"(\d+(?:\.\d+)?)\s*([a-z]*)")

# Verbose diagnostics (--debug / -v / --verbose).
#: Logger that owns every ``ipi_check.*`` diagnostic record.
_LOGGER_NAME: str = "ipi_check"
#: Format used for verbose diagnostics forwarded to stderr.
_VERBOSE_LOG_FORMAT: str = "%(levelname)s %(name)s: %(message)s"


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
        help=(
            "LLM model name, e.g. gpt-4o-mini. Required to enable LLM "
            f"classification (env fallback: {LLM_MODEL_ENV}); omit for a "
            "static-only scan."
        ),
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
        help=(
            "Path to write the report (default: stdout). A path without any "
            "extension is auto-completed with the --format extension "
            "(.sarif/.json/.md/.txt)."
        ),
    )
    scan_parser.add_argument(
        "--format",
        type=str,
        default=DEFAULT_FORMAT,
        choices=list(REPORT_FORMATS),
        metavar="{sarif,json,md,table}",
        help=(
            "Report format (default: sarif). 'sarif' emits SARIF v2.1.0 "
            "(unchanged machine format), 'json' a flat JSON summary, 'md' a "
            "grouped Markdown report and 'table' a plain-text table. Only "
            "'sarif' is consumed by code-scanning tools."
        ),
    )
    scan_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress and summary output (the report only is emitted).",
    )
    scan_parser.add_argument(
        "-v",
        "--verbose",
        "--debug",
        dest="verbose",
        action="store_true",
        help=(
            "Emit verbose diagnostics on stderr (LLM configuration, provider "
            "errors, retries). Ignored when --quiet is set."
        ),
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
    scan_parser.add_argument(
        "--max-findings-per-file",
        type=int,
        default=DEFAULT_MAX_FINDINGS_PER_FILE,
        metavar="N",
        help=(
            "Maximum SARIF findings emitted per file (0 = unlimited). "
            f"Default: {DEFAULT_MAX_FINDINGS_PER_FILE}."
        ),
    )
    scan_parser.add_argument(
        "--max-llm-calls",
        type=int,
        default=0,
        metavar="N",
        help=(
            "Maximum number of LLM API calls per scan (0 = unlimited). "
            "Once reached, remaining files fall back to static analysis."
        ),
    )
    scan_parser.add_argument(
        "--llm-cache-dir",
        type=str,
        default=None,
        metavar="PATH",
        help=(
            "Directory for the LLM response cache (enables caching: a repeated "
            "scan of unchanged files issues no new LLM calls). Entries are "
            "keyed to the API credential, so a cache shared with or planted by "
            "untrusted parties never hits. Supports ${VAR} expansion; also "
            "settable via IPI_CHECK_LLM_CACHE_DIR."
        ),
    )

    scan_parser.add_argument(
        "--jobs",
        type=int,
        default=DEFAULT_JOBS,
        metavar="N",
        help=(
            "Number of worker processes for the static-analysis passes "
            f"(default: {DEFAULT_JOBS} = sequential). Values > 1 parallelise "
            "per-file analysis across processes; results are identical."
        ),
    )
    scan_parser.add_argument(
        "--max-file-size",
        type=str,
        default=None,
        metavar="SIZE",
        help=(
            "Skip files larger than SIZE, e.g. 512KB, 1.5MB, 10MB or a plain "
            "byte count. Supports ${VAR} expansion. Default: 10MB."
        ),
    )
    scan_parser.add_argument(
        "--severity-threshold",
        type=str,
        default=DEFAULT_SEVERITY_THRESHOLD.name,
        choices=[severity.name for severity in Severity],
        metavar="{CRITICAL,HIGH,MEDIUM,LOW,NONE}",
        help=(
            "Only emit individual findings at or above this severity "
            f"(default: {DEFAULT_SEVERITY_THRESHOLD.name} = emit every finding). "
            "Skill-level results are unaffected."
        ),
    )
    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=float(LLM_TIMEOUT_SECONDS),
        metavar="SECONDS",
        help=(
            "Per-LLM-call timeout in seconds "
            f"(default: {LLM_TIMEOUT_SECONDS})."
        ),
    )
    scan_parser.add_argument(
        "--fail-on",
        type=str,
        default=_FAIL_ON_NONE,
        choices=list(_FAIL_ON_CHOICES),
        metavar="{none,block,review}",
        help=(
            "Exit-code policy: choose which verdicts make the scan fail. "
            "'none' (default) always exits 0 on a completed scan — findings "
            "live in the SARIF report (C002). 'block' exits 3 when any BLOCK "
            "verdict is present; 'review' exits 3 on a BLOCK and 4 on a "
            "REVIEW_REQUIRED (without BLOCK). Runtime (1) and usage (2) "
            "errors keep their existing codes."
        ),
    )

    return parser


def _validate_repo_path(repo_path_str: str) -> Path:
    """Validate the positional ``repo_path`` argument.

    Exits with :data:`EXIT_USAGE_ERROR` (2) on validation failure. An empty
    (or whitespace-only) value is rejected explicitly: an undefined
    ``${VAR}`` expands to ``""`` and ``Path("")`` silently means the current
    working directory, which would scan the wrong tree with a clean-looking
    report.
    """
    if not repo_path_str.strip():
        print(_ERR_REPO_PATH_EMPTY, file=sys.stderr)
        sys.exit(EXIT_USAGE_ERROR)
    repo_path = Path(repo_path_str)
    if not repo_path.exists():
        print(_ERR_REPO_NOT_FOUND.format(path=repo_path), file=sys.stderr)
        sys.exit(EXIT_USAGE_ERROR)
    if not repo_path.is_dir():
        print(_ERR_REPO_NOT_DIR.format(path=repo_path), file=sys.stderr)
        sys.exit(EXIT_USAGE_ERROR)
    return repo_path


def _validate_output_path(
    output_str: str | None,
    report_format: str = DEFAULT_FORMAT,
) -> Path | None:
    """Validate the ``--output`` argument's parent directory.

    A path without any extension is auto-completed with the ``--format``
    extension (``results`` → ``results.sarif`` for the default SARIF format).
    Exits with :data:`EXIT_USAGE_ERROR` (2) when the parent directory does not
    exist. Emits a warning when the SARIF format is requested and the file
    extension is not ``.sarif`` (R006).
    """
    if output_str is None:
        return None
    if not output_str.strip():
        # An empty --output (e.g. an undefined ${VAR} expansion) must be a
        # clean usage error, not a ValueError traceback from Path.with_name.
        print(_ERR_OUTPUT_EMPTY, file=sys.stderr)
        sys.exit(EXIT_USAGE_ERROR)
    output_path = ensure_output_extension(Path(output_str), report_format)
    parent = output_path.parent if str(output_path.parent) else Path(".")
    if not parent.exists() or not parent.is_dir():
        print(_ERR_OUTPUT_DIR_MISSING.format(dir=parent), file=sys.stderr)
        sys.exit(EXIT_USAGE_ERROR)
    if report_format == FORMAT_SARIF and output_path.suffix.lower() != _SARIF_FILE_EXTENSION:
        print(_WARN_OUTPUT_EXTENSION.format(path=output_path), file=sys.stderr)
    return output_path


def _validate_max_findings_per_file(value: int) -> int:
    """Validate the ``--max-findings-per-file`` argument.

    Exits with :data:`EXIT_USAGE_ERROR` (2) when the value is negative.
    ``0`` is allowed and disables the per-file cap.
    """
    if value < 0:
        print(_ERR_MAX_FINDINGS_NEGATIVE.format(value=value), file=sys.stderr)
        sys.exit(EXIT_USAGE_ERROR)
    return value


def _validate_max_llm_calls(value: int) -> int:
    """Validate the ``--max-llm-calls`` argument.

    Exits with :data:`EXIT_USAGE_ERROR` (2) when the value is negative.
    ``0`` is allowed and disables the call cap (unlimited calls).
    """
    if value < 0:
        print(_ERR_MAX_LLM_CALLS_NEGATIVE.format(value=value), file=sys.stderr)
        sys.exit(EXIT_USAGE_ERROR)
    return value


def parse_file_size(value: str) -> int:
    """Parse a human-readable byte size into an integer.

    Accepts an optional case-insensitive unit suffix (``B``/``KB``/``MB``/``GB``
    and the binary aliases ``KiB``/``MiB``/``GiB``; a bare number means bytes).
    Fractional values are allowed (``1.5MB``).

    Raises:
        ValueError: when the value is malformed or not strictly positive.
    """
    match = _SIZE_PATTERN.fullmatch(value.strip().lower())
    if match is None:
        raise ValueError(value)
    number = float(match.group(1))
    multiplier = _SIZE_UNIT_MULTIPLIERS.get(match.group(2))
    if multiplier is None:
        raise ValueError(value)
    size = int(number * multiplier)
    if size <= 0:
        raise ValueError(value)
    return size


def _validate_jobs(value: int) -> int:
    """Validate ``--jobs``; exits with :data:`EXIT_USAGE_ERROR` when < 1."""
    if value < 1:
        print(_ERR_JOBS_INVALID.format(value=value), file=sys.stderr)
        sys.exit(EXIT_USAGE_ERROR)
    return value


def _validate_timeout(value: float) -> float:
    """Validate ``--timeout``; exits with :data:`EXIT_USAGE_ERROR` when <= 0."""
    if value <= 0:
        print(_ERR_TIMEOUT_INVALID.format(value=value), file=sys.stderr)
        sys.exit(EXIT_USAGE_ERROR)
    return value


def _parse_max_file_size(value: str | None) -> int | None:
    """Validate ``--max-file-size``; exits with code 2 when unparsable.

    ``None`` (flag omitted) leaves the pipeline's default (10 MB) in force.
    """
    if value is None:
        return None
    try:
        return parse_file_size(value)
    except ValueError:
        print(_ERR_MAX_FILE_SIZE_INVALID.format(value=value), file=sys.stderr)
        sys.exit(EXIT_USAGE_ERROR)


def _parse_severity_threshold(value: str) -> Severity:
    """Map the ``--severity-threshold`` argument to a :class:`Severity`."""
    try:
        return Severity[value.upper()]
    except KeyError:
        print(_ERR_SEVERITY_INVALID.format(value=value), file=sys.stderr)
        sys.exit(EXIT_USAGE_ERROR)


def _validate_cache_dir(cache_dir_str: str | None) -> Path | None:
    """Validate (and create) the ``--llm-cache-dir`` directory.

    Exits with :data:`EXIT_USAGE_ERROR` (2) when the directory cannot be
    created. ``None`` (flag omitted) leaves the response cache disabled.
    """
    if cache_dir_str is None:
        return None
    if not cache_dir_str.strip():
        # An empty --llm-cache-dir (e.g. an undefined ${VAR} expansion) must
        # not silently resolve to the current working directory.
        print(_ERR_CACHE_DIR_EMPTY, file=sys.stderr)
        sys.exit(EXIT_USAGE_ERROR)
    cache_dir = Path(cache_dir_str)
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        print(_ERR_CACHE_DIR_UNWRITABLE.format(path=cache_dir), file=sys.stderr)
        sys.exit(EXIT_USAGE_ERROR)
    return cache_dir


def _utc_now_iso8601() -> str:
    """Return the current UTC time as an ISO-8601 string with Z suffix."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _enable_verbose_logging() -> Callable[[], None]:
    """Route ``ipi_check.*`` diagnostics to stderr at DEBUG level.

    Installed when ``--verbose`` / ``--debug`` / ``-v`` is given. Provider
    transport errors and retry attempts (see
    :mod:`ipi_check.scanner.llm_classifier`) then surface on stderr, while the
    SARIF document is unaffected and still goes to stdout.

    Returns a teardown callback that detaches the handler and restores the
    logger's previous level, so consecutive invocations neither duplicate
    output nor leak the DEBUG level into unrelated runs.
    """
    verbose_logger = logging.getLogger(_LOGGER_NAME)
    previous_level = verbose_logger.level
    verbose_logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(_VERBOSE_LOG_FORMAT))
    verbose_logger.addHandler(handler)

    def _teardown() -> None:
        verbose_logger.removeHandler(handler)
        verbose_logger.setLevel(previous_level)

    return _teardown


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
    skill_verdicts: list[SkillFinalVerdict] | None = None,
    suppression: SarifLimitStats | None = None,
    report_label: str = "SARIF",
) -> None:
    """Print the formatted results block to stderr unless ``quiet``."""
    if quiet:
        return
    block_count = sum(1 for v in verdicts if v.decision == VerdictDecision.BLOCK)
    review_count = sum(1 for v in verdicts if v.decision == VerdictDecision.REVIEW_REQUIRED)
    pass_count = sum(1 for v in verdicts if v.decision == VerdictDecision.PASS)
    total = len(verdicts)

    # Skill counts
    skill_block = 0
    skill_review = 0
    skill_pass = 0
    if skill_verdicts:
        skill_block = sum(1 for v in skill_verdicts if v.decision == VerdictDecision.BLOCK)
        skill_review = sum(
            1 for v in skill_verdicts if v.decision == VerdictDecision.REVIEW_REQUIRED
        )
        skill_pass = sum(1 for v in skill_verdicts if v.decision == VerdictDecision.PASS)

    target = str(output_path) if output_path is not None else _SARIF_STDOUT_LABEL
    scanned_line = f"Scanned: {total} files"
    if skill_verdicts:
        scanned_line += f" + {len(skill_verdicts)} skills"
    lines = [
        "",
        _RESULTS_HEADING,
        _RESULTS_RULE_CHAR * _RESULTS_RULE_WIDTH,
        scanned_line,
        f"  BLOCK:           {block_count}",
        f"  REVIEW_REQUIRED: {review_count}",
        f"  PASS:            {pass_count}",
    ]
    if skill_verdicts:
        lines.append(f"  Skills: {skill_block} BLOCK, {skill_review} REVIEW, {skill_pass} PASS")
    suppressed_total = suppression.total_suppressed if suppression is not None else 0
    if suppressed_total > 0 and suppression is not None:
        detail = (
            f"{suppression.duplicates_removed} duplicates,"
            f" {suppression.capped_removed} over cap"
        )
        if suppression.below_threshold_removed:
            detail += f", {suppression.below_threshold_removed} below threshold"
        lines.append(f"  Suppressed:      {suppressed_total} findings ({detail})")
    lines += [
        "",
        f"{report_label} report written to {target}",
    ]
    for line in lines:
        print(line, file=sys.stderr)


def _policy_exit_code(
    fail_on: str,
    verdicts: list[FinalVerdict],
    skill_verdicts: list[SkillFinalVerdict],
) -> int:
    """Map the ``--fail-on`` policy to the process exit code.

    ``none`` never fails (preserves the C002 contract: exit ``0`` means "scan
    completed", not "no findings"). ``block`` fails with
    :data:`EXIT_BLOCK` when any BLOCK verdict is present. ``review`` fails on
    the same BLOCK (still :data:`EXIT_BLOCK`) and additionally fails with
    :data:`EXIT_REVIEW` when only REVIEW_REQUIRED verdicts are present.
    Skill-unit verdicts count exactly like file verdicts.
    """
    if fail_on == _FAIL_ON_NONE:
        return EXIT_SUCCESS
    decisions = [v.decision for v in verdicts]
    decisions += [v.decision for v in skill_verdicts]
    has_block = any(d is VerdictDecision.BLOCK for d in decisions)
    has_review = any(d is VerdictDecision.REVIEW_REQUIRED for d in decisions)
    if has_block:
        return EXIT_BLOCK
    if fail_on == _FAIL_ON_REVIEW and has_review:
        return EXIT_REVIEW
    return EXIT_SUCCESS


def _print_fail_on_message(
    *,
    fail_on: str,
    exit_code: int,
    verdicts: list[FinalVerdict],
    skill_verdicts: list[SkillFinalVerdict],
    quiet: bool,
) -> None:
    """Explain a tripped ``--fail-on`` policy on stderr (unless ``quiet``)."""
    if quiet:
        return
    decisions = [v.decision for v in verdicts]
    decisions += [v.decision for v in skill_verdicts]
    block_count = sum(1 for d in decisions if d is VerdictDecision.BLOCK)
    review_count = sum(1 for d in decisions if d is VerdictDecision.REVIEW_REQUIRED)
    print(
        _FAIL_ON_MESSAGE.format(
            policy=fail_on,
            block=block_count,
            review=review_count,
            code=exit_code,
        ),
        file=sys.stderr,
    )


def _emit_json_document(
    document: dict[str, Any],
    output_path: Path | None,
) -> None:
    """Write a JSON report either to a file (compact) or stdout (pretty)."""
    if output_path is None:
        json.dump(document, sys.stdout, indent=_PRETTY_JSON_INDENT)
        sys.stdout.write("\n")
        sys.stdout.flush()
        return

    try:
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(
                document,
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


def _emit_text(text: str, output_path: Path | None) -> None:
    """Write a text report (Markdown / table) to a file or stdout."""
    if output_path is None:
        sys.stdout.write(text)
        sys.stdout.flush()
        return

    try:
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(text)
    except OSError as exc:
        print(
            _ERR_OUTPUT_WRITE_FAILED.format(path=output_path),
            file=sys.stderr,
        )
        print(f"  ({exc})", file=sys.stderr)
        sys.exit(EXIT_RUNTIME_ERROR)


def _emit_report(
    *,
    report_format: str,
    sarif_doc: dict[str, Any],
    verdicts: list[FinalVerdict],
    skill_verdicts: list[SkillFinalVerdict],
    stats: SarifLimitStats,
    output_path: Path | None,
) -> None:
    """Dispatch to the renderer selected by ``--format`` (T5.2 / IN-18).

    ``sarif`` stays the default and emits the unchanged SARIF document; the
    other formats render from the verdict model via
    :mod:`ipi_check.reporter.human_reporter`.
    """
    if report_format == FORMAT_SARIF:
        _emit_json_document(sarif_doc, output_path)
    elif report_format == FORMAT_JSON:
        _emit_json_document(
            build_json_report(verdicts, skill_verdicts, stats=stats),
            output_path,
        )
    elif report_format == FORMAT_MD:
        _emit_text(render_markdown(verdicts, skill_verdicts, stats=stats), output_path)
    else:  # report_format == FORMAT_TABLE
        _emit_text(render_table(verdicts, skill_verdicts, stats=stats), output_path)


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
    llm_cache_dir_str: str | None = _expand_optional(args.llm_cache_dir)
    max_file_size_str: str | None = _expand_optional(args.max_file_size)
    quiet: bool = bool(args.quiet)
    verbose: bool = bool(args.verbose)
    no_gitignore: bool = bool(args.no_gitignore)
    exclude_patterns: list[str] | None = (
        [expand_env_vars(p) for p in args.exclude] if args.exclude else None
    )

    # Validate inputs.
    repo_path = _validate_repo_path(repo_path_str)
    report_format: str = args.format
    output_path = _validate_output_path(output_str, report_format)
    max_findings_per_file = _validate_max_findings_per_file(args.max_findings_per_file)
    max_llm_calls = _validate_max_llm_calls(args.max_llm_calls)
    llm_cache_dir = _validate_cache_dir(llm_cache_dir_str)
    jobs = _validate_jobs(args.jobs)
    timeout = _validate_timeout(args.timeout)
    max_file_size = _parse_max_file_size(max_file_size_str)
    severity_threshold = _parse_severity_threshold(args.severity_threshold)
    fail_on: str = args.fail_on

    # Suppress Python warnings from ipi_check internals when --quiet is set,
    # ensuring no non-SARIF output reaches stderr.
    if quiet:
        import warnings as _warnings  # noqa: PLC0415

        _warnings.filterwarnings("ignore", module=r"ipi_check\..*")

    _print_banner(quiet)

    # Verbose diagnostics go to stderr; suppressed entirely by --quiet.
    teardown_verbose: Callable[[], None] | None = (
        _enable_verbose_logging() if verbose and not quiet else None
    )

    # Build LLM config — empty strings (e.g. unresolved ${VAR}) collapse to None.
    llm_config = LLMConfig(
        base_url=llm_base_url or None,
        model=llm_model or None,
        api_token=llm_api_token or None,
        timeout=timeout,
    )

    start_time = _utc_now_iso8601()
    try:
        verdicts, skill_verdicts = run_pipeline(
            repo_path,
            llm_config,
            quiet=quiet,
            verbose=verbose,
            respect_gitignore=not no_gitignore,
            exclude_patterns=exclude_patterns,
            max_llm_calls=max_llm_calls,
            llm_cache_dir=llm_cache_dir,
            jobs=jobs,
            max_file_size=max_file_size,
        )
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(EXIT_USAGE_ERROR)
    except Exception as exc:  # noqa: BLE001 — top-level CLI catch-all.
        print(_ERR_INTERNAL.format(message=exc), file=sys.stderr)
        sys.exit(EXIT_RUNTIME_ERROR)
    finally:
        if teardown_verbose is not None:
            teardown_verbose()
    end_time = _utc_now_iso8601()

    sarif_doc, limit_stats = generate_sarif_with_stats(
        verdicts=verdicts,
        repo_path=repo_path,
        tool_info=TOOL_INFO,
        start_time=start_time,
        end_time=end_time,
        skill_verdicts=skill_verdicts,
        max_findings_per_file=max_findings_per_file,
        severity_threshold=severity_threshold,
    )

    _emit_report(
        report_format=report_format,
        sarif_doc=sarif_doc,
        verdicts=verdicts,
        skill_verdicts=skill_verdicts,
        stats=limit_stats,
        output_path=output_path,
    )
    _print_summary(
        verdicts,
        quiet=quiet,
        output_path=output_path,
        skill_verdicts=skill_verdicts,
        suppression=limit_stats,
        report_label=format_label(report_format),
    )

    # --fail-on exit-code policy (IN-17). Default "none" keeps the C002
    # contract: a completed scan exits 0 regardless of findings.
    policy_code = _policy_exit_code(fail_on, verdicts, skill_verdicts)
    if policy_code != EXIT_SUCCESS:
        _print_fail_on_message(
            fail_on=fail_on,
            exit_code=policy_code,
            verdicts=verdicts,
            skill_verdicts=skill_verdicts,
            quiet=quiet,
        )
    sys.exit(policy_code)


if __name__ == "__main__":  # pragma: no cover — script entry point.
    main()
