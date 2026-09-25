#!/usr/bin/env python3
"""Validate a SARIF report against the SARIF 2.1.0 JSON Schema — roadmap T6.3 / QA-3.

The CI ``self-scan`` job first runs ``ipi-check scan .`` over this repository
(the "dogfood" scan) and then feeds the emitted report to this script. A schema
violation is a **hard failure** — :func:`main` exits non-zero so an invalid
report stops the build (assumption QA-3: "невалидный SARIF останавливает
сборку").

The schema is the *same vendored copy the test-suite validates against*
(``tests/fixtures/sarif-2.1.0-schema.json``): the SARIF-SDK flavoured schema,
which — unlike the JSON-Schema-Store copy — correctly declares ``message.text``.
Keeping a single copy guarantees the CI gate and the tests agree on what
"valid" means.

Exit codes (script-local; the scanner CLI's codes are unrelated):

* ``0`` — the document is valid SARIF 2.1.0;
* ``1`` — the document is invalid (schema violation, bad JSON, or unreadable);
* ``2`` — usage error (handled by :mod:`argparse`).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "tests" / "fixtures" / "sarif-2.1.0-schema.json"

# A `uniqueItems` violation echoes the whole offending array; cap the per-error
# message so a single violation cannot flood the CI log.
_MAX_ERROR_MESSAGE_CHARS = 300


def load_schema(schema_path: Path = SCHEMA_PATH) -> dict[str, Any]:
    """Load a SARIF JSON Schema from disk."""
    with schema_path.open(encoding="utf-8") as handle:
        schema: dict[str, Any] = json.load(handle)
    return schema


def _error_sort_key(error: Any) -> tuple[str, ...]:
    return tuple(str(part) for part in error.absolute_path)


def _format_error(error: Any) -> str:
    location = "/".join(str(part) for part in error.absolute_path) or "<root>"
    message = error.message
    if len(message) > _MAX_ERROR_MESSAGE_CHARS:
        message = message[:_MAX_ERROR_MESSAGE_CHARS] + "... (truncated)"
    return f"{location}: {message}"


def validate_document(
    document: dict[str, Any],
    schema: dict[str, Any],
) -> list[str]:
    """Return human-readable schema violations; an empty list means valid.

    ``jsonschema`` is imported lazily so that importing this module (as the test
    suite does, by file path) never requires the optional dependency up front.
    """
    import jsonschema

    validator_cls = jsonschema.validators.validator_for(schema)
    validator = validator_cls(schema)
    errors = sorted(validator.iter_errors(document), key=_error_sort_key)
    return [_format_error(error) for error in errors]


def validate_sarif_file(
    sarif_path: Path,
    schema_path: Path = SCHEMA_PATH,
) -> list[str]:
    """Load ``sarif_path`` and validate it against the SARIF schema."""
    with sarif_path.open(encoding="utf-8") as handle:
        document: dict[str, Any] = json.load(handle)
    return validate_document(document, load_schema(schema_path))


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: validate one SARIF file and report the outcome."""
    parser = argparse.ArgumentParser(
        description="Validate a SARIF report against the SARIF 2.1.0 JSON Schema.",
    )
    parser.add_argument("sarif", type=Path, help="path to the SARIF report to validate")
    parser.add_argument(
        "--schema",
        type=Path,
        default=SCHEMA_PATH,
        help="path to the SARIF JSON Schema (defaults to the vendored 2.1.0 schema)",
    )
    args = parser.parse_args(argv)

    try:
        errors = validate_sarif_file(args.sarif, args.schema)
    except ModuleNotFoundError:
        print(
            "error: the 'jsonschema' package is required to validate SARIF "
            "(install it with `pip install jsonschema`).",
            file=sys.stderr,
        )
        return 1
    except OSError as exc:
        print(f"error: cannot read {exc.filename!r}: {exc.strerror}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"error: {args.sarif} is not valid JSON: {exc}", file=sys.stderr)
        return 1

    if errors:
        print(
            f"error: {args.sarif} is not a valid SARIF 2.1.0 document "
            f"({len(errors)} schema violation(s)):",
            file=sys.stderr,
        )
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"ok: {args.sarif} is valid SARIF 2.1.0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
