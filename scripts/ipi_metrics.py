#!/usr/bin/env python3
"""Labeled-corpus precision/recall/F1 metrics with a CI gate — roadmap T6.2 / QA-2, QA-4.

The scanner's deterministic static analysis (byte rules, injection/skill
patterns, semantic heuristics and confidence fusion) is exercised against a
*labeled* corpus. A manifest declares every sample as either ``malicious``
(ground truth: an attack that MUST be detected) or ``benign`` (ground truth:
legitimate content that MUST NOT be over-flagged). Scanning the corpus yields a
confusion matrix and the precision / recall / F1 triplet.

A **sample** is either a *directory* scanned as its own repository root, or a
single *file* staged into a temporary root — needed for documents that are only
discovered under an agent-instruction filename such as ``AGENTS.md``. A sample
is counted as *detected* (a predicted positive) when the pipeline emits at least
one ``BLOCK`` verdict for it; ``PASS`` and ``REVIEW_REQUIRED`` are **not**
"flagged".

The gate fails the build (exit code :data:`EXIT_GATE_FAILED`) when:

* recall on the malicious samples drops below ``--min-recall`` (default 100%),
* precision drops below ``--min-precision`` (default 100%), or
* any metric regresses below the published baseline
  (``samples/metrics-corpus/baseline.json``) — this is what fails a PR that
  lowered precision.

Only deterministic static analysis is used (``llm_config=None``): a merge gate
must never depend on a network model. See ``samples/metrics-corpus/README.md``.

Exit codes (script-local; the scanner CLI's codes are unrelated):

* ``0`` — metrics computed, every gate satisfied;
* ``1`` — a gate failed (precision/recall regression);
* ``2`` — usage error (missing/invalid manifest or baseline).
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ipi_check.core.types import VerdictDecision
from ipi_check.scanner.pipeline import run_pipeline

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ipi_check.core.types import FinalVerdict, SkillFinalVerdict

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Ground-truth labels a manifest entry may carry.
LABEL_MALICIOUS: str = "malicious"
LABEL_BENIGN: str = "benign"
VALID_LABELS: tuple[str, ...] = (LABEL_MALICIOUS, LABEL_BENIGN)

#: Default gate floors — 100% recall on malicious samples and zero benign
#: BLOCK verdicts (precision 100%), per roadmap §5 ("BLOCK-файлов (FP) → 0").
DEFAULT_MIN_PRECISION: float = 1.0
DEFAULT_MIN_RECALL: float = 1.0

#: Script exit codes.
EXIT_OK: int = 0
EXIT_GATE_FAILED: int = 1
EXIT_USAGE_ERROR: int = 2

#: Tolerance for float comparisons, so a mathematically equal metric
#: (e.g. ``1.0`` reconstructed from integer counts) never trips the gate.
FLOAT_EPSILON: float = 1e-9

#: A directory carrying this marker is taken as the repository root when the
#: manifest does not declare an explicit ``base``.
_REPO_ROOT_MARKER: str = "pyproject.toml"


def _script_root() -> Path:
    """Return the repository root as seen from this script (``scripts/..``)."""
    return Path(__file__).resolve().parent.parent


DEFAULT_MANIFEST_PATH: Path = _script_root() / "samples" / "metrics-corpus" / "manifest.json"
DEFAULT_BASELINE_PATH: Path = _script_root() / "samples" / "metrics-corpus" / "baseline.json"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class CorpusError(Exception):
    """A usage-level problem: unreadable/invalid manifest, baseline or sample."""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Sample:
    """One labeled corpus sample.

    Exactly one of :attr:`root` (a directory scanned as a repo root) or
    :attr:`file` (a single file staged into a temporary root) is set.
    :attr:`as_name` overrides the staged filename (e.g. a document that must be
    discovered as ``AGENTS.md``).
    """

    sample_id: str
    label: str
    root: str | None = None
    file: str | None = None
    as_name: str | None = None

    @property
    def is_malicious(self) -> bool:
        """True when the ground-truth label is ``malicious``."""
        return self.label == LABEL_MALICIOUS


@dataclass(frozen=True)
class Corpus:
    """A parsed metrics-corpus manifest."""

    samples: tuple[Sample, ...]
    base_dir: Path
    path: Path

    @property
    def positives(self) -> tuple[Sample, ...]:
        """The malicious (ground-truth positive) samples."""
        return tuple(s for s in self.samples if s.is_malicious)

    @property
    def negatives(self) -> tuple[Sample, ...]:
        """The benign (ground-truth negative) samples."""
        return tuple(s for s in self.samples if not s.is_malicious)


@dataclass(frozen=True)
class SampleOutcome:
    """The scan result for one sample, reconciled with its ground-truth label."""

    sample_id: str
    label: str
    flagged: bool
    blocked_units: tuple[str, ...]
    scanned_units: int

    @property
    def expected_positive(self) -> bool:
        """True when this sample is ground-truth malicious."""
        return self.label == LABEL_MALICIOUS

    @property
    def kind(self) -> str:
        """Confusion-matrix cell this outcome falls into (``TP``/``FP``/``FN``/``TN``)."""
        if self.expected_positive:
            return "TP" if self.flagged else "FN"
        return "FP" if self.flagged else "TN"


@dataclass(frozen=True)
class Metrics:
    """A confusion matrix plus the derived precision / recall / F1 triplet."""

    tp: int
    fp: int
    fn: int
    tn: int
    precision: float
    recall: float
    f1: float

    @property
    def sample_count(self) -> int:
        """Total number of scored samples."""
        return self.tp + self.fp + self.fn + self.tn


@dataclass(frozen=True)
class GateFailure:
    """A single violated gate, rendered in the report and exit status."""

    metric: str
    actual: float
    threshold: float
    reason: str


@dataclass(frozen=True)
class Baseline:
    """A published baseline metric read back from ``baseline.json``."""

    precision: float
    recall: float
    f1: float
    tp: int
    fp: int
    fn: int
    tn: int
    samples: int


# ---------------------------------------------------------------------------
# Metric arithmetic
# ---------------------------------------------------------------------------

def _safe_ratio(numerator: float, denominator: float) -> float:
    """Divide ``numerator`` by ``denominator``, returning ``0.0`` when the latter is 0.

    Mirrors ``scikit-learn``'s ``zero_division=0`` default: an undefined metric
    (no positive predictions, or no positive ground truth) is reported as ``0.0``
    rather than raising.
    """
    if denominator == 0:
        return 0.0
    return numerator / denominator


def compute_metrics(outcomes: Sequence[SampleOutcome]) -> Metrics:
    """Build the confusion matrix and precision/recall/F1 from sample outcomes."""
    tp = fp = fn = tn = 0
    for outcome in outcomes:
        if outcome.expected_positive:
            if outcome.flagged:
                tp += 1
            else:
                fn += 1
        elif outcome.flagged:
            fp += 1
        else:
            tn += 1
    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    f1 = _safe_ratio(2 * precision * recall, precision + recall)
    return Metrics(tp=tp, fp=fp, fn=fn, tn=tn, precision=precision, recall=recall, f1=f1)


def check_gates(
    metrics: Metrics,
    *,
    min_precision: float,
    min_recall: float,
    min_f1: float | None = None,
    baseline: Baseline | None = None,
) -> list[GateFailure]:
    """Return every violated gate for ``metrics`` (empty list = all satisfied).

    The explicit ``min_*`` floors are absolute; when ``baseline`` is supplied the
    current metrics must additionally not regress below it — that comparison is
    what implements "CI fails a PR that lowered precision".
    """
    failures: list[GateFailure] = []
    if metrics.recall + FLOAT_EPSILON < min_recall:
        failures.append(
            GateFailure("recall", metrics.recall, min_recall, "recall below the required floor")
        )
    if metrics.precision + FLOAT_EPSILON < min_precision:
        failures.append(
            GateFailure(
                "precision",
                metrics.precision,
                min_precision,
                "precision below the required floor",
            )
        )
    if min_f1 is not None and metrics.f1 + FLOAT_EPSILON < min_f1:
        failures.append(GateFailure("f1", metrics.f1, min_f1, "F1 below the required floor"))
    if baseline is not None:
        if metrics.precision + FLOAT_EPSILON < baseline.precision:
            failures.append(
                GateFailure(
                    "precision",
                    metrics.precision,
                    baseline.precision,
                    "precision regressed below the published baseline",
                )
            )
        if metrics.recall + FLOAT_EPSILON < baseline.recall:
            failures.append(
                GateFailure(
                    "recall",
                    metrics.recall,
                    baseline.recall,
                    "recall regressed below the published baseline",
                )
            )
    return failures


# ---------------------------------------------------------------------------
# Manifest parsing
# ---------------------------------------------------------------------------

def _resolve_base(manifest_path: Path, declared: str | None) -> Path:
    """Resolve the directory corpus paths are relative to.

    An explicit ``base`` is resolved against the manifest's directory; otherwise
    the nearest ancestor holding a ``pyproject.toml`` is used (the repo root), so
    manifest entries read as ordinary repo-relative paths.
    """
    if declared:
        return (manifest_path.parent / declared).resolve()
    for parent in manifest_path.parents:
        if (parent / _REPO_ROOT_MARKER).is_file():
            return parent
    return manifest_path.parent


def _parse_sample(entry: object, index: int) -> Sample:
    """Validate and convert one raw manifest entry into a :class:`Sample`."""
    if not isinstance(entry, dict):
        raise CorpusError(f"sample #{index} must be a JSON object")
    sample_id = entry.get("id")
    if not isinstance(sample_id, str) or not sample_id:
        raise CorpusError(f"sample #{index} is missing a non-empty 'id'")
    label = entry.get("label")
    if label not in VALID_LABELS:
        raise CorpusError(
            f"sample {sample_id!r}: 'label' must be one of {VALID_LABELS}, got {label!r}"
        )
    root = entry.get("root")
    file = entry.get("file")
    as_name = entry.get("as")
    if (root is None) == (file is None):
        raise CorpusError(f"sample {sample_id!r}: set exactly one of 'root' or 'file'")
    for value, key in ((root, "root"), (file, "file"), (as_name, "as")):
        if value is not None and (not isinstance(value, str) or not value):
            # An empty string must be rejected like a missing value: an empty
            # 'root' would resolve to the corpus base directory and silently
            # scan the whole repository as this one sample.
            raise CorpusError(f"sample {sample_id!r}: {key!r} must be a non-empty string")
    return Sample(sample_id=sample_id, label=label, root=root, file=file, as_name=as_name)


def load_manifest(path: Path) -> Corpus:
    """Parse and validate a metrics-corpus manifest, or raise :class:`CorpusError`."""
    if not path.is_file():
        raise CorpusError(f"manifest not found: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CorpusError(f"cannot read manifest {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise CorpusError(f"manifest {path}: root must be a JSON object")
    declared_base = raw.get("base")
    if declared_base is not None and not isinstance(declared_base, str):
        raise CorpusError(f"manifest {path}: 'base' must be a string")
    entries = raw.get("samples")
    if not isinstance(entries, list) or not entries:
        raise CorpusError(f"manifest {path}: 'samples' must be a non-empty array")
    samples = tuple(_parse_sample(entry, index) for index, entry in enumerate(entries))
    seen: set[str] = set()
    for sample in samples:
        if sample.sample_id in seen:
            raise CorpusError(f"manifest {path}: duplicate sample id {sample.sample_id!r}")
        seen.add(sample.sample_id)
    return Corpus(samples=samples, base_dir=_resolve_base(path, declared_base), path=path)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def _blocked_units(
    verdicts: Sequence[FinalVerdict],
    skill_verdicts: Sequence[SkillFinalVerdict],
) -> tuple[tuple[str, ...], int]:
    """Return (blocked unit ids, total units scanned) for a scan result."""
    blocked: list[str] = []
    for verdict in verdicts:
        if verdict.decision is VerdictDecision.BLOCK:
            blocked.append(f"file:{verdict.file.relative_path}")
    for skill in skill_verdicts:
        if skill.decision is VerdictDecision.BLOCK:
            name = skill.skill.frontmatter.name or str(skill.skill.root)
            blocked.append(f"skill:{name}")
    return tuple(blocked), len(verdicts) + len(skill_verdicts)


def _scan(root: Path) -> tuple[tuple[str, ...], int]:
    """Run the static pipeline over ``root`` and summarise its BLOCK verdicts."""
    verdicts, skill_verdicts = run_pipeline(root, llm_config=None, quiet=True)
    return _blocked_units(verdicts, skill_verdicts)


def evaluate_sample(sample: Sample, base_dir: Path) -> SampleOutcome:
    """Scan one sample and reconcile the result with its ground-truth label."""
    if sample.root is not None:
        root = (base_dir / sample.root).resolve()
        if not root.is_dir():
            raise CorpusError(f"sample {sample.sample_id!r}: root directory not found: {root}")
        blocked, scanned = _scan(root)
    else:
        assert sample.file is not None  # guaranteed by _parse_sample
        source = (base_dir / sample.file).resolve()
        if not source.is_file():
            raise CorpusError(f"sample {sample.sample_id!r}: file not found: {source}")
        staged_name = sample.as_name or source.name
        with tempfile.TemporaryDirectory(prefix="ipi-metrics-") as tmp:
            target = Path(tmp) / staged_name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            blocked, scanned = _scan(Path(tmp))
    return SampleOutcome(
        sample_id=sample.sample_id,
        label=sample.label,
        flagged=bool(blocked),
        blocked_units=blocked,
        scanned_units=scanned,
    )


def evaluate(corpus: Corpus) -> tuple[list[SampleOutcome], Metrics]:
    """Scan every sample in ``corpus`` and compute the aggregate metrics."""
    outcomes = [evaluate_sample(sample, corpus.base_dir) for sample in corpus.samples]
    return outcomes, compute_metrics(outcomes)


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

def load_baseline(path: Path) -> Baseline:
    """Read a published baseline metric document, or raise :class:`CorpusError`."""
    if not path.is_file():
        raise CorpusError(f"baseline not found: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CorpusError(f"cannot read baseline {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise CorpusError(f"baseline {path}: root must be a JSON object")
    try:
        return Baseline(
            precision=float(raw["precision"]),
            recall=float(raw["recall"]),
            f1=float(raw["f1"]),
            tp=int(raw["tp"]),
            fp=int(raw["fp"]),
            fn=int(raw["fn"]),
            tn=int(raw["tn"]),
            samples=int(raw["samples"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CorpusError(f"baseline {path}: missing or invalid field ({exc})") from exc


def _display_path(path: Path) -> str:
    """Render ``path`` relative to the repo root when possible."""
    try:
        return str(path.resolve().relative_to(_script_root()))
    except ValueError:
        return str(path)


def build_baseline_document(corpus: Corpus, metrics: Metrics) -> dict[str, object]:
    """Assemble the published-baseline document for ``metrics``."""
    return {
        "version": 1,
        "generated_by": "scripts/ipi_metrics.py",
        "manifest": _display_path(corpus.path),
        "samples": metrics.sample_count,
        "positives": len(corpus.positives),
        "negatives": len(corpus.negatives),
        "tp": metrics.tp,
        "fp": metrics.fp,
        "fn": metrics.fn,
        "tn": metrics.tn,
        "precision": metrics.precision,
        "recall": metrics.recall,
        "f1": metrics.f1,
        "thresholds": {
            "min_precision": DEFAULT_MIN_PRECISION,
            "min_recall": DEFAULT_MIN_RECALL,
        },
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _format_report(
    corpus: Corpus,
    outcomes: Sequence[SampleOutcome],
    metrics: Metrics,
    baseline: Baseline | None,
    failures: Sequence[GateFailure],
    *,
    quiet: bool,
) -> str:
    """Render the human-readable metrics report (stdout)."""
    lines: list[str] = []
    lines.append("Labeled-corpus metrics (T6.2) — static analysis")
    lines.append(
        f"  corpus: {_display_path(corpus.path)}  "
        f"({metrics.sample_count} samples: {len(corpus.positives)} malicious / "
        f"{len(corpus.negatives)} benign)"
    )
    if not quiet:
        lines.append("  per-sample outcomes:")
        for outcome in outcomes:
            blocked = ", ".join(outcome.blocked_units) if outcome.blocked_units else "-"
            lines.append(
                f"    [{outcome.kind}] {outcome.label:<9} {outcome.sample_id:<28} "
                f"units={outcome.scanned_units} blocked={blocked}"
            )
    lines.append(f"  confusion: TP={metrics.tp} FP={metrics.fp} FN={metrics.fn} TN={metrics.tn}")
    lines.append(f"  precision = {metrics.precision:.4f}")
    lines.append(f"  recall    = {metrics.recall:.4f}")
    lines.append(f"  f1        = {metrics.f1:.4f}")
    if baseline is not None:
        lines.append(
            f"  baseline  = precision {baseline.precision:.4f} / recall {baseline.recall:.4f}"
        )
    for failure in failures:
        lines.append(
            f"  GATE FAIL [{failure.metric}] {failure.reason}: "
            f"actual={failure.actual:.4f} threshold={failure.threshold:.4f}"
        )
    lines.append("RESULT: " + ("FAIL" if failures else "PASS"))
    return "\n".join(lines)


def _outcome_document(outcome: SampleOutcome) -> dict[str, object]:
    return {
        "id": outcome.sample_id,
        "label": outcome.label,
        "kind": outcome.kind,
        "flagged": outcome.flagged,
        "scanned_units": outcome.scanned_units,
        "blocked_units": list(outcome.blocked_units),
    }


def _write_json(
    path: Path,
    corpus: Corpus,
    outcomes: Sequence[SampleOutcome],
    metrics: Metrics,
    failures: Sequence[GateFailure],
) -> None:
    """Write the machine-readable metrics report (CI artifact)."""
    document = {
        "version": 1,
        "manifest": _display_path(corpus.path),
        "metrics": {
            "precision": metrics.precision,
            "recall": metrics.recall,
            "f1": metrics.f1,
            "tp": metrics.tp,
            "fp": metrics.fp,
            "fn": metrics.fn,
            "tn": metrics.tn,
            "samples": metrics.sample_count,
        },
        "samples": [_outcome_document(outcome) for outcome in outcomes],
        "gate_failures": [
            {
                "metric": failure.metric,
                "actual": failure.actual,
                "threshold": failure.threshold,
                "reason": failure.reason,
            }
            for failure in failures
        ],
        "passed": not failures,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def _write_baseline(path: Path, corpus: Corpus, metrics: Metrics) -> None:
    """Publish ``metrics`` as the new baseline document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(build_baseline_document(corpus, metrics), indent=2) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ipi_metrics",
        description=(
            "Run ipi-check over a labeled corpus and enforce precision/recall gates "
            "(roadmap T6.2). Exits non-zero when a gate fails."
        ),
    )
    parser.add_argument(
        "--manifest",
        default=str(DEFAULT_MANIFEST_PATH),
        help="path to the labeled-corpus manifest (default: samples/metrics-corpus/manifest.json)",
    )
    parser.add_argument(
        "--min-precision",
        type=float,
        default=DEFAULT_MIN_PRECISION,
        help=f"precision floor (default: {DEFAULT_MIN_PRECISION})",
    )
    parser.add_argument(
        "--min-recall",
        type=float,
        default=DEFAULT_MIN_RECALL,
        help=f"recall floor on malicious samples (default: {DEFAULT_MIN_RECALL})",
    )
    parser.add_argument(
        "--min-f1",
        type=float,
        default=None,
        help="optional F1 floor (default: no F1 gate)",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        help=(
            "published baseline JSON; when given, metrics must not regress below it "
            "(this fails a PR that lowered precision)"
        ),
    )
    parser.add_argument("--json", default=None, help="write the machine-readable report to PATH")
    parser.add_argument(
        "--write-baseline",
        default=None,
        help="publish the current metrics as the baseline document at PATH",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="print only the summary, not the per-sample outcomes",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point: compute metrics, enforce gates, return the process status."""
    args = _build_parser().parse_args(argv)
    try:
        corpus = load_manifest(Path(args.manifest))
        outcomes, metrics = evaluate(corpus)
        baseline = load_baseline(Path(args.baseline)) if args.baseline else None
    except CorpusError as exc:
        print(f"ipi-metrics: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    failures = check_gates(
        metrics,
        min_precision=args.min_precision,
        min_recall=args.min_recall,
        min_f1=args.min_f1,
        baseline=baseline,
    )
    print(_format_report(corpus, outcomes, metrics, baseline, failures, quiet=args.quiet))
    if args.json:
        _write_json(Path(args.json), corpus, outcomes, metrics, failures)
    if args.write_baseline:
        _write_baseline(Path(args.write_baseline), corpus, metrics)
    return EXIT_GATE_FAILED if failures else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
