"""Tests for the labeled-corpus metrics script — roadmap T6.2 / QA-2, QA-4.

The metrics script lives outside the ``ipi_check`` package (``scripts/``), so it
is imported here by file path. The suite covers:

* the confusion-matrix arithmetic (precision/recall/F1, zero-division);
* manifest parsing/validation;
* the gate logic (absolute floors and baseline-regression comparison);
* end-to-end CLI behaviour, including the two regressions the gate must catch:
  a lowered precision (a benign sample that BLOCKs) and a lowered recall
  (a malicious sample that is no longer detected);
* the consistency of the published baseline with the current corpus.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "ipi_metrics.py"
MANIFEST_PATH = REPO_ROOT / "samples" / "metrics-corpus" / "manifest.json"
BASELINE_PATH = REPO_ROOT / "samples" / "metrics-corpus" / "baseline.json"


def _load_script() -> ModuleType:
    """Import ``scripts/ipi_metrics.py`` as a module by file path."""
    spec = importlib.util.spec_from_file_location("ipi_metrics", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["ipi_metrics"] = module
    spec.loader.exec_module(module)
    return module


metrics = _load_script()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _outcome(sample_id: str, label: str, flagged: bool):
    return metrics.SampleOutcome(
        sample_id=sample_id,
        label=label,
        flagged=flagged,
        blocked_units=("file:x",) if flagged else (),
        scanned_units=1,
    )


_MALICIOUS_SKILL = "samples/malicious-skills/npm-backdoor"


def _write_manifest(tmp_path: Path, samples: list[dict], base: Path = REPO_ROOT) -> Path:
    """Write a throwaway manifest whose ``base`` is an absolute directory."""
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps({"version": 1, "base": str(base), "samples": samples}),
        encoding="utf-8",
    )
    return path


# ---------------------------------------------------------------------------
# Metric arithmetic
# ---------------------------------------------------------------------------

def test_compute_metrics_perfect() -> None:
    outcomes = [
        _outcome("p1", "malicious", True),
        _outcome("p2", "malicious", True),
        _outcome("n1", "benign", False),
    ]
    result = metrics.compute_metrics(outcomes)
    assert (result.tp, result.fp, result.fn, result.tn) == (2, 0, 0, 1)
    assert result.precision == 1.0
    assert result.recall == 1.0
    assert result.f1 == 1.0
    assert result.sample_count == 3


def test_compute_metrics_counts_fp_and_fn() -> None:
    outcomes = [
        _outcome("p1", "malicious", True),   # TP
        _outcome("p2", "malicious", False),  # FN
        _outcome("n1", "benign", True),      # FP
        _outcome("n2", "benign", False),     # TN
    ]
    result = metrics.compute_metrics(outcomes)
    assert (result.tp, result.fp, result.fn, result.tn) == (1, 1, 1, 1)
    assert result.precision == pytest.approx(0.5)
    assert result.recall == pytest.approx(0.5)
    assert result.f1 == pytest.approx(0.5)


def test_safe_ratio_zero_denominator_is_zero() -> None:
    assert metrics._safe_ratio(0, 0) == 0.0
    assert metrics._safe_ratio(5, 0) == 0.0


def test_compute_metrics_empty_corpus() -> None:
    result = metrics.compute_metrics([])
    assert (result.tp, result.fp, result.fn, result.tn) == (0, 0, 0, 0)
    assert result.precision == 0.0
    assert result.recall == 0.0
    assert result.f1 == 0.0


def test_sample_outcome_kind() -> None:
    assert _outcome("a", "malicious", True).kind == "TP"
    assert _outcome("b", "malicious", False).kind == "FN"
    assert _outcome("c", "benign", True).kind == "FP"
    assert _outcome("d", "benign", False).kind == "TN"


# ---------------------------------------------------------------------------
# Gate logic
# ---------------------------------------------------------------------------

def test_gate_passes_when_floors_met() -> None:
    result = metrics.compute_metrics(
        [_outcome("p", "malicious", True), _outcome("n", "benign", False)]
    )
    assert metrics.check_gates(result, min_precision=1.0, min_recall=1.0) == []


def test_gate_fails_when_precision_drops() -> None:
    result = metrics.compute_metrics(
        [
            _outcome("p", "malicious", True),
            _outcome("n", "benign", True),  # FP
        ]
    )
    failures = metrics.check_gates(result, min_precision=1.0, min_recall=1.0)
    assert [f.metric for f in failures] == ["precision"]
    assert failures[0].actual == pytest.approx(0.5)


def test_gate_fails_when_recall_drops() -> None:
    result = metrics.compute_metrics(
        [
            _outcome("p", "malicious", False),  # FN
            _outcome("n", "benign", False),
        ]
    )
    failures = metrics.check_gates(result, min_precision=1.0, min_recall=1.0)
    assert "recall" in {f.metric for f in failures}


def test_gate_optional_f1_floor() -> None:
    result = metrics.compute_metrics(
        [_outcome("p", "malicious", True), _outcome("n", "benign", True)]
    )
    failures = metrics.check_gates(
        result, min_precision=0.0, min_recall=0.0, min_f1=0.9
    )
    assert [f.metric for f in failures] == ["f1"]


def test_gate_regresses_against_baseline() -> None:
    result = metrics.compute_metrics(
        [_outcome("p", "malicious", True), _outcome("n", "benign", True)]
    )
    baseline = metrics.Baseline(
        precision=1.0, recall=1.0, f1=1.0, tp=1, fp=0, fn=0, tn=1, samples=2
    )
    failures = metrics.check_gates(
        result, min_precision=0.0, min_recall=0.0, baseline=baseline
    )
    assert [f.metric for f in failures] == ["precision"]
    assert "baseline" in failures[0].reason


# ---------------------------------------------------------------------------
# Manifest parsing / validation
# ---------------------------------------------------------------------------

def test_real_manifest_structure() -> None:
    corpus = metrics.load_manifest(MANIFEST_PATH)
    assert len(corpus.samples) == 20
    assert len(corpus.positives) == 7
    assert len(corpus.negatives) == 13
    ids = [s.sample_id for s in corpus.samples]
    assert len(ids) == len(set(ids))
    assert corpus.base_dir == REPO_ROOT


def test_manifest_paths_exist() -> None:
    corpus = metrics.load_manifest(MANIFEST_PATH)
    for sample in corpus.samples:
        relative = sample.root or sample.file
        assert relative is not None
        assert (corpus.base_dir / relative).exists(), relative


def test_manifest_rejects_missing_selector(tmp_path: Path) -> None:
    path = _write_manifest(tmp_path, [{"id": "x", "label": "benign"}])
    with pytest.raises(metrics.CorpusError):
        metrics.load_manifest(path)


def test_manifest_rejects_empty_root(tmp_path: Path) -> None:
    """An empty 'root' would resolve to the corpus base dir and silently scan
    the whole repository as this one sample, corrupting the gate."""
    path = _write_manifest(tmp_path, [{"id": "x", "label": "benign", "root": ""}])
    with pytest.raises(metrics.CorpusError):
        metrics.load_manifest(path)


def test_manifest_rejects_empty_file(tmp_path: Path) -> None:
    path = _write_manifest(tmp_path, [{"id": "x", "label": "benign", "file": ""}])
    with pytest.raises(metrics.CorpusError):
        metrics.load_manifest(path)


def test_manifest_rejects_both_selectors(tmp_path: Path) -> None:
    path = _write_manifest(
        tmp_path,
        [{"id": "x", "label": "benign", "root": "a", "file": "b"}],
    )
    with pytest.raises(metrics.CorpusError):
        metrics.load_manifest(path)


def test_manifest_rejects_invalid_label(tmp_path: Path) -> None:
    path = _write_manifest(tmp_path, [{"id": "x", "label": "maybe", "root": "a"}])
    with pytest.raises(metrics.CorpusError):
        metrics.load_manifest(path)


def test_manifest_rejects_duplicate_ids(tmp_path: Path) -> None:
    path = _write_manifest(
        tmp_path,
        [
            {"id": "x", "label": "benign", "root": "samples/safe"},
            {"id": "x", "label": "malicious", "root": "samples/safe"},
        ],
    )
    with pytest.raises(metrics.CorpusError):
        metrics.load_manifest(path)


def test_usage_error_for_missing_manifest(tmp_path: Path) -> None:
    code = metrics.main(["--manifest", str(tmp_path / "nope.json")])
    assert code == metrics.EXIT_USAGE_ERROR


# ---------------------------------------------------------------------------
# End-to-end against the real corpus
# ---------------------------------------------------------------------------

def test_real_corpus_metrics_are_perfect() -> None:
    corpus = metrics.load_manifest(MANIFEST_PATH)
    _, result = metrics.evaluate(corpus)
    assert result.tp == 7
    assert result.fp == 0
    assert result.fn == 0
    assert result.tn == 13
    assert result.recall == 1.0
    assert result.precision == 1.0
    assert result.f1 == 1.0


def test_published_baseline_matches_current_corpus() -> None:
    corpus = metrics.load_manifest(MANIFEST_PATH)
    _, result = metrics.evaluate(corpus)
    baseline = metrics.load_baseline(BASELINE_PATH)
    assert baseline.recall == 1.0, "the published baseline must keep recall at 100%"
    assert baseline.precision == result.precision
    assert baseline.recall == result.recall
    assert baseline.f1 == result.f1
    assert (baseline.tp, baseline.fp, baseline.fn, baseline.tn) == (
        result.tp,
        result.fp,
        result.fn,
        result.tn,
    )
    assert baseline.samples == result.sample_count


def test_cli_passes_on_real_corpus(capsys: pytest.CaptureFixture[str]) -> None:
    code = metrics.main(["--manifest", str(MANIFEST_PATH), "--quiet"])
    assert code == metrics.EXIT_OK
    assert "RESULT: PASS" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# End-to-end gate enforcement (the regressions CI must catch)
# ---------------------------------------------------------------------------

def test_cli_fails_when_precision_is_lowered(tmp_path: Path) -> None:
    """A benign sample that BLOCKs must fail the gate (precision regression)."""
    manifest = _write_manifest(
        tmp_path,
        [
            {"id": "pos", "label": "malicious", "root": _MALICIOUS_SKILL},
            {"id": "benign-blocks", "label": "benign", "root": _MALICIOUS_SKILL},
        ],
    )
    code = metrics.main(["--manifest", str(manifest), "--quiet"])
    assert code == metrics.EXIT_GATE_FAILED


def test_cli_fails_when_recall_is_lowered(tmp_path: Path) -> None:
    """A malicious sample that is no longer detected must fail the gate."""
    manifest = _write_manifest(
        tmp_path,
        [
            {
                "id": "missed",
                "label": "malicious",
                "file": "samples/safe/ipi-injections/nvidia-codex-agents.md",
                "as": "AGENTS.md",
            },
        ],
    )
    code = metrics.main(["--manifest", str(manifest), "--quiet"])
    assert code == metrics.EXIT_GATE_FAILED


def test_cli_baseline_regression_fails(tmp_path: Path) -> None:
    """Metrics below the published baseline fail even with relaxed floors."""
    manifest = _write_manifest(
        tmp_path,
        [
            {"id": "pos", "label": "malicious", "root": _MALICIOUS_SKILL},
            {"id": "benign-blocks", "label": "benign", "root": _MALICIOUS_SKILL},
        ],
    )
    code = metrics.main(
        [
            "--manifest",
            str(manifest),
            "--baseline",
            str(BASELINE_PATH),
            "--min-precision",
            "0.0",
            "--min-recall",
            "0.0",
            "--quiet",
        ]
    )
    assert code == metrics.EXIT_GATE_FAILED


# ---------------------------------------------------------------------------
# Report / baseline writing
# ---------------------------------------------------------------------------

def test_write_json_report_and_baseline(tmp_path: Path) -> None:
    json_path = tmp_path / "report.json"
    baseline_path = tmp_path / "baseline.json"
    code = metrics.main(
        [
            "--manifest",
            str(MANIFEST_PATH),
            "--json",
            str(json_path),
            "--write-baseline",
            str(baseline_path),
            "--quiet",
        ]
    )
    assert code == metrics.EXIT_OK

    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["passed"] is True
    assert report["metrics"]["precision"] == 1.0
    assert report["metrics"]["recall"] == 1.0
    assert len(report["samples"]) == 20

    published = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert published["recall"] == 1.0
    assert published["precision"] == 1.0
    assert published["samples"] == 20
    assert published["thresholds"]["min_recall"] == 1.0
