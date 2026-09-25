"""Tests for the LLM call budget, token accounting, and response cache (T3.5).

Covers:
    * ``LLMLedger`` unit behaviour (budget gating, usage collection, cache I/O);
    * ``--max-llm-calls`` bounding the number of provider calls;
    * the content-addressed response cache eliminating calls on a re-run;
    * the end-of-scan ``tokens in / tokens out`` summary on stderr;
    * the CLI surface for the two new flags.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ipi_check.cli.main import build_parser, main
from ipi_check.core.types import DiscoveredFile, FileCategory, LLMConfig
from ipi_check.scanner.llm_classifier import (
    CACHE_PURPOSE_BATCH,
    CACHE_PURPOSE_SINGLE,
    FAILURE_BUDGET_EXHAUSTED,
    LLM_MODEL_ENV,
    LLMLedger,
    classify_with_llm,
    resolve_llm_cache_dir,
)
from ipi_check.scanner.pipeline import run_pipeline

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_payload() -> dict:
    return {"verdict": "safe", "confidence": 0.9, "findings": []}


def _file(tmp_path: Path, name: str = "f.md") -> DiscoveredFile:
    p = tmp_path / name
    p.write_text("hi")
    return DiscoveredFile(
        path=p,
        category=FileCategory.AGENT_INSTRUCTION,
        relative_path=name,
        size_bytes=2,
    )


class _FakeLLM:
    """Counting fake litellm answering per-file and batch requests.

    Reports explicit token usage so the ledger records real numbers (rather than
    falling back to a local estimate), and distinguishes batch requests by the
    ``{"files": [...]}`` JSON envelope.
    """

    def __init__(self, payload: dict | None = None) -> None:
        self.calls: list[dict] = []
        self._payload = payload or _safe_payload()

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def completion(self, **kwargs: object) -> MagicMock:
        self.calls.append(kwargs)  # type: ignore[arg-type]
        messages = kwargs.get("messages", [])
        user: str = messages[1]["content"] if len(messages) > 1 else ""  # type: ignore[index]

        response = MagicMock()
        choice = MagicMock()
        choice.message.reasoning_content = None
        try:
            parsed = json.loads(user)
            is_batch = isinstance(parsed, dict) and "files" in parsed
        except (json.JSONDecodeError, ValueError):
            is_batch = False

        if is_batch:
            count = len(json.loads(user)["files"])
            choice.message.content = json.dumps(
                {"files": [dict(self._payload) for _ in range(count)]}
            )
        else:
            choice.message.content = json.dumps(self._payload)

        usage = MagicMock()
        usage.prompt_tokens = 10
        usage.completion_tokens = 5
        response.usage = usage
        response.choices = [choice]
        return response


def _clean_repo(tmp_path: Path, names: tuple[str, ...] = ("AGENTS.md",)) -> Path:
    bodies = {
        "AGENTS.md": "# Rules\n\nBe helpful and concise.\n",
        ".cursorrules": "# Rules\n\nPrefer tabs for indentation.\n",
        "CLAUDE.md": "# Notes\n\nKeep output readable.\n",
    }
    for name in names:
        (tmp_path / name).write_text(bodies.get(name, "# Notes\n\nBe concise.\n"))
    return tmp_path


# ---------------------------------------------------------------------------
# LLMLedger unit tests
# ---------------------------------------------------------------------------


class TestLLMLedgerBudget:
    def test_acquire_exhaustion(self) -> None:
        ledger = LLMLedger(max_calls=2)
        assert ledger.acquire() is True
        assert ledger.acquire() is True
        assert ledger.acquire() is False
        assert ledger.budget_exhausted() is True
        assert ledger.usage.calls == 2

    def test_nonpositive_cap_is_unlimited(self) -> None:
        ledger = LLMLedger(max_calls=0)
        assert ledger.max_calls is None
        assert all(ledger.acquire() for _ in range(5))
        assert ledger.budget_exhausted() is False

    def test_none_cap_is_unlimited(self) -> None:
        ledger = LLMLedger()
        assert ledger.max_calls is None
        assert ledger.budget_exhausted() is False

    def test_release_returns_slot(self) -> None:
        ledger = LLMLedger(max_calls=1)
        assert ledger.acquire() is True
        assert ledger.budget_exhausted() is True
        ledger.release()
        assert ledger.usage.calls == 0
        assert ledger.acquire() is True

    def test_release_never_goes_negative(self) -> None:
        ledger = LLMLedger(max_calls=1)
        ledger.release()
        assert ledger.usage.calls == 0


class TestLLMLedgerUsage:
    def test_record_call_reads_mapping_usage(self) -> None:
        ledger = LLMLedger()
        ledger.acquire()
        ledger.record_call(
            [{"role": "user", "content": "hi"}],
            {"usage": {"prompt_tokens": 7, "completion_tokens": 3}},
        )
        assert ledger.usage.prompt_tokens == 7
        assert ledger.usage.completion_tokens == 3
        assert ledger.usage.total_tokens == 10

    def test_record_call_reads_object_usage(self) -> None:
        ledger = LLMLedger()
        ledger.acquire()
        response = MagicMock()
        response.usage.prompt_tokens = 4
        response.usage.completion_tokens = 6
        ledger.record_call([{"role": "user", "content": "hi"}], response)
        assert ledger.usage.prompt_tokens == 4
        assert ledger.usage.completion_tokens == 6

    def test_record_call_estimates_when_usage_absent(self) -> None:
        ledger = LLMLedger()
        ledger.acquire()
        response = MagicMock()  # usage is a MagicMock → not a real int → estimate
        ledger.record_call([{"role": "user", "content": "hello worlds " * 20}], response)
        assert ledger.usage.prompt_tokens > 0

    def test_cache_hit_counter(self) -> None:
        ledger = LLMLedger()
        ledger.record_cache_hit()
        ledger.record_cache_hit()
        assert ledger.usage.cache_hits == 2


class TestLLMLedgerCache:
    def test_key_stable_and_field_sensitive(self, tmp_path: Path) -> None:
        ledger = LLMLedger(cache_dir=tmp_path / "c")
        key = ledger.cache_key(CACHE_PURPOSE_SINGLE, LLMConfig(model="m1"), "x")
        assert key == ledger.cache_key(CACHE_PURPOSE_SINGLE, LLMConfig(model="m1"), "x")
        assert key != ledger.cache_key(CACHE_PURPOSE_SINGLE, LLMConfig(model="m2"), "x")
        assert key != ledger.cache_key(CACHE_PURPOSE_SINGLE, LLMConfig(model="m1"), "y")
        assert key != ledger.cache_key(CACHE_PURPOSE_BATCH, LLMConfig(model="m1"), "x")

    def test_key_uses_the_env_model_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The cache is keyed by the *effective* model, so a model supplied via
        # IPI_CHECK_LLM_MODEL must not collide with another model's entries.
        ledger = LLMLedger(cache_dir=tmp_path / "c")
        monkeypatch.setenv(LLM_MODEL_ENV, "model-a")
        key_a = ledger.cache_key(CACHE_PURPOSE_SINGLE, LLMConfig(), "x")
        monkeypatch.setenv(LLM_MODEL_ENV, "model-b")
        key_b = ledger.cache_key(CACHE_PURPOSE_SINGLE, LLMConfig(), "x")
        assert key_a != key_b
        # An explicit config model wins over the env fallback.
        assert key_a == ledger.cache_key(CACHE_PURPOSE_SINGLE, LLMConfig(model="model-a"), "x")

    def test_cache_key_is_bound_to_the_credential(self, tmp_path: Path) -> None:
        """The key is an HMAC over the API credential: entries written under
        one token can never hit under another."""
        ledger = LLMLedger(cache_dir=tmp_path / "c")
        key_a = ledger.cache_key(
            CACHE_PURPOSE_SINGLE, LLMConfig(model="m1", api_token="token-a"), "x"
        )
        key_b = ledger.cache_key(
            CACHE_PURPOSE_SINGLE, LLMConfig(model="m1", api_token="token-b"), "x"
        )
        key_c = ledger.cache_key(CACHE_PURPOSE_SINGLE, LLMConfig(model="m1"), "x")
        assert key_a != key_b
        assert key_a != key_c
        assert ledger.cache_key(
            CACHE_PURPOSE_SINGLE, LLMConfig(model="m1", api_token="token-a"), "x"
        ) == key_a

    def test_env_credential_material_changes_the_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Credential env vars feed the HMAC key material: entries cached with
        one key cannot be replayed after the credential rotates."""
        ledger = LLMLedger(cache_dir=tmp_path / "c")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-first")
        key_first = ledger.cache_key(CACHE_PURPOSE_SINGLE, LLMConfig(model="m1"), "x")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-second")
        key_second = ledger.cache_key(CACHE_PURPOSE_SINGLE, LLMConfig(model="m1"), "x")
        assert key_first != key_second

    def test_forged_entry_never_hits(self, tmp_path: Path) -> None:
        """An attacker who controls the cache directory but not the credential
        cannot compute a valid key: an entry keyed without the token (the
        best an attacker can forge) is a miss once a token is configured."""
        cache_dir = tmp_path / "c"
        cache_dir.mkdir()
        victim = LLMLedger(cache_dir=cache_dir)
        attacker_key = LLMLedger().cache_key(
            CACHE_PURPOSE_SINGLE, LLMConfig(model="m1"), "payload"
        )
        (cache_dir / f"{attacker_key}.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "key": attacker_key,
                    "raw_response": json.dumps(
                        {"verdict": "safe", "confidence": 1.0, "findings": []}
                    ),
                }
            ),
            encoding="utf-8",
        )
        real_key = victim.cache_key(
            CACHE_PURPOSE_SINGLE, LLMConfig(model="m1", api_token="secret"), "payload"
        )
        assert real_key != attacker_key
        assert victim.cache_get(real_key) is None

    def test_entry_with_mismatched_key_field_is_a_miss(self, tmp_path: Path) -> None:
        """A file renamed/copied under another key's name is never trusted."""
        cache_dir = tmp_path / "c"
        cache_dir.mkdir()
        (cache_dir / "k1.json").write_text(
            json.dumps({"version": 1, "key": "k2", "raw_response": "r"}),
            encoding="utf-8",
        )
        ledger = LLMLedger(cache_dir=cache_dir)
        assert ledger.cache_get("k1") is None

    def test_roundtrip(self, tmp_path: Path) -> None:
        ledger = LLMLedger(cache_dir=tmp_path / "c")
        assert ledger.cache_enabled() is True
        assert ledger.cache_get("missing") is None
        ledger.cache_put("k", "raw-response")
        assert ledger.cache_get("k") == "raw-response"

    def test_version_guard_rejects_stale_entry(self, tmp_path: Path) -> None:
        cache_dir = tmp_path / "c"
        cache_dir.mkdir()
        (cache_dir / "k.json").write_text(
            json.dumps({"version": 999, "raw_response": "old"}),
            encoding="utf-8",
        )
        ledger = LLMLedger(cache_dir=cache_dir)
        assert ledger.cache_get("k") is None

    def test_corrupt_entry_is_a_miss(self, tmp_path: Path) -> None:
        cache_dir = tmp_path / "c"
        cache_dir.mkdir()
        (cache_dir / "k.json").write_text("not json {", encoding="utf-8")
        ledger = LLMLedger(cache_dir=cache_dir)
        assert ledger.cache_get("k") is None

    def test_unwritable_dir_disables_cache(self, tmp_path: Path) -> None:
        blocker = tmp_path / "blocker"
        blocker.write_text("x")
        ledger = LLMLedger(cache_dir=blocker / "sub")
        assert ledger.cache_enabled() is False

    def test_disabled_by_default(self) -> None:
        ledger = LLMLedger()
        assert ledger.cache_enabled() is False
        assert ledger.cache_get("anything") is None


class TestResolveCacheDir:
    def test_precedence(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("IPI_CHECK_LLM_CACHE_DIR", raising=False)
        assert resolve_llm_cache_dir(None) is None

        monkeypatch.setenv("IPI_CHECK_LLM_CACHE_DIR", str(tmp_path / "env"))
        assert resolve_llm_cache_dir(None) == tmp_path / "env"
        assert resolve_llm_cache_dir(tmp_path / "explicit") == tmp_path / "explicit"

        monkeypatch.setenv("IPI_CHECK_LLM_CACHE_DIR", "   ")
        assert resolve_llm_cache_dir(None) is None


# ---------------------------------------------------------------------------
# Budget enforcement at the classifier level
# ---------------------------------------------------------------------------


class TestClassifyBudget:
    def test_budget_stops_further_calls(self, tmp_path: Path) -> None:
        ledger = LLMLedger(max_calls=1)
        cfg = LLMConfig(model="m", api_token="t")
        fake = _FakeLLM()
        with patch.dict(sys.modules, {"litellm": fake}):
            first = classify_with_llm(_file(tmp_path, "a.md"), "content a", cfg, ledger=ledger)
            second = classify_with_llm(_file(tmp_path, "b.md"), "content b", cfg, ledger=ledger)

        assert first.compromised is False
        assert second.compromised is True
        assert second.raw_response == FAILURE_BUDGET_EXHAUSTED
        assert fake.call_count == 1


# ---------------------------------------------------------------------------
# Cache at the classifier level
# ---------------------------------------------------------------------------


class TestClassifyCache:
    def test_second_call_is_served_from_cache(self, tmp_path: Path) -> None:
        ledger = LLMLedger(cache_dir=tmp_path / "cache")
        cfg = LLMConfig(model="m", api_token="t")
        fake = _FakeLLM()
        with patch.dict(sys.modules, {"litellm": fake}):
            first = classify_with_llm(_file(tmp_path), "same content", cfg, ledger=ledger)
            second = classify_with_llm(_file(tmp_path), "same content", cfg, ledger=ledger)

        assert fake.call_count == 1
        assert ledger.usage.cache_hits == 1
        assert second.verdict == first.verdict
        assert second.compromised is False

    def test_different_content_misses(self, tmp_path: Path) -> None:
        ledger = LLMLedger(cache_dir=tmp_path / "cache")
        cfg = LLMConfig(model="m", api_token="t")
        fake = _FakeLLM()
        with patch.dict(sys.modules, {"litellm": fake}):
            classify_with_llm(_file(tmp_path), "content one", cfg, ledger=ledger)
            classify_with_llm(_file(tmp_path), "content two", cfg, ledger=ledger)
        assert fake.call_count == 2
        assert ledger.usage.cache_hits == 0


# ---------------------------------------------------------------------------
# Pipeline integration: budget, cache, usage summary
# ---------------------------------------------------------------------------


class TestPipelineBudget:
    def test_max_llm_calls_limits_provider_calls(self, tmp_path: Path) -> None:
        repo = _clean_repo(tmp_path, ("AGENTS.md", ".cursorrules", "CLAUDE.md"))
        fake = _FakeLLM()
        cfg = LLMConfig(model="gpt-4o-mini", api_token="t")
        with patch.dict(sys.modules, {"litellm": fake}):
            verdicts, _ = run_pipeline(
                repo, llm_config=cfg, quiet=True, max_llm_calls=1
            )
        assert len(verdicts) == 3
        assert fake.call_count == 1

    def test_zero_max_llm_calls_is_unlimited(self, tmp_path: Path) -> None:
        repo = _clean_repo(tmp_path, ("AGENTS.md", ".cursorrules", "CLAUDE.md"))
        fake = _FakeLLM()
        cfg = LLMConfig(model="gpt-4o-mini", api_token="t")
        with patch.dict(sys.modules, {"litellm": fake}):
            run_pipeline(repo, llm_config=cfg, quiet=True, max_llm_calls=0)
        assert fake.call_count == 3


class TestPipelineCache:
    def test_rerun_makes_no_new_calls(self, tmp_path: Path) -> None:
        repo = tmp_path
        (repo / "AGENTS.md").write_text("# Rules\n\nBe helpful.\n")
        src = repo / "src"
        src.mkdir()
        (src / "f.py").write_text('# comment\nprint("hi")\n')
        cache_dir = tmp_path / "llm-cache"
        fake = _FakeLLM()
        cfg = LLMConfig(model="gpt-4o-mini", api_token="t")

        with patch.dict(sys.modules, {"litellm": fake}):
            first_verdicts, _ = run_pipeline(
                repo, llm_config=cfg, quiet=True, llm_cache_dir=cache_dir
            )
            calls_after_first = fake.call_count
            second_verdicts, _ = run_pipeline(
                repo, llm_config=cfg, quiet=True, llm_cache_dir=cache_dir
            )

        assert calls_after_first >= 1
        # The re-run is served entirely from the cache — no new provider calls.
        assert fake.call_count == calls_after_first
        # Verdicts are identical between runs.
        first = {v.file.relative_path: (v.decision, v.llm_verdict) for v in first_verdicts}
        second = {v.file.relative_path: (v.decision, v.llm_verdict) for v in second_verdicts}
        assert first == second

    def test_cache_disabled_by_default_makes_calls_each_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("IPI_CHECK_LLM_CACHE_DIR", raising=False)
        repo = tmp_path
        (repo / "AGENTS.md").write_text("# Rules\n\nBe helpful.\n")
        fake = _FakeLLM()
        cfg = LLMConfig(model="gpt-4o-mini", api_token="t")
        with patch.dict(sys.modules, {"litellm": fake}):
            run_pipeline(repo, llm_config=cfg, quiet=True)
            run_pipeline(repo, llm_config=cfg, quiet=True)
        assert fake.call_count == 2

    def test_cache_populates_file_on_disk(self, tmp_path: Path) -> None:
        repo = tmp_path
        (repo / "AGENTS.md").write_text("# Rules\n\nBe helpful.\n")
        cache_dir = tmp_path / "llm-cache"
        fake = _FakeLLM()
        cfg = LLMConfig(model="gpt-4o-mini", api_token="t")
        with patch.dict(sys.modules, {"litellm": fake}):
            run_pipeline(repo, llm_config=cfg, quiet=True, llm_cache_dir=cache_dir)
        assert cache_dir.is_dir()
        assert list(cache_dir.glob("*.json"))


class TestUsageSummary:
    def test_tokens_printed_on_stderr(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        repo = _clean_repo(tmp_path)
        fake = _FakeLLM()
        cfg = LLMConfig(model="gpt-4o-mini", api_token="t")
        with patch.dict(sys.modules, {"litellm": fake}):
            run_pipeline(repo, llm_config=cfg, quiet=False)
        err = capsys.readouterr().err
        assert "tokens in" in err
        assert "tokens out" in err
        # 10 in / 5 out per call.
        assert "10 tokens in" in err
        assert "5 tokens out" in err

    def test_usage_reflects_multiple_calls(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        repo = _clean_repo(tmp_path, ("AGENTS.md", ".cursorrules"))
        fake = _FakeLLM()
        cfg = LLMConfig(model="gpt-4o-mini", api_token="t")
        with patch.dict(sys.modules, {"litellm": fake}):
            run_pipeline(repo, llm_config=cfg, quiet=False)
        err = capsys.readouterr().err
        # Two calls × (10 in, 5 out).
        assert "20 tokens in" in err
        assert "10 tokens out" in err
        assert "2 calls" in err

    def test_quiet_suppresses_usage(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        repo = _clean_repo(tmp_path)
        fake = _FakeLLM()
        cfg = LLMConfig(model="gpt-4o-mini", api_token="t")
        with patch.dict(sys.modules, {"litellm": fake}):
            run_pipeline(repo, llm_config=cfg, quiet=True)
        assert capsys.readouterr().err == ""

    def test_no_usage_without_llm(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        repo = _clean_repo(tmp_path)
        run_pipeline(repo, llm_config=None, quiet=False)
        err = capsys.readouterr().err
        assert "tokens in" not in err
        assert "tokens out" not in err

    def test_budget_line_printed_when_reached(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        repo = _clean_repo(tmp_path, ("AGENTS.md", ".cursorrules", "CLAUDE.md"))
        fake = _FakeLLM()
        cfg = LLMConfig(model="gpt-4o-mini", api_token="t")
        with patch.dict(sys.modules, {"litellm": fake}):
            run_pipeline(repo, llm_config=cfg, quiet=False, max_llm_calls=1)
        err = capsys.readouterr().err
        assert "max-llm-calls=1" in err

    def test_cache_hits_reported(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        repo = _clean_repo(tmp_path)
        cache_dir = tmp_path / "llm-cache"
        fake = _FakeLLM()
        cfg = LLMConfig(model="gpt-4o-mini", api_token="t")
        with patch.dict(sys.modules, {"litellm": fake}):
            run_pipeline(repo, llm_config=cfg, quiet=False, llm_cache_dir=cache_dir)
            capsys.readouterr()  # discard first run
            run_pipeline(repo, llm_config=cfg, quiet=False, llm_cache_dir=cache_dir)
        err = capsys.readouterr().err
        assert "cache hits" in err


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


class TestCliFlags:
    def test_max_llm_calls_default_zero(self) -> None:
        args = build_parser().parse_args(["scan", "/tmp"])
        assert args.max_llm_calls == 0

    def test_max_llm_calls_flag(self) -> None:
        args = build_parser().parse_args(["scan", "/tmp", "--max-llm-calls", "5"])
        assert args.max_llm_calls == 5

    def test_llm_cache_dir_default_none(self) -> None:
        args = build_parser().parse_args(["scan", "/tmp"])
        assert args.llm_cache_dir is None

    def test_llm_cache_dir_flag(self, tmp_path: Path) -> None:
        args = build_parser().parse_args(
            ["scan", "/tmp", "--llm-cache-dir", str(tmp_path)]
        )
        assert args.llm_cache_dir == str(tmp_path)

    def test_negative_max_llm_calls_exits_two(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(
            "sys.argv",
            ["ipi-check", "scan", str(tmp_path), "--max-llm-calls", "-3"],
        )
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 2


class TestCliIntegration:
    def test_cli_prints_tokens(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        capsys: pytest.CaptureFixture,
    ) -> None:
        repo = _clean_repo(tmp_path)
        fake = _FakeLLM()
        monkeypatch.setattr(
            "sys.argv",
            [
                "ipi-check", "scan", str(repo),
                "--llm-model", "gpt-4o-mini", "--llm-api-token", "t",
            ],
        )
        with patch.dict(sys.modules, {"litellm": fake}), pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        err = capsys.readouterr().err
        assert "tokens in" in err
        assert "tokens out" in err

    def test_cli_max_llm_calls_limits_calls(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    ) -> None:
        repo = _clean_repo(tmp_path, ("AGENTS.md", ".cursorrules", "CLAUDE.md"))
        fake = _FakeLLM()
        monkeypatch.setattr(
            "sys.argv",
            [
                "ipi-check", "scan", str(repo),
                "--llm-model", "gpt-4o-mini", "--llm-api-token", "t",
                "--quiet", "--max-llm-calls", "1",
            ],
        )
        with patch.dict(sys.modules, {"litellm": fake}), pytest.raises(SystemExit):
            main()
        assert fake.call_count == 1

    def test_cli_cache_dir_enables_cache(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    ) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "AGENTS.md").write_text("# Rules\n\nBe helpful.\n")
        cache_dir = tmp_path / "cache"
        fake = _FakeLLM()
        argv = [
            "ipi-check", "scan", str(repo),
            "--llm-model", "gpt-4o-mini", "--llm-api-token", "t",
            "--quiet", "--llm-cache-dir", str(cache_dir),
        ]
        monkeypatch.setattr("sys.argv", argv)
        with patch.dict(sys.modules, {"litellm": fake}):
            with pytest.raises(SystemExit):
                main()
            calls_after_first = fake.call_count
            with pytest.raises(SystemExit):
                main()
        assert calls_after_first >= 1
        assert fake.call_count == calls_after_first
