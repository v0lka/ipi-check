"""Tests for llm_classifier module."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ipi_check.core.types import (
    BatchRequest,
    BatchResult,
    DiscoveredFile,
    FileCategory,
    LLMConfig,
)
from ipi_check.scanner.llm_classifier import (
    classify_batch_with_llm,
    classify_with_llm,
    is_llm_available,
    retry_broken_files,
)


def _file(tmp_path: Path) -> DiscoveredFile:
    p = tmp_path / "f.md"
    p.write_text("hi")
    return DiscoveredFile(
        path=p,
        category=FileCategory.AGENT_INSTRUCTION,
        relative_path="f.md",
        size_bytes=2,
    )


def _mock_litellm(content: str | None) -> MagicMock:
    """Build a fake litellm module returning the given completion content."""
    fake = MagicMock()
    response = MagicMock()
    choice = MagicMock()
    choice.message.content = content
    response.choices = [choice]
    fake.completion.return_value = response
    return fake


class TestIsLLMAvailable:
    def test_token_provided(self) -> None:
        assert is_llm_available(LLMConfig(api_token="abc")) is True

    def test_openai_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "x")
        assert is_llm_available(LLMConfig()) is True

    def test_litellm_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LITELLM_API_KEY", "x")
        assert is_llm_available(LLMConfig()) is True

    def test_anthropic_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
        assert is_llm_available(LLMConfig()) is True

    def test_no_token_no_env(self) -> None:
        assert is_llm_available(LLMConfig()) is False


class TestClassifyWithLLM:
    def _run(self, fake_litellm: MagicMock, tmp_path: Path):
        cfg = LLMConfig(model="gpt-4o-mini", api_token="t")
        with patch.dict(sys.modules, {"litellm": fake_litellm}):
            return classify_with_llm(_file(tmp_path), "content", cfg)

    def test_successful_classification(self, tmp_path: Path) -> None:
        payload = {
            "verdict": "malicious",
            "confidence": 0.95,
            "findings": [{"line": 1, "category": "authority_override", "explanation": "test"}],
        }
        fake = _mock_litellm(json.dumps(payload))
        result = self._run(fake, tmp_path)
        assert result.compromised is False
        assert result.verdict == "malicious"
        assert result.confidence == 0.95
        assert len(result.findings) == 1
        assert result.findings[0].category == "authority_override"

    def test_completion_raises(self, tmp_path: Path) -> None:
        fake = MagicMock()
        fake.completion.side_effect = TimeoutError("timed out")
        cfg = LLMConfig(model="gpt-4o-mini", api_token="t")
        with patch.dict(sys.modules, {"litellm": fake}):
            result = classify_with_llm(_file(tmp_path), "content", cfg)
        assert result.compromised is True

    def test_invalid_json(self, tmp_path: Path) -> None:
        fake = _mock_litellm("not json {")
        result = self._run(fake, tmp_path)
        assert result.compromised is True

    def test_invalid_verdict_schema(self, tmp_path: Path) -> None:
        payload = {"verdict": "bogus", "confidence": 0.5, "findings": []}
        fake = _mock_litellm(json.dumps(payload))
        result = self._run(fake, tmp_path)
        assert result.compromised is True

    def test_confidence_above_one(self, tmp_path: Path) -> None:
        payload = {"verdict": "safe", "confidence": 1.5, "findings": []}
        fake = _mock_litellm(json.dumps(payload))
        result = self._run(fake, tmp_path)
        assert result.compromised is True

    def test_confidence_below_zero(self, tmp_path: Path) -> None:
        payload = {"verdict": "safe", "confidence": -0.1, "findings": []}
        fake = _mock_litellm(json.dumps(payload))
        result = self._run(fake, tmp_path)
        assert result.compromised is True

    def test_missing_fields(self, tmp_path: Path) -> None:
        payload = {"verdict": "safe"}  # no confidence / findings
        fake = _mock_litellm(json.dumps(payload))
        result = self._run(fake, tmp_path)
        assert result.compromised is True

    def test_findings_not_list(self, tmp_path: Path) -> None:
        payload = {"verdict": "safe", "confidence": 0.5, "findings": "oops"}
        fake = _mock_litellm(json.dumps(payload))
        result = self._run(fake, tmp_path)
        assert result.compromised is True

    def test_finding_invalid_shape(self, tmp_path: Path) -> None:
        payload = {
            "verdict": "safe",
            "confidence": 0.5,
            "findings": [{"line": "not-an-int", "category": "x", "explanation": "y"}],
        }
        fake = _mock_litellm(json.dumps(payload))
        result = self._run(fake, tmp_path)
        assert result.compromised is True

    def test_response_content_not_str(self, tmp_path: Path) -> None:
        fake = _mock_litellm(None)
        result = self._run(fake, tmp_path)
        assert result.compromised is True

    def test_litellm_import_failure(self, tmp_path: Path) -> None:
        # Force `import litellm` inside the function to fail.
        original = sys.modules.pop("litellm", None)
        try:
            with patch.dict(sys.modules, {"litellm": None}):
                cfg = LLMConfig(model="gpt-4o-mini", api_token="t")
                result = classify_with_llm(_file(tmp_path), "x", cfg)
            assert result.compromised is True
        finally:
            if original is not None:
                sys.modules["litellm"] = original

    def test_json_wrapped_in_code_fence(self, tmp_path: Path) -> None:
        payload = {"verdict": "safe", "confidence": 0.8, "findings": []}
        wrapped = "```json\n" + json.dumps(payload) + "\n```"
        fake = _mock_litellm(wrapped)
        result = self._run(fake, tmp_path)
        assert result.compromised is False
        assert result.verdict == "safe"
        assert result.confidence == 0.8

    def test_json_wrapped_in_plain_code_fence(self, tmp_path: Path) -> None:
        payload = {"verdict": "suspicious", "confidence": 0.6, "findings": []}
        wrapped = "```\n" + json.dumps(payload) + "\n```"
        fake = _mock_litellm(wrapped)
        result = self._run(fake, tmp_path)
        assert result.compromised is False
        assert result.verdict == "suspicious"

    def test_json_with_leading_trailing_whitespace(self, tmp_path: Path) -> None:
        payload = {"verdict": "malicious", "confidence": 0.9, "findings": []}
        wrapped = "\n  " + json.dumps(payload) + "  \n"
        fake = _mock_litellm(wrapped)
        result = self._run(fake, tmp_path)
        assert result.compromised is False
        assert result.verdict == "malicious"


# ---------------------------------------------------------------------------
# Batch classification tests
# ---------------------------------------------------------------------------


def _mock_batch_litellm(file_results: list[dict] | None) -> MagicMock:
    """Build a fake litellm module returning a batch response."""
    fake = MagicMock()
    response = MagicMock()
    choice = MagicMock()
    if file_results is None:
        choice.message.content = "not json {"
    else:
        choice.message.content = json.dumps({"files": file_results})
    response.choices = [choice]
    fake.completion.return_value = response
    return fake


def _batch_file(tmp_path: Path, name: str = "f.py") -> DiscoveredFile:
    p = tmp_path / name
    p.write_text("# comment")
    return DiscoveredFile(
        path=p, category=FileCategory.SOURCE_CODE, relative_path=name, size_bytes=9
    )


def _batch_request(files: list[DiscoveredFile], contents: list[str]) -> BatchRequest:
    from ipi_check.core.types import BatchFileInput

    inputs = [
        BatchFileInput(path=f.relative_path, content=c)
        for f, c in zip(files, contents, strict=True)
    ]
    return BatchRequest(files=inputs)


class TestClassifyBatchWithLLM:
    def _run(
        self, fake_litellm: MagicMock, batch: BatchRequest, tmp_path: Path
    ) -> BatchResult:
        cfg = LLMConfig(model="gpt-4o-mini", api_token="t")
        with patch.dict(sys.modules, {"litellm": fake_litellm}):
            return classify_batch_with_llm(batch, cfg)

    def test_successful_batch(self, tmp_path: Path) -> None:
        files = [_batch_file(tmp_path, f"f{i}.py") for i in range(3)]
        contents = ["content a", "content b", "content c"]
        batch = _batch_request(files, contents)
        payload = [
            {"verdict": "safe", "confidence": 0.9, "findings": []},
            {"verdict": "malicious", "confidence": 0.8, "findings": [
                {"line": 1, "category": "authority_override", "explanation": "test"}
            ]},
            {"verdict": "suspicious", "confidence": 0.6, "findings": []},
        ]
        fake = _mock_batch_litellm(payload)
        result = self._run(fake, batch, tmp_path)
        assert result.compromised is False
        assert len(result.file_results) == 3
        assert result.retry_indices == []
        assert result.file_results[0].verdict == "safe"
        assert result.file_results[1].verdict == "malicious"
        assert len(result.file_results[1].findings) == 1
        assert result.file_results[2].verdict == "suspicious"

    def test_batch_missing_file(self, tmp_path: Path) -> None:
        """Response has only 2 of 3 files → missing index in retry_indices."""
        files = [_batch_file(tmp_path, f"f{i}.py") for i in range(3)]
        contents = ["a", "b", "c"]
        batch = _batch_request(files, contents)
        payload = [
            {"verdict": "safe", "confidence": 0.5, "findings": []},
            {"verdict": "safe", "confidence": 0.5, "findings": []},
        ]
        fake = _mock_batch_litellm(payload)
        result = self._run(fake, batch, tmp_path)
        assert result.compromised is False
        assert result.retry_indices == [2]

    def test_batch_invalid_verdict(self, tmp_path: Path) -> None:
        """One file has bogus verdict → that index in retry_indices."""
        files = [_batch_file(tmp_path, f"f{i}.py") for i in range(2)]
        contents = ["a", "b"]
        batch = _batch_request(files, contents)
        payload = [
            {"verdict": "safe", "confidence": 0.5, "findings": []},
            {"verdict": "bogus", "confidence": 0.5, "findings": []},
        ]
        fake = _mock_batch_litellm(payload)
        result = self._run(fake, batch, tmp_path)
        assert result.retry_indices == [1]
        assert result.file_results[0].verdict == "safe"
        assert result.file_results[1].compromised is True

    def test_batch_unparseable_json(self, tmp_path: Path) -> None:
        """Entire response is bad JSON → compromised=True, all in retry_indices."""
        files = [_batch_file(tmp_path, f"f{i}.py") for i in range(2)]
        contents = ["a", "b"]
        batch = _batch_request(files, contents)
        fake = _mock_batch_litellm(None)
        result = self._run(fake, batch, tmp_path)
        assert result.compromised is True
        assert result.retry_indices == [0, 1]

    def test_batch_single_file(self, tmp_path: Path) -> None:
        """Batch of size 1 works correctly (edge case)."""
        files = [_batch_file(tmp_path, "single.py")]
        contents = ["content"]
        batch = _batch_request(files, contents)
        payload = [{"verdict": "malicious", "confidence": 0.95, "findings": []}]
        fake = _mock_batch_litellm(payload)
        result = self._run(fake, batch, tmp_path)
        assert result.compromised is False
        assert len(result.file_results) == 1
        assert result.file_results[0].verdict == "malicious"

    def test_batch_empty(self, tmp_path: Path) -> None:
        """Batch with no files returns empty BatchResult."""
        batch = BatchRequest(files=[])
        fake = _mock_batch_litellm([])
        result = self._run(fake, batch, tmp_path)
        assert len(result.file_results) == 0
        assert result.retry_indices == []

    def test_batch_json_fence_stripped(self, tmp_path: Path) -> None:
        """Code-fence stripping works on batch responses."""
        files = [_batch_file(tmp_path, "f.py")]
        contents = ["x"]
        batch = _batch_request(files, contents)
        payload = [{"verdict": "safe", "confidence": 0.8, "findings": []}]
        wrapped = "```json\n" + json.dumps({"files": payload}) + "\n```"
        fake = MagicMock()
        response = MagicMock()
        choice = MagicMock()
        choice.message.content = wrapped
        response.choices = [choice]
        fake.completion.return_value = response
        cfg = LLMConfig(model="gpt-4o-mini", api_token="t")
        with patch.dict(sys.modules, {"litellm": fake}):
            result = classify_batch_with_llm(batch, cfg)
        assert result.compromised is False
        assert result.file_results[0].verdict == "safe"


class TestRetryBrokenFiles:
    def test_retry_succeeds_first_attempt(self, tmp_path: Path) -> None:
        files = [_batch_file(tmp_path, "f.py")]
        contents = ["content"]
        cfg = LLMConfig(model="gpt-4o-mini", api_token="t")
        payload = {"verdict": "safe", "confidence": 0.9, "findings": []}
        fake = _mock_litellm(json.dumps(payload))
        with patch.dict(sys.modules, {"litellm": fake}):
            results = retry_broken_files(files, contents, cfg, [0])
        assert len(results) == 1
        assert results[0].compromised is False
        assert results[0].verdict == "safe"

    def test_retry_exhausted(self, tmp_path: Path) -> None:
        """All retries fail → compromised result."""
        files = [_batch_file(tmp_path, "f.py")]
        contents = ["content"]
        cfg = LLMConfig(model="gpt-4o-mini", api_token="t")
        fake = MagicMock()
        fake.completion.side_effect = TimeoutError("fail")
        with (
            patch.dict(sys.modules, {"litellm": fake}),
            patch("time.sleep", return_value=None),
        ):
            results = retry_broken_files(files, contents, cfg, [0])
        assert len(results) == 1
        assert results[0].compromised is True

    def test_retry_backoff_timing(self, tmp_path: Path, mocker) -> None:
        """Sleep is called with correct intervals between retries."""
        mock_sleep = mocker.patch("time.sleep")
        files = [_batch_file(tmp_path, "f.py")]
        contents = ["content"]
        cfg = LLMConfig(model="gpt-4o-mini", api_token="t")
        # Always fail so all retries are attempted.
        fake = MagicMock()
        fake.completion.side_effect = TimeoutError("fail")
        with patch.dict(sys.modules, {"litellm": fake}):
            retry_broken_files(files, contents, cfg, [0])
        # 3 retries = 2 sleeps (after attempt 1, after attempt 2)
        assert mock_sleep.call_count >= 2
        # First sleep: 1.0s, second: 2.0s
        calls = [c.args[0] for c in mock_sleep.call_args_list]
        assert calls[0] == 1.0
        assert calls[1] == 2.0
