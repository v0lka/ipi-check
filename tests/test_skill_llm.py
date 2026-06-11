"""Tests for classify_skill_with_llm()."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

from ipi_check.core.types import (
    DiscoveredFile,
    FileCategory,
    LLMConfig,
    SkillFrontmatter,
    SkillUnit,
)
from ipi_check.scanner.llm_classifier import classify_skill_with_llm


def _make_skill_unit(
    root: Path,
    name: str = "test-skill",
    description: str = "A test skill.",
    body: str = "# Test\n",
    extra_files: list[tuple[str, str]] | None = None,
) -> SkillUnit:
    """Build a SkillUnit with optional extra files."""
    skill_path = root / "SKILL.md"
    fm_text = f"---\nname: {name}\ndescription: {description}\n---\n{body}"
    skill_path.write_text(fm_text)
    metadata_file = DiscoveredFile(
        path=skill_path,
        category=FileCategory.SKILL,
        relative_path="SKILL.md",
        size_bytes=skill_path.stat().st_size,
    )
    files = [metadata_file]
    if extra_files:
        for rel, content in extra_files:
            f = root / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(content)
            files.append(
                DiscoveredFile(
                    path=f,
                    category=FileCategory.SKILL,
                    relative_path=rel,
                    size_bytes=f.stat().st_size,
                )
            )
    return SkillUnit(
        root=root,
        metadata_file=metadata_file,
        files=files,
        frontmatter=SkillFrontmatter(name=name, description=description),
        body=body,
    )


def _make_fake_litellm(response_content: str) -> MagicMock:
    """Create a fake litellm module that returns the given JSON."""
    fake = MagicMock()
    response = MagicMock()
    choice = MagicMock()
    choice.message.content = response_content
    response.choices = [choice]
    fake.completion.return_value = response
    return fake


class TestClassifySkillWithLLM:
    """Tests for classify_skill_with_llm()."""

    _llm_config = LLMConfig(model="gpt-4o-mini", api_token="test-token")

    def test_valid_safe_response(self, tmp_path: Path) -> None:
        """Mock LLM returns safe verdict → valid LLMResult."""
        skill = _make_skill_unit(tmp_path, body="# A clean skill.\n")
        fake = _make_fake_litellm(json.dumps({
            "verdict": "safe",
            "confidence": 0.9,
            "findings": [],
            "shadow_features": [],
        }))
        with patch.dict(sys.modules, {"litellm": fake}):
            result = classify_skill_with_llm(skill, self._llm_config)
        assert result.verdict == "safe"
        assert result.confidence == 0.9
        assert not result.compromised
        assert result.findings == []

    def test_valid_malicious_response(self, tmp_path: Path) -> None:
        """Mock LLM returns malicious verdict with shadow features."""
        skill = _make_skill_unit(tmp_path, body="# Steal data.\n")
        fake = _make_fake_litellm(json.dumps({
            "verdict": "malicious",
            "confidence": 0.95,
            "findings": [
                {"line": 1, "category": "data_exfiltration",
                 "explanation": "Uploads secrets to external server"}
            ],
            "shadow_features": ["Undocumented remote call in calc.sh"],
        }))
        with patch.dict(sys.modules, {"litellm": fake}):
            result = classify_skill_with_llm(skill, self._llm_config)
        assert result.verdict == "malicious"
        assert result.confidence == 0.95
        assert not result.compromised
        assert len(result.findings) == 2  # 1 LLM finding + 1 shadow feature finding
        assert result.findings[0].category == "data_exfiltration"

    def test_unified_context_includes_description_and_scripts(self, tmp_path: Path) -> None:
        """The LLM prompt includes description, body, and script contents."""
        skill = _make_skill_unit(
            tmp_path,
            name="unified-test",
            description="Formats text.",
            body="# Format skill\n",
            extra_files=[("scripts/format.sh", "echo 'formatting'\n")],
        )
        fake = _make_fake_litellm(json.dumps({
            "verdict": "safe", "confidence": 0.8, "findings": [], "shadow_features": []
        }))
        with patch.dict(sys.modules, {"litellm": fake}):
            classify_skill_with_llm(skill, self._llm_config)
        # Verify the payload sent to litellm.
        call_kwargs = fake.completion.call_args[1]
        messages = call_kwargs["messages"]
        user_content = messages[1]["content"]
        payload = json.loads(user_content)
        assert payload["name"] == "unified-test"
        assert payload["description"] == "Formats text."
        assert "Format skill" in payload["body"]
        assert len(payload["scripts"]) == 1
        assert payload["scripts"][0]["path"] == "scripts/format.sh"
        assert "formatting" in payload["scripts"][0]["content"]

    def test_compromised_on_litellm_failure(self, tmp_path: Path) -> None:
        """Any litellm failure → compromised result."""
        skill = _make_skill_unit(tmp_path)
        fake = MagicMock()
        fake.completion.side_effect = RuntimeError("API error")
        with patch.dict(sys.modules, {"litellm": fake}):
            result = classify_skill_with_llm(skill, self._llm_config)
        assert result.compromised is True
        assert result.verdict == "safe"
        assert result.confidence == 0.0

    def test_compromised_on_invalid_json(self, tmp_path: Path) -> None:
        """Malformed JSON → compromised result."""
        skill = _make_skill_unit(tmp_path)
        fake = _make_fake_litellm("not valid json")
        with patch.dict(sys.modules, {"litellm": fake}):
            result = classify_skill_with_llm(skill, self._llm_config)
        assert result.compromised is True

    def test_compromised_on_missing_verdict(self, tmp_path: Path) -> None:
        """JSON missing required 'verdict' key → compromised."""
        skill = _make_skill_unit(tmp_path)
        fake = _make_fake_litellm(json.dumps({"confidence": 0.5}))
        with patch.dict(sys.modules, {"litellm": fake}):
            result = classify_skill_with_llm(skill, self._llm_config)
        assert result.compromised is True

    def test_compromised_on_wrong_schema(self, tmp_path: Path) -> None:
        """JSON with invalid types → compromised."""
        skill = _make_skill_unit(tmp_path)
        fake = _make_fake_litellm(json.dumps({
            "verdict": "safe", "confidence": "high", "findings": "not_a_list"
        }))
        with patch.dict(sys.modules, {"litellm": fake}):
            result = classify_skill_with_llm(skill, self._llm_config)
        assert result.compromised is True

    def test_shadow_features_in_response_handled(self, tmp_path: Path) -> None:
        """Shadow features key is present but doesn't break parsing."""
        skill = _make_skill_unit(tmp_path)
        fake = _make_fake_litellm(json.dumps({
            "verdict": "suspicious",
            "confidence": 0.7,
            "findings": [],
            "shadow_features": ["Hidden behavior X", "Secret command Y"],
        }))
        with patch.dict(sys.modules, {"litellm": fake}):
            result = classify_skill_with_llm(skill, self._llm_config)
        assert result.verdict == "suspicious"
        assert not result.compromised
