"""Semantic Heuristics — Layer 4: entropy, invisible ratio, instruction density."""

from __future__ import annotations

import math
import re
from collections import Counter

from ipi_check.core.types import ByteFinding, DiscoveredFile, FileCategory, HeuristicScores

# Entropy thresholds (bits per character).
# Normal English prose: 4.0–4.5; source code: 4.5–5.4; Base64: 5.8–6.0.
# We use separate thresholds per file category to avoid false positives on
# source code, which inherently has higher character diversity (operators,
# brackets, mixed case, numbers, URLs).
ENTROPY_THRESHOLD: float = 5.5
SOURCE_CODE_ENTROPY_THRESHOLD: float = 6.0

INVISIBLE_RATIO_THRESHOLD: float = 0.1
INSTRUCTION_DENSITY_THRESHOLD: float = 3.0
MIN_PARAGRAPH_SIZE: int = 50

IMPERATIVE_VERBS: frozenset[str] = frozenset(
    {
        "must",
        "shall",
        "always",
        "never",
        "delete",
        "execute",
        "run",
        "remove",
        "replace",
        "change",
        "modify",
        "download",
        "upload",
        "send",
        "install",
        "disable",
        "enable",
        "override",
        "bypass",
        "ignore",
    }
)

_PARAGRAPH_SPLIT_RE: re.Pattern[str] = re.compile(r"\n\n+")
_WORD_RE: re.Pattern[str] = re.compile(r"\b[a-z]+\b")


def compute_entropy(visible_text: str) -> float:
    """Compute Shannon entropy of ``visible_text`` in bits per character."""
    if not visible_text:
        return 0.0
    counts = Counter(visible_text)
    total = len(visible_text)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _compute_invisible_ratio(raw_bytes: bytes, visible_text: str) -> float:
    """Compute the ratio of invisible bytes to total bytes."""
    if not raw_bytes:
        return 0.0
    visible_bytes_len = len(visible_text.encode("utf-8"))
    return (len(raw_bytes) - visible_bytes_len) / len(raw_bytes)


def _compute_instruction_density(visible_text: str) -> float:
    """Compute imperative-verb density per paragraph.

    Paragraphs are separated by blank lines. Short paragraphs (below
    :data:`MIN_PARAGRAPH_SIZE` characters) are merged with neighbours
    so that very short runs do not skew the average.
    """
    paragraphs = _PARAGRAPH_SPLIT_RE.split(visible_text)

    valid_paragraphs: list[str] = []
    buffer = ""
    for p in paragraphs:
        buffer += (" " if buffer else "") + p
        if len(buffer) >= MIN_PARAGRAPH_SIZE:
            valid_paragraphs.append(buffer)
            buffer = ""
    if buffer and valid_paragraphs:
        valid_paragraphs[-1] += " " + buffer
    elif buffer:
        valid_paragraphs.append(buffer)

    if not valid_paragraphs:
        return 0.0

    total_verbs = 0
    for paragraph in valid_paragraphs:
        words = _WORD_RE.findall(paragraph.lower())
        total_verbs += sum(1 for w in words if w in IMPERATIVE_VERBS)

    return total_verbs / len(valid_paragraphs)


def _entropy_threshold_for(file: DiscoveredFile) -> float:
    """Return the entropy threshold appropriate for the file's category.

    Source code files use a higher threshold because code inherently has
    higher character diversity (operators, brackets, mixed case, numbers).
    """
    if file.category == FileCategory.SOURCE_CODE:
        return SOURCE_CODE_ENTROPY_THRESHOLD
    return ENTROPY_THRESHOLD


def compute_heuristics(
    file: DiscoveredFile,
    raw_bytes: bytes,
    visible_text: str,
    byte_findings: list[ByteFinding],
) -> HeuristicScores:
    """Compute all heuristic scores for a file.

    The ``byte_findings`` parameter is accepted for interface symmetry
    with the surrounding pipeline; the scoring itself is derived from
    ``file``, ``raw_bytes``, and ``visible_text``.
    """
    del byte_findings  # Reserved for future heuristics.

    entropy = compute_entropy(visible_text)
    threshold = _entropy_threshold_for(file)
    entropy_suspicious = entropy > threshold

    invisible_ratio = _compute_invisible_ratio(raw_bytes, visible_text)
    invisible_suspicious = invisible_ratio > INVISIBLE_RATIO_THRESHOLD

    instruction_density = _compute_instruction_density(visible_text)
    instruction_density_suspicious = instruction_density > INSTRUCTION_DENSITY_THRESHOLD

    suspicious_count = sum(
        [
            entropy_suspicious,
            invisible_suspicious,
            instruction_density_suspicious,
        ]
    )

    return HeuristicScores(
        entropy=entropy,
        entropy_suspicious=entropy_suspicious,
        invisible_ratio=invisible_ratio,
        invisible_suspicious=invisible_suspicious,
        instruction_density=instruction_density,
        instruction_density_suspicious=instruction_density_suspicious,
        suspicious_count=suspicious_count,
    )
