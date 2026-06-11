"""Core data types for ipi-check scanner."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


class FileCategory(enum.Enum):
    """Categories of discovered files."""
    AGENT_INSTRUCTION = "agent_instruction"
    DOT_DIRECTORY_MD = "dot_directory_md"
    SOURCE_CODE = "source_code"
    SKILL = "skill"


class Severity(enum.Enum):
    """Finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class VerdictDecision(enum.Enum):
    """Final verdict decisions."""
    BLOCK = "BLOCK"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    PASS = "PASS"


class ByteFindingCategory(enum.Enum):
    """Categories of byte-level findings."""
    ANSI_HIDDEN = "ansi_hidden"
    UNICODE_TAGS = "unicode_tags"
    VARIATION_SELECTORS = "variation_selectors"
    BIDI_OVERRIDE = "bidi_override"
    ZERO_WIDTH = "zero_width"
    HOMOGLYPH = "homoglyph"
    PUA = "pua"


class PatternFindingCategory(enum.Enum):
    """Categories of pattern matching findings."""
    INSTRUCTION_OVERRIDE = "instruction_override"
    AUTHORITY_CLAIM = "authority_claim"
    DESTRUCTIVE_COMMAND = "destructive_command"
    DATA_EXFILTRATION = "data_exfiltration"
    SHELL_INJECTION = "shell_injection"
    JAILBREAK = "jailbreak"
    SOCIAL_ENGINEERING = "social_engineering"
    OBFUSCATION = "obfuscation"
    INSTRUCTION_CONTRADICTION = "instruction_contradiction"
    # Skill-specific categories (IPI401–411)
    REMOTE_EXECUTION = "remote_execution"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    EXTERNAL_TRANSMISSION = "external_transmission"
    DYNAMIC_CONTEXT = "dynamic_context"
    EXCESSIVE_PERMISSIONS = "excessive_permissions"
    OBFUSCATED_SKILL_CODE = "obfuscated_skill_code"
    HIDDEN_INSTRUCTIONS = "hidden_instructions"
    COMMAND_INJECTION_SKILL = "command_injection_skill"
    SKILL_SECRECY = "skill_secrecy"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    FILE_SYSTEM_ENUMERATION = "file_system_enumeration"


@dataclass
class ToolInfo:
    """Tool metadata for SARIF output."""
    name: str
    version: str
    semver: str


@dataclass
class DiscoveredFile:
    """A file discovered during scanning."""
    path: Path
    category: FileCategory
    relative_path: str
    size_bytes: int


@dataclass
class ByteFinding:
    """A finding from byte-level analysis."""
    category: ByteFindingCategory
    severity: Severity
    line: int
    column: int
    snippet_hex: str
    description: str


@dataclass
class PatternFinding:
    """A finding from pattern matching."""
    category: PatternFindingCategory
    severity: Severity
    line: int
    column: int
    matched_text: str
    pattern_id: str
    description: str


@dataclass
class HeuristicScores:
    """Scores from semantic heuristic analysis."""
    entropy: float
    entropy_suspicious: bool
    invisible_ratio: float
    invisible_suspicious: bool
    instruction_density: float
    instruction_density_suspicious: bool
    contradiction_score: float
    contradiction_suspicious: bool
    suspicious_count: int


@dataclass
class LLMFinding:
    """A finding from LLM classification."""
    line: int
    category: str
    explanation: str


@dataclass
class LLMConfig:
    """Configuration for LLM classifier."""
    base_url: str | None = None
    model: str | None = None
    api_token: str | None = None


@dataclass
class LLMResult:
    """Result from LLM classification."""
    verdict: str  # "safe" | "suspicious" | "malicious"
    confidence: float
    findings: list[LLMFinding] = field(default_factory=list)
    compromised: bool = False
    raw_response: str | None = None

    def __post_init__(self) -> None:
        if not self.compromised:
            if self.verdict not in ("safe", "suspicious", "malicious"):
                raise ValueError(f"Invalid LLM verdict: {self.verdict}")
            if not 0.0 <= self.confidence <= 1.0:
                raise ValueError(f"Confidence must be 0.0-1.0, got {self.confidence}")


@dataclass
class StaticResult:
    """Assembled result from static analysis pipeline."""
    file: DiscoveredFile
    byte_findings: list[ByteFinding]
    pattern_findings: list[PatternFinding]
    heuristic_scores: HeuristicScores
    severity: Severity


@dataclass
class FinalVerdict:
    """Final verdict for a scanned file."""
    file: DiscoveredFile
    decision: VerdictDecision
    static_severity: Severity
    llm_verdict: str | None
    llm_confidence: float | None
    llm_compromised: bool
    all_findings: list[ByteFinding | PatternFinding | LLMFinding]
    reasoning: str
    heuristic_scores: HeuristicScores | None = None


@dataclass
class BatchFileInput:
    """A single file's input within a batch LLM request."""
    path: str
    content: str


@dataclass
class BatchRequest:
    """Input to a single batched LLM call."""
    files: list[BatchFileInput]
    estimated_tokens: int = 0


@dataclass
class BatchResult:
    """Output from a single batched LLM call."""
    file_results: list[LLMResult]
    compromised: bool = False
    raw_response: str | None = None
    retry_indices: list[int] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Skill scanning types
# ---------------------------------------------------------------------------


@dataclass
class SkillFrontmatter:
    """Parsed YAML frontmatter from SKILL.md."""
    name: str
    description: str
    license: str | None = None
    compatibility: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)
    allowed_tools: str | None = None


@dataclass
class SkillUnit:
    """A complete skill: SKILL.md + all files in its directory."""
    root: Path
    metadata_file: DiscoveredFile
    files: list[DiscoveredFile]
    frontmatter: SkillFrontmatter
    body: str


@dataclass
class SkillStaticResult:
    """Aggregated static result for a complete skill unit."""
    skill: SkillUnit
    file_byte_findings: list[list[ByteFinding]]
    file_pattern_findings: list[list[PatternFinding]]
    metadata_heuristic_scores: HeuristicScores
    aggregate_severity: Severity


@dataclass
class SkillFinalVerdict:
    """Final verdict for a complete skill unit."""
    skill: SkillUnit
    decision: VerdictDecision
    static_severity: Severity
    llm_verdict: str | None
    llm_confidence: float | None
    llm_compromised: bool
    all_findings: list[ByteFinding | PatternFinding | LLMFinding]
    reasoning: str
