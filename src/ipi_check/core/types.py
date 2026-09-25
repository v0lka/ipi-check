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


class CompromisedReason(enum.Enum):
    """Why an LLM classification was marked compromised.

    Distinguishes an ordinary provider/transport failure from a *suspicious*
    broken response:

    - ``PROVIDER_ERROR`` — the provider never produced a usable answer
      (network error, timeout, rate limit, empty completion, ``litellm``
      missing). Purely transient; degrades to static-only analysis.
    - ``SCHEMA_INVALID`` — the provider answered but the JSON did not match the
      required schema (even after the repair retry). A benign model error;
      degrades to static-only analysis.
    - ``INJECTION_SUSPECTED`` — the provider answered, but the response was
      broken in a way that indicates the classifier itself was steered by the
      analysed content (hidden characters, injected directives, or a
      jailbreak-style verdict token). This is an *attack signal* and MUST NOT
      be silently downgraded to ``safe`` — the fusion layer escalates it.
    """
    PROVIDER_ERROR = "provider_error"
    SCHEMA_INVALID = "schema_invalid"
    INJECTION_SUSPECTED = "injection_suspected"


#: Ranking of compromised reasons by the strength of the signal they carry.
#: Used when merging per-chunk classification results: the *worst* (highest)
#: reason wins, mirroring the worst-verdict merge — otherwise an
#: ``INJECTION_SUSPECTED`` chunk (an attack signal the fusion layer escalates
#: to REVIEW_REQUIRED) could be diluted to a mere provider error, or dropped
#: entirely, letting a steered classifier on an oversized file fuse to PASS.
COMPROMISED_REASON_RANK: dict[CompromisedReason, int] = {
    CompromisedReason.PROVIDER_ERROR: 1,
    CompromisedReason.SCHEMA_INVALID: 2,
    CompromisedReason.INJECTION_SUSPECTED: 3,
}


def worst_compromised_reason(
    reasons: list[CompromisedReason | None],
) -> CompromisedReason | None:
    """Return the strongest (highest-ranked) reason among ``reasons``.

    ``None`` entries rank lowest; an all-``None`` (or empty) input returns
    ``None``.
    """
    worst: CompromisedReason | None = None
    for reason in reasons:
        if reason is None:
            continue
        if worst is None or COMPROMISED_REASON_RANK.get(reason, 0) > (
            COMPROMISED_REASON_RANK.get(worst, 0)
        ):
            worst = reason
    return worst


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
    """A finding from byte-level analysis.

    ``file`` records the artifact the finding was detected in. A skill verdict
    aggregates findings across every bundled file, so the SARIF reporter needs
    this to anchor each finding at the *real* file and line (T4.3 / IN-3).
    It is ``None`` for a single-file verdict, where the owning file is already
    known from the verdict itself. Excluded from equality/repr so it never
    perturbs finding comparisons.
    """
    category: ByteFindingCategory
    severity: Severity
    line: int
    column: int
    snippet_hex: str
    description: str
    file: DiscoveredFile | None = field(default=None, compare=False, repr=False)


@dataclass
class PatternFinding:
    """A finding from pattern matching.

    ``file`` records the artifact the finding was detected in (see
    :class:`ByteFinding`); excluded from equality/repr.
    """
    category: PatternFindingCategory
    severity: Severity
    line: int
    column: int
    matched_text: str
    pattern_id: str
    description: str
    file: DiscoveredFile | None = field(default=None, compare=False, repr=False)
    framed: bool = field(default=False, compare=False, repr=False)
    """True when the severity was capped by *example-region framing* (a cue
    list, table row or inline-code span) in an agent-instruction file. The
    framing there is attacker-writable prose, so the cap cannot be trusted to
    mean "quotation" — confidence fusion floors such a file's verdict at
    ``REVIEW_REQUIRED`` (never ``PASS``). See ADR-007."""


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
    """A finding from LLM classification.

    ``file`` records the artifact the finding belongs to (``None`` for a
    single-file verdict; the skill's ``SKILL.md`` for a skill verdict). See
    :class:`ByteFinding`; excluded from equality/repr.
    """
    line: int
    category: str
    explanation: str
    file: DiscoveredFile | None = field(default=None, compare=False, repr=False)


@dataclass
class LLMConfig:
    """Configuration for LLM classifier.

    ``timeout`` is the per-LLM-call timeout in seconds (CLI ``--timeout``).
    ``None`` falls back to the classifier's built-in default
    (``ipi_check.scanner.llm_classifier.LLM_TIMEOUT_SECONDS``).
    """

    base_url: str | None = None
    model: str | None = None
    api_token: str | None = None
    timeout: float | None = None


@dataclass
class LLMResult:
    """Result from LLM classification."""
    verdict: str  # "safe" | "suspicious" | "malicious"
    confidence: float
    findings: list[LLMFinding] = field(default_factory=list)
    compromised: bool = False
    raw_response: str | None = None
    compromised_reason: CompromisedReason | None = None

    def __post_init__(self) -> None:
        if not self.compromised:
            if self.verdict not in ("safe", "suspicious", "malicious"):
                raise ValueError(f"Invalid LLM verdict: {self.verdict}")
            if not 0.0 <= self.confidence <= 1.0:
                raise ValueError(f"Confidence must be 0.0-1.0, got {self.confidence}")


@dataclass
class LLMUsage:
    """Aggregated LLM call accounting for a single scan.

    Populated by :class:`ipi_check.scanner.llm_classifier.LLMLedger` and
    surfaced by the pipeline as a ``tokens in / tokens out`` summary (see the
    ``--max-llm-calls`` and ``--llm-cache-dir`` options in the CLI contract).
    All counters are monotonic within one scan.
    """

    calls: int = 0
    """LLM API calls actually attempted (after ``--max-llm-calls`` gating)."""

    cache_hits: int = 0
    """Classifications served from the response cache (no API call made)."""

    prompt_tokens: int = 0
    """Total input (prompt) tokens across all calls."""

    completion_tokens: int = 0
    """Total output (completion) tokens across all calls."""

    @property
    def total_tokens(self) -> int:
        """Sum of input and output tokens."""
        return self.prompt_tokens + self.completion_tokens


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
    # Repository suppression policy (``.ipi-checkignore`` + inline directives),
    # attached by the pipeline and applied by the SARIF reporter (T5.3). Excluded
    # from equality/repr so it never perturbs verdict comparisons.
    suppression_policy: SuppressionPolicy | None = field(
        default=None, compare=False, repr=False
    )


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
    compromised_reason: CompromisedReason | None = None


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
    # Repository suppression policy (``.ipi-checkignore`` + inline directives);
    # see :class:`FinalVerdict.suppression_policy`.
    suppression_policy: SuppressionPolicy | None = field(
        default=None, compare=False, repr=False
    )


# ---------------------------------------------------------------------------
# Suppression types (T5.3 / IN-19)
# ---------------------------------------------------------------------------


class SuppressionKind(enum.Enum):
    """Origin of a suppression (mirrors the SARIF ``suppression.kind`` enum).

    - ``EXTERNAL`` — declared in a ``.ipi-checkignore`` file.
    - ``IN_SOURCE`` — declared inline in the scanned file, e.g.
      ``# ipi-check:ignore[IPI006]``.
    """

    IN_SOURCE = "inSource"
    EXTERNAL = "external"


@dataclass(frozen=True)
class Suppression:
    """A resolved suppression for one finding (rule id + location)."""

    kind: SuppressionKind
    justification: str


@dataclass(frozen=True)
class IgnoreEntry:
    """One effective line of a ``.ipi-checkignore`` file (gitignore syntax).

    ``pattern`` is a gitignore path pattern relative to the repository root
    (``None`` = every path). ``rules`` restricts the entry to a set of rule IDs
    (``None`` = every rule). ``negated`` reverses the entry (a ``!`` prefix),
    re-including findings that earlier entries suppressed.
    """

    pattern: str | None
    rules: frozenset[str] | None
    negated: bool = False


@dataclass
class FileDirectives:
    """Inline ``ipi-check:ignore`` directives parsed from one file.

    ``file_rules`` holds the rule set of a file-scoped directive
    (``ipi-check:ignore-file[...]``); empty means "all rules", ``None`` means no
    file-scoped directive. ``lines`` maps a 1-based line number to the rule set
    of a line-scoped directive (``ipi-check:ignore[...]``); an empty set means
    "all rules".
    """

    file_rules: frozenset[str] | None = None
    lines: dict[int, frozenset[str]] = field(default_factory=dict)


@dataclass
class SuppressionPolicy:
    """Repository suppression policy applied by the SARIF reporter.

    Combines the parsed ``.ipi-checkignore`` entries (``external``) with the
    inline directives found in each scanned file (``inSource``). Built by the
    pipeline and attached to every verdict; the reporter consults it while
    assembling the SARIF ``results`` array.
    """

    entries: list[IgnoreEntry] = field(default_factory=list)
    inline: dict[str, FileDirectives] = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        """True when the policy cannot suppress anything."""
        return not self.entries and not self.inline


# ---------------------------------------------------------------------------
# SARIF output-limiting statistics
# ---------------------------------------------------------------------------


@dataclass
class SarifLimitStats:
    """Counts of SARIF results removed by the dedup / per-file-cap pass.

    Populated by the reporter when it assembles the SARIF ``results`` array
    (see :func:`ipi_check.reporter.sarif_reporter.generate_sarif_with_stats`).
    The CLI surfaces these counts in the stderr summary so that suppressing
    findings is never silent.
    """

    max_findings_per_file: int = 0
    duplicates_removed: int = 0
    capped_removed: int = 0
    below_threshold_removed: int = 0
    suppressed_results: int = 0

    @property
    def total_suppressed(self) -> int:
        """Total SARIF results removed (duplicates + cap + severity threshold).

        Note: results carrying an accepted suppression
        (:attr:`suppressed_results`) are *not* removed from the SARIF output —
        they stay in ``results`` marked suppressed — so they are not counted
        here.
        """
        return self.duplicates_removed + self.capped_removed + self.below_threshold_removed
