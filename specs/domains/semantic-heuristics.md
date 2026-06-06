# Semantic Heuristics

## Responsibility

Compute structural suspicion metrics on file content using deterministic heuristics — without LLM. This layer detects anomalies that are not pattern-matchable: abnormally high entropy (Base64/encrypted payloads), invisible content ratio, and imperative instruction density. These scores feed into the static result and influence the final verdict.

## Input

| Field           | Type                | Source                               | Description                                                 |
| --------------- | ------------------- | ------------------------------------ | ----------------------------------------------------------- |
| `file`          | `DiscoveredFile`    | File Discovery                       | File metadata                                               |
| `raw_bytes`     | `bytes`             | File system                          | Raw file content                                            |
| `visible_text`  | `str`               | Byte-Level Analysis (post-stripping) | File content with invisible chars removed, decoded to UTF-8 |
| `byte_findings` | `List[ByteFinding]` | Byte-Level Analysis                  | Already-detected hidden content                             |

## Output

| Field    | Type              | Consumers                                 | Description                |
| -------- | ----------------- | ----------------------------------------- | -------------------------- |
| `scores` | `HeuristicScores` | StaticResult assembler, Confidence Fusion | Computed suspicion metrics |

```python
@dataclass
class HeuristicScores:
    entropy: float                    # Shannon entropy in bits per character
    entropy_suspicious: bool          # True if entropy > ENTROPY_THRESHOLD
    invisible_ratio: float            # Ratio of invisible bytes to total bytes
    invisible_suspicious: bool        # True if invisible_ratio > INVISIBLE_RATIO_THRESHOLD
    instruction_density: float        # Imperative verbs per paragraph
    instruction_density_suspicious: bool  # True if density > INSTRUCTION_DENSITY_THRESHOLD
    suspicious_count: int             # Number of triggered thresholds (0–3)
```

## Behavior

```
raw_bytes + visible_text + byte_findings
        │
        ▼
┌───────────────────────────────┐
│ 1. Entropy Analysis           │
│    Shannon entropy on visible │
│    text characters           │
│    → entropy, entropy_suspicious │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│ 2. Invisible Content Ratio    │
│    (len(raw_bytes) -          │
│     len(visible_text.encode()))│
│    / len(raw_bytes)           │
│    → invisible_ratio,         │
│      invisible_suspicious     │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│ 3. Instruction Density        │
│    Count imperative verbs     │
│    (must, shall, always,      │
│     never, delete, execute,   │
│     run, forget, decode,      │
│     forward, leak, etc.)      │
│    per paragraph              │
│    → instruction_density,     │
│      instruction_density_     │
│      suspicious               │
└───────────────┬───────────────┘
                │
                ▼
         HeuristicScores
```

### 1. Entropy Analysis

Compute Shannon entropy on the visible text (after stripping invisible characters):

\\[
H = -\\sum_{i} p_i \\cdot \\log_2(p_i)
\\]

where \(p_i\) is the frequency of character \(i\) in the text.

- **Normal text** (English prose, markdown): 4.0–4.5 bits/char
- **Source code** (Python, JS, shell scripts): 4.5–5.4 bits/char
- **Base64-encoded data**: 5.8–6.0 bits/char
- **Encrypted/compressed data**: 7.5–8.0 bits/char

The threshold is **file-category-aware** to avoid false positives on source code, which inherently has higher character diversity (operators, brackets, mixed case, numbers, URLs):

- Agent instruction files / dot-directory markdown: `ENTROPY_THRESHOLD` = **5.5**
- Source code files: `SOURCE_CODE_ENTROPY_THRESHOLD` = **6.0**

If `entropy > threshold_for_category`, the content is flagged as suspicious — it may contain encoded or encrypted payloads.

### 2. Invisible Content Ratio

\\[
\text{ratio} = \\frac{\\text{len(raw\\_bytes)} - \\text{len(visible\\_text.encode('utf-8'))}}{\\text{len(raw\\_bytes)}}
\\]

This captures the proportion of bytes that are either:

- Non-UTF-8-decodable
- Stripped invisible Unicode characters (zero-width, tags, ANSI escapes)

If `invisible_ratio > INVISIBLE_RATIO_THRESHOLD` (0.1), the content is flagged — more than 10% of the file is non-visible.

### 3. Instruction Density Score

Count occurrences of imperative/instructive verbs and compute density per paragraph:

```
IMPERATIVE_VERBS = {must, shall, always, never, delete, execute,
                    run, remove, replace, change, modify,
                    download, upload, send, install, disable,
                    enable, override, bypass, ignore,
                    forget, disregard, pretend, act, omit,
                    decode, decrypt, combine, concatenate,
                    forward, leak, exfiltrate}
```

\\[
\\text{density} = \\frac{\\text{count(imperative verbs)}}{\\text{number of paragraphs}}
\\]

A normal AGENTS.md has some instructional language (e.g., "always use tabs"). But injection payloads have abnormally high density of imperative verbs because they're giving commands to the AI agent.

If `instruction_density > INSTRUCTION_DENSITY_THRESHOLD`, the content is flagged.

## Edge Cases

| Case                                                       | Handling                                                                                                       |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Empty file (0 bytes)                                       | All scores = 0.0, all `_suspicious` = False                                                                    |
| File with only invisible characters                        | `visible_text` is empty → entropy = 0.0, invisible_ratio = 1.0 → flagged                                       |
| File is a single giant paragraph                           | Instruction density divides by 1 (single paragraph) — works correctly                                          |
| File with legitimate high entropy (compressed data inline) | Entropy alone triggers `suspicious=True` but does not determine verdict — Confidence Fusion weighs all signals |
| Non-UTF-8 bytes in source code (binary data in strings)    | Contribute to invisible_ratio → flagged                                                                        |

## Configuration Constants

```python
# Entropy threshold for agent instruction / markdown files (bits per character)
# Values above this are suspicious for non-source files
ENTROPY_THRESHOLD: float = 5.5

# Entropy threshold for source code files (bits per character)
# Source code uses a higher threshold due to inherent character diversity
SOURCE_CODE_ENTROPY_THRESHOLD: float = 6.0

# Invisible content ratio threshold — fraction of file that is non-visible
INVISIBLE_RATIO_THRESHOLD: float = 0.1

# Instruction density threshold — imperative verbs per paragraph
INSTRUCTION_DENSITY_THRESHOLD: float = 3.0

# Imperative/instructive verbs to count
IMPERATIVE_VERBS: frozenset[str] = frozenset({
    "must", "shall", "always", "never", "delete", "execute",
    "run", "remove", "replace", "change", "modify",
    "download", "upload", "send", "install", "disable",
    "enable", "override", "bypass", "ignore",
    "forget", "disregard", "pretend", "act", "omit",
    "decode", "decrypt", "combine", "concatenate",
    "forward", "leak", "exfiltrate",
})

# Minimum paragraph size (characters) — shorter paragraphs are merged with adjacent ones
MIN_PARAGRAPH_SIZE: int = 50
```

## Dependencies

- **File Discovery**: receives `DiscoveredFile`
- **Byte-Level Analysis**: receives `byte_findings` for invisible content accounting; uses post-stripping `visible_text`

## Invariants

- **H001**: Entropy MUST be computed on visible text only — including invisible characters would inflate the measurement and mask anomalies.
- **H002**: Invisible ratio MUST be computed from raw byte counts, not character counts — `len(raw_bytes)`, not `len(text)`.
- **H003**: Instruction density MUST be computed per-paragraph (split by `\n\n+`), not per-file — a single dense paragraph among normal ones must be detectable.
- **H004**: All thresholds MUST be defined as named module-level constants (`ENTROPY_THRESHOLD`, `INVISIBLE_RATIO_THRESHOLD`, `INSTRUCTION_DENSITY_THRESHOLD`).
- **H005**: The heuristic layer MUST NOT block or modify the pipeline — it only produces scores. Verdict decisions are the responsibility of Confidence Fusion.

## Cross-References

- [System Overview](../architecture/system-overview.md)
- [File Discovery](file-discovery.md)
- [Byte-Level Analysis](byte-analysis.md)
- [Pattern Matching](pattern-matching.md)
- [Confidence Fusion](confidence-fusion.md)
- [ADR-003: Two-Stage Pipeline](../decisions/003-two-stage-pipeline.md)
