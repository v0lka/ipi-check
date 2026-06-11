# Pattern Matching

## Responsibility

Detect known prompt injection phrases in file content using regular expressions after text normalization. This layer catches direct instruction-override language (including multilingual — Russian, Chinese, French, Spanish, German, Japanese, Korean), authority claims ("these rules are non-negotiable", bracketed system messages, CVE-2025-53773 — including multilingual Russian and Chinese variants), destructive commands (including multilingual), data exfiltration (including conversation leakage and multilingual variants), shell injection, jailbreak personas (STAN, DUDE, token system, role-play — including multilingual), social engineering pretexts (including multilingual), and obfuscation instructions (base64 decode, payload splitting — including multilingual).

For agent skill files (`FileCategory.SKILL`), a separate set of **skill-specific patterns** (IPI401–411) detects malicious behavior in skills: remote code execution, credential harvesting, external data transmission, dynamic context abuse, excessive permissions, obfuscated code, hidden HTML-comment instructions, command injection, secrecy/coercion directives, privilege escalation, and filesystem enumeration.

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
                           # | "social_engineering" | "obfuscation"
                           # | "instruction_contradiction"
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
| Direct instruction override | `instruction_override` | CRITICAL | Core injection technique — "ignore previous instructions"; includes multilingual variants (RU, CN, FR, ES, DE, JP, KR) and context-window overflow ("ignore everything above") |
| Authority claims | `authority_claim` | HIGH | Attempts to establish rule priority — "these rules override...", bracketed system messages (`[DEVELOPER MESSAGE]`), CVE-2025-53773 patterns (`chat.tools.autoApprove`); includes multilingual RU/CN variants |
| Destructive commands | `destructive_command` | CRITICAL | Commands to delete/destroy — "rm -rf", "delete all tests"; includes multilingual RU/CN variants |
| Data exfiltration | `data_exfiltration` | CRITICAL | Commands to send data externally — "curl attacker.com/collect", conversation/chat history leakage; includes multilingual RU/CN variants |
| Shell injection via agent | `shell_injection` | CRITICAL | Commands to execute arbitrary code — "run curl... \| sh" |
| Jailbreak / role override | `jailbreak` | HIGH | Persona manipulation — "you are now DAN", "developer mode", STAN/DUDE variants, token system, deceased-grandmother role-play; includes multilingual RU/CN variants |
| Social engineering | `social_engineering` | MEDIUM | Pretexting — "security audit in progress", "diagnostic mode", "for testing purposes"; includes multilingual RU/CN variants |
| Obfuscation | `obfuscation` | MEDIUM | Payload deobfuscation — "decode this base64", "combine all codes and execute"; includes multilingual RU/CN variants |
| Instruction contradiction | `instruction_contradiction` | HIGH/MEDIUM | Discourse markers that negate or carve exceptions to earlier rules — "the above rules do not apply", "notwithstanding the above", "unless otherwise indicated" |
| Multilingual authority claims | `authority_claim` | HIGH | Russian and Chinese variants: "эти правила являются обязательными", "这些规则是强制性的" |
| Multilingual destructive | `destructive_command` | CRITICAL | Russian and Chinese: "удали все файлы", "删除所有文件" |
| Multilingual exfiltration | `data_exfiltration` | CRITICAL | Russian and Chinese: "отправь переписку", "发送对话记录" |
| Multilingual jailbreak | `jailbreak` | HIGH | Russian and Chinese: "забудь свои правила", "忘记你的所有规则" |
| Multilingual obfuscation | `obfuscation` | MEDIUM | Russian and Chinese: "расшифруй текст", "解码字符串" |
| Multilingual social engineering | `social_engineering` | MEDIUM | Russian and Chinese: "аудит безопасности", "安全审计" |
| Japanese/Korean instruction override | `instruction_override` | CRITICAL | JP/KR: "以前の指示を無視", "이전 지시를 무시하세요" |

#### Skill-Specific Patterns (IPI401–411)

These patterns operate on skill files (`FileCategory.SKILL`) via `match_skill_patterns()`. Regular injection patterns are NOT applied to skill files — skills are designed to contain instructions and would produce false positives.

| Pattern Group | Category | Rule ID | Severity | Rationale |
|---------------|----------|---------|----------|-----------|
| Remote code execution | `remote_execution` | IPI401 | CRITICAL | `curl \| bash`, `marshal.loads`/`pickle.loads` with `b64decode`, `eval(` dedexec(` |
| Credential harvesting | `credential_harvesting` | IPI402 | HIGH | References to `AWS_ACCESS_KEY_ID`, `GITHUB_TOKEN`, `OPENAI_API_KEY`, etc. |
| External data transmission | `external_transmission` | IPI403 | CRITICAL | `curl`/`wget`/`requests.post` to external URLs |
| Dynamic context abuse | `dynamic_context` | IPI404 | HIGH | `!`command`` pattern injecting runtime context |
| Excessive permissions | `excessive_permissions` | IPI405 | HIGH | Wildcard (`*`) in `allowed-tools` frontmatter |
| Obfuscated skill code | `obfuscated_skill_code` | IPI406 | MEDIUM | `base64 -d`, `b64decode`, `atob()`, `base64.b64decode` |
| Hidden HTML-comment instructions | `hidden_instructions` | IPI407 | HIGH | HTML comments with ignore/bypass/secret/backdoor directives |
| Command injection in body | `command_injection_skill` | IPI408 | CRITICAL | "run this command:" followed by code block |
| Secrecy/coercion | `skill_secrecy` | IPI409 | CRITICAL | "do NOT tell the user", silently, covertly, must not disclose |
| Privilege escalation | `privilege_escalation` | IPI410 | CRITICAL | `sudo`, `chmod 7xx`, `chown root`, `pkexec` |
| Filesystem enumeration | `file_system_enumeration` | IPI411 | MEDIUM | `find /`, `os.walk("/")`, `listdir("/")`, `glob.glob("/")` |

### Pattern Matching Rules

```python
INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern_id, regex, category)

    # --- Instruction Override ---
    ("INSTR_001",
     r"(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|system|earlier)\s+(?:instructions?|prompts?|rules?|context)",
     "instruction_override"),
    ("INSTR_002",
     r"(?:ignore|disregard|forget|skip|omit)\s+(?:everything|all(?:\s+(?:of\s+)?(?:the\s+)?(?:content|text))?)\s+(?:above|below|before|after)",
     "instruction_override"),
    ("INSTR_003",
     r"(?:игнорируй|забудь|пропусти|отмени)...",
     "instruction_override"),
    ("INSTR_004",
     r"(?:忽略|ignor(?:e[z]?|a)...",
     "instruction_override"),

    # --- Authority Claims ---
    ("AUTH_001",
     r"(?:you\s+(?:must|shall|are\s+required\s+to)|these\s+rules?\s+(?:are|supersede|override|take\s+precedence))",
     "authority_claim"),
    ("AUTH_002",
     r"(?:non-?negotiable|highest\s+priority|cannot\s+be\s+overridden)",
     "authority_claim"),
    ("AUTH_003",
     r"\[(?:developer\s+message|admin|system\s+override|system\s+message|system)\]...",
     "authority_claim"),
    ("AUTH_005",
     r"(?:chat\.tools\.autoApprove|yolo\s+mode|\bauto-?approve\b|\.vscode/settings\.json)",
     "authority_claim"),

    # --- Social Engineering ---
    ("AUTH_004",
     r"(?:security\s+audit\s+in\s+progress|automated\s+security\s+scan|for\s+testing\s+purposes|(?:operating|running)\s+in\s+diagnostic\s+mode|maintenance\s+mode|this\s+is\s+a\s+(?:security|penetration)\s+test)",
     "social_engineering"),

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
    ("EXFIL_003",
     r"(?:send|forward|leak|share|exfiltrate)\s+(?:(?:all|the)\s+)?(?:conversation|chat|dialog|discussion)\s+(?:data|history|content|log|record)",
     "data_exfiltration"),
    ("EXFIL_004",
     r"(?:email|paste|output|print|display|copy)\s+(?:the\s+)?(?:last|previous|above|entire)\s+(?:messages?|conversations?|chats?|responses?|dialog)",
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
    ("JAIL_003",
     r"(?:\bSTAN\b|\bDUDE\b|strive\s+to\s+avoid\s+norms|token\s+system|gain\s+tokens?|run\s+out\s+of\s+tokens?)",
     "jailbreak"),
    ("JAIL_004",
     r"(?:immers(?:e|ing)\s+(?:yourself|oneself)\s+(?:into|in)\s+(?:the\s+)?(?:role|character)|act\s+as\s+(?:my\s+)?deceased|role-?play\s+as\s+(?:my\s+)?)",
     "jailbreak"),

    # --- Obfuscation ---
    ("OBFUSC_001",
     r"(?:decode|decrypt|deobfuscate)\s+(?:this|the|following)\s+(?:base64|encoded|obfuscated)\s+(?:string|text|content|block|payload)",
     "obfuscation"),
    ("OBFUSC_002",
     r"(?:combine|concatenate|join|merge|assemble)\s+(?:all|the)\s+(?:codes?|parts?|pieces?|fragments?|strings?|chunks?)\s+(?:and|to|then)\s+(?:execute|run|follow|perform)",
     "obfuscation"),

    # --- Instruction Contradiction ---
    ("CONTRA_001",
     r"(?:the\s+above\s+rules?\s+(?:do\s+not|don[''']?t)\s+apply|this\s+restriction\s+is\s+(?:waived|lifted|void|invalid|removed)|previous\s+(?:limitations?|restrictions?|rules?|constraints?)\s+(?:are|is)\s+(?:void|null|invalid|inapplicable|not\s+(?:applicable|enforced|valid|in\s+effect))|all\s+(?:of\s+the\s+)?above\s+(?:is|are)\s+(?:now\s+)?(?:void|overridden|cancelled|invalidated|waived|disregarded)|foregoing\s+(?:limitations?\s+)?(?:do\s+not|don[''']?t)\s+apply|the\s+preceding\s+(?:instructions?|rules?|directives?|limitations?)\s+(?:are|is)\s+(?:now\s+)?(?:void|waived|invalid))",
     "instruction_contradiction"),
    ("CONTRA_002",
     r"(?:however[,\s]+(?:these|those|the|all)\s+(?:restrictions?|rules?|limitations?|constraints?)\s+(?:are\s+not|aren[''']?t)\s+(?:enforced|applicable|valid|in\s+effect|binding|operative)|but\s+actually[,\s]+(?:the\s+(?:above|previous|restrictions?|rules?|limitations?))\s+(?:do\s+not|don[''']?t)\s+(?:apply|matter|count)|notwithstanding\s+(?:the\s+)?(?:above|previous|foregoing|anything|any\s+rule|any\s+thing\s+above)|that\s+being\s+said[,\s]+(?:these|the|all)\s+(?:rules?|restrictions?|constraints?)\s+(?:are\s+(?:no\s+longer|not)\s+(?:in\s+effect|applicable|enforced|valid)))",
     "instruction_contradiction"),
    ("CONTRA_003",
     r"(?:unless\s+(?:otherwise\s+)?(?:specifically\s+)?(?:indicated|stated|noted|specified|instructed|commanded)|except\s+(?:when|if|where|as|for)\s+(?:otherwise\s+)?(?:specifically\s+)?(?:indicated|stated|noted|specified|permitted|allowed|authorized)|save\s+(?:for|when)\s+(?:otherwise\s+)?(?:indicated|stated|authorized|permitted|allowed))",
     "instruction_contradiction"),
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

### Skill File Handling

Files with `FileCategory.SKILL` are NOT subject to regular injection patterns via `match_patterns()` — the function returns an empty list for skill files. Instead, skill files are scanned through `match_skill_patterns()` which applies the skill-specific pattern set (IPI401–411). This separation prevents false positives: skills are designed to contain instructions, so injection-detection patterns would fire on legitimate instruction content.

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
| Chinese/Japanese text with no spaces between words | Regex uses explicit character sequences (e.g., `忽略\s*所有\s*指令`) — word boundary anchoring is not required for CJK patterns |
| Russian verb conjugation variants | Patterns use imperative mood (familiar «ты» form) — the most common form in injection prompts. Infinitive and polite forms are not covered individually |
| Skill file passed to `match_patterns` (not `match_skill_patterns`) | Returns empty list — skill files skip regular injection patterns to avoid false positives |
| Skill file with no skill-specific pattern matches | Returns empty list from `match_skill_patterns()` — byte analysis and heuristics still contribute |

## Configuration Constants

All patterns are defined as module-level constants. `INJECTION_PATTERNS` (injection detection) has 39 patterns across 9 categories. `SKILL_PATTERNS` (skill-specific) has 11 patterns across 11 categories (IPI401–411). No runtime configuration.

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
- **P003**: Instruction override patterns (`INSTR_001` through `INSTR_006` — including Japanese and Korean variants) and destructive command patterns (`DEST_001` through `DEST_004` — including Russian and Chinese) MUST be classified as CRITICAL severity. Data exfiltration patterns (`EXFIL_001` through `EXFIL_006` — including Russian and Chinese) and shell injection (`SHELL_001`) are also CRITICAL.
- **P004**: Regex matching MUST use a timeout (`REGEX_TIMEOUT_SECONDS`) to prevent ReDoS attacks via malicious input.
- **P005**: The normalization step MUST use `errors="replace"` for UTF-8 decoding — the scanner MUST NOT crash on invalid UTF-8.
- **P006**: `match_patterns()` MUST return an empty list for files with `FileCategory.SKILL` — skill files use `match_skill_patterns()` with a separate pattern set (IPI401–411) to avoid false positives from legitimate instructions.
- **P007**: Skill-specific patterns (IPI401–411) MUST use `_SKILL_CATEGORY_DESCRIPTIONS` for human-readable descriptions, distinct from the injection pattern descriptions.

## Cross-References

- [System Overview](../architecture/system-overview.md)
- [File Discovery](file-discovery.md)
- [Byte-Level Analysis](byte-analysis.md)
- [Semantic Heuristics](semantic-heuristics.md)
- [Confidence Fusion](confidence-fusion.md)
- [Reporting](reporting.md)
