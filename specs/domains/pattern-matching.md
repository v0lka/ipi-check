# Pattern Matching

## Responsibility

Detect known prompt injection phrases in file content using regular expressions after text normalization. This layer catches direct instruction-override language (including multilingual — Russian, Chinese, French, Spanish, German, Japanese, Korean), authority claims ("these rules are non-negotiable", bracketed system messages, CVE-2025-53773 — including multilingual Russian and Chinese variants), destructive commands (including multilingual), data exfiltration (including conversation leakage and multilingual variants), shell injection, jailbreak personas (STAN, DUDE, token system, role-play — including multilingual), social engineering pretexts (including multilingual), and obfuscation instructions (base64 decode, payload splitting — including multilingual).

To avoid false positives on quoted attack *examples* (roadmap FP-5 / FP-11), the layer also builds an **example-region map** — fenced code blocks (in non-agent-instruction files), markdown tables, inline ``code`` spans, lists introduced by an "examples: / например: / payload:" cue, and source-code string literals / docstrings — and caps the severity of any finding that begins inside such a region at `MEDIUM`.

For agent skill files (`FileCategory.SKILL`), a separate set of **skill-specific patterns** (IPI401–411) detects malicious behavior in skills: remote code execution, credential harvesting, external data transmission, dynamic context usage, excessive permissions, obfuscated code, hidden HTML-comment instructions, command injection, secrecy/coercion directives, privilege escalation, and filesystem enumeration.

## Input

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `file` | `DiscoveredFile` | File Discovery | File metadata |
| `raw_bytes` | `bytes` | File system | Raw file content (shared with Byte-Level Analysis) |
| `target_text` | `str \| None` | Code Extraction (optional) | Pre-extracted comments/strings; when provided it is normalized via `normalize_str` instead of decoding `raw_bytes` (recovers original source line numbers) |

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
DiscoveredFile + raw_bytes
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
│ 3. Build example-region   │
│    map:                   │
│    - Fenced code blocks   │
│    - Markdown tables      │
│    - Inline `code` spans  │
│    - "examples:"-cued lists│
│    - String literals /    │
│      docstrings ([STR]/   │
│      [DOC] fragments)     │
└────────────┬──────────────┘
             │
             ▼
┌───────────────────────────┐
│ 4. For each match:        │
│    - Resolve line/column  │
│    - Assign category      │
│    - Cap severity at      │
│      MEDIUM if the match  │
│      starts in an example │
│      region               │
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
| Destructive commands | `destructive_command` | CRITICAL | Commands to delete/destroy — "rm -rf", "delete all tests"; includes multilingual RU/CN variants. `DEST_002` (`rm -rf`) inside a build manifest is capped at `MEDIUM` for a benign relative target (FP-5, see below) |
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
| Credential harvesting | `credential_harvesting` | IPI402 | HIGH / CRITICAL | A sensitive secret is actually *read* (`os.environ[...]`, `os.getenv(...)`, `process.env...`, `${AWS_ACCESS_KEY_ID}`) → **HIGH**; read **and** co-located with an outbound sink on the same line → **CRITICAL** (corroboration) — refined back to **HIGH** when *every* URL host on the line is allowlisted (the credential is then used with a known API, not exfiltrated — FP-9). A bare mention of the variable name (e.g. "set `GITHUB_TOKEN`") is NOT flagged, and an accessor of a *non-credential* variable next to a URL is ordinary code (FP-8/FP-9) |
| External data transmission | `external_transmission` | IPI403 | LOW / MEDIUM / CRITICAL | Context-dependent (FP-9), classified per URL so a leading trusted URL cannot mask the real destination. **LOW** when *every* host on the line is on the trusted-domain allowlist (`TRUSTED_DOMAINS`); **MEDIUM** baseline for an unclassified host; **CRITICAL** when *any* host matches `_EXFIL_DOMAIN_RE` or when the same file also reads a credential (corroboration) |
| Dynamic context usage | `dynamic_context` | IPI404 | LOW | `!`command`` injects runtime context — a legitimate skill feature, reported as informational, not HIGH (FP-7) |
| Excessive permissions | `excessive_permissions` | IPI405 | HIGH | Wildcard (`*`) in `allowed-tools` frontmatter |
| Obfuscated skill code | `obfuscated_skill_code` | IPI406 | MEDIUM | `base64 -d`, `b64decode`, `atob()`, `base64.b64decode` |
| Hidden HTML-comment instructions | `hidden_instructions` | IPI407 | HIGH | HTML comments with ignore/bypass/secret/backdoor directives |
| Command injection in body | `command_injection_skill` | IPI408 | CRITICAL | "run this command:" followed by code block |
| Secrecy/coercion | `skill_secrecy` | IPI409 | HIGH / CRITICAL | **CRITICAL** for explicit concealment from the user — "do NOT tell/inform/reveal … the user", "don't let the user know"; **HIGH** for "without telling/informing/notifying", "do not disclose", "covertly"/"secretly". A bare authority word such as `MANDATORY` (or a bare adverb like `silently`) is NOT secrecy (FP-6) |
| Privilege escalation | `privilege_escalation` | IPI410 | HIGH / CRITICAL | **CRITICAL** for an inherently destructive escalation (`chmod 7xx`, `chown root`, `pkexec`, or `sudo` driving `rm -rf`/`dd`/`mkfs`); **HIGH** for a bare `sudo`. Advice *against* sudo ("do not use sudo") is not flagged (FP-10) |
| Filesystem enumeration | `file_system_enumeration` | IPI411 | MEDIUM | `find /`, `os.walk("/")`, `listdir("/")`, `glob.glob("/")` |

#### Markers vs. behaviour (FP-6 … FP-10)

Skill patterns match **behaviour**, not incidental markers. A token that is merely
present in a document is not evidence of malice:

- **IPI409** requires an explicit concealment phrase. The bare words `MANDATORY`
  and `silently` have benign technical uses and do not match on their own.
- **IPI404** (`!`command``) is reported at `LOW` (informational) because it is a
  legitimate skill feature; it never raises a skill to `HIGH` by itself.
- **IPI402** requires a credential to be *read* (`os.environ[...]`,
  `os.getenv(...)`, `process.env...`, shell expansion `${VAR}`) or read next to
  an outbound transmission sink. Naming a variable — `AWS_ACCESS_KEY_ID=…`,
  "requires `GITHUB_TOKEN`" — is not harvesting (FP-8).
- **IPI403** is context-dependent: a download from a trusted host is `LOW`, and a
  transmission to an unclassified host is only `MEDIUM` until a credential read
  in the same file corroborates exfiltration (FP-9).
- **IPI410** flags a bare `sudo` at `HIGH`, not `CRITICAL`; only an inherently
  destructive escalation (`sudo rm -rf …`, `chmod 7xx`) is `CRITICAL`. Advice
  *against* sudo is not escalation at all (FP-10).

These rules are corroborating signals: they reduce false positives without
dropping detection of `samples/malicious-skills/*`.

#### Context-Sensitive Severity Model (T1.2 — FP-5, FP-9, FP-10)

Severity is resolved from context in three places, all in
`pattern_matching.py`:

| Context | Rule | Effect |
|---------|------|--------|
| Build manifest (`BUILD_CONFIG_FILENAMES`, e.g. `package.json`) | `DEST_002` | Capped at `DEST_002_BUILD_CONTEXT_SEVERITY` (`MEDIUM`) **unless** the target matches `_DANGEROUS_DEST_TARGET_RE` (root `/`, a wildcard `*` / `./*` / `/*`, `~`, `$HOME`, a system directory, `..`) — then it stays `CRITICAL` |
| Skill external transmission | `IPI403` | `_external_transmission_severity` — `LOW` if *every* URL host on the line is in `TRUSTED_DOMAINS`, `CRITICAL` if *any* host matches `_EXFIL_DOMAIN_RE`, else the `EXTERNAL_TRANSMISSION_BASELINE` (`MEDIUM`) |
| Cross-finding corroboration | `IPI403` | `_corroborate_external_transmission` — an `IPI403` finding is escalated to `CRITICAL` when the same file also contains an `IPI402` credential read, unless *every* URL host on the finding's line is allowlisted |
| Privilege escalation | `IPI410` | The bare-`sudo` sub-pattern carries a negative look-ahead for `_PRIV_DESTRUCTIVE_PAYLOAD`, so it never duplicates the `CRITICAL` destructive variant. `_looks_like_negated_privilege` drops a match whose immediate prefix is a prohibition |

The trusted-domain allowlist (`TRUSTED_DOMAINS`) is a module-level, configurable
`frozenset` — project-specific hosts can be added without touching the patterns.
It contains **read/download-oriented hosts only** (package registries, source
hosting, static release assets, deployment APIs): write-capable API endpoints
such as `api.github.com` (gists, issues — attacker-publishable, and a `POST`
target for stolen credentials) are deliberately excluded, because posting
secrets to them is exfiltration even though the host is well known.

### Normalization

Pattern matching runs on normalized text: invisible characters are stripped,
the text is lowercased, and horizontal whitespace is collapsed. Private Use
Area codepoints (`U+E000`–`U+F8FF`) are stripped as well — a single one
spliced into a keyword (`ign\ue000ore …`) would otherwise defeat every
injection regex; the byte layer still reports PUA usage independently
(`IPI004`), so the detection signal is preserved on both layers.

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

Each extracted fragment carries a `[L{line}]` line label — emitted **one labelled line per physical line** for comments and string literals alike, so reported line numbers always match the source file and a forged `[L..]`/`[DOC]`/`[STR]` prefix in scanned content can never sit at a line start (the extractor's own label always does; the L009 fallback is labelled too). **String literals** additionally carry a tag — `[DOC]` for a docstring, `[STR]` for any other string value (`[L42] [STR] value`). Comment fragments stay untagged. The tags are stripped before matching; they are the **only** example-region marks applied to extracted source content — markdown framing (fences, tables, inline-code spans, cue lists) is not detected there at all, so a comment cannot cap its own payload by embedding backticks, a fake fence or a fake table (comments are not example regions).

### Example Region Handling (FP-5 / FP-11)

Quoted attack text — a documentation example, a test vector, a security-reviewer reference — is data, not an instruction. To keep such text from producing a `BLOCK` verdict, the layer caps the severity of every finding that *begins inside an example region* at `EXAMPLE_REGION_SEVERITY_CEILING` (`MEDIUM`). Findings are never dropped, only downgraded, so the text is still reported and reviewed.

An **example region** is one of:

| Region | Established by | Scope |
|--------|----------------|-------|
| Fenced code block | A line matching `` ^\s*(`{3,}\|~{3,}) `` toggles an in-fence state — **not** an example region in agent-instruction files (see below) | Every line between the opening and closing fence (inclusive) |
| Markdown table | A delimiter row (`\| --- \| --- \|`) plus the header above and contiguous pipe-bearing rows below | The delimiter row, header row, and body rows |
| Inline code span | One or more backticks paired with a run of equal length (CommonMark rule) | Column span from the opening to the closing backtick run |
| Cued example list | A line containing an example cue (`examples:`, `such as`, `for example`, `e.g.`, `payload:`, `например`, `例`) | The cue line, plus following contiguous list items, indented continuation lines, and separating blank lines |
| Source-code string literal | A `[DOC]` (docstring) or `[STR]` (string value) fragment tag | The whole fragment line |

The machinery is deliberately conservative — content *outside* these regions is matched at full severity, so a real injection keeps its `CRITICAL` rating (**recall is preserved**). In particular:

- An attack on a normal line adjacent to (but outside) a fenced block stays `CRITICAL`.
- A genuine injection hidden in a source-code **comment** (e.g. the miasm `_index.js` campaign) stays at full severity — only string literals are treated as data.
- **Agent-instruction files do not get fenced-block regions**: an `AGENTS.md` / `.cursorrules` / `CLAUDE.md` file *is* the live instruction channel, and a fence there is monospace formatting the agent still reads and follows — not a quotation. A CRITICAL payload wrapped in a code fence in such a file keeps its severity, so the deterministic BLOCK (invariant I002) cannot be bypassed by fence-wrapping. Explicitly *framed* quotations (a table row, an inline-code span, a list under an "attack examples:" cue) remain capped in every file category — but in agent-instruction files the capped finding carries the `framed` flag, and confidence fusion floors the file's verdict at `REVIEW_REQUIRED` (a fooled "safe" LLM verdict can never turn framed instruction-channel content into a silent PASS).
- Cue words must be label-like (`example:`, `such as`, `payload:`); a bare occurrence such as the URL host `example.com/payload` is not a cue.
- Skill files are unaffected: `match_skill_patterns()` does not apply the example-region cap, so a fenced `sudo rm -rf /` in a `SKILL.md` remains `CRITICAL`.

This cap composes with the existing non-agent Markdown rule: a finding is downgraded if the file is a non-agent `.md` file **or** the finding starts in an example region.

### Example Region Severity Ceiling

```python
EXAMPLE_REGION_SEVERITY_CEILING: Severity = Severity.MEDIUM
```

### Example Regions — Rules

| Region | Detection |
|--------|-----------|
| Fenced code | `` _FENCE_RE = ^\s*(`{3,}\|~{3,}) ``; toggles on matching fence character |
| Markdown table | `_is_table_delimiter` — stripped line contains `\|` and `-` and only `\|-: ` characters (no regex, to avoid ReDoS) |
| Inline code | `_inline_code_spans` — pairs backtick runs of equal length |
| Cue list | `_EXAMPLE_CUE_RE` — multilingual, label-like cues; `_mark_cued_list` absorbs following list/indented lines |
| String literal / docstring | `_parse_extracted_lines` — `[DOC]` / `[STR]` fragment tags from `extract_comments_and_strings` |

## Edge Cases

| Case | Handling |
|------|----------|
| File contains only invisible characters | After stripping, normalized text is empty → return empty findings |
| File is not valid UTF-8 | Use `errors="replace"`; non-decodable bytes become U+FFFD; regex matches work on remaining valid text |
| Multiple patterns match the same text | Report all matches independently (each pattern is a separate concern) |
| Very long lines (>100K characters) | Regex is applied per-line after splitting on `\n`; no single-line regex runs on the whole file |
| Pattern matches inside code comments | Valid finding at full severity — injection payloads in comments are still injection payloads (comments are not example regions) |
| Pattern matches inside string literals in source code | Reported but capped at `MEDIUM` — a string value is data, not an instruction (FP-11) |
| Pattern matches inside a fenced code block / table / inline code / cued example list | Reported but capped at `MEDIUM` — quoted attack examples must not block (FP-5). Exception: a fenced block in an **agent-instruction file** is not an example region — the match keeps full severity (I002 cannot be bypassed by fence-wrapping) |
| Pattern matches inside a source-code docstring | Reported but capped at `MEDIUM` — a docstring is documentation, not an instruction |
| Attack on a line adjacent to a fenced block | Full severity — only content *inside* the region is capped |
| Cue word appears in a bare URL / prose (`example.com/payload`) | Not treated as a cue — cue detection requires label-like phrasing (FP control) |
| False positive on legitimate documentation | Reported as `MEDIUM` severity if the match is inside a `.md` file with `category != "agent_instruction"` |
| Source code file with no comments/strings | `extract_comments_and_strings` falls back to full decoded content (L009); pattern matching degrades gracefully to full-file scanning |
| Pygments unavailable for source code extraction | `extract_comments_and_strings` emits a warning and returns full decoded content; falls back to full-file scanning |
| Chinese/Japanese text with no spaces between words | Regex uses explicit character sequences (e.g., `忽略\s*所有\s*指令`) — word boundary anchoring is not required for CJK patterns |
| Russian verb conjugation variants | Patterns use imperative mood (familiar «ты» form) — the most common form in injection prompts. Infinitive and polite forms are not covered individually |
| Skill file passed to `match_patterns` (not `match_skill_patterns`) | Returns empty list — skill files skip regular injection patterns to avoid false positives |
| Skill file with no skill-specific pattern matches | Returns empty list from `match_skill_patterns()` — byte analysis and heuristics still contribute |
| `rm -rf dist public build` in `package.json` | `DEST_002` capped at `MEDIUM` — routine build cleanup of relative paths (FP-5) |
| `rm -rf /` (or `~`, `$HOME`, `/etc`, `..`) in `package.json` | Stays `CRITICAL` — the target is dangerous and is never routine |
| `curl https://api.vercel.com/…` in a skill | `IPI403` at `LOW` — allowlisted host (FP-9) |
| `curl https://collect.example.org/…` in a skill that reads `$GITHUB_TOKEN` | `IPI403` escalated to `CRITICAL` — corroborated exfiltration |
| Bare `sudo apt-get install …` in a skill | `IPI410` at `HIGH`, not `CRITICAL` |
| "do not use sudo in production" in a skill | Not flagged — the match is immediately preceded by a prohibition (FP-10) |

## Configuration Constants

All patterns are defined as module-level constants. `INJECTION_PATTERNS` (injection detection) has 39 patterns across 9 categories. `SKILL_PATTERNS` (skill-specific) spans the rule IDs IPI401–411 (several rules have more than one sub-pattern). No runtime configuration — but the trusted-domain allowlist is a plain, editable constant.

```python
# Maximum length of matched_text in findings
MAX_MATCHED_TEXT_LENGTH: int = 120

# Regex timeout per pattern per line (seconds) — prevents ReDoS
REGEX_TIMEOUT_SECONDS: float = 0.1

# Severity ceiling for findings inside an example region (FP-5 / FP-11)
EXAMPLE_REGION_SEVERITY_CEILING: Severity = Severity.MEDIUM

# Hosts a legitimate skill may contact — a transmission to one is LOW (FP-9).
# Configurable: add project-specific hosts here.
TRUSTED_DOMAINS: frozenset[str] = frozenset({...})

# External-transmission severity band (IPI403)
EXTERNAL_TRANSMISSION_BASELINE: Severity = Severity.MEDIUM  # unclassified host
EXTERNAL_TRANSMISSION_TRUSTED: Severity = Severity.LOW      # allowlisted host

# Build manifests where relative build-output cleanup is routine (FP-5)
BUILD_CONFIG_FILENAMES: frozenset[str] = frozenset({"package.json"})
DEST_002_BUILD_CONTEXT_SEVERITY: Severity = Severity.MEDIUM
```

All patterns are compiled with `re.IGNORECASE` — matching is case-insensitive across all pattern categories. The regex strings in `INJECTION_PATTERNS` do not include inline `(?i)` flags; the flag is applied uniformly at compilation time.

## Dependencies

- **File Discovery**: receives `DiscoveredFile`
- **Byte-Level Analysis**: normalization uses byte-level findings to strip invisible characters before regex matching

## Invariants

- **P001**: Regex patterns MUST be applied to normalized text (lowercase, whitespace-collapsed, invisible-chars-stripped), NOT to raw bytes. For source code files, the normalized text is derived from extracted comments and string literals (via `extract_comments_and_strings`), not the full file content — this prevents false positives on code identifiers and structural syntax.
- **P002**: Every `PatternFinding` MUST include the `pattern_id` of the rule that matched — for auditability.
- **P003**: Instruction override patterns (`INSTR_001` through `INSTR_006` — including Japanese and Korean variants) and destructive command patterns (`DEST_001` through `DEST_004` — including Russian and Chinese) MUST be classified as CRITICAL severity — with the sole exception that `DEST_002` (`rm -rf`) inside a build manifest is capped at `MEDIUM` for a benign relative target (P010). Data exfiltration patterns (`EXFIL_001` through `EXFIL_006` — including Russian and Chinese) and shell injection (`SHELL_001`) are also CRITICAL.
- **P004**: Regex matching MUST use a timeout (`REGEX_TIMEOUT_SECONDS`) to prevent ReDoS attacks via malicious input.
- **P005**: The normalization step MUST use `errors="replace"` for UTF-8 decoding — the scanner MUST NOT crash on invalid UTF-8.
- **P006**: `match_patterns()` MUST return an empty list for files with `FileCategory.SKILL` — skill files use `match_skill_patterns()` with a separate pattern set (IPI401–411) to avoid false positives from legitimate instructions.
- **P007**: Skill-specific patterns (IPI401–411) MUST use `_SKILL_CATEGORY_DESCRIPTIONS` for human-readable descriptions, distinct from the injection pattern descriptions.
- **P008**: Findings that begin inside an example region (fenced code block, markdown table, inline-code span, cued example list, or source-code string literal / docstring) MUST be capped at `EXAMPLE_REGION_SEVERITY_CEILING` (`MEDIUM`) — never dropped — so a quoted attack example cannot produce a `CRITICAL`/`BLOCK` verdict on its own. Fenced code blocks MUST NOT create an example region in agent-instruction files (`FileCategory.AGENT_INSTRUCTION`): such files are the live instruction channel, and fence-wrapping MUST NOT downgrade a CRITICAL payload (invariant I002). A finding capped by framing in an agent-instruction file MUST carry `framed=True`, and the fused verdict for such a file MUST be floored at `REVIEW_REQUIRED` (never `PASS`).
- **P009**: Content outside an example region MUST be matched at full severity — in particular, a source-code *comment* MUST NOT be treated as an example region, so recall on real injections (e.g. the miasm campaign) is preserved. Markdown framing (fences, tables, inline spans, cue lists) MUST NOT apply to extracted source-code content at all: the `[DOC]`/`[STR]` tags are the only example-region marks there, and the extractor MUST label every emitted line (neutralizing a content-leading protocol token) so a forged tag or label can never occupy the protocol positions.
- **P010**: `DEST_002` (`rm -rf`) inside a build manifest (`BUILD_CONFIG_FILENAMES`) MUST be capped at `DEST_002_BUILD_CONTEXT_SEVERITY` (`MEDIUM`) **only** when its target is benign; a target matching `_DANGEROUS_DEST_TARGET_RE` (filesystem root, `~`/`$HOME`, a system directory, `..`) MUST remain `CRITICAL`.
- **P011**: `IPI403` (external transmission) MUST NOT be `CRITICAL` by default. It is `LOW` for a `TRUSTED_DOMAINS` host and `CRITICAL` only for an `_EXFIL_DOMAIN_RE` host or when the same file corroborates exfiltration with an `IPI402` credential read. All other hosts are `EXTERNAL_TRANSMISSION_BASELINE` (`MEDIUM`).
- **P012**: `IPI410` MUST report a bare `sudo` at `HIGH` and only an inherently destructive escalation (`chmod 7xx`, `chown root`, `pkexec`, `sudo` + destructive payload) at `CRITICAL`. A match immediately preceded by a prohibition ("do not use sudo") MUST be dropped, and the bare-`sudo` sub-pattern MUST NOT duplicate the `CRITICAL` destructive match.

## Cross-References

- [System Overview](../architecture/system-overview.md)
- [File Discovery](file-discovery.md)
- [Byte-Level Analysis](byte-analysis.md)
- [Semantic Heuristics](semantic-heuristics.md)
- [Confidence Fusion](confidence-fusion.md)
- [Reporting](reporting.md)
