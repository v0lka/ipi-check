# Byte-Level Analysis

## Responsibility

Detect hidden or obfuscated content in files by scanning raw bytes — not rendered text. This layer catches payloads that are invisible to text-based analysis: ANSI escape sequences, Unicode tag characters, zero-width characters, bidi overrides, variation selectors, homoglyphs, and PUA characters.

## Input

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `file` | `DiscoveredFile` | File Discovery | File metadata and path |
| `raw_bytes` | `bytes` | File system (read in binary mode) | Full file content as raw bytes |

## Output

| Field | Type | Consumers | Description |
|-------|------|-----------|-------------|
| `findings` | `List[ByteFinding]` | StaticResult assembler, Pattern Matching (for normalization) | Detected hidden-content issues |

```python
@dataclass
class ByteFinding:
    category: str          # "ansi_hidden" | "unicode_tags" | "variation_selectors"
                           # | "bidi_override" | "zero_width" | "homoglyph" | "pua"
    severity: str          # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    line: int              # 1-based line number where found
    column: int            # 1-based column where found
    snippet_hex: str       # Hex representation of the suspicious bytes (max 32 bytes)
    description: str       # Human-readable explanation
```

## Behavior

```
DiscoveredFile + raw_bytes
        │
        ▼
┌───────────────────┐
│ 1. Scan for ANSI  │  Search for \x1b[...m, \x1b[2K, \x1b[8m
│    escape seqs    │  → category: "ansi_hidden"
└────────┬──────────┘  → severity: CRITICAL
         │
         ▼
┌───────────────────┐
│ 2. Scan for       │  Search for U+E0000–U+E007F (Unicode tag block)
│    Unicode tags   │  → category: "unicode_tags"
└────────┬──────────┘  → severity: CRITICAL
         │
         ▼
┌───────────────────┐
│ 3. Scan for       │  Search for U+FE00–U+FE0E (VS1–VS15)
│    variation      │  → category: "variation_selectors"
│    selectors      │  → severity: HIGH
│                   │  U+FE0F (VS16) is reported only when it lacks a
│                   │  preceding emoji base or U+FE0F density is anomalous
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│ 4. Scan for bidi  │  Search for U+202A–U+202E, U+2066–U+2069
│    overrides      │  → category: "bidi_override"
└────────┬──────────┘  → severity: HIGH
         │
         ▼
┌───────────────────┐
│ 5. Scan for zero- │  Search for U+200B–U+200F, U+2028, U+2029, U+202A–U+202E
│    width chars    │  → category: "zero_width"
└────────┬──────────┘  → severity: MEDIUM
         │
         ▼
┌───────────────────┐
│ 6. Scan for PUA   │  Search for U+E000–U+F8FF (Private Use Area)
│    characters     │  → category: "pua"
└────────┬──────────┘  → severity: MEDIUM
         │
         ▼
┌───────────────────┐
│ 7. Detect         │  Flag word tokens (maximal \w+ runs) that mix Latin and
│    homoglyphs     │  Cyrillic letters — e.g. Cyrillic 'а' inside "pаypal"
└────────┬──────────┘  → category: "homoglyph"
         │             → severity: MEDIUM (LOW when no Latin lookalike)
         │             → at most 1 finding per file
         ▼
  List[ByteFinding]
```

### Severity Assignment Logic

- **CRITICAL**: Active concealment techniques — ANSI escape sequences that erase/hide text, Unicode tag characters (designed for invisible metadata)
- **HIGH**: Bidi overrides (visual text reordering), variation selectors (encoding channel). The emoji presentation selector U+FE0F (VS16) is downgraded to "not reported" when it legitimately follows an emoji base character (e.g. `⚠` U+26A0) and the file's U+FE0F density is normal.
- **MEDIUM**: Zero-width characters, PUA characters (may be legitimate in some contexts), and homoglyphs spliced into a Latin token (a confusable Cyrillic lookalike inside a mixed-script identifier, e.g. `pаypal`)
- **LOW**: Script mixing within a token that contains no confusable Latin lookalike — reported as a note, not a warning

### Homoglyph Detection (token granularity)

Homoglyph detection does **not** use a whole-file Cyrillic ratio. A legitimate multilingual document (e.g. a Russian README) places Latin and Cyrillic words side by side, but never inside the same token; a homoglyph attack replaces a Latin letter with a lookalike Cyrillic one *within a single identifier*.

Detection therefore works at token granularity:

1. Split the decoded text into word tokens (maximal Unicode `\w+` runs).
2. A token is a **mixed-script token** when it contains both Latin and Cyrillic letters. Tokens that are entirely Latin or entirely Cyrillic are never flagged.
3. The **suspicious mix ratio** is the number of mixed-script tokens containing a confusable Cyrillic lookalike (`HOMOGLYPH_MAP`) divided by the total number of word tokens.
4. At most `MAX_HOMOGLYPH_FINDINGS_PER_FILE` finding is emitted per file (the offending token's position is reported). Severity is `MEDIUM` when a confusable lookalike is present, `LOW` when scripts merely mix without one, and no finding is emitted when there is no mixed-script token at all.

### Line/Column Resolution

Byte-level findings resolve to line/column by counting newline bytes (`\n`) before the matched offset. This enables precise location reporting in SARIF output.

## Edge Cases

| Case | Handling |
|------|----------|
| Empty file (0 bytes) | Return empty findings list |
| File is pure binary (non-text) | Excluded during File Discovery by the binary sniff (`BINARY_EXTENSIONS` + `_has_binary_magic` container-magic check); it never reaches this layer. `analyze_bytes` applies no binary check of its own |
| Valid ANSI sequences in legitimate contexts | Always reported. ANSI escapes in instruction files are always suspicious — there is no legitimate use case in AGENTS.md or source code. |
| Multilingual files with natural homoglyphs | Never flagged: detection is per token, so Latin and Cyrillic words side by side (a Russian README) produce no mixed-script token. Only a Cyrillic lookalike spliced *inside* a Latin token is reported. |
| Overlapping findings (same byte matches multiple categories) | Report all matches independently. Each byte offset can produce multiple `ByteFinding` entries with different categories. |
| Emoji with a presentation selector (`⚠️`, `✅`) | U+FE0F directly after an emoji base is legitimate and not reported. It is reported only when it has no preceding emoji base, or when U+FE0F density is anomalous. |
| Duplicate findings | Identical `(category, severity, line, column, snippet_hex)` findings are collapsed to one per file, preserving order. |
| Very long lines (>10K characters) | Line resolution still works — newline counting does not depend on line length. |

## Configuration Constants

```python
# Byte-level signatures as compiled regex patterns on bytes
BYTE_SIGNATURES: dict[str, bytes] = {
    "ansi_escape":    rb"\x1b\[\d*(?:;\d+)*m",       # ANSI SGR sequences
    "ansi_erase":     rb"\x1b\[2K",                   # Erase line
    "ansi_hide":      rb"\x1b\[8m",                   # Hide text
    "unicode_tags":   rb"[\xf3][\xa0][\x80-\x81][\x80-\xbf]",  # U+E0000 block
    "variation_selectors": rb"\xef\xb8[\x80-\x8e]",   # VS1-VS15 (U+FE00-U+FE0E)
    "bidi_override":  rb"\xe2\x80[\xaa-\xae]",        # U+202A-U+202E
    "bidi_isolate":   rb"\xe2\x81[\xa6-\xa9]",        # U+2066-U+2069
    "zero_width":     rb"\xe2\x80[\x8b-\x8f]",        # U+200B-U+200F
    "line_separator": rb"\xe2\x80[\xa8-\xa9]",        # U+2028-U+2029 (line/paragraph sep)
}

# Emoji presentation selector (VS16, U+FE0F) — handled separately from the
# BYTE_SIGNATURES table because it is legitimate directly after an emoji base
# (e.g. `⚠` U+26A0 + U+FE0F). Raw UTF-8 bytes: EF B8 8F.
VS16_CHAR: str = "\ufe0f"

# Unicode Emoji property — the characters a presentation selector may modify.
EMOJI_BASE_PATTERN: regex.Pattern[str] = regex.compile(r"\p{Emoji}")

# U+FE0F following an emoji base is still reported only when the file is
# saturated with selectors: at least VS16_MIN_COUNT_FOR_DENSITY of them, and
# their share of the decoded characters above VS16_DENSITY_THRESHOLD.
VS16_DENSITY_THRESHOLD: float = 0.10
VS16_MIN_COUNT_FOR_DENSITY: int = 10

# Homoglyph mapping: Cyrillic lookalikes → Latin equivalents
HOMOGLYPH_MAP: dict[str, str] = {
    "а": "a",  # Cyrillic small a
    "е": "e",  # Cyrillic small ie
    "о": "o",  # Cyrillic small o
    "р": "p",  # Cyrillic small er
    "с": "c",  # Cyrillic small es
    "у": "y",  # Cyrillic small u
    "х": "x",  # Cyrillic small ha
    "А": "A",  # Cyrillic capital a
    "В": "B",  # Cyrillic capital ve
    "Е": "E",  # Cyrillic capital ie
    "К": "K",  # Cyrillic capital ka
    "М": "M",  # Cyrillic capital em
    "Н": "H",  # Cyrillic capital en
    "О": "O",  # Cyrillic capital o
    "Р": "P",  # Cyrillic capital er
    "С": "C",  # Cyrillic capital es
    "Т": "T",  # Cyrillic capital te
    "Х": "X",  # Cyrillic capital ha
}

# Word tokens are maximal Unicode \w+ runs (script-agnostic).
WORD_TOKEN_PATTERN = re.compile(r"\w+")

# Cyrillic letters (U+0400–U+04FF).
CYRILLIC_LETTER_PATTERN = re.compile(r"[\u0400-\u04FF]")

# Cyrillic characters confusable with a Latin counterpart.
CONFUSABLE_HOMOGLYPH_CHARS: frozenset[str] = frozenset(HOMOGLYPH_MAP)

# Cap on homoglyph (IPI006) findings emitted per file.
MAX_HOMOGLYPH_FINDINGS_PER_FILE: int = 1

# Max bytes to include in snippet_hex
MAX_HEX_SNIPPET_BYTES: int = 32
```

## Dependencies

- **File Discovery**: receives `DiscoveredFile` objects
- **Pattern Matching**: consumes this module's output indirectly (Pattern Matching operates on text normalized after stripping byte-level findings)

## Invariants

- **B001**: All files MUST be read in binary mode (`"rb"`) — text mode corrupts byte-level signatures.
- **B002**: ANSI escape sequences with hide/erase semantics (`\x1b[8m`, `\x1b[2K`) MUST be classified as CRITICAL severity.
- **B003**: Unicode tag characters (U+E0000 block) MUST be classified as CRITICAL severity — they have no legitimate use outside of Unicode's intended tagging mechanism.
- **B004**: Homoglyph detection MUST NOT flag files that are legitimately multilingual (e.g., a Russian README). Detection is scoped to mixed-script tokens (Latin and Cyrillic within a single `\w+` run), so words in different scripts are never flagged.
- **B006**: Homoglyph detection MUST emit at most `MAX_HOMOGLYPH_FINDINGS_PER_FILE` finding per file, regardless of how many mixed-script tokens are present.
- **B005**: Every `ByteFinding` MUST include a resolved line number and column for SARIF reporting.
- **B007**: The emoji presentation selector (U+FE0F, VS16) MUST NOT be reported when it directly follows an emoji base and the file's U+FE0F density is normal — ordinary emoji (`⚠️`, `✅`) must not raise IPI003. VS1–VS15 (U+FE00–U+FE0E) remain unconditionally HIGH.

## Cross-References

- [System Overview](../architecture/system-overview.md)
- [Security Model](../architecture/security-model.md) — AV1: LLM Classifier Prompt Injection
- [File Discovery](file-discovery.md)
- [Pattern Matching](pattern-matching.md)
- [Semantic Heuristics](semantic-heuristics.md)
- [Reporting](reporting.md)
