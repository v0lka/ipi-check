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
    severity: str          # "CRITICAL" | "HIGH" | "MEDIUM"
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
│ 3. Scan for       │  Search for U+FE00–U+FE0F (VS1–VS16)
│    variation      │  → category: "variation_selectors"
│    selectors      │  → severity: HIGH
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
│ 7. Detect         │  Compare character sets: Cyrillic 'а' in mostly-Latin text
│    homoglyphs     │  → category: "homoglyph"
└────────┬──────────┘  → severity: MEDIUM
         │
         ▼
  List[ByteFinding]
```

### Severity Assignment Logic

- **CRITICAL**: Active concealment techniques — ANSI escape sequences that erase/hide text, Unicode tag characters (designed for invisible metadata)
- **HIGH**: Bidi overrides (visual text reordering), variation selectors (encoding channel)
- **MEDIUM**: Zero-width characters, PUA characters (may be legitimate in some contexts), homoglyphs (may be false positives for multilingual text)

### Line/Column Resolution

Byte-level findings resolve to line/column by counting newline bytes (`\n`) before the matched offset. This enables precise location reporting in SARIF output.

## Edge Cases

| Case | Handling |
|------|----------|
| Empty file (0 bytes) | Return empty findings list |
| File is pure binary (non-text) | Skipped at File Discovery stage; if reached, scan bytes but flag as `FILE_APPEARS_BINARY` warning. Homoglyph detection is skipped. |
| Valid ANSI sequences in legitimate contexts | Always reported. ANSI escapes in instruction files are always suspicious — there is no legitimate use case in AGENTS.md or source code. |
| Multilingual files with natural homoglyphs | Homoglyph detection uses ratio: if Cyrillic-looking characters exceed `HOMOGLYPH_RATIO_THRESHOLD` of total Latin+Cyrillic chars, the file is flagged. |
| Overlapping findings (same byte matches multiple categories) | Report all matches independently. Each byte offset can produce multiple `ByteFinding` entries with different categories. |
| Very long lines (>10K characters) | Line resolution still works — newline counting does not depend on line length. |

## Configuration Constants

```python
# Byte-level signatures as compiled regex patterns on bytes
BYTE_SIGNATURES: dict[str, bytes] = {
    "ansi_escape":    rb"\x1b\[\d*(?:;\d+)*m",       # ANSI SGR sequences
    "ansi_erase":     rb"\x1b\[2K",                   # Erase line
    "ansi_hide":      rb"\x1b\[8m",                   # Hide text
    "unicode_tags":   rb"[\xf3][\xa0][\x80-\x81][\x80-\xbf]",  # U+E0000 block
    "variation_selectors": rb"\xef\xb8[\x80-\xaf]",   # VS1-VS16 (U+FE00-U+FE0F)
    "bidi_override":  rb"\xe2\x80[\xaa-\xae]",        # U+202A-U+202E
    "bidi_isolate":   rb"\xe2\x81[\xa6-\xa9]",        # U+2066-U+2069
    "zero_width":     rb"\xe2\x80[\x8b-\x8f]",        # U+200B-U+200F
    "line_separator": rb"\xe2\x80[\xa8-\xa9]",        # U+2028-U+2029 (line/paragraph sep)
}

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

# Threshold: if ratio of homoglyph chars to total Latin+Cyrillic chars exceeds this, flag
HOMOGLYPH_RATIO_THRESHOLD: float = 0.05

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
- **B004**: Homoglyph detection MUST NOT flag files that are legitimately multilingual (e.g., a Russian README). The `HOMOGLYPH_RATIO_THRESHOLD` and character-set heuristics prevent this.
- **B005**: Every `ByteFinding` MUST include a resolved line number and column for SARIF reporting.

## Cross-References

- [System Overview](../architecture/system-overview.md)
- [Security Model](../architecture/security-model.md) — AV1: LLM Classifier Prompt Injection
- [File Discovery](file-discovery.md)
- [Pattern Matching](pattern-matching.md)
- [Semantic Heuristics](semantic-heuristics.md)
- [Reporting](reporting.md)
