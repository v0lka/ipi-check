# Reporting

## Responsibility

Generate a SARIF v2.1.0 report from scan findings. The report aggregates `FinalVerdict` objects into a standards-compliant SARIF document suitable for GitHub Code Scanning, GitLab SAST, and IDE integrations.

## Input

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `verdicts` | `List[FinalVerdict]` | Confidence Fusion | Final per-file decisions with all findings |
| `repo_path` | `Path` | CLI argument | Repository root (for relative path computation) |
| `tool_info` | `ToolInfo` | Package metadata | Tool name, version, semantic version |

```python
@dataclass
class ToolInfo:
    name: str       # "ipi-check"
    version: str    # e.g., "0.1.0"
    semver: str     # e.g., "0.1.0"
```

## Output

The SARIF document is written to a file or stdout. The output target is determined by CLI arguments.

| Target | Format | Description |
|--------|--------|-------------|
| stdout | SARIF JSON (pretty-printed) | Default output when no `--output` flag |
| file | SARIF JSON (compact) | When `--output <file.sarif>` is specified |

## Behavior

```
List[FinalVerdict] + repo_path + tool_info
        │
        ▼
┌───────────────────────────────┐
│ 1. Group verdicts by file     │
│    One sarif.Result per file  │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│ 2. Convert each finding to    │
│    sarif.Result               │
│    - Map severity → level     │
│    - Map category → ruleId    │
│    - Build region (line/col)  │
│    - Build message.text       │
│    - Build message.markdown   │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│ 3. Compute summary counts     │
│    - BLOCK count              │
│    - REVIEW_REQUIRED count    │
│    - PASS count               │
│    - Total files scanned       │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│ 4. Assemble SARIF document    │
│    - version: 2.1.0           │
│    - runs[0].tool             │
│    - runs[0].results          │
│    - runs[0].invocations      │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│ 5. Write output               │
│    - stdout: json.dumps(      │
│      sarif, indent=2)         │
│    - file: json.dumps(        │
│      sarif, separators=...)   │
│      + .sarif extension       │
└───────────────────────────────┘
```

### Severity-to-Level Mapping

| Finding Severity | SARIF Level |
|------------------|-------------|
| CRITICAL | `error` |
| HIGH | `error` |
| MEDIUM | `warning` |
| LOW | `note` |

### Category-to-Rule Mapping

Each finding category maps to a SARIF rule with a stable `ruleId`:

| Category | ruleId | CWE |
|----------|--------|-----|
| `ansi_hidden` | `IPI001` | CWE-506 |
| `unicode_tags` | `IPI002` | CWE-506 |
| `variation_selectors` | `IPI003` | CWE-506 |
| `bidi_override` | `IPI004` | CWE-451 |
| `zero_width` | `IPI005` | CWE-506 |
| `homoglyph` | `IPI006` | CWE-1007 |
| `pua` | `IPI007` | CWE-506 |
| `instruction_override` | `IPI101` | CWE-77 |
| `authority_claim` | `IPI102` | CWE-77 |
| `destructive_command` | `IPI103` | CWE-77 |
| `data_exfiltration` | `IPI104` | CWE-77 |
| `shell_injection` | `IPI105` | CWE-77 |
| `jailbreak` | `IPI106` | CWE-77 |
| `entropy_suspicious` | `IPI201` | CWE-506 |
| `invisible_ratio` | `IPI202` | CWE-506 |
| `instruction_density` | `IPI203` | CWE-77 |
| `llm_finding.*` | `IPI301` | CWE-77 |

**Note on SARIF levels:** LLM findings (`IPI301`) are reported at `warning` level since they represent probabilistic classifications rather than deterministic detections. Byte-level and pattern findings follow the severity-to-level mapping table above. LLM compromise (`IPI900`) is reported at `note` level as it indicates a diagnostic condition rather than a security finding.

### SARIF Document Structure

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "ipi-check",
          "version": "0.1.0",
          "informationUri": "https://github.com/org/ipi-check",
          "rules": [...]
        }
      },
      "invocations": [
        {
          "executionSuccessful": true,
          "startTimeUtc": "2026-06-06T12:00:00Z",
          "endTimeUtc": "2026-06-06T12:00:05Z"
        }
      ],
      "results": [
        {
          "ruleId": "IPI001",
          "level": "error",
          "message": {
            "text": "ANSI escape sequence detected in file",
            "markdown": "**ANSI escape sequence** found at line 5, column 12. This may hide malicious instructions from human reviewers while being visible to AI agents."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": ".cursorrules"
                },
                "region": {
                  "startLine": 5,
                  "startColumn": 12
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

## Edge Cases

| Case | Handling |
|------|----------|
| Zero findings across all files | SARIF output has empty `results` array; `executionSuccessful: true` |
| File with multiple findings of different categories | Multiple `sarif.Result` entries for the same `artifactLocation.uri` |
| Finding without line/column information | `region` is omitted from the `physicalLocation` |
| File path contains special characters | URI-encoded in `artifactLocation.uri` per SARIF spec |
| LLM compromise warnings | Reported as `note`-level result with `ruleId: IPI900` and `CWE-506` |

## Configuration Constants

```python
# SARIF schema version
SARIF_VERSION: str = "2.1.0"

# SARIF schema URL
SARIF_SCHEMA_URL: str = "https://json.schemastore.org/sarif-2.1.0.json"

# Tool name
TOOL_NAME: str = "ipi-check"

# Maximum snippet length in SARIF message (characters)
MAX_MESSAGE_SNIPPET_LENGTH: int = 200

# SARIF output file extension
SARIF_FILE_EXTENSION: str = ".sarif"

# LLM compromise rule ID
LLM_COMPROMISE_RULE_ID: str = "IPI900"
```

## Dependencies

- **Confidence Fusion**: receives `List[FinalVerdict]`

## Invariants

- **R001**: The SARIF output MUST conform to SARIF v2.1.0 schema — the `$schema` field MUST reference the official schema URL.
- **R002**: Every finding MUST include an `artifactLocation.uri` relative to the repository root.
- **R003**: SARIF `level` MUST map deterministically from finding severity: CRITICAL→`error`, HIGH→`error`, MEDIUM→`warning`, LOW→`note`.
- **R004**: The tool `driver.name` MUST be `"ipi-check"` and `driver.version` MUST match the package version.
- **R005**: User-controlled content in SARIF `message.text` and `message.markdown` MUST be escaped to prevent SARIF injection.
- **R006**: If the output target is a file, the extension MUST be `.sarif`.
- **R007**: The SARIF output MUST include an `invocations` array with `executionSuccessful` and timestamps.

## Cross-References

- [System Overview](../architecture/system-overview.md)
- [Security Model](../architecture/security-model.md) — AV3: SARIF Injection
- [Confidence Fusion](confidence-fusion.md)
- [CLI Interface](../contracts/cli-interface.md)
- [ADR-002: SARIF Format](../decisions/002-sarif-format.md)
