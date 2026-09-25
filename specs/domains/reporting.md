# Reporting

## Responsibility

Generate a SARIF v2.1.0 report from scan findings. The report aggregates `FinalVerdict` objects (per-file) and `SkillFinalVerdict` objects (per-skill) into a standards-compliant SARIF document suitable for GitHub Code Scanning, GitLab SAST, and IDE integrations.

## Input

| Field            | Type                          | Source            | Description                                     |
| ---------------- | ----------------------------- | ----------------- | ----------------------------------------------- |
| `verdicts`       | `List[FinalVerdict]`          | Confidence Fusion | Final per-file decisions with all findings      |
| `skill_verdicts` | `List[SkillFinalVerdict]`     | Confidence Fusion | Final per-skill decisions (optional)            |
| `repo_path`      | `Path`                        | CLI argument      | Repository root (for relative path computation) |
| `tool_info`      | `ToolInfo`                    | Package metadata  | Tool name, version, semantic version            |

```python
@dataclass
class ToolInfo:
    name: str       # "ipi-check"
    version: str    # e.g., "0.1.0"
    semver: str     # e.g., "0.1.0"
```

## Output

The SARIF document is written to a file or stdout. The output target is determined by CLI arguments.

| Target | Format                      | Description                               |
| ------ | --------------------------- | ----------------------------------------- |
| stdout | SARIF JSON (pretty-printed) | Default output when no `--output` flag    |
| file   | SARIF JSON (compact)        | When `--output <file.sarif>` is specified |

## Behavior

```
List[FinalVerdict] + List[SkillFinalVerdict]? + repo_path + tool_info
        │
        ▼
┌───────────────────────────────┐
│ 1. Build per-file results     │
│    One sarif.Result per file  │
│    finding (from verdicts)    │
│    + heuristic results        │
│    PASS verdicts → no results │
└───────────────┬───────────────┘
                │
        ┌───────┴────────┐
        │ skill_verdicts?│
        ├───────┬────────┤
        │ YES   │ NO     │
        ▼       ▼
┌──────────────┐   skip
│ 1b. Build    │
│    per-skill │
│    results   │
│    (one per  │
│    skill)    │
└──────┬───────┘
       │
       └────────────────┐
                        ▼
┌───────────────────────────────┐
│ 2. Convert each finding to    │
│    sarif.Result               │
│    - Map severity → level     │
│    - Map category → ruleId    │
│    - Build region (line/col)  │
│    - Build message.text       │
│    - Build message.markdown   │
│    - Attach partialFingerprints│
│    - Attach properties        │
│      (confidence, pattern_id) │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│ 2b. Deduplicate + cap         │
│    - Collapse identical       │
│      (ruleId, uri, line,      │
│       column, snippet)        │
│    - Keep ≤ N per file        │
│      (≥1 per ruleId)          │
│    - Count suppressed         │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│ 3. Compute summary counts     │
│    - BLOCK count              │
│    - REVIEW_REQUIRED count    │
│    - PASS count               │
│    - Total files scanned       │
│    - Skill verdict counts     │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│ 4. Assemble SARIF document    │
│    - version: 2.1.0           │
│    - runs[0].tool             │
│    - runs[0].results          │
│    - runs[0].invocations      │
│    - summary counters         │
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
| ---------------- | ----------- |
| CRITICAL         | `error`     |
| HIGH             | `error`     |
| MEDIUM           | `warning`   |
| LOW              | `note`      |

### Category-to-Rule Mapping

Each finding category maps to a SARIF rule with a stable `ruleId`:

| Category               | ruleId   | CWE      |
| ---------------------- | -------- | -------- |
| `ansi_hidden`          | `IPI001` | CWE-506  |
| `unicode_tags`         | `IPI002` | CWE-506  |
| `variation_selectors`  | `IPI003` | CWE-506  |
| `bidi_override`        | `IPI004` | CWE-451  |
| `zero_width`           | `IPI005` | CWE-506  |
| `homoglyph`            | `IPI006` | CWE-1007 |
| `pua`                  | `IPI007` | CWE-506  |
| `instruction_override` | `IPI101` | CWE-77   |
| `authority_claim`      | `IPI102` | CWE-77   |
| `destructive_command`  | `IPI103` | CWE-77   |
| `data_exfiltration`    | `IPI104` | CWE-77   |
| `shell_injection`      | `IPI105` | CWE-77   |
| `jailbreak`            | `IPI106` | CWE-77   |
| `social_engineering`   | `IPI107` | CWE-77   |
| `obfuscation`          | `IPI108` | CWE-77   |
| `instruction_contradiction` | `IPI109` | CWE-77 |
| `entropy_suspicious`   | `IPI201` | CWE-506  |
| `invisible_ratio`      | `IPI202` | CWE-506  |
| `instruction_density`  | `IPI203` | CWE-77   |
| `contradiction`        | `IPI204` | CWE-77   |
| `llm_finding.*`        | `IPI301` | CWE-77   |
| `remote_execution`     | `IPI401` | CWE-77   |
| `credential_harvesting`| `IPI402` | CWE-77   |
| `external_transmission`| `IPI403` | CWE-77   |
| `dynamic_context`      | `IPI404` | CWE-77   |
| `excessive_permissions`| `IPI405` | CWE-506  |
| `obfuscated_skill_code`| `IPI406` | CWE-506  |
| `hidden_instructions`  | `IPI407` | CWE-77   |
| `command_injection_skill`| `IPI408` | CWE-77 |
| `skill_secrecy`        | `IPI409` | CWE-77   |
| `privilege_escalation` | `IPI410` | CWE-77   |
| `file_system_enumeration`| `IPI411` | CWE-506 |

**Note on SARIF levels:** LLM findings (`IPI301`) are reported at `warning` level since they represent probabilistic classifications rather than deterministic detections. Byte-level and pattern findings follow the severity-to-level mapping table above. LLM compromise (`IPI900`) is reported at `note` level as it indicates a diagnostic condition rather than a security finding.

**Skill-level rule selection.** A skill verdict aggregates findings across every bundled file, so its single emitted result carries the `ruleId` of its **heaviest mapped static finding** (IN-1) — a skill that blocks purely on byte findings is labelled with the matching byte rule (e.g. `IPI003`), never `IPI401`. When no static finding maps to a rule, the `ruleId` falls back in order to `IPI601` (skill LLM-detected malicious behaviour), the `IPI900` compromise diagnostic (for a degraded classification), then `IPI501` (skill heuristic — suspicious behaviour/description mismatch).

### Result Gating, Deduplication and Per-File Cap

Five deterministic rules shape the `results` array immediately before the
SARIF document is assembled, in this order:

1. **PASS exclusion.** A `PASS` verdict (file or skill) contributes **no**
   results: the fused decision already adjudicated its findings as
   non-actionable, so a PASS file or skill is represented only in the
   invocation summary (see below), never in `results`. This removes the
   `level: none` placeholder that a PASS skill used to emit. The single
   exception is the `IPI900` compromise diagnostic, which is emitted
   regardless of the decision so a degraded LLM classification stays visible
   (IN-14).
2. **Severity threshold.** An individual finding whose severity falls below
   `severity_threshold` (CLI `--severity-threshold`; default
   `DEFAULT_SEVERITY_THRESHOLD` = `NONE`, i.e. keep everything) is dropped
   *before* deduplication, so it is never counted as a duplicate. Byte and
   pattern findings use their own severity; LLM findings are treated as
   `MEDIUM` (they map to a `warning` level); the `IPI900` compromise note as
   `LOW`; standalone heuristic notices as `MEDIUM`. Skill-level results — one
   aggregated result per skill — are **not** subject to the threshold. The
   number dropped is counted as `below_threshold_removed`.
3. **Heuristic gating.** Standalone heuristic results (`IPI201`–`IPI204`) are
   emitted only for non-`PASS` verdicts. A `PASS` decision means the fused
   analysis found nothing actionable, so heuristic notices are suppressed to
   keep clean files quiet.
4. **Deduplication.** Results that are identical in
   `(ruleId, artifactLocation.uri, startLine, startColumn, snippet)` are
   collapsed to their first occurrence. The snippet component is the raw
   finding payload — `snippet_hex` for byte findings, `matched_text` for
   pattern findings, and `category`/`explanation` for LLM findings (heuristic
   and compromise results carry an empty snippet). This removes genuine
   duplicates (for example, the same string literal repeated on one source
   line produces several identical findings).
5. **Per-file cap.** Each file (`artifactLocation.uri`) contributes at most
   `DEFAULT_MAX_FINDINGS_PER_FILE` (50) results. The first `N` results
   survive, except that the first occurrence of every distinct `ruleId` in
   the file is always retained — so the set of emitted `ruleId` values is
   stable even when a rare rule only appears late in a large file. When a
   file contains more distinct rule IDs than the cap, only the earliest `cap`
   first-occurrences are kept. A cap of `0` disables the limit.

All four counts (findings dropped below the threshold, duplicates removed,
results dropped by the cap, and results marked suppressed) are returned as a
`SarifLimitStats` by `generate_sarif_with_stats()` and reported on stderr by
the CLI.

### Suppressions (`.ipi-checkignore` + inline directives)

A finding can be suppressed so that consumers treat it as an accepted false
positive **without losing the audit trail**. Two inputs feed a repository-level
`SuppressionPolicy`, which the pipeline attaches to every verdict:

- **`.ipi-checkignore`** — a gitignore-syntax file at the repository root
  (`IGNORE_FILE_NAME`). Each effective line is either a gitignore path pattern
  (suppresses *every* rule in matching files) or one or more `IPI###` rule ids,
  optionally followed by a path pattern (suppresses those rules, in matching
  files or everywhere when no pattern is given). A leading `!` negates the entry
  (the last matching entry wins); blank lines and `#` comments are ignored.
- **Inline directives** in a scanned file, recognised only in a comment
  context — the token must be preceded on the line by a comment marker
  (`#`, `//`, `/* … */`, `<!-- … -->`, `--`, `;`) at the line start or after
  whitespace. A bare prose mention of `ipi-check:ignore` inside untrusted
  content is NOT a directive (untrusted content must not be able to suppress
  its own findings):
  - `ipi-check:ignore[IPI006]` / `ipi-check:ignore[IPI006,IPI101]` — suppress the
    listed rules on the directive's line **and the line below it**, so the
    directive may sit on the same line as the finding or directly above it;
  - `ipi-check:ignore` (no brackets) — suppress every rule on those lines;
  - `ipi-check:ignore-file[...]` — the same rule set, scoped to the whole file.

  Inline directives are honoured **in source-code files only** (`FileCategory.SOURCE_CODE`).
  The comment marker is the trust boundary: in source code it denotes an author
  annotation (like `# noqa`). In markdown-family files — agent instructions,
  dot-directory markdown, `SKILL.md` and bundled skill files — `#` is a
  *heading* and `<!--` an HTML comment, i.e. ordinary attacker-writable prose,
  so a directive there would let injected content suppress its own findings.
  Those files suppress exclusively through `.ipi-checkignore` (R012). Within a
  source file, the directive's line must moreover be a real comment token
  (Pygments classification): a directive inside a string literal is untrusted
  *data*, not an annotation, and is ignored — as is every directive when the
  file cannot be tokenized (fail closed).

Suppression is a **reporting** concern: it never changes a verdict's decision.
A suppressed result is **kept in `results`** and gains a standard SARIF
`suppressions` array whose single entry carries `kind` (`external` for
`.ipi-checkignore`, `inSource` for an inline directive), `status: "accepted"`,
and a human-readable `justification` (R012). Consumers such as GitHub Code
Scanning therefore hide an accepted suppression while it stays auditable in the
document.

```json
{
  "ruleId": "IPI101",
  "level": "warning",
  "message": { "text": "…", "markdown": "…" },
  "locations": [ … ],
  "suppressions": [
    {
      "kind": "external",
      "status": "accepted",
      "justification": "IPI101 suppressed by .ipi-checkignore (samples/fp-corpus/)"
    }
  ]
}
```

The number of suppressed results is exposed as
`SarifLimitStats.suppressed_results` and as `resultsSuppressed` in the run
summary. (These results are *not* removed from `results` — unlike the
dedup/cap/threshold funnel — so `resultsEmitted` still counts them.)

### Result Identity (`partialFingerprints`)

Every emitted result carries a `partialFingerprints` object so a consumer
(GitHub Code Scanning, GitLab SAST, IDE viewers) can match an alert across runs
instead of opening a duplicate each time the tree is re-scanned:

```json
"partialFingerprints": {
  "primaryLocationLineHash": "39fa2ee980eb94b0:1",
  "ipiCheck/v1": "39fa2ee980eb94b0"
}
```

- `primaryLocationLineHash` is the only key GitHub Code Scanning consumes; the
  namespaced `ipiCheck/v1` key carries the same digest for other consumers.
- The digest is the first 16 hex characters of
  `SHA-256("ruleId␟uri␟line␟snippet")`, where `␟` is U+001F — a separator that
  cannot occur in any component, so distinct tuples can never collide through
  concatenation. `primaryLocationLineHash` appends GitHub's `:1` occurrence
  suffix.
- Every component is deterministic, so **two scans of unchanged content produce
  identical fingerprints** — the basis of stable alert identity. The *snippet*
  component is the raw detector payload, chosen to be reproducible:
  - byte finding → `snippet_hex`;
  - pattern finding → `matched_text`;
  - LLM finding → the finding **category only** — the model-generated
    `explanation` is deliberately *excluded*, since the classifier may reword
    it between runs and that must not change the alert's identity;
  - heuristic / compromise / skill results → the empty string.
- Results with no region (skill, heuristic, compromise) fingerprint at line
  `0`.
- Fingerprints are attached before deduplication/capping, so the identity of a
  surviving result never depends on the order or the size of the result set.

### Result Properties (`properties`)

SARIF forbids unknown top-level `result` keys (`additionalProperties: false`),
so tool-specific data lives in the result's `properties` bag — a `propertyBag`
that explicitly accepts additional properties:

```json
"properties": { "confidence": 1.0, "pattern_id": "INSTR_001" }
```

| Property     | Type   | Meaning                                                                                                                                                    |
| ------------ | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `confidence` | number | `1.0` for a deterministic detection (byte, pattern, heuristic), the classifier's `llm_confidence` for an LLM finding, and `0.0` for the `IPI900` diagnostic |
| `pattern_id` | string | The most specific detector identifier — the internal pattern id for a regex finding (`INSTR_001`), otherwise the result's own `ruleId`                       |

### Run Summary (`invocations[0].properties`)

Because PASS verdicts are excluded from `results`, the reporter records them —
and the decision breakdown of the whole run — in a summary attached to
`runs[0].invocations[0].properties`:

| Property                | Meaning                                              |
| ----------------------- | ---------------------------------------------------- |
| `filesScanned`          | Number of per-file verdicts                          |
| `filesBlocked`          | Files decided `BLOCK`                                |
| `filesReviewRequired`   | Files decided `REVIEW_REQUIRED`                      |
| `filesPassed`           | Files decided `PASS` (excluded from `results`)       |
| `skillsScanned`         | Number of skill verdicts                             |
| `skillsBlocked`         | Skills decided `BLOCK`                               |
| `skillsReviewRequired`  | Skills decided `REVIEW_REQUIRED`                     |
| `skillsPassed`          | Skills decided `PASS` (excluded from `results`)      |
| `resultsEmitted`        | Number of results actually emitted in `results`      |
| `resultsSuppressed`     | Emitted results carrying an accepted suppression      |
| `suppressionSources`    | The repo-provided suppression configuration: `.ipi-checkignore` entry count and (up to 100) entries, plus every file carrying inline directives. Suppressed results carry SARIF `status: "accepted"` (which GitHub Code Scanning hides), so the configuration that silenced them MUST be visible in the same document — an attacker-authored ignore file cannot suppress alerts without a machine-readable trail |

The summary is always present (even for an empty scan), so exclusion of PASS
verdicts is never silent.

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
          "semanticVersion": "0.1.0",
          "informationUri": "https://github.com/v0lka/ipi-check",
          "rules": [...]
        }
      },
      "invocations": [
        {
          "executionSuccessful": true,
          "startTimeUtc": "2026-06-06T12:00:00Z",
          "endTimeUtc": "2026-06-06T12:00:05Z",
          "properties": {
            "filesScanned": 42,
            "filesBlocked": 1,
            "filesReviewRequired": 3,
            "filesPassed": 38,
            "skillsScanned": 4,
            "skillsBlocked": 1,
            "skillsReviewRequired": 0,
            "skillsPassed": 3,
            "resultsEmitted": 12,
            "resultsSuppressed": 0
          }
        }
      ],
      "results": [
        {
          "ruleId": "IPI001",
          "level": "error",
          "message": {
            "text": "ANSI escape sequence detected",
            "markdown": "**IPI001** at line 5, column 12: ANSI escape sequence detected (snippet: `1b[31m...`)"
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
          ],
          "partialFingerprints": {
            "primaryLocationLineHash": "39fa2ee980eb94b0:1",
            "ipiCheck/v1": "39fa2ee980eb94b0"
          },
          "properties": {
            "confidence": 1.0,
            "pattern_id": "IPI001"
          }
        }
      ]
    }
  ]
}
```

## Edge Cases

| Case                                                | Handling                                                            |
| --------------------------------------------------- | ------------------------------------------------------------------- |
| Zero findings across all files                      | SARIF output has empty `results` array; `executionSuccessful: true` |
| File with multiple findings of different categories | Multiple `sarif.Result` entries for the same `artifactLocation.uri` |
| Finding without line/column information             | `region` is omitted from the `physicalLocation`                     |
| File path contains special characters               | URI-encoded in `artifactLocation.uri` per SARIF spec                |
| LLM compromise warnings                             | Reported as `note`-level result with `ruleId: IPI900` and `CWE-506` |
| Skill verdict (no specific line)                    | Skill result uses SKILL.md as primary location with `relatedLocations` pointing to all bundled files |
| Skill with no findings (PASS)                       | Skill excluded from SARIF results, counted as `skillsPassed` in the invocation summary (no `level: none` placeholder) |
| File with a PASS decision                           | Excluded from `results`; counted as `filesPassed` in the invocation summary |
| Any PASS verdict                                    | Contributes no `level: none` result — `results` never carries `level: none` |
| File with duplicate findings                        | Identical `(ruleId, uri, line, column, snippet)` results are collapsed to one |
| File exceeding the per-file cap                     | Truncated to `--max-findings-per-file` results, keeping one per `ruleId` |
| Finding below `--severity-threshold`                | Dropped before deduplication/cap; counted as `SarifLimitStats.below_threshold_removed` |
| Finding matched by `.ipi-checkignore` or inline directive | Kept in `results` with an accepted `suppressions` entry (`kind` `external`/`inSource`); counted as `resultsSuppressed` |
| `.ipi-checkignore` negation (`!pattern`)            | Re-includes a finding suppressed by an earlier entry — the last matching entry wins |
| No `.ipi-checkignore` and no inline directive       | Empty policy: no result carries `suppressions` |
| Re-scan of an unchanged tree                        | Every result keeps its `partialFingerprints` — alert identity is stable across runs |
| LLM finding reworded between runs                   | Fingerprint unchanged — the free-text `explanation` is excluded from the digest |
| Result with no region (skill/heuristic/compromise)  | Fingerprint computed at line `0` |
| Consumer-specific result metadata                   | Carried in `properties` (a `propertyBag`), since `result` forbids unknown keys |

## Configuration Constants

```python
# SARIF schema version
SARIF_VERSION: str = "2.1.0"

# SARIF schema URL
SARIF_SCHEMA_URL: str = "https://json.schemastore.org/sarif-2.1.0.json"

# Tool information URI (rule help links). The tool *name* is TOOL_INFO.name in __init__.py.
TOOL_INFORMATION_URI: str = "https://github.com/v0lka/ipi-check"

# Maximum snippet length in SARIF message (characters)
MAX_MESSAGE_SNIPPET_LENGTH: int = 200

# SARIF output file extension (enforced by the CLI in cli/main.py — see R006)
SARIF_FILE_EXTENSION: str = ".sarif"

# LLM compromise rule ID
LLM_COMPROMISE_RULE_ID: str = "IPI900"

# Default maximum SARIF results emitted per file (0 = unlimited)
DEFAULT_MAX_FINDINGS_PER_FILE: int = 50

# Default minimum severity for emitting an individual finding (NONE = keep all)
DEFAULT_SEVERITY_THRESHOLD: Severity = Severity.NONE
```

## Dependencies

- **Confidence Fusion**: receives `List[FinalVerdict]` and `List[SkillFinalVerdict]`

## Invariants

- **R001**: The SARIF output MUST conform to SARIF v2.1.0 schema — the `$schema` field MUST reference the official schema URL.
- **R002**: Every finding MUST include an `artifactLocation.uri` relative to the repository root.
- **R003**: SARIF `level` MUST map deterministically from finding severity: CRITICAL→`error`, HIGH→`error`, MEDIUM→`warning`, LOW→`note`.
- **R004**: The tool `driver.name` MUST be `"ipi-check"` and `driver.version` MUST match the package version.
- **R005**: User-controlled content in SARIF `message.text` and `message.markdown` MUST be escaped to prevent SARIF injection.
- **R006**: If the output target is a file, the extension MUST be `.sarif`.
- **R007**: The SARIF output MUST include an `invocations` array with `executionSuccessful` and timestamps.
- **R008**: Each skill unit MUST produce at most one SARIF result — the `SKILL.md` file serves as the primary location artifact, with all other skill files listed as `relatedLocations`. A skill whose fused decision is `PASS` produces no result at all (it is counted in the run summary instead).
- **R009**: Identical results (same `ruleId`, artifact URI, line, column and snippet) MUST be deduplicated, and each artifact MUST emit at most `DEFAULT_MAX_FINDINGS_PER_FILE` results while preserving the set of emitted `ruleId` values. The number of suppressed results MUST be available for reporting (returned as `SarifLimitStats`).

- **R010**: Individual findings whose severity is below the configured `severity_threshold` MUST be dropped before deduplication and the per-file cap, and the dropped count MUST be available for reporting via `SarifLimitStats.below_threshold_removed`. Skill-level results MUST be unaffected by the threshold.

- **R011**: A `PASS` verdict (file or skill) MUST NOT contribute results, and no emitted result may use the SARIF `level` value `none`. The run summary on `runs[0].invocations[0].properties` MUST record the per-file and per-skill decision counts and the number of emitted results, so PASS exclusion is never silent. The `IPI900` compromise diagnostic is exempt from PASS exclusion and is emitted whenever a verdict's LLM classification was compromised.

- **R012**: A finding suppressed by `.ipi-checkignore` or an inline `ipi-check:ignore` directive (honoured in source-code files only, see the Suppressions section) MUST remain in `results`, carrying a `suppressions` array entry with `kind` (`external` for `.ipi-checkignore`, `inSource` for an inline directive), `status: "accepted"` and a non-empty `justification`. Suppression MUST NOT change a verdict's decision, and the number of suppressed results MUST be recorded in `SarifLimitStats.suppressed_results` and surfaced as `resultsSuppressed` in the run summary.

- **R013**: Every emitted result MUST carry a `partialFingerprints` object whose `primaryLocationLineHash` entry is derived **solely** from deterministic result data — `ruleId`, artifact URI, start line, and a reproducible snippet component — and never from model-generated free text, so that re-scanning unchanged content reproduces the same alert identity. Every emitted result MUST also carry a `properties` bag (SARIF `propertyBag`) with a numeric `confidence` and a non-empty `pattern_id`.

- **R014**: User-controlled content interpolated by the human renderers (`--format md` / `table`) MUST be sanitized the way the SARIF renderer sanitizes its messages (R005 parity): Markdown free text is whitespace-collapsed, truncated and HTML/Markdown-escaped; paths are wrapped in an unbreakable code span; and concealed characters (ANSI escapes, zero-width/bidi controls, tag characters, other control characters) are neutralized to a visible marker — so report content can neither forge report structure nor smuggle terminal control sequences.

## Cross-References

- [System Overview](../architecture/system-overview.md)
- [Security Model](../architecture/security-model.md) — AV3: SARIF Injection
- [Confidence Fusion](confidence-fusion.md)
- [CLI Interface](../contracts/cli-interface.md)
- [ADR-002: SARIF Format](../decisions/002-sarif-format.md)
