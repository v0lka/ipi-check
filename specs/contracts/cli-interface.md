# CLI Interface

## Purpose

Define the command-line interface for the ipi-check scanner. The CLI is the sole entry point — there is no library API, no config file, and no configuration beyond command-line arguments and environment variables.

## Schema / Signature

```
ipi-check scan <repo_path> [OPTIONS]
```

### Positional Arguments

| Argument    | Required | Type   | Description                                                    |
| ----------- | -------- | ------ | -------------------------------------------------------------- |
| `repo_path` | Yes      | `Path` | Path to the repository to scan. Must be an existing directory. |

### Options

| Option            | Required | Type               | Default | Description                                                                                             |
| ----------------- | -------- | ------------------ | ------- | ------------------------------------------------------------------------------------------------------- |
| `--llm-base-url`  | No       | `str`              | `None`  | LiteLLM base URL. If not set, LiteLLM uses its default (from environment or built-in config).           |
| `--llm-model`     | No       | `str`              | `None`  | LLM model name (e.g., `gpt-4o-mini`, `claude-3-haiku-20240307`). Falls back to the `IPI_CHECK_LLM_MODEL` env var. **Required to enable the LLM phase** — `litellm.completion()` has no ambient default model, so with a credential but no model the scan stays static-only and stderr reports why. |
| `--llm-api-token` | No       | `str`              | `None`  | API token for the LLM provider. If not set, LiteLLM uses its default auth chain.                        |
| `--output`        | No       | `Path`             | stdout  | Path to write the report (per `--format`) to. If not set, the report is printed to stdout. A path **without any extension** is auto-completed with the format's canonical extension (`.sarif`, `.json`, `.md`, `.txt`); a path that already has one is used verbatim. |
| `--format`        | No       | `str`              | `sarif` | Report format: one of `sarif`, `json`, `md`, `table`. `sarif` (default) emits the unchanged SARIF v2.1.0 document; `json` a flat JSON summary; `md` a grouped human-readable Markdown report; `table` a fixed-width plain-text table. See [Report Formats](#report-formats). Only `sarif` is consumed by code-scanning tools. |
| `--quiet`         | No       | `flag`             | `False` | Suppress progress and informational output. Only the selected report is emitted.                        |
| `-v` / `--verbose` / `--debug` | No | `flag`          | `False` | Emit verbose diagnostics on stderr (LLM configuration, provider errors, retries). Ignored when `--quiet` is set. |
| `--no-gitignore`  | No       | `flag`             | `False` | Disable .gitignore-aware file exclusion. By default, files matching .gitignore patterns are skipped.    |
| `--exclude`       | No       | `str` (repeatable) | `None`  | Glob pattern (gitignore/gitwildmatch syntax) to exclude from scanning. Can be specified multiple times. |
| `--max-findings-per-file` | No | `int`           | `50`    | Maximum number of SARIF results emitted per file. Identical results (same `ruleId`, URI, line, column and snippet) are always collapsed first; a file that still exceeds the cap is truncated to the first `N` results, except that one result per `ruleId` is always kept. `0` disables the cap. |
| `--max-llm-calls` | No       | `int`              | `0`     | Maximum number of LLM API calls attempted per scan (`0` = unlimited). Once reached, remaining files/skills fall back to static analysis. Retries and the repair retry each consume one unit. |
| `--llm-cache-dir` | No       | `Path`             | `None`  | Directory for the content-addressed LLM response cache. Enables caching: a repeated scan of unchanged files issues no new LLM calls. Supports `${VAR}` expansion; also settable via `IPI_CHECK_LLM_CACHE_DIR`. Disabled when omitted. |
| `--jobs`          | No       | `int`              | `1`     | Number of worker processes for the three static-analysis passes. `1` (default) runs them in-process/sequentially; values `> 1` fan per-file work out across processes. The emitted verdicts are independent of `--jobs`. Must be `>= 1`. |
| `--max-file-size` | No       | `str`              | `10MB`  | Skip files larger than this size. Accepts a byte count or a unit suffix — `B`, `KB`/`KiB`, `MB`/`MiB`, `GB`/`GiB` (binary multiples), case-insensitive, fractional allowed (e.g. `512kb`, `1.5MB`, `1048576`). Supports `${VAR}` expansion. Must be positive. |
| `--severity-threshold` | No | `str`            | `NONE`  | Minimum severity for an **individual finding** to be emitted: one of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`. `NONE` (default) emits every finding. Filters findings before deduplication/the per-file cap. Skill-level results (one aggregated result per skill) are unaffected. |
| `--timeout`       | No       | `float`            | `180`   | Per-LLM-call timeout, in seconds. Applies to every provider call (single, batch, skill, and the auxiliary contradiction probe). Must be `> 0`. Has no effect on the deterministic static passes. |
| `--fail-on`       | No       | `str`              | `none`  | Exit-code policy: one of `none`, `block`, `review`. `none` (default) always exits `0` on a completed scan — findings live in the SARIF report (C002). `block` exits `3` when any BLOCK verdict is present; `review` exits `3` on a BLOCK and `4` when only REVIEW_REQUIRED verdicts are present. Runtime/usage exit codes (`1`/`2`) are unchanged. Counts both file and skill verdicts. |
| `--version`       | No       | `flag`             | —       | Print the tool version and exit.                                                                        |
| `--help`          | No       | `flag`             | —       | Print help message and exit.                                                                            |

### Environment Variable Expansion

All string arguments support `${ENV_VAR_NAME}` expansion:

```bash
ipi-check scan ./repo --llm-api-token '${OPENAI_API_KEY}' --llm-model '${LLM_MODEL}'
```

Rules:

- The syntax `${VAR_NAME}` is expanded at parse time by the CLI argument parser.
- Undefined variables (no matching environment variable) are replaced with an empty string.
- If `--llm-api-token` expands to an empty string and no `LITELLM_API_KEY` environment variable is set, LLM is disabled (Case 1 only).
- Nested expansion (`${${VAR}}`) is NOT supported.
- Expansion is applied BEFORE any other validation.

## Behavior

### Valid Invocation

```bash
# Full scan with LLM
ipi-check scan /path/to/repo --llm-model gpt-4o-mini --llm-api-token '${OPENAI_API_KEY}'

# Static-only scan (Case 1)
ipi-check scan /path/to/repo

# Scan with output file
ipi-check scan /path/to/repo --output results.sarif

# Quiet mode for CI pipes
ipi-check scan /path/to/repo --quiet | jq .

# Scan including gitignored files
ipi-check scan /path/to/repo --no-gitignore

# Exclude specific patterns
ipi-check scan /path/to/repo --exclude "*.log" --exclude "vendor/"

# Raise the per-file finding cap (or disable it entirely)
ipi-check scan /path/to/repo --max-findings-per-file 200
ipi-check scan /path/to/repo --max-findings-per-file 0

# Parallelise the static passes across 4 worker processes
ipi-check scan /path/to/repo --jobs 4

# Skip vendored assets larger than 1 MB and report only HIGH and CRITICAL findings
ipi-check scan /path/to/repo --max-file-size 1MB --severity-threshold HIGH

# Tighten the per-LLM-call timeout to 30 seconds
ipi-check scan /path/to/repo --llm-model gpt-4o-mini --timeout 30

# Fail CI on a BLOCK verdict (exit 3); REVIEW_REQUIRED still exits 0
ipi-check scan /path/to/repo --fail-on block

# Treat REVIEW_REQUIRED as blocking too (BLOCK → 3, REVIEW-only → 4)
ipi-check scan /path/to/repo --fail-on review

# Emit a grouped, human-readable Markdown report (extension auto-completed → report.md)
ipi-check scan /path/to/repo --format md --output report

# Emit a plain-text table for a terminal/CI log, and a flat JSON summary
ipi-check scan /path/to/repo --format table
ipi-check scan /path/to/repo --format json --output summary
```

### Findings Deduplication and Per-File Cap

Before the SARIF `results` array is assembled, two limits are applied
deterministically (see [Reporting](../domains/reporting.md)):

1. **Deduplication** — results that are identical in `(ruleId, uri, line, column, snippet)`
   are collapsed to their first occurrence. Repeated identical findings (for
   example, the same string literal duplicated on one source line) produce a
   single SARIF result.
2. **Per-file cap** — each file's results are truncated to at most
   `--max-findings-per-file` (default `50`) entries. The first `N` results
   survive, except that one result per distinct `ruleId` is always retained so
   that no finding category silently disappears. A value of `0` disables the
   cap.

The number of suppressed results is reported on stderr (unless `--quiet`):

```
  Suppressed:      18 findings (0 duplicates, 18 over cap)
```

The set of emitted `ruleId` values is preserved by both steps.

### False-Positive Suppression (`.ipi-checkignore` and inline directives)

Findings can be acknowledged as accepted false positives without dropping the
audit trail (roadmap T5.3 / IN-19). There is no CLI flag — suppression is
declared in the repository:

- **`.ipi-checkignore`** — an optional gitignore-syntax file at the repository
  root. Each line is either a gitignore path pattern (suppresses every rule in
  matching files) or one or more `IPI###` rule ids optionally followed by a path
  pattern. A leading `!` negates an entry; blank lines and `#` comments are
  ignored.
- **Inline directives** — `# ipi-check:ignore[IPI006]` (any comment style)
  suppresses the listed rules on the directive's line and the line below it;
  bare `# ipi-check:ignore` suppresses every rule on those lines;
  `# ipi-check:ignore-file[...]` scopes the rule set to the whole file.
  Honoured **in source-code files only**, and there only when the directive's
  line is a real comment token (a directive inside a string literal is
  untrusted data): in markdown-family content (agent instructions,
  dot-directory markdown, skill files) every comment marker is ordinary
  attacker-writable prose, so those files suppress via `.ipi-checkignore`
  alone.

A suppressed result is kept in `results` and gains a SARIF `suppressions` entry
(`kind` `external`/`inSource`, `status` `accepted`), so GitHub Code Scanning
hides it while it stays auditable (see [Reporting](../domains/reporting.md)).
Suppression never changes a verdict's decision. When a policy is loaded, a
progress line is printed to stderr (unless `--quiet`):

```
  [suppress]         2 ignore-file rule(s), 1 file(s) with inline directives
```

### LLM Call Budget, Token Accounting, and Response Cache

When the LLM is enabled, the scanner accounts for every call it makes:

- **Call budget** — `--max-llm-calls N` caps the number of LLM API calls attempted
  per scan (`0`, the default, means unlimited). Once the budget is reached, any
  remaining classification degrades to static analysis — no further API call is
  made — and the budget hit is reported on stderr. Retries and the schema repair
  retry each consume one unit of the budget.
- **Token summary** — at the end of the scan (unless `--quiet`) a summary line is
  printed to stderr:

  ```
    [llm] usage: 41230 tokens in / 3120 tokens out (14 calls, 0 cache hits)
  ```

  Token counts are taken from the provider's `usage` report; when a provider omits
  it, the scanner falls back to a local estimate. When the `--max-llm-calls`
  budget was reached an additional line is printed:

  ```
    [llm] budget: --max-llm-calls=50 reached; remaining files fall back to static analysis
  ```
- **Response cache** — `--llm-cache-dir PATH` (or the `IPI_CHECK_LLM_CACHE_DIR`
  environment variable) enables a file cache of raw LLM responses, keyed by an
  HMAC-SHA256 over the API credential, cache version, call purpose, model,
  base URL and the exact request content. The credential inside the key makes
  entries unforgeable for anyone who does not hold the token, so a cache
  directory placed inside (or shared with) the scanned repository cannot be
  pre-seeded with `"safe"` verdicts. A repeated scan of unchanged files
  therefore issues **no** new API calls and reports them as cache hits. The
  cache is **opt-in** — it is disabled unless a directory is supplied — so the
  scanner stays read-only by default. A cache directory placed inside the
  scanned repository is excluded from discovery automatically.

### Performance and Coverage Controls

Flags that tune how the scan scales to large repositories, plus one that trims
the report:

- **`--jobs N` (parallelism)** — the static phase runs three passes (byte
  analysis → pattern matching → heuristics) over every discovered file. With
  `N > 1` each pass is fanned out to a pool of `N` worker processes and results
  are re-assembled in the original file order, so the verdict set is
  **identical** to the sequential run — only wall-clock time changes. The
  default `1` runs in-process (unchanged behaviour). Only the file-level static
  passes are parallelised; LLM calls and skill analysis keep their existing
  scheduling.
- **`--max-file-size SIZE` (coverage)** — discovery skips any file larger than
  `SIZE` with a warning (see [File Discovery](../domains/file-discovery.md)).
  The default is `10MB`; lowering it is the cheapest way to bound worst-case
  scan time on repositories that vendor large generated assets.
- **`--severity-threshold LEVEL` (reporting)** — individual findings below
  `LEVEL` are dropped *before* the dedup/per-file-cap pass, so they are never
  counted as duplicates. The set of emitted `ruleId` values shrinks with the
  threshold. Findings suppressed this way are reported on stderr:

  ```
    Suppressed:      21 findings (0 duplicates, 6 over cap, 15 below threshold)
  ```
- **`--timeout SECONDS`** — bounds every LLM provider call. A call exceeding it
  degrades to static analysis (exit code stays `0`); it never affects the
  deterministic static passes.

`--jobs` and `--max-file-size` are performance/coverage controls: they must not
change what a given file yields (`--jobs` produces a byte-identical verdict set)
or the verdicts of files below the size limit.

**Target timing.** On the 4-worker setting, the static analysis of a multi-thousand-file
repository must complete in seconds — parallel throughput scales roughly linearly
with worker count up to the CPU budget (measured ≈3.4× on 4 workers versus `--jobs 1`
for a ~2 000-file corpus). The regression test
`test_large_repo_on_four_workers_within_budget` pins an 800-file corpus to a 60 s
ceiling; a strict parallel-versus-sequential comparison is intentionally *not*
asserted (ProcessPoolExecutor spawn/pickle overhead makes it flaky on contended
shared runners).

### Report Formats

`--format` selects the report written to stdout (or to `--output`). The scan
itself is identical for every format — only the presentation changes, and
`--fail-on` exit codes are unaffected.

| `--format` | Default extension | Output                                                                                         |
| ---------- | ----------------- | ---------------------------------------------------------------------------------------------- |
| `sarif`    | `.sarif`          | SARIF v2.1.0 document — the **default and unchanged** machine format (see [Reporting](../domains/reporting.md)) |
| `json`     | `.json`           | Flat JSON summary: `tool`, `summary` (decision counts), `suppression` (limit counters) and a flat `results` array of verdicts, each with its `findings` |
| `md`       | `.md`             | Grouped Markdown report                                                                        |
| `table`    | `.txt`            | Fixed-width plain-text table                                                                   |

- **`--output` extension auto-completion** — an `--output` value with **no**
  extension (e.g. `--output results`) gains the canonical extension of the
  selected format: `results.sarif` (default), `results.json` (`--format json`),
  `results.md` (`--format md`) or `results.txt` (`--format table`). A value that
  already carries a suffix is used verbatim, and the `R006` "not a `.sarif`
  extension" warning applies only to the `sarif` format.
- **Markdown report (`--format md`)** — a summary block (`Tool`, `Scanned`,
  `Verdicts`, `Findings`), then one section per decision in severity order —
  `## BLOCK (n)`, `## REVIEW_REQUIRED (n)`, `## PASS (n)`. A non-passing file or
  skill shows its static severity, LLM verdict/confidence and every finding
  (rule id, level, line, message); passing verdicts are listed compactly.
- **Table report (`--format table`)** — the same information as aligned columns
  (`DECISION`, `FILE`, `RULE`, `LEVEL`, `LINE`, `MESSAGE`), grouped by decision
  (BLOCK first) under a banner, with long messages truncated for readability.
  A non-passing verdict that carries no individual finding still gets a summary
  row, so it never silently disappears.
- **Scope of the human/JSON views** — `md`, `table` and `json` render the
  **full verdict set** returned by fusion. The SARIF-only result-shaping passes
  (deduplication, `--max-findings-per-file`, `--severity-threshold`) apply to
  the `sarif` document, not to them; the resulting counters are still surfaced
  in the summary block. Only `--format sarif` produces a document consumable by
  GitHub Code Scanning / GitLab SAST.
- The stderr summary line names the selected format (e.g. `Markdown report
  written to results.md`); the `sarif` label is unchanged (`SARIF report
  written to …`).

### Exit-Code Policy (`--fail-on`)

`--fail-on` turns a *completed* scan into a non-zero exit when the verdicts cross a
chosen threshold — the deterministic way for CI and the git hook to "block". It never
changes **what** the scan reports: the SARIF `results` array is byte-identical for
every policy. Only the process exit code differs.

| `--fail-on` | BLOCK present | REVIEW_REQUIRED only | Neither | This is the default |
| ----------- | ------------- | -------------------- | ------- | ------------------- |
| `none`      | `0`           | `0`                  | `0`     | ✅                  |
| `block`     | `3`           | `0`                  | `0`     |                     |
| `review`    | `3`           | `4`                  | `0`     |                     |

- The policy counts **both** file verdicts and skill-unit verdicts.
- `block ⊂ review`: when a BLOCK exists it always wins (`3`), whatever the policy.
- Runtime (`1`) and usage (`2`) errors are unaffected — `--fail-on` only applies to a
  scan that completed. A failed `--output` write still exits `1`.
- An unknown policy value (not `none`/`block`/`review`) is a usage error (`2`).
- When the policy trips, one explanatory line is printed to stderr (unless `--quiet`):

  ```
  ipi-check: --fail-on=block matched — 2 BLOCK and 5 REVIEW_REQUIRED verdict(s); exiting with code 3.
  ```

- **Default `none` preserves the C002 contract**: a completed scan exits `0` regardless
  of findings, and SARIF consumers inspect `results`, not the exit code.

### Git Hook (`scripts/ipi-check-hook.sh`)

The bundled client-side git hook (`post-checkout` / `post-merge` / `post-rewrite` /
`pre-commit`) runs `ipi-check scan --output <repo>/.git/ipi-check-last.sarif --fail-on <policy>`
and maps the scanner's **exit code** to a blocking result. It does **not** parse the
human-readable stderr summary, so it stays correct however that text is worded.

| Scanner exit | Meaning                      | Hook exit |
| ------------ | ---------------------------- | --------- |
| `0`          | No policy-level findings     | `0`       |
| `3`          | BLOCK verdict present        | `1` (blocks) |
| `4`          | REVIEW_REQUIRED only         | `1` (blocks) |
| `1` / `2`    | Scanner failed / usage error | `1`       |

The hook's policy is controlled by environment variables (defaults preserve the
historical "block on BLOCK" behaviour):

| Variable                     | Default | Effect                                                         |
| ---------------------------- | ------- | -------------------------------------------------------------- |
| `IPI_CHECK_FAIL_ON`          | —       | Explicit `--fail-on` value (`none`/`block`/`review`); overrides the shortcuts below. |
| `IPI_CHECK_BLOCK_ON_REVIEW`  | `0`     | When `1`, widens the policy to `review` (also fails on REVIEW_REQUIRED). |
| `IPI_CHECK_HOOK_DISABLE`     | `0`     | When `1`, skips the scan entirely.                             |
| `IPI_CHECK_BIN`              | `ipi-check` | Overrides the scanner binary path.                         |

### Execution Flow

1. Parse CLI arguments with env expansion
2. Validate `repo_path` exists and is a directory
3. Print tool banner (name + version) unless `--quiet`
4. Run scanner pipeline (see [System Overview](../architecture/system-overview.md)) — discovery applies the size limit and every `.gitignore` in the tree; the three static passes run across `--jobs` worker processes when `> 1`
5. Output SARIF report to stdout or `--output` file — findings below `--severity-threshold` are dropped first, then identical results are deduplicated and each file is capped at `--max-findings-per-file` (default 50) results
6. Print summary line to stderr (unless `--quiet`): "Scanned {N} files. BLOCK: {b}, REVIEW_REQUIRED: {r}, PASS: {p}", followed by a "Suppressed: {n} findings ({d} duplicates, {c} over cap, {t} below threshold)" line when any pass removed results (the "below threshold" component appears only when non-zero)
7. Print the LLM token summary ("tokens in / tokens out", call and cache-hit counts) to stderr (unless `--quiet`), plus a budget line when `--max-llm-calls` was reached
8. Compute the `--fail-on` policy and exit: `0` when the policy is not tripped (default `none` always exits `0`), `3` on a BLOCK under `--fail-on block`/`review`, or `4` on a REVIEW_REQUIRED-only result under `--fail-on review`

### LLM Availability Detection

LLM is enabled if ANY of these conditions is true:

- `--llm-api-token` is provided (directly or via env expansion)
- `LITELLM_API_KEY` environment variable is set
- `OPENAI_API_KEY` environment variable is set
- `ANTHROPIC_API_KEY` environment variable is set

If none of these conditions are met:

- Print informational message to stderr: "LLM not configured — running static analysis only"
- Run Case 1 only (skip LLM classifier)

## Error Handling

| Condition                                  | Exit Code | stderr Message                                                              |
| ------------------------------------------ | --------- | --------------------------------------------------------------------------- |
| `repo_path` does not exist                 | 2         | `Error: Repository path not found: {path}`                                  |
| `repo_path` is a file                      | 2         | `Error: Expected a directory: {path}`                                       |
| `repo_path` is empty/whitespace (undefined `${VAR}`) | 2 | `Error: repo_path must not be empty (an undefined ${VAR} expands to '')` — never silently scan the working directory |
| `--output` is empty/whitespace (undefined `${VAR}`) | 2 | `Error: --output path must not be empty`                            |
| `--output` parent directory does not exist | 2         | `Error: Output directory not found: {dir}`                                  |
| `--output` file cannot be written          | 1         | `Error: Cannot write to output file: {path}`                                |
| `--max-llm-calls` is negative              | 2         | `Error: --max-llm-calls must be >= 0 (got {value})`                         |
| `--llm-cache-dir` is empty/whitespace (undefined `${VAR}`) | 2 | `Error: --llm-cache-dir path must not be empty`                    |
| `--llm-cache-dir` cannot be created        | 2         | `Error: Cannot create LLM cache directory: {path}`                          |
| `--jobs` is not `>= 1`                     | 2         | `Error: --jobs must be >= 1 (got {value})`                                  |
| `--timeout` is not positive                | 2         | `Error: --timeout must be a positive number of seconds (got {value})`      |
| `--max-file-size` cannot be parsed         | 2         | `Error: --max-file-size must be a positive size (got {value})`              |
| `--severity-threshold` is not a valid level| 2         | `Error: --severity-threshold must be one of CRITICAL, HIGH, MEDIUM, LOW, NONE (got {value})` |
| `--fail-on` is not `none`/`block`/`review` | 2         | `argument --fail-on: invalid choice: '{value}' (choose from 'none', 'block', 'review')` (argparse) |
| `--format` is not `sarif`/`json`/`md`/`table` | 2      | `argument --format: invalid choice: '{value}' (choose from 'sarif', 'json', 'md', 'table')` (argparse) |
| LLM API call fails (network, auth)         | 0         | Warning to stderr: "LLM API error: {msg} — falling back to static analysis" |
| LLM API call times out                     | 0         | Warning to stderr: "LLM API timeout — falling back to static analysis"      |
| Unhandled exception                        | 1         | `Error: Internal error: {exception}` with traceback to stderr               |
| `--help` flag                              | 0         | Print help and exit                                                         |
| `--version` flag                           | 0         | Print `ipi-check {version}` and exit                                        |
| No arguments at all                        | 2         | Print usage and exit                                                        |

### Exit Code Semantics

| Code | Meaning                                                                                          |
| ---- | ------------------------------------------------------------------------------------------------ |
| 0    | Scan completed successfully (regardless of findings — with the default `--fail-on none`, BLOCK findings do NOT cause non-zero exit) |
| 1    | Runtime error (file I/O error, unhandled exception)                                              |
| 2    | Usage error (invalid arguments)                                                                  |
| 3    | `--fail-on` policy tripped by a **BLOCK** verdict (`--fail-on block` or `review`)                |
| 4    | `--fail-on review` tripped by a **REVIEW_REQUIRED** verdict when no BLOCK is present             |

Code `0` remains the default for every completed scan; `3`/`4` appear only when
`--fail-on` requests it. Codes `1` and `2` keep their meaning under every policy.

## Examples

### Basic scan (Case 1 only — no LLM)

```bash
$ ipi-check scan ./my-project
ipi-check 0.1.0 — Prompt injection and skills security scanner

Scanning ./my-project...
Discovered 47 files to scan
  [byte-analysis]   100% |████████████████| 47/47
  [pattern-matching] 100% |████████████████| 47/47
  [heuristics]      100% |████████████████| 47/47
  [llm]             SKIPPED (no LLM configured)

RESULTS
═══════════════════════════════════
Scanned: 47 files
  BLOCK:           2
  REVIEW_REQUIRED: 5
  PASS:           40

SARIF report written to stdout
```

### Scan with LLM

```bash
$ ipi-check scan ./my-project --llm-model gpt-4o-mini --llm-api-token "${OPENAI_API_KEY}"
```

### Scan with output file

```bash
$ ipi-check scan ./my-project --output results.sarif
```

### Quiet mode for scripting

```bash
$ ipi-check scan ./my-project --quiet | jq '.runs[0].results | length'
42
```

### Exclude patterns

```bash
# Skip vendored code and logs
$ ipi-check scan ./my-project --exclude "vendor/" --exclude "*.log"

# Include files that are in .gitignore
$ ipi-check scan ./my-project --no-gitignore
```

### Docker usage

```bash
$ docker run -v $(pwd):/repo ipi-check scan /repo --llm-api-token "${OPENAI_API_KEY}"
```

## Invariants

- **C001**: The CLI MUST expand `${ENV_VAR}` in ALL string arguments before any validation.
- **C002**: Exit code 0 MUST mean "scan completed" — NOT "no findings". SARIF consumers inspect the `results` array, not the exit code. This is the contract under the default `--fail-on none`; `--fail-on block|review` is an explicit opt-in to non-zero codes (`3`/`4`) that never changes the emitted SARIF.
- **C003**: When `--llm-api-token` is not provided and no known LLM API key environment variables are set, the scanner MUST run Case 1 only and MUST NOT attempt any LLM API call.
- **C004**: Progress output MUST go to stderr; SARIF output MUST go to stdout (or `--output` file). This enables piping SARIF to other tools.
- **C005**: The `--quiet` flag MUST suppress all non-SARIF output, including the summary line. Only the SARIF JSON is printed.
- **C006**: When `--no-gitignore` is NOT set, EVERY `.gitignore` in the tree MUST be honoured with git semantics — each file's patterns are matched relative to the directory that owns it, and a deeper `.gitignore` overrides a shallower one. Files matching those patterns MUST be excluded from scanning.
- **C007**: The `--exclude` patterns MUST use gitignore/gitwildmatch syntax and MUST exclude matching files regardless of their category.
- **C008**: Identical SARIF results (same `ruleId`, URI, line, column, snippet) MUST be deduplicated, and each file MUST emit at most `--max-findings-per-file` results (default `50`; `0` = unlimited) while preserving the set of emitted `ruleId` values. The number of suppressed results MUST be reported on stderr unless `--quiet` is set.
- **C009**: When the LLM is enabled the CLI MUST report the total input/output tokens (with call and cache-hit counts) on stderr unless `--quiet`. `--max-llm-calls N` MUST bound the number of LLM API calls attempted to at most `N` (retries included); a reached budget MUST be reported on stderr and MUST NOT abort the scan.
- **C010**: The LLM response cache MUST be opt-in (disabled unless `--llm-cache-dir` or `IPI_CHECK_LLM_CACHE_DIR` is set) and content-addressed (keyed by the API credential, model, base URL and request content — the key is an HMAC-SHA256 over the credential, so entries are unforgeable without the token even when the cache directory is inside the scanned repository). A repeated scan of an unchanged corpus MUST reuse cached classifications and MUST NOT issue new LLM calls; every cached entry MUST be re-validated against the current response schema before use.
- **C011**: `--jobs N` (`N >= 1`) MUST parallelise only the deterministic per-file static passes and MUST produce a verdict set identical to `--jobs 1`; the default MUST be `1`.
- **C012**: `--max-file-size SIZE` MUST be parsed as a positive byte count (plain number, or `B`/`KB`/`MB`/`GB` and their `KiB`/`MiB`/`GiB` aliases — binary multiples) and MUST exclude files larger than it from discovery.
- **C013**: `--severity-threshold LEVEL` MUST drop individual findings below `LEVEL` before deduplication and the per-file cap, and MUST leave skill-level results unchanged. Findings removed by the threshold MUST be counted and reported on stderr unless `--quiet` is set.
- **C014**: `--timeout SECONDS` MUST bound the duration of every LLM provider call (single, batch, skill and auxiliary) and MUST default to the classifier's built-in 180 s. It MUST NOT affect the static passes.
- **C015**: `--fail-on {none,block,review}` MUST control the exit code without changing the SARIF output. The default `none` MUST exit `0` for every completed scan (C002). `block` MUST exit `3` when any BLOCK verdict (file or skill) is present; `review` MUST exit `3` on any BLOCK and `4` when only REVIEW_REQUIRED verdicts are present. Runtime (`1`) and usage (`2`) codes MUST be unaffected, and an invalid policy value MUST be a usage error (`2`).
- **C016**: `--format {sarif,json,md,table}` MUST select the report renderer without changing what the scan finds or the `--fail-on` exit codes. `sarif` MUST remain the default and MUST emit the unchanged SARIF v2.1.0 document. An `--output` value without any extension MUST be auto-completed with the format's canonical extension (`.sarif`/`.json`/`.md`/`.txt`); an invalid format value MUST be a usage error (`2`).
- **C017**: The LLM phase MUST run only when a credential **and** a model both resolve — `--llm-model`, else the `IPI_CHECK_LLM_MODEL` environment variable (LiteLLM has no ambient default model). A credential without a model MUST NOT be sent to the provider and MUST NOT produce per-file `IPI900` compromises: the scan MUST stay static-only with exit code `0` and MUST report the missing parameter on stderr unless `--quiet`. That diagnostic MUST NOT echo the credential value.

## Breaking Change Checklist

Any of the following constitutes a CLI breaking change:

- [ ] Renaming or removing `scan` subcommand
- [ ] Renaming `repo_path` argument
- [ ] Changing `--llm-base-url`, `--llm-model`, `--llm-api-token`, or `--output` flag names
- [ ] Changing the SARIF output schema (version, field names, rule IDs)
- [ ] Changing exit code semantics (0 for findings, non-zero for success)
- [ ] Dropping `${ENV_VAR}` expansion support
- [ ] Changing the environment variable names the scanner auto-detects
- [ ] Changing `--no-gitignore` or `--exclude` flag names
- [ ] Changing the `--max-findings-per-file` default value or the dedup/per-file-cap semantics
- [ ] Removing or renaming `--max-llm-calls` / `--llm-cache-dir`, or changing the `--max-llm-calls` default (`0`) semantics
- [ ] Changing the token-summary line format or the cache-key semantics (credential + model + base URL + request content)
- [ ] Removing or renaming `--jobs`, `--max-file-size`, `--severity-threshold` or `--timeout`, or changing the `--jobs` default (`1`)
- [ ] Changing `--severity-threshold` semantics (which findings it filters) or the `--max-file-size` default (`10MB`) / accepted units
- [ ] Removing or renaming `--fail-on`, changing its default (`none`), or making findings fail the scan without an explicit `--fail-on`
- [ ] Changing the `--fail-on` exit codes (`3` for BLOCK, `4` for REVIEW_REQUIRED-only)
- [ ] Removing or renaming `--format`, changing its default (`sarif`), altering the `--output` extension auto-completion, or changing the `md`/`table`/`json` report structure
- [ ] Changing nested-`.gitignore` handling (git semantics: directory-scoped patterns, deeper file overrides shallower)

## Cross-References

- [System Overview](../architecture/system-overview.md)
- [File Discovery](../domains/file-discovery.md)
- [LLM Classifier](../domains/llm-classifier.md)
- [Reporting](../domains/reporting.md)
- [ADR-004: LiteLLM Provider](../decisions/004-litellm-provider.md)
