# CLI Interface

## Purpose

Define the command-line interface for the ipi-check scanner. The CLI is the sole entry point — there is no library API, no config file, and no configuration beyond command-line arguments and environment variables.

## Schema / Signature

```
ipi-check scan <repo_path> [OPTIONS]
```

### Positional Arguments

| Argument | Required | Type | Description |
|----------|----------|------|-------------|
| `repo_path` | Yes | `Path` | Path to the repository to scan. Must be an existing directory. |

### Options

| Option | Required | Type | Default | Description |
|--------|----------|------|---------|-------------|
| `--llm-base-url` | No | `str` | `None` | LiteLLM base URL. If not set, LiteLLM uses its default (from environment or built-in config). |
| `--llm-model` | No | `str` | `None` | LLM model name (e.g., `gpt-4o-mini`, `claude-3-haiku-20240307`). If not set, LiteLLM uses its default. |
| `--llm-api-token` | No | `str` | `None` | API token for the LLM provider. If not set, LiteLLM uses its default auth chain. |
| `--output` | No | `Path` | stdout | Path to write the SARIF report file. If not set, the report is printed to stdout. |
| `--quiet` | No | `flag` | `False` | Suppress progress and informational output. Only the SARIF report is emitted. |
| `--no-gitignore` | No | `flag` | `False` | Disable .gitignore-aware file exclusion. By default, files matching .gitignore patterns are skipped. |
| `--exclude` | No | `str` (repeatable) | `None` | Glob pattern (gitignore/gitwildmatch syntax) to exclude from scanning. Can be specified multiple times. |
| `--version` | No | `flag` | — | Print the tool version and exit. |
| `--help` | No | `flag` | — | Print help message and exit. |

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
```

### Execution Flow

1. Parse CLI arguments with env expansion
2. Validate `repo_path` exists and is a directory
3. Print tool banner (name + version) unless `--quiet`
4. Run scanner pipeline (see [System Overview](../architecture/system-overview.md))
5. Output SARIF report to stdout or `--output` file
6. Print summary line to stderr (unless `--quiet`): "Scanned {N} files. BLOCK: {b}, REVIEW_REQUIRED: {r}, PASS: {p}"
7. Exit with code 0

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

| Condition | Exit Code | stderr Message |
|-----------|-----------|----------------|
| `repo_path` does not exist | 2 | `Error: Repository path not found: {path}` |
| `repo_path` is a file | 2 | `Error: Expected a directory: {path}` |
| `--output` parent directory does not exist | 2 | `Error: Output directory not found: {dir}` |
| `--output` file cannot be written | 1 | `Error: Cannot write to output file: {path}` |
| LLM API call fails (network, auth) | 0 | Warning to stderr: "LLM API error: {msg} — falling back to static analysis" |
| LLM API call times out | 0 | Warning to stderr: "LLM API timeout — falling back to static analysis" |
| Unhandled exception | 1 | `Error: Internal error: {exception}` with traceback to stderr |
| `--help` flag | 0 | Print help and exit |
| `--version` flag | 0 | Print `ipi-check {version}` and exit |
| No arguments at all | 2 | Print usage and exit |

### Exit Code Semantics

| Code | Meaning |
|------|---------|
| 0 | Scan completed successfully (regardless of findings — BLOCK findings do NOT cause non-zero exit) |
| 1 | Runtime error (file I/O error, unhandled exception) |
| 2 | Usage error (invalid arguments) |

## Examples

### Basic scan (Case 1 only — no LLM)
```bash
$ ipi-check scan ./my-project
ipi-check 0.1.0 — Prompt Injection Scanner

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
- **C002**: Exit code 0 MUST mean "scan completed" — NOT "no findings". SARIF consumers inspect the `results` array, not the exit code.
- **C003**: When `--llm-api-token` is not provided and no known LLM API key environment variables are set, the scanner MUST run Case 1 only and MUST NOT attempt any LLM API call.
- **C004**: Progress output MUST go to stderr; SARIF output MUST go to stdout (or `--output` file). This enables piping SARIF to other tools.
- **C005**: The `--quiet` flag MUST suppress all non-SARIF output, including the summary line. Only the SARIF JSON is printed.
- **C006**: When `.gitignore` exists at repo root and `--no-gitignore` is NOT set, files matching `.gitignore` patterns MUST be excluded from scanning.
- **C007**: The `--exclude` patterns MUST use gitignore/gitwildmatch syntax and MUST exclude matching files regardless of their category.

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

## Cross-References

- [System Overview](../architecture/system-overview.md)
- [File Discovery](../domains/file-discovery.md)
- [LLM Classifier](../domains/llm-classifier.md)
- [Reporting](../domains/reporting.md)
- [ADR-004: LiteLLM Provider](../decisions/004-litellm-provider.md)
