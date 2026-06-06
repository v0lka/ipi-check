# ipi-check — Indirect Prompt Injection Scanner

[![CI](https://github.com/v0lka/ipi-check/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/v0lka/ipi-check/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/)
[![SARIF](https://img.shields.io/badge/output-SARIF%20v2.1.0-green)](https://sarifweb.azurewebsites.net/)

A SAST scanner that detects **indirect prompt injection** ([OWASP LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)) in AI agent
instruction files and source code. It combines deterministic static analysis with an
optional LLM classifier and emits results as SARIF v2.1.0 — ready to upload to
GitHub Code Scanning, GitLab SAST, or any SARIF-aware viewer.

![ipi-check screenshot](images/screenshot.png)

---

## Overview

LLM-powered coding agents read project-local instruction files such as
`AGENTS.md`, `.cursorrules`, `CLAUDE.md`, and `.windsurfrules`. An attacker who
controls those files (or smuggles content into source-code comments) can hijack
the agent — exfiltrate secrets, run destructive commands, or rewrite its
behavior. `ipi-check` scans a repository for the byte- and language-level
signals of such attacks.

The scanner is built around a **two-stage pipeline**:

1. **Stage 1 — Static analysis (always on).** Byte-level inspection, regex
   pattern matching, and semantic heuristics produce per-file static results
   with deterministic confidence scores.
2. **Stage 2 — LLM classification (optional, Case 2).** When an LLM provider is
   configured, sanitized file content is forwarded to the model for a
   structured classification verdict.

A deterministic confidence-fusion matrix combines both stages into a final
verdict: `PASS`, `REVIEW_REQUIRED`, or `BLOCK`.

---

## Features

- **Byte-level hidden-content detection** — ANSI escapes, Unicode tag
  characters (E0000–E007F), variation selectors, bidi overrides, zero-width
  characters, Private Use Area codepoints, homoglyphs.
- **Regex injection patterns** — instruction overrides, authority claims,
  destructive shell commands, data exfiltration, shell injection, jailbreak
  prompts.
- **Semantic heuristics** — Shannon entropy, invisible-content ratio,
  instruction density.
- **Optional LLM classification** via [LiteLLM](https://github.com/BerriAI/litellm)
  — works with OpenAI, Anthropic, Azure, Bedrock, Ollama, or any LiteLLM
  provider.
- **SARIF v2.1.0 output** — compatible with GitHub Code Scanning, GitLab,
  VS Code SARIF Viewer, and Sonar.
- **AI-agent file awareness** — automatically discovers `.cursorrules`,
  `.windsurfrules`, `.clinerules`, `AGENTS.md`, `CLAUDE.md`,
  `copilot-instructions.md`, `.cursor/**/*.mdc`, and more.
- **Pre-LLM sanitization** prevents the classifier itself from being prompt-injected.
- **Batch LLM classification** for source code files with automatic chunking of oversized files and exponential-backoff retry on partial failures.
- **Path-traversal protection** for symbolic links.
- **Pygments-based code extraction** isolates comments and string literals
  from source files for targeted scanning.

---

## Installation

### From PyPI

```bash
# TODO: pip install ipi-check
```

### From source

```bash
git clone https://github.com/v0lka/ipi-check.git
cd ipi-check
pip install -e .
```

### Docker

```bash
# TODO: docker pull ghcr.io/v0lka/ipi-check:latest
# or build locally:
docker build -t ipi-check .
```

Requires Python 3.12+.

---

## Quick Start

### Case 1 — Static analysis only

No LLM provider; uses byte, pattern, and heuristic stages.

```bash
ipi-check scan ./my-repo
```

### Case 2 — Static analysis + LLM classification

```bash
ipi-check scan ./my-repo \
  --llm-model gpt-4o-mini \
  --llm-api-token "${OPENAI_API_KEY}"
```

Write SARIF to a file instead of stdout:

```bash
ipi-check scan ./my-repo --output results.sarif
```

The `--llm-api-token` value supports `${VAR_NAME}` expansion so credentials
never have to appear on the command line literally.

---

## CLI Reference

```
ipi-check scan REPO_PATH [OPTIONS]
```

| Argument / Option       | Type   | Default      | Description                                                                       |
| ----------------------- | ------ | ------------ | --------------------------------------------------------------------------------- |
| `REPO_PATH`             | path   | _(required)_ | Repository directory to scan. Supports `${VAR}` expansion.                        |
| `--llm-base-url URL`    | string | `None`       | LiteLLM base URL (for self-hosted / proxy endpoints).                             |
| `--llm-model NAME`      | string | `None`       | LLM model name, e.g. `gpt-4o-mini`, `claude-3-5-sonnet`. Omit to disable Stage 2. |
| `--llm-api-token TOKEN` | string | `None`       | API token for the LLM provider. Supports `${VAR}` expansion.                      |
| `--output PATH`         | path   | stdout       | Write SARIF to a file (compact JSON). Warns if extension is not `.sarif`.         |
| `--quiet`               | flag   | `false`      | Suppress banner, progress, and summary lines on stderr.                           |
| `--no-gitignore`        | flag   | `false`      | Disable `.gitignore`-aware file exclusion.                                        |
| `--exclude PAT`         | string | _(none)_     | Glob pattern to exclude (gitignore syntax). Repeatable.                           |
| `--version`             | flag   | —            | Print version and exit.                                                           |
| `-h`, `--help`          | flag   | —            | Show help and exit.                                                               |

---

## Exit Codes

| Code | Meaning                                                                     |
| ---- | --------------------------------------------------------------------------- |
| `0`  | Scan completed successfully. SARIF emitted. Findings (if any) are in SARIF. |
| `1`  | Runtime error (I/O failure, pipeline crash, etc.). See stderr.              |
| `2`  | Usage error (invalid path, missing argument, bad output directory).         |

`ipi-check` always exits `0` on a clean scan regardless of verdicts —
the SARIF report carries the findings, leaving gating decisions to your CI.

---

## Output Format

Output is [SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html).
Each finding includes the file URI, the offending rule ID, the static
confidence, the LLM verdict (when present), and a human-readable message.

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "ipi-check",
          "version": "0.1.0",
          "informationUri": "https://github.com/v0lka/ipi-check"
        }
      },
      "results": [
        {
          "ruleId": "IPI101",
          "level": "error",
          "message": {
            "text": "Instruction override pattern detected in .cursorrules"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": ".cursorrules" }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

---

## Local Git Hook (blocking `post-checkout`)

`ipi-check` itself always exits `0` so its SARIF can be consumed by CI gates.
For local development you can wrap it in a small bash script that parses the
verdict summary and exits non-zero on `BLOCK`. The wrapper is shipped at
[`scripts/ipi-check-hook.sh`](./scripts/ipi-check-hook.sh) and is suitable for
any client-side hook (`post-checkout`, `post-merge`, `post-rewrite`,
`pre-commit`, …).

**About blocking semantics.** `post-checkout` runs _after_ the working tree
has been updated, so a non-zero exit cannot roll the checkout back. It does,
however, propagate as the exit status of `git checkout`, which is enough for
shells, IDE integrations, and chained automation to treat the checkout as
failed and halt subsequent steps. If you need to _prevent_ a state change
(rather than flag it after the fact), install the same wrapper as a
`pre-commit` or `pre-push` hook — those are truly preventive.

### Install globally (once per machine)

Use Git's `core.hooksPath` to point every repository on your machine at a
single hooks directory:

```bash
# 1. Pick a directory for your global hooks.
mkdir -p ~/.githooks

# 2. Drop the wrapper in as the post-checkout hook (must be named exactly
#    'post-checkout' and be executable).
curl -fsSL https://raw.githubusercontent.com/v0lka/ipi-check/main/scripts/ipi-check-hook.sh \
    -o ~/.githooks/post-checkout
chmod +x ~/.githooks/post-checkout

# 3. Tell Git to use it for every repository on this machine.
git config --global core.hooksPath ~/.githooks
```

If you have a local clone of this repository instead, copy the script
directly:

```bash
cp scripts/ipi-check-hook.sh ~/.githooks/post-checkout
chmod +x ~/.githooks/post-checkout
```

### What the hook does

On every branch checkout (`branch_flag == 1`) the wrapper:

1. Skips when not inside a git work tree, when `IPI_CHECK_HOOK_DISABLE=1` is
   set, or when the `ipi-check` binary is unavailable (fail-open).
2. Runs `ipi-check scan "$REPO_ROOT" --output .git/ipi-check-last.sarif`.
3. Re-emits the scanner banner and summary to your terminal.
4. Parses the `BLOCK: N, REVIEW_REQUIRED: M, PASS: K` summary line.
5. **Exits `1` when `BLOCK > 0`**, leaving the SARIF report at
   `.git/ipi-check-last.sarif` for inspection.

### Tuning the hook

The wrapper honours a few environment variables:

| Variable                    | Default     | Effect                                                            |
| --------------------------- | ----------- | ----------------------------------------------------------------- |
| `IPI_CHECK_HOOK_DISABLE`    | `0`         | Set to `1` to skip the scan entirely (one-shot opt-out).          |
| `IPI_CHECK_BLOCK_ON_REVIEW` | `0`         | Set to `1` to also fail when `REVIEW_REQUIRED > 0`.               |
| `IPI_CHECK_BIN`             | `ipi-check` | Override the binary path, e.g. to a virtualenv or pinned version. |

Example — temporarily bypass the hook for one checkout:

```bash
IPI_CHECK_HOOK_DISABLE=1 git checkout some-branch
```

Example — make `REVIEW_REQUIRED` blocking for stricter local gating:

```bash
git config --global hook.ipi-check.blockOnReview true   # for documentation
export IPI_CHECK_BLOCK_ON_REVIEW=1                      # actually used by the hook
```

### Disable for a single repository

Per-repo `core.hooksPath` overrides the global setting:

```bash
cd /path/to/repo
git config --local core.hooksPath .git/hooks   # restore the default
```

---

## CI/CD Integration

### GitHub — Code Scanning upload

```yaml
name: ipi-check
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install ipi-check
      - run: ipi-check scan . --output ipi-check.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ipi-check.sarif
```

### GitLab — SAST report

```yaml
ipi-check:
  image: python:3.12-slim
  stage: test
  script:
    - pip install ipi-check
    - ipi-check scan . --output gl-sast-report.sarif
  artifacts:
    reports:
      sast: gl-sast-report.sarif
```

---

## Docker Usage

Mount the repository to scan as a volume and let the container produce SARIF
on stdout:

```bash
docker run --rm -v "$(pwd):/repo" ipi-check scan /repo
```

Persist the report and pass an API token via environment variable:

```bash
docker run --rm \
  -v "$(pwd):/repo" \
  -e OPENAI_API_KEY \
  ipi-check scan /repo \
  --llm-model gpt-4o-mini \
  --llm-api-token '${OPENAI_API_KEY}' \
  --output /repo/results.sarif
```

---

## Development

```bash
git clone https://github.com/v0lka/ipi-check.git
cd ipi-check
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run the test suite, linter, and type-checker:

```bash
pytest tests/ -v --tb=short
ruff check src/ tests/
mypy src/
```

---

## Architecture

`ipi-check` is organized into a small set of focused modules:

- `core/types.py` — shared data types, enums, and dataclasses.
- `scanner/file_discovery.py` — locate AI-agent files and source files.
- `scanner/byte_analysis.py` — detect hidden/abusive bytes.
- `scanner/pattern_matching.py` — regex-based injection signatures.
- `scanner/semantic_heuristics.py` — entropy, density, invisibility ratios.
- `scanner/static_result.py` — assemble static results and compute severity.
- `scanner/code_extractor.py` — Pygments-driven comment/string extraction.
- `scanner/llm_sanitizer.py` — neutralize hostile content before the LLM call.
- `scanner/token_counter.py` — tiktoken-based token counting for batch assembly.
- `scanner/llm_classifier.py` — LiteLLM-backed Stage 2 classifier (single-file and batch).
- `scanner/confidence_fusion.py` — deterministic verdict matrix.
- `scanner/pipeline.py` — end-to-end orchestration (including batch LLM for source code).
- `reporter/sarif_reporter.py` — SARIF v2.1.0 emission.
- `cli/main.py` — argparse CLI entry point.

The full architecture and decision records live in [`specs/`](./specs/):
[`system-overview.md`](./specs/architecture/system-overview.md),
[`security-model.md`](./specs/architecture/security-model.md),
and the ADRs in [`specs/decisions/`](./specs/decisions/).

---

## License

[MIT](./LICENSE) © 2026 Vladimir Kochetkov.
