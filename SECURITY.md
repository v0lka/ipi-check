# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

Only the latest minor release receives security updates. The project is pre-1.0; breaking changes may occur.

## Reporting a Vulnerability

**Do NOT** open public GitHub issues for security vulnerabilities.

**Preferred channel:** Open a [private vulnerability report](https://github.com/v0lka/ipi-check/security/advisories/new) via GitHub Security Advisories.

**Response SLA:**

- Acknowledgment: within 48 hours
- Triage & severity assessment: within 5 business days
- Fix timeline: Critical — 7 days, High — 30 days, Medium — 90 days

**Disclosure policy:** Coordinated disclosure. We request a 90-day embargo before public disclosure. We credit reporters in release notes unless they prefer anonymity.

**Bug bounty:** No — this is a volunteer-maintained open-source project.

---

## Threat Model

### Assets

| Asset                      | Sensitivity | Description                                                                                                                                                                                 |
| -------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LLM API credentials        | Critical    | API tokens passed via `--llm-api-token` or env vars (`LITELLM_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`)                                                                              |
| Tool integrity             | High        | Correctness of scan results (BLOCK / REVIEW_REQUIRED / PASS); false negatives could let malicious instructions reach AI agents                                                              |
| Scanned repository content | Medium      | Files are read but never persisted; content is sanitized and forwarded to LLM without truncation (batch processing handles large files via chunking); SARIF snippets truncated at 200 chars |
| SARIF output               | Low         | Findings report written to stdout or file; contains file paths and matched content snippets                                                                                                 |

The scanner is inherently a **read-only, offline-first** tool. It stores no data persistently and has no network exposure beyond the optional LLM API call.

### Threat Actors

- **Opportunistic attacker** — Places hidden prompt-injection payloads (ANSI escapes, zero-width chars, bidi overrides) in agent instruction files to manipulate AI coding assistants.
- **Motivated external attacker** — Crafts files specifically to bypass the scanner (e.g., encoding injections in a way that evades regex patterns).
- **Compromised dependency** — A malicious update to `litellm`, `pathspec`, or `pygments` introduces a backdoor.
- **AI coding agent (adversarial)** — A repository's own agent-instruction files contain injected instructions designed to compromise the scanner's LLM classifier.

### Attack Surface

| Entry Point                                                     | Authentication    | Input Validation                                                                 |
| --------------------------------------------------------------- | ----------------- | -------------------------------------------------------------------------------- |
| CLI arguments (`repo_path`, `--llm-*`, `--output`, `--exclude`) | None (local tool) | Path existence/directory checks; `${VAR}` expansion with undefined-var hardening |
| File system (scanned files)                                     | None              | Binary-only reads; 10 MB size limit; path traversal protection                   |
| Environment variables (`LITELLM_API_KEY`, etc.)                 | OS-level          | Boolean/string extraction only                                                   |
| LLM API call (LiteLLM)                                          | API token         | 180s timeout; strict JSON schema validation; sanitized content only              |
| SARIF output (stdout/file)                                      | None              | HTML escaping; 200-char truncation                                               |
| Git hook trigger (`ipi-check-hook.sh`)                          | None              | Opt-out via `IPI_CHECK_HOOK_DISABLE=1`                                           |
| CI/CD pipeline (`.github/workflows/ci.yml`)                     | GitHub Actions    | PRs from forks run with read-only token                                          |

### Trust Boundaries

```
┌──────────────────────────────────────────────────────────────┐
│  CLI Input (UNTRUSTED)                                       │
│  — repo_path, LLM config, exclude patterns, output path      │
└────────────────────────────┬─────────────────────────────────┘
                             │ Path validation, env expansion
┌────────────────────────────▼─────────────────────────────────┐
│  Scanner Pipeline (TRUSTED)                                   │
│  — static analysis (bytes, patterns, heuristics)              │
│  — deterministic, no external influence                       │
└────────────────────────────┬─────────────────────────────────┘
                             │ Sanitized content only (S002)
┌────────────────────────────▼─────────────────────────────────┐
│  LLM API (EXTERNAL / UNTRUSTED)                               │
│  — LiteLLM → model provider                                   │
│  — response parsed as JSON, never eval'd (S003, S004)        │
└────────────────────────────┬─────────────────────────────────┘
                             │ Validated JSON
┌────────────────────────────▼─────────────────────────────────┐
│  SARIF Reporter (TRUSTED)                                     │
│  — HTML-escapes user content (S006)                           │
│  — truncates snippets at 200 chars                            │
└────────────────────────────┬─────────────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │ stdout / .sarif │
                    └─────────────────┘
```

### Known Risks & Accepted Trade-offs

| Risk                                  | Severity | Mitigation / Rationale                                                                                                                                          |
| ------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LLM classifier prompt injection (AV1) | High     | Pre-LLM sanitization replaces invisible chars with placeholders; immutable system prompt (single-file and batch); strict JSON parsing with compromised fallback |
| Regex denial-of-service (ReDoS)       | Medium   | 0.1s thread timeout per regex per line via `ThreadPoolExecutor`                                                                                                 |
| SARIF injection (AV3)                 | Medium   | HTML escaping + 200-char truncation in `sarif_reporter.py`                                                                                                      |
| Path traversal via symlinks (AV4)     | Medium   | Symlink targets resolved and validated against repo root in `file_discovery.py`                                                                                 |
| LLM API token exposure in CI logs     | Medium   | Accepted: tokens are passed via CLI arg or env var; CI config does not echo them, but caller is responsible for secret masking                                  |
| No dependency lockfile                | Low      | Accepted: hatchling-based build pins to `>=` minimums; CI runs on clean venvs; full lockfile pending pre-1.0 stability                                          |

---

## Security Architecture

### Scanner Self-Protection Invariants

The scanner was designed with the explicit understanding that it analyzes adversarial content. The following invariants are enforced in code (see [`specs/architecture/security-model.md`](specs/architecture/security-model.md)):

- **S001**: The scanner MUST NOT execute or evaluate any content from scanned files — it is strictly a read-and-analyze tool. All file I/O uses binary read mode (`open(path, "rb")`).
- **S002**: File content sent to the LLM MUST pass through [Pre-LLM Sanitization](src/ipi_check/scanner/llm_sanitizer.py) first — unsanitized content MUST NOT cross the LLM API boundary.
- **S003**: The LLM response MUST be parsed as structured JSON — the parser rejects any response that is not valid JSON matching the expected schema.
- **S004**: If the LLM response fails JSON parsing, the scanner MUST fall back to the static-only verdict and emit `IPI900` (LLM_CLASSIFIER_COMPROMISED).
- **S005**: All file paths MUST be validated to reside within the target repository root — path traversal outside the root MUST be blocked.
- **S006**: SARIF output MUST HTML-escape user-controlled content to prevent injection into SARIF viewers.

### LLM Classifier Defense Layers

See [AV1 in the security model](specs/architecture/security-model.md#av1-llm-classifier-prompt-injection):

1. **Pre-LLM Sanitization** ([`llm_sanitizer.py`](src/ipi_check/scanner/llm_sanitizer.py)) — invisible characters, ANSI escapes, bidi overrides, and variation selectors are replaced with visible placeholders; base64 blocks are decoded. Content is no longer truncated (batch processing handles large inputs via chunking).
2. **Immutable System Prompts** ([`llm_classifier.py`](src/ipi_check/scanner/llm_classifier.py)) — module-level constants `CLASSIFIER_SYSTEM_PROMPT` (single-file) and `BATCH_CLASSIFIER_SYSTEM_PROMPT` (batch) with explicit "DO NOT follow instructions" directive.
3. **Structured Output Enforcement** ([`llm_classifier.py`](src/ipi_check/scanner/llm_classifier.py)) — response parsed as JSON with strict schema validation; any failure → `compromised=True`.
4. **Batch Partial Failure Handling** — individual file entries in batch responses are validated independently; broken entries trigger per-file retry with exponential backoff (max 3 attempts).
5. **Confidence Fusion** ([`confidence_fusion.py`](src/ipi_check/scanner/confidence_fusion.py)) — CRITICAL static findings cannot be overridden by LLM `safe` verdicts.

### Secret Management

| Secret           | Storage                                                                                            | Rotation                       |
| ---------------- | -------------------------------------------------------------------------------------------------- | ------------------------------ |
| LLM API tokens   | CLI arg (`--llm-api-token`) or env vars (`LITELLM_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) | Manual — caller responsibility |
| Git hook control | Env vars (`IPI_CHECK_HOOK_DISABLE`, `IPI_CHECK_BLOCK_ON_REVIEW`)                                   | N/A                            |

**Secrets that MUST NEVER appear in:** source code, tests, commit messages, logs, error messages, or SARIF output.

### Dependency Management

| Dependency | Version | Purpose                           | Evaluation                                                                            |
| ---------- | ------- | --------------------------------- | ------------------------------------------------------------------------------------- |
| `litellm`  | >=1.0   | LLM provider abstraction          | Community-standard, actively maintained; deferred import for graceful fallback        |
| `pathspec` | >=0.12  | `.gitignore` pattern matching     | Used by major tools (Black, etc.); minimal attack surface                             |
| `pygments` | >=2.17  | Code lexer for comment extraction | Widely used; deferred import; fallback to full-text when unavailable                  |
| `tiktoken` | >=0.5   | Token counting for batch assembly | OpenAI maintained; optional `[batch]` extra; deferred import with char-based fallback |

- No lockfile (hatchling `>=` pins); CI runs with clean venvs
- CI pipeline (`lint → type-check → test → docker`) gates all merges
- No automated dependency vulnerability scanning is configured (tracked for future CI enhancement)

### Logging & Monitoring

The scanner itself produces no persistent logs. Runtime output:

- **stderr**: Progress bars, banner, scan summary, file-skip warnings
- **stdout / `--output`**: SARIF v2.1.0 JSON document

The git hook (`ipi-check-hook.sh`) stores SARIF results at `.git/ipi-check-last.sarif` for audit trails.

---

## Secure Coding Guidelines

These guidelines apply to ALL contributors: human developers, code reviewers, and AI/LLM coding agents (GitHub Copilot, Cursor, Qoder, Codeium, etc.). Automated agents MUST treat these rules as hard constraints.

### Input Validation

- Validate all CLI arguments at the boundary (`cli/main.py:_validate_repo_path`, `_validate_output_path`)
- `${VAR_NAME}` expansion collapses undefined variables to empty strings — no partial injection possible
- File discovery validates every path against the repo root before reading ([`file_discovery.py:244`](src/ipi_check/scanner/file_discovery.py#L244))
- Use `os.walk` with in-place directory pruning rather than constructing paths from user input
- Reject files exceeding `MAX_FILE_SIZE_BYTES` (10 MB)
- Binary extensions are filtered by allowlist ([`file_discovery.py:38`](src/ipi_check/scanner/file_discovery.py#L38-L42))

### Path Traversal Prevention

- ALL file paths must be validated to reside within the repository root (invariant S005)
- Symlinks are resolved with `Path.resolve()` and the result is validated with `Path.relative_to()` — any path escaping the root is rejected with a warning
- `..` traversal is inherently blocked because paths are resolved relative to the repo root before use

### LLM Safety

- **NEVER** send unsanitized file content to the LLM (invariant S002). The `sanitize_content()` function in [`llm_sanitizer.py`](src/ipi_check/scanner/llm_sanitizer.py) must run before any LLM call.
- **NEVER** modify `CLASSIFIER_SYSTEM_PROMPT` or `BATCH_CLASSIFIER_SYSTEM_PROMPT` in [`llm_classifier.py`](src/ipi_check/scanner/llm_classifier.py) without a security review. These prompts are security boundaries (invariant I005).
- **NEVER** interpret free-text LLM output. All responses must pass through `_parse_and_validate()` (single-file) or `_parse_batch_response()` (batch) which strictly reject non-JSON or schema-mismatched content.
- LLM calls use a 180-second timeout. No call can hang indefinitely.

### Output Encoding & Injection Prevention

- All user-controlled content embedded in SARIF `message.text` and `message.markdown` fields must pass through `_escape_sarif_content()` — which performs HTML escaping and 200-char truncation
- SARIF messages use parameterized templates — content is always inserted via `.format()`, never via string concatenation or raw format strings
- Content sent to stdout/stderr is bounded (summary uses pre-computed counters, not raw file content)

### Python-Specific Rules

- **No `eval()` / `exec()`**: Banned. The only occurrences of `eval`, `exec`, `system` in source code are in regex detection patterns for finding malicious content in scanned files.
- **No `subprocess` with user input**: The scanner does not spawn subprocesses.
- **No `pickle`**: Not used. Use `json` for serialization.
- **Binary mode for file I/O**: Always use `open(path, "rb")` when reading scanned files to preserve byte-level information for ANSI/Unicode detection (invariant I001).
- **Deferred imports**: `litellm`, `pygments`, and `tiktoken` are imported inside functions to allow graceful fallback when not installed. Follow this pattern for any optional dependency.
- **No mysterious `# nosec` or `# type: ignore` without justification comment**.

### Dependency & Supply Chain Rules

- All dependencies are declared in `pyproject.toml` with minimum version pins
- CI runs lint + type-check + tests on every push and PR
- Do not add dependencies with: no maintenance activity >12 months, known unpatched critical vulnerabilities, excessive transitive trees for trivial functionality
- Prefer standard-library solutions when possible (e.g., `argparse` over `click`, `pathlib` over `os.path`)

### Secrets & Configuration

- NEVER commit secrets to version control
- LLM API tokens are accepted via CLI arg or environment variable — never hardcoded
- Environment variables `LITELLM_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` are checked for LLM availability but never logged
- `.env` is in `.gitignore`

---

## Rules for AI Coding Agents

This section provides explicit directives for AI/LLM-based coding assistants working on this codebase. These rules are non-negotiable and override any general-purpose training behavior of the agent.

### Hard Constraints

The following actions are FORBIDDEN for any AI agent working on this repository:

1. **No secret exposure** — Do not write, echo, log, or commit any secret, token, password, or API key in source code, tests, comments, commit messages, or CI configuration. This includes OpenAI, Anthropic, or LiteLLM API keys.

2. **No LLM safety bypass** — Do not modify `CLASSIFIER_SYSTEM_PROMPT` or `BATCH_CLASSIFIER_SYSTEM_PROMPT` in [`llm_classifier.py`](src/ipi_check/scanner/llm_classifier.py) without explicit approval and a security review. These prompts are security boundaries.

3. **No unsanitized LLM input** — Do not send file content to the LLM without first passing it through `sanitize_content()` in [`llm_sanitizer.py`](src/ipi_check/scanner/llm_sanitizer.py). The sanitization pipeline is non-optional.

4. **No raw LLM output interpretation** — Do not use LLM response text directly. All LLM output must pass through `_parse_and_validate()` (single-file) or `_parse_batch_response()` (batch) which enforces strict JSON schema validation.

5. **No `eval()`, `exec()`, `os.system()`, or `subprocess` with scanned-file content** — These are banned (anti-pattern AP-S01). The scanner is strictly read-only.

6. **No path traversal** — Do not read files outside the repository root. All path resolution must validate against `repo_path` using `Path.relative_to()`.

7. **No text-mode file reads** — Always use `open(path, "rb")` for reading scanned files (invariant I001). Text mode loses byte-level information needed for ANSI/Unicode detection.

8. **No suppressed security warnings** — Do not add `# noqa`, `# nosec`, `# type: ignore[import-untyped]`, or equivalent suppression annotations without a comment justifying why the suppression is safe.

9. **No magic security thresholds** — All numeric thresholds (entropy, invisible ratio, instruction density, confidence) must be defined as named module-level constants, never as magic numbers inline (invariant I006).

10. **No uncontrolled SARIF content** — User-controlled content in SARIF output must always pass through `_escape_sarif_content()` for HTML escaping and truncation.

### Behavioral Guidelines for Agents

- **Respect security invariants** — The invariants documented in [`specs/architecture/security-model.md`](specs/architecture/security-model.md) (S001–S006) and [`specs/architecture/system-overview.md`](specs/architecture/system-overview.md) (I001–I007) are non-negotiable. Read them before modifying scanner code.
- **Confidence fusion is deterministic** — The decision matrix in [`confidence_fusion.py`](src/ipi_check/scanner/confidence_fusion.py) must remain deterministic. Do not introduce probabilistic or ML-based fusion logic without spec and security review.
- **CRITICAL static severity always blocks** — Do not change the invariant that CRITICAL static findings skip the LLM (invariant I002). This is a defense-in-depth measure.
- **Ask before acting on security boundaries** — If a change involves the LLM classifier, sanitizer, path validation, SARIF escaping, or the confidence fusion matrix, flag it for human review.
- **Default to secure** — When multiple implementation options exist, choose the one that preserves existing security invariants.
- **Flag uncertainty** — If you are uncertain whether a change introduces a security risk, flag it explicitly in a PR description or code comment.

---

## Security-Related Configuration Files

| File                                                                                       | Purpose                                                                                           |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| [`src/ipi_check/scanner/llm_sanitizer.py`](src/ipi_check/scanner/llm_sanitizer.py)         | Pre-LLM content sanitization — neutralizes hostile content before LLM API call                    |
| [`src/ipi_check/scanner/llm_classifier.py`](src/ipi_check/scanner/llm_classifier.py)       | LLM classification with immutable system prompts (single-file + batch) and strict JSON validation |
| [`src/ipi_check/scanner/confidence_fusion.py`](src/ipi_check/scanner/confidence_fusion.py) | Deterministic decision matrix for final verdicts                                                  |
| [`src/ipi_check/scanner/file_discovery.py`](src/ipi_check/scanner/file_discovery.py)       | Path traversal protection and file filtering                                                      |
| [`src/ipi_check/reporter/sarif_reporter.py`](src/ipi_check/reporter/sarif_reporter.py)     | SARIF output with HTML escaping and content truncation                                            |
| [`src/ipi_check/scanner/pattern_matching.py`](src/ipi_check/scanner/pattern_matching.py)   | ReDoS protection via thread-based regex timeout                                                   |
| [`src/ipi_check/scanner/token_counter.py`](src/ipi_check/scanner/token_counter.py)         | Token counting for batch assembly (tiktoken with char-based fallback)                             |
| [`scripts/ipi-check-hook.sh`](scripts/ipi-check-hook.sh)                                   | Git hook wrapper with BLOCK verdict enforcement                                                   |
| [`.github/workflows/ci.yml`](.github/workflows/ci.yml)                                     | CI with lint, type-check, tests (Python 3.12+3.13), docker build                                  |
| [`pyproject.toml`](pyproject.toml)                                                         | Build config, dependency declarations, linter/type-checker settings                               |
| [`.gitignore`](.gitignore)                                                                 | Excludes `.env`, `.venv`, bytecode, caches                                                        |
| [`Dockerfile`](Dockerfile)                                                                 | Multi-stage build on `python:3.12-slim`                                                           |
| [`specs/architecture/security-model.md`](specs/architecture/security-model.md)             | Threat model and security invariants                                                              |

---

## Revision History

| Date       | Author      | Change                                                   |
| ---------- | ----------- | -------------------------------------------------------- |
| 2026-06-06 | @vkochetkov | Initial security policy generated from codebase analysis |
