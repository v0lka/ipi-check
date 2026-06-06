# ADR-002: SARIF as Output Format

## Status

Accepted

## Context

The scanner produces structured findings (severity, line/column location, category, description) that need to be consumed by:
- Developer IDE plugins (VS Code, JetBrains)
- Code review platforms (GitHub Code Scanning, GitLab SAST)
- CI/CD pipelines (scripted consumption via `jq` or similar)
- Human readers (for manual review)

We need a format that is both machine-readable and standardized enough that existing tools can consume it without custom parsers.

## Decision

**Use SARIF v2.1.0** (Static Analysis Results Interchange Format) as the sole output format.

SARIF is an OASIS standard (ISO/IEC 23360-1:2022) designed specifically for static analysis tool output. It is natively supported by:
- GitHub Code Scanning (ingests SARIF directly)
- GitLab SAST (SARIF support since GitLab 14.7)
- VS Code (SARIF Viewer extension)
- JetBrains IDEs (Qodana and SARIF plugins)

## Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| **Custom JSON** | Simple to generate, no schema to follow | No tooling support; every consumer needs a custom parser; no standard location format | Zero ecosystem integration — defeats the purpose |
| **SonarQube Generic Issue Format** | SonarQube integration | Proprietary, limited to one platform, not an open standard | SARIF covers SonarQube + GitHub + GitLab + IDEs |
| **JUnit XML** | CI systems parse it natively | Designed for test results, not SAST findings; no location format; no severity levels | Wrong semantic model |
| **CSV** | Human-readable in spreadsheets | No multi-line support; no nested data; no standard schema | Too primitive for structured security findings |

## Consequences

### Enables
- Direct GitHub Code Scanning integration — upload the `.sarif` file, findings appear in the Security tab
- GitLab SAST integration — SARIF artifacts are parsed automatically
- IDE integration via existing SARIF plugins
- Deterministic, versioned schema (v2.1.0) prevents format drift
- JSON format enables scripting with `jq`, Python, etc.

### Constrains
- SARIF is verbose — a scan with many findings produces a large JSON file (acceptable trade-off for standardization)
- Requires strict adherence to SARIF schema — custom fields must go in `properties` bag
- No human-friendly "pretty" mode in the standard — mitigated by the `--quiet` flag enabling `jq` post-processing

## Cross-References

- [Reporting](../domains/reporting.md)
- [CLI Interface](../contracts/cli-interface.md)
- [System Overview](../architecture/system-overview.md)
