# ADR-005: Pygments Tokenization for Code File Preprocessing

## Status

Accepted

## Context

The LLM Classifier currently sends the full content of every discovered file to the LLM. For non-code files (`.cursorrules`, `AGENTS.md`, dot-directory `.md` files), this is correct — the entire text is a potential injection vector.

For source code files (`.py`, `.js`, `.go`, etc.), however, full-file transmission is wasteful and noisy. Prompt injection payloads in code can only appear in:
- **Comments** (single-line, multi-line, doc-comments)
- **String literals** (single-quoted, double-quoted, template literals, f-strings, heredocs)

Actual code (keywords, identifiers, operators, numbers) is structural noise — it increases token cost, risks hitting context window limits, and adds no signals for injection detection.

We need a lightweight way to extract only comments and string literals from source code files before the Pre-LLM Sanitization stage. The solution must support 20+ languages (Python, JavaScript, TypeScript, Java, Go, Rust, Ruby, C/C++, C#, Swift, Kotlin, Scala, PHP, shell scripts, YAML, TOML, JSON, XML) without maintaining per-language parsers.

## Decision

**Use Pygments lexers for tokenization-based extraction of comments and string literals.**

When a file's `DiscoveredFile.category == "source_code"`, the LLM Classifier extracts comments and string literals using Pygments tokenization before applying Pre-LLM Sanitization:

1. Map the file extension to a Pygments lexer via `pygments.lexers.get_lexer_for_filename()`.
2. Tokenize the file content via `pygments.lex(content, lexer)`.
3. Filter tokens by type: `Comment.*` (all comment types), `String.*` (all string literal types), `Literal.String.*`.
4. Concatenate filtered token values with newline separators, preserving original 1-based line numbers for each extracted fragment.
5. Pass the concatenated result to Pre-LLM Sanitization instead of the raw file content.

For non-code files (`agent_instruction`, `dot_directory_md`), the full content passes directly to Pre-LLM Sanitization — no change.

## Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| **Full AST parsing per language** | Most precise extraction possible | Requires 20+ parsers (one per language); heavy dependency footprint; maintenance burden; AST parsers couple to language versions | 20 parsers = unsustainable. We need lightweight extraction, not compiler-grade analysis. |
| **Regex-based comment/string extraction** | Zero dependencies; simple | Fragile across languages; can't handle nested contexts (e.g., regex inside string, comment-like strings); false positives on comment delimiters inside strings | Every language has different comment/string syntax — a regex solution would miss edge cases in every language. |
| **Tree-sitter** | Single parser framework; accurate; supports many languages | Requires compiled grammars; `tree-sitter` Python bindings are not pure Python; adds build complexity; heavier than Pygments | Over-engineered for extraction. Pygments provides sufficient accuracy at lower cost. |
| **Send full code to LLM (status quo)** | Simple; no preprocessing | Wastes tokens on structural code (up to 80%+ of file content); increases latency and cost; LLM may be distracted by keywords and syntax | Primary motivation for this change — we explicitly want to avoid this. |
| **Pygments with `get_lexer_for_filename()`** | Single library; supports 500+ languages; pure Python; already well-maintained; handles unknown extensions gracefully (falls back to `TextLexer`); token types cleanly separate comments and strings | Tokenization is less precise than AST (no structural context); some edge cases in template-heavy languages may be mis-categorized | **Chosen.** The trade-off between tokenization and AST is acceptable — we only need surface-level token types, not structural relationships. |

## Consequences

### Enables
- **Token cost reduction**: For typical code files, 60–80% fewer tokens sent to the LLM (only comments and strings).
- **Signal-to-noise improvement**: The LLM sees only injection-relevant content — no keywords, operators, or structural syntax.
- **Broader language support**: Pygments covers 500+ languages out of the box; adding a new `.SOURCE_CODE_EXTENSIONS` entry works automatically via `get_lexer_for_filename()`.
- **Fallback safety**: If Pygments doesn't recognize a file extension, it falls back to `TextLexer` which treats the entire file as `Text` tokens — the module detects this (no `Comment.*`/`String.*` tokens found) and passes the full content through, ensuring no content is silently dropped.

### Constrains
- Adds a dependency on `pygments` package (~3MB).
- Token-level extraction loses structural context (e.g., which function a comment belongs to) — acceptable since LLM classification is semantic, not structural.
- Some template-heavy languages (JSX, TSX, Vue SFC) may tokenize inaccurately at boundaries between template, script, and style blocks. When in doubt, content is preserved rather than dropped.
- `pygments.lexers.get_lexer_for_filename()` relies on file extension — files without extensions in `source_code` category (if any) fall back to `TextLexer`.

## Cross-References

- [LLM Classifier](../domains/llm-classifier.md)
- [File Discovery](../domains/file-discovery.md)
- [ADR-004: LiteLLM Provider](004-litellm-provider.md)
- [ADR-003: Two-Stage Pipeline](003-two-stage-pipeline.md)
- [Pygments Documentation](https://pygments.org/docs/lexers/)
