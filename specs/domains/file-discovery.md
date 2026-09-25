# File Discovery

## Responsibility

Locate all files in a repository that may contain indirect prompt injection payloads or malicious agent skills — both AI agent instruction files (`.cursorrules`, `AGENTS.md`, etc.), agent skills (directories containing `SKILL.md`), and general source code files that could embed injection strings as literals.

## Input

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `repo_path` | `Path` | CLI argument | Absolute or relative path to the repository root |
| `respect_gitignore` | `bool` | CLI argument (`--no-gitignore` inverts) | Whether to honor `.gitignore` patterns (default: True) |
| `exclude_patterns` | `list[str] \| None` | CLI argument (`--exclude`) | User-specified exclude glob patterns (gitwildmatch syntax) |
| `max_file_size` | `int` | CLI argument (`--max-file-size`) | Byte ceiling above which a file is skipped (default: `MAX_FILE_SIZE_BYTES` = 10 MB) |

## Output

| Field | Type | Consumers | Description |
|-------|------|-----------|-------------|
| `non_skill_files` | `List[DiscoveredFile]` | Byte-Level Analysis | List of non-skill files to scan, each annotated with category |
| `skill_units` | `List[SkillUnit]` | Skill Static Analysis | Complete skill units discovered from `SKILL.md` directories |

```python
@dataclass
class DiscoveredFile:
    path: Path           # Absolute path to the file
    category: str        # "agent_instruction" | "dot_directory_md" | "source_code" | "skill"
    relative_path: str   # Path relative to repo root
    size_bytes: int      # File size in bytes

@dataclass
class SkillUnit:
    root: Path                # Absolute path to the skill directory
    metadata_file: DiscoveredFile  # The SKILL.md file
    files: list[DiscoveredFile]    # All files within the skill directory
    frontmatter: SkillFrontmatter  # Parsed YAML frontmatter (name, description, etc.)
    body: str                     # Body content after frontmatter

@dataclass
class SkillFrontmatter:
    name: str                     # Skill name from frontmatter
    description: str              # Skill description from frontmatter
    license: str | None = None
    compatibility: str | None = None
    metadata: dict[str, str]      # Arbitrary metadata key-values
    allowed_tools: str | None = None
```

## Behavior

```
repo_path ──▶ [Validate path exists] ──▶ [Walk directory tree]
                                              │
                    ┌──────────────────────────┼──────────────────────────┐
                    ▼                          ▼                          ▼
            ┌──────────────┐          ┌──────────────┐          ┌──────────────┐
            │ Match agent  │          │ Match .md    │          │ Match source │
            │ instruction  │          │ in dot-dirs  │          │ code files   │
            │ files        │          │ + root .md   │          │              │
            └──────┬───────┘          └──────┬───────┘          └──────┬───────┘
                   │                         │                         │
                   └─────────────────────────┼─────────────────────────┘
                                             │
                                             ▼
                                    ┌────────────────┐
                                    │ Deduplicate    │
                                    │ (exclude       │
                                    │  duplicates,   │
                                    │  binary files, │
                                    │  .git/)        │
                                    └───────┬────────┘
                                            │
                                            ▼
                                    List[DiscoveredFile]
```

### Exclusion Filters

Before category matching, discovered paths are filtered through two exclusion mechanisms:

#### Gitignore Exclusion (default: enabled)

When `respect_gitignore=True`, **every** `.gitignore` in the tree is honoured
with git semantics:

- Each ignore file is parsed with `gitwildmatch` syntax (via `pathspec`) and
  **scoped to the directory that contains it** — its patterns are matched
  against paths relative to that directory.
- Verdicts are evaluated from the repository root downwards and a deeper
  `.gitignore` overrides a shallower one. A nested `!keep.py` can therefore
  re-include a file that a root-level `*.py` rule excluded.
- Files matching any pattern are excluded from discovery.
- Directory patterns (e.g., `node_modules/`) prune the walk tree early for
  performance.
- Ignore files are read lazily and cached per directory; a missing or
  unreadable file is skipped silently (its scope simply contributes no rules).

`--no-gitignore` disables the mechanism entirely — no `.gitignore` is read.

#### User Exclude Patterns

When `exclude_patterns` is non-empty:
- Build a `pathspec.PathSpec` from the patterns using `gitwildmatch` syntax, matched against repo-root-relative paths
- Files and directories matching any pattern are excluded
- Directory patterns prune the walk tree early
- Applied in addition to gitignore exclusions (a file is excluded when either mechanism matches)

Both exclusion filters are applied BEFORE category matching — an excluded file never reaches the categorization step, regardless of whether it would match as an agent instruction file, dot-directory markdown, or source code.

### Category: Agent Instruction Files

Match exact filenames anywhere in the repository tree:
- `.cursorrules`
- `.windsurfrules`
- `.clinerules`
- `AGENTS.md`
- `CLAUDE.md`
- `copilot-instructions.md`
- `.cursor/**/*.mdc`

### Category: Dot-Directory Markdown Files

Match `.md` files (recursively) in:
- The repository root directory
- Any directory whose name starts with `.` (e.g., `.github/`, `.cursor/`, `.vscode/`)

### Category: Source Code Files

Match files by extension. All files with the following extensions are included:
- `.py`, `.js`, `.ts`, `.jsx`, `.tsx`, `.java`, `.go`, `.rs`, `.rb`, `.c`, `.cpp`, `.h`, `.hpp`, `.cs`, `.swift`, `.kt`, `.scala`, `.php`, `.sh`, `.bash`, `.zsh`, `.ps1`, `.svg`, `.yaml`, `.yml`, `.toml`, `.json`, `.xml`

### Category: Skill Files

When `SKILL.md` is discovered during the walk, the containing directory is treated as a **skill root**. All files within the skill root are re-categorized as `FileCategory.SKILL` and excluded from the non-skill file list. The scanner then:

1. Walks the skill directory to discover any additional files missed by the initial tree walk
2. Parses the `SKILL.md` frontmatter (YAML, extracting `name`, `description`, `license`, `compatibility`, `metadata`, `allowed-tools`)
3. Builds a `SkillUnit` aggregating the metadata file, all bundled files, the frontmatter, and the body content
4. Nested skills (skills within skills) are resolved with deepest-first priority

Skill files are **not** subject to regular pattern matching — they pass through a dedicated skill-specific static analysis pipeline instead.

## Edge Cases

| Case | Handling |
|------|----------|
| `repo_path` does not exist | Exit with error code 2 and message: "Repository path not found: {path}" |
| `repo_path` is a file, not a directory | Exit with error code 2 and message: "Expected a directory: {path}" |
| Empty repository (no matching files) | Return empty list; scanner exits with code 0 and message "No files to scan" |
| Symbolic links | Follow symlink; validate resolved path is within repo root; if outside, skip with warning |
| Binary files detected by extension | Skip `.png`, `.jpg`, `.pdf`, `.exe`, `.dll`, `.so`, `.dylib`, `.class`, `.pyc`, `.o`, `.obj`, `.zip`, `.tar`, `.gz`, `.bin` |
| Binary payload detected by content sniff | Second barrier after the extension check: a file whose first 8 KiB starts with a known binary container magic header — **only prefixes whose leading bytes are control/high-bit bytes** (ZIP archives, TrueType fonts, PNG/JPEG images, ELF/Mach-O objects, WASM, gzip/xz/7z archives, legacy Office, ICO) — is skipped, and only for files whose name carries no text signal (extensionless/unrecognized assets). Two rules are absolute: a NUL byte is **never** a drop signal (an interpreter executes a script with an embedded `\x00`), and neither is a purely-ASCII prefix (`true`, `wOFF`, `RIFF`, `%PDF`, `BZh`, …) — a shell keeps executing after an unparseable first line, so an ASCII "magic" can open a functional script. Text-named files (agent instructions, dot-dir markdown, `SKILL.md`, source code) never pass through the sniff at all, so a prepended magic cannot remove an injection-bearing text file either |
| Files exceeding `MAX_FILE_SIZE_BYTES` | Skip with warning: "Skipping large file: {path} ({size} bytes)" |
| `.git/` directory | Always excluded from scanning |
| `.gitignore` does not exist | Silently proceed without gitignore exclusion — no error |
| `.gitignore` contains malformed lines | Skip unrecognized lines; parse valid patterns normally |
| `--exclude` pattern matches an agent instruction file | File IS excluded — exclude patterns override category matching |
| Both `.gitignore` and `--exclude` specified | Both apply (union of exclusions) |
| `--no-gitignore` with `--exclude` | Gitignore is disabled but user excludes still apply |
| No `SKILL.md` files found | Return empty `skill_units` list; all files remain in non-skill output |
| `SKILL.md` cannot be read (I/O error) | Skip that skill; all files in its directory remain in non-skill output |
| Nested skill directories (skill inside skill) | Deepest skill root wins; parent skill does NOT include files belonging to the nested skill |
| Skill directory contains only `SKILL.md` | SkillUnit is created with a single file (the SKILL.md itself) |

## Configuration Constants

```python
# Default file size limit — files larger than this are skipped with a warning.
# The `--max-file-size` CLI flag overrides it per scan (passed to
# `discover_files` as the `max_file_size` parameter).
MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB

# Filename that triggers skill discovery
SKILL_METADATA_FILENAME: str = "SKILL.md"

# Agent instruction files — matched by exact filename, case-insensitive
AGENT_INSTRUCTION_FILES: tuple[str, ...] = (
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    "AGENTS.md",
    "CLAUDE.md",
    "copilot-instructions.md",
)

# Cursor rule files pattern
CURSOR_RULE_PATTERN: str = ".cursor/**/*.mdc"

# Source code extensions to scan
SOURCE_CODE_EXTENSIONS: tuple[str, ...] = (
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs",
    ".rb", ".c", ".cpp", ".h", ".hpp", ".cs", ".swift", ".kt",
    ".scala", ".php", ".sh", ".bash", ".zsh", ".ps1", ".svg",
    ".yaml", ".yml", ".toml", ".json", ".xml",
)

# Binary file extensions to skip
BINARY_EXTENSIONS: tuple[str, ...] = (
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".pdf",
    ".exe", ".dll", ".so", ".dylib", ".class", ".pyc", ".o", ".obj",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".bin",
)

# Gitignore filename
GITIGNORE_FILENAME: str = ".gitignore"
```

## Dependencies

- **pathspec** (external library): Parses `.gitignore` and `--exclude` patterns using gitwildmatch syntax

## Invariants

- **D001**: Every returned `DiscoveredFile.path` MUST be an absolute path that resides within `repo_path`.
- **D002**: No file from `.git/` directory MUST appear in the output.
- **D003**: Binary files MUST be excluded by extension, or — only for files whose name carries no text signal — by a content sniff that recognizes binary **container magic headers**. A NUL byte MUST NOT exclude any file, text-named or not: an interpreter runs a script with an embedded NUL, so a NUL-based drop is a one-byte evasion oracle. A magic header may only exclude a file whose bytes make it unusable as a script or document.
- **D004**: The output list MUST NOT contain duplicate paths (same file discovered via multiple rules).
- **D005**: Files exceeding the effective size limit (`max_file_size`, default `MAX_FILE_SIZE_BYTES`) MUST be skipped with a warning logged.
- **D006**: When `respect_gitignore=True`, EVERY `.gitignore` in the tree MUST be honoured with git semantics — patterns matched relative to the directory that owns the ignore file, with deeper files overriding shallower ones — and matching files MUST be excluded from the output.
- **D007**: `--exclude` patterns MUST exclude files regardless of their category — even agent instruction files are subject to user-specified exclusion.
- **D008**: Exclusion filters MUST be applied BEFORE category matching to avoid unnecessary processing.
- **D009**: Files within a skill directory MUST be re-categorized to `FileCategory.SKILL` and excluded from the non-skill file list — they MUST NOT appear in both outputs.
- **D010**: When nested skill directories are detected, the deepest skill root takes precedence — files MUST be assigned to the innermost containing skill only.
- **D011**: `discover_files` MUST return a tuple of `(non_skill_files, skill_units)`, not a flat list.

## Cross-References

- [System Overview](../architecture/system-overview.md)
- [Security Model](../architecture/security-model.md) — AV4: Path Traversal
- [Byte-Level Analysis](byte-analysis.md)
- [Pattern Matching](pattern-matching.md)
- [CLI Interface](../contracts/cli-interface.md)
