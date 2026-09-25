"""File Discovery — Layer 1: locate files that may contain prompt injection payloads."""

from __future__ import annotations

import fnmatch
import os
import warnings
from pathlib import Path

import pathspec
from pathspec.pattern import Pattern as _PathSpecPattern

from ipi_check.core.types import (
    DiscoveredFile,
    FileCategory,
    SkillFrontmatter,
    SkillUnit,
)

# Concrete PathSpec type used for both gitignore parsing and explicit excludes.
_GitignorePathSpec = pathspec.PathSpec[_PathSpecPattern]

MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB

AGENT_INSTRUCTION_FILES: tuple[str, ...] = (
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    "AGENTS.md",
    "CLAUDE.md",
    "copilot-instructions.md",
)

CURSOR_RULE_PATTERN: str = ".cursor/**/*.mdc"

SOURCE_CODE_EXTENSIONS: tuple[str, ...] = (
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".go",
    ".rs",
    ".rb",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".cs",
    ".swift",
    ".kt",
    ".scala",
    ".php",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".svg",
    ".yaml",
    ".yml",
    ".toml",
    ".json",
    ".xml",
)

BINARY_EXTENSIONS: tuple[str, ...] = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".ico",
    ".webp",
    ".avif",
    ".pdf",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".class",
    ".pyc",
    ".o",
    ".obj",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".bin",
    # Font containers — never contain reviewable text payloads.
    ".otf",
    ".ttf",
    ".woff",
    ".woff2",
    # OOXML (Office Open XML) packages — ZIP containers of XML parts.
    ".pptx",
    ".docx",
    ".xlsx",
)

# Content-sniff window: the first 8 KiB is enough to detect any of the magic
# headers below.
BINARY_SNIFF_BYTES: int = 8 * 1024

# Magic byte prefixes identifying common binary container formats. These act as
# a second barrier (after the extension check) for files that either have no
# extension or carry an unrecognized one. Every prefix must start with a byte
# that makes the file *unusable as a script or document*: shell interpreters
# keep executing after an unparseable first line (verified: a script whose
# line 1 is garbage still runs line 2), so a purely-ASCII prefix — ``true``,
# ``wOFF``, ``RIFF``, ``%PDF``, ``BZh``, … — can open a *functional* script
# and must never appear here. Font/archive/image formats with ASCII names are
# caught by their extension; only containers whose leading bytes are control
# or high-bit bytes (untypable as script text) are listed.
BINARY_MAGIC_PREFIXES: tuple[bytes, ...] = (
    b"PK\x03\x04",  # ZIP archive (also .docx/.xlsx/.pptx and many others)
    b"PK\x05\x06",  # Empty ZIP archive (end-of-central-directory marker)
    b"PK\x07\x08",  # Spanned ZIP archive
    b"\x00\x01\x00\x00",  # TrueType font (.ttf)
    b"\x89PNG",  # PNG image
    b"\xff\xd8\xff",  # JPEG image
    b"\x7fELF",  # ELF object/executable
    b"\xfe\xed\xfa\xce",  # Mach-O binary (big-endian, 32-bit)
    b"\xfe\xed\xfa\xcf",  # Mach-O binary (big-endian, 64-bit)
    b"\xce\xfa\xed\xfe",  # Mach-O binary (little-endian, 32-bit)
    b"\xcf\xfa\xed\xfe",  # Mach-O binary (little-endian, 64-bit)
    b"\xca\xfe\xba\xbe",  # Mach-O fat binary / Java class file
    b"\x00asm",  # WebAssembly binary
    b"\x1f\x8b",  # gzip archive
    b"\xfd7zXZ\x00",  # xz archive
    b"7z\xbc\xaf\x27\x1c",  # 7-Zip archive
    b"\xd0\xcf\x11\xe0",  # Legacy Office compound file (.doc/.xls/.ppt)
    b"\x00\x00\x01\x00",  # ICO icon
)

GIT_DIR_NAME: str = ".git"
GITIGNORE_FILENAME: str = ".gitignore"
MARKDOWN_EXTENSION: str = ".md"
MDC_EXTENSION: str = ".mdc"
CURSOR_DIR_NAME: str = ".cursor"
DOT_PREFIX: str = "."
SKILL_METADATA_FILENAME: str = "SKILL.md"


def _is_within_repo(resolved_path: Path, repo_path: Path) -> bool:
    """Check whether resolved_path is within repo_path (path traversal protection)."""
    try:
        resolved_path.relative_to(repo_path)
        return True
    except ValueError:
        return False


def _matches_cursor_rule(relative_path: str) -> bool:
    """Check whether a relative path matches the .cursor/**/*.mdc pattern.

    Uses a manual check because fnmatch does not implement glob-style `**`
    recursive matching. A path matches when its first component is `.cursor`,
    it has at least one path component beyond `.cursor`, and its suffix is `.mdc`.
    """
    parts = Path(relative_path).parts
    if len(parts) < 2:
        return False
    if parts[0] != CURSOR_DIR_NAME:
        return False
    return fnmatch.fnmatch(parts[-1], f"*{MDC_EXTENSION}")


def _is_agent_instruction(filename: str, relative_path: str) -> bool:
    """Determine whether a file qualifies as an agent instruction file."""
    if filename.lower() in tuple(name.lower() for name in AGENT_INSTRUCTION_FILES):
        return True
    return _matches_cursor_rule(relative_path)


def _is_dot_directory_markdown(relative_path: str) -> bool:
    """Determine whether a file is a markdown file in the repo root or a dot-prefixed directory.

    A file qualifies if:
    - it has a .md extension AND
    - it is at the repo root, OR any parent directory component (relative to repo root)
      starts with '.'
    """
    path = Path(relative_path)
    if path.suffix.lower() != MARKDOWN_EXTENSION:
        return False
    parent_parts = path.parts[:-1]
    if not parent_parts:
        # Root-level markdown file
        return True
    return any(component.startswith(DOT_PREFIX) for component in parent_parts)


def _is_source_code(filename: str) -> bool:
    """Determine whether a file is a source code file based on its extension."""
    suffix = Path(filename).suffix.lower()
    return suffix in SOURCE_CODE_EXTENSIONS


def _has_binary_extension(filename: str) -> bool:
    """Check whether a file has a known binary extension."""
    suffix = Path(filename).suffix.lower()
    return suffix in BINARY_EXTENSIONS


def _has_binary_magic(path: Path) -> bool:
    """Content-based binary detection — the second barrier after extension checks.

    Reads the first :data:`BINARY_SNIFF_BYTES` (8 KiB) of ``path`` and reports
    whether the payload starts with a known binary container magic header
    (archives, Office documents, fonts, images, objects — see
    :data:`BINARY_MAGIC_PREFIXES`; only prefixes whose leading bytes are
    control or high-bit bytes, i.e. untypable as script text).

    A NUL byte is deliberately **not** treated as binary. An embedded NUL does
    not stop an interpreter: a shell script (or any script run via
    ``bash setup`` / ``./setup``) executes just fine with a stray ``\\x00`` in
    it, so a NUL-based drop rule applied to files without a recognized text
    name let a one-byte edit hide a *fully functional* malicious skill script
    from the entire skill audit. For the same reason a purely-ASCII magic
    (``true``, ``wOFF``, ``RIFF``, ``%PDF``, ``BZh``, …) never excludes a
    file: a shell keeps executing after an unparseable first line, so a
    script can be prefixed with such bytes and still run. Only a leading
    control/high-bit byte sequence — bytes that cannot open a working script
    or document — may silently exclude a file.

    **Callers must only apply this sniff to files whose name carries no text
    signal** (``not is_text_named(...)``). For a text-named file — agent
    instruction, ``SKILL.md``, source code, bundled notes — even the magic
    rule is an *evasion oracle*: an attacker who prepends a ZIP magic would
    otherwise silently remove an injection-bearing file from the scan. The
    file's name is the only trustworthy text/binary signal for those files.

    Unreadable or empty files are reported as NOT binary — the caller handles
    stat/read errors separately, so this helper must not mask them.
    """
    try:
        with open(path, "rb") as handle:
            head = handle.read(BINARY_SNIFF_BYTES)
    except OSError:
        return False
    if not head:
        return False
    return any(head.startswith(prefix) for prefix in BINARY_MAGIC_PREFIXES)


def _categorize(filename: str, relative_path: str) -> FileCategory | None:
    """Categorize a file by priority: agent instruction → dot-dir markdown → source code → skill."""
    if _is_agent_instruction(filename, relative_path):
        return FileCategory.AGENT_INSTRUCTION
    if _is_dot_directory_markdown(relative_path):
        return FileCategory.DOT_DIRECTORY_MD
    if filename == SKILL_METADATA_FILENAME:
        return FileCategory.SKILL
    if _is_source_code(filename):
        return FileCategory.SOURCE_CODE
    return None


#: Extensions of plain-text assets that ``_categorize`` does not classify but
#: that are still reviewable text (bundled docs, notes) — never excluded by
#: the NUL-byte heuristic of the content sniff (see :func:`is_text_named`).
TEXT_ASSET_EXTENSIONS: frozenset[str] = frozenset({".md", ".markdown", ".txt", ".rst"})


def is_text_named(filename: str, relative_path: str) -> bool:
    """Return ``True`` when a file's *name* marks it as reviewable text.

    True for every categorizable name (agent-instruction file, dot-directory
    markdown, ``SKILL.md``, source-code extension) plus common text-asset
    extensions (``.md``, ``.txt``, ``.rst`` — e.g. notes bundled in a skill
    directory). Such files are the ones coding agents read, so the
    content-based binary sniff (:func:`_has_binary_magic`) must never be
    applied to them — a prepended ZIP magic would otherwise silently remove an
    injection-bearing file from the scan. All sniff call sites (discovery,
    skill static analysis, skill LLM payload assembly) share this predicate so
    the exemption cannot drift apart.
    """
    if _categorize(filename, relative_path) is not None:
        return True
    return Path(filename).suffix.lower() in TEXT_ASSET_EXTENSIONS


def _load_gitignore_spec(gitignore_path: Path) -> _GitignorePathSpec | None:
    """Parse a single ``.gitignore`` file into a PathSpec, or None when absent.

    ``gitignore_path`` is the path of the ignore file itself (not the directory
    that contains it), so the same loader serves the repository root and every
    nested ``.gitignore`` (IN-22).
    """
    if not gitignore_path.is_file():
        return None
    try:
        with open(gitignore_path, encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except OSError as exc:
        warnings.warn(
            f"Could not read {gitignore_path}: {exc}; proceeding without gitignore.",
            stacklevel=2,
        )
        return None
    return pathspec.PathSpec.from_lines("gitwildmatch", lines)


def _probe_gitignore_spec(spec: _GitignorePathSpec, rel_path: str) -> bool | None:
    """Return one gitignore spec's verdict for ``rel_path``.

    Returns ``True`` when the path is ignored, ``False`` when the *last*
    matching pattern is a negation (``!pattern``), and ``None`` when no pattern
    matched at all (so a shallower spec's verdict stays in force).  Matching is
    attempted both with and without a trailing slash so that directory patterns
    (``build/``) are honoured for the directory itself as well as its contents.
    """
    result: bool | None = None
    rel_with_slash = rel_path + "/"
    for pattern in spec.patterns:
        if pattern.match_file(rel_path) or pattern.match_file(rel_with_slash):
            result = pattern.include
    return result


class _GitignoreResolver:
    """Resolve nested ``.gitignore`` exclusions for paths under a repo root.

    Git scopes every ``.gitignore`` to the directory that contains it: patterns
    are matched against paths **relative to that directory**, and a deeper
    file's verdict overrides a shallower one's.  A single root-level spec (the
    previous behaviour) cannot express this, so the resolver keeps a
    per-directory spec cache and evaluates the full ancestor chain for each
    candidate — shallowest first, with the last non-``None`` verdict winning
    (IN-22).

    When ``enabled`` is ``False`` (``--no-gitignore``) every query returns
    ``False`` without touching the filesystem.
    """

    def __init__(self, repo_path: Path, *, enabled: bool = True) -> None:
        self._repo_path = repo_path
        self._enabled = enabled
        self._spec_cache: dict[Path, _GitignorePathSpec | None] = {}
        self._chain_cache: dict[Path, list[tuple[Path, _GitignorePathSpec]]] = {}

    @property
    def enabled(self) -> bool:
        """Whether gitignore handling is active for this scan."""
        return self._enabled

    def _spec_for_dir(self, directory: Path) -> _GitignorePathSpec | None:
        """Return (and memoize) the spec for ``directory/.gitignore``."""
        if directory not in self._spec_cache:
            self._spec_cache[directory] = _load_gitignore_spec(directory / GITIGNORE_FILENAME)
        return self._spec_cache[directory]

    def _chain_for_dir(self, directory: Path) -> list[tuple[Path, _GitignorePathSpec]]:
        """Return ``[(base_dir, spec), ...]`` from the repo root down to ``directory``."""
        cached = self._chain_cache.get(directory)
        if cached is not None:
            return cached
        ancestors: list[Path] = []
        current = directory
        while True:
            ancestors.append(current)
            if current == self._repo_path or current.parent == current:
                break
            current = current.parent
        ancestors.reverse()
        chain: list[tuple[Path, _GitignorePathSpec]] = []
        for base in ancestors:
            spec = self._spec_for_dir(base)
            if spec is not None:
                chain.append((base, spec))
        self._chain_cache[directory] = chain
        return chain

    def is_ignored(self, target: Path) -> bool:
        """Return True when ``target`` (absolute, inside the repo) is gitignored."""
        if not self._enabled:
            return False
        result: bool | None = None
        for base, spec in self._chain_for_dir(target.parent):
            try:
                rel = str(target.relative_to(base))
            except ValueError:
                continue
            verdict = _probe_gitignore_spec(spec, rel)
            if verdict is not None:
                result = verdict
        return bool(result)


def _is_excluded(
    name: str,
    parent_dir: Path,
    repo_path: Path,
    gitignore: _GitignoreResolver,
    exclude_spec: _GitignorePathSpec | None,
) -> bool:
    """Check if a file/directory path is excluded by gitignore or exclude patterns."""
    target = (parent_dir / name).resolve()
    try:
        rel = str(target.relative_to(repo_path))
    except ValueError:
        # Path resolves outside the repository — treat as excluded.
        return True
    # Explicit --exclude patterns always win and are matched repo-relative.
    if exclude_spec and (exclude_spec.match_file(rel) or exclude_spec.match_file(rel + "/")):
        return True
    return gitignore.is_ignored(target)


def _build_exclude_spec(
    exclude_patterns: list[str] | None,
) -> _GitignorePathSpec | None:
    """Build a PathSpec from explicit --exclude glob patterns, or None."""
    if not exclude_patterns:
        return None
    return pathspec.PathSpec.from_lines("gitwildmatch", exclude_patterns)


def _split_frontmatter(text: str) -> tuple[str | None, str]:
    """Split ``---``-delimited frontmatter from the markdown body.

    Returns ``(yaml_block, body)``. ``yaml_block`` is ``None`` when the
    document carries no usable frontmatter — the body is then the whole text
    and callers fall back to empty metadata.
    """
    if not text.startswith("---"):
        return (None, text)
    # Skip the opening --- (and any whitespace/newline after it).
    rest = text[3:].lstrip()
    # Find the closing --- at line start.
    closing_idx = rest.find("\n---")
    if closing_idx == -1:
        return (None, text)
    yaml_block = rest[:closing_idx]
    body = rest[closing_idx + 1:]  # +1 to skip the \n before ---
    # Skip past the --- line itself and any trailing newline.
    nl_after = body.find("\n")
    if nl_after != -1:
        body = body[nl_after + 1:]
    return (yaml_block, body)


def _normalize_frontmatter_value(value: object) -> str:
    """Coerce a parsed YAML value into a trimmed plain string.

    YAML scalars are not guaranteed to be strings — ``1.0`` parses as a float,
    ``true`` as a bool, ``null`` as ``None`` — and block sequences parse as
    lists. Every value is therefore normalised to text so downstream consumers
    (SARIF rendering, LLM payloads) always receive a string. Sequence items are
    joined with ``", "``.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (list, tuple)):
        return ", ".join(_normalize_frontmatter_value(item) for item in value)
    return str(value).strip()


def _frontmatter_from_mapping(data: dict[str, object]) -> SkillFrontmatter:
    """Build a :class:`SkillFrontmatter` from a parsed YAML mapping."""
    metadata_raw = data.get("metadata")
    metadata: dict[str, str] = {}
    if isinstance(metadata_raw, dict):
        metadata = {
            str(key).strip(): _normalize_frontmatter_value(value)
            for key, value in metadata_raw.items()
        }
    # ``allowed-tools`` is the canonical (hyphenated) spelling; accept the
    # underscore variant too so either form normalises identically.
    allowed_raw = data.get("allowed-tools")
    if allowed_raw is None:
        allowed_raw = data.get("allowed_tools")
    return SkillFrontmatter(
        name=_normalize_frontmatter_value(data.get("name")),
        description=_normalize_frontmatter_value(data.get("description")),
        license=_normalize_frontmatter_value(data.get("license")) or None,
        compatibility=_normalize_frontmatter_value(data.get("compatibility")) or None,
        metadata=metadata,
        allowed_tools=_normalize_frontmatter_value(allowed_raw) or None,
    )


def _yaml_load_mapping(yaml_block: str) -> dict[str, object] | None:
    """Best-effort ``yaml.safe_load`` of a frontmatter block.

    Returns the parsed mapping, or ``None`` when PyYAML is unavailable, the
    block does not parse, or the document is not a mapping. The *safe* loader
    guarantees no arbitrary Python object is ever constructed, so a hostile
    frontmatter payload cannot execute code through the parser; every error
    (syntax, unknown tag, resource blow-up) degrades to the ``None`` sentinel so
    the caller falls back to the regex parser.
    """
    try:
        import yaml
    except ImportError:
        return None
    try:
        loaded: object = yaml.safe_load(yaml_block)
    except Exception:  # defensive: any malformed/hostile document degrades gracefully.
        return None
    if isinstance(loaded, dict):
        return loaded
    return None


def _parse_frontmatter_regex(yaml_block: str) -> SkillFrontmatter:
    """Regex fallback for frontmatter parsing when PyYAML is unavailable.

    Handles top-level ``key: value`` pairs and a nested ``metadata:`` block.
    Values are taken verbatim (quotes and block-scalar indicators are *not*
    interpreted) — this exists only as a safety net so that a missing or
    misbehaving YAML library never breaks discovery.
    """
    import re as _re

    name: str = ""
    description: str = ""
    license_val: str | None = None
    compatibility: str | None = None
    metadata_dict: dict[str, str] = {}
    allowed_tools: str | None = None

    current_meta_key: str | None = None
    for line in yaml_block.split("\n"):
        stripped = line.rstrip()
        if not stripped or stripped.startswith("#"):
            continue

        # Nested value under metadata:
        if current_meta_key == "metadata" and stripped.startswith(("  ", "\t")):
            m = _re.match(r"\s+(\S[^:]*):\s*(.*)", stripped)
            if m:
                metadata_dict[m.group(1).strip()] = m.group(2).strip()
            continue
        else:
            current_meta_key = None

        m = _re.match(r"(\S[^:]*):(?:\s+(.*))?", stripped)
        if not m:
            continue
        key = m.group(1).strip()
        val = m.group(2).strip() if m.group(2) else ""

        if key == "name":
            name = val
        elif key == "description":
            description = val
        elif key == "license":
            license_val = val or None
        elif key == "compatibility":
            compatibility = val or None
        elif key == "allowed-tools":
            allowed_tools = val or None
        elif key == "metadata":
            current_meta_key = "metadata"

    return SkillFrontmatter(
        name=name,
        description=description,
        license=license_val,
        compatibility=compatibility,
        metadata=metadata_dict,
        allowed_tools=allowed_tools,
    )


def _parse_skill_frontmatter(raw_bytes: bytes) -> tuple[SkillFrontmatter, str]:
    """Parse YAML frontmatter from SKILL.md raw bytes.

    The standard ``---``-delimited YAML frontmatter defined by the Agent Skills
    specification is parsed with a full YAML parser (PyYAML ``safe_load``),
    which unquotes values (``name: "x"`` → ``x``) and expands block scalars
    (``description: >`` / ``|``) into their multi-line text. Parsed values are
    normalised to plain strings (see :func:`_normalize_frontmatter_value`).

    PyYAML is optional: when it is unavailable, or the block cannot be parsed as
    a YAML mapping, a lightweight regex parser is used as a fallback so that
    discovery never fails on a malformed or hostile frontmatter.

    Returns a :class:`SkillFrontmatter` and the body text that follows the
    closing ``---`` delimiter. When the frontmatter is missing or malformed the
    returned frontmatter carries an empty name/description; callers are expected
    to handle this gracefully (empty frontmatter is not an error — the skill is
    still scanned, just without metadata-augmented heuristics).
    """
    text = raw_bytes.decode("utf-8", errors="replace")
    yaml_block, body = _split_frontmatter(text)
    if yaml_block is None:
        return (SkillFrontmatter(name="", description=""), text)
    mapping = _yaml_load_mapping(yaml_block)
    if mapping is not None:
        return (_frontmatter_from_mapping(mapping), body)
    return (_parse_frontmatter_regex(yaml_block), body)


def _is_skill_file(relative_path: str, skill_roots: dict[str, Path]) -> Path | None:
    """Check whether ``relative_path`` falls within any skill root.

    Returns the skill root :class:`Path` that most tightly encloses the file
    (deepest match, i.e. the innermost skill for nested layouts), or ``None``
    if the file is not inside any skill directory.
    """
    file_parts = Path(relative_path).parts
    best_root: Path | None = None
    best_depth: int = -1
    for root_rel, root_path in skill_roots.items():
        root_parts = Path(root_rel).parts
        if len(root_parts) > len(file_parts):
            continue
        if file_parts[:len(root_parts)] == root_parts and len(root_parts) > best_depth:
            best_depth = len(root_parts)
            best_root = root_path
    return best_root


def _walk_skill_dir(
    skill_root: Path,
    repo_path: Path,
    gitignore: _GitignoreResolver,
    exclude_spec: _GitignorePathSpec | None,
    existing_seen: set[Path],
    max_file_size: int = MAX_FILE_SIZE_BYTES,
) -> list[DiscoveredFile]:
    """Walk a skill directory to find all additional files not already discovered.

    Files already in ``existing_seen`` are skipped. Binary extensions and
    oversized files (``max_file_size``) are filtered. Every file returned has
    ``FileCategory.SKILL``.
    """
    extra: list[DiscoveredFile] = []
    for current_dir_str, dirs, filenames in os.walk(skill_root):
        dirs[:] = [d for d in dirs if d != GIT_DIR_NAME]
        current_dir_path = Path(current_dir_str)
        if gitignore.enabled or exclude_spec:
            dirs[:] = [
                d
                for d in dirs
                if not _is_excluded(d, current_dir_path, repo_path, gitignore, exclude_spec)
            ]
        for fname in filenames:
            file_path = current_dir_path / fname
            if (gitignore.enabled or exclude_spec) and _is_excluded(
                fname, current_dir_path, repo_path, gitignore, exclude_spec
            ):
                continue
            try:
                resolved = file_path.resolve()
            except OSError:
                continue
            if not _is_within_repo(resolved, repo_path):
                continue
            if resolved in existing_seen:
                continue
            if _has_binary_extension(fname):
                continue
            relative_path = str(resolved.relative_to(repo_path))
            # Second barrier: content sniff for binary payloads without a
            # recognized binary extension (see discover_files). Text-named
            # files (source code, SKILL.md, bundled notes — see
            # ``is_text_named``) skip the sniff entirely; it applies only to
            # extensionless/unrecognized assets, and only a container magic
            # excludes a file — a NUL byte must not (an interpreter runs a
            # script with a stray NUL just fine).
            if not is_text_named(fname, relative_path) and _has_binary_magic(
                resolved
            ):
                continue
            try:
                size_bytes = resolved.stat().st_size
            except OSError:
                continue
            if size_bytes > max_file_size:
                continue
            existing_seen.add(resolved)
            extra.append(DiscoveredFile(
                path=resolved,
                category=FileCategory.SKILL,
                relative_path=relative_path,
                size_bytes=size_bytes,
            ))
    return extra


def _build_skill_units(
    discovered: list[DiscoveredFile],
    repo_path: Path,
    gitignore: _GitignoreResolver,
    exclude_spec: _GitignorePathSpec | None,
    max_file_size: int = MAX_FILE_SIZE_BYTES,
) -> tuple[list[DiscoveredFile], list[SkillUnit]]:
    """Post-process discovered files into non-skill files and SkillUnits.

    Identifies SKILL.md files, determines skill roots, re-categorizes files
    within skill directories, discovers any additional files in skill dirs
    that were missed by the initial walk, and builds :class:`SkillUnit` objects.
    """
    # --- Find SKILL.md files and build skill-root mapping ---
    skill_roots: dict[str, Path] = {}  # relative_path → resolved root dir
    skill_metadata_files: dict[str, DiscoveredFile] = {}  # relative_path → SKILL.md file
    for f in discovered:
        if f.path.name == SKILL_METADATA_FILENAME:
            root_dir = f.path.parent
            root_rel = str(root_dir.relative_to(repo_path))
            if root_rel == ".":
                root_rel = ""
            # If there's already a deeper skill root here, keep the deepest.
            # We sort later, but for now just track.
            skill_roots[root_rel] = root_dir
            skill_metadata_files[root_rel] = f

    if not skill_roots:
        return (discovered, [])

    # Sort roots by depth (deepest first) so nested skills are identified correctly.
    sorted_roots = sorted(
        skill_roots.items(),
        key=lambda item: len(Path(item[0]).parts),
        reverse=True,
    )
    # Rebuild with deepest-first order preserved as dict for _is_skill_file lookups.
    skill_roots_by_depth: dict[str, Path] = dict(sorted_roots)

    # --- Split discovered into skill-grouped and non-skill ---
    skill_file_map: dict[str, list[DiscoveredFile]] = {root_rel: [] for root_rel in skill_roots}
    non_skill: list[DiscoveredFile] = []
    all_seen: set[Path] = {f.path for f in discovered}

    for f in discovered:
        skill_root = _is_skill_file(f.relative_path, skill_roots_by_depth)
        if skill_root is None:
            non_skill.append(f)
            continue
        # Find the corresponding root_rel key.
        root_rel = str(skill_root.relative_to(repo_path))
        if root_rel == ".":
            root_rel = ""
        if root_rel in skill_file_map:
            # Re-categorize to SKILL
            skill_file_map[root_rel].append(DiscoveredFile(
                path=f.path,
                category=FileCategory.SKILL,
                relative_path=f.relative_path,
                size_bytes=f.size_bytes,
            ))

    # --- Walk each skill dir to find additional files not in original discovered ---
    for root_rel, root_path in skill_roots_by_depth.items():
        extra = _walk_skill_dir(
            root_path, repo_path, gitignore, exclude_spec, all_seen, max_file_size
        )
        skill_file_map[root_rel].extend(extra)
        for ef in extra:
            all_seen.add(ef.path)

    # --- Build SkillUnits ---
    skill_units: list[SkillUnit] = []
    for root_rel, root_path in skill_roots_by_depth.items():
        metadata_file = skill_metadata_files[root_rel]
        # Read and parse SKILL.md
        try:
            raw = metadata_file.path.read_bytes()
        except OSError:
            continue
        frontmatter, body = _parse_skill_frontmatter(raw)

        # Collect all files for this skill (including SKILL.md itself).
        skill_files = list(skill_file_map[root_rel])
        # Ensure the metadata file itself is included (may not be if SKILL.md
        # was re-categorized above).
        md_path = metadata_file.path
        if not any(f.path == md_path for f in skill_files):
            skill_files.append(DiscoveredFile(
                path=md_path,
                category=FileCategory.SKILL,
                relative_path=metadata_file.relative_path,
                size_bytes=metadata_file.size_bytes,
            ))
        skill_files.sort(key=lambda f: f.relative_path)

        skill_units.append(SkillUnit(
            root=root_path,
            metadata_file=DiscoveredFile(
                path=md_path,
                category=FileCategory.SKILL,
                relative_path=metadata_file.relative_path,
                size_bytes=metadata_file.size_bytes,
            ),
            files=skill_files,
            frontmatter=frontmatter,
            body=body,
        ))

    # Sort non-skill files deterministically.
    non_skill.sort(key=lambda f: f.relative_path)
    return (non_skill, skill_units)


def discover_files(
    repo_path: Path,
    *,
    respect_gitignore: bool = True,
    exclude_patterns: list[str] | None = None,
    max_file_size: int = MAX_FILE_SIZE_BYTES,
) -> tuple[list[DiscoveredFile], list[SkillUnit]]:
    """Discover files within repo_path that may contain prompt injection payloads.

    Walks the repository tree, skipping .git/, binary files, and oversize files.
    Categorizes each file and returns deduplicated DiscoveredFile entries.

    When ``respect_gitignore`` is True (default), every ``.gitignore`` in the
    tree is honoured with git semantics: patterns match relative to the
    directory that owns the ignore file, and a deeper file overrides a
    shallower one (IN-22). Additional ``exclude_patterns`` (gitignore-style
    globs) are also honored when provided. Files larger than
    ``max_file_size`` bytes are skipped with a warning.

    If ``SKILL.md`` files are found, skill directories are automatically
    detected and returned as :class:`SkillUnit` objects. Files within skill
    directories are excluded from the non-skill file list.

    Returns:
        A tuple of ``(non_skill_files, skill_units)``.
    """
    if not repo_path.exists():
        raise FileNotFoundError(f"Repository path not found: {repo_path}")
    if repo_path.is_file():
        raise NotADirectoryError(f"Expected a directory: {repo_path}")

    repo_path = repo_path.resolve()

    gitignore = _GitignoreResolver(repo_path, enabled=respect_gitignore)
    exclude_spec: _GitignorePathSpec | None = _build_exclude_spec(exclude_patterns)

    discovered: list[DiscoveredFile] = []
    seen: set[Path] = set()

    for current_dir, dirs, files in os.walk(repo_path):
        # Always skip .git/ directories
        dirs[:] = [d for d in dirs if d != GIT_DIR_NAME]

        current_dir_path = Path(current_dir)

        # Prune directories matching gitignore or exclude specs.
        if gitignore.enabled or exclude_spec:
            dirs[:] = [
                d
                for d in dirs
                if not _is_excluded(d, current_dir_path, repo_path, gitignore, exclude_spec)
            ]

        for filename in files:
            file_path = current_dir_path / filename

            try:
                resolved = file_path.resolve()
            except OSError as exc:
                warnings.warn(
                    f"Skipping file due to resolution error: {file_path} ({exc})",
                    stacklevel=2,
                )
                continue

            # Path traversal protection (AV4): symlinks must resolve within repo_path
            if not _is_within_repo(resolved, repo_path):
                warnings.warn(
                    f"Skipping symlink resolving outside repository: {file_path} -> {resolved}",
                    stacklevel=2,
                )
                continue

            # Exclude files matching gitignore or exclude specs before any
            # other checks (binary ext, size, category).
            if (gitignore.enabled or exclude_spec) and _is_excluded(
                filename,
                current_dir_path,
                repo_path,
                gitignore,
                exclude_spec,
            ):
                continue

            if resolved in seen:
                continue

            if _has_binary_extension(filename):
                continue

            relative_path = str(resolved.relative_to(repo_path))
            category = _categorize(filename, relative_path)
            if category is None:
                continue

            # Second barrier: content sniff for binary payloads that slip past
            # the extension check (extensionless or renamed assets such as
            # fonts and Office documents). Text-named files (see
            # ``is_text_named``) never pass through the sniff — a magic
            # header must not silently remove a file the agent will read, and
            # for everything else only a container magic excludes: a NUL byte
            # must not (an interpreter runs a script with a stray NUL).
            if not is_text_named(filename, relative_path) and _has_binary_magic(
                resolved
            ):
                continue

            try:
                size_bytes = resolved.stat().st_size
            except OSError as exc:
                warnings.warn(f"Skipping file due to stat error: {file_path} ({exc})", stacklevel=2)
                continue

            if size_bytes > max_file_size:
                warnings.warn(
                    f"Skipping file exceeding {max_file_size} bytes: "
                    f"{file_path} ({size_bytes} bytes)",
                    stacklevel=2,
                )
                continue

            seen.add(resolved)
            discovered.append(
                DiscoveredFile(
                    path=resolved,
                    category=category,
                    relative_path=relative_path,
                    size_bytes=size_bytes,
                )
            )

    # Sort for deterministic output regardless of OS/filesystem ordering.
    discovered.sort(key=lambda f: f.relative_path)

    # Post-process: detect skills and build SkillUnits.
    return _build_skill_units(discovered, repo_path, gitignore, exclude_spec, max_file_size)
