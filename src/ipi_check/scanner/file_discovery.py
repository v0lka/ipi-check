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


def _is_excluded(
    name: str,
    parent_dir: Path,
    repo_path: Path,
    gitignore_spec: _GitignorePathSpec | None,
    exclude_spec: _GitignorePathSpec | None,
) -> bool:
    """Check if a file/directory path is excluded by gitignore or exclude patterns."""
    target = (parent_dir / name).resolve()
    try:
        rel = str(target.relative_to(repo_path))
    except ValueError:
        # Path resolves outside the repository — treat as excluded.
        return True
    # For directories, also check with trailing slash (gitignore convention)
    if gitignore_spec and (gitignore_spec.match_file(rel) or gitignore_spec.match_file(rel + "/")):
        return True
    return bool(
        exclude_spec and (exclude_spec.match_file(rel) or exclude_spec.match_file(rel + "/"))
    )


def _load_gitignore_spec(repo_path: Path) -> _GitignorePathSpec | None:
    """Load and parse the repo's .gitignore file into a PathSpec, or None."""
    gitignore_path = repo_path / GITIGNORE_FILENAME
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


def _build_exclude_spec(
    exclude_patterns: list[str] | None,
) -> _GitignorePathSpec | None:
    """Build a PathSpec from explicit --exclude glob patterns, or None."""
    if not exclude_patterns:
        return None
    return pathspec.PathSpec.from_lines("gitwildmatch", exclude_patterns)


def _parse_skill_frontmatter(raw_bytes: bytes) -> tuple[SkillFrontmatter, str]:
    """Parse YAML frontmatter from SKILL.md raw bytes.

    Uses a lightweight regex-based parser that handles the standard
    ``---``-delimited YAML frontmatter format defined by the Agent Skills
    specification.  Returns a :class:`SkillFrontmatter` and the body text
    that follows the closing ``---`` delimiter.

    When the frontmatter is missing or malformed the returned frontmatter
    carries an empty name/description; callers are expected to handle this
    gracefully (empty frontmatter is not an error — the skill is still
    scanned, just without metadata-augmented heuristics).
    """
    import re as _re

    text = raw_bytes.decode("utf-8", errors="replace")
    name: str = ""
    description: str = ""
    license_val: str | None = None
    compatibility: str | None = None
    metadata_dict: dict[str, str] = {}
    allowed_tools: str | None = None
    body: str = text

    # Split on --- delimiters. The opening --- is at the start of the
    # file (no leading newline), the closing --- is preceded by \n.
    if text.startswith("---"):
        # Skip the opening --- (and any whitespace/newline after it).
        rest = text[3:].lstrip()
        # Find the closing --- at line start.
        closing_idx = rest.find("\n---")
        if closing_idx != -1:
            yaml_block = rest[:closing_idx]
            body = rest[closing_idx + 1:]  # +1 to skip the \n before ---
            # Skip past the --- line itself and any trailing newline.
            nl_after = body.find("\n")
            if nl_after != -1:
                body = body[nl_after + 1:]

            # Parse top-level key: value pairs and nested metadata.
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

    return (SkillFrontmatter(
        name=name,
        description=description,
        license=license_val,
        compatibility=compatibility,
        metadata=metadata_dict,
        allowed_tools=allowed_tools,
    ), body)


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
    gitignore_spec: _GitignorePathSpec | None,
    exclude_spec: _GitignorePathSpec | None,
    existing_seen: set[Path],
) -> list[DiscoveredFile]:
    """Walk a skill directory to find all additional files not already discovered.

    Files already in ``existing_seen`` are skipped. Binary extensions and
    oversized files are filtered. Every file returned has ``FileCategory.SKILL``.
    """
    extra: list[DiscoveredFile] = []
    for current_dir_str, dirs, filenames in os.walk(skill_root):
        dirs[:] = [d for d in dirs if d != GIT_DIR_NAME]
        current_dir_path = Path(current_dir_str)
        if gitignore_spec or exclude_spec:
            dirs[:] = [
                d
                for d in dirs
                if not _is_excluded(d, current_dir_path, repo_path, gitignore_spec, exclude_spec)
            ]
        for fname in filenames:
            file_path = current_dir_path / fname
            if (gitignore_spec or exclude_spec) and _is_excluded(
                fname, current_dir_path, repo_path, gitignore_spec, exclude_spec
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
            try:
                size_bytes = resolved.stat().st_size
            except OSError:
                continue
            if size_bytes > MAX_FILE_SIZE_BYTES:
                continue
            relative_path = str(resolved.relative_to(repo_path))
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
    gitignore_spec: _GitignorePathSpec | None,
    exclude_spec: _GitignorePathSpec | None,
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
            root_path, repo_path, gitignore_spec, exclude_spec, all_seen
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
) -> tuple[list[DiscoveredFile], list[SkillUnit]]:
    """Discover files within repo_path that may contain prompt injection payloads.

    Walks the repository tree, skipping .git/, binary files, and oversize files.
    Categorizes each file and returns deduplicated DiscoveredFile entries.

    When ``respect_gitignore`` is True (default), entries matching the repo
    root's ``.gitignore`` file are excluded. Additional ``exclude_patterns``
    (gitignore-style globs) are also honored when provided.

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

    gitignore_spec: _GitignorePathSpec | None = (
        _load_gitignore_spec(repo_path) if respect_gitignore else None
    )
    exclude_spec: _GitignorePathSpec | None = _build_exclude_spec(exclude_patterns)

    discovered: list[DiscoveredFile] = []
    seen: set[Path] = set()

    for current_dir, dirs, files in os.walk(repo_path):
        # Always skip .git/ directories
        dirs[:] = [d for d in dirs if d != GIT_DIR_NAME]

        current_dir_path = Path(current_dir)

        # Prune directories matching gitignore or exclude specs.
        if gitignore_spec or exclude_spec:
            dirs[:] = [
                d
                for d in dirs
                if not _is_excluded(d, current_dir_path, repo_path, gitignore_spec, exclude_spec)
            ]

        for filename in files:
            file_path = current_dir_path / filename

            # Exclude files matching gitignore or exclude specs before any
            # other checks (binary ext, size, category).
            if (gitignore_spec or exclude_spec) and _is_excluded(
                filename,
                current_dir_path,
                repo_path,
                gitignore_spec,
                exclude_spec,
            ):
                continue

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

            if resolved in seen:
                continue

            if _has_binary_extension(filename):
                continue

            try:
                size_bytes = resolved.stat().st_size
            except OSError as exc:
                warnings.warn(f"Skipping file due to stat error: {file_path} ({exc})", stacklevel=2)
                continue

            if size_bytes > MAX_FILE_SIZE_BYTES:
                warnings.warn(
                    f"Skipping file exceeding {MAX_FILE_SIZE_BYTES} bytes: "
                    f"{file_path} ({size_bytes} bytes)",
                    stacklevel=2,
                )
                continue

            relative_path = str(resolved.relative_to(repo_path))
            category = _categorize(filename, relative_path)
            if category is None:
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
    return _build_skill_units(discovered, repo_path, gitignore_spec, exclude_spec)
