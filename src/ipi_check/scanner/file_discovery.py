"""File Discovery — Layer 1: locate files that may contain prompt injection payloads."""

from __future__ import annotations

import fnmatch
import os
import sys
import warnings
from pathlib import Path

import pathspec
from pathspec.pattern import Pattern as _PathSpecPattern

from ipi_check.core.types import DiscoveredFile, FileCategory

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
    """Categorize a file by priority: agent instruction → dot-dir markdown → source code."""
    if _is_agent_instruction(filename, relative_path):
        return FileCategory.AGENT_INSTRUCTION
    if _is_dot_directory_markdown(relative_path):
        return FileCategory.DOT_DIRECTORY_MD
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
    rel = str((parent_dir / name).resolve().relative_to(repo_path))
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


def discover_files(
    repo_path: Path,
    *,
    respect_gitignore: bool = True,
    exclude_patterns: list[str] | None = None,
) -> list[DiscoveredFile]:
    """Discover files within repo_path that may contain prompt injection payloads.

    Walks the repository tree, skipping .git/, binary files, and oversize files.
    Categorizes each file and returns deduplicated DiscoveredFile entries.

    When ``respect_gitignore`` is True (default), entries matching the repo
    root's ``.gitignore`` file are excluded. Additional ``exclude_patterns``
    (gitignore-style globs) are also honored when provided.
    """
    if not repo_path.exists():
        print(f"Error: Repository path not found: {repo_path}", file=sys.stderr)
        sys.exit(2)
    if repo_path.is_file():
        print(f"Error: Expected a directory: {repo_path}", file=sys.stderr)
        sys.exit(2)

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
    return discovered
