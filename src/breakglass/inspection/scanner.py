"""Core deterministic repository scanner and inspection engine."""

import os
from pathlib import Path
import fnmatch
from typing import Set, List, Dict, Optional, Tuple

from breakglass.inspection.models import (
    RepositoryReport,
    RepositorySummary,
    SecurityIndicator,
    RouteCandidate,
    EntryPointCandidate,
    ManifestInfo,
    InspectionError
)
from breakglass.inspection.indicators import scan_line_for_indicators, scan_line_for_routes
from breakglass.inspection.detectors import (
    detect_language,
    parse_manifest_file,
    detect_frameworks_from_manifests,
    check_is_config_or_infra,
    scan_line_for_entry_points
)


# Default directories ignored to prevent scanning dependencies, builds, or cache
DEFAULT_IGNORED_DIRS: Set[str] = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    "target",
    "vendor",
    ".pytest_cache",
    ".idea",
    ".vscode",
    ".next",
    ".nuxt",
    "coverage",
    ".tox",
    ".mypy_cache",
    "out",
    "bin",
    "obj"
}

# Maximum file size to scan for line-by-line static analysis (2 MB)
MAX_FILE_SIZE_BYTES: int = 2 * 1024 * 1024


def _is_binary_file(file_path: Path) -> bool:
    """Checks if a file is likely binary by inspecting the first 1024 bytes."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            if b"\x00" in chunk:
                return True
    except Exception:
        pass
    return False


def _parse_gitignore(repo_root: Path) -> List[str]:
    """Parses .gitignore patterns if present in the repository root."""
    gitignore_path = repo_root / ".gitignore"
    patterns: List[str] = []
    if gitignore_path.exists() and gitignore_path.is_file():
        try:
            content = gitignore_path.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    # Normalize pattern
                    patterns.append(line)
        except Exception:
            pass
    return patterns


def _is_ignored_by_gitignore(rel_path_str: str, gitignore_patterns: List[str]) -> bool:
    """Checks whether a relative file path matches any .gitignore pattern strictly."""
    rel_path_normalized = rel_path_str.replace("\\", "/")
    parts = rel_path_normalized.split("/")

    for pattern in gitignore_patterns:
        pattern = pattern.strip()
        if not pattern or pattern.startswith("#"):
            continue

        clean_pattern = pattern.rstrip("/")

        # Rooted pattern starting with /
        if clean_pattern.startswith("/"):
            root_pattern = clean_pattern[1:]
            if fnmatch.fnmatch(rel_path_normalized, root_pattern) or fnmatch.fnmatch(rel_path_normalized, f"{root_pattern}/*"):
                return True
        else:
            # Check full relative path or any individual directory/file component
            if fnmatch.fnmatch(rel_path_normalized, clean_pattern):
                return True
            for part in parts:
                if fnmatch.fnmatch(part, clean_pattern):
                    return True
    return False


def inspect_repository(repository_path: str) -> RepositoryReport:
    """Performs a deterministic, safe static inspection of a local repository.

    Args:
        repository_path: Path to the target repository directory.

    Returns:
        RepositoryReport containing structured analysis results.

    Raises:
        ValueError: If repository_path is invalid, non-existent, or not a directory.
    """
    path_obj = Path(repository_path).resolve()

    if not path_obj.exists():
        raise ValueError(f"Repository path does not exist: {repository_path}")
    if not path_obj.is_dir():
        raise ValueError(f"Repository path is not a directory: {repository_path}")

    repo_root = path_obj
    repo_root_str = str(repo_root)

    gitignore_patterns = _parse_gitignore(repo_root)

    total_files = 0
    total_directories = 0
    languages: Dict[str, int] = {}
    frameworks: List[str] = []
    ecosystems: Set[str] = set()
    config_files: List[str] = []
    docker_configs: List[str] = []
    cicd_configs: List[str] = []
    infrastructure_configs: List[str] = []
    test_files: List[str] = []

    entry_points: List[EntryPointCandidate] = []
    routes: List[RouteCandidate] = []
    security_indicators: List[SecurityIndicator] = []
    manifests: List[ManifestInfo] = []
    errors: List[InspectionError] = []

    # File traversal
    for root, dirs, files in os.walk(repo_root, followlinks=False):
        dirs.sort()
        current_dir = Path(root)

        # Filter, inspect, and prune directory list
        valid_dirs = []
        for d in dirs:
            dir_path = current_dir / d
            try:
                rel_dir = dir_path.relative_to(repo_root)
                rel_dir_str = str(rel_dir).replace("\\", "/")
            except ValueError:
                errors.append(
                    InspectionError(
                        file=str(dir_path),
                        message="Directory is outside repository root",
                        error_type="boundary_error"
                    )
                )
                continue

            # Directory symlink check
            if dir_path.is_symlink():
                try:
                    resolved_dir = dir_path.resolve()
                    resolved_dir.relative_to(repo_root)
                except ValueError:
                    errors.append(
                        InspectionError(
                            file=rel_dir_str,
                            message=f"Directory symlink points outside repository: {dir_path.resolve()}",
                            error_type="symlink_out_of_bounds"
                        )
                    )
                    continue
                except Exception as e:
                    errors.append(
                        InspectionError(
                            file=rel_dir_str,
                            message=f"Failed to resolve directory symlink: {str(e)}",
                            error_type="symlink_error"
                        )
                    )
                    continue

            if d in DEFAULT_IGNORED_DIRS or _is_ignored_by_gitignore(rel_dir_str, gitignore_patterns):
                continue

            valid_dirs.append(d)

        dirs[:] = valid_dirs
        total_directories += len(dirs)

        for filename in sorted(files):
            file_path = current_dir / filename

            # Calculate relative path for reporting
            try:
                rel_path = file_path.relative_to(repo_root)
                rel_path_str = str(rel_path).replace("\\", "/")
            except ValueError:
                # File outside repository root
                errors.append(
                    InspectionError(
                        file=str(file_path),
                        message="File is outside repository root",
                        error_type="boundary_error"
                    )
                )
                continue

            # Symlink validation
            if file_path.is_symlink():
                try:
                    resolved_symlink = file_path.resolve()
                    # Verify resolved path is strictly within repo_root
                    resolved_symlink.relative_to(repo_root)
                except ValueError:
                    errors.append(
                        InspectionError(
                            file=rel_path_str,
                            message=f"Symlink points outside repository: {file_path.resolve()}",
                            error_type="symlink_out_of_bounds"
                        )
                    )
                    continue
                except Exception as e:
                    errors.append(
                        InspectionError(
                            file=rel_path_str,
                            message=f"Failed to resolve symlink: {str(e)}",
                            error_type="symlink_error"
                        )
                    )
                    continue

            # Gitignore check
            if _is_ignored_by_gitignore(rel_path_str, gitignore_patterns):
                continue

            total_files += 1

            # Language detection
            lang = detect_language(file_path)
            if lang:
                languages[lang] = languages.get(lang, 0) + 1

            # Classification (config, docker, cicd, infra, tests)
            classifications = check_is_config_or_infra(rel_path_str)
            if classifications["is_config"]:
                config_files.append(rel_path_str)
            if classifications["is_docker"]:
                docker_configs.append(rel_path_str)
            if classifications["is_cicd"]:
                cicd_configs.append(rel_path_str)
            if classifications["is_infra"]:
                infrastructure_configs.append(rel_path_str)

            # Test file detection heuristic
            filename_lower = filename.lower()
            rel_lower = rel_path_str.lower()
            if (
                filename_lower.startswith("test_")
                or filename_lower.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts", "_test.go", "test.rs", "Test.java"))
                or "/tests/" in rel_lower
                or "/test/" in rel_lower
                or "/__tests__/" in rel_lower
            ):
                test_files.append(rel_path_str)

            # Manifest parsing
            manifest_info = parse_manifest_file(file_path, rel_path_str)
            if manifest_info:
                manifests.append(manifest_info)
                ecosystems.add(manifest_info.ecosystem)

            # File size check before line scanning
            try:
                file_size = file_path.stat().st_size
                if file_size > MAX_FILE_SIZE_BYTES:
                    errors.append(
                        InspectionError(
                            file=rel_path_str,
                            message=f"File size ({file_size} bytes) exceeds safety scan limit ({MAX_FILE_SIZE_BYTES} bytes)",
                            error_type="file_size_exceeded"
                        )
                    )
                    continue
            except Exception as e:
                errors.append(
                    InspectionError(
                        file=rel_path_str,
                        message=f"Could not stat file: {str(e)}",
                        error_type="stat_error"
                    )
                )
                continue

            # Skip binary files for indicator analysis
            if _is_binary_file(file_path):
                continue

            # Line-by-line static analysis
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, start=1):
                        # Security Indicators
                        found_indicators = scan_line_for_indicators(line, line_num, rel_path_str)
                        security_indicators.extend(found_indicators)

                        # Routes
                        found_routes = scan_line_for_routes(line, line_num, rel_path_str)
                        routes.extend(found_routes)

                        # Entry Points
                        ep = scan_line_for_entry_points(line, line_num, rel_path_str)
                        if ep:
                            entry_points.append(ep)

            except Exception as e:
                errors.append(
                    InspectionError(
                        file=rel_path_str,
                        message=f"Error reading file content: {str(e)}",
                        error_type="read_error"
                    )
                )

    # Detect frameworks from manifests
    frameworks = detect_frameworks_from_manifests(manifests)

    # Deterministic sorting of output collections
    entry_points.sort(key=lambda x: (x.file, x.line or 0, x.type, x.description))
    routes.sort(key=lambda x: (x.file, x.line, x.method, x.pattern))
    security_indicators.sort(key=lambda x: (x.file, x.line or 0, x.category, x.indicator_type, x.evidence))
    manifests.sort(key=lambda x: (x.file, x.ecosystem))
    errors.sort(key=lambda x: (x.file, x.error_type, x.message))

    summary = RepositorySummary(
        root=repo_root_str,
        total_files=total_files,
        total_directories=total_directories,
        languages=languages,
        frameworks=frameworks,
        ecosystems=sorted(list(ecosystems)),
        config_files=sorted(config_files),
        docker_configs=sorted(docker_configs),
        cicd_configs=sorted(cicd_configs),
        infrastructure_configs=sorted(infrastructure_configs),
        test_files=sorted(test_files)
    )

    return RepositoryReport(
        repository=summary,
        entry_points=entry_points,
        routes=routes,
        security_indicators=security_indicators,
        manifests=manifests,
        errors=errors
    )
