"""Core deterministic repository scanner and inspection engine."""

import os
import time
from pathlib import Path
import fnmatch
from typing import Set, List, Dict, Optional, Tuple, Any

from breakglass.inspection.models import (
    RepositoryReport,
    RepositorySummary,
    SecurityIndicator,
    RouteCandidate,
    EntryPointCandidate,
    ManifestInfo,
    InspectionError,
    InspectionLimits
)
from breakglass.inspection.indicators import scan_line_for_indicators, scan_line_for_routes, redact_secrets
from breakglass.inspection.detectors import (
    detect_language,
    parse_manifest_file,
    detect_frameworks_from_manifests,
    check_is_config_or_infra,
    scan_line_for_entry_points,
    classify_file
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


def _is_contained_in(parent: Path, child: Path) -> bool:
    """Checks if child is strictly inside parent in a component-aware manner."""
    try:
        parent_real = Path(os.path.realpath(str(parent)))
        child_real = Path(os.path.realpath(str(child)))
        p_str = os.path.normcase(str(parent_real))
        c_str = os.path.normcase(str(child_real))

        parent_parts = Path(p_str).parts
        child_parts = Path(c_str).parts

        if len(child_parts) < len(parent_parts):
            return False

        return child_parts[:len(parent_parts)] == parent_parts
    except Exception:
        return False


def _is_component_ignored(rel_path_str: str, extra_ignored_dirs: Optional[Set[str]] = None) -> bool:
    """Component-aware check to see if any path component matches the blacklist."""
    parts = rel_path_str.replace("\\", "/").split("/")
    ignored_set = DEFAULT_IGNORED_DIRS.copy()
    if extra_ignored_dirs:
        ignored_set.update(extra_ignored_dirs)

    for part in parts:
        if part in ignored_set:
            return True
    return False


class GitIgnoreRule:
    """Represents a single parsed .gitignore pattern rule."""
    def __init__(self, pattern: str, base_dir: str):
        self.raw_pattern = pattern
        self.base_dir = base_dir.replace("\\", "/").strip("/")

        rule_str = pattern.strip()
        self.is_negation = rule_str.startswith("!")
        if self.is_negation:
            rule_str = rule_str[1:]

        self.is_dir_only = rule_str.endswith("/")
        rule_str = rule_str.rstrip("/")

        self.is_rooted = rule_str.startswith("/")
        if self.is_rooted:
            rule_str = rule_str[1:]

        self.clean_pattern = rule_str

    def matches(self, rel_path_str: str, is_dir: bool = False) -> bool:
        norm_path = rel_path_str.replace("\\", "/")

        if self.base_dir:
            if not (norm_path == self.base_dir or norm_path.startswith(self.base_dir + "/")):
                return False
            path_in_base = norm_path[len(self.base_dir):].lstrip("/")
        else:
            path_in_base = norm_path

        if self.is_dir_only and not is_dir:
            return False

        parts = path_in_base.split("/")

        if self.is_rooted or "/" in self.clean_pattern:
            if fnmatch.fnmatch(path_in_base, self.clean_pattern) or fnmatch.fnmatch(path_in_base, f"{self.clean_pattern}/*"):
                return True
        else:
            if fnmatch.fnmatch(path_in_base, self.clean_pattern):
                return True
            for part in parts:
                if fnmatch.fnmatch(part, self.clean_pattern):
                    return True
        return False


def _collect_gitignore_rules(repo_root: Path) -> List[GitIgnoreRule]:
    """Collects all .gitignore rules across the repository hierarchy in top-down order."""
    all_rules: List[GitIgnoreRule] = []

    for root, dirs, files in os.walk(repo_root, followlinks=False):
        dirs.sort()
        current_dir = Path(root)
        if ".gitignore" in files:
            gitignore_file = current_dir / ".gitignore"
            try:
                rel_base = str(current_dir.relative_to(repo_root)).replace("\\", "/")
                if rel_base == ".":
                    rel_base = ""
                content = gitignore_file.read_text(encoding="utf-8", errors="ignore")
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        all_rules.append(GitIgnoreRule(line, rel_base))
            except Exception:
                pass
    return all_rules


def _is_path_ignored(rel_path_str: str, rules: List[GitIgnoreRule], is_dir: bool = False) -> bool:
    """Evaluates ignore status against ordered gitignore rules, handling negations."""
    ignored = False
    for rule in rules:
        if rule.matches(rel_path_str, is_dir=is_dir):
            ignored = not rule.is_negation
    return ignored


class RepositoryInspectionEngine:
    """Deterministic, bounded codebase static analysis and inspection engine."""

    def __init__(self, config: Optional[InspectionLimits] = None, custom_exclusions: Optional[List[str]] = None):
        self.config = config or InspectionLimits()
        self.config.validate()
        self.custom_exclusions = set(custom_exclusions) if custom_exclusions else set()

    def inspect(self, repository_path: str) -> RepositoryReport:
        """Performs structured, resource-bounded static scan of target repository.

        Args:
            repository_path: File system path of repository to inspect.

        Returns:
            RepositoryReport containing gathered structure facts and indicators.
        """
        start_time = time.perf_counter()

        # 1. Root Directory Verification & Canonicalization
        path_obj = Path(repository_path)
        try:
            repo_root = Path(os.path.realpath(str(path_obj)))
        except Exception as e:
            raise ValueError(f"Could not resolve repository path: {str(e)}")

        if not repo_root.exists():
            raise ValueError(f"Repository path does not exist: {repository_path}")
        if not repo_root.is_dir():
            raise ValueError(f"Repository path is not a directory: {repository_path}")

        repo_root_str = str(repo_root)

        # 2. Gather gitignore rules
        gitignore_rules = _collect_gitignore_rules(repo_root)

        # 3. Counters & Result list setup
        total_files = 0
        total_directories = 0
        total_bytes_inspected = 0

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

        # Tracking set for findings and path length truncation helper
        def limit_text(text: str) -> str:
            if len(text) > self.config.max_text_length:
                return text[:self.config.max_text_length] + "... [TRUNCATED]"
            return text

        def limit_path(path: str) -> str:
            if len(path) > self.config.max_path_length:
                return path[:self.config.max_path_length]
            return path

        limit_reached_reason = None
        visited_dirs = 0
        dirs_limit_reached = False

        # 4. Directory and File Traversal using os.walk
        for root, dirs, files in os.walk(repo_root, followlinks=False):
            # Check duration timeout budget first
            if time.perf_counter() - start_time > self.config.max_duration_seconds:
                limit_reached_reason = f"Scan duration limit of {self.config.max_duration_seconds}s exceeded"
                break

            current_dir = Path(root)
            if current_dir != Path(repo_root):
                visited_dirs += 1

            # A. Canonicalize and verify current directory containment
            if not _is_contained_in(repo_root, current_dir):
                errors.append(
                    InspectionError(
                        file=limit_path(str(current_dir)),
                        message="Directory lies outside canonical repository root",
                        error_type="boundary_error"
                    )
                )
                dirs[:] = []  # Do not descend
                continue

            # B. Check directory limits (Qodo 8: directories are counted when actually visited)
            if visited_dirs >= self.config.max_directories:
                dirs_limit_reached = True
                dirs[:] = []
                break

            # C. Filter, inspect, and prune directory list
            valid_dirs = []
            for d in sorted(dirs):
                # Check duration inside subdirectory loops
                if time.perf_counter() - start_time > self.config.max_duration_seconds:
                    break

                dir_path = current_dir / d

                try:
                    rel_dir = dir_path.relative_to(repo_root)
                    rel_dir_str = str(rel_dir).replace("\\", "/")
                except ValueError:
                    errors.append(
                        InspectionError(
                            file=limit_path(str(dir_path)),
                            message="Subdirectory is outside repository root",
                            error_type="boundary_error"
                        )
                    )
                    continue

                # Check path length limits before descent. Prefer rejecting overlong paths to prevent ambiguous identity (Qodo 4)
                if len(rel_dir_str) > self.config.max_path_length:
                    errors.append(
                        InspectionError(
                            file=limit_path(rel_dir_str),
                            message="Directory relative path exceeds max_path_length limit",
                            error_type="path_too_long"
                        )
                    )
                    continue

                # Directory symlink check using full path
                if dir_path.is_symlink():
                    try:
                        resolved_dir = dir_path.resolve()
                        if not _is_contained_in(repo_root, resolved_dir):
                            errors.append(
                                InspectionError(
                                    file=limit_path(rel_dir_str),
                                    message=f"Directory symlink points outside repository: {resolved_dir}",
                                    error_type="symlink_out_of_bounds"
                                )
                            )
                            continue
                    except Exception as e:
                        errors.append(
                            InspectionError(
                                file=limit_path(rel_dir_str),
                                message=f"Failed to resolve directory symlink: {str(e)}",
                                error_type="symlink_error"
                            )
                        )
                        continue

                # Check component blacklist and gitignores
                if _is_component_ignored(rel_dir_str, self.custom_exclusions) or _is_path_ignored(rel_dir_str, gitignore_rules, is_dir=True):
                    continue

                valid_dirs.append(d)

            # Apply pruned dirs list to control os.walk descent and cap dynamically to remaining budget (Qodo 8)
            remaining_budget = self.config.max_directories - visited_dirs
            if len(valid_dirs) > remaining_budget:
                valid_dirs = valid_dirs[:remaining_budget]
                dirs_limit_reached = True

            dirs[:] = valid_dirs

            # D. File handling
            for filename in sorted(files):
                # Check duration inside file loops
                if time.perf_counter() - start_time > self.config.max_duration_seconds:
                    break

                file_path = current_dir / filename

                try:
                    rel_path = file_path.relative_to(repo_root)
                    rel_path_str = str(rel_path).replace("\\", "/")
                except ValueError:
                    errors.append(
                        InspectionError(
                            file=limit_path(str(file_path)),
                            message="File is outside repository root",
                            error_type="boundary_error"
                        )
                    )
                    continue

                # Check path length limits before scanning. Prefer rejecting overlong paths to prevent ambiguous identity (Qodo 4)
                if len(rel_path_str) > self.config.max_path_length:
                    errors.append(
                        InspectionError(
                            file=limit_path(rel_path_str),
                            message="File relative path exceeds max_path_length limit",
                            error_type="path_too_long"
                        )
                    )
                    continue

                # Symlink validation using full path
                if file_path.is_symlink():
                    try:
                        resolved_symlink = file_path.resolve()
                        if not _is_contained_in(repo_root, resolved_symlink):
                            errors.append(
                                InspectionError(
                                    file=limit_path(rel_path_str),
                                    message=f"Symlink points outside repository: {resolved_symlink}",
                                    error_type="symlink_out_of_bounds"
                                )
                            )
                            continue
                    except Exception as e:
                        errors.append(
                            InspectionError(
                                file=limit_path(rel_path_str),
                                message=f"Failed to resolve symlink: {str(e)}",
                                decline_type="symlink_error"
                            )
                        )
                        continue

                # Ignore checks on full path
                if _is_component_ignored(rel_path_str, self.custom_exclusions) or _is_path_ignored(rel_path_str, gitignore_rules, is_dir=False):
                    continue

                # Check files limits
                if total_files >= self.config.max_files:
                    limit_reached_reason = f"Files limit of {self.config.max_files} reached"
                    break

                total_files += 1

                # Classify file using full relative path
                category = classify_file(filename, rel_path_str)

                # Track language and classification metrics
                lang = detect_language(file_path)
                if lang:
                    languages[lang] = languages.get(lang, 0) + 1

                if category == "tests":
                    test_files.append(limit_path(rel_path_str))
                elif category == "infrastructure_config":
                    classes = check_is_config_or_infra(rel_path_str)
                    if classes["is_docker"]:
                        docker_configs.append(limit_path(rel_path_str))
                    if classes["is_infra"]:
                        infrastructure_configs.append(limit_path(rel_path_str))
                elif category == "cicd_config":
                    cicd_configs.append(limit_path(rel_path_str))
                elif category == "configuration":
                    config_files.append(limit_path(rel_path_str))

                # Parse manifest dependencies under resource limits (Qodo 10)
                if category == "dependency_manifests":
                    try:
                        file_size = file_path.stat().st_size
                        remaining_budget = self.config.max_total_bytes - total_bytes_inspected
                        if file_size > self.config.max_file_size:
                            raise ValueError(f"Manifest size ({file_size} bytes) exceeds limit ({self.config.max_file_size} bytes)")
                        if remaining_budget <= 0:
                            raise ValueError("Aggregate size limit exceeded before parsing manifest")

                        manifest_info = parse_manifest_file(file_path, limit_path(rel_path_str), self.config, remaining_budget)
                        if manifest_info:
                            manifests.append(manifest_info)
                            ecosystems.add(manifest_info.ecosystem)
                            bytes_read = min(file_size, self.config.max_bytes_per_file, remaining_budget)
                            total_bytes_inspected += bytes_read
                    except Exception as e:
                        errors.append(
                            InspectionError(
                                file=limit_path(rel_path_str),
                                message=redact_secrets(f"Manifest parse failed: {str(e)}"),
                                error_type="manifest_parse_error"
                            )
                        )

                # File size check before line scanning
                try:
                    file_size = file_path.stat().st_size
                except Exception as e:
                    errors.append(
                        InspectionError(
                            file=limit_path(rel_path_str),
                            message=redact_secrets(f"Could not stat file: {str(e)}"),
                            error_type="stat_error"
                        )
                    )
                    continue

                if file_size > self.config.max_file_size:
                    errors.append(
                        InspectionError(
                            file=limit_path(rel_path_str),
                            message=f"File size ({file_size} bytes) exceeds safety scan limit ({self.config.max_file_size} bytes)",
                            error_type="file_size_exceeded"
                        )
                    )
                    continue

                # Skip content inspection for binary files
                if category == "binary" or _is_binary_file(file_path):
                    continue

                # Check aggregate bytes limit before reading (Qodo 11)
                remaining_budget = self.config.max_total_bytes - total_bytes_inspected
                if remaining_budget <= 0:
                    errors.append(
                        InspectionError(
                            file=limit_path(rel_path_str),
                            message="Content scan skipped: aggregate size limit exceeded",
                            error_type="total_bytes_exceeded"
                        )
                    )
                    continue

                # Content scanning under bounds (Qodo 11)
                # Read at most min(max_bytes_per_file, remaining_budget) bytes in binary mode rb to prevent encoding overshoot
                max_bytes_to_read = min(self.config.max_bytes_per_file, remaining_budget)

                try:
                    with open(file_path, "rb") as f:
                        raw_bytes = f.read(max_bytes_to_read)

                    actual_bytes_read = len(raw_bytes)
                    total_bytes_inspected += actual_bytes_read

                    # Decode safely ignoring incomplete sequences
                    content_chunk = raw_bytes.decode("utf-8", errors="ignore")

                    lines = content_chunk.splitlines()
                    for line_num, line in enumerate(lines, start=1):
                        if time.perf_counter() - start_time > self.config.max_duration_seconds:
                            break

                        # 1. Security Indicators
                        found_indicators = scan_line_for_indicators(line, line_num, limit_path(rel_path_str))
                        for ind in found_indicators:
                            if len(entry_points) + len(routes) + len(security_indicators) >= self.config.max_findings:
                                if not limit_reached_reason:
                                    limit_reached_reason = f"Findings count limit of {self.config.max_findings} reached"
                                break

                            ind.evidence = limit_text(ind.evidence)
                            security_indicators.append(ind)

                        # 2. HTTP Route candidates
                        found_routes = scan_line_for_routes(line, line_num, limit_path(rel_path_str))
                        for rt in found_routes:
                            if len(entry_points) + len(routes) + len(security_indicators) >= self.config.max_findings:
                                if not limit_reached_reason:
                                    limit_reached_reason = f"Findings count limit of {self.config.max_findings} reached"
                                break

                            rt.evidence = limit_text(rt.evidence)
                            rt.pattern = limit_text(rt.pattern)
                            routes.append(rt)

                        # 3. Entry point candidates
                        ep = scan_line_for_entry_points(line, line_num, limit_path(rel_path_str))
                        if ep:
                            if len(entry_points) + len(routes) + len(security_indicators) >= self.config.max_findings:
                                if not limit_reached_reason:
                                    limit_reached_reason = f"Findings count limit of {self.config.max_findings} reached"
                                break

                            ep.description = limit_text(ep.description)
                            entry_points.append(ep)

                except Exception as e:
                    errors.append(
                        InspectionError(
                            file=limit_path(rel_path_str),
                            message=redact_secrets(f"Error reading file content: {str(e)}"),
                            error_type="read_error"
                        )
                    )

            if limit_reached_reason:
                break

        # If a limit was breached, document it in errors
        if limit_reached_reason:
            errors.append(
                InspectionError(
                    file="",
                    message=limit_reached_reason,
                    error_type="resource_limit_exceeded"
                )
            )
        elif dirs_limit_reached:
            errors.append(
                InspectionError(
                    file="",
                    message=f"Directories limit of {self.config.max_directories} reached",
                    error_type="resource_limit_exceeded"
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
            total_directories=visited_dirs,
            languages=languages,
            frameworks=frameworks,
            ecosystems=sorted(list(ecosystems)),
            config_files=sorted(config_files),
            docker_configs=sorted(docker_configs),
            cicd_configs=sorted(cicd_configs),
            infrastructure_configs=sorted(infrastructure_configs),
            test_files=sorted(test_files)
        )

        report = RepositoryReport(
            repository=summary,
            entry_points=entry_points,
            routes=routes,
            security_indicators=security_indicators,
            manifests=manifests,
            errors=errors
        )

        # 5. Serialized report size check & incremental pruning (Qodo 7)
        try:
            serialized_len = len(report.to_json().encode("utf-8"))
            if serialized_len > self.config.max_serialized_report_bytes:
                # Add report limit warning to errors list first
                report.errors.append(
                    InspectionError(
                        file="",
                        message=f"Report serialized size ({serialized_len} bytes) exceeded limit of {self.config.max_serialized_report_bytes} bytes; findings truncated",
                        error_type="serialized_report_size_exceeded"
                    )
                )

                # Keep pruning findings lists until the size requirement is met or they are empty
                while serialized_len > self.config.max_serialized_report_bytes:
                    pruned = False
                    if report.security_indicators:
                        report.security_indicators.pop()
                        pruned = True
                    elif report.routes:
                        report.routes.pop()
                        pruned = True
                    elif report.entry_points:
                        report.entry_points.pop()
                        pruned = True
                    elif report.manifests:
                        report.manifests.pop()
                        pruned = True
                    elif report.repository.config_files:
                        report.repository.config_files.pop()
                        pruned = True
                    elif report.repository.docker_configs:
                        report.repository.docker_configs.pop()
                        pruned = True
                    elif report.repository.cicd_configs:
                        report.repository.cicd_configs.pop()
                        pruned = True
                    elif report.repository.infrastructure_configs:
                        report.repository.infrastructure_configs.pop()
                        pruned = True
                    elif report.repository.test_files:
                        report.repository.test_files.pop()
                        pruned = True
                    elif report.repository.languages:
                        if report.repository.languages:
                            k = next(iter(report.repository.languages))
                            report.repository.languages.pop(k)
                            pruned = True
                    elif report.repository.frameworks:
                        report.repository.frameworks.pop()
                        pruned = True
                    elif report.repository.ecosystems:
                        report.repository.ecosystems.pop()
                        pruned = True
                    elif len(report.errors) > 1:
                        report.errors.pop(0)
                        pruned = True

                    if not pruned:
                        break

                    serialized_len = len(report.to_json().encode("utf-8"))

                # If still over limit, fallback to deliberately minimal representation
                if serialized_len > self.config.max_serialized_report_bytes:
                    report.security_indicators = []
                    report.routes = []
                    report.entry_points = []
                    report.manifests = []
                    report.repository.config_files = []
                    report.repository.docker_configs = []
                    report.repository.cicd_configs = []
                    report.repository.infrastructure_configs = []
                    report.repository.test_files = []
                    report.repository.languages = {}
                    report.repository.frameworks = []
                    report.repository.ecosystems = []
                    report.errors = [
                        InspectionError(
                            file="",
                            message="Report size exceeded limit. All collections cleared.",
                            error_type="serialized_report_size_exceeded"
                        )
                    ]
        except Exception:
            pass

        return report


def inspect_repository(repository_path: str, config: Optional[InspectionLimits] = None) -> RepositoryReport:
    """Performs codebase static analysis and inspection using the default RepositoryInspectionEngine configuration."""
    engine = RepositoryInspectionEngine(config)
    return engine.inspect(repository_path)


def inspect(repository_path: str, config: Optional[InspectionLimits] = None) -> RepositoryReport:
    """Exposes programmatic API matching inspect_repository."""
    return inspect_repository(repository_path, config)
