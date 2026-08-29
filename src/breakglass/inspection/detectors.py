"""Detection logic for languages, frameworks, manifests, entry points, and configs."""

from pathlib import Path
import json
import re
from typing import Dict, List, Set, Tuple, Optional, Any
from breakglass.inspection.models import ManifestInfo, EntryPointCandidate


# Extension to Language mapping
EXTENSION_LANGUAGE_MAP: Dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".c": "C",
    ".h": "C/C++ Header",
    ".cpp": "C++",
    ".hpp": "C++",
    ".cc": "C++",
    ".cs": "C#",
    ".php": "PHP",
    ".rb": "Ruby",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".ps1": "PowerShell",
    ".sql": "SQL",
    ".html": "HTML",
    ".css": "CSS",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".toml": "TOML",
    ".xml": "XML",
    ".md": "Markdown",
    ".kt": "Kotlin",
    ".swift": "Swift",
    ".scala": "Scala",
    ".dockerfile": "Dockerfile"
}

FILENAME_LANGUAGE_MAP: Dict[str, str] = {
    "dockerfile": "Dockerfile",
    "makefile": "Makefile",
    "rakefile": "Ruby",
    "gemfile": "Ruby",
    "cmakelists.txt": "CMake"
}

# Known framework indicator dependencies / symbols
FRAMEWORK_INDICATORS: Dict[str, str] = {
    "express": "Express",
    "fastapi": "FastAPI",
    "flask": "Flask",
    "django": "Django",
    "next": "Next.js",
    "react": "React",
    "vue": "Vue.js",
    "angular": "Angular",
    "spring-boot": "Spring Boot",
    "org.springframework": "Spring",
    "github.com/gin-gonic/gin": "Gin",
    "github.com/labstack/echo": "Echo",
    "rails": "Ruby on Rails",
    "laravel/framework": "Laravel",
    "actix-web": "Actix Web",
    "tokio": "Tokio"
}


def detect_language(file_path: Path) -> Optional[str]:
    """Detects programming language from shebang or file extension/name."""
    # 1. Try shebang detection first
    try:
        if file_path.is_file() and not file_path.is_symlink():
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                first_line = f.readline()
                if first_line.startswith("#!"):
                    first_line_lower = first_line.lower()
                    if "python" in first_line_lower:
                        return "Python"
                    elif "node" in first_line_lower:
                        return "JavaScript"
                    elif "bash" in first_line_lower or "zsh" in first_line_lower or "sh" in first_line_lower or first_line_lower.endswith("/sh") or first_line_lower.endswith("/bash") or first_line_lower.endswith("/zsh"):
                        return "Shell"
                    elif "ruby" in first_line_lower:
                        return "Ruby"
                    elif "perl" in first_line_lower:
                        return "Perl"
                    elif "php" in first_line_lower:
                        return "PHP"
    except Exception:
        pass

    # 2. Fall back to filename/extension mapping
    filename_lower = file_path.name.lower()
    if filename_lower in FILENAME_LANGUAGE_MAP:
        return FILENAME_LANGUAGE_MAP[filename_lower]

    ext = file_path.suffix.lower()
    return EXTENSION_LANGUAGE_MAP.get(ext)


def parse_manifest_file(file_path: Path, rel_path_str: str) -> Optional[ManifestInfo]:
    """Safely parses package/dependency manifest files."""
    name = file_path.name.lower()
    if name == "package.json":
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(content)
        deps = list(data.get("dependencies", {}).keys()) if isinstance(data.get("dependencies"), dict) else []
        dev_deps = list(data.get("devDependencies", {}).keys()) if isinstance(data.get("devDependencies"), dict) else []
        return ManifestInfo(
            ecosystem="npm",
            file=rel_path_str,
            dependencies=deps,
            dev_dependencies=dev_deps
        )
    elif name in ("requirements.txt", "requirements-dev.txt"):
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("-"):
                # Extract package name before any operator (==, >=, etc.)
                pkg = re.split(r"[=<>;~\s]", line)[0].strip()
                if pkg:
                    deps.append(pkg)
        return ManifestInfo(
            ecosystem="pip",
            file=rel_path_str,
            dependencies=deps
        )
    elif name == "pyproject.toml":
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        deps = []
        try:
            import tomllib
            data = tomllib.loads(content)
            # PEP 621 [project] dependencies
            proj_deps = data.get("project", {}).get("dependencies", [])
            for d in proj_deps:
                pkg = re.split(r"[=<>;~\s\[]", d)[0].strip()
                if pkg:
                    deps.append(pkg)
            # Poetry [tool.poetry.dependencies]
            poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
            for k in poetry_deps.keys():
                if k.lower() != "python":
                    deps.append(k)
        except Exception:
            # Fallback parsing
            in_deps = False
            for line in content.splitlines():
                if "dependencies" in line:
                    in_deps = True
                    continue
                if in_deps:
                    if line.startswith("["):
                        in_deps = False
                        continue
                    m = re.match(r"""^\s*["']?([a-zA-Z0-9_\-]+)["']?\s*=""", line)
                    if m:
                        deps.append(m.group(1))
                    else:
                        m_arr = re.match(r"""^\s*["']([a-zA-Z0-9_\-]+).*?["']""", line)
                        if m_arr:
                            deps.append(m_arr.group(1))
        return ManifestInfo(
            ecosystem="pip/poetry/flit",
            file=rel_path_str,
            dependencies=deps
        )
    elif name == "cargo.toml":
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        deps = []
        in_deps = False
        for line in content.splitlines():
            if "[dependencies]" in line or "[dev-dependencies]" in line:
                in_deps = True
                continue
            if in_deps:
                if line.startswith("["):
                    in_deps = False
                    continue
                m = re.match(r"^\s*([a-zA-Z0-9_\-]+)\s*=", line)
                if m:
                    deps.append(m.group(1))
        return ManifestInfo(
            ecosystem="cargo",
            file=rel_path_str,
            dependencies=deps
        )
    elif name == "go.mod":
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        deps = []
        in_require_block = False
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            if line.startswith("replace") or line.startswith("exclude"):
                continue
            if line == "require (":
                in_require_block = True
                continue
            if in_require_block:
                if line == ")":
                    in_require_block = False
                    continue
                parts = line.split()
                if parts and "/" in parts[0]:
                    deps.append(parts[0])
            elif line.startswith("require "):
                parts = line.split()
                if len(parts) >= 2 and "/" in parts[1]:
                    deps.append(parts[1])
        return ManifestInfo(
            ecosystem="go",
            file=rel_path_str,
            dependencies=deps
        )
    return None


def detect_frameworks_from_manifests(manifests: List[ManifestInfo]) -> List[str]:
    """Detects framework names from parsed manifest dependencies strictly without false positives."""
    detected = set()
    for manifest in manifests:
        all_deps = manifest.dependencies + manifest.dev_dependencies
        for dep in all_deps:
            dep_lower = dep.lower()
            for key, framework in FRAMEWORK_INDICATORS.items():
                # Strict identifier comparison (exact match or module path prefix)
                if dep_lower == key or dep_lower.startswith(key + "/") or dep_lower.startswith(key + "-"):
                    detected.add(framework)
    return sorted(list(detected))


def check_is_config_or_infra(rel_path_str: str) -> Dict[str, bool]:
    """Classifies file paths into configuration, docker, cicd, or infrastructure categories."""
    path_lower = rel_path_str.lower().replace("\\", "/")
    filename = Path(path_lower).name

    is_docker = False
    is_cicd = False
    is_infra = False
    is_config = False

    # Docker / Container
    if "dockerfile" in filename or "containerfile" in filename or filename in ("docker-compose.yml", "docker-compose.yaml", ".dockerignore"):
        is_docker = True

    # CI/CD - use path_lower for directory-qualified configs like .circleci/config.yml
    if ".github/workflows" in path_lower or ".gitlab-ci.yml" in filename or ".circleci/config.yml" in path_lower or filename in ("jenkinsfile", ".travis.yml", "bitbucket-pipelines.yml"):
        is_cicd = True

    # Infrastructure
    if filename.endswith(".tf") or filename in ("serverless.yml", "serverless.yaml", "pulumi.yaml", "cdk.json") or "kubernetes/" in path_lower or "helm/" in path_lower:
        is_infra = True

    # Configuration files
    if filename.endswith((".json", ".toml", ".yaml", ".yml", ".ini", ".env", ".env.example", ".xml")) or filename in ("config.py", "settings.py", "webpack.config.js"):
        is_config = True

    return {
        "is_docker": is_docker,
        "is_cicd": is_cicd,
        "is_infra": is_infra,
        "is_config": is_config
    }


def scan_line_for_entry_points(
    line: str,
    line_num: int,
    file_rel_path: str
) -> Optional[EntryPointCandidate]:
    """Scans code lines for explicit entry point constructs."""
    # Python __main__
    if 'if __name__ == "__main__":' in line or "if __name__ == '__main__':" in line:
        return EntryPointCandidate(
            file=file_rel_path,
            type="cli/script",
            description="Python __main__ execution block",
            line=line_num,
            confidence=0.95
        )

    # Go func main()
    if re.search(r"^\s*func\s+main\s*\(\s*\)", line):
        return EntryPointCandidate(
            file=file_rel_path,
            type="main",
            description="Go main entry point function",
            line=line_num,
            confidence=0.95
        )

    # Rust fn main()
    if re.search(r"^\s*fn\s+main\s*\(\s*\)", line):
        return EntryPointCandidate(
            file=file_rel_path,
            type="main",
            description="Rust main entry point function",
            line=line_num,
            confidence=0.95
        )

    # Java main method
    if "public static void main" in line:
        return EntryPointCandidate(
            file=file_rel_path,
            type="main",
            description="Java public static void main entry point",
            line=line_num,
            confidence=0.95
        )

    return None


def classify_file(filename: str, rel_path_str: str) -> str:
    """Classifies a file into one of the BREAKGLASS standard categories."""
    filename_lower = filename.lower()
    path_lower = rel_path_str.lower().replace("\\", "/")

    # 1. Lock files
    if filename_lower in (
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock",
        "go.sum", "composer.lock", "gemfile.lock", "pubspec.lock", "poetry.lock"
    ):
        return "lock_files"

    # 2. Dependency manifests
    if filename_lower in (
        "package.json", "requirements.txt", "requirements-dev.txt", "pyproject.toml",
        "pipfile", "pom.xml", "build.gradle", "cargo.toml", "go.mod",
        "composer.json", "gemfile", "pubspec.yaml"
    ):
        return "dependency_manifests"

    # 3. Docker / Infrastructure / Configuration-as-Code
    is_docker = ("dockerfile" in filename_lower or "containerfile" in filename_lower or
                 filename_lower in ("docker-compose.yml", "docker-compose.yaml", ".dockerignore"))
    is_infra = (filename_lower.endswith(".tf") or
                filename_lower in ("serverless.yml", "serverless.yaml", "pulumi.yaml", "cdk.json") or
                "kubernetes/" in path_lower or "helm/" in path_lower)
    if is_docker or is_infra:
        return "infrastructure_config"

    # 4. CI/CD configuration
    if (".github/workflows" in path_lower or ".gitlab-ci.yml" in filename_lower or
        ".circleci/config.yml" in path_lower or filename_lower in ("jenkinsfile", ".travis.yml", "bitbucket-pipelines.yml")):
        return "cicd_config"

    # 5. Tests
    if (filename_lower.startswith("test_") or
        filename_lower.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts", "_test.go", "test.rs", "test.java")) or
        "/tests/" in path_lower or "/test/" in path_lower or "/__tests__/" in path_lower):
        return "tests"

    # 6. Shell / Scripts
    if filename_lower.endswith((".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd")):
        return "shell_scripts"

    # 7. Source Code
    ext = Path(filename_lower).suffix
    if ext in (
        ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java",
        ".c", ".h", ".cpp", ".hpp", ".cc", ".cs", ".php", ".rb",
        ".kt", ".swift", ".scala"
    ):
        return "source_code"

    # 8. Configuration files
    if filename_lower.endswith((".json", ".toml", ".yaml", ".yml", ".ini", ".env", ".env.example", ".xml")) or filename_lower in ("config.py", "settings.py", "webpack.config.js"):
        return "configuration"

    # 9. Documentation
    if filename_lower.endswith((".md", ".txt", ".rst", ".adoc")):
        return "documentation"

    # 10. Generated / Minified
    if filename_lower.endswith((".min.js", ".min.css")) or ".generated." in filename_lower:
        return "generated_minified"

    # 11. Binary files (heuristic extension)
    if filename_lower.endswith((".pyc", ".exe", ".dll", ".so", ".a", ".o", ".bin", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar.gz", ".tgz")):
        return "binary"

    return "unknown"
