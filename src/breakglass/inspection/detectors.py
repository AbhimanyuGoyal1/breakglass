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
    """Detects programming language from file extension or name."""
    filename_lower = file_path.name.lower()
    if filename_lower in FILENAME_LANGUAGE_MAP:
        return FILENAME_LANGUAGE_MAP[filename_lower]

    ext = file_path.suffix.lower()
    return EXTENSION_LANGUAGE_MAP.get(ext)


def parse_manifest_file(file_path: Path, rel_path_str: str) -> Optional[ManifestInfo]:
    """Safely parses package/dependency manifest files."""
    name = file_path.name.lower()
    try:
        if name == "package.json":
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            data = json.loads(content)
            deps = list(data.get("dependencies", {}).keys())
            dev_deps = list(data.get("devDependencies", {}).keys())
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
            # Primitive regex parsing to avoid needing toml library dependency
            deps = []
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
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("//") and not line.startswith("module") and not line.startswith("go "):
                    parts = line.split()
                    if len(parts) >= 1 and "/" in parts[0]:
                        deps.append(parts[0])
            return ManifestInfo(
                ecosystem="go",
                file=rel_path_str,
                dependencies=deps
            )
    except Exception:
        pass
    return None


def detect_frameworks_from_manifests(manifests: List[ManifestInfo]) -> List[str]:
    """Detects framework names from parsed manifest dependencies."""
    detected = set()
    for manifest in manifests:
        all_deps = manifest.dependencies + manifest.dev_dependencies
        for dep in all_deps:
            dep_lower = dep.lower()
            for key, framework in FRAMEWORK_INDICATORS.items():
                if key in dep_lower:
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

    # CI/CD
    if ".github/workflows" in path_lower or ".gitlab-ci.yml" in filename or filename in ("jenkinsfile", ".travis.yml", "bitbucket-pipelines.yml", ".circleci/config.yml"):
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
