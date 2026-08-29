"""Data models for repository inspection reports."""

from dataclasses import dataclass, field
import json
import math
from typing import List, Dict, Any, Optional


@dataclass
class InspectionLimits:
    """Resource limits and configurations for codebase inspection."""
    max_files: int = 1000
    max_directories: int = 100
    max_total_bytes: int = 50 * 1024 * 1024  # 50MB
    max_file_size: int = 2 * 1024 * 1024  # 2MB
    max_bytes_per_file: int = 512 * 1024  # 512KB (for scanning file content)
    max_duration_seconds: float = 30.0
    max_findings: int = 2000
    max_serialized_report_bytes: int = 10 * 1024 * 1024  # 10MB
    max_path_length: int = 1024
    max_text_length: int = 500

    def validate(self) -> None:
        """Validates configuration parameters strictly, rejecting NaN/infinity or non-positive values."""
        if not isinstance(self.max_files, int) or self.max_files <= 0 or isinstance(self.max_files, bool):
            raise ValueError("max_files must be a positive integer")
        if not isinstance(self.max_directories, int) or self.max_directories <= 0 or isinstance(self.max_directories, bool):
            raise ValueError("max_directories must be a positive integer")
        if not isinstance(self.max_total_bytes, int) or self.max_total_bytes <= 0 or isinstance(self.max_total_bytes, bool):
            raise ValueError("max_total_bytes must be a positive integer")
        if not isinstance(self.max_file_size, int) or self.max_file_size <= 0 or isinstance(self.max_file_size, bool):
            raise ValueError("max_file_size must be a positive integer")
        if not isinstance(self.max_bytes_per_file, int) or self.max_bytes_per_file <= 0 or isinstance(self.max_bytes_per_file, bool):
            raise ValueError("max_bytes_per_file must be a positive integer")
        if not isinstance(self.max_duration_seconds, (int, float)) or isinstance(self.max_duration_seconds, bool) or not math.isfinite(self.max_duration_seconds) or self.max_duration_seconds <= 0:
            raise ValueError("max_duration_seconds must be a finite positive number")
        if not isinstance(self.max_findings, int) or self.max_findings <= 0 or isinstance(self.max_findings, bool):
            raise ValueError("max_findings must be a positive integer")
        if not isinstance(self.max_serialized_report_bytes, int) or self.max_serialized_report_bytes <= 0 or isinstance(self.max_serialized_report_bytes, bool):
            raise ValueError("max_serialized_report_bytes must be a positive integer")
        if not isinstance(self.max_path_length, int) or self.max_path_length <= 0 or isinstance(self.max_path_length, bool):
            raise ValueError("max_path_length must be a positive integer")
        if not isinstance(self.max_text_length, int) or self.max_text_length <= 0 or isinstance(self.max_text_length, bool):
            raise ValueError("max_text_length must be a positive integer")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InspectionLimits":
        if not isinstance(data, dict):
            raise ValueError("Data must be a dictionary")
        limits = cls(
            max_files=data.get("max_files", 1000),
            max_directories=data.get("max_directories", 100),
            max_total_bytes=data.get("max_total_bytes", 50 * 1024 * 1024),
            max_file_size=data.get("max_file_size", 2 * 1024 * 1024),
            max_bytes_per_file=data.get("max_bytes_per_file", 512 * 1024),
            max_duration_seconds=data.get("max_duration_seconds", 30.0),
            max_findings=data.get("max_findings", 2000),
            max_serialized_report_bytes=data.get("max_serialized_report_bytes", 10 * 1024 * 1024),
            max_path_length=data.get("max_path_length", 1024),
            max_text_length=data.get("max_text_length", 500)
        )
        limits.validate()
        return limits


@dataclass
class SecurityIndicator:
    """Represents a static indicator or evidence pattern found in codebase."""
    category: str  # e.g., "database", "subprocess", "authentication", "serialization"
    indicator_type: str  # e.g., "subprocess_execution_indicator", "sql_query_indicator"
    file: str
    line: Optional[int] = None
    evidence: str = ""
    confidence: float = 0.8

    def to_dict(self) -> Dict[str, Any]:
        res = {
            "category": self.category,
            "indicator_type": self.indicator_type,
            "file": self.file,
            "evidence": self.evidence,
            "confidence": round(self.confidence, 2)
        }
        if self.line is not None:
            res["line"] = self.line
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityIndicator":
        if not isinstance(data, dict):
            raise ValueError("Data must be a dictionary")
        for field_name in ("category", "indicator_type", "file"):
            if field_name not in data or not isinstance(data[field_name], str):
                raise ValueError(f"Missing or invalid field '{field_name}'")
        line = data.get("line")
        if line is not None and (not isinstance(line, int) or line < 0 or isinstance(line, bool)):
            raise ValueError("Field 'line' must be a non-negative integer or None")
        evidence = data.get("evidence", "")
        if not isinstance(evidence, str):
            raise ValueError("Field 'evidence' must be a string")
        confidence = data.get("confidence", 0.8)
        if not isinstance(confidence, (int, float)):
            raise ValueError("Field 'confidence' must be a float")

        return cls(
            category=data["category"],
            indicator_type=data["indicator_type"],
            file=data["file"],
            line=line,
            evidence=evidence,
            confidence=float(confidence)
        )


@dataclass
class RouteCandidate:
    """Represents an HTTP or API route definition candidate."""
    file: str
    line: int
    method: str  # e.g. "GET", "POST", "ALL"
    pattern: str  # e.g. "/api/users/:id"
    evidence: str
    confidence: float = 0.85

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "method": self.method,
            "pattern": self.pattern,
            "evidence": self.evidence,
            "confidence": round(self.confidence, 2)
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RouteCandidate":
        if not isinstance(data, dict):
            raise ValueError("Data must be a dictionary")
        for field_name in ("file", "method", "pattern", "evidence"):
            if field_name not in data or not isinstance(data[field_name], str):
                raise ValueError(f"Missing or invalid field '{field_name}'")
        if "line" not in data or not isinstance(data["line"], int) or data["line"] <= 0 or isinstance(data["line"], bool):
            raise ValueError("Field 'line' must be a positive integer")
        confidence = data.get("confidence", 0.85)
        if not isinstance(confidence, (int, float)):
            raise ValueError("Field 'confidence' must be a float")

        return cls(
            file=data["file"],
            line=data["line"],
            method=data["method"],
            pattern=data["pattern"],
            evidence=data["evidence"],
            confidence=float(confidence)
        )


@dataclass
class EntryPointCandidate:
    """Represents a potential entry point for application execution."""
    file: str
    type: str  # e.g., "cli", "http_server", "worker", "script", "main"
    description: str
    line: Optional[int] = None
    confidence: float = 0.8

    def to_dict(self) -> Dict[str, Any]:
        res = {
            "file": self.file,
            "type": self.type,
            "description": self.description,
            "confidence": round(self.confidence, 2)
        }
        if self.line is not None:
            res["line"] = self.line
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EntryPointCandidate":
        if not isinstance(data, dict):
            raise ValueError("Data must be a dictionary")
        for field_name in ("file", "type", "description"):
            if field_name not in data or not isinstance(data[field_name], str):
                raise ValueError(f"Missing or invalid field '{field_name}'")
        line = data.get("line")
        if line is not None and (not isinstance(line, int) or line < 0 or isinstance(line, bool)):
            raise ValueError("Field 'line' must be a non-negative integer or None")
        confidence = data.get("confidence", 0.8)
        if not isinstance(confidence, (int, float)):
            raise ValueError("Field 'confidence' must be a float")

        return cls(
            file=data["file"],
            type=data["type"],
            description=data["description"],
            line=line,
            confidence=float(confidence)
        )


@dataclass
class ManifestInfo:
    """Information extracted from package manifests."""
    ecosystem: str  # e.g., "npm", "pip", "cargo", "go"
    file: str
    dependencies: List[str] = field(default_factory=list)
    dev_dependencies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "file": self.file,
            "dependencies": self.dependencies,
            "dev_dependencies": self.dev_dependencies
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ManifestInfo":
        if not isinstance(data, dict):
            raise ValueError("Data must be a dictionary")
        for field_name in ("ecosystem", "file"):
            if field_name not in data or not isinstance(data[field_name], str):
                raise ValueError(f"Missing or invalid field '{field_name}'")
        deps = data.get("dependencies", [])
        if not isinstance(deps, list) or not all(isinstance(x, str) for x in deps):
            raise ValueError("Field 'dependencies' must be a list of strings")
        dev_deps = data.get("dev_dependencies", [])
        if not isinstance(dev_deps, list) or not all(isinstance(x, str) for x in dev_deps):
            raise ValueError("Field 'dev_dependencies' must be a list of strings")

        return cls(
            ecosystem=data["ecosystem"],
            file=data["file"],
            dependencies=deps,
            dev_dependencies=dev_deps
        )


@dataclass
class InspectionError:
    """Error encountered during file inspection."""
    file: str
    message: str
    error_type: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "message": self.message,
            "error_type": self.error_type
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InspectionError":
        if not isinstance(data, dict):
            raise ValueError("Data must be a dictionary")
        for field_name in ("file", "message", "error_type"):
            if field_name not in data or not isinstance(data[field_name], str):
                raise ValueError(f"Missing or invalid field '{field_name}'")
        return cls(
            file=data["file"],
            message=data["message"],
            error_type=data["error_type"]
        )


@dataclass
class RepositorySummary:
    """Summary metrics and detected ecosystems for a repository."""
    root: str
    total_files: int = 0
    total_directories: int = 0
    languages: Dict[str, int] = field(default_factory=dict)  # Language name -> file count
    frameworks: List[str] = field(default_factory=list)
    ecosystems: List[str] = field(default_factory=list)
    config_files: List[str] = field(default_factory=list)
    docker_configs: List[str] = field(default_factory=list)
    cicd_configs: List[str] = field(default_factory=list)
    infrastructure_configs: List[str] = field(default_factory=list)
    test_files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root": self.root,
            "total_files": self.total_files,
            "total_directories": self.total_directories,
            "languages": sorted(list(self.languages.keys())),
            "language_counts": self.languages,
            "frameworks": self.frameworks,
            "ecosystems": self.ecosystems,
            "config_files": self.config_files,
            "docker_configs": self.docker_configs,
            "cicd_configs": self.cicd_configs,
            "infrastructure_configs": self.infrastructure_configs,
            "test_files": self.test_files
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RepositorySummary":
        if not isinstance(data, dict):
            raise ValueError("Data must be a dictionary")
        if "root" not in data or not isinstance(data["root"], str):
            raise ValueError("Missing or invalid field 'root'")
        for field_name in ("total_files", "total_directories"):
            val = data.get(field_name, 0)
            if not isinstance(val, int) or val < 0 or isinstance(val, bool):
                raise ValueError(f"Field '{field_name}' must be a non-negative integer")

        languages = data.get("language_counts", {})
        if not isinstance(languages, dict) or not all(isinstance(k, str) and isinstance(v, int) for k, v in languages.items()):
            raise ValueError("Field 'language_counts' must be a dictionary of string to integer")

        for field_name in ("frameworks", "ecosystems", "config_files", "docker_configs", "cicd_configs", "infrastructure_configs", "test_files"):
            lst = data.get(field_name, [])
            if not isinstance(lst, list) or not all(isinstance(x, str) for x in lst):
                raise ValueError(f"Field '{field_name}' must be a list of strings")

        return cls(
            root=data["root"],
            total_files=data.get("total_files", 0),
            total_directories=data.get("total_directories", 0),
            languages=languages,
            frameworks=data.get("frameworks", []),
            ecosystems=data.get("ecosystems", []),
            config_files=data.get("config_files", []),
            docker_configs=data.get("docker_configs", []),
            cicd_configs=data.get("cicd_configs", []),
            infrastructure_configs=data.get("infrastructure_configs", []),
            test_files=data.get("test_files", [])
        )


@dataclass
class RepositoryReport:
    """Complete structured report resulting from deterministic repository inspection."""
    repository: RepositorySummary
    entry_points: List[EntryPointCandidate] = field(default_factory=list)
    routes: List[RouteCandidate] = field(default_factory=list)
    security_indicators: List[SecurityIndicator] = field(default_factory=list)
    manifests: List[ManifestInfo] = field(default_factory=list)
    errors: List[InspectionError] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repository": self.repository.to_dict(),
            "entry_points": [ep.to_dict() for ep in self.entry_points],
            "routes": [r.to_dict() for r in self.routes],
            "security_indicators": [si.to_dict() for si in self.security_indicators],
            "manifests": [m.to_dict() for m in self.manifests],
            "errors": [e.to_dict() for e in self.errors]
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RepositoryReport":
        if not isinstance(data, dict):
            raise ValueError("Data must be a dictionary")
        if "repository" not in data:
            raise ValueError("Missing 'repository' summary dict")
        repo_summary = RepositorySummary.from_dict(data["repository"])

        eps = [EntryPointCandidate.from_dict(x) for x in data.get("entry_points", [])]
        routes = [RouteCandidate.from_dict(x) for x in data.get("routes", [])]
        indicators = [SecurityIndicator.from_dict(x) for x in data.get("security_indicators", [])]
        manifests = [ManifestInfo.from_dict(x) for x in data.get("manifests", [])]
        errors = [InspectionError.from_dict(x) for x in data.get("errors", [])]

        return cls(
            repository=repo_summary,
            entry_points=eps,
            routes=routes,
            security_indicators=indicators,
            manifests=manifests,
            errors=errors
        )
