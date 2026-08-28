"""Data models for repository inspection reports."""

from dataclasses import dataclass, field, asdict
import json
from typing import List, Dict, Any, Optional, Union


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
