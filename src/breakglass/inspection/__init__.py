"""BREAKGLASS Codebase Inspection Package."""

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
from breakglass.inspection.scanner import inspect_repository, RepositoryInspectionEngine, inspect
from breakglass.inspection.detectors import classify_file
from breakglass.inspection.indicators import redact_secrets

__all__ = [
    "inspect_repository",
    "RepositoryInspectionEngine",
    "inspect",
    "InspectionLimits",
    "RepositoryReport",
    "RepositorySummary",
    "SecurityIndicator",
    "RouteCandidate",
    "EntryPointCandidate",
    "ManifestInfo",
    "InspectionError",
    "classify_file",
    "redact_secrets"
]
