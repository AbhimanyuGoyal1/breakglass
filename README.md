# BREAKGLASS

Autonomous red-team security assessment agent designed for safe repository analysis and security hypothesis validation.

> Built for The Agent Harness Hackathon using TrueForge.

---

## Status

🚧 **Milestone 1 Complete**: Deterministic Codebase Inspection Foundation implemented.

BREAKGLASS can statically inspect unfamiliar software repositories without running application code or executing untrusted scripts, generating structured metadata, ecosystem maps, route candidates, entry points, and security-relevant indicators.

---

## Key Principles & Safety Controls

1. **Evidence over Verdicts**: The inspection layer extracts static indicators (e.g. `subprocess_execution_indicator`, `database_query_indicator`). It does **not** declare vulnerabilities or create false alarms.
2. **Safe Execution**: Does not execute repository code, invoke package managers, or run target scripts.
3. **Boundary Enforced**: Skips directory traversal outside the repository root and rejects out-of-bounds symlinks.
4. **Resilient**: Gracefully handles unreadable, malformed, or large files without halting analysis.

---

## Architecture

The intended BREAKGLASS workflow is:

```
Target Repository
      │
      ▼
Repository Ingestion & Path Controls
      │
      ▼
Codebase Inspection (Deterministic Foundation)
      │
      ▼
Repository / Ecosystem / Route / Indicator Map
      │
      ▼
Agent Reasoning Layer (LLM Security Hypotheses)
      │
      ▼
Sandboxed Validation (TrueForge Execution)
      │
      ▼
Evidence + Confidence Score
      │
      ▼
Human Approval Gate
      │
      ▼
Controlled Action
```

---

## How to Run Inspection

### Programmatic Python API

```python
from breakglass import inspect_repository

# Inspect a local codebase
report = inspect_repository("/path/to/target/repository")

# Access summary metrics
print(f"Total files: {report.repository.total_files}")
print(f"Languages: {report.repository.languages}")
print(f"Frameworks: {report.repository.frameworks}")

# Access security indicators
for indicator in report.security_indicators:
    print(f"[{indicator.category}] {indicator.file}:{indicator.line} -> {indicator.indicator_type}")

# Export structured report to JSON
json_output = report.to_json(indent=2)
```

---

## Running Tests

Run the test suite using Python's standard `unittest` framework:

```bash
$env:PYTHONPATH="src"; python -m unittest discover -s tests
```

Or with `pytest`:

```bash
pytest tests/
```

---

## Limitations

- Milestone 1 relies on deterministic static analysis and regex heuristics for language, route, and indicator detection.
- TrueForge sandbox integration and LLM hypothesis formation will be added in subsequent milestones.
