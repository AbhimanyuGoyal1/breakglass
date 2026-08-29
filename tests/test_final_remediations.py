"""Regression tests verifying remediations for Qodo findings and final productization gaps."""

import os
import json
import math
import tempfile
import sys
import unittest
from unittest.mock import MagicMock, patch

from breakglass.inspection.models import (
    RepositoryReport,
    RepositorySummary,
    SecurityIndicator,
    RouteCandidate,
    EntryPointCandidate,
    ManifestInfo,
    InspectionError
)
from breakglass.reasoning.models import SecurityHypothesis, EvidenceReference, ReasoningReport
from breakglass.llm import LLMReasoningEngine, MockLLMClient, GeminiLLMClient
from breakglass.validation import (
    ValidationConfig,
    ValidationEngine,
    TrueForgeSandboxValidator,
    MockSandboxValidator,
    ValidationStatus,
    ValidationResult
)
from breakglass.cli import main


class TestReasoningLLMAugmentation(unittest.TestCase):
    """Test suite verifying that deterministic hypotheses are preserved and augmented, not overwritten."""

    def setUp(self):
        self.summary = RepositorySummary(
            root="/repo",
            total_files=1,
            total_directories=0,
            languages={},
            frameworks=[],
            ecosystems=[],
            config_files=[],
            docker_configs=[],
            cicd_configs=[],
            infrastructure_configs=[],
            test_files=[]
        )
        # Create a single indicator and route
        self.indicator = SecurityIndicator(
            category="subprocess",
            indicator_type="subprocess_execution_indicator",
            file="server.py",
            line=10,
            evidence="subprocess.run"
        )
        self.route = RouteCandidate(
            file="server.py",
            line=5,
            method="GET",
            pattern="/run",
            evidence=""
        )
        self.report = RepositoryReport(
            repository=self.summary,
            routes=[self.route],
            security_indicators=[self.indicator],
            manifests=[ManifestInfo(ecosystem="npm", file="package.json", dependencies=["express"])]
        )
        
        # Create a baseline deterministic hypothesis with canonical ID
        from breakglass.reasoning.models import generate_hypothesis_id
        identity = {
            "category": "command_injection",
            "title": "Deterministic Cmd Injection",
            "description": "Found subprocess",
            "references": [
                {"type": "route", "file": "server.py", "line": 5, "detail": "Route: GET /run"},
                {"type": "security_indicator", "file": "server.py", "line": 10, "detail": "Security indicator: subprocess.run"}
            ]
        }
        self.det_id = generate_hypothesis_id("command_injection", identity, is_llm=False)
        self.det_hyp = SecurityHypothesis(
            id=self.det_id,
            title="Deterministic Cmd Injection",
            description="Found subprocess",
            category="command_injection",
            severity="HIGH",
            confidence=0.8,
            evidence_references=[
                EvidenceReference(type="route", file="server.py", line=5, detail="Route: GET /run"),
                EvidenceReference(type="security_indicator", file="server.py", line=10, detail="Security indicator: subprocess.run")
            ]
        )
        self.det_report = ReasoningReport(hypotheses=[self.det_hyp])

    def test_successful_llm_augmentation(self):
        """Verify successful LLM analysis augments (appends) to deterministic hypotheses."""
        llm_response = {
            "hypotheses": [
                {
                    "id": "HYP-LLM-COMMAND-INJECTION-456",
                    "title": "LLM command injection hypothesis",
                    "description": "LLM reasoned vulnerability",
                    "category": "command_injection",
                    "severity": "CRITICAL",
                    "confidence": 0.9,
                    "rationale": "Uses subprocess inside GET",
                    "evidence_references": [
                        {"type": "route", "file": "server.py", "line": 5, "detail": "Route: GET /run"},
                        {"type": "security_indicator", "file": "server.py", "line": 10, "detail": "Security indicator: subprocess.run"}
                    ]
                }
            ]
        }
        client = MockLLMClient(response_text=json.dumps(llm_response))
        engine = LLMReasoningEngine(client)
        result = engine.analyze(self.report, self.det_report)

        self.assertEqual(result.validation_status, "success")
        self.assertEqual(len(result.hypotheses), 2)
        hyp_ids = [h.id for h in result.hypotheses]
        self.assertIn(self.det_id, hyp_ids)
        llm_hyp = next(h for h in result.hypotheses if h.id.startswith("HYP-LLM-COMMAND-INJECTION-"))
        self.assertIsNotNone(llm_hyp)

    def test_deterministic_hypotheses_survive_api_failure(self):
        """Verify deterministic hypotheses survive when the LLM provider raises an exception."""
        class FailClient(MockLLMClient):
            def generate(self, system_prompt, user_prompt):
                raise RuntimeError("API Rate Limit Exceeded")

        client = FailClient()
        engine = LLMReasoningEngine(client)
        result = engine.analyze(self.report, self.det_report)

        self.assertEqual(result.validation_status, "failed")
        self.assertEqual(len(result.hypotheses), 1)
        self.assertEqual(result.hypotheses[0].id, self.det_id)
        self.assertIn("API Rate Limit Exceeded", result.errors[0])

    def test_deterministic_hypotheses_survive_malformed_llm_output(self):
        """Verify deterministic hypotheses survive when the LLM returns invalid JSON."""
        client = MockLLMClient(response_text="Malformed text response (not JSON)")
        engine = LLMReasoningEngine(client)
        result = engine.analyze(self.report, self.det_report)

        self.assertEqual(result.validation_status, "failed")
        self.assertEqual(len(result.hypotheses), 1)
        self.assertEqual(result.hypotheses[0].id, self.det_id)

    def test_duplicate_hypothesis_handling(self):
        """Verify that identical LLM hypotheses are deduplicated against the deterministic baseline."""
        # LLM returns the exact same hypothesis details as deterministic baseline
        llm_response = {
            "hypotheses": [
                {
                    "id": "HYP-COMMAND-INJECTION-123",
                    "title": "Deterministic Cmd Injection",
                    "description": "Found subprocess",
                    "category": "command_injection",
                    "severity": "HIGH",
                    "confidence": 0.8,
                    "rationale": "Subprocess detail check",
                    "evidence_references": [
                        {"type": "route", "file": "server.py", "line": 5, "detail": "Route: GET /run"},
                        {"type": "security_indicator", "file": "server.py", "line": 10, "detail": "Security indicator: subprocess.run"}
                    ]
                }
            ]
        }
        client = MockLLMClient(response_text=json.dumps(llm_response))
        engine = LLMReasoningEngine(client)
        result = engine.analyze(self.report, self.det_report)

        self.assertEqual(result.validation_status, "success")
        self.assertEqual(len(result.hypotheses), 1)
        self.assertEqual(result.hypotheses[0].id, self.det_id)

    def test_empty_llm_output_preserves_deterministic_hypotheses(self):
        """Verify deterministic hypotheses survive when the LLM returns an empty hypotheses list."""
        llm_response = {"hypotheses": []}
        client = MockLLMClient(response_text=json.dumps(llm_response))
        engine = LLMReasoningEngine(client)
        result = engine.analyze(self.report, self.det_report)

        self.assertEqual(result.validation_status, "success")
        self.assertEqual(len(result.hypotheses), 1)
        self.assertEqual(result.hypotheses[0].id, self.det_id)

    def test_deterministic_hypothesis_evidence_remains_authoritative(self):
        """Verify that deterministic hypothesis evidence references remain authoritative after LLM analysis."""
        llm_response = {"hypotheses": []}
        client = MockLLMClient(response_text=json.dumps(llm_response))
        engine = LLMReasoningEngine(client)
        result = engine.analyze(self.report, self.det_report)

        self.assertEqual(len(result.hypotheses), 1)
        hyp = result.hypotheses[0]
        self.assertEqual(len(hyp.evidence_references), 2)
        self.assertEqual(hyp.evidence_references[0].detail, "Route: GET /run")
        self.assertEqual(hyp.evidence_references[1].detail, "Security indicator: subprocess.run")


class TestValidatorEnvironmentOverrides(unittest.TestCase):
    """Test suite verifying validator arguments override environment variables."""

    def test_explicit_selection_wins_over_environment(self):
        """Verify explicit local_sandbox=False, container_sandbox=False overrides environment variable defaults."""
        env_patches = {
            "TRUEFORGE_LOCAL_SANDBOX": "true",
            "TRUEFORGE_CONTAINER_SANDBOX": "true",
            "TRUEFORGE_API_KEY": "tf_test_key"
        }
        with patch.dict(os.environ, env_patches):
            # Constructor explicitly requests remote API mode (local=False, container=False)
            validator = TrueForgeSandboxValidator(local_sandbox=False, container_sandbox=False)
            self.assertFalse(validator.local_sandbox)
            self.assertFalse(validator.container_sandbox)

    def test_environment_only_defaults_work(self):
        """Verify environment settings are used as fallback defaults when no arguments are provided."""
        env_patches = {
            "TRUEFORGE_LOCAL_SANDBOX": "true",
            "TRUEFORGE_CONTAINER_SANDBOX": "false"
        }
        with patch.dict(os.environ, env_patches):
            validator = TrueForgeSandboxValidator()
            self.assertTrue(validator.local_sandbox)
            self.assertFalse(validator.container_sandbox)


class TestCliValidatorSelectionOverrides(unittest.TestCase):
    """Test suite proving CLI selection wins over ambient environment settings."""

    @patch('breakglass.cli.TrueForgeSandboxValidator')
    @patch('breakglass.cli.inspect_repository')
    @patch('breakglass.cli.DeterministicReasoningEngine')
    def test_cli_local_overrides_env(self, mock_det, mock_inspect, mock_validator_class):
        """CLI local + container/local env enabled -> local"""
        env_patches = {
            "TRUEFORGE_LOCAL_SANDBOX": "true",
            "TRUEFORGE_CONTAINER_SANDBOX": "true",
        }
        mock_inspect.return_value = MagicMock()
        mock_det.return_value.generate_hypotheses.return_value.hypotheses = []
        with patch.dict(os.environ, env_patches):
            with patch('sys.argv', ['breakglass', '.', '--validate', '--validator', 'local']):
                try:
                    main()
                except SystemExit:
                    pass
            mock_validator_class.assert_called_with(local_sandbox=True, container_sandbox=False, timeout_seconds=30.0)

    @patch('breakglass.cli.TrueForgeSandboxValidator')
    @patch('breakglass.cli.inspect_repository')
    @patch('breakglass.cli.DeterministicReasoningEngine')
    def test_cli_container_overrides_env(self, mock_det, mock_inspect, mock_validator_class):
        """CLI container + local env enabled -> container"""
        env_patches = {
            "TRUEFORGE_LOCAL_SANDBOX": "true",
            "TRUEFORGE_CONTAINER_SANDBOX": "false",
        }
        mock_inspect.return_value = MagicMock()
        mock_det.return_value.generate_hypotheses.return_value.hypotheses = []
        with patch.dict(os.environ, env_patches):
            with patch('sys.argv', ['breakglass', '.', '--validate', '--validator', 'container']):
                try:
                    main()
                except SystemExit:
                    pass
            mock_validator_class.assert_called_with(container_sandbox=True, local_sandbox=False, timeout_seconds=30.0)

    @patch('breakglass.cli.TrueForgeSandboxValidator')
    @patch('breakglass.cli.inspect_repository')
    @patch('breakglass.cli.DeterministicReasoningEngine')
    def test_cli_trueforge_overrides_env(self, mock_det, mock_inspect, mock_validator_class):
        """CLI trueforge + both env flags enabled -> TrueForge API orchestration"""
        env_patches = {
            "TRUEFORGE_LOCAL_SANDBOX": "true",
            "TRUEFORGE_CONTAINER_SANDBOX": "true",
            "TRUEFORGE_API_KEY": "test_api_key"
        }
        mock_inspect.return_value = MagicMock()
        mock_det.return_value.generate_hypotheses.return_value.hypotheses = []
        with patch.dict(os.environ, env_patches):
            with patch('sys.argv', ['breakglass', '.', '--validate', '--validator', 'trueforge']):
                try:
                    main()
                except SystemExit:
                    pass
            mock_validator_class.assert_called_with(local_sandbox=False, container_sandbox=False, timeout_seconds=30.0)


class TestCliTimeoutPropagation(unittest.TestCase):
    """Test suite verifying CLI timeout propagation to TrueForgeSandboxValidator"""

    @patch('breakglass.cli.TrueForgeSandboxValidator')
    @patch('breakglass.cli.inspect_repository')
    @patch('breakglass.cli.DeterministicReasoningEngine')
    def test_cli_timeout_propagation_local(self, mock_det, mock_inspect, mock_validator_class):
        """CLI local + timeout specified -> propagates to TrueForgeSandboxValidator"""
        mock_inspect.return_value = MagicMock()
        mock_det.return_value.generate_hypotheses.return_value.hypotheses = []
        with patch('sys.argv', ['breakglass', '.', '--validate', '--validator', 'local', '--timeout', '120.0']):
            try:
                main()
            except SystemExit:
                pass
        mock_validator_class.assert_called_with(local_sandbox=True, container_sandbox=False, timeout_seconds=120.0)

    @patch('breakglass.cli.TrueForgeSandboxValidator')
    @patch('breakglass.cli.inspect_repository')
    @patch('breakglass.cli.DeterministicReasoningEngine')
    def test_cli_timeout_propagation_container(self, mock_det, mock_inspect, mock_validator_class):
        """CLI container + timeout specified -> propagates to TrueForgeSandboxValidator"""
        mock_inspect.return_value = MagicMock()
        mock_det.return_value.generate_hypotheses.return_value.hypotheses = []
        with patch('sys.argv', ['breakglass', '.', '--validate', '--validator', 'container', '--timeout', '120.0']):
            try:
                main()
            except SystemExit:
                pass
        mock_validator_class.assert_called_with(container_sandbox=True, local_sandbox=False, timeout_seconds=120.0)

    @patch('breakglass.cli.TrueForgeSandboxValidator')
    @patch('breakglass.cli.inspect_repository')
    @patch('breakglass.cli.DeterministicReasoningEngine')
    def test_cli_timeout_propagation_trueforge(self, mock_det, mock_inspect, mock_validator_class):
        """CLI trueforge + timeout specified -> propagates to TrueForgeSandboxValidator"""
        mock_inspect.return_value = MagicMock()
        mock_det.return_value.generate_hypotheses.return_value.hypotheses = []
        env_patches = {"TRUEFORGE_API_KEY": "test_key"}
        with patch.dict(os.environ, env_patches):
            with patch('sys.argv', ['breakglass', '.', '--validate', '--validator', 'trueforge', '--timeout', '120.0']):
                try:
                    main()
                except SystemExit:
                    pass
        mock_validator_class.assert_called_with(local_sandbox=False, container_sandbox=False, timeout_seconds=120.0)


class TestGeminiModelConfiguration(unittest.TestCase):
    """Test suite verifying Gemini model configuration and fallback updates."""

    def test_gemini_client_model_fallback_and_env(self):
        """Verify Gemini model name precedence: constructor argument -> env variable -> default."""
        # 1. Default fallback
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test_key"}, clear=True):
            client = GeminiLLMClient()
            self.assertEqual(client.model_name, "gemini-1.5-flash")

        # 2. Environment variable
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test_key", "GEMINI_MODEL": "gemini-2.0-flash-exp"}, clear=True):
            client = GeminiLLMClient()
            self.assertEqual(client.model_name, "gemini-2.0-flash-exp")

        # 3. Explicit constructor override
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test_key", "GEMINI_MODEL": "gemini-2.0-flash-exp"}, clear=True):
            client = GeminiLLMClient(model_name="gemini-1.5-pro-latest")
            self.assertEqual(client.model_name, "gemini-1.5-pro-latest")

    @patch('breakglass.cli.GeminiLLMClient')
    @patch('breakglass.cli.inspect_repository')
    @patch('breakglass.cli.DeterministicReasoningEngine')
    @patch('breakglass.cli.LLMReasoningEngine')
    def test_cli_gemini_model_propagation(self, mock_llm_engine, mock_det, mock_inspect, mock_client_class):
        """CLI model option propagates to GeminiLLMClient constructor"""
        mock_inspect.return_value = MagicMock()
        mock_det.return_value.generate_hypotheses.return_value.hypotheses = []

        # Test case 1: Explicit --gemini-model overrides
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test_key"}, clear=True):
            with patch('sys.argv', ['breakglass', '.', '--llm', '--gemini-model', 'gemini-2.5-pro']):
                try:
                    main()
                except SystemExit:
                    pass
            mock_client_class.assert_called_with(model_name='gemini-2.5-pro')

        # Test case 2: Default when not specified falls back to None in constructor (delegating to client class default/env)
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test_key"}, clear=True):
            with patch('sys.argv', ['breakglass', '.', '--llm']):
                try:
                    main()
                except SystemExit:
                    pass
            mock_client_class.assert_called_with(model_name=None)


class TestTimeoutPropagation(unittest.TestCase):
    """Test suite verifying CLI and configuration timeouts propagate correctly."""

    def test_timeout_reaches_validator(self):
        """Verify ValidationEngine config timeout overrides/updates validator timeout_seconds."""
        validator = TrueForgeSandboxValidator(local_sandbox=True, timeout_seconds=10.0)
        config = ValidationConfig(timeout_seconds=45.0)
        engine = ValidationEngine(validator, config)

        # Assert validator is synchronized at constructor
        self.assertEqual(validator.timeout_seconds, 45.0)

        # Assert validator is synchronized at validation invocation
        config.timeout_seconds = 75.0
        engine.validate_hypotheses([], RepositoryReport(repository=RepositorySummary(root="/repo")))
        self.assertEqual(validator.timeout_seconds, 75.0)

    def test_invalid_timeout_rejected(self):
        """Verify invalid timeout configuration values raise ValueError."""
        with self.assertRaises(ValueError):
            ValidationConfig(timeout_seconds=-10.0).validate()
        with self.assertRaises(ValueError):
            ValidationConfig(timeout_seconds=float('inf')).validate()


class TestExportIntegrity(unittest.TestCase):
    """Test suite verifying JSON report export preserves manifests, errors, and indicators."""

    def test_report_export_complete_fields(self):
        """Verify output JSON contains full canonical inspection report data and remains serializable."""
        # 1. Build Representative Report
        summary = RepositorySummary(
            root="/repo",
            total_files=5,
            total_directories=2,
            languages={"Python": 100},
            frameworks=["FastAPI"],
            ecosystems=["pip"],
            config_files=[],
            docker_configs=[],
            cicd_configs=[],
            infrastructure_configs=[],
            test_files=[]
        )
        indicator = SecurityIndicator(
            category="subprocess",
            indicator_type="subprocess_execution_indicator",
            file="main.py",
            line=12,
            evidence="subprocess.run"
        )
        route = RouteCandidate(
            file="main.py",
            line=10,
            method="POST",
            pattern="/validate",
            evidence=""
        )
        manifest = ManifestInfo(
            ecosystem="pip",
            file="requirements.txt",
            dependencies=["fastapi", "uvicorn"]
        )
        err = InspectionError(
            file="broken.py",
            message="UnicodeDecodeError",
            error_type="decode_error"
        )
        report = RepositoryReport(
            repository=summary,
            routes=[route],
            security_indicators=[indicator],
            manifests=[manifest],
            errors=[err]
        )

        # 2. Build Hypotheses & Validation Results
        hyp = SecurityHypothesis(
            id="HYP-COMMAND-INJECTION-EXMAPLE",
            title="Command Injection",
            description="Found query indicator",
            category="command_injection",
            severity="CRITICAL",
            confidence=0.95,
            evidence_references=[
                EvidenceReference(type="route", file="main.py", line=10, detail="Route: POST /validate"),
                EvidenceReference(type="security_indicator", file="main.py", line=12, detail="Security indicator: subprocess.run")
            ]
        )
        result = ValidationResult(
            hypothesis_id="HYP-COMMAND-INJECTION-EXMAPLE",
            status=ValidationStatus.VALIDATED,
            attempted=True,
            confirmed=True,
            evidence="Confirmed manually in sandbox",
            duration=1.24
        )

        # 3. Simulate CLI Serialization block
        output_data = {
            "report": report.to_dict(),
            "repository": report.repository.to_dict(),
            "inspection_summary": {
                "security_indicators": len(report.security_indicators),
                "routes": len(report.routes),
                "entry_points": len(report.entry_points)
            },
            "hypotheses": [hyp.to_dict()],
            "validation_results": [result.to_dict()]
        }

        # Verify JSON serializability
        serialized = json.dumps(output_data, indent=2)
        data = json.loads(serialized)

        # 4. Assertions on Exported Content
        self.assertIn("report", data)
        report_data = data["report"]
        self.assertIn("repository", report_data)
        self.assertIn("routes", report_data)
        self.assertIn("security_indicators", report_data)
        self.assertIn("manifests", report_data)
        self.assertIn("errors", report_data)

        # Assert manifests survive
        self.assertEqual(len(report_data["manifests"]), 1)
        self.assertEqual(report_data["manifests"][0]["ecosystem"], "pip")

        # Assert errors survive
        self.assertEqual(len(report_data["errors"]), 1)
        self.assertEqual(report_data["errors"][0]["file"], "broken.py")

        # Assert hypotheses can resolve references against report
        exported_hyp = data["hypotheses"][0]
        for ref in exported_hyp["evidence_references"]:
            ref_type = ref["type"]
            ref_file = ref["file"]
            ref_line = ref["line"]
            
            # Resolve against serialized report
            resolved = False
            if ref_type == "route":
                for r in report_data["routes"]:
                    if r["file"] == ref_file and r["line"] == ref_line:
                        resolved = True
            elif ref_type == "security_indicator":
                for ind in report_data["security_indicators"]:
                    if ind["file"] == ref_file and ind["line"] == ref_line:
                        resolved = True
            self.assertTrue(resolved, f"Reference {ref_type} at {ref_file}:{ref_line} failed to resolve")
