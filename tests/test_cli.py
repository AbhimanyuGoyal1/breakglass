"""End-to-end integration and sanity tests for the BREAKGLASS command-line interface."""

import json
import os
import subprocess
import tempfile
import sys
import unittest


class TestCommandLineInterface(unittest.TestCase):
    """End-to-end test cases for breakglass CLI script and options."""

    def setUp(self):
        self.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.sample_repo = os.path.join(self.repo_root, "tests", "fixtures", "sample_repo")

    def run_cli(self, args):
        """Runs the CLI module using python -m breakglass and returns output/exit code."""
        cmd = [sys.executable, "-m", "breakglass"] + args
        proc = subprocess.run(
            cmd,
            cwd=self.repo_root,
            capture_output=True,
            text=True
        )
        return proc.returncode, proc.stdout, proc.stderr

    def test_cli_help(self):
        """Verify breakglass CLI help description prints correctly."""
        code, stdout, stderr = self.run_cli(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("BREAKGLASS: Autonomous red-team security", stdout)
        self.assertIn("target_path", stdout)

    def test_cli_basic_inspection_and_hypotheses(self):
        """Verify basic run generates and prints correct inspection metrics and hypotheses."""
        code, stdout, stderr = self.run_cli([self.sample_repo])
        self.assertEqual(code, 0)
        self.assertIn("REPOSITORY INGESTION & INSPECTION SUMMARY", stdout)
        self.assertIn("Files: 8 | Directories: 4", stdout)
        self.assertIn("SECURITY HYPOTHESES GENERATED", stdout)
        self.assertIn("Total Hypotheses: 10", stdout)
        self.assertIn("[HYP-COMMAND-INJECTION", stdout)

    def test_cli_validation_enabled(self):
        """Verify basic run with --validate successfully prints validation results."""
        code, stdout, stderr = self.run_cli([self.sample_repo, "--validate", "--validator", "mock"])
        self.assertEqual(code, 0)
        self.assertIn("SANDBOX HYPOTHESIS VALIDATION RESULTS", stdout)
        self.assertIn("Status: NOT_CONFIRMED", stdout)
        self.assertIn("Attempted: True | Confirmed: False", stdout)

    def test_cli_output_export_json(self):
        """Verify CLI exports structured assessment JSON correctly when --output is specified."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "assessment_report.json")
            code, stdout, stderr = self.run_cli([
                self.sample_repo,
                "--validate",
                "--output", out_file
            ])
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(out_file))

            with open(out_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.assertIn("repository", data)
            self.assertEqual(data["repository"]["total_files"], 8)
            self.assertIn("inspection_summary", data)
            self.assertEqual(data["inspection_summary"]["security_indicators"], 6)
            self.assertIn("hypotheses", data)
            self.assertEqual(len(data["hypotheses"]), 10)
            self.assertIn("validation_results", data)
            self.assertEqual(len(data["validation_results"]), 10)

    def test_cli_invalid_path_fails(self):
        """Verify providing a non-existent path results in failure exit code and error message."""
        code, stdout, stderr = self.run_cli(["/nonexistent/directory/path/here"])
        self.assertEqual(code, 1)
        self.assertIn("Error: Target path does not exist", stderr)
