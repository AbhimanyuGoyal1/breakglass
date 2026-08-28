"""Unit tests for BREAKGLASS codebase inspection foundation scanner."""

import os
import unittest
import tempfile
from pathlib import Path

from breakglass.inspection import inspect_repository, RepositoryReport


FIXTURE_REPO_PATH = Path(__file__).parent / "fixtures" / "sample_repo"


class TestCodebaseScanner(unittest.TestCase):
    """Test suite for deterministic codebase scanner."""

    def test_invalid_repository_path(self):
        """Test that invalid or non-existent paths raise ValueError."""
        with self.assertRaises(ValueError):
            inspect_repository("non_existent_path_xyz_123")

        # Pass a file instead of directory
        file_path = FIXTURE_REPO_PATH / "package.json"
        with self.assertRaises(ValueError):
            inspect_repository(str(file_path))

    def test_repository_discovery_and_languages(self):
        """Test basic file discovery, directory counting, and language classification."""
        report = inspect_repository(str(FIXTURE_REPO_PATH))

        self.assertIsInstance(report, RepositoryReport)
        self.assertGreater(report.repository.total_files, 0)
        self.assertIn("Python", report.repository.languages)
        self.assertIn("JavaScript", report.repository.languages)
        self.assertIn("Go", report.repository.languages)
        self.assertIn("Dockerfile", report.repository.languages)

    def test_ignored_directories(self):
        """Test that default ignored directories (like node_modules) are excluded."""
        report = inspect_repository(str(FIXTURE_REPO_PATH))

        scanned_files = [
            ind.file for ind in report.security_indicators
        ] + report.repository.config_files + report.repository.docker_configs

        for f in scanned_files:
            self.assertNotIn("node_modules", f)
            self.assertNotIn(".venv", f)

    def test_manifest_and_framework_detection(self):
        """Test manifest parsing (package.json, requirements.txt) and framework detection."""
        report = inspect_repository(str(FIXTURE_REPO_PATH))

        ecosystems = report.repository.ecosystems
        self.assertIn("npm", ecosystems)
        self.assertIn("pip", ecosystems)

        manifest_files = [m.file for m in report.manifests]
        self.assertTrue(any("package.json" in m for m in manifest_files))
        self.assertTrue(any("requirements.txt" in m for m in manifest_files))

        frameworks = report.repository.frameworks
        self.assertIn("Express", frameworks)
        self.assertIn("FastAPI", frameworks)

    def test_security_indicator_detection(self):
        """Test that security indicators (subprocess, database, cloud_sdk) are detected correctly."""
        report = inspect_repository(str(FIXTURE_REPO_PATH))

        categories = {ind.category for ind in report.security_indicators}
        self.assertIn("subprocess", categories)
        self.assertIn("database", categories)
        self.assertIn("cloud_sdk", categories)

        subprocess_inds = [ind for ind in report.security_indicators if ind.category == "subprocess"]
        self.assertGreaterEqual(len(subprocess_inds), 1)
        self.assertEqual(subprocess_inds[0].indicator_type, "subprocess_execution_indicator")

    def test_route_and_entry_point_candidates(self):
        """Test HTTP route candidate detection and application entry point candidates."""
        report = inspect_repository(str(FIXTURE_REPO_PATH))

        route_patterns = [r.pattern for r in report.routes]
        self.assertTrue(any("/health" in p for p in route_patterns))
        self.assertTrue(any("/run-task" in p for p in route_patterns))
        self.assertTrue(any("/api/v1/users" in p for p in route_patterns))
        self.assertTrue(any("/status" in p for p in route_patterns))

        entry_types = {ep.type for ep in report.entry_points}
        self.assertTrue("cli/script" in entry_types or "main" in entry_types)

    def test_docker_and_cicd_configs(self):
        """Test Docker and CI/CD configuration discovery."""
        report = inspect_repository(str(FIXTURE_REPO_PATH))

        self.assertTrue(any("Dockerfile" in d for d in report.repository.docker_configs))
        self.assertTrue(any("ci.yml" in c for c in report.repository.cicd_configs))

    def test_deterministic_output(self):
        """Test that inspecting the repository produces byte-for-byte identical JSON and strictly sorted collections."""
        report1 = inspect_repository(str(FIXTURE_REPO_PATH))
        report2 = inspect_repository(str(FIXTURE_REPO_PATH))

        dict1 = report1.to_dict()
        dict2 = report2.to_dict()

        self.assertEqual(dict1, dict2)
        self.assertEqual(report1.to_json(), report2.to_json())

        # Verify strict deterministic field sorting of collections
        ep_keys = [(x.file, x.line or 0, x.type, x.description) for x in report1.entry_points]
        self.assertEqual(ep_keys, sorted(ep_keys))

        route_keys = [(x.file, x.line, x.method, x.pattern) for x in report1.routes]
        self.assertEqual(route_keys, sorted(route_keys))

        indicator_keys = [(x.file, x.line or 0, x.category, x.indicator_type, x.evidence) for x in report1.security_indicators]
        self.assertEqual(indicator_keys, sorted(indicator_keys))

        manifest_keys = [(x.file, x.ecosystem) for x in report1.manifests]
        self.assertEqual(manifest_keys, sorted(manifest_keys))

        error_keys = [(x.file, x.error_type, x.message) for x in report1.errors]
        self.assertEqual(error_keys, sorted(error_keys))

    def test_large_file_safety_handling(self):
        """Test that files exceeding safety byte limits are logged as errors rather than crashing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            large_file = Path(temp_dir) / "huge_data.py"
            # Create 3MB file
            with open(large_file, "wb") as f:
                f.write(b"# huge file content\n" * 200000)

            report = inspect_repository(temp_dir)
            error_files = [e.file for e in report.errors]
            self.assertIn("huge_data.py", error_files)
            self.assertTrue(any(e.error_type == "file_size_exceeded" for e in report.errors))

    def test_symlink_out_of_bounds_prevention(self):
        """Test that symlinks pointing outside repository root are safely caught and not traversed."""
        with tempfile.TemporaryDirectory() as external_dir:
            ext_file = Path(external_dir) / "secret.txt"
            ext_file.write_text("sensitive outside data")

            with tempfile.TemporaryDirectory() as repo_dir:
                repo_path = Path(repo_dir)
                (repo_path / "valid.py").write_text("print('hello')")
                symlink_file = repo_path / "external_link.py"

                try:
                    os.symlink(ext_file, symlink_file)
                except (OSError, NotImplementedError):
                    # Skip test if symlink creation is not permitted on host OS
                    return

                report = inspect_repository(str(repo_path))
                error_types = [e.error_type for e in report.errors]
                self.assertIn("symlink_out_of_bounds", error_types)
                # Ensure external file contents were NOT scanned
                scanned_files = [i.file for i in report.security_indicators]
                self.assertNotIn("external_link.py", scanned_files)

    def test_gitignore_precision_matching(self):
        """Test that gitignore rules do not accidentally exclude valid source files containing pattern substrings."""
        with tempfile.TemporaryDirectory() as repo_dir:
            repo_path = Path(repo_dir)
            (repo_path / ".gitignore").write_text("dist\n*.log\n")

            # Legitimate file with "dist" in name
            legit_dir = repo_path / "src" / "mydistribution"
            legit_dir.mkdir(parents=True)
            legit_file = legit_dir / "app.py"
            legit_file.write_text("import os\nos.system('echo test')\n")

            # Actual dist directory
            ignored_dir = repo_path / "dist"
            ignored_dir.mkdir()
            (ignored_dir / "bundle.js").write_text("console.log('built');")

            report = inspect_repository(str(repo_path))

            # legit_file should be scanned
            scanned_files = [i.file for i in report.security_indicators]
            self.assertTrue(any("mydistribution" in f for f in scanned_files))

    def test_database_false_positive_prevention(self):
        """Test that common code keywords (user.update, select_option, delete_item) do NOT generate database indicators."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            sample_file = repo_path / "helpers.py"
            sample_file.write_text(
                "def update_ui():\n"
                "    user.update()\n"
                "    select_option()\n"
                "    delete_item()\n"
                "    insert_item()\n"
            )

            report = inspect_repository(temp_dir)
            db_indicators = [i for i in report.security_indicators if i.category == "database"]
            self.assertEqual(len(db_indicators), 0)

    def test_go_route_method_mapping(self):
        """Test that net/http HandleFunc and Handle routes map method to ALL."""
        report = inspect_repository(str(FIXTURE_REPO_PATH))
        go_routes = [r for r in report.routes if r.pattern == "/status"]
        self.assertGreaterEqual(len(go_routes), 1)
        self.assertEqual(go_routes[0].method, "ALL")

    def test_directory_symlink_out_of_bounds_prevention(self):
        """Test that directory symlinks pointing outside repository root are safely caught and ignored."""
        with tempfile.TemporaryDirectory() as external_dir:
            ext_dir_path = Path(external_dir) / "external_sub"
            ext_dir_path.mkdir()
            (ext_dir_path / "secret.py").write_text("import os\nos.system('secret')")

            with tempfile.TemporaryDirectory() as repo_dir:
                repo_path = Path(repo_dir)
                (repo_path / "valid.py").write_text("print('valid')")
                symlink_dir = repo_path / "ext_link_dir"

                try:
                    os.symlink(ext_dir_path, symlink_dir, target_is_directory=True)
                except (OSError, NotImplementedError):
                    # Skip if OS user lacks symlink privilege
                    return

                report = inspect_repository(str(repo_path))
                error_types = [e.error_type for e in report.errors]
                self.assertIn("symlink_out_of_bounds", error_types)
                # Verify external directory files were NOT scanned
                scanned_files = [i.file for i in report.security_indicators]
                self.assertNotIn("ext_link_dir/secret.py", scanned_files)

    def test_qodo1_indicator_regex_literal_calls(self):
        """Test 1: Ensure function calls followed by non-word chars (quotes, slashes) trigger indicators."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            (repo_path / "app.js").write_text('eval("payload");\nexec("payload");\nfetch("/api");\n')
            report = inspect_repository(str(repo_path))
            cats = {i.category for i in report.security_indicators}
            self.assertIn("serialization", cats)
            self.assertIn("subprocess", cats)
            self.assertIn("network", cats)

    def test_qodo2_pep621_toml_dependencies(self):
        """Test 2: Ensure PEP 621 pyproject.toml dependencies are parsed correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            (repo_path / "pyproject.toml").write_text(
                '[project]\nname = "demo"\ndependencies = [\n    "fastapi>=0.100",\n    "uvicorn",\n]\n'
            )
            report = inspect_repository(str(repo_path))
            self.assertIn("FastAPI", report.repository.frameworks)

    def test_qodo3_go_mod_single_line_require(self):
        """Test 3: Ensure go.mod single line require directives are parsed and replace/exclude ignored."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            (repo_path / "go.mod").write_text(
                'module example.com/demo\n\ngo 1.20\n\nrequire github.com/gin-gonic/gin v1.10.0\nreplace github.com/foo/bar => ./fork\n'
            )
            report = inspect_repository(str(repo_path))
            self.assertIn("Gin", report.repository.frameworks)
            self.assertEqual(len(report.manifests[0].dependencies), 1)
            self.assertEqual(report.manifests[0].dependencies[0], "github.com/gin-gonic/gin")

    def test_qodo4_gitignore_negation(self):
        """Test 4: Ensure gitignore negation rules (!important.log) re-include files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            (repo_path / ".gitignore").write_text('*.log\n!important.log\n')
            (repo_path / "app.log").write_text("import os\nos.system('app log')")
            (repo_path / "important.log").write_text("import os\nos.system('important log')")
            (repo_path / "code.py").write_text("print('hello')")

            report = inspect_repository(str(repo_path))
            scanned_files = [i.file for i in report.security_indicators]
            self.assertIn("important.log", scanned_files)
            self.assertNotIn("app.log", scanned_files)

    def test_qodo5_nested_gitignore(self):
        """Test 5: Ensure nested .gitignore files apply relative rules correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            (repo_path / ".gitignore").write_text('*.tmp\n')
            sub_dir = repo_path / "sub"
            sub_dir.mkdir()
            (sub_dir / ".gitignore").write_text('!special.tmp\n')
            (sub_dir / "normal.tmp").write_text("import os\nos.system('normal')")
            (sub_dir / "special.tmp").write_text("import os\nos.system('special')")

            report = inspect_repository(str(repo_path))
            scanned_files = [i.file for i in report.security_indicators]
            self.assertIn("sub/special.tmp", scanned_files)
            self.assertNotIn("sub/normal.tmp", scanned_files)

    def test_qodo6_spring_request_mapping_method(self):
        """Test 6: Ensure generic @RequestMapping produces method=ALL."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            (repo_path / "Controller.java").write_text('@RequestMapping("/api/v1")\npublic class Controller {}\n')
            report = inspect_repository(str(repo_path))
            spring_routes = [r for r in report.routes if r.pattern == "/api/v1"]
            self.assertEqual(len(spring_routes), 1)
            self.assertEqual(spring_routes[0].method, "ALL")

    def test_qodo7_go_route_arbitrary_receivers(self):
        """Test 7: Ensure Go web routes match arbitrary identifier receivers."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            (repo_path / "routes.go").write_text('package main\nfunc setup() {\n  v1.GET("/users", h1)\n  apiGroup.POST("/orders", h2)\n}\n')
            report = inspect_repository(str(repo_path))
            patterns = {r.pattern for r in report.routes}
            self.assertIn("/users", patterns)
            self.assertIn("/orders", patterns)

    def test_qodo8_circleci_config_matching(self):
        """Test 8: Ensure .circleci/config.yml is detected as CI/CD config."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            circle_dir = repo_path / ".circleci"
            circle_dir.mkdir()
            (circle_dir / "config.yml").write_text("version: 2.1\n")
            report = inspect_repository(str(repo_path))
            self.assertIn(".circleci/config.yml", report.repository.cicd_configs)

    def test_qodo9_framework_substring_false_positives(self):
        """Test 9: Ensure packages like expressive and reactive do not trigger Express or React."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            (repo_path / "package.json").write_text('{"dependencies": {"expressive": "1.0.0", "reactive": "2.0.0"}}\n')
            report = inspect_repository(str(repo_path))
            self.assertNotIn("Express", report.repository.frameworks)
            self.assertNotIn("React", report.repository.frameworks)

    def test_qodo10_java_test_suffix_matching(self):
        """Test 10: Ensure UserTest.java is correctly detected as a test file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            (repo_path / "UserTest.java").write_text("public class UserTest {}\n")
            report = inspect_repository(str(repo_path))
            self.assertIn("UserTest.java", report.repository.test_files)


if __name__ == "__main__":
    unittest.main()
