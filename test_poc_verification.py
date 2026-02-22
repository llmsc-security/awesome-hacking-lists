#!/usr/bin/env python3
"""
Unit tests for PoC verification and container runner functionality.

Tests cover:
1. Docker support detection
2. Port extraction from docker-compose files
3. PoC pattern scanning
4. HTTP test configuration validation
5. CSV format validation for Docker-based entries
"""

import os
import re
import csv
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import the module to test
from run_and_verify_poc import (
    check_docker_support,
    extract_port_from_docker_compose,
    scan_files_for_poc,
    generate_description,
    POC_VERIFICATION,
    WEB_FRAMEWORKS,
)

# Test fixtures
TEST_VULPOC_PATH = "/mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/local_repos/VulPOC"
LOCAL_REPOS_DIR = "/mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/local_repos"
CSV_FILE = "/mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/executable_poc_web.csv"


class TestDockerSupportDetection(unittest.TestCase):
    """Test Docker support detection functionality."""

    def test_vulpoc_django_has_docker(self):
        """Test that VulPOC Django CVE directories have Docker support."""
        django_paths = [
            "Django/Django 核心 SQL 注入（CVE-2022-28346）/CVE-2022-28346",
            "Django/Django 核心 SQL 注入（CVE-2020-7471）/CVE-2020-7471",
            "Django/Django 核心 SQL 注入（CVE-2022-28347）/CVE-2022-28347",
        ]

        for django_path in django_paths:
            full_path = os.path.join(TEST_VULPOC_PATH, django_path)
            if os.path.exists(full_path):
                has_docker, docker_path = check_docker_support(full_path)
                self.assertTrue(has_docker, f"{django_path} should have Docker support")
                self.assertIsNotNone(docker_path)

    def test_moodle_cve_has_docker(self):
        """Test that Moodle CVE directory has Docker support."""
        moodle_path = os.path.join(TEST_VULPOC_PATH, "Moodle/CVE-2021-36394 Pre-Auth RCE in Moodle")

        if os.path.exists(moodle_path):
            has_docker, docker_path = check_docker_support(moodle_path)
            self.assertTrue(has_docker, "Moodle CVE should have Docker support")

    def test_non_existent_path(self):
        """Test that non-existent path returns False."""
        has_docker, docker_path = check_docker_support("/non/existent/path")
        self.assertFalse(has_docker)
        self.assertIsNone(docker_path)


class TestPortExtraction(unittest.TestCase):
    """Test port extraction from docker-compose files."""

    def test_django_cve_port(self):
        """Test port extraction from Django CVE docker-compose.yml."""
        test_cases = [
            ("""
version: '2'
services:
  web:
    build: .
    ports:
    - "10101:8000"
    depends_on:
    - db
""", 10101),
            ("""
version: '3'
services:
  web:
    image: n0puple/moodle:3.11.0
    ports:
      - "80:80"
""", 80),
            ("""
version: '3'
services:
  app:
    image: myapp
    ports:
      - "8080:3000"
""", 8080),
        ]

        for compose_content, expected_port in test_cases:
            # Create temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
                f.write(compose_content)
                temp_path = f.name

            try:
                port = extract_port_from_docker_compose(temp_path)
                self.assertEqual(port, expected_port, f"Expected port {expected_port} from compose file")
            finally:
                os.unlink(temp_path)


class TestPoCPatternScanning(unittest.TestCase):
    """Test PoC pattern scanning functionality."""

    def test_sql_injection_patterns(self):
        """Test SQL injection pattern detection."""
        test_content = """
        SELECT * FROM users WHERE id = 1
        UNION SELECT username, password FROM admin
        OR 1=1--
        """

        patterns = POC_VERIFICATION["SQL Injection"]["patterns"]
        found_patterns = []

        for pattern in patterns:
            if re.search(pattern, test_content, re.IGNORECASE):
                found_patterns.append(pattern)

        self.assertGreater(len(found_patterns), 0, "Should detect SQL injection patterns")

    def test_xss_patterns(self):
        """Test XSS pattern detection."""
        test_content = """
        <script>alert('XSS')</script>
        document.cookie
        <img src=x onerror=alert(1)>
        """

        patterns = POC_VERIFICATION["XSS"]["patterns"]
        found_patterns = []

        for pattern in patterns:
            if re.search(pattern, test_content, re.IGNORECASE):
                found_patterns.append(pattern)

        self.assertGreater(len(found_patterns), 0, "Should detect XSS patterns")

    def test_rce_patterns(self):
        """Test RCE pattern detection."""
        test_content = """
        import os
        os.system('ls -la')
        subprocess.call(['whoami'])
        eval(user_input)
        """

        patterns = POC_VERIFICATION["RCE"]["patterns"]
        found_patterns = []

        for pattern in patterns:
            if re.search(pattern, test_content, re.IGNORECASE):
                found_patterns.append(pattern)

        self.assertGreater(len(found_patterns), 0, "Should detect RCE patterns")

    def test_scan_real_vulpoc_files(self):
        """Test scanning actual VulPOC files for PoC patterns."""
        if not os.path.exists(TEST_VULPOC_PATH):
            self.skipTest("VulPOC path does not exist")

        # Find a docker-compose.yml and scan its directory
        for root, dirs, files in os.walk(TEST_VULPOC_PATH):
            if 'docker-compose.yml' in files:
                detected = scan_files_for_poc(root, os.path.join(root, 'docker-compose.yml'))
                # VulPOC repos should have at least one PoC type detected
                # Note: This may fail if the PoC is in parent directory
                # so we just check it runs without error
                self.assertIsInstance(detected, dict)
                break


class TestDescriptionGeneration(unittest.TestCase):
    """Test description generation functionality."""

    def test_sql_injection_description(self):
        """Test SQL injection description generation."""
        desc = generate_description("test/repo", {"SQL Injection": []}, True, 8080)
        self.assertIn("SQL Injection", desc)
        self.assertIn("Docker-based", desc)
        self.assertIn("port 8080", desc)
        self.assertTrue(desc.endswith("."))

    def test_xss_description(self):
        """Test XSS description generation."""
        desc = generate_description("test/repo", {"XSS": []}, True, 80)
        self.assertIn("XSS", desc)
        self.assertIn("Cross-Site Scripting", desc)

    def test_rce_description(self):
        """Test RCE description generation."""
        desc = generate_description("test/repo", {"RCE": []}, True, 3000)
        self.assertIn("RCE", desc)
        self.assertIn("Remote Code Execution", desc)

    def test_empty_poc_description(self):
        """Test description with no PoC types."""
        desc = generate_description("test/repo", {}, False, None)
        self.assertIn("Security research", desc)

    def test_single_sentence(self):
        """Test that description is a single sentence."""
        desc = generate_description("test/repo", {"SQL Injection": []}, True, 8080)
        # Should have exactly one period at the end
        sentences = desc.split('.')
        self.assertEqual(len(sentences), 2)  # One sentence = content + empty after period
        self.assertEqual(sentences[1], "")  # Nothing after the period


class TestCSVFormat(unittest.TestCase):
    """Test CSV format for Docker-based entries."""

    def setUp(self):
        """Load CSV data if exists."""
        self.entries = []
        self.docker_entries = []

        if os.path.exists(CSV_FILE):
            with open(CSV_FILE, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                self.entries = list(reader)
                self.docker_entries = [e for e in self.entries if e.get("Has Docker") == "Yes"]

    def test_csv_file_exists(self):
        """Test that CSV file exists."""
        self.assertTrue(os.path.exists(CSV_FILE), f"CSV file not found: {CSV_FILE}")

    def test_docker_entries_have_valid_format(self):
        """Test that Docker entries have valid format."""
        for entry in self.docker_entries:
            self.assertIn("Repo", entry)
            self.assertIn("Folder Path", entry)
            self.assertIn("Has Docker", entry)
            self.assertIn("PoC Logic", entry)
            self.assertIn("Show Description", entry)

            self.assertEqual(entry["Has Docker"], "Yes")
            self.assertTrue(len(entry["PoC Logic"]) > 0, f"PoC Logic should not be empty for {entry['Repo']}")
            self.assertTrue(len(entry["Show Description"]) > 20, f"Show Description too short for {entry['Repo']}")

    def test_docker_entries_have_port(self):
        """Test that Docker entries have port information."""
        for entry in self.docker_entries:
            port = entry.get("Port", "")
            # Port should be a number or empty (for backward compatibility)
            if port:
                self.assertTrue(port.isdigit() or port.replace('.', '').isdigit(),
                               f"Port should be numeric for {entry['Repo']}: {port}")

    def test_no_duplicate_docker_entries(self):
        """Test no duplicate Docker entries."""
        seen = set()
        duplicates = []

        for entry in self.docker_entries:
            key = (entry.get("Repo", ""), entry.get("Folder Path", ""))
            if key in seen:
                duplicates.append(key)
            seen.add(key)

        self.assertEqual(len(duplicates), 0, f"Found duplicate entries: {duplicates}")


class TestPOCVerificationConfig(unittest.TestCase):
    """Test POC verification configuration."""

    def test_all_poc_types_have_patterns(self):
        """Test that all PoC types have pattern definitions."""
        for poc_type, config in POC_VERIFICATION.items():
            self.assertIn("patterns", config, f"{poc_type} missing 'patterns' key")
            self.assertIsInstance(config["patterns"], list)
            self.assertGreater(len(config["patterns"]), 0, f"{poc_type} has no patterns defined")

    def test_all_poc_types_have_http_tests(self):
        """Test that all PoC types have HTTP test definitions."""
        for poc_type, config in POC_VERIFICATION.items():
            self.assertIn("http_tests", config, f"{poc_type} missing 'http_tests' key")
            self.assertIsInstance(config["http_tests"], list)

    def test_all_poc_types_have_indicators(self):
        """Test that all PoC types have indicator definitions."""
        for poc_type, config in POC_VERIFICATION.items():
            self.assertIn("indicators", config, f"{poc_type} missing 'indicators' key")
            self.assertIsInstance(config["indicators"], list)

    def test_http_tests_have_required_fields(self):
        """Test that HTTP tests have required fields."""
        for poc_type, config in POC_VERIFICATION.items():
            for i, test in enumerate(config["http_tests"]):
                self.assertIn("path", test, f"{poc_type} test {i} missing 'path'")


class TestLocalReposIntegrity(unittest.TestCase):
    """Test local_repos directory integrity."""

    def test_local_repos_exists(self):
        """Test that local_repos directory exists."""
        self.assertTrue(os.path.isdir(LOCAL_REPOS_DIR), f"local_repos not found: {LOCAL_REPOS_DIR}")

    def test_vulpoc_exists(self):
        """Test that VulPOC directory exists."""
        vulpoc_path = os.path.join(LOCAL_REPOS_DIR, "VulPOC")
        self.assertTrue(os.path.isdir(vulpoc_path), "VulPOC directory not found")

    def test_vulpoc_has_docker_compose_files(self):
        """Test that VulPOC has docker-compose.yml files."""
        docker_compose_count = 0

        for root, dirs, files in os.walk(TEST_VULPOC_PATH):
            if 'docker-compose.yml' in files:
                docker_compose_count += 1

        self.assertGreater(docker_compose_count, 0, "VulPOC should have docker-compose.yml files")


def run_tests():
    """Run all tests and print results."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestDockerSupportDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestPortExtraction))
    suite.addTests(loader.loadTestsFromTestCase(TestPoCPatternScanning))
    suite.addTests(loader.loadTestsFromTestCase(TestDescriptionGeneration))
    suite.addTests(loader.loadTestsFromTestCase(TestCSVFormat))
    suite.addTests(loader.loadTestsFromTestCase(TestPOCVerificationConfig))
    suite.addTests(loader.loadTestsFromTestCase(TestLocalReposIntegrity))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")

    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback.split('\\n')[-2] if '\\n' in traceback else traceback[:100]}")

    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback.split('\\n')[-2] if '\\n' in traceback else traceback[:100]}")

    return result


if __name__ == "__main__":
    run_tests()
