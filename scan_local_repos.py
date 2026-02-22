#!/usr/bin/env python3
"""
Script to scan local repositories for web vulnerability PoCs and generate CSV.
Scans all folders in local_repos/ directory directly.
"""

import os
import re
import csv
from pathlib import Path

# File paths - using relative paths from current working directory
LOCAL_REPOS_DIR = "local_repos"
OUTPUT_CSV = "executable_poc_web.csv"

# Vulnerability patterns for scanning
PATTERNS = {
    "SQL Injection": [
        r"SELECT\s+.*\s+FROM",
        r"OR\s+1\s*=\s*1",
        r"UNION\s+SELECT",
        r"'\s*OR\s+",
        r";\s*DROP\s+TABLE",
        r"xp_cmdshell",
        r"INSERT\s+INTO",
        r"DELETE\s+FROM",
        r"1\s*=\s*1",
        r"admin'\s*--",
    ],
    "XSS": [
        r"document\.cookie",
        r"<script",
        r"innerHTML",
        r"document\.write",
        r"onerror\s*=",
        r"onload\s*=",
        r"onclick\s*=",
        r"eval\s*\(",
        r"javascript:",
        r"outerHTML",
        r"alert\s*\(",
    ],
    "Deserialization": [
        r"pickle\.loads?",
        r"yaml\.load",
        r"marshal\.loads?",
        r"unserialize\s*\(",
        r"ObjectInputStream",
        r"readObject",
    ],
    "Header Injection": [
        r"setHeader\s*\(",
        r"addHeader\s*\(",
        r"Location\s*:",
        r"header\s*\(",
        r"setcookie",
        r"X-Forwarded",
        r"X-Original",
    ],
    "RCE": [
        r"os\.system",
        r"subprocess\.(call|run|Popen)",
        r"system\s*\(",
        r"exec\s*\(",
        r"shell_exec",
        r"passthru\s*\(",
        r"Runtime\.getRuntime",
        r"ProcessBuilder",
        r"cmd\.exe",
        r"/bin/sh",
        r"/bin/bash",
    ],
    "LFI/RFI": [
        r"include\s+",
        r"require\s+",
        r"file_get_contents",
        r"readfile",
        r"fopen\s*\(",
        r"\.\./",
        r"php://filter",
        r"zip://",
        r"data://text",
    ],
    "SSRF": [
        r"urllib\.request",
        r"requests\.get",
        r"http://169\.254",
        r"http://127\.0\.0\.1",
        r"http://localhost",
        r"curl_exec",
    ],
    "Path Traversal": [
        r"\.\./",
        r"\.\.\\",
        r"/etc/passwd",
        r"/etc/shadow",
        r"C:\\Windows",
    ],
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

def check_docker(folder_path):
    """Check if the repository contains Docker-related files."""
    docker_files = ['docker-compose.yml', 'docker-compose.yaml', 'Dockerfile']
    for root, dirs, files in os.walk(folder_path):
        for f in docker_files:
            if f in files:
                return "Yes"
    return "No"

def check_web_service(folder_path):
    """Check if the repository is a web service."""
    # Check for Docker files first
    if check_docker(folder_path) == "Yes":
        return True

    # Check for web framework code
    web_indicators = WEB_FRAMEWORKS
    target_extensions = ['.py', '.js', '.ts', '.java', '.php', '.rb', '.go']

    for root, dirs, files in os.walk(folder_path):
        # Skip common non-essential directories
        if any(skip in root for skip in ['node_modules', '.git', '__pycache__', 'vendor']):
            continue

        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in target_extensions:
                try:
                    filepath = os.path.join(root, file)
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read().lower()
                        for indicator in web_indicators:
                            if indicator.lower() in content:
                                return True
                except:
                    pass
    return False

def scan_for_vulnerabilities(folder_path):
    """Scan files for vulnerability patterns."""
    target_extensions = ['.md', '.py', '.sh', '.java', '.js', '.html', '.php', '.rb', '.go', '.yaml', '.yml']
    found_vulns = {}

    for root, dirs, files in os.walk(folder_path):
        # Skip common non-essential directories
        if any(skip in root for skip in ['node_modules', '.git', '__pycache__', 'vendor', '.venv']):
            continue

        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in target_extensions:
                try:
                    filepath = os.path.join(root, file)
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        content_lower = content.lower()

                        for vuln_type, patterns in PATTERNS.items():
                            for pattern in patterns:
                                try:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        if vuln_type not in found_vulns:
                                            found_vulns[vuln_type] = []
                                        # Store context (filename and matching line)
                                        found_vulns[vuln_type].append({
                                            'file': os.path.relpath(filepath, folder_path),
                                            'pattern': pattern
                                        })
                                        break
                                except re.error:
                                    pass
                except Exception as e:
                    pass

    return found_vulns

def extract_port_from_docker(folder_path):
    """Extract exposed ports from docker-compose.yml or Dockerfile."""
    ports = []

    # Check docker-compose.yml
    for dc_file in ['docker-compose.yml', 'docker-compose.yaml']:
        dc_path = os.path.join(folder_path, dc_file)
        if os.path.exists(dc_path):
            try:
                with open(dc_path, 'r') as f:
                    content = f.read()
                    # Match port mappings like "8080:80" or "8080"
                    port_matches = re.findall(r'["\']?(\d+)(?::(\d+))?["\']?', content)
                    for match in port_matches:
                        if isinstance(match, tuple):
                            ports.append(match[0])  # host port
                        else:
                            ports.append(match)
            except:
                pass

    # Check Dockerfile
    dockerfile_path = os.path.join(folder_path, 'Dockerfile')
    if os.path.exists(dockerfile_path):
        try:
            with open(dockerfile_path, 'r') as f:
                for line in f:
                    if line.strip().startswith('EXPOSE'):
                        port = line.split()[-1]
                        ports.append(port)
        except:
            pass

    return list(set(ports))

def get_poc_logic_from_readme(folder_path):
    """Extract PoC logic from README.md if available."""
    readme_paths = ['README.md', 'readme.md', 'README.MD', 'Readme.md']

    for readme in readme_paths:
        readme_path = os.path.join(folder_path, readme)
        if os.path.exists(readme_path):
            try:
                with open(readme_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    # Look for PoC indicators
                    poc_keywords = {
                        'RCE': ['rce', 'remote code execution', 'command injection'],
                        'SQL Injection': ['sql injection', 'sqli'],
                        'XSS': ['xss', 'cross-site scripting'],
                        'LFI': ['lfi', 'local file inclusion', 'file read'],
                        'RFI': ['rfi', 'remote file inclusion'],
                        'SSRF': ['ssrf', 'server-side request forgery'],
                        'Deserialization': ['deserialization', 'unserialize'],
                        'Path Traversal': ['path traversal', 'directory traversal'],
                        'Header Injection': ['header injection', 'http header'],
                        'Auth Bypass': ['auth bypass', 'authentication bypass', 'unauthorized'],
                        'Privilege Escalation': ['privilege escalation', 'priv esc'],
                    }

                    found = []
                    for logic, keywords in poc_keywords.items():
                        for keyword in keywords:
                            if keyword in content.lower():
                                found.append(logic)
                                break

                    if found:
                        return ', '.join(found[:2])  # Return top 2
            except:
                pass

    return None

def generate_show_description(repo, folder_path, has_docker, vulns, port=None):
    """Generate a one-sentence description based on findings."""
    if not vulns:
        return f"Security research repository - {repo}"

    vuln_types = list(vulns.keys())[:3]
    vuln_str = ', '.join(vuln_types).lower()

    docker_info = " with Docker deployment" if has_docker == "Yes" else ""
    port_info = f" on port {port}" if port else ""

    return f"This repository provides {vuln_str} proof-of-concept{docker_info}{port_info} demonstrating web-based attack vectors."

def scan_all_repos():
    """Main function to scan all local repositories."""
    print("=" * 60)
    print("Scanning local repositories for web vulnerability PoCs")
    print("=" * 60)

    if not os.path.isdir(LOCAL_REPOS_DIR):
        print(f"Error: {LOCAL_REPOS_DIR} directory not found")
        return

    # Get all repository folders
    repos = []
    for item in os.listdir(LOCAL_REPOS_DIR):
        item_path = os.path.join(LOCAL_REPOS_DIR, item)
        if os.path.isdir(item_path):
            repos.append(item)

    print(f"Found {len(repos)} repositories in {LOCAL_REPOS_DIR}")

    results = []
    processed = 0
    with_docker = 0
    with_vulns = 0

    for repo in repos:
        folder_path = os.path.join(LOCAL_REPOS_DIR, repo)

        # Check if it's a web service
        is_web = check_web_service(folder_path)
        if not is_web:
            continue

        processed += 1

        # Check for Docker
        has_docker = check_docker(folder_path)
        if has_docker == "Yes":
            with_docker += 1

        # Extract ports
        ports = extract_port_from_docker(folder_path)
        port = ports[0] if ports else None

        # Scan for vulnerabilities
        vulns = scan_for_vulnerabilities(folder_path)

        # Try to get PoC logic from README
        poc_from_readme = get_poc_logic_from_readme(folder_path)

        # Determine PoC Logic
        if poc_from_readme:
            poc_logic = poc_from_readme
        elif vulns:
            vuln_priority = ["RCE", "SQL Injection", "XSS", "SSRF", "LFI/RFI", "Path Traversal", "Deserialization", "Header Injection"]
            poc_logic = next((v for v in vuln_priority if v in vulns), list(vulns.keys())[0])
        else:
            poc_logic = "Web Application"

        # Generate description
        show_desc = generate_show_description(repo, folder_path, has_docker, vulns, port)

        if vulns:
            with_vulns += 1

        results.append({
            "Repo": repo,
            "Folder Path": folder_path,
            "Has Docker": has_docker,
            "Port": port or "",
            "PoC Logic": poc_logic,
            "Show Description": show_desc,
            "Vulnerabilities": list(vulns.keys())
        })

        if processed % 100 == 0:
            print(f"Processed {processed} repositories... (Docker: {with_docker}, Vulns: {with_vulns})")

    # Write results to CSV
    print(f"\nWriting {len(results)} results to {OUTPUT_CSV}...")

    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ["Repo", "Folder Path", "Has Docker", "Port", "PoC Logic", "Show Description", "Vulnerabilities"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    print("\n" + "=" * 60)
    print("SCAN COMPLETE - STATISTICS")
    print("=" * 60)
    print(f"Total repositories scanned: {len(repos)}")
    print(f"Web service repositories: {processed}")
    print(f"Repositories with Docker: {with_docker}")
    print(f"Repositories with vulnerabilities: {with_vulns}")
    print(f"\nResults saved to: {OUTPUT_CSV}")

    # Print vulnerability breakdown
    vuln_counts = {}
    for r in results:
        for v in r['Vulnerabilities']:
            vuln_counts[v] = vuln_counts.get(v, 0) + 1

    if vuln_counts:
        print("\nVulnerability breakdown:")
        for vuln, count in sorted(vuln_counts.items(), key=lambda x: -x[1]):
            print(f"  {vuln}: {count}")

if __name__ == "__main__":
    scan_all_repos()
