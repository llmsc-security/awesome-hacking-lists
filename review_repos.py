#!/usr/bin/env python3
"""
Repository Review Script
Reviews cloned repositories for:
1. Docker infrastructure (docker-compose.yml, Dockerfile)
2. Web service indicators
3. PoC/Exploit files
4. Unittest files and errors
5. Generates comprehensive report
"""

import os
import sys
import re
import json
import csv
import subprocess
from pathlib import Path
from datetime import datetime


def find_docker_files(repo_path):
    """Find Docker infrastructure files."""
    docker_files = []
    docker_patterns = [
        "docker-compose.yml",
        "docker-compose.yaml",
        "Dockerfile",
        "compose.yml",
        "compose.yaml"
    ]

    for root, dirs, files in os.walk(repo_path):
        # Skip hidden directories
        dirs[:] = [d for d in dirs if not d.startswith('.')]

        for file in files:
            if file in docker_patterns:
                docker_files.append(os.path.join(root, file))

    return docker_files


def check_web_ports(docker_files):
    """Check for web service ports in docker files."""
    exposed_ports = set()
    web_ports = {'80', '443', '8080', '8000', '3000', '5000', '8888', '9000'}

    for docker_file in docker_files:
        try:
            with open(docker_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

                # Check for EXPOSE directives
                expose_matches = re.findall(r'EXPOSE\s+([^#\n]+)', content, re.IGNORECASE)
                for match in expose_matches:
                    ports = re.findall(r'(\d+)', match)
                    exposed_ports.update(ports)

                # Check for port mappings in docker-compose
                if 'docker-compose' in docker_file:
                    port_matches = re.findall(r'["\']?(\d{3,4})["\']?\s*:\s*["\']?(\d+)', content)
                    for host_port, container_port in port_matches:
                        exposed_ports.add(container_port)

        except Exception as e:
            pass

    return exposed_ports.intersection(web_ports)


def find_poc_files(repo_path):
    """Find PoC/exploit files."""
    poc_indicators = [
        r'\b(PoC|Proof of Concept)\b',
        r'\b(exploit|exp)\b',
        r'\b(CVE[-_]\d{4}-\d{4,})\b',
        r'\b(vulnerabilit[yi]|VULN)\b',
        r'\b(attack|pwn)\b',
        r'\b(poc\.py|exploit\.py|test\.py|demo\.py)\b',
    ]

    found_files = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if not d.startswith('.')]

        for file in files:
            file_lower = file.lower()
            if any(pattern in file_lower for pattern in ['poc', 'exploit', 'cve', 'vuln', 'attack']):
                found_files.append(os.path.join(root, file))
                continue

            try:
                filepath = os.path.join(root, file)
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(2000)

                for pattern in poc_indicators:
                    if re.search(pattern, content, re.IGNORECASE):
                        found_files.append(filepath)
                        break

            except Exception:
                continue

    return found_files[:10]  # Limit to 10 files


def find_unittest_files(repo_path):
    """Find unittest files."""
    test_patterns = [
        'unittest', 'test_', '_test.', 'tests/', 'spec_', '_spec.',
        'pytest', 'test.py', 'spec.py'
    ]

    found_files = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if not d.startswith('.')]

        for file in files:
            file_lower = file.lower()
            if any(pattern in file_lower for pattern in test_patterns):
                filepath = os.path.join(root, file)
                found_files.append(filepath)

    return found_files[:20]  # Limit to 20 files


def categorize_poc(file_path):
    """Categorize the PoC type based on file content."""
    categories = {
        'SQL Injection': [r'\b(sql|SQL|SELECT|INSERT|UNION.*SELECT)\b', r'\b(injection|INJECTION)\b'],
        'RCE': [r'\b(RCE|Remote Code Execution|exec|system|shell_exec|eval)\b', r'\b(cmd|command|bash|sh -c)\b'],
        'XSS': [r'\b(xss|XSS|script|<script|onerror|onload)\b', r'\b(alert\(document\.cookie)\b'],
        'LFI/RFI': [r'\b(LFI|RFI|include.*\$\w|require.*\$\w)\b', r'\b(\.\./|/etc/passwd)\b'],
        'Deserialization': [r'\b(deseriali[sz]ation|ObjectInputStream|readObject|gadget)\b'],
        'Header Injection': [r'\b(header|Location:|Set-Cookie|CRLF)\b'],
        'Authentication Bypass': [r'\b(auth.*bypass|login.*bypass|admin.*bypass)\b'],
        'Path Traversal': [r'\b(\.\./|\.\.\\|/etc/passwd|/etc/shadow)\b'],
        'SSRF': [r'\b(SSRF|curl|fopen|file_get_contents|localhost|127\.0\.0\.1)\b'],
        'XXE': [r'\b(XXE|XML External Entity|<!ENTITY|DOCTYPE)\b'],
        'Command Injection': [r'\b(command injection|backtick|`|system\(|exec\()\b'],
        'File Upload': [r'\b(file upload|upload.*php|move_uploaded_file)\b'],
        'Information Disclosure': [r'\b(info disclosure|leak|exposure|unauth)\b'],
    }

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(5000)

        detected = set()
        for category, patterns in categories.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    detected.add(category)
                    break

        return '; '.join(sorted(detected)) if detected else 'Unknown'

    except Exception:
        return 'Unknown'


def extract_readme_summary(repo_path):
    """Extract summary from README file."""
    readme_files = ['README.md', 'README.rst', 'README.txt', 'readme.md', 'README']

    for readme in readme_files:
        readme_path = os.path.join(repo_path, readme)
        if os.path.exists(readme_path):
            try:
                with open(readme_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(2000)

                # Extract title
                title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
                title = title_match.group(1).strip() if title_match else "Unknown"

                # Extract first meaningful description
                lines = content.split('\n')
                for line in lines[1:10]:  # Skip title line
                    line = line.strip()
                    if line and not line.startswith('#') and len(line) > 20:
                        return line[:200]

                return title

            except Exception:
                pass

    return "No README found"


def check_docker_can_run(docker_files):
    """Check if docker-compose can validate the setup."""
    for docker_file in docker_files:
        if 'docker-compose' in docker_file:
            try:
                dir_path = os.path.dirname(docker_file)
                result = subprocess.run(
                    ['docker-compose', '-f', docker_file, 'config'],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=dir_path
                )
                if result.returncode == 0:
                    return True, "Valid docker-compose configuration"
                else:
                    return False, f"docker-compose config error: {result.stderr[:200]}"
            except subprocess.TimeoutExpired:
                return False, "docker-compose config timeout"
            except FileNotFoundError:
                return False, "docker-compose not found"
            except Exception as e:
                return False, str(e)

    # Check Dockerfile if no docker-compose
    for docker_file in docker_files:
        if 'Dockerfile' in docker_file:
            return True, "Has Dockerfile (untested)"

    return False, "No valid Docker configuration"


def review_repository(repo_path, base_name):
    """Review a single repository."""
    result = {
        'repo_name': base_name,
        'path': str(repo_path),
        'has_docker': False,
        'docker_files': [],
        'web_ports': [],
        'has_poc': False,
        'poc_files': [],
        'poc_categories': set(),
        'unittest_files': [],
        'docker_valid': False,
        'docker_message': '',
        'readme_summary': '',
    }

    # Find Docker files
    docker_files = find_docker_files(repo_path)
    result['has_docker'] = len(docker_files) > 0
    result['docker_files'] = docker_files[:5]  # Limit for report

    if result['has_docker']:
        result['web_ports'] = list(check_web_ports(docker_files))
        result['docker_valid'], result['docker_message'] = check_docker_can_run(docker_files)

    # Find PoC files
    poc_files = find_poc_files(repo_path)
    result['has_poc'] = len(poc_files) > 0
    result['poc_files'] = poc_files[:5]

    # Categorize PoCs
    for poc_file in poc_files[:3]:
        category = categorize_poc(poc_file)
        if category != 'Unknown':
            result['poc_categories'].add(category)

    # Find unittest files
    result['unittest_files'] = find_unittest_files(repo_path)

    # Extract README summary
    result['readme_summary'] = extract_readme_summary(repo_path)

    return result


def scan_all_repos(base_dir):
    """Scan all repositories in the base directory."""
    results = []
    base_path = Path(base_dir)

    if not base_path.exists():
        print(f"Error: {base_dir} does not exist")
        return results

    # Get all immediate subdirectories
    repos = [d for d in base_path.iterdir() if d.is_dir() and not d.name.startswith('.')]

    print(f"Found {len(repos)} repositories to scan")

    for i, repo in enumerate(repos, 1):
        print(f"[{i}/{len(repos)}] Scanning {repo.name}...")
        result = review_repository(repo, repo.name)

        # Only include repos with Docker or PoC files
        if result['has_docker'] or result['has_poc']:
            results.append(result)

    return results


def generate_report(results, output_file):
    """Generate CSV report."""
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = [
            'Repo', 'Path', 'Has Docker', 'Docker Files', 'Web Ports',
            'Has PoC', 'PoC Categories', 'PoC Files', 'Unittest Files',
            'Docker Valid', 'Docker Message', 'Summary'
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for result in results:
            row = {
                'Repo': result['repo_name'],
                'Path': result['path'],
                'Has Docker': 'Yes' if result['has_docker'] else 'No',
                'Docker Files': '; '.join(result['docker_files'][:2]),
                'Web Ports': ', '.join(result['web_ports']),
                'Has PoC': 'Yes' if result['has_poc'] else 'No',
                'PoC Categories': '; '.join(sorted(result['poc_categories'])),
                'PoC Files': '; '.join(result['poc_files'][:2]),
                'Unittest Files': '; '.join(result['unittest_files'][:3]),
                'Docker Valid': 'Yes' if result['docker_valid'] else 'No',
                'Docker Message': result['docker_message'][:100],
                'Summary': result['readme_summary'][:150]
            }
            writer.writerow(row)

    print(f"Report written to {output_file}")


def generate_json_report(results, output_file):
    """Generate JSON report with full details."""
    # Convert sets to lists for JSON serialization
    json_results = []
    for result in results:
        json_result = result.copy()
        json_result['poc_categories'] = list(result['poc_categories'])
        json_results.append(json_result)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(json_results, f, indent=2, ensure_ascii=False)

    print(f"JSON report written to {output_file}")


def main():
    base_dir = '/mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/local_repos'
    output_csv = '/mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/repo_review_report.csv'
    output_json = '/mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/repo_review_report.json'

    print("=" * 60)
    print("Repository Review Scanner")
    print("=" * 60)
    print(f"Base Directory: {base_dir}")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    results = scan_all_repos(base_dir)

    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total repos scanned: {len(results)}")
    print(f"Repos with Docker: {sum(1 for r in results if r['has_docker'])}")
    print(f"Repos with PoC files: {sum(1 for r in results if r['has_poc'])}")
    print(f"Repos with valid Docker: {sum(1 for r in results if r['docker_valid'])}")
    print()

    # Show top findings
    print("=" * 60)
    print("TOP FINDINGS (repos with both Docker and PoC)")
    print("=" * 60)

    top_findings = [r for r in results if r['has_docker'] and r['has_poc']]
    for finding in top_findings[:20]:
        print(f"\n- {finding['repo_name']}")
        print(f"  Path: {finding['path']}")
        print(f"  Docker: {', '.join(finding['docker_files'][:1])}")
        print(f"  Web Ports: {', '.join(finding['web_ports']) or 'None detected'}")
        print(f"  PoC Categories: {', '.join(finding['poc_categories']) or 'Unknown'}")
        print(f"  Docker Valid: {finding['docker_valid']}")

    print()
    generate_report(results, output_csv)
    generate_json_report(results, output_json)

    print()
    print("Review complete!")


if __name__ == '__main__':
    main()
