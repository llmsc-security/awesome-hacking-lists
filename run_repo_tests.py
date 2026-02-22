#!/usr/bin/env python3
"""
Script to review and run unittests for local repositories.
Logs results and identifies issues that need debugging.
"""

import os
import subprocess
import json
from datetime import datetime
from pathlib import Path

LOCAL_REPOS_DIR = "local_repos"
OUTPUT_LOG = "test_review_report.txt"
PYTHON = "/home/crpo_readonly_cuda122/anaconda3/bin/python3"

def find_test_files(repo_path):
    """Find test files in a repository."""
    test_files = []
    test_dirs = []

    for root, dirs, files in os.walk(repo_path):
        # Skip common non-essential directories
        if any(skip in root for skip in ['.git', 'node_modules', '__pycache__', '.venv', 'venv']):
            continue

        # Find test files
        for f in files:
            if f.startswith('test_') or f.endswith('_test.py') or f == 'tests.py':
                test_files.append(os.path.join(root, f))

        # Find test directories
        if os.path.basename(root) == 'tests' or os.path.basename(root) == 'test':
            test_dirs.append(root)

    return test_files, test_dirs

def check_test_framework(repo_path):
    """Check what test framework is used."""
    frameworks = []

    # Check for pytest
    if os.path.exists(os.path.join(repo_path, 'pytest.ini')):
        frameworks.append('pytest')
    if os.path.exists(os.path.join(repo_path, 'pyproject.toml')):
        try:
            with open(os.path.join(repo_path, 'pyproject.toml')) as f:
                if 'pytest' in f.read():
                    frameworks.append('pytest')
        except:
            pass

    # Check for unittest
    test_files, _ = find_test_files(repo_path)
    for tf in test_files[:5]:  # Check first 5 test files
        try:
            with open(tf) as f:
                content = f.read(2000)
                if 'unittest' in content:
                    frameworks.append('unittest')
                if 'pytest' in content or 'import pytest' in content:
                    frameworks.append('pytest')
        except:
            pass

    # Check for setup.py or requirements
    if os.path.exists(os.path.join(repo_path, 'setup.py')):
        try:
            with open(os.path.join(repo_path, 'setup.py')) as f:
                content = f.read()
                if 'pytest' in content:
                    frameworks.append('pytest')
        except:
            pass

    return list(set(frameworks))

def run_tests(repo_path, repo_name):
    """Run tests for a repository."""
    test_files, test_dirs = find_test_files(repo_path)
    frameworks = check_test_framework(repo_path)

    result = {
        'repo': repo_name,
        'path': repo_path,
        'test_files_count': len(test_files),
        'test_dirs': test_dirs,
        'frameworks': frameworks,
        'status': 'no_tests',
        'output': '',
        'error': ''
    }

    if not test_files and not test_dirs:
        return result

    # Try to run pytest
    if frameworks or test_dirs:
        try:
            proc = subprocess.run(
                [PYTHON, '-m', 'pytest', repo_path, '-v', '--tb=short', '-x'],
                capture_output=True,
                text=True,
                timeout=300
            )
            result['output'] = proc.stdout[-5000:] if len(proc.stdout) > 5000 else proc.stdout
            result['error'] = proc.stderr[-2000:] if len(proc.stderr) > 2000 else proc.stderr
            result['status'] = 'passed' if proc.returncode == 0 else 'failed'
            result['return_code'] = proc.returncode
        except subprocess.TimeoutExpired:
            result['status'] = 'timeout'
            result['error'] = 'Test execution timed out after 300 seconds'
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)

    return result

def main():
    print("=" * 70)
    print("Repository Unit Test Review")
    print("=" * 70)
    print(f"Started at: {datetime.now().isoformat()}")
    print()

    if not os.path.isdir(LOCAL_REPOS_DIR):
        print(f"Error: {LOCAL_REPOS_DIR} directory not found")
        return

    # Get all repository folders
    repos = []
    for item in os.listdir(LOCAL_REPOS_DIR):
        item_path = os.path.join(LOCAL_REPOS_DIR, item)
        if os.path.isdir(item_path):
            repos.append(item)

    print(f"Found {len(repos)} repositories to check")
    print()

    results = []
    passed = 0
    failed = 0
    no_tests = 0
    errors = 0

    for i, repo in enumerate(repos):
        repo_path = os.path.join(LOCAL_REPOS_DIR, repo)
        print(f"[{i+1}/{len(repos)}] Checking {repo}...")

        result = run_tests(repo_path, repo)
        results.append(result)

        if result['status'] == 'passed':
            passed += 1
            print(f"  PASSED ({len(result['test_files'])} test files)")
        elif result['status'] == 'failed':
            failed += 1
            print(f"  FAILED - {result['error'][:100] if result['error'] else 'See log'}")
        elif result['status'] == 'no_tests':
            no_tests += 1
        elif result['status'] == 'error':
            errors += 1
            print(f"  ERROR - {result['error'][:100]}")
        elif result['status'] == 'timeout':
            errors += 1
            print(f"  TIMEOUT")

    # Write report
    print()
    print(f"Writing report to {OUTPUT_LOG}...")

    with open(OUTPUT_LOG, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("REPOSITORY UNIT TEST REVIEW REPORT\n")
        f.write("=" * 70 + "\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n\n")

        f.write("SUMMARY\n")
        f.write("-" * 70 + "\n")
        f.write(f"Total repositories: {len(repos)}\n")
        f.write(f"Tests passed: {passed}\n")
        f.write(f"Tests failed: {failed}\n")
        f.write(f"No tests found: {no_tests}\n")
        f.write(f"Errors/Timeouts: {errors}\n\n")

        f.write("=" * 70 + "\n")
        f.write("DETAILED RESULTS\n")
        f.write("=" * 70 + "\n\n")

        # Write failed tests first
        f.write("FAILED TESTS\n")
        f.write("-" * 70 + "\n\n")
        for r in results:
            if r['status'] == 'failed':
                f.write(f"Repository: {r['repo']}\n")
                f.write(f"Path: {r['path']}\n")
                f.write(f"Test files: {r['test_files_count']}\n")
                f.write(f"Frameworks: {', '.join(r['frameworks']) if r['frameworks'] else 'unknown'}\n")
                f.write(f"Error:\n{r['error']}\n")
                f.write(f"Output:\n{r['output']}\n")
                f.write("\n" + "=" * 70 + "\n\n")

        # Write errors
        f.write("ERRORS/TIMEOUTS\n")
        f.write("-" * 70 + "\n\n")
        for r in results:
            if r['status'] in ['error', 'timeout']:
                f.write(f"Repository: {r['repo']}\n")
                f.write(f"Path: {r['path']}\n")
                f.write(f"Status: {r['status']}\n")
                f.write(f"Error: {r['error']}\n\n")
                f.write("=" * 70 + "\n\n")

        # Write repos with no tests
        f.write("REPOSITORIES WITHOUT TESTS\n")
        f.write("-" * 70 + "\n\n")
        for r in results:
            if r['status'] == 'no_tests':
                f.write(f"- {r['repo']}\n")

    print()
    print("=" * 70)
    print("REVIEW COMPLETE")
    print("=" * 70)
    print(f"Total repositories: {len(repos)}")
    print(f"Tests passed: {passed}")
    print(f"Tests failed: {failed}")
    print(f"No tests found: {no_tests}")
    print(f"Errors/Timeouts: {errors}")
    print(f"\nReport saved to: {OUTPUT_LOG}")

if __name__ == "__main__":
    main()
