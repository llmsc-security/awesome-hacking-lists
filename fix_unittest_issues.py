#!/usr/bin/env python3
"""
Unittest Fix Script
Finds and fixes common unittest issues in repositories:
1. Missing imports
2. Incorrect test method signatures
3. Deprecated unittest methods
4. Path issues
"""

import os
import re
import sys
from pathlib import Path
from datetime import datetime


COMMON_FIXES = {
    # Fix missing unittest import
    r'(?m)^import unittest$': 'import unittest',

    # Fix deprecated assert methods (Python 2 -> 3)
    r'\bassertEquals\b': 'assertEqual',
    r'\bassertNotEquals\b': 'assertNotEqual',
    r'\bassertAlmostEquals\b': 'assertAlmostEqual',

    # Fix deprecated failUnless/failIf
    r'\bfailUnless\b': 'assertTrue',
    r'\bfailIf\b': 'assertFalse',
    r'\bfailUnlessEqual\b': 'assertEqual',
    r'\bfailIfEqual\b': 'assertNotEqual',

    # Fix deprecated assert_
    r'\.assert_\(': '.assertTrue(',

    # Fix deprecated assertRaisesRegexp
    r'\bassertRaisesRegexp\b': 'assertRaisesRegex',

    # Fix deprecated assertRegexpMatches
    r'\bassertRegexpMatches\b': 'assertRegex',
}


def find_unittest_files(base_dir, max_files=100):
    """Find unittest files in repositories."""
    test_files = []
    test_patterns = ['test_*.py', '*_test.py', 'tests/*.py', 'test/*.py']

    for root, dirs, files in os.walk(base_dir):
        # Skip hidden directories and common non-test directories
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'vendor']]

        for file in files:
            if file.endswith('.py') and 'test' in file.lower():
                filepath = os.path.join(root, file)

                # Check if it's actually a unittest file
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(2000)

                    # Look for unittest patterns
                    if any(pattern in content for pattern in ['unittest.TestCase', 'def test_', 'self.assert', 'pytest']):
                        test_files.append(filepath)

                        if len(test_files) >= max_files:
                            return test_files

                except Exception:
                    continue

    return test_files


def analyze_test_file(filepath):
    """Analyze a test file for issues."""
    issues = []

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')

        # Check for missing imports
        has_unittest = 'import unittest' in content or 'from unittest' in content
        has_testcase = 'unittest.TestCase' in content or 'TestCase' in content
        if has_testcase and not has_unittest:
            # Check for pytest style
            if 'import pytest' not in content and 'pytest' not in content:
                issues.append({
                    'type': 'missing_import',
                    'line': 1,
                    'message': 'Missing unittest import'
                })

        # Check for deprecated methods
        for line_num, line in enumerate(lines, 1):
            for old, new in [('assertEquals', 'assertEqual'),
                             ('assertNotEquals', 'assertNotEqual'),
                             ('failUnless', 'assertTrue'),
                             ('failIf', 'assertFalse'),
                             ('assert_', 'assertTrue'),
                             ('assertRaisesRegexp', 'assertRaisesRegex')]:
                if old in line:
                    issues.append({
                        'type': 'deprecated_method',
                        'line': line_num,
                        'message': f'{old} is deprecated, use {new}',
                        'fix': (old, new)
                    })

        # Check for common syntax errors
        if 'def test_' in content:
            # Check for missing self parameter
            for line_num, line in enumerate(lines, 1):
                if re.match(r'\s*def test_\w+\(', line):
                    if 'self' not in line and 'TestCase' in content:
                        issues.append({
                            'type': 'missing_self',
                            'line': line_num,
                            'message': 'Missing self parameter in test method'
                        })

        # Check for path issues
        if '__file__' in content:
            # Check if using relative paths that might break
            if 'os.chdir' in content or 'os.path.dirname(__file__)' not in content:
                issues.append({
                    'type': 'path_issue',
                    'line': 0,
                    'message': 'May have path resolution issues'
                })

        # Check for import errors
        for line_num, line in enumerate(lines, 1):
            if line.strip().startswith('import ') or line.strip().startswith('from '):
                # Check for common missing packages
                for pkg in ['mock', 'parameterized', 'nose', 'hypothesis']:
                    if pkg in line and f'import {pkg}' in content:
                        # This is fine, but note it
                        pass

        # Check for async test issues
        if 'async def test_' in content:
            if 'pytest-asyncio' not in content and 'import pytest' in content:
                issues.append({
                    'type': 'async_issue',
                    'line': 0,
                    'message': 'Async tests may need pytest-asyncio'
                })

    except Exception as e:
        issues.append({
            'type': 'read_error',
            'line': 0,
            'message': str(e)
        })

    return issues


def fix_test_file(filepath, issues):
    """Fix issues in a test file."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        original_content = content
        fixes_applied = []

        for issue in issues:
            if issue['type'] == 'deprecated_method' and 'fix' in issue:
                old, new = issue['fix']
                content = content.replace(old, new)
                fixes_applied.append(f"Replaced {old} with {new}")

            elif issue['type'] == 'missing_import':
                # Add import at the beginning
                if 'import unittest' not in content:
                    content = 'import unittest\n' + content
                    fixes_applied.append("Added unittest import")

        # Only write if changes were made
        if content != original_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True, fixes_applied

        return False, []

    except Exception as e:
        return False, [str(e)]


def generate_report(all_issues, output_file):
    """Generate report of issues found."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 60 + "\n")
        f.write("UNITTEST ISSUES REPORT\n")
        f.write("=" * 60 + "\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # Summary
        f.write("SUMMARY\n")
        f.write("-" * 40 + "\n")
        f.write(f"Total files analyzed: {len(all_issues)}\n")
        f.write(f"Files with issues: {sum(1 for issues in all_issues.values() if issues)}\n")
        f.write(f"Total issues: {sum(len(issues) for issues in all_issues.values())}\n\n")

        # Issue types
        issue_types = {}
        for issues in all_issues.values():
            for issue in issues:
                t = issue['type']
                issue_types[t] = issue_types.get(t, 0) + 1

        f.write("ISSUE TYPES\n")
        f.write("-" * 40 + "\n")
        for t, count in sorted(issue_types.items(), key=lambda x: -x[1]):
            f.write(f"  {t}: {count}\n")
        f.write("\n")

        # Detailed issues
        f.write("DETAILED ISSUES\n")
        f.write("-" * 40 + "\n")
        for filepath, issues in all_issues.items():
            if issues:
                f.write(f"\n{filepath}:\n")
                for issue in issues:
                    f.write(f"  Line {issue['line']}: {issue['type']} - {issue['message']}\n")

    print(f"Report written to {output_file}")


def main():
    base_dir = '/mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/local_repos'
    output_report = '/mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/unittest_issues_report.txt'

    print("=" * 60)
    print("Unittest Fix Script")
    print("=" * 60)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Find test files
    print("Finding unittest files...")
    test_files = find_unittest_files(base_dir, max_files=200)
    print(f"Found {len(test_files)} test files")
    print()

    # Analyze files
    print("Analyzing test files for issues...")
    all_issues = {}
    fixable_count = 0

    for i, filepath in enumerate(test_files, 1):
        if i % 50 == 0:
            print(f"  Analyzed {i}/{len(test_files)} files...")

        issues = analyze_test_file(filepath)
        if issues:
            all_issues[filepath] = issues

            # Check if fixable
            fixable = any(issue['type'] in ['deprecated_method', 'missing_import'] for issue in issues)
            if fixable:
                fixable_count += 1

    print(f"Found issues in {len(all_issues)} files")
    print(f"Fixable issues: {fixable_count}")
    print()

    # Fix files
    if fixable_count > 0:
        print("Fixing issues...")
        fixed_count = 0

        for filepath, issues in all_issues.items():
            success, fixes = fix_test_file(filepath, issues)
            if success:
                fixed_count += 1
                print(f"  Fixed {filepath}: {', '.join(fixes)}")

        print(f"Fixed {fixed_count} files")
        print()

    # Generate report
    generate_report(all_issues, output_report)

    print()
    print("=" * 60)
    print("Complete!")
    print("=" * 60)


if __name__ == '__main__':
    main()
