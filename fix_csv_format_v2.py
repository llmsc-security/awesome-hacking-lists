#!/usr/bin/env python3
"""
Fix CSV format - properly handle mixed 5 and 6 column entries.
"""

import csv
import os

CSV_FILE = "/mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/executable_poc_web.csv"

def fix_csv():
    """Fix CSV format by properly handling mixed column counts."""
    if not os.path.exists(CSV_FILE):
        print(f"CSV file not found: {CSV_FILE}")
        return

    # Read raw lines to detect column count
    entries = []
    fixed_count = 0

    with open(CSV_FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # Skip header
    header = lines[0].strip()
    print(f"Header: {header}")

    for i, line in enumerate(lines[1:], 1):
        line = line.strip()
        if not line:
            continue

        # Split by comma but handle quoted fields
        parts = []
        in_quote = False
        current = ""
        for char in line:
            if char == '"':
                in_quote = not in_quote
                current += char
            elif char == ',' and not in_quote:
                parts.append(current)
                current = ""
            else:
                current += char
        parts.append(current)

        # Handle 5-column format: Repo, Folder Path, Has Docker, PoC Logic, Show Description
        # Handle 6-column format: Repo, Folder Path, Has Docker, Port, PoC Logic, Show Description

        if len(parts) == 5:
            entry = {
                "Repo": parts[0],
                "Folder Path": parts[1],
                "Has Docker": parts[2],
                "PoC Logic": parts[3],
                "Show Description": parts[4],
            }
        elif len(parts) == 6:
            # 6-column format - skip Port (index 3)
            entry = {
                "Repo": parts[0],
                "Folder Path": parts[1],
                "Has Docker": parts[2],
                "PoC Logic": parts[4],  # Skip Port at index 3
                "Show Description": parts[5],
            }
            fixed_count += 1
        else:
            print(f"Line {i}: Unexpected column count {len(parts)}: {parts[:3]}...")
            # Try to salvage
            entry = {
                "Repo": parts[0] if len(parts) > 0 else "",
                "Folder Path": parts[1] if len(parts) > 1 else "",
                "Has Docker": parts[2] if len(parts) > 2 else "",
                "PoC Logic": parts[3] if len(parts) > 3 else "",
                "Show Description": parts[4] if len(parts) > 4 else "",
            }

        entries.append(entry)

    print(f"Read {len(entries)} entries, fixed {fixed_count} 6-column entries")

    # Write back with consistent 5-column format
    fieldnames = ["Repo", "Folder Path", "Has Docker", "PoC Logic", "Show Description"]

    with open(CSV_FILE, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for entry in entries:
            writer.writerow(entry)

    print(f"Fixed CSV format with {len(entries)} entries")

    # Verify
    with open(CSV_FILE, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    docker_yes = sum(1 for r in rows if r.get("Has Docker") == "Yes")
    print(f"Entries with 'Has Docker' = Yes: {docker_yes}")

    # Check for entries with empty Show Description
    empty_desc = [r for r in rows if not r.get("Show Description") or len(r.get("Show Description", "")) < 10]
    if empty_desc:
        print(f"Entries with empty/short Show Description: {len(empty_desc)}")
        for r in empty_desc[:10]:
            print(f"  - {r.get('Repo')}: '{r.get('Show Description')}'")

if __name__ == "__main__":
    fix_csv()
