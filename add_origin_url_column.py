#!/usr/bin/env python3
"""
Add GitHub Origin URL column to executable_poc_web.csv
Extracts actual git remote URLs from cloned repositories
"""

import csv
import os
import subprocess

CSV_FILE = "/mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/executable_poc_web.csv"
OUTPUT_FILE = "/mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/executable_poc_web.csv"
BACKUP_FILE = "/mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/executable_poc_web_origin_backup.csv"
LOCAL_REPOS_DIR = "/mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/local_repos"


def get_origin_url(folder_path, base_dir=None):
    """Get the original git remote URL from a cloned repository"""
    if not folder_path or folder_path == "local_repos":
        return ""

    # Handle both full path and relative folder name
    if not os.path.isabs(folder_path):
        if base_dir:
            folder_path = os.path.join(base_dir, folder_path)
        else:
            folder_path = os.path.join(LOCAL_REPOS_DIR, folder_path)

    if not os.path.isdir(folder_path):
        return ""

    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=folder_path,
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            url = result.stdout.strip()
            # Convert SSH URLs to HTTPS
            if url.startswith("git@github.com:"):
                url = url.replace("git@github.com:", "https://github.com/")
            return url
    except Exception as e:
        print(f"  Error getting origin URL for {folder_path}: {e}")
        pass

    return ""


def add_origin_url_column():
    """Add GitHub Origin URL column to CSV"""
    if not os.path.exists(CSV_FILE):
        print(f"CSV file not found: {CSV_FILE}")
        return

    # Get base directory (where this script is located)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"Base directory: {base_dir}")

    # Create backup
    print(f"Creating backup at {BACKUP_FILE}...")
    with open(CSV_FILE, 'r', encoding='utf-8') as f:
        content = f.read()
    with open(BACKUP_FILE, 'w', encoding='utf-8') as f:
        f.write(content)

    # Read all entries
    entries = []
    with open(CSV_FILE, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            entries.append(row)

    print(f"Read {len(entries)} entries from CSV")
    print(f"Scanning {len(entries)} repositories for origin URLs...")

    # Add Origin URL to each entry
    cache = {}  # Cache for folder paths we've already checked

    for i, entry in enumerate(entries):
        folder_path = entry.get("Folder Path", "")

        # Use cache if available
        if folder_path in cache:
            entry["Origin URL"] = cache[folder_path]
        else:
            origin_url = get_origin_url(folder_path, base_dir)
            cache[folder_path] = origin_url
            entry["Origin URL"] = origin_url

        if (i + 1) % 200 == 0:
            print(f"  Processed {i + 1}/{len(entries)} entries...")

    # Write back with new column
    fieldnames = ["Repo", "Folder Path", "Has Docker", "Port", "PoC Logic", "Show Description", "Vulnerabilities", "Origin URL"]

    with open(OUTPUT_FILE, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for entry in entries:
            writer.writerow(entry)

    print(f"\nUpdated CSV with {len(entries)} entries")
    print(f"Output saved to: {OUTPUT_FILE}")

    # Count URLs found
    urls_found = sum(1 for e in entries if e.get("Origin URL", ""))
    print(f"Origin URLs found: {urls_found}/{len(entries)}")

    # Show sample URLs
    print("\nSample Origin URLs:")
    for entry in entries[:10]:
        print(f"  {entry['Repo']} -> {entry['Origin URL']}")


if __name__ == "__main__":
    add_origin_url_column()
