#!/usr/bin/env python3
"""
Add GitHub URL column to executable_poc_web.csv
Converts folder names like 'username_reponame' to GitHub URLs
"""

import csv
import re
import os

CSV_FILE = "/mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/executable_poc_web.csv"
OUTPUT_FILE = "/mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/executable_poc_web.csv"
BACKUP_FILE = "/mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/executable_poc_web_with_url_backup.csv"

def folder_to_github_url(folder_path, repo_name):
    """
    Convert folder path or repo name to GitHub URL.

    Examples:
    - fabidick22_inject-sec-to-devops -> https://github.com/fabidick22/inject-sec-to-devops
    - CAT-Team-mmc_lysec -> https://github.com/CAT-Team-mmc/lysec
    - local_repos/awspx -> https://github.com/llmsc-security/awesome-hacking-lists/tree/master/local_repos/awspx
    """
    # Clean up folder path
    if folder_path:
        folder_path = folder_path.strip()

    # Try to extract owner/repo from folder path or repo name
    # Pattern 1: owner_reponame (single underscore separates owner from repo)
    # Pattern 2: owner-sub_owner-sub/repo (with dashes)

    def convert_name(name):
        """Convert a name like 'user_repo' or 'user-repo' to owner/repo"""
        name = name.strip()

        # Skip if it looks like a full URL already
        if name.startswith('http'):
            return name

        # Skip common non-repo names
        if name.lower() in ['local_repos', 'none', 'n/a', '']:
            return None

        # Try to split by underscore (owner_reponame format)
        # Look for the last underscore that separates owner from repo
        parts = name.split('_')

        if len(parts) >= 2:
            # Find the best split point
            # Heuristic: repo names often have hyphens, owner names less so
            for i in range(len(parts) - 1, 0, -1):
                owner = '_'.join(parts[:i])
                repo = '_'.join(parts[i:])

                # Validate: both parts should be non-empty and reasonable
                if owner and repo and len(owner) >= 2 and len(repo) >= 2:
                    # Check if owner looks like a valid GitHub username
                    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,38}$', owner):
                        return f"https://github.com/{owner}/{repo}"

        # If no valid split found, return the local repo URL
        return None

    # Try repo name first
    if repo_name:
        url = convert_name(repo_name)
        if url:
            return url

    # Try folder path
    if folder_path:
        # Extract just the folder name from path
        folder_name = os.path.basename(folder_path)
        if folder_name and folder_name != 'local_repos':
            url = convert_name(folder_name)
            if url:
                return url

    # Default: return local repo URL
    if folder_path and folder_path != 'local_repos':
        folder_name = os.path.basename(folder_path) if folder_path else repo_name
        return f"https://github.com/llmsc-security/awesome-hacking-lists/tree/master/local_repos/{folder_name}"

    return ""


def add_github_url_column():
    """Add GitHub URL column to CSV"""
    if not os.path.exists(CSV_FILE):
        print(f"CSV file not found: {CSV_FILE}")
        return

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

    # Add GitHub URL to each entry
    for i, entry in enumerate(entries):
        repo_name = entry.get("Repo", "")
        folder_path = entry.get("Folder Path", "")

        github_url = folder_to_github_url(folder_path, repo_name)
        entry["GitHub URL"] = github_url

        if (i + 1) % 1000 == 0:
            print(f"  Processed {i + 1}/{len(entries)} entries...")

    # Write back with new column
    fieldnames = ["Repo", "Folder Path", "Has Docker", "Port", "PoC Logic", "Show Description", "Vulnerabilities", "GitHub URL"]

    with open(OUTPUT_FILE, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for entry in entries:
            writer.writerow(entry)

    print(f"\nUpdated CSV with {len(entries)} entries")
    print(f"Output saved to: {OUTPUT_FILE}")

    # Show sample URLs
    print("\nSample GitHub URLs:")
    for i, entry in enumerate(entries[:5]):
        print(f"  {entry['Repo']} -> {entry['GitHub URL']}")


if __name__ == "__main__":
    add_github_url_column()
