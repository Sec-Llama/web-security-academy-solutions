# SSRF with blacklist-based input filter

**Category:** Server-Side Request Forgery (SSRF)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter

Blacklists are a losing game against SSRF for the same reason they're a losing game against most
injection classes: they encode a list of strings someone thought of, not a definition of what's
actually safe. This lab puts a blacklist directly in front of the same `stockApi` parameter from the
first two labs and asks whether blocking the obvious strings — `127.0.0.1`, `localhost`, `admin` — is
enough.

## The Target

Same stock-check feature, same parameter shape:

```
POST /product/stock
stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

This time, pointing `stockApi` directly at `http://localhost/admin` or `http://127.0.0.1/admin` came
back blocked rather than returning the admin page — the application is now filtering the value before
fetching it.

## The Investigation

Our `detect_ssrf()` function already tests for exactly this shape of defense: send the loopback URL,
and if the response looks blocked (`400`/`403`/`500`, or the words "blocked"/"denied" in the body),
try `127.1` as a bypass before giving up:

```python
if r.status_code in (400, 403, 500) or "blocked" in r.text.lower() or "denied" in r.text.lower():
    bypass_url = test_url.replace("localhost", "127.1").replace("127.0.0.1", "127.1")
```

`127.1` is a valid shorthand IPv4 representation of `127.0.0.1` that most string-matching blacklists
don't account for — they're checking for the literal substrings `127.0.0.1` or `localhost`, not
parsing the value as an actual address and comparing it to loopback. That bypass alone got us past the
host check, but the response still came back blocked once the path contained `/admin` — the blacklist
was also filtering the string `admin` directly, independent of the host.

Bypassing that second check needed URL encoding, and this is where our own tooling introduced a
problem PortSwigger's manual Burp workflow doesn't have to think about at all. `SSRF.py` sends the
`stockApi` value through `httpx`'s `data={}` form-encoding, and `httpx` URL-encodes that value itself
before putting it on the wire — meaning any `%` character we write into our Python string gets
encoded a second time. Write `%2561` into the Python payload expecting it to arrive on the wire as
`%2561`, and it actually arrives as `%252561` — one encoding layer too many, and the application's
decoder never resolves it back to `admin`. The fix, once we traced it, was to write only a single
layer of encoding in the Python source (`%61` for the letter `a`) and let `httpx`'s own form-encoding
pass produce the second layer automatically, landing on the wire exactly as `%2561`:

```python
# httpx data={} form-encodes values, adding one URL-encode layer.
# Want %2561 on the wire? Use %61 in Python value.
encoded_path = target_path.replace("admin", "%61dmin")
```

The server's form parser decodes `%2561` back to `%61` (passing the blacklist's literal string check
for "admin," since the value it inspects is still `%61dmin`), and the internal web server serving the
admin panel decodes `%61` the rest of the way to `a`, resolving the path to `/admin` only after the
blacklist has already approved it.

## The Exploit

Combining both bypasses — `127.1` for the host, `%61dmin` for the path — got us the admin interface:

```
stockApi=http://127.1/%61dmin
```

Reading the returned HTML for the delete link and re-applying the same encoding to the delete path
produced the final request:

```
stockApi=http://127.1/%61dmin/delete?username=carlos
```

That came back successfully, and the lab's solved check confirmed carlos was deleted.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the identical two-stage bypass: `127.0.0.1` blocked, `127.1` bypasses
the host check; `127.1/admin` blocked again, double-URL-encoding the `a` in "admin" to `%2561`
bypasses the path check. The underlying blacklist-evasion technique is exactly what we landed on.

The interesting divergence is entirely about tooling, not technique. In Burp Repeater, you type the
literal bytes you want sent — write `%2561` in the request editor and `%2561` is what goes on the
wire, because Repeater doesn't apply any encoding of its own on top of what you typed. Scripting the
same request through `httpx` with `data={}` isn't that direct: the library treats the value as form
data and encodes it for you, so the string you write in Python and the bytes that leave the socket are
not the same thing. Getting the wire-level payload PortSwigger's solution describes required
understanding and compensating for that extra encoding pass — writing `%61` instead of `%2561` in our
source to land on the same `%2561` byte sequence Burp sends directly. Same destination, different path
to get the client library to produce it.

## What This Teaches Us

Two separate defenses needed two separate bypasses here, and that's the real lesson: a blacklist isn't
one control, it's however many string patterns someone wrote down, and each one only blocks the
literal forms they thought to include. `127.1` isn't a trick specific to this lab — it's a reminder
that "the same IP address" has many textual representations, and a blacklist checking for one string
says nothing about the others. The `%61dmin` bypass makes the same point about paths: encoding is a
transformation the blacklist has to normalize *before* comparing, and if it compares the raw string
instead, any encoding the downstream fetcher will decode later slips straight through. An allowlist
that resolves the URL to its final host and path before checking closes both problems at once —
blacklists, by contrast, only ever cover the specific bypasses someone has already thought to test for.
