# SSRF with whitelist-based input filter

**Category:** Server-Side Request Forgery (SSRF)
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter

Blacklists fail because they only cover what someone thought to block. Whitelists are supposed to be
the fix — instead of listing what's forbidden, only allow what's explicitly approved. This lab shows
the failure mode that survives even that: a whitelist is only as strong as the URL parser checking
against it, and if that parser disagrees with the one actually making the request, the "allowlist"
never really applied at all.

## The Target

Same `stockApi` parameter as the earlier labs, this time validated against a whitelist requiring the
URL's host to be `stock.weliketoshop.net`. Pointing it at `http://127.0.0.1/` came back rejected — the
application is parsing the URL, extracting the hostname, and checking it against that single
approved value.

## The Investigation

A hostname whitelist sounds airtight until you ask which *part* of the URL the validator is treating
as the hostname, and whether the HTTP client that actually issues the request agrees. URLs support
embedded credentials in the form `http://user:pass@host/`, and testing
`http://localhost@stock.weliketoshop.net/` came back accepted — confirmation that the validator
extracts everything after the `@` as the host, sees `stock.weliketoshop.net`, and approves it, while
treating everything before the `@` as harmless userinfo it doesn't need to check.

That's the seam. If the validator trusts the substring after `@` and the client actually making the
request trusts something else, the two can be made to disagree. Appending a literal `#` after the
userinfo got the request rejected again — a bare `#` starts a URL fragment, which many parsers treat
as ending the authority section entirely, so the validator likely started reading `stock.weliketoshop.net`
as part of the userinfo instead of the host once the fragment marker showed up. Double-URL-encoding
that `#` to `%2523` bypassed the rejection: the *validator's* parser sees the raw string
`localhost%2523@stock.weliketoshop.net`, decodes it once to `localhost%23@stock.weliketoshop.net`,
and still reads the host correctly as `stock.weliketoshop.net` after the `@`. But the *HTTP client*
that eventually fetches the URL decodes percent-escapes at a different stage, resolving `%23` the rest
of the way down to a literal `#` — at which point everything after it, including
`@stock.weliketoshop.net`, becomes a fragment the client discards entirely, and the request is
actually routed to `localhost`.

`exploit_ssrf_whitelist_bypass()` builds exactly this string, with the same `httpx` form-encoding
consideration from the blacklist lab: writing `%23` once in the Python source lets `httpx`'s own
`data={}` encoding add the second layer automatically, landing on the wire as the `%2523` the
whitelist parser needs to see:

```python
# httpx data={} adds one form-encode layer: %23 in Python -> %2523 on wire
# Whitelist parser sees userinfo=TARGET%23, host=WHITELISTED -> passes
# HTTP client decodes %23 -> #, sends request to TARGET with PATH
bypass_url = f"http://{target_host}%23@{whitelisted_host}{target_path}{query}"
```

## The Exploit

With `target_host` set to `localhost` and `whitelisted_host` set to `stock.weliketoshop.net`, the
primary bypass URL our function generated — and the one that worked on the first attempt, without
needing any of the fallback variations also coded into `exploit_ssrf_whitelist_bypass()` — was:

```
stockApi=http://localhost%23@stock.weliketoshop.net/admin
```

That returned the admin interface. Reading the delete link out of the response and re-running the
same bypass with the delete path appended:

```
stockApi=http://localhost%23@stock.weliketoshop.net/admin/delete?username=carlos
```

completed the exploit, and the lab's solved check confirmed carlos was deleted.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution walks through the identical discovery sequence — `127.0.0.1` rejected,
`username@stock.weliketoshop.net` accepted (confirming embedded-credential support), a bare `#`
rejected, `%2523` accepted with a suspicious internal server error — and lands on the same underlying
parser-confusion bypass. Their final payload is:

```
http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
```

which includes an explicit `:80` port before the encoded `#`. Our primary payload omitted the port —
`http://localhost%23@stock.weliketoshop.net/admin` — and it worked without it, since `80` is already
the default port for a plain `http://` URL and adding it explicitly doesn't change where the request
actually lands. (Our exploit function does carry a `:80` variant as one of its fallback attempts, for
targets where a parser might require the port to be explicit, but the plain version succeeded first
here.) Otherwise this is the same bypass PortSwigger describes, reached through the same reasoning
about where the validator's parsing and the HTTP client's parsing diverge.

## What This Teaches Us

A whitelist is a genuine improvement over a blacklist in principle — it inverts the failure mode from
"list everything dangerous" to "list everything safe" — but it only holds if every component in the
request path parses the URL identically. Here, the validator and the actual HTTP client disagreed
about what a `#` character means once it's been through one round of URL-decoding, and that
disagreement was the entire vulnerability. The fix isn't a smarter whitelist regex; it's structural —
parse the URL exactly once, with the same parser that will be used to issue the request, extract the
host from that single canonical parse, and validate that host before any second decoding pass has a
chance to change what it means.
