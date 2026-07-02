# Exploiting NoSQL operator injection to bypass authentication

**Category:** NoSQL Injection
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-bypass-authentication

MongoDB's query language isn't just strings — its filters are JSON objects, and several of its
built-in comparison operators (`$ne`, `$regex`, `$gt`, `$in`) can be smuggled into a request as
structured data instead of a plain value. A login form that accepts `{"username": "wiener"}` as
JSON will often accept `{"username": {"$ne": "invalid"}}` just as happily, and MongoDB will
interpret the second one as "match any username that isn't the literal string 'invalid'" — which is
every username in the collection. This lab turns that operator confusion into a full authentication
bypass.

## The Target

The login flow is a JSON POST:

```
POST /login
{"username":"wiener","password":"peter"}
```

powered by a MongoDB lookup on those two fields. We know from the outset that we're trying to reach
an administrator account, but the lab doesn't hand us the admin username — it's randomized per
instance (something like `adminubmqp0nt`), which rules out just guessing `"administrator"` outright
and forces the injection to do the work of finding the account, not just bypassing its password.

## The Investigation

We probed the login endpoint with a sequence of operator payloads rather than assuming the first
one would work, since MongoDB's tolerance for combined operators varies by driver and query
construction:

- `{"username":"administrator","password":{"$ne":""}}` — exact username, operator on password
- `{"username":"administrator","password":{"$ne":"invalid"}}`
- `{"username":"administrator","password":{"$regex":".*"}}`
- `{"username":"administrator","password":{"$gt":""}}`
- `{"username":{"$ne":""},"password":{"$ne":""}}` — operator on both fields
- `{"username":{"$regex":"admin.*"},"password":{"$ne":""}}`
- `{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}`

Two results stood out. Putting `$ne` on both `username` and `password` simultaneously returned a
500 server error — the application (or its query builder) rejects a double-operator query outright,
which is a useful negative signal but not an exploit. Using the literal string `"administrator"` as
the username with an operator on password came back as an ordinary failed login, because the real
admin account isn't named `administrator` at all — the randomized name meant nothing matched. That
ruled out guessing the username and pointed straight at needing an operator there too, not just on
the password.

## The Exploit

The payload that worked combined a `$regex` on the username with a `$ne` on the password:

```json
{"username":{"$regex":"admin.*"},"password":{"$ne":""}}
```

`$regex` matches any username starting with `admin`, which catches the randomized admin account
without knowing its exact suffix, and `$ne: ""` on the password matches any non-empty password
value — so it authenticates as whichever admin-prefixed account exists, regardless of its real
password. We ran the injection probe with redirects disabled specifically so a `302` (success) was
distinguishable from a `200` (failure) rather than getting silently followed and masked; sending
this payload returned a `302` redirect to `/my-account?id=<admin-username>`. Following that session
into `/my-account` and `/admin` confirmed we were now looking at the administrator's own panel.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution arrives at the identical final payload through a more incremental Repeater
workflow: confirm `{"$ne": ""}` on username alone changes the response, confirm `{"$regex":
"wien.*"}` on the known `wiener` account behaves the same way as an exact match (proving `$regex`
is evaluated as a query operator rather than a literal string), then set both username and password
to `{"$ne": ""}` at once and note that multiple account records match — before finally narrowing the
username to `{"$regex": "admin.*"}` with `password: {"$ne": ""}` to land on the administrator
account specifically.

That's the same technique end to end, and it's worth calling out that PortSwigger's own
intermediate step — both fields set to `$ne` — is the one query that produced a 500 in our version
of the probe rather than "multiple records match." That's a legitimate divergence in server
behavior between test runs of the same lab, not a difference in technique; either way it correctly
signals that combining operators on both fields does something the double-operator matching path
doesn't like, and both of us moved past it toward the `$regex`+`$ne` combination that actually
authenticates. The other difference is the usual one: PortSwigger edits and resends through Burp's
GUI, we scripted the payload list and read status codes/redirect locations directly.

## What This Teaches Us

The vulnerability here isn't really about weak passwords — it's about a JSON parser that can't tell
the difference between "a value the user typed" and "a query operator the developer meant to write
themselves." Because MongoDB's filter objects use the same JSON structure for both, any endpoint
that deserializes request JSON straight into a query without an allowlist on permitted keys hands
an attacker the ability to rewrite the query's logic, not just its data — up to and including
authenticating as an account whose name and password were never actually known. The fix is
structural: reject any field with `$`-prefixed keys or nested objects where a plain string was
expected, before the value ever reaches the query builder.
