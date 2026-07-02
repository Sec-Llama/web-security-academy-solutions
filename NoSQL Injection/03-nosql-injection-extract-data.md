# Exploiting NoSQL injection to extract data

**Category:** NoSQL Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-data

The first NoSQL lab in this series showed that an always-true condition can dump an entire
collection. That's useful for bypassing a filter, but it doesn't get you a specific secret out of a
specific field. This lab asks for the harder thing: pulling the administrator's password out of the
database one character at a time, using nothing but the true/false shape of the application's
responses — the same blind-extraction discipline as blind SQL injection, translated into MongoDB's
`$where` JavaScript evaluation.

## The Target

A `/user/lookup` endpoint takes a `user` parameter and returns that user's profile data:

```
GET /user/lookup?user=administrator
```

but only to an authenticated caller — the endpoint returns a `401` without a valid session. We
authenticate as the low-privilege user `wiener:peter` through a standard HTML form POST that
carries a CSRF token, then use that session to reach the injection point.

## The Investigation

The lookup response gives a clean three-way oracle once we're logged in: a real user's data comes
back as a 96-byte response, a nonexistent user returns "Could not find user" at 38 bytes, and a
malformed query throws a 58-byte error. That's enough signal to run a full blind extraction without
ever needing the response body's actual content — only its length.

We confirmed the injection the same way as the previous lab, with a `||` tautology and a hard
`false` condition:

```
administrator'||'1'=='1     -> returns every user (true, override)
administrator' && 0 && 'x   -> returns none (false, suppress)
```

and confirmed JavaScript string concatenation was actually being evaluated — not just tolerated —
with:

```
wiener'+'
```

which returned wiener's own data. That matters because it proves the parser is executing our input
as code inside the `$where` expression, not merely failing to reject a stray quote.

One operational detail cost us early attempts before we adjusted for it: the `&&` in these payloads
contains a literal `&`, which is a query-string delimiter. Concatenating it directly into a URL
string splits the request into two parameters and breaks the payload silently. Passing the payload
through httpx's `params={}` dict instead of hand-built URL strings let the library handle the
encoding correctly and fixed it.

With the oracle and encoding both working, we first determined the password's length by testing
each candidate length in parallel against the baseline response size:

```
administrator' && this.password.length == 8 && 'x
```

Length 8 matched the baseline byte count, confirming the administrator's password is exactly eight
characters. From there we extracted it position by position using a regex-anchored match against
each candidate character:

```
administrator' && this.password.match(/^y/) && 'x
```

extended with a growing known prefix at each step (`/^<known-so-far><candidate>/`), and cross-
checked the technique against the array-index equivalent PortSwigger's own solution uses:

```
administrator' && this.password[0]=='y' && 'x
```

Both forms work identically — matching a regex anchor or indexing a specific character are just two
ways to ask the same yes/no question. The regex form has the edge when you also want to probe
character *classes* before brute-forcing individual values, e.g. `this.password.match(/\d/)` to
check whether digits appear anywhere in the string before spending requests on a full charset sweep.

## The Exploit

Running the full extraction loop — one parallelized batch of requests per character position across
the printable charset, checking each response length against the 96-byte baseline — recovered the
administrator's password character by character. Our internal record of this run doesn't capture
the literal recovered string, only the mechanism and the confirmed 8-character length; the important
part for the lab is that the loop terminated with a complete password and a login attempt against
`/login` using it (submitted through the same form-POST-plus-CSRF flow used to authenticate as
wiener) returned a redirect into the administrator's session, which the lab's own completion check
confirmed.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the same oracle-and-extract shape: submit `'` to trigger a syntax
error, confirm `wiener'+'` behaves like a valid lookup, test `wiener' && '1'=='2` against
`wiener' && '1'=='1` to establish the boolean channel, then narrow in on the administrator's
password with `administrator' && this.password.length < 30 || 'a'=='b` before switching to Burp
Intruder's Cluster bomb attack type with a two-position payload —
`administrator' && this.password[§0§]=='§a§` — sweeping position `0`–`7` against the lowercase
alphabet to recover all eight characters at once.

The underlying technique is identical to ours down to the array-index payload shape; the only
substantive differences are tooling. PortSwigger drives the sweep through Intruder's Cluster bomb
mode, which brute-forces position and character together as a two-dimensional grid; we ran it as a
sequential loop over positions with each position's full charset fired in parallel, which is really
the same brute-force shape expressed as async Python instead of Intruder's payload grid. We also
used regex matching rather than raw indexing for the character check, which is a difference in
syntax, not in what's being asked of the database.

## What This Teaches Us

This lab is the NoSQL equivalent of blind SQL injection's core lesson: even when a response carries
zero visible data about the value you're after, a query engine that evaluates attacker-controlled
boolean logic will leak that value one true/false answer at a time, given enough requests. The
`$where` clause is the load-bearing weakness — it hands the database a JavaScript expression to
execute per document, and nothing stops that expression from referencing fields the application
never intended to expose through this endpoint. Removing `$where` from untrusted input entirely (or
replacing free-form JavaScript evaluation with parameterized field comparisons) closes this off at
the source, the same way parameterized queries close off SQL injection.
