# SQL injection vulnerability allowing login bypass

**Category:** SQL Injection
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/sql-injection/lab-login-bypass

A login form is usually the single most attacked endpoint on any application, and it's also
where SQL injection stops being a data-disclosure bug and becomes a full authentication bypass.
This lab is the canonical demonstration: no password required, no credential stuffing, no
brute-force — just a comment character in the right place.

## The Target

The login form posts a username and password:

```
POST /login
username=carlos&password=wrong
```

A typical backend implementation checks credentials with a query built by concatenating both
fields directly into the SQL text, something like:

```sql
SELECT * FROM users WHERE username = 'carlos' AND password = 'wrong'
```

If that query returns a row, the login succeeds. The password check exists entirely inside that
one query — which means if we can control where the query's string boundaries fall, we control
whether the password is ever actually checked.

## The Investigation

The same closing-quote-plus-comment idea from the previous lab applies here, but the target this
time is the `username` field rather than a filter parameter, and the goal isn't to broaden a
`WHERE` clause — it's to remove the password condition from the query entirely. Since the query
structure is `username = '<input>' AND password = '<input>'`, closing the username string and
commenting out everything after it deletes the password check outright, regardless of what
password value is submitted.

## The Exploit

We submitted the login form with the username field terminated early:

```
POST /login
username=administrator'--&password=anything
```

The resulting query:

```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = 'anything'
```

`--` comments out the rest of the line, so the database only ever evaluates
`username = 'administrator'`. If a row with that username exists, the query returns it — and the
application logs us in as administrator without ever checking a password, because the password
clause was never executed as SQL at all.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution is the same payload, delivered the same way at heart: intercept the login
request in Burp Suite and set the `username` parameter to `administrator'--`. There's no
divergence in technique here — this is a single well-known payload, and both approaches send the
exact same bytes to the same endpoint.

As with the previous lab, the only distinction is tooling: their walkthrough edits the field by
hand in Burp's proxy before forwarding it; we sent it as a scripted `POST` request. The SQL
mechanics, the payload, and the outcome are identical.

## What This Teaches Us

This lab makes the stakes of string-concatenated SQL concrete: it's not just "an attacker can read
extra rows," it's "an attacker can delete a security check by choosing where a string ends." The
password field was never actually broken — it simply never got evaluated, because the query
structure let an attacker decide how much of the SQL statement counted as "the query" in the first
place. Parameterized queries remove this entirely: the username value is bound as data, so an
apostrophe inside it can never end the string early or introduce a comment that swallows the
password check.
