# Blind SQL injection with conditional responses

**Category:** SQL Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses

Every technique so far in this series has relied on the response echoing something back — a
version string, a table row, a marker value. Blind SQL injection is what happens when that
channel disappears entirely and the only thing left to work with is a single bit of information
per request: did the page look the way it normally does, or didn't it.

## The Target

This lab doesn't inject through a visible query parameter at all — the vulnerable input is the
`TrackingId` cookie, set automatically on every visit and never displayed anywhere in the page.
The application uses it to look up tracking data server-side, and the page shows a "Welcome back"
message when that lookup succeeds. Nothing about the response ever contains database output
directly.

## The Investigation

With no data reflected, the only usable signal is that one conditional message. So the entire
attack is built around asking the database yes/no questions and reading the answer off whether
"Welcome back" appears.

**Confirming the channel exists.** We appended a condition that's always true and one that's
always false to the cookie value, and confirmed the message toggled accordingly:

```
TrackingId=xyz' AND '1'='1
TrackingId=xyz' AND '1'='2
```

The first showed "Welcome back"; the second didn't. That's the entire information channel this
attack has to work with — one bit per request.

**Turning yes/no into a string.** A single true/false bit doesn't sound like much, but it's enough
to reconstruct arbitrary text through binary search. For each character position in the target
string, we ask whether its ASCII value is greater than some midpoint, narrow the range based on the
answer, and repeat — the same algorithm as guessing a number between 1 and 100 in seven questions,
just applied one character at a time:

```
' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),{pos},1) > 'X'--
```

We first extracted the password's *length* the same way — testing `LENGTH(password) = N` for
increasing `N` until the true condition hit — so the character loop knows exactly when to stop.

## The Exploit

With the length known, we ran the ASCII binary search independently for every character position,
narrowing each one from the full printable range (32–126) down to a single value in about seven
requests. Running the positions concurrently — rather than one after another — cut what would be a
long sequential extraction (dozens of characters × roughly seven requests each) down to the time
of the slowest single character, since each position's binary search doesn't depend on any other
position's result. The reconstructed string was the administrator's full password, which we used
to log in through the normal form.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution walks through the identical logic — confirm the true/false channel, confirm
the `users` table and the `administrator` row exist, determine the password length by incrementing
a `LENGTH()` comparison, then extract character by character with `SUBSTRING(password,{pos},1)`
comparisons. Same conditions, same extraction primitive.

The real difference shows up in execution. PortSwigger's walkthrough uses Burp Intruder configured
with a payload set of `a`–`z` and `0`–`9`, launched once per character position, with the
"Welcome back" string set as a grep-match filter to read results by eye. That's effectively a
manual, alphabet-based linear search per position. We ran a binary search over the full ASCII
range instead of a fixed alphabet — roughly seven requests per character rather than up to
thirty-six — and parallelized across character positions using a thread pool, so the whole
password came back in one pass rather than twenty sequential Intruder runs. Same vulnerability,
same fundamental technique (boolean oracle → character extraction), meaningfully different
extraction strategy.

## What This Teaches Us

Blind injection is a good reminder that "the response doesn't show database output" is not the
same thing as "the query result is invisible" — a single conditional message, or even a subtly
different response length or status code, is enough of a channel to reconstruct anything the
database will answer questions about, one bit at a time. The fix is unchanged from every other lab
in this series: with the `TrackingId` value bound as a parameter instead of concatenated into SQL
text, there's no boolean condition left for an attacker to control in the first place — the
"Welcome back" message would only ever reflect the tracking ID's actual, harmless database lookup.
