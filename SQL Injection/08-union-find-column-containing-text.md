# SQL injection UNION attack, finding a column containing text

**Category:** SQL Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text

Knowing how many columns a query returns is only half of what a UNION attack needs. The other
half is knowing *which* of those columns will actually render a string back to you — because
that's the only column position where extracted data (a password, a table name, anything text-based)
can be placed and expected to show up in the response at all.

## The Target

The `category` filter again, this time with the column count already known to be three — the lab
states this and even hands us a marker string it expects to see reflected, which is itself part of
the test: reflection alone proves both that a column accepts text *and* that our injected value
specifically is what came back, not some coincidental existing product name.

## The Investigation

Not every column that accepts a `NULL` will actually display a string. Some columns might be
numeric types that happen to tolerate `NULL` but would error — or silently fail to render — on an
actual string value. So the only reliable test is to try a real string literal in each column
position, one at a time, and see which position both avoids an error and shows up in the page.

## The Exploit

We substituted the lab's required marker string into each of the three columns in turn:

```
' UNION SELECT 'abcdef',NULL,NULL--
' UNION SELECT NULL,'abcdef',NULL--
' UNION SELECT NULL,NULL,'abcdef'--
```

Two of the three attempts either errored or rendered nothing. The one that succeeded returned the
marker string visibly in the response body, in the product listing — confirming which of the three
columns is safe to use for text extraction in every subsequent attack against this endpoint.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the same per-column substitution, first confirming the count with
`'+UNION+SELECT+NULL,NULL,NULL--`, then trying the lab's random marker string in each null
position in turn — "if an error occurs, move on to the next null and try that instead" — until the
string appears in the response. Same method, same three-column probe.

The difference again is purely operational: theirs is three sequential manual Repeater sends,
reading the response after each one. We ran the same three substitutions as one automated probe
loop with the marker string, stopping at the first position where it appeared verbatim in the
response body — same requests, same logic.

## What This Teaches Us

This lab is a small but important reminder that "the injection point exists" and "the injection
point is directly useful for exfiltration" aren't the same fact — you need a text-bearing return
channel, and finding it is a distinct, mechanical step from finding the injection itself. It's also
a good illustration of why UNION attacks are self-verifying: reflecting a chosen marker string back
is unambiguous proof of control, in a way that a generic `NULL` never could be. As with the rest of
this series, the underlying flaw and its fix are the same — parameterized queries remove the
concatenation point this entire technique depends on.
