# SQL injection UNION attack, retrieving multiple values in a single column

**Category:** SQL Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column

Every UNION attack so far in this series has had the luxury of at least two usable text columns —
one for a username, one for a password. This lab removes that luxury: only a single column
renders as text, which means two separate values have to be squeezed through one channel, and
string concatenation is what makes that possible.

## The Target

The category filter, with the query returning two columns total but only one of them actually
displaying as text in the response — confirmed the same way as in labs 7 and 8, by probing each
`NULL` position with a marker string.

## The Investigation

With only one text-bearing column available, selecting `username, password FROM users` directly
the way the previous lab did won't work — the second value has nowhere to render. The fix is to
combine both values into a single string before they ever reach that column, using the database's
string concatenation operator along with a separator character, so the two values can be split
back apart just by reading the output.

Concatenation syntax differs by engine — `||` on Oracle and PostgreSQL, `CONCAT()` on MySQL — which
is itself a small piece of the fingerprinting work covered earlier in this series paying off here.

## The Exploit

We placed a concatenated `username~password` expression into the confirmed text column, with the
other column left `NULL`:

```
' UNION SELECT NULL, username||'~'||password FROM users--
```

The response rendered each row as a single string like `administrator~<password>`, with the `~`
separator making it trivial to split the two fields back apart from plain text. We parsed out the
`administrator` row, extracted the password, and used it to log in — the lab tracker confirmed the
solve on that authenticated session.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same construction: confirm the single text column, then extract
with `'+UNION+SELECT+NULL,username||'~'||password+FROM+users--` — the identical concatenation
operator and separator character. No divergence in technique.

As with the closely related labs earlier in this series, the difference is purely in delivery —
manual Repeater edit versus a scripted request — with the response parsed by regex on our side
instead of by eye.

## What This Teaches Us

This lab demonstrates that a limited number of text-bearing columns is not a meaningful defense
against UNION injection — it's an inconvenience, solved with a string operator every SQL dialect
supports in some form. It's also a reminder that the separator character matters: if the extracted
data could itself contain the separator (unlikely for a password, common for free-text fields),
a real attacker would pick a rarer delimiter or hex-encode the concatenated value to avoid
ambiguity when splitting the result. The underlying fix hasn't moved across any of these UNION
labs: parameterized queries remove the concatenation point the entire family of attacks depends
on, regardless of how many columns happen to be text-compatible.
