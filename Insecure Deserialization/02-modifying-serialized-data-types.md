# Lab: Modifying serialized data types

**Category:** Insecure Deserialization
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-data-types

The previous lab showed that a serialized object handed to the client is really just an editable
form. This one goes a step further: the interesting bug isn't in the *value* of an attribute at
all, but in its *type*. PHP's serialization format encodes a type tag alongside every value, and
that tag is just as editable as the value itself — which opens the door to a language quirk that
has nothing to do with deserialization on its own, but becomes exploitable the moment
deserialization hands an attacker the ability to choose a field's type.

## The Target

Same storefront, same session mechanism as the previous lab: login produces a base64-encoded PHP
serialized `User` object as the session cookie. This time the object carries a `username` and an
`access_token` rather than an `admin` boolean, and the access-control check compares the token
against a stored value using PHP's loose `==` operator rather than a hard identity comparison.

## The Investigation

PHP's loose comparison has a long-documented quirk: comparing an integer to a non-numeric string
with `==` coerces the string to `0` for the comparison, so `0 == "some_non_numeric_string"`
evaluates to `true` on PHP 7.x and earlier. That's a language-level footgun independent of
deserialization — but deserialization is what lets an attacker actually deliver an integer `0`
into a field the application only ever expected to hold a string. Nothing forces the client-
supplied object to keep `access_token` as a string; the serialization format lets us relabel the
type tag from `s` (string) to `i` (integer) and supply `0` as the value, and the deserializer will
build exactly that object, no matter what the application code presumed elsewhere.

## The Exploit

We took the verified payload for this lab, which does two things in one edit: switches the
username to `administrator` and retypes `access_token` as the integer `0`:

```
O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}
```

Note the two things that have to change together — the string-length prefix on `username` grows
from whatever `wiener` needed to `13` for `administrator`, and `access_token`'s type tag flips
from `s:LEN:"..."` to a bare `i:0;` with no quotes or length field at all, since integers don't
carry a length. Base64-encoded and sent as the session cookie, this made the application's loose
comparison of the (now-integer) token against its stored (non-numeric) comparison value evaluate
to true, and the response granted access consistent with the `administrator` identity. From there,
`/admin` exposed the same delete-user action as the previous lab, and
`/admin/delete?username=carlos` solved it.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's official solution walks the identical edit: change `username` to `administrator`
(updating its length prefix to `13`), then change `access_token`'s value from a quoted string to
the bare integer `0` by switching its type label from `s` to `i` and removing the quotes — landing
on the exact same serialized string we used, `O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}`.
Their walkthrough performs this in Burp Repeater's Inspector panel, applying the change and
resending; we built and encoded the same string via script before sending it.

This is a case where the underlying PHP type-juggling bug is the entire lesson, and our approach
and PortSwigger's converge on byte-identical output — the only real difference is, again, GUI edit
versus scripted construction.

## What This Teaches Us

This lab isolates a bug class that's easy to miss when auditing PHP applications: `==` versus
`===`. The comparison itself isn't a deserialization vulnerability — plenty of PHP code uses loose
comparison safely because every value flowing into it originates as a string from a database or a
form field. What makes it exploitable here is that deserialization removes that guarantee
entirely; the attacker chooses the type of every field in the object, not just its value. Any code
path that deserializes attacker-influenced data and then relies on loose typing downstream
inherits this risk. The durable fix is `===` for security-sensitive comparisons, which fails closed
on a type mismatch instead of coercing its way to `true` — but the broader lesson is that
deserialized input should be validated and re-typed explicitly before it's trusted anywhere in the
comparison logic that follows.
