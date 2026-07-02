# Reflected XSS with AngularJS sandbox escape without strings

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-without-strings

AngularJS's expression sandbox was built specifically to stop `{{...}}` template injection from
turning into arbitrary code execution, by blocking access to dangerous globals like `constructor`
inside string literals written in an expression. This lab strips away the easiest way around that
sandbox — using string literals at all — and asks for the escape to be built entirely out of numbers,
property access, and filters.

## The Target

A page reflecting the `search` parameter inside an AngularJS expression context, but configured so
that `$eval` isn't reachable and, more importantly, quote characters in the expression are stripped or
blocked. Every AngularJS sandbox-escape technique we'd normally reach for — `constructor.constructor
('alert(1)')()`-style chains — depends on being able to write a string literal like `'alert(1)'`
inside the expression. Without quotes, that entire family of payloads is unavailable.

## The Investigation

Two separate problems needed solving. First: how do you construct a string in JavaScript without a
string literal? `toString()` is the answer — calling it on almost any value hands back a string, no
quotes required, and that string can itself be manipulated with array/string methods.

Second, and more specific to this lab: examining how the application builds its Angular expression
showed it reflects every URL parameter *name* — not just the value — into a `$parse()` call. That
meant the injection point wasn't the `search` value at all, but the parameter name itself, changing
where in the URL the payload actually needed to live.

With those two pieces, the escape chain came together as: use `toString()` to get a string without
quotes, walk to `String.prototype` through it, and overwrite `charAt` — a method AngularJS's sandbox
checker relies on internally — with `[].join`, which effectively neutralizes the sandbox's ability to
correctly inspect string content. From there, `[1]|orderBy:` pipes an array through the `orderBy`
filter, and the filter argument is built via `toString().constructor.fromCharCode(...)`, converting a
list of character codes into the literal text `x=alert(1)` without ever writing a quote. The one
syntax hazard: the `=` inside `charAt=[].join` needed to be percent-encoded as `%3d`, since a literal
`=` in a URL query would be parsed as a key/value separator and split the payload in half before it
ever reached the parameter name.

## The Exploit

The full payload, delivered as a URL parameter *name* (not value):

```
toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)
```

sent as:

```
GET /?search=1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```

`fromCharCode(120,61,97,108,101,114,116,40,49,41)` decodes to the string `x=alert(1)`. Once
`charAt` is overwritten on `String.prototype`, AngularJS's sandbox check — which relies on inspecting
string content via `charAt` to decide whether an expression looks dangerous — no longer sees the
expression accurately, and `orderBy` evaluates `x=alert(1)` for each element of the `[1]` array,
executing `alert(1)`.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution is the identical payload, delivered as the identical URL, with the identical
explanation: use `toString()` to build strings without quotes, overwrite `String.prototype.charAt`
with `[].join` to break the sandbox's inspection of strings, then use `orderBy` with a
`fromCharCode`-built argument to execute `x=alert(1)`. This is a byte-for-byte match, not a case of
independently converging on the same idea — the reasoning chain is intricate enough (URL-parameter-name
injection, sandbox internals reliant on `charAt`, the specific `fromCharCode` sequence) that landing on
the exact same construction confirms we were working the same underlying mechanism PortSwigger
designed the lab around.

## What This Teaches Us

Sandboxes built by pattern-matching against dangerous-looking syntax — rather than genuinely
restricting what the underlying language can do — tend to fail against payloads built from primitives
the pattern-matcher didn't anticipate. AngularJS's sandbox assumed an attacker needed string literals
to reach `constructor`; removing quotes from the threat model didn't remove the capability, it just
required routing around string literals via `toString()` and character-code construction. The deeper
lesson specific to this lab is that the sandbox's own internal machinery — the `charAt` calls it uses
to inspect strings during its safety checks — was itself an attack surface: overwriting a prototype
method the sandbox trusted turned the sandbox's own inspection logic against it. AngularJS's
maintainers eventually addressed this by deprecating the sandbox model entirely rather than continuing
to patch individual escapes, which is the honest long-term fix for a defense built on this kind of
denylist reasoning.
