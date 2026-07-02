# DOM XSS via an alternative prototype pollution vector

**Category:** Client-Side Prototype Pollution
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-via-an-alternative-prototype-pollution-vector

The bracket-notation `__proto__[prop]=value` source is the first thing anyone tests for prototype
pollution, which makes it the first thing developers patch against. This lab makes that patch
irrelevant by using a different parser with a different notation, and then adds a second
complication once the source is found: the sink doesn't just execute our payload, it silently
appends a character to it first. Getting alert() to fire here meant reasoning about exactly what
that appended character would do to our JavaScript.

## The Target

Same search-tracking storefront, different logging script — `searchLoggerAlternative.js` this
time. The lab title's "alternative vector" turned out to mean two things at once: an alternative
source notation, and an alternative sink (`eval()` rather than `script.src`).

## The Investigation

Our first probe was the bracket-notation source that worked on the previous lab:

```
/?__proto__[foo]=bar
```

Checking `Object.prototype.foo` in the console came back `undefined` — bracket notation didn't
pollute anything here. That ruled out one parser but not prototype pollution generally, so we
tried dot notation instead:

```
/?__proto__.foo=bar
```

This time `Object.prototype.foo` returned `"bar"`. The page's parser (a jQuery-style
`$.parseParams`-equivalent) handles nested dot-separated keys but not bracket syntax — the same
functional vulnerability, reached through a different query-string grammar.

With the source confirmed, we read `searchLoggerAlternative.js` and found an `eval()` call built
around a `manager.sequence` property:

```javascript
eval('if(manager && manager.sequence){ manager.macro(' + manager.sequence + ') }');
```

`manager.sequence` isn't set anywhere by default, so polluting `Object.prototype.sequence` should
land directly inside an `eval()` call — about as direct a sink as prototype pollution gets. Our
first attempt, though, was more complicated than expected:

```
?__proto__.sequence=alert(1)
```

This didn't fire. Stepping through in the debugger showed why: the actual value reaching `eval()`
wasn't `alert(1)` but `alert(1)1` — the application appends a `1` to whatever `manager.sequence`
holds before using it (part of a sequencing counter, evidently — the surrounding logic reads
something like `let a = manager.sequence || 1; manager.sequence = a + 1;`). `alert(1)1` is not
valid JavaScript syntax, so the call silently failed.

## The Exploit

The fix was to make the appended `1` land somewhere syntactically harmless rather than fight the
append. We closed our payload with a trailing minus sign:

```
?__proto__.sequence=alert(1)-
```

After the application's own concatenation, this becomes `alert(1)-1` — a perfectly valid
JavaScript expression: call `alert(1)`, which returns `undefined`, then evaluate
`undefined - 1`, which is `NaN`. The subtraction never throws; it just quietly produces `NaN` and
gets discarded. `alert(1)` fires along the way, and the lab was solved.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's manual solution walks the identical path: confirm bracket notation fails, confirm
dot notation (`/?__proto__.foo=bar`) works, find the `eval()` sink and the unset `manager.sequence`
property in `searchLoggerAlternative.js`, then try the naive `?__proto__.sequence=alert(1)` and
watch it fail. Their write-up describes setting a breakpoint on the `eval()` line and hovering over
`manager.sequence` to observe it evaluates to `alert(1)1` — exactly the numeric-append behavior we
diagnosed — and lands on the same fix: a trailing `-` so the appended `1` becomes valid subtraction
syntax rather than a syntax error. This is a case where our reasoning and PortSwigger's converge on
the identical payload and the identical justification for it; the only difference is that their
walkthrough drives the discovery through Burp's browser DevTools step by step, while we drove it
through direct source reading and console checks.

## What This Teaches Us

Two lessons stack in this lab. First, a source-detection routine that only tries one notation
(bracket) will miss vulnerable parsers that only accept another (dot) — testing prototype
pollution sources means trying multiple grammars, not just the most common one. Second, when a
sink transforms your payload before using it — here, string-concatenating a counter onto whatever
you inject — the fix isn't to fight the transformation, it's to make your payload syntactically
valid *after* it happens. A trailing arithmetic operator is a small trick, but it's the difference
between a gadget that looks unreachable and one that's fully exploitable.
