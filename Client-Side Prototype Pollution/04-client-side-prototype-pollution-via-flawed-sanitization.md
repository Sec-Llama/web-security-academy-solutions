# Client-side prototype pollution via flawed sanitization

**Category:** Client-Side Prototype Pollution
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-client-side-prototype-pollution-via-flawed-sanitization

Once a team knows prototype pollution is a risk, the obvious fix is to strip dangerous keys like
`__proto__` out of user input before merging it into an object. This lab shows exactly how that
fix goes wrong when it's implemented as a single string-replace instead of a proper recursive
sanitizer — and the bypass technique it demonstrates (nesting the blocked string inside itself) is
one of the most broadly reusable filter-evasion tricks in this vulnerability class.

## The Target

The same search-tracking storefront, now defending its query-string parser. The straightforward
sources from the earlier labs in this series — `?__proto__[foo]=bar` and `?__proto__.foo=bar` —
were the first things we tried here, on the assumption the developers hadn't patched anything yet.

## The Investigation

Both of the standard sources failed:

```
/?__proto__[foo]=bar
/?__proto__.foo=bar
```

`Object.prototype.foo` stayed `undefined` after both. We also tried the constructor-based vector
as a third option (`?constructor.prototype.foo=bar`), which also failed. That ruled out a missing
filter and pointed toward an active one.

Reading the page's scripts, `deparamSanitized.js` calls a `sanitizeKey()` function (defined in
`searchLoggerFiltered.js`) that strips dangerous substrings — `__proto__`, `constructor`,
`prototype` — from each key before the merge happens. The critical detail was *how* it strips
them: a single, one-time string replacement rather than a loop that re-checks the result. That's
the classic non-recursive sanitization bug, and it has a well-known bypass — wrap the blocked
string inside a second copy of itself, so that removing the *inner* occurrence leaves the *outer*
one intact:

```
__pro__proto__to__
```

Strip the inner `__proto__` (the middle six characters of this string, `proto__`, form the actual
substring the filter targets once you account for how it's embedded) and what remains reassembles
into `__proto__`. We tested this against the query string:

```
/?__pro__proto__to__[foo]=bar
```

`Object.prototype.foo` came back `"bar"` — the sanitizer had been bypassed. With a working source
again, the gadget was the same `transport_url`-into-`script.src` pattern from the earlier DOM XSS
lab in this series: `searchLogger.js` reads `config.transport_url` with no default set, and uses
it to build a dynamically injected `<script>` tag.

## The Exploit

We combined the sanitization bypass with the known `transport_url` gadget:

```
?__pro__proto__to__[transport_url]=data:,alert(1);//
```

After the sanitizer stripped the inner `__proto__` from our key, the surviving `__proto__[transport_url]`
polluted the prototype exactly as in the unfiltered lab. `searchLogger.js` picked up the inherited
`transport_url`, injected a `<script src="data:,alert(1);//">`, and the payload fired.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows an identical diagnostic path: try `__proto__[foo]=bar`, then
`__proto__.foo=bar`, confirm both fail, then read `deparamSanitized.js`/`searchLoggerFiltered.js`
and note that `sanitizeKey()` "does not apply this filter recursively." Their bypass list offers
four equivalent nested forms — `__pro__proto__to__[foo]=bar`, `__pro__proto__to__.foo=bar`, and two
`constconstructorructor`/`protoprototypetype` variants targeting the constructor vector instead —
any of which restore a valid pollution key once the single-pass filter strips the embedded copy.
We used the same `__pro__proto__to__` form they lead with. The gadget and final payload
(`/?__pro__proto__to__[transport_url]=data:,alert(1);`) match ours exactly in substance; the only
difference is the trailing `//` we added as a defensive habit versus their bare `;`.

## What This Teaches Us

Non-recursive string sanitization is bypassable by construction, not by luck: if a filter removes
a substring once and stops, embedding the substring inside itself guarantees a surviving copy
after exactly one removal pass. This applies far beyond `__proto__` — any blocklist-based sanitizer
that does a single `.replace()` instead of looping until no more matches are found has the same
hole. The durable fix for prototype pollution specifically isn't a smarter key filter at all; it's
removing the trust relationship entirely, e.g. parsing untrusted input with `Object.create(null)`
or a `Map` so there's no prototype for a filter to protect in the first place.
