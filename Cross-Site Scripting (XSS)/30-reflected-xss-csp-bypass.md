# Reflected XSS protected by CSP, with CSP bypass

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-bypass

The final lab in the series closes the loop on a theme that's run through every CSP-related lab here:
a Content Security Policy is only as strong as the mechanism that generates it. If any part of that
policy is built from data an attacker controls, the policy itself becomes an injection point.

## The Target

A page with a genuine reflected XSS vulnerability in its search functionality — `<img src=1
onerror=alert(1)>` reflects back unescaped — protected by a CSP header that should block it outright.
Inspecting the response headers showed the policy includes a `report-uri` directive built from a
`token` query parameter: whatever value we send in `token` gets echoed directly into the
`Content-Security-Policy` header the server sends back.

## The Investigation

A `report-uri` value is just a URL the browser should POST CSP violation reports to — on its own,
completely inert from an attacker's perspective. But because the server builds that part of the header
by directly concatenating our `token` parameter into the policy string, the header itself is now
attacker-influenced text, not a fixed configuration. A CSP header is just a semicolon-separated list of
directives; if we can inject our own semicolon and directive name into the `token` value, we're not
manipulating the `report-uri` destination at all — we're adding an entirely new directive to the
policy that the browser will parse and apply exactly as if the server had configured it deliberately.

`script-src-elem` is the specific directive that governs `<script>` *elements* (as opposed to
`script-src`, which is broader and also covers things like inline event handlers depending on policy
version). Injecting `;script-src-elem 'unsafe-inline'` appends a new directive that permits inline
`<script>` tags — directly overriding whatever restriction the original policy intended — while the
already-confirmed reflected XSS in `search` supplies the payload to go into that now-permitted
`<script>` tag.

## The Exploit

Two parameters, one carrying the script payload and one carrying the CSP injection:

```
GET /?search=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'
```

sent URL-encoded as:

```
GET /?search=%3Cscript%3Ealert(1)%3C%2Fscript%3E&token=%3Bscript-src-elem%20%27unsafe-inline%27
```

The `token` value lands in the response's `Content-Security-Policy` header as an appended
`script-src-elem 'unsafe-inline'` directive, permitting inline `<script>` elements. The `search` value
lands in the page body as a literal `<script>alert(1)</script>` tag. Because the CSP now explicitly
allows inline script elements by the time the browser parses the body, the injected tag executes and
`alert(1)` fires.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution is the identical technique and an identical payload: submit
`<img src=1 onerror=alert(1)>`, observe it's reflected but blocked by CSP; inspect the response and
notice the `report-uri` directive reflects a `token` parameter; then visit
`https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=;script-src-elem%20%27unsafe-inline%27`.
Their explanation matches ours precisely: `script-src-elem` targets script elements specifically and
can override the existing `script-src` rules once injected, permitting `unsafe-inline` and letting the
injected `<script>` tag run. This is the same technique end to end, arrived at through the same
observation — a policy field built from reflected, attacker-controlled input is itself exploitable
independent of whatever XSS the policy was meant to be defending against.

## What This Teaches Us

This lab is the cleanest illustration in the whole series of a general security principle: a
defense mechanism configured from untrusted input inherits every vulnerability of untrusted input,
regardless of how effective that mechanism would be with a hardcoded configuration. CSP headers are
usually treated as static, server-controlled configuration — exactly the kind of thing developers
assume is safe from user tampering — and that assumption is precisely what made the `report-uri`
reflection dangerous here. It's also a fitting note to end the series on: every lab in this collection
came down to the same root question — where does user input land, and does anything downstream of
that landing point still trust it implicitly? Whether the answer was a JavaScript string, a DOM sink,
an AngularJS expression, a CSP header, or a form's submission target, the fix was always the same
category of discipline: never let attacker-controlled data influence a security mechanism's own
configuration, and never assume a context is safe just because it doesn't look like the one you
already defended.
