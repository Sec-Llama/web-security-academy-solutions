# DOM XSS in document.write sink using source location.search

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink

DOM-based XSS breaks the mental model the first two labs built up: there is no server-side reflection
to find, because the vulnerable data flow happens entirely inside the browser after the page has
already loaded. The payload never has to survive a server-side filter at all, since the server never
sees the dangerous part of the request the way a search parameter normally would — the client-side
JavaScript reads it straight out of the URL and writes it into the page itself. This lab is the
simplest introduction to that idea: `location.search` (an attacker-controlled source) flowing into
`document.write()` (a dangerous sink).

## The Target

The blog's search results page includes client-side JavaScript that echoes the search term back to
the user via `document.write()`, presumably to redisplay "you searched for: ..." somewhere in the
markup. A normal request looks the same as any other search:

```
GET /?search=test
```

## The Investigation

The canary reflected, but classifying the context the same way we did for the reflected-HTML lab
was misleading here. Inspecting the actual written-out markup showed the search term wasn't sitting
between two tags — it was being placed inside an `<img>` tag's `src` attribute by `document.write()`,
which is a dangerous sink because it writes raw, unparsed HTML into the document. A generic "close
the string and inject a script tag" payload wouldn't be right, because the attribute context calls
for breaking out of the attribute first, not launching straight into `<script>`.

## The Exploit

We closed the `src` attribute and the `<img>` tag, then supplied a fresh element with its own load
event:

```
"><svg onload=alert(1)>
```

Delivered as:

```
GET /?search=%22%3E%3Csvg%20onload%3Dalert(1)%3E
```

`document.write()` wrote this straight into the DOM verbatim. The `">` closed out the original `img`
tag's attribute and the tag itself, and the browser then parsed our injected `<svg onload=alert(1)>`
as a new element, firing the alert as soon as it rendered.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution walks through the same discovery process: enter a random alphanumeric string,
inspect the element to confirm it landed inside an `img src` attribute, then break out of that
attribute with `"><svg onload=alert(1)>`. This is the same payload and the same reasoning we used —
full agreement on technique. The difference is purely in tooling: their solution uses the browser's
own inspector to see where the string landed, while we fetched the rendered page and parsed the
`document.write()` output programmatically, then confirmed execution with a headless browser
listening for the alert.

## What This Teaches Us

This lab is a reminder that "where does my input land" has to be answered separately for server-side
reflection and client-side DOM writes — they can disagree, and only one of them is visible by
reading the raw HTTP response. `document.write()` is dangerous specifically because it doesn't
distinguish data from markup: whatever string it's given is parsed as HTML, attributes and all. The
fix is to avoid writing attacker-controlled data into `document.write()` (or any raw-HTML sink) at
all — if the value has to be shown, it should go through a safe DOM API like `textContent`, or be
strictly validated and encoded for the specific attribute context it's landing in.
