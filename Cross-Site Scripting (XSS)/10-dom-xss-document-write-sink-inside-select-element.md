# DOM XSS in document.write sink using source location.search inside a select element

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element

We've already exploited a `document.write()` sink fed by `location.search` earlier in this series —
what makes this lab different, and a step up to Practitioner difficulty, is *where* inside the
written markup our value lands: nested inside a `<select>` element's `<option>` list, one of the more
awkward HTML contexts to break out of cleanly, since `<option>` tags have unusually permissive
parsing rules.

## The Target

A product page includes a stock-checker widget: a dropdown of store locations built via
`document.write()`, populated in part from a `storeId` query parameter. A normal request looks like:

```
GET /product?productId=1&storeId=1
```

## The Investigation

We supplied a random alphanumeric string as `storeId` and inspected the rendered page: our string
showed up as a new `<option>` entry in the dropdown, confirming the sink was writing it inside a
`<select>` block rather than into a standalone attribute or the page body. That's a more constrained
context than the earlier `document.write()` lab — we're nested inside `<select><option>...</option>`
markup, and simply appending an `<img onerror=...>` tag wouldn't necessarily execute, since browsers
apply special, more permissive parsing rules inside `<select>`/`<option>` that can swallow or
misinterpret arbitrary child markup. The reliable path is to explicitly close out of both the
`<option>` and the `<select>` first, so the rest of our payload is parsed as ordinary top-level HTML
rather than as select-list content.

## The Exploit

We closed the option and select elements before injecting the event-handler payload:

```
</option></select><img src=1 onerror=alert(1)>
```

Delivered as:

```
GET /product?productId=1&storeId=%3C%2Foption%3E%3C%2Fselect%3E%3Cimg%20src%3D1%20onerror%3Dalert(1)%3E
```

`document.write()` wrote this directly into the DOM. The `</option></select>` closed out of the
dropdown's constrained parsing context, and the browser then parsed our `<img src=1 onerror=alert(1)>`
as ordinary markup outside the select list, firing `onerror` on the broken image immediately.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the identical construction: notice the `storeId` parameter lands
inside a `<select>` option, then supply
`product?productId=1&storeId="></select><img%20src=1%20onerror=alert(1)>` (their version includes a
leading `">` to close the option's own attribute context before closing the tags, versus a plain
`</option></select>` prefix in ours). Both close out of the select-list nesting before dropping in
the same `<img onerror>` payload — the underlying technique is identical, and the small textual
difference in the closing sequence reflects the exact attribute structure PortSwigger observed versus
what our own probing confirmed, not a different approach. The delivery difference is the usual one:
manual URL editing in their walkthrough versus a direct HTTP request plus headless-browser trigger in
ours.

## What This Teaches Us

Nested markup contexts need their own escape sequence, not just a generic "close the tag" reflex —
`<select>`/`<option>` parsing is permissive enough that a naive injection can land inside the dropdown
without ever executing, which is exactly the kind of near-miss that makes manual inspection of the
actual rendered DOM (not just the raw response text) essential before crafting a payload. The
underlying flaw is the same `document.write()`-plus-`location.search` pattern as before, and the fix
is unchanged — don't feed attacker-controlled data into a raw-HTML sink — but this lab is a good
demonstration that "the sink is dangerous" and "I know the exact payload that will work in it" are
two separate questions, and the second one depends on precisely where in the markup structure the
injection point sits.
