# Reflected XSS into attribute with angle brackets HTML-encoded

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded

The first reflected lab in this series had no encoding at all, so a plain `<script>` tag was enough.
This lab adds the first real defense we've seen: angle brackets are HTML-encoded before the value is
reflected. That single change breaks every payload that depends on injecting a new tag — but it
doesn't help if the value is landing *inside* an existing tag's attribute rather than between tags,
because an attacker doesn't need a new tag if they can add a new attribute to one that's already
there.

## The Target

The same search functionality as the earlier labs, but this time the search term is reflected as the
value of an existing HTML attribute — an input field's `value`, based on where the response placed
our probe string — rather than as text between tags.

## The Investigation

We submitted a canary string and confirmed it was reflected, then probed with angle brackets and a
double quote to see what the application does to each. The angle brackets came back as `&lt;`/`&gt;`
in the response — confirmed encoding, meaning `<script>` or any new-tag payload was off the table.
The double quote, however, came back completely unescaped. That's the key detail: if the reflection
point is inside a double-quoted attribute and the quote character itself isn't touched, we don't need
angle brackets to break out — we just need to close the current attribute with a quote and open a new
one.

## The Exploit

We closed the existing attribute and added a new event-handler attribute in its place:

```
" onmouseover="alert(1)
```

Delivered as:

```
GET /?search=%22%20onmouseover%3D%22alert(1)
```

This turns the tag's opening from `<input value="INPUT">` into
`<input value="" onmouseover="alert(1)">` — a syntactically valid tag with a brand-new `onmouseover`
handler attached. No angle brackets were needed anywhere in the payload, so the encoding never came
into play.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same payload through the same reasoning: submit a random string,
observe it lands inside a quoted attribute, then replace it with `"onmouseover="alert(1)` to escape
the attribute and inject an event handler, verifying by moving the mouse over the element to trigger
`onmouseover`. This matches our approach exactly — same injection point, same technique, same
payload. The one operational difference is how we confirmed execution: `onmouseover` requires an
actual mouse event, so PortSwigger's manual walkthrough triggers it by hovering in the browser, while
our automated pipeline used `craft_xss_payload()`'s attribute-context branch, which defaults to
`autofocus`/`onfocus` specifically because that pair fires immediately on page load without any
simulated mouse movement — a small but deliberate adaptation for headless automation.

## What This Teaches Us

Encoding one dangerous character class doesn't close off every path into the page — it closes off
the specific technique that character enables. Angle-bracket encoding stops an attacker from
introducing a *new tag*, but it says nothing about attribute boundaries, and an attacker who can add
attributes to an *existing* tag has just as much reach as one who can add a whole new element, since
event-handler attributes execute arbitrary JavaScript. The actual fix has to encode every character
that has meaning in the attribute's context — angle brackets for tag structure, but also the quote
character delimiting the attribute itself — or better, avoid string-concatenating user input into
attribute values at all in favor of a templating system that encodes correctly for whichever context
the value lands in.
