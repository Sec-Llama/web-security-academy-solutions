# Reflected XSS with event handlers and href attributes blocked

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-event-handlers-and-href-attributes-blocked

Blocking every `on*` event attribute and every `href` value that starts with `javascript:` covers the
two most obvious ways to get script execution out of an anchor tag. It doesn't cover SVG's animation
elements, which can rewrite another element's attributes dynamically at runtime — including `href` —
without ever writing the word `href=` themselves.

## The Target

A page whose filter allows a permissive set of tags through but strips every event-handler attribute
and blocks any `href` value using the `javascript:` scheme. That closes off both the "event handler
fires the alert" pattern from most of the earlier labs and the "javascript: URL in an anchor" pattern
from the href-attribute labs.

## The Investigation

SVG's `<animate>` element exists specifically to animate an attribute of a target element over time,
and it identifies which attribute to animate through its own `attributeName` attribute — not through a
literal `href=` on the target tag. That's the gap: a filter looking for the literal string `href=` to
block or sanitize won't recognize `attributeName=href` as equivalent, even though the browser resolves
it to exactly the same effect — SVG's `<animate>` sets the named attribute on its parent element to the
values given, `javascript:alert(1)` included, entirely dynamically and with no event-handler attribute
anywhere in the markup.

The remaining problem was triggering navigation without an `onclick` handler to fire it — SVG anchors
still require a click like any other link, and PortSwigger's simulated victim user only interacts with
elements it can identify as clickable by their visible text. Labeling the clickable text "Click me"
inside an SVG `<text>` element satisfies that requirement.

## The Exploit

```
<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a></svg>
```

sent as:

```
GET /?search=%3Csvg%3E%3Ca%3E%3Canimate%20attributeName%3Dhref%20values%3Djavascript%3Aalert(1)%20%2F%3E%3Ctext%20x%3D20%20y%3D20%3EClick%20me%3C%2Ftext%3E%3C%2Fa%3E%3C%2Fsvg%3E
```

The `<animate>` element inside the SVG `<a>` sets that anchor's `href` to `javascript:alert(1)` as soon
as the SVG renders — no `href=` literal, no event-handler attribute, nothing the filter's blocklist was
watching for. We delivered the payload and, since no exploit server was available in our run, drove a
headless browser directly to the crafted URL and clicked the rendered "Click me" text, which navigated
the `javascript:` href and fired `alert(1)`.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the identical payload:
`https://YOUR-LAB-ID.web-security-academy.net/?search=%3Csvg%3E%3Ca%3E%3Canimate+attributeName%3Dhref+values%3Djavascript%3Aalert(1)+%2F%3E%3Ctext+x%3D20+y%3D20%3EClick%20me%3C%2Ftext%3E%3C%2Fa%3E`,
with the same underlying mechanism: SVG's `<animate>` can dynamically assign the `href` attribute of
its parent `<a>` without the filter ever seeing a literal `href=` to block, and the "Click me" label
induces the platform's simulated user to trigger it. This matches our approach exactly — same tag
structure, same `attributeName=href` trick, same click-bait text. The only operational difference is
delivery: PortSwigger's walkthrough is a direct browser visit to the crafted URL, and our run used a
headless browser to navigate and click programmatically rather than relying on an exploit-server
redirect, since none was available in that pass.

## What This Teaches Us

Filtering by looking for a literal attribute name in the markup assumes attributes only get set the
way they're written — as a literal `attr=value` pair in the tag itself. SVG's animation elements break
that assumption structurally: `<animate>`, `<set>`, and their relatives are designed to modify a target
element's attributes at runtime, addressed by name through a separate attribute (`attributeName`)
rather than by writing the target attribute directly. Any filter that pattern-matches on attribute
names as literal text in the submitted markup will miss every one of these indirect assignment
vectors. The durable fix, consistent with the rest of this series, is allow-listing a minimal safe set
of tags with no capacity for dynamic attribute manipulation at all, rather than trying to enumerate
every syntactic form a dangerous attribute value could take.
