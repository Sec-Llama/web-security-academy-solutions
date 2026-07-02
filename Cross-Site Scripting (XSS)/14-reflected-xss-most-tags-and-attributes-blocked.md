# Reflected XSS into HTML context with most tags and attributes blocked

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked

Every lab up to this point relied on a single well-known tag or attribute — `<script>`, `onmouseover`,
`javascript:`. This lab takes those away with a real filter that blocks most of the standard XSS
toolkit, which means the actual challenge shifts from "know a payload" to "discover what the filter
still allows." That's a much more realistic simulation of what testing a hardened application looks
like — you don't get a filter's source code, you get its behavior under systematic probing.

## The Target

The same search functionality, now backed by a filter that rejects most tags and most event-handler
attributes outright — submitting an obvious payload like `<img src=1 onerror=alert(1)>` gets blocked
rather than reflected.

## The Investigation

Confirming the filter existed was trivial — a standard payload came back rejected. Figuring out what
*was* allowed required systematic enumeration rather than guesswork. We used the PortSwigger XSS
cheat sheet's list of tags as a fuzzing wordlist against the `search` parameter, sending each
candidate tag through and checking whether the response indicated it was blocked or accepted. That
process surfaced `<body>` as one of the few tags the filter let through. The same fuzzing approach
against the cheat sheet's list of event-handler attributes, this time using `<body>` as the carrier
tag, surfaced `onresize` as an allowed event.

`onresize` doesn't fire under normal circumstances, though — a `<body>` tag rendered directly in a
tab doesn't get resized by the user. The reliable way to trigger it is to load the vulnerable page
inside an `<iframe>` on an attacker-controlled page and then resize the iframe itself via script,
which fires `onresize` on the embedded document without requiring the victim to do anything.

## The Exploit

We built the payload once the two allowed primitives were confirmed:

```
<body onresize=print()>
```

and delivered it via an iframe that resizes itself immediately after loading:

```html
<iframe src="https://LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload="this.style.width='100px'"></iframe>
```

Storing and delivering this via the exploit server: the iframe loads the lab page with the payload in
`search`, and its own `onload` handler immediately shrinks the iframe's width, which fires the
embedded page's `body onresize` handler and executes `print()`.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows essentially the same fuzzing methodology, but drives it through Burp
Intruder rather than a scripted loop: inject `<>` with a payload position between the brackets, paste
the cheat sheet's tag list as the payload set, and look for the one response that returns `200`
instead of `400` — landing on `body`. Then repeat the same Intruder sweep with the cheat sheet's event
list against `<body %s=1>`, landing on `onresize`. The discovered primitives and the final iframe
delivery payload match ours exactly. The only real difference is the fuzzing engine: Burp Intruder's
payload-position UI versus our own scripted enumeration against the cheat sheet lists — functionally
the same brute-force-the-allow-list technique, different tooling.

## What This Teaches Us

Blocklist-style XSS filters — reject known-dangerous tags and attributes — are inherently a losing
proposition, because the "known-dangerous" set is neither exhaustive nor stable. `<body onresize>` is
a legitimate, rarely-considered combination that most blocklists miss precisely because it isn't part
of the handful of tags people usually think to test for XSS. Systematic enumeration against the full
HTML tag and event-attribute surface is what actually reveals these gaps, which is why the XSS cheat
sheet's tag/event lists exist as fuzzing wordlists in the first place. The real fix isn't a better
blocklist — it's switching to an allow-list of specific safe tags with no event-handler attributes
permitted at all, combined with proper output encoding, since no blocklist can keep pace with the
full combinatorial space of HTML tags and their associated events.
