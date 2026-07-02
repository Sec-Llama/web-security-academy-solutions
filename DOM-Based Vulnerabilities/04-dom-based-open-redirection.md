# DOM-based open redirection

**Category:** DOM-Based Vulnerabilities
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection

Open redirects get dismissed as low-severity more often than they deserve, mostly because a bare
redirect on its own doesn't leak data or execute code. What it does is turn a link that visibly
points at a trusted domain into one that silently lands the victim somewhere else entirely — which
is precisely the ingredient a phishing campaign needs. This lab's version of the bug lives entirely
in client-side JavaScript rather than a server-side redirect, which changes how — and where — it
has to be triggered.

## The Target

The lab is a blog. Each post page has a "Back to Blog" link, and that link's behavior isn't a plain
`href` — it's driven by an `onclick` handler that reads the current page's URL, looks for a `url`
parameter, and if one is present, navigates the browser to whatever value that parameter holds
instead of back to the blog index.

## The Investigation

The handler's logic runs a regex against `location` to extract a URL-shaped `url=` parameter, then
assigns the extracted value to `location` if the match succeeds. That's the sink: a
regex-extracted, fully attacker-controlled string handed directly to a property that triggers
navigation, with no check on what domain it points to. Since the extraction reads directly from
`location` rather than from a server-rendered value, the server never has to see or process
anything malicious — the entire vulnerable data flow is a query parameter the browser parses on its
own.

The complication is *how* this fires. Unlike the previous three labs, there's no `postMessage()`
delivery step and no exploit-server-hosted page doing the work automatically — the vulnerable code
only runs inside an `onclick` handler, meaning it executes only when a user actually clicks the
link. A plain HTTP GET to the crafted URL, the kind an `httpx` client sends, loads the page and
parses the JavaScript, but never fires a click event — there's no browser executing a real click
gesture, so the redirect logic inside `onclick` simply never runs. Confirming this lab's solve
condition genuinely required a browser actually clicking the link, not just requesting the URL.

## The Exploit

`craft_open_redirect_url()` builds the crafted link — it's not an HTML exploit page at all here,
just a URL:

```
https://TARGET/post?postId=4&url=https://EXPLOIT-SERVER/
```

Visiting this URL puts the "Back to Blog" link's `onclick` handler in a state where its regex will
match our injected `url` parameter. When that link is clicked, the handler's regex extracts
`https://EXPLOIT-SERVER/` from the current location and assigns it, redirecting the browser away
from the blog entirely and onto infrastructure we control — proof the lab's solve condition
(reaching the exploit server via this redirect) was met.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution constructs the identical URL — `postId=4` with a `url` parameter pointing at
the exploit server — and describes the same underlying flaw: the "Back to Blog" link extracts a
`url` value from `location` via regex and assigns it to `location.href` on click. There's no
technique divergence in the payload itself; both approaches are exactly "append the right query
parameter."

Where this lab differs from the exploit-server-driven labs earlier in this series is delivery.
PortSwigger's instructions have you visit the crafted URL and click the link yourself inside Burp's
built-in browser. Our own `DOMBased.py` wrapper documents the same constraint explicitly: it
constructs the redirect URL and prints instructions to visit it and click the link, because an
automated `httpx` GET against that URL — while it does load the page — cannot dispatch the click
event the `onclick` handler is waiting for. Confirming this one actually solved required real
browser interaction rather than a scripted request, which is a meaningfully different execution
path from the three postMessage labs before it, even though the vulnerable pattern (attacker data
reaching a navigation sink) is the same family of bug.

## What This Teaches Us

The vulnerability is a straightforward case of trusting a URL parameter as a redirect destination
without validating it against an allow-list of known-safe domains — the same root cause behind
every open redirect regardless of whether the redirect logic lives on the server or, as here, in
client-side JavaScript. What's specific to the DOM-based version is the execution model: because
the flaw lives inside an event handler rather than a page-load script, exploiting it in the real
world requires getting a victim to actually interact with the page (click a link, in this case),
which is a meaningfully higher bar for an attacker than a page-load-triggered DOM XSS, but not a
bar that's hard to clear — a phishing email linking directly to the crafted URL with instructions
to "go back to the blog" would do it. The fix is the same one that applies to every open redirect:
validate the destination against a fixed allow-list of permitted paths or domains before ever
assigning it to a navigation property.
