# DOM XSS using web messages and JSON.parse

**Category:** DOM-Based Vulnerabilities
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-json-parse

The first two labs in this series had a message handler that treated the raw string it received as
the payload. This one adds a layer of structure — the handler expects JSON, parses it, and
branches on a `type` field before doing anything dangerous. Structure alone doesn't make an input
safe; it just changes what the attacker's string has to look like. This lab turned out to be more
interesting for a reason that had nothing to do with the target at all: getting our own exploit
payload to survive three layers of string quoting.

## The Target

The home page's message listener expects a JSON-encoded string. Once parsed, the handler switches
on a `type` property; a `"load-channel"` type causes it to read a `url` property from the same
object and assign it to an iframe's `src` attribute. Functionally, this looks like a legitimate
"load this embedded channel" feature — the kind of thing a page embedding third-party widgets might
build.

## The Investigation

`detect_dom_sinks()` confirmed the message listener on the home page. The sink here is less
obvious from a pure regex scan than the previous two labs — it isn't a direct `location.href =` or
`.innerHTML =` on the message data itself, it's an `iframe.src` assignment reached after a
`JSON.parse()` and a `switch` statement. The taint path is: `postMessage` data -> `JSON.parse` ->
object property `.url` -> `iframe.src`. Since `iframe.src` accepts `javascript:` URLs the same way
`location.href` does, this reduces to the same underlying primitive as the previous lab — we just
have to get our payload through a JSON parse and a property match first, which means our injected
value has to be valid JSON, and the `type` field has to be exactly `"load-channel"` to reach the
vulnerable branch.

The genuinely hard part wasn't the target's logic — it was the payload construction on our own
side. The exploit needs to nest three separate quoting contexts inside one string: HTML attribute
quoting (the iframe's `onload="..."` attribute), JavaScript string quoting (the argument to
`postMessage()`), and JSON's own double-quote requirement for both keys and values. Escaping all
three correctly inside a single inline `onload` attribute value is exactly the kind of thing that
looks fine until the browser's HTML parser, then its JS parser, then `JSON.parse()` each interpret
the escaping differently. Rather than fight that by hand, we sidestepped it: `craft_web_message_json()`
builds the exploit page using a `<script>` block instead of an inline `onload` handler, which
removes the HTML-attribute quoting layer from the problem entirely — inside a `<script>` tag,
there's no HTML attribute to escape out of, so only the JS-string/JSON nesting remains, and that's
solvable with a single level of quote-escaping (`json_str.replace("'", "\\'")`).

## The Exploit

The generated exploit page:

```html
<iframe src="https://TARGET/" id="jsonframe"></iframe>
<script>
  window.addEventListener("load", function() {
    document.getElementById('jsonframe').contentWindow.postMessage('{"type":"load-channel","url":"javascript:print()"}', '*');
  });
</script>
```

Delivered through the exploit server's store/deliver mechanism, the victim's browser loads the
iframe, then the page's own `load` event fires our script, which posts the JSON string
`{"type":"load-channel","url":"javascript:print()"}` to the iframe's content window. The home
page's handler parses that JSON, matches the `"load-channel"` case, and sets the iframe's `src` to
our `url` value — `javascript:print()` — which the browser evaluates immediately as a `javascript:`
navigation, executing `print()`.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same JSON payload and the same underlying flaw — a `type`/`url`
JSON object routed through `JSON.parse()` into an `iframe.src` sink — but it takes the inline
`onload` route we specifically avoided:

```html
<iframe src=https://YOUR-LAB-ID.web-security-academy.net/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
```

That string is exactly the triple-quoting problem described above, solved by backslash-escaping
the inner JSON double-quotes and switching the outer JS string delimiter to double quotes while the
HTML attribute itself uses single quotes. It works, but it's fragile in the way hand-escaped nested
quoting always is — one wrong escape level and the HTML parser, JS parser, or `JSON.parse()` call
breaks silently. Our `<script>`-tag approach reaches the identical wire payload without needing
three coordinated quoting conventions in a single attribute string, which is a meaningfully
different construction even though the exploited vulnerability and the final JSON payload are the
same.

## What This Teaches Us

On the target side, this lab teaches the same lesson as the previous one wearing a JSON costume:
parsing input into a structured object doesn't validate the *values* inside that object, and
`iframe.src` is just as dangerous a sink for a `javascript:` URL as `location.href` is. The fix is
identical — validate `event.origin`, and if a URL value from an untrusted message must be used at
all, parse it and check its protocol explicitly rather than trusting whatever string arrives.

On our own side, this lab was a reminder that when an exploit payload requires nesting multiple
quoting/escaping contexts, restructuring the delivery mechanism to eliminate one of those contexts
is often more reliable than getting the escaping exactly right — a `<script>` block sidesteps the
HTML-attribute layer entirely rather than fighting it.
