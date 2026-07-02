# DOM XSS via client-side prototype pollution

**Category:** Client-Side Prototype Pollution
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-via-client-side-prototype-pollution

Prototype pollution earns its place as its own vulnerability class because it breaks a
programmer's basic assumption: that an object only has the properties someone explicitly gave it.
Once `Object.prototype` itself is polluted, every object in the page — including ones the
attacker never touched directly — silently inherits the attacker's property. This lab is the
textbook demonstration of that chain: a source that lets us write to the prototype, and a gadget
that reads an unset property straight into a script's `src` attribute.

## The Target

The application is a small e-commerce search page instrumented with a client-side analytics
script, `searchLogger.js`, that logs each search term. A normal search request doesn't touch
`Object.prototype` at all — the page just needs a source that does, and a property downstream
that trusts whatever it finds there.

## The Investigation

The first step was confirming a prototype pollution source exists at all. We appended a test
property to the query string and checked whether it showed up on the global prototype:

```
/?__proto__[foo]=bar
```

Then in the console:

```javascript
Object.prototype.foo   // "bar" — confirmed
```

The query string is being parsed and recursively merged into a config object using
`__proto__` bracket notation, which is exactly the shape of a vulnerable `deparam()`-style parser.

With a working source, the next question was what property to inject. Reading `searchLogger.js`
showed the script reading `config.transport_url` and, if present, dynamically appending a
`<script>` element with that value as its `src`:

```javascript
if (config.transport_url) {
    let s = document.createElement('script');
    s.src = config.transport_url;
    document.body.appendChild(s);
}
```

`transport_url` is never given a default value anywhere in the config object, which means if it's
undefined on the object itself, JavaScript falls through the prototype chain to look for it — and
if we've polluted `Object.prototype.transport_url`, that's exactly what it finds.

## The Exploit

We polluted `transport_url` with a `data:` URL carrying our XSS payload:

```
?__proto__[transport_url]=data:,alert(1);//
```

The polluted `Object.prototype.transport_url` was inherited by `config`, `searchLogger.js` read it
as truthy, built a `<script src="data:,alert(1);//">` element, and the browser executed it as
JavaScript when the script tag loaded — firing `alert(1)` and solving the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's manual solution follows the same three-step shape we did: confirm the source with
`/?__proto__[foo]=bar` and a console check of `Object.prototype`, find the `transport_url` gadget
by reading `searchLogger.js` in the Sources tab, confirm the sink by injecting a harmless value
(`/?__proto__[transport_url]=foo`) and observing the rendered `<script src="foo">` element in the
Elements tab, then escalate to the real payload: `/?__proto__[transport_url]=data:,alert(1);`.
That's the identical gadget and effectively the identical payload we used. PortSwigger also
documents a DOM Invader path that finds the same source and gadget automatically through Burp's
built-in browser; we found both by reading the script source directly, which is the manual route
their own solution describes as the fallback when DOM Invader isn't being used.

## What This Teaches Us

This is the cleanest possible version of the client-side prototype pollution chain: a source that
writes to the prototype, and a gadget that reads a property with no default and no validation
straight into a DOM sink. Neither half is exotic — recursively merging query parameters and
dynamically loading a script from a config value are both common patterns — but combined, an
attacker who never touches the server gets arbitrary JavaScript execution purely through a URL.
The fix is standard for the whole vulnerability class: never merge untrusted input into an object
without stripping `__proto__`/`constructor`/`prototype` keys first, and never trust a property
value that could have arrived via inheritance rather than direct assignment before using it in a
sink like `script.src`.
