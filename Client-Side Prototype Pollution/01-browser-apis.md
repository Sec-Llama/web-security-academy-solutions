# Client-side prototype pollution via browser APIs

**Category:** Client-Side Prototype Pollution
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/prototype-pollution/client-side/browser-apis/lab-prototype-pollution-client-side-prototype-pollution-via-browser-apis

Prototype pollution is a strange kind of bug: on its own, adding a property to `Object.prototype`
does nothing observable at all. The danger only shows up once some other piece of code — a
"gadget" — reads that property back without checking whether it was ever meant to be set. This
lab is built around a gadget that PortSwigger's own research team found lurking in a pattern
JavaScript developers use constantly: hardening an object property with `Object.defineProperty()`.
Get the descriptor wrong in one specific way, and the hardening becomes the vulnerability.

## The Target

The lab is the same search-tracking storefront used across this series — a page that logs search
queries via a small `searchLoggerConfigurable.js` script. According to the lab description, the
developers had "noticed a potential gadget and attempted to patch it," which told us before we'd
even opened DevTools that this lab's story is about a defense that looks solid but isn't.

## The Investigation

We started with the standard prototype pollution source check: appending `?__proto__[foo]=bar`
to the URL and inspecting `Object.prototype` in the console afterward. It came back polluted,
confirming a URL-query source exists — the same recursive-merge pattern (via `deparam()`-style
parsing) seen in the other labs in this series.

With a confirmed source, the question became which property to pollute. Reading through
`searchLoggerConfigurable.js`, we found the script setting a `transport_url` property on its
`config` object — the same gadget property from the more basic DOM XSS lab in this series — and
then immediately calling `Object.defineProperty()` on it:

```javascript
Object.defineProperty(config, 'transport_url', {
    configurable: false,
    writable: false
});
```

This is a deliberate attempt to lock `transport_url` down after it's set, so an attacker can't
simply overwrite it. But the descriptor object passed to `defineProperty()` only specifies
`configurable` and `writable` — it never specifies `value`. A property descriptor is itself a
plain object, and plain objects inherit from `Object.prototype`. Any key the descriptor doesn't
set explicitly — including `value` — falls through to whatever is sitting on the prototype chain.
That means polluting `Object.prototype.value` reaches into the descriptor and supplies the
`transport_url` value the developers thought they'd frozen shut.

## The Exploit

We polluted the `value` property and let it flow through the descriptor into `transport_url`,
which the script uses as the `src` of a dynamically appended `<script>` element:

```
?__proto__[value]=data:,alert(1);//
```

Navigating to that URL polluted `Object.prototype.value`, which the unset `value` key in the
`Object.defineProperty()` descriptor inherited, which set `transport_url` to our `data:` URL,
which the script tag loaded as its `src` — firing `alert(1)` and solving the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's manual solution reaches the identical gadget: it walks through finding the same
`?__proto__[foo]=bar` source, then inspecting `searchLoggerConfigurable.js` in DevTools' Sources
tab and noticing that the `Object.defineProperty()` call locking down `transport_url` "doesn't
define a `value` property." Their exploit payload is `/?__proto__[value]=data:,alert(1);` —
functionally the same string we used, differing only in that we appended a trailing `//` comment
marker as a defensive habit rather than out of necessity here. PortSwigger also documents a
second path using DOM Invader to find and confirm the same gadget automatically; we identified it
by reading the script source directly, which is the manual technique their own write-up describes
as the alternative to DOM Invader.

This lab is also a rare case where PortSwigger names the real-world research behind it directly:
the lab description links to Gareth Heyes' "Widespread prototype pollution gadgets" research,
which is exactly the class of bug being demonstrated — `Object.defineProperty()` calls that
protect a property's writability but never pin down its value.

## What This Teaches Us

The instinct to "lock down" a sensitive property with `Object.defineProperty()` is good security
hygiene against direct overwrites, but it only closes half the door. `configurable: false` and
`writable: false` stop an attacker from reassigning `transport_url` directly — but if the
descriptor never states `value` explicitly, the property still needs to get its value from
somewhere, and that somewhere is the prototype chain. The fix isn't more defensive flags on the
descriptor; it's supplying an explicit `value` (or `get`/`set`) in every `defineProperty()` call,
so there's nothing left for a polluted prototype to fill in.
