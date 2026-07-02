# Clobbering DOM attributes to bypass HTML filters

**Category:** DOM-Based Vulnerabilities
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-clobbering-attributes-to-bypass-html-filters

The previous lab clobbered a plain JavaScript variable. This one goes a level deeper and clobbers a
property that a sanitizer library relies on internally to do its own filtering — which means the
target of the attack isn't the application's business logic at all, it's the sanitizer's own
iteration code. If you can make a sanitizer's loop silently stop iterating, everything downstream
of that loop is unfiltered by definition.

## The Target

The same comment system as the previous lab, but sanitized with a different library — HTMLJanitor,
configured with an explicit allow-list: `{tags: {input:{name:true,type:true,value:true},
form:{id:true}, i:{}, b:{}, p:{}}}`. That configuration permits `<form>` elements (with only an
`id` attribute) and `<input>` elements (with `name`, `type`, `value`), but nothing that would
obviously allow an event handler like `onfocus` to survive.

## The Investigation

HTMLJanitor's filtering works by walking each element's `attributes` property — the standard
`NamedNodeMap` every DOM element exposes — and removing any attribute not present in that
element's allow-list entry. That's a reasonable implementation, except that `attributes` is itself
just a named property on the element, and HTML has a well-known quirk where child elements with an
`id` or `name` attribute shadow their parent's own built-in named properties. A `<form>` containing
`<input id=attributes>` causes `form.attributes` to resolve to that `<input>` element instead of
the form's actual `NamedNodeMap` — the child element's `id` clobbers the parent's built-in property
the same way the previous lab's anchors clobbered a `window` global.

That clobbered reference breaks the sanitizer's iteration in a specific, exploitable way. Whatever
loop condition HTMLJanitor uses to know how many attributes to check — something in the shape of
`for (let i = 0; i < node.attributes.length; i++)` — now evaluates `node.attributes` as the clobbered
`<input>` element rather than a `NamedNodeMap`, and an `HTMLInputElement` has no `.length` property
at all. `.length` on the clobbered reference is `undefined`, and `0 < undefined` evaluates to
`false` in JavaScript, so the loop condition is false from the very first check. The sanitizer's
attribute-removal loop for that `<form>` element never runs a single iteration, and every attribute
on the form — including ones the allow-list would never have permitted — survives untouched.

The remaining question was how to actually *trigger* whatever attribute we smuggled through,
without JavaScript execution to fire it directly. `onfocus` answers that: an element gains focus,
and its `onfocus` handler fires, when the browser navigates to a URL fragment matching that
element's `id` — provided the element is focusable, which a `tabindex` attribute grants it. That
gave us a delivery mechanism that needs no script injection of its own: an exploit-server iframe
that loads the comment page, waits for the comment (and our clobbering form) to be present in the
DOM, then updates its own `src` to add a `#x` fragment, which the browser resolves by focusing the
element with `id=x` — our clobbered form.

## The Exploit

The comment posted to trigger the clobbering, from `craft_dom_clobbering_attributes_bypass()`:

```html
<form id=x tabindex=0 onfocus=print()><input id=attributes></form>
```

Delivered via an exploit-server page:

```html
<iframe src="https://TARGET/post?postId=N" onload="setTimeout(()=>this.src='https://TARGET/post?postId=N#x',500)"></iframe>
```

The `setTimeout` delay of 500ms exists to let the initial page load — including our injected
comment — finish rendering before the iframe's `src` is updated with the `#x` fragment; without
that delay, the fragment navigation could race the comment content actually being present in the
DOM. Once the fragment navigation happens, the browser focuses the `<form id=x>` (focusable because
of `tabindex=0`), and because HTMLJanitor's clobbered attribute-removal loop never stripped
`onfocus` from the form, that handler fires and calls `print()`.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses the identical clobbering payload —
`<form id=x tabindex=0 onfocus=print()><input id=attributes>` — and the identical delivery
mechanism: an exploit-server iframe that loads the post, then after a delay appends a `#x` fragment
to trigger focus. Their version of the iframe writes the fragment append slightly differently
(`this.src=this.src+'#x'` versus our explicit reconstruction of the full URL with `#x` appended),
but both perform the same operation — take the iframe's current `src` and append the fragment — so
the two are functionally identical. As with the DOM clobbering lab before it, this is a case where
the underlying browser/sanitizer interaction is specific enough that there's essentially one
working payload shape, and both approaches land on it.

The recurring pattern across this whole lab series holds here too: our version drives the comment
posting through a direct HTTP request to `/post/comment` and the exploit delivery through the
exploit server's HTTP endpoint, where PortSwigger's walkthrough has you type the comment into the
form and click through the exploit server's UI.

## What This Teaches Us

This lab generalizes the previous one's lesson in a more consequential direction: DOM clobbering
doesn't just corrupt an application's own global variables, it can corrupt properties that a
*sanitizer library itself* depends on to function, meaning the vulnerability isn't really in the
application's code at all — it's in an assumption baked into the sanitization library's
implementation, that `element.attributes` will always be the browser's built-in `NamedNodeMap` and
never something an attacker influenced. Any sanitizer that reads element properties without first
confirming they're the type it expects is vulnerable to exactly this trick, regardless of how
strict its tag/attribute allow-list otherwise is. The fix at the application layer is to avoid
naming any injectable child element with an `id` or `name` that collides with a built-in DOM
property name (`attributes`, `children`, `id`, `name`, and others are all shadowable this way); at
the library layer, HTMLJanitor and similar tools need to snapshot or explicitly type-check
`element.attributes` before trusting it, rather than reading it fresh off a DOM node that user
content directly controls the shape of.
