# DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression

Every context so far has been plain HTML, an HTML attribute, or raw JavaScript. This lab introduces
a client-side framework into the mix — AngularJS — and with it, a template expression language that
runs on top of whatever HTML-level encoding the application already applies. Once a page loads
AngularJS and marks a region of the DOM with `ng-app`, anything inside double curly braces in that
region is evaluated as an AngularJS expression, independent of whether angle brackets are encoded.

## The Target

The search results page reflects the search term as text inside a `<div ng-app>` element — the
`ng-app` directive is what tells AngularJS to treat that region of the DOM as a live template rather
than static content.

## The Investigation

We submitted a random string and viewed the page source rather than just the rendered output, which
showed our string sitting inside an element carrying the `ng-app` attribute. That detail is the whole
key to this lab: with angle brackets HTML-encoded, injecting a new tag was off the table exactly like
in the earlier attribute-encoding labs — but AngularJS doesn't need a new tag at all. It scans the
text content of any `ng-app`-scoped element for `{{ }}` expressions and evaluates them as JavaScript,
which means the injection doesn't need to touch HTML syntax in any way. We just needed a valid
AngularJS expression that reaches `alert()`.

AngularJS's expression sandbox (in the version this lab uses) blocks direct references to dangerous
globals like `window` or `document`, but it doesn't block reaching a function constructor through an
object method's own `.constructor` chain — `$on` is a method available on the scope, and walking from
`$on.constructor` gets to the `Function` constructor, which can build and immediately invoke arbitrary
code from a string.

## The Exploit

We submitted an AngularJS expression as the search term:

```
{{$on.constructor('alert(1)')()}}
```

Delivered as:

```
GET /?search=%7B%7B%24on.constructor(%27alert(1)%27)()%7D%7D
```

No angle brackets, no quotes needing to break out of anything — the entire payload is plain text
that AngularJS's template engine picks up inside the `ng-app` element and evaluates. `$on.constructor`
resolves to the `Function` constructor; calling it with `'alert(1)'` builds a new function whose body
is `alert(1)`; the trailing `()` invokes it immediately.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the identical path: submit a random string, view the page source to
confirm it's enclosed in an `ng-app` directive, then submit
`{{$on.constructor('alert(1)')()}}` and search again. Same discovery process, same payload, same
technique — no divergence at all. This is a case where recognizing the AngularJS sandbox-escape
pattern is really the entire lab, and there's only one clean way to combine `$on.constructor` into a
working expression. The only difference, again, is manual browser interaction on their side versus
scripted HTTP requests plus headless-browser confirmation on ours.

## What This Teaches Us

HTML encoding operates at the wrong layer to stop this attack — it protects against the browser's
HTML parser, but AngularJS's template engine runs its own separate evaluation pass over element text
content, completely independent of whether that text originally contained literal angle brackets.
Any client-side templating or expression framework loaded on a page effectively adds a second
"interpreter" that user input can reach, and encoding schemes designed for HTML alone won't defend
against it. The real fix is to never let user input reach a live AngularJS scope as raw template text
in the first place — use one-way text binding (`ng-bind` or Angular's newer strict contextual escaping)
rather than interpolating untrusted strings directly into `ng-app`-scoped markup, and keep the
framework itself updated, since later AngularJS versions closed off several of these sandbox-escape
primitives.
