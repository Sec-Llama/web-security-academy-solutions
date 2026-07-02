# Server-side template injection in a sandboxed environment

**Category:** Server-Side Template Injection
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-a-sandboxed-environment

The documentation-research lab earlier in this series ended with a clean answer: Freemarker's
`Execute` class shells out, game over. This lab closes that door — the same engine, with a sandbox
specifically built to block `Execute` and friends — and asks what's left once the obvious RCE
primitive is denied. The answer is that a template engine capable of calling methods on any object
in its context is, by construction, capable of Java reflection, and reflection doesn't need a
blocklist entry because it isn't a named dangerous class — it's just method calls, all the way
down to the filesystem.

## The Target

The same content-manager template preview endpoint as the earlier Freemarker lab:

```
POST /product/template?productId=1
csrf=...&template=...&template-action=preview
```

with one difference we needed to confirm before doing anything else: this instance's Freemarker
configuration wraps template execution in a sandbox.

## The Investigation

We first re-sent the `Execute`-class payload that solved the earlier Freemarker lab:

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

and this time the response text contained language to the effect of the class not being allowed
for security reasons — confirmation the sandbox was actively blocking that specific class rather
than the payload simply failing for some unrelated reason.

With `Execute` denied, we turned to the `product` object already present in every template's
context (used elsewhere in the page to render product details). Every Java object exposes
`.getClass()` by inheritance from `java.lang.Object`, and Freemarker's bean-property syntax lets
you call it as `.class` without parentheses. From there, standard Java reflection opens up a chain
that has nothing to do with Freemarker's own sandbox rules at all — it's asking the JVM class
loader where the application's own code lives on disk, then reading arbitrary files relative to
that location:

```
product.class -> .protectionDomain -> .codeSource -> .location
  -> .toURI() -> .resolve(path) -> .toURL() -> .openStream() -> .readAllBytes()
```

None of those method names appear on any Freemarker-specific blocklist, because the sandbox
restricts Freemarker's own utility classes (`Execute` and its relatives) — it has no way to
distinguish "reflection used for legitimate bean access" from "reflection used to open an
arbitrary file stream," because at the API level they're the same operation.

## The Exploit

Our capability tool builds the full reflection chain against any available context object and
targets it at the lab's target file:

```
${product.class.protectionDomain.codeSource.location.toURI().resolve("/home/carlos/my_password.txt")
  .toURL().openStream().readAllBytes()?join(",")}
```

Submitted through the same `template-action=preview` endpoint, the response's `preview-result`
element contained a comma-separated list of decimal byte values — `readAllBytes()` returns a raw
byte array, and Freemarker's `?join(",")` built-in is the only way to render it as text, one
integer per byte. We decoded it back to ASCII in Python (`''.join(chr(int(b)) for b in
byte_str.split(','))`), which recovered Carlos's password as plain text. Submitting that string to
the lab's solution endpoint triggered the "Congratulations" confirmation.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same reflection chain through the same reasoning: confirm you
have access to the `product` object, consult the JavaDoc for `java.lang.Object` to find methods
available on every object, confirm `${object.getClass()}` works, then explore the documentation to
find a path from `getClass()` to a class with a static file-reading method — landing on:

```
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI()
  .resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}
```

The chain is identical in substance, and the technique matches exactly: this lab is a genuine case
of technique convergence, not divergence. There are two small syntactic differences worth naming
precisely because they show the same underlying mechanism expressed two ways. First,
`.getClass()` versus `.class` — Freemarker's bean-property resolution treats a no-argument getter
and its shorthand property name as interchangeable, so `product.class` and `product.getClass()`
invoke the same method. Second, the byte-array join separator — PortSwigger's solution joins with
a space (`?join(" ")`), ours with a comma (`?join(",")`) — a cosmetic choice in how the
decimal byte values get delimited before decoding back to ASCII on our end; either separator
carries the same information.

## What This Teaches Us

Sandboxing a template engine by blocking named dangerous classes is a blocklist, and blocklists
have exactly the failure mode this lab demonstrates: they stop the specific attack you thought of
(`Execute`) without stopping the general capability that made the attack possible in the first
place (arbitrary method invocation on live Java objects). Freemarker's own documentation
acknowledges this — the framework's actual recommended defense isn't blocking `Execute`, it's
restricting *which classes and packages* a sandboxed template can reach at all, since any object
graph reachable from the template context is, transitively, a path to `java.lang.Object`,
`getClass()`, and everything reflection makes visible from there. A sandbox that reasons about
individual class names will always be one reflection chain behind a sandbox that reasons about
reachability.
