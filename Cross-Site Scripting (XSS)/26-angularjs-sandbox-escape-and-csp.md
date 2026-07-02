# Reflected XSS with AngularJS sandbox escape and CSP

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-and-csp

Content Security Policy is supposed to be the backstop that makes XSS harmless even when an injection
point exists — no inline script, no execution. AngularJS breaks that assumption in a specific and
subtle way: its template evaluator isn't `eval()`, isn't an inline `<script>` block, and isn't
anything CSP's `script-src` directive was built to catch, because from the browser's point of view
Angular is just a `'self'`-hosted library doing its own internal JavaScript logic.

## The Target

A page loading AngularJS from `'self'` (so CSP's `script-src 'self'` permits the library itself to
run) while enforcing `default-src 'self'; script-src 'self'` against everything else — no inline
scripts, no `unsafe-inline`, no `eval`. The `search` parameter reflects into an Angular template
context, but a direct `{{...}}` expression injection alone isn't enough here: we also need the
sandbox-escape technique from the previous lab, layered under a CSP that would normally block any
script we tried to inject directly.

## The Investigation

The key realization is that CSP governs *how script gets onto the page*, not what a library already
running on the page is allowed to compute. AngularJS's directive system — `ng-click`, `ng-focus`, and
similar — evaluates attribute expressions through Angular's own parser whenever the corresponding DOM
event fires. That evaluation happens entirely inside AngularJS's already-loaded, already-CSP-approved
code; nothing about it looks like "load an external script" or "run an inline `<script>` block" to the
browser's CSP enforcement, so it isn't blocked by even a strict `script-src`.

`ng-focus` was the event we used to trigger evaluation, paired with `$event.composedPath()` —
`composedPath()` returns the real DOM objects that were part of an event's propagation path, not an
Angular-sandboxed wrapper around them, and Chrome includes the `window` object itself as the final
entry in that path. Piping that array through the `orderBy` filter makes Angular iterate it and
evaluate the filter's argument expression against each element in turn. The final piece was avoiding a
direct reference to `window.alert`, since AngularJS's sandbox specifically checks for that pattern —
assigning `alert` to a throwaway variable (`z=alert`) first, then invoking `z` once the iteration
reaches the `window` element, sidesteps that specific check without ever writing `window.alert(...)`
literally in the expression.

## The Exploit

We delivered the payload via the exploit server as a redirect, since `ng-focus` needs the element to
actually receive focus and the URL fragment `#x` handles that automatically on page load:

```html
<script>location='https://LAB-ID.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x';</script>
```

which resolves to the injected markup:

```html
<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>#x
```

Loading the URL auto-focuses the injected `<input id=x>` via the `#x` fragment, firing `ng-focus`.
Angular evaluates `$event.composedPath()|orderBy:'(z=alert)(document.cookie)'` — `composedPath()`
returns the real DOM path array including `window`; `orderBy` iterates it, evaluating
`(z=alert)(document.cookie)` against each element; when the iteration reaches `window`, assigning
`alert` to `z` and immediately invoking it calls `alert(document.cookie)`, entirely inside Angular's
own CSP-permitted code path.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution delivers the identical exploit-server payload —
`<script>location='https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x'; </script>` —
with the identical explanation: `ng-focus` triggers Angular's own evaluation (bypassing CSP because it
isn't inline script), `$event.composedPath()` (Chrome-specific) surfaces the real `window` object
through the event path, `orderBy` iterates it, and assigning `alert` to a variable before invoking it
bypasses AngularJS's explicit check for direct `window` references. This is a byte-for-byte match to
our final payload — an early working note in our own internal capability file described a variant
using `[].constructor.from([document.cookie],alert)` instead, but the payload we actually verified and
shipped in the lab wrapper is the `(z=alert)(document.cookie)` form, identical to PortSwigger's. No
technique divergence.

## What This Teaches Us

CSP's threat model is "don't let the browser load or run script the page author didn't intend,"
enforced at the level of script sources and inline blocks. A client-side template framework already
approved to run under that model is a blind spot by construction — its expression evaluator is neither
a script source nor an inline block, so anything it can compute is implicitly trusted regardless of
where the expression driving it came from. Combined with a sandbox-escape technique that avoids the
one direct reference (`window.alert`) the sandbox explicitly checks for, this chain shows why CSP and
framework-level sandboxes need to be evaluated together rather than assumed to compound independently:
a bypass in one can fully neutralize the other's protection. The practical fix here is the one
AngularJS's own maintainers eventually took — retire the sandbox model rather than keep patching
individual escapes, since the framework's dynamic expression evaluation was never actually compatible
with the guarantees a sandbox promised.
