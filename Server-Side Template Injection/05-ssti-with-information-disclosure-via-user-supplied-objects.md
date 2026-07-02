# Server-side template injection with information disclosure via user-supplied objects

**Category:** Server-Side Template Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-information-disclosure-via-user-supplied-objects

Not every SSTI ends in remote code execution, and this lab is a useful corrective to that
expectation. Django's template engine is deliberately sandboxed — no arbitrary Python execution,
no shelling out — which on paper sounds like SSTI is neutralized. It isn't. The engine still
exposes objects from the application's own context, and one of those objects, in this lab, is
worth more than shell access: the framework's own secret key.

## The Target

The same content-manager template editor from the documentation-research lab:

```
POST /product/template?productId=1
csrf=...&template=...&template-action=preview
```

logged in as `content-manager`, previewing arbitrary template content against a product
description without permanently saving it.

## The Investigation

Submitting `{{7*7}}` — the standard Jinja-family math probe — returned `49`, which on Django's
templates is expected behavior rather than proof of a vulnerability: Django's template language
evaluates simple arithmetic-looking expressions as part of its normal filter/variable resolution,
so this alone doesn't distinguish "this is exploitable SSTI" from "this is how Django templates
always behave." We went directly to Django's own object model instead. Django ships a built-in
template tag, `{% debug %}`, that dumps every object and variable accessible from the current
template context — effectively a documented introspection primitive, not something we had to
infer.

Crucially, Django's request context includes the `settings` object by default in many
configurations, and `settings` carries `SECRET_KEY` — the value Django uses to sign sessions, CSRF
tokens, and password reset links. If a template can reach `settings.SECRET_KEY`, an attacker gains
everything that key protects: the ability to forge valid signed session cookies, forge CSRF tokens,
and in applications using `pickle`-based signed serialization, a path toward deserialization RCE.
None of that requires the template engine itself to execute arbitrary code — it only requires the
engine to expose an object the attacker shouldn't be able to read.

## The Exploit

We submitted `{{settings.SECRET_KEY}}` directly through the same preview endpoint:

```
template={{settings.SECRET_KEY}}
template-action=preview
```

The preview response contained the extracted key. Our tool parses it out of the `preview-result`
element in the response HTML and submits it through the lab's own solution-checking endpoint:

```
POST /submitSolution
answer=<extracted secret key>
```

which returned the "Congratulations" confirmation.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution takes a more exploratory route to the same payload: submit an invalid fuzz
string first (`${{<%[%'"}}%\`) to trigger an error message that names Django explicitly, consult
Django's documentation to discover `{% debug %}`, submit it to see the full list of accessible
context objects and confirm `settings` is one of them, and only then submit
`{{settings.SECRET_KEY}}`.

The final payload is identical. The difference is investigative depth: PortSwigger's solution
walks through *discovering* that `settings` is reachable before reading from it, using `{% debug
%}` as a reconnaissance step. We skipped straight to `{{settings.SECRET_KEY}}` because this exact
technique — Django template SSTI reaching the framework's `settings` object — was already recorded
in our capability notes from prior work, so the discovery step PortSwigger's walkthrough performs
live had already happened for us. It's worth noting explicitly that skipping the `{% debug %}`
step is a shortcut that only works because we already knew what we were looking for; against an
unfamiliar Django target, that reconnaissance step is exactly how you'd find out `settings` (or any
other sensitive object) is reachable in the first place.

## What This Teaches Us

Sandboxing a template language's *syntax* — no imports, no arbitrary function calls, no shell
access — doesn't sandbox the *data* available inside it. Django's template engine did exactly what
it was designed to do here: it refused to execute Python and refused to shell out. It just also
handed over an object that happened to contain a secret. The actual fix isn't a template-engine
setting at all — it's making sure `settings` (or any object carrying secrets, credentials, or
internal configuration) is never part of the context passed to a template that renders
user-influenced content, sandboxed or not. This is the same lesson underneath every SSTI lab in
this series wearing a different costume: the engine only leaks what the application's own code
decided to expose to it.
