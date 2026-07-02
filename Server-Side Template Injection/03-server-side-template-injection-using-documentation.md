# Server-side template injection using documentation

**Category:** Server-Side Template Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation

Confirming a template engine evaluates `7*7` is the easy half of SSTI. The harder half is turning
that confirmation into code execution, and for most engines the path from "I can evaluate
expressions" to "I can run shell commands" isn't something you derive from first principles — it's
something you look up, because template engines expose their own utility classes and built-ins
that were never meant to be attacker-reachable. This lab is a direct test of that research step.

## The Target

Logged in as a content manager, the application exposes a template editor for product
descriptions:

```
POST /product/template?productId=1
csrf=...&template=...&template-action=preview
```

The `template-action=preview` mode renders whatever's submitted without permanently saving it,
which makes it a safe, repeatable place to iterate on payloads before committing anything.

## The Investigation

We logged in as `content-manager` and submitted `${7*7}` through the preview endpoint. It came
back as `49`, confirming SSTI with `${...}` expression syntax — consistent with several JVM
template engines (Freemarker, Velocity, Thymeleaf). To narrow it down, we consulted our
capability notes rather than guessing: Freemarker's public documentation includes a FAQ entry
titled "Can I allow users to upload templates and what are the security implications?", which
directly names the danger — a built-in called `new()` that can instantiate arbitrary Java objects
implementing Freemarker's `TemplateModel` interface. Freemarker's own documentation, in other
words, hands you the exploit primitive: the vendor knows `new()` is dangerous and says so in
writing.

Following that thread to Freemarker's `TemplateModel` implementations turns up a class called
`Execute`, purpose-built (from an attacker's perspective) to run shell commands from inside a
template. This is the same technique documented by PortSwigger's own SSTI research and already
recorded in our capability notes as the standard Freemarker RCE primitive:

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("CMD")}
```

## The Exploit

We submitted the RCE payload with the target command substituted directly through the same
preview endpoint used for detection:

```
template=<#assign ex="freemarker.template.utility.Execute"?new()>${ex("rm /home/carlos/morale.txt")}
template-action=preview
```

The `<#assign>` directive instantiates Freemarker's `Execute` utility class via the `new()`
built-in, binds it to the name `ex`, and `${ex("...")}` immediately invokes it as a shell command
runner — Freemarker's `Execute` class shells out and returns the command's output as a string.
Loading the product page after the preview confirmed the lab's "Congratulations" banner.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the identical research path: edit a template, enter invalid syntax
like `${foobar}` to trigger an error message that names Freemarker explicitly, then walk through
Freemarker's own documentation — the FAQ entry on `new()`, then the `TemplateModel` JavaDoc, then
the `Execute` class — arriving at the same `<#assign ex="freemarker.template.utility.Execute"?
new()> ${ ex("rm /home/carlos/morale.txt") }` payload, credited to the same exploit originally
published on PortSwigger's own research page.

This is a case where the technique converges exactly, because the vulnerability's fix path really
is "read Freemarker's documentation and find the class the vendor already warned you about." The
only difference is that we didn't need to independently rediscover the `Execute` class through
live documentation research — it was already recorded in our capability notes as the standard
Freemarker RCE primitive from prior work, so detection and exploitation happened as two
back-to-back requests rather than a documentation deep-dive in between. The underlying reasoning
PortSwigger's solution walks through is the same reasoning that got the payload into our notes in
the first place.

## What This Teaches Us

This lab is a reminder that template engine security isn't just about the syntax an application
lets through — it's about every utility class the engine ships with, whether or not the
application's developers ever intended to expose it. `Execute` exists in Freemarker's standard
library for legitimate reasons unrelated to this application; the vulnerability isn't that
`Execute` exists, it's that untrusted input can reach `new()` at all. Freemarker's own
recommended mitigation, sandboxing template execution so dangerous classes like `Execute` are
unreachable regardless of what expression an attacker submits, is exactly the fix explored in the
next lab in this series — this one demonstrates why that sandbox needs to exist in the first
place.
