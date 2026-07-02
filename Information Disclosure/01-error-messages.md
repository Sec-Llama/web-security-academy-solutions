# Information disclosure in error messages

**Category:** Information Disclosure
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages

Verbose error messages are the easiest information disclosure bug to find and the hardest to
justify keeping around: a stack trace that was only ever meant for a developer's console ends up
in an HTTP response, and with it goes the exact framework and version the application is running
on. That's not a theoretical risk — it's a direct lookup key into a CVE database. This lab hands
over that key for free, in response to a single malformed parameter.

## The Target

The application is an e-commerce storefront where product pages are requested like:

```
GET /product?productId=1
```

`productId` is expected to be an integer that the backend uses to look up a row. Nothing about the
normal response hints at what's running underneath — no version banner, no `Server` header of
interest, just a rendered product page.

## The Investigation

The question we wanted answered was simple: what happens when `productId` isn't a valid integer?
Type-confusion at a parameter boundary is one of the most reliable ways to make a backend fail
loudly instead of gracefully, because the exception path is usually the code that got the least
production hardening. We sent a single quote in place of the numeric ID:

```
GET /product?productId='
```

The response came back with a full stack trace instead of a product page. Our detector looks for
version strings using a pattern that matches known frameworks and servers (`Apache`, `Struts`,
`Nginx`, `PHP`, `Spring`, and so on) followed by a version number, and specifically takes the
*last* match in the trace rather than the first — stack traces are full of package names like
`java.lang.NumberFormatException` that can look like framework identifiers if you're not careful,
and the actual framework/version banner is typically printed at the bottom, closest to the root
cause. That gave us a clean, unambiguous result: `Apache Struts 2 2.3.31` — a version with a
well-documented remote code execution vulnerability (CVE-2017-5638).

## The Exploit

There's no further exploitation step in this lab beyond extraction — the objective is simply to
prove the version banner is retrievable and report it. We submitted the extracted string as the
answer:

```
POST /submitSolution
answer=Apache Struts 2 2.3.31
```

The lab tracker flipped to solved, confirming the version string matched what the platform expected.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution reaches the same stack trace through a slightly different
trigger: instead of a single quote, they send a string literal where an integer is expected —
`GET /product?productId="example"`. Either input works for the same underlying reason: both are
values the type conversion code doesn't expect, and both blow through the same unguarded exception
handler. Our script defaults to a single quote as its primary trigger (with `"example"` and several
other non-integer payloads available as fallbacks in the same detector), so we landed on the
identical stack trace and the identical version string through a slightly different malformed
input. The official solution also submits the version number in the abbreviated form `2 2.3.31`
rather than prefixing it with `Apache Struts`; our extraction keeps the framework name attached
since our detector is built to report a self-describing finding, not just a bare version number for
a single lab's answer field.

The other difference is delivery: PortSwigger's walkthrough sends the malformed parameter manually
through Burp Repeater. We ran the same request through a Python script that fuzzes a list of
non-integer triggers and parses the response automatically, which matters more once you're testing
this technique against dozens of parameters across a real target rather than one lab's single
`productId`.

## What This Teaches Us

The vulnerability here isn't a missing input filter — the application correctly rejected a bad
`productId` and threw an exception, which is the right behavior. The bug is what happened *after*
the exception: the full trace, including internal class names, file paths, and library versions,
was serialized straight into the HTTP response instead of being caught and replaced with a generic
error page. That's the actual fix — catch exceptions at the boundary, log the detail server-side,
and return nothing more specific than "something went wrong" to the client. Every version string an
application leaks this way is one less step an attacker needs to take before searching for a known
exploit.
