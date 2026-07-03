# Bypassing access controls using email address parsing discrepancies

**Category:** Business Logic Vulnerabilities
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-bypassing-access-controls-using-email-address-parsing-discrepancies

Email addresses look like the simplest possible identifier — a local part, an `@`, a domain — right up
until you have to parse one according to the actual RFCs, which allow for comments, quoted strings,
and encoded-word headers that most validation code never anticipated. When a domain-based access
check reads a raw string and a completely different mail-delivery library later decodes and
interprets that same string, any gap between what the two consider "the domain" becomes a way to
register as one identity while actually receiving mail as another.

## The Target

Registration is restricted to addresses ending in `@ginandjuice.shop`, described by the lab as
belonging to a fictional company's employees. The validation logic checks the submitted address
string directly against that domain requirement. This lab is explicitly built on a specific piece of
published research — PortSwigger's own "Splitting the Email Atom" whitepaper — which catalogs exactly
this class of parser discrepancy.

## The Investigation

MIME's "encoded-word" syntax (RFC 2047) lets an email header segment declare its own character
encoding inline: `=?charset?encoding?encoded-text?=`. It exists for legitimate reasons — representing
non-ASCII characters in headers that are otherwise restricted to ASCII — but it also means a single
address field can contain a block of text whose actual meaning only becomes apparent after a decoder
processes it according to the declared charset. If the application's registration validator checks
the raw, undecoded string for a domain suffix, but the mail server that actually delivers the
confirmation email decodes the encoded-word segment first, the two components can disagree about
what address the message is really addressed to.

UTF-7 is the specific charset that makes this dangerous here: UTF-7 can represent characters like `@`
and space using only safe, non-special ASCII sequences (`&AEA-` for `@`, `&ACA-` for a space) that
don't visually or syntactically resemble an email address boundary to a validator scanning the raw
string. That means a UTF-7 encoded-word segment can smuggle an entirely different `local@domain`
pair inside what still reads, character-for-character in its undecoded form, as ending in
`@ginandjuice.shop`.

The payload construction: prefix the encoded-word with the real target address we want mail routed
to, encoded in UTF-7, then close the encoded-word and append the literal string
`@ginandjuice.shop` outside it:

```
=?utf-7?q?foo&AEA-{exploit_domain}&ACA-?=@ginandjuice.shop
```

To the domain validator, this string simply ends in `@ginandjuice.shop` and passes. To a mail
transport agent that honors RFC 2047 and decodes the UTF-7 encoded-word, `&AEA-` becomes `@` and
`&ACA-` becomes a space, so the address it actually resolves and delivers to is
`foo@{exploit_domain}` — our own inbox — with the trailing ` @ginandjuice.shop` left as inert
trailing text after the real address, or otherwise discarded depending on the parser.

## The Exploit

We registered with the constructed UTF-7 encoded-word address, using the lab's exploit-server domain
as the delivery target:

```
email = "=?utf-7?q?foo&AEA-{exploit_domain}&ACA-?=@ginandjuice.shop"
```

Registration was accepted — the raw-string domain check saw the required `@ginandjuice.shop` suffix
and passed it through. After a short delay for delivery, the exploit server's email client showed a
confirmation message had actually arrived, meaning the mail transport had decoded the UTF-7 segment
and routed to our real address as intended. Extracting the `temp-registration-token` from that email
and visiting the confirmation link completed registration. Logging in with the new account granted
access to the admin panel, and deleting `carlos` solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution builds up to the same UTF-7 payload through a deliberately incremental
investigation rather than jumping straight to it. It first confirms the baseline domain restriction
by registering `foo@exploit-server.net` directly and observing the rejection. It then tries an
encoded-word address using ISO-8859-1 Q-encoding
(`=?iso-8859-1?q?=61=62=63?=foo@ginandjuice.shop`, which decodes to `abcfoo@ginandjuice.shop`) and
finds it's specifically blocked with a "Registration blocked for security reasons" message — evidence
the server is actively detecting and rejecting encoded-word manipulation attempts. It then tries the
same technique with UTF-8 encoding and finds that blocked too, by the same message. Only after both
of those attempts fail does the solution try UTF-7 encoding
(`=?utf-7?q?&AGEAYgBj-?=foo@ginandjuice.shop`) and finds that this one *doesn't* trigger the security
block — evidence the server's encoded-word detection doesn't recognize UTF-7 specifically. From
there, it constructs the final payload,
`=?utf-7?q?attacker&AEA-[exploit-server-id]&ACA-?=@ginandjuice.shop`, encoding the `@` and space in
UTF-7 exactly as we did, and completes registration the same way.

The final payload and underlying technique are the same as ours, but the path to it differs in a way
worth naming honestly: PortSwigger's walkthrough is written as a genuine discovery process, probing
multiple encodings in sequence and using the server's differing responses (generic domain rejection
vs. an explicit "blocked for security reasons" vs. silent acceptance) to work out which encoding the
server's detection doesn't cover. Our internal record shows we went directly to the UTF-7 construction
without that exploratory sequence, because this lab explicitly names its required background reading
— the "Splitting the Email Atom" whitepaper — and that paper documents UTF-7's encoded-word behavior
as a known bypass for exactly this kind of domain check. Knowing the specific published technique in
advance meant we didn't need to rediscover it by testing ISO-8859-1 and UTF-8 first; that exploratory
narrowing is genuinely valuable methodology for a target where the working encoding isn't already
known, but it wasn't the step that got us to the working payload here.

## What This Teaches Us

This is the most structurally distinct flaw in the series: not a missing check, not a skipped step,
but two pieces of code — a validator and a mail transport library — that are individually correct by
their own standards and only produce a vulnerability when composed, because they don't agree on how
to interpret the same input. The domain check wasn't wrong to look at the raw string; RFC 2047
decoding wasn't wrong to honor a declared charset. The gap exists because nobody verified that the
*decoded* form of an address — the one actually used for delivery — was checked against the same
domain rule as the raw form used for validation. Any system that validates one representation of an
input while a downstream component acts on a semantically different, decoded representation of the
same input has this class of bug available to it, regardless of how correct each individual component
is in isolation.
