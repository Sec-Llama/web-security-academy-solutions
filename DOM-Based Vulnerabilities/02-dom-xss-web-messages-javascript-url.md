# DOM XSS using web messages and a JavaScript URL

**Category:** DOM-Based Vulnerabilities
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-a-javascript-url

An origin check is only as strong as what it actually checks. The previous lab had no origin
validation at all; this one has a check on the *content* of the message instead — a string filter
meant to make sure only genuine URLs get passed to a navigation sink. String filters written
against attacker-controlled input are notoriously easy to satisfy without satisfying their intent,
and that's the whole lab in one sentence.

## The Target

The home page again registers a web message listener, but this time the sink is different:
instead of `innerHTML`, the handler assigns the message content to `location.href`, presumably to
support some kind of "navigate to this URL" feature delivered via `postMessage()`. Before doing
that assignment, the handler runs a check against the message string using `indexOf()`, looking
for the substring `"http:"` (or `"https:"`) — evidently intended to ensure the value being
navigated to is a real HTTP(S) URL rather than something like a `javascript:` URL.

## The Investigation

Running `detect_dom_sinks()` against the home page again confirmed the message listener and
flagged a `location.href` assignment as a sink pattern in the same script. That combination — a
message handler that eventually reaches a navigation sink — is exactly what this lab's title
promises: a JavaScript URL smuggled past whatever validation stands between the message and the
sink.

The validation here is a substring check, not a URL parse. `indexOf('http:')` returns a
non-negative index as long as the literal characters `http:` appear *anywhere* in the string — it
has no concept of where in the string they need to be, or what comes before or after them. That's
the exact gap `javascript:` URLs exploit: a `javascript:` URL is still just a string, and strings
can contain JavaScript comments. If we put `//http:` after our real payload, everything from `//`
onward is a JS single-line comment when the browser actually evaluates the URL as JavaScript — but
as far as `indexOf()` is concerned, the substring `http:` is still sitting right there in the
string, satisfying the check.

## The Exploit

We used `craft_web_message_js_url()` to build the payload, which concatenates the JS code, a
comment marker, and the bypass string: `javascript:{js_code}//{bypass_check}`, giving us
`javascript:print()//http:`. That went into the same iframe/postMessage delivery pattern as the
previous lab:

```html
<iframe src="https://TARGET/" onload="this.contentWindow.postMessage('javascript:print()//http:','*')"></iframe>
```

Delivered through the exploit server's store/deliver flow, the sequence on the victim side is:
the iframe loads, `postMessage()` fires with our string, the handler's `indexOf('http:')` check
finds the substring at the tail end of our comment and passes, and the full string is assigned to
`location.href`. The browser evaluates `location.href = "javascript:print()//http:"` as a
`javascript:` URL, executes `print()`, and treats `//http:` as a trailing comment that has zero
effect on execution.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution is textually identical to ours: notice the flawed `indexOf()` check against
`"http:"`/`"https:"` feeding into `location.href`, then deliver
`onload="this.contentWindow.postMessage('javascript:print()//http:','*')"` via the exploit server.
There's no technique divergence here at all — the comment-based bypass is the one and only way
past a substring check like this, so both approaches land on the same payload by construction.

As with the previous lab, the only difference is that PortSwigger's walkthrough fills in the
exploit server's form manually while our script posts the same STORE and DELIVER_TO_VICTIM
requests directly against the exploit server's HTTP endpoint.

## What This Teaches Us

This lab is a sharp illustration of why "does the string contain X" is not the same question as
"is this string safe to use as X." The developer's intent was reasonable — block anything that
isn't a real HTTP URL — but `indexOf()` can only tell you a substring exists somewhere, never that
it exists in a position that changes the string's actual meaning. The fix isn't a better substring
check; it's not trusting the origin of the message enough to hand its contents to a navigation sink
at all without validating the message's `origin` against an exact allow-list first, combined with
parsing the value with a real URL parser (checking the resulting protocol is `http:`/`https:`)
rather than a pattern match against the raw string.
