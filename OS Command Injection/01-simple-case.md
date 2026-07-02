# OS command injection, simple case

**Category:** OS Command Injection
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/os-command-injection/lab-simple

OS command injection sits a level above SQL injection in terms of consequence — instead of
manipulating a database query, the attacker is handing the operating system itself a command to
run, with whatever privileges the web server process has. Shellshock, one of the more infamous
vulnerabilities of the last decade, was exactly this bug class in a different guise: user input
reaching a shell unfiltered. This lab is the cleanest possible demonstration — a feature that
shells out to the OS, and a parameter that lands directly in the command string.

## The Target

The lab is a storefront with a stock checker. Viewing a product's availability at a given store
sends:

```
POST /product/stock
productId=1&storeId=1
```

and the response reports whether that product is in stock at that store. Checking stock levels
across a chain of physical stores is exactly the kind of feature that gets implemented by shelling
out to an OS utility rather than querying a database directly — and that's the shape of bug this
lab is testing for.

## The Investigation

We ran our OS command injection detector against the `storeId` parameter. The detector's inline
strategy works through a fixed list of shell metacharacter operators — `;`, `|`, `||`, `&`, `&&`,
newline, backtick, and subshell — appending a canary command (`whoami`) after each one, and
checking whether the response changes shape compared to a clean baseline request.

Both the semicolon and the pipe operator turned out to be injectable on `storeId`. Because our
detector tests operators in a fixed order and stops at the first one that works, it was the
semicolon that our tool actually surfaced first, even though the pipe operator — the one
PortSwigger's own solution uses — was equally valid. Two working operators on the same parameter
is normal for this kind of unsanitized shell-out: whichever character reaches the shell first ends
the original command and starts a new one.

## The Exploit

We confirmed exploitation with both operators. The pipe variant:

```
storeId=1|whoami
```

and the semicolon variant:

```
storeId=1;whoami
```

Either one turns the backend's stock-check command into two commands: the original lookup for
store `1`, followed immediately by `whoami`. The response came back with the output of `whoami`
appended directly to the stock-check result — the current user the web server process runs as,
printed in plain text in an HTTP response that was never supposed to return anything but a stock
count.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution intercepts the stock-check request in Burp Suite and changes
`storeId` to `1|whoami`, then observes the username appear in the response — the pipe variant we
also verified, reached the same way in substance.

The one real difference is which operator our tooling happened to land on first. Our detector
checks the semicolon before the pipe in its operator list, so it reported the semicolon-separated
payload as the confirmed injection, while PortSwigger's walkthrough uses the pipe from the start.
Both are correct; the storefront's stock-check command doesn't sanitize either character, so the
"first working operator" is really just an artifact of which order you happen to try them in.
Delivery-wise, the difference is the usual one for this series: PortSwigger drives the change
through Burp's proxy by hand, we sent it as a direct HTTP request from a script.

## What This Teaches Us

The vulnerability here isn't really about `storeId` specifically — it's about building a command
string by concatenating user input into a system shell call at all. Any of `;`, `|`, `&`, or a
handful of other characters are enough to break out of the intended command, because the shell
doesn't know or care that the string was assembled from partially-trusted input. The fix
PortSwigger's own guidance points to is avoiding shell invocation entirely in favor of
language-level APIs that take arguments as a list rather than a single interpreted string, and
where that's not possible, strict allow-listing of the input rather than trying to blacklist
dangerous characters — a blacklist has to catch every metacharacter; an allow-list only has to
define what's actually legitimate.
