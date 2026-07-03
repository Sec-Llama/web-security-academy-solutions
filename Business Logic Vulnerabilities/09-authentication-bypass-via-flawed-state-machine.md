# Authentication bypass via flawed state machine

**Category:** Business Logic Vulnerabilities
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-flawed-state-machine

Multi-step login flows have an implicit state machine: authenticate, then pick a role, then land in
the application proper. State machines are only secure if every state has a well-defined default —
and "what happens if the user just never finishes the sequence" is exactly the kind of edge case
developers under-specify. If skipping the last step of an authentication flow resolves to the most
privileged default rather than the least privileged one, the flow was never really enforcing
anything.

## The Target

Logging in with valid credentials doesn't land the user directly on the home page — it redirects to
`GET /role-selector`, a page that lets the account choose which role to operate under before
proceeding. Only after a role is explicitly selected does the session reach the home page in that
role's context.

## The Investigation

The question this lab poses is exactly what this series keeps circling back to: what happens if you
don't follow the sequence the UI expects? The login POST redirects to the role selector, which
implies the server considers the session to be in some intermediate, not-yet-fully-authenticated-with-
a-role state at that point. The interesting case is what the server treats that intermediate state
*as*, by default, if the client simply never requests `/role-selector` at all and instead goes
straight to the home page.

We tested it by logging in with `follow_redirects` disabled on the login POST, capturing the
resulting session cookie without ever issuing the follow-up request to `/role-selector`, and then
requesting the home page directly with that session.

## The Exploit

The login request was sent without following its redirect, then the role-selector step was dropped
entirely:

```
POST /login
username=wiener&password=peter          (follow_redirects=False; response is a 302 to /role-selector)

GET /                                    (sent directly, /role-selector never requested)
```

The home page loaded in the administrator role. Whatever server-side logic decided which role a
session operated under had a default value for "no role explicitly selected yet," and that default
was the most privileged one available rather than the least. From there, `GET /admin` returned the
admin panel, and deleting `carlos` solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution completes a normal login first to confirm the role-selector step exists and
that `/admin` isn't directly reachable from that page, then goes back to the login page with proxy
interception on, forwards the `POST /login` request, and — when the next request in the sequence
turns out to be `GET /role-selector` — drops it instead of forwarding it, then browses directly to
the home page and observes the session has defaulted to the administrator role.

This is the identical vulnerability and the identical exploitation step: intercept the intermediate
redirect and simply never send it. The only difference is that Burp's proxy naturally puts a human in
the position to drop a request mid-flight, while our script achieved the same effect more directly by
disabling redirect-following on the login response and never issuing the role-selector request in
the first place — same outcome, since either method just means the server never receives that
request.

## What This Teaches Us

The role-selector step wasn't actually authenticating anything by itself — it was a UI convenience
that happened to also be where a session's role got assigned, and the server-side code evidently
initialized new sessions to an administrator-equivalent state and only *narrowed* that scope once a
role was explicitly chosen, rather than starting unprivileged and *elevating* it. Any state machine
with a privileged default for an unreached state is backwards: defaults should always be the least
privileged option, with privilege only granted by an explicit, verified transition — never assumed as
a starting point that a skipped step was supposed to walk back from.
