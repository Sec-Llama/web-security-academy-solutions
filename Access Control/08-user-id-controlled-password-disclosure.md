# Lab: User ID controlled by request parameter with password disclosure

**Category:** Access Control
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure

An IDOR that leaks another user's API key is bad. An IDOR that leaks the *administrator's password*
turns a horizontal information leak into full vertical privilege escalation in one request. This lab
chains the same identifier-tampering flaw seen throughout this series into an account takeover, by
pointing it at a page that happens to render a password field with the value already filled in.

## The Target

The now-familiar `/my-account?id=<username>` pattern, on an account page that includes a password
change form. For an ordinary account, that field is naturally blank. For the `administrator`
account specifically, the field comes pre-filled — a convenience feature ("show me my current
setting") that becomes a liability the moment the IDOR from Lab 5 is pointed at it.

## The Investigation

We already knew from Lab 5 that swapping the `id` parameter returns another account's page under
our own session. The only new question here was what that page actually contains for the
`administrator` account specifically — and account pages with editable password fields are worth
checking for exactly this pattern, because a masked `<input type="password">` still has to carry its
current value in the markup for a browser to display it, masked or not.

Extracting that value turned out to need more care than a single regex pattern. PortSwigger labs
render the input's attributes with inconsistent quoting — some single-quoted, some double-quoted,
some unquoted — so a regex written for one style silently misses the others:

```
<input type=password name=password value='...'>
regex: name=.?password.?[^>]*value=["\']([^"\']+)["\']
-- Key: PortSwigger labs use single-quoted, unquoted attributes — regex must handle all quote styles
```

## The Exploit

Logged in as `wiener`, we requested the administrator's account page via the same IDOR used in Lab
5:

```
GET /my-account?id=administrator
```

```python
resp = client.get(f"{base}/my-account", params={"id": "administrator"})
pw_match = re.search(r'name=.?password.?[^>]*value=["\']([^"\']+)["\']', resp.text)
```

The regex pulled the administrator's actual password straight out of the pre-filled input field. We
logged in as `administrator` with the recovered credential, opened `/admin`, located the delete link
for `carlos`, and followed it — solving the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution is the same chain: log in, change `id` to `administrator`, observe the
response contains the administrator's password, log in as administrator, delete `carlos`. This
matches our approach exactly — same IDOR, same target field, same escalation path from leaked
password to admin panel access.

The only difference is extraction mechanics: Burp Repeater lets a human just read the value straight
off the rendered response body, while our script needed a regex robust enough to handle whatever
quoting style the specific input tag used. That's a scripting-specific wrinkle, not a difference in
the underlying exploit.

## What This Teaches Us

This lab is a reminder that IDOR impact isn't fixed by the vulnerability class — it's set by what
the exposed page happens to contain. The same missing ownership check that leaked an API key in Lab
5 leaks a plaintext-equivalent password here, purely because this particular account page renders a
password field pre-filled for convenience. Pre-filling sensitive fields for the "current user" is
already a questionable pattern; doing it on a page reachable by anyone who can control the `id`
parameter turns a UX shortcut into a direct path to full account takeover.
