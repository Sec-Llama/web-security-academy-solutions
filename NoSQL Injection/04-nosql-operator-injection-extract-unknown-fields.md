# Exploiting NoSQL operator injection to extract unknown fields

**Category:** NoSQL Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-unknown-fields

Every extraction technique so far has targeted a field we already knew existed — `category`,
`password`. This lab removes that assumption entirely: the field holding the password reset token
doesn't exist in the database until a password-reset flow creates it, and its name isn't documented
anywhere in the application. The only way in is to use MongoDB's own reflection — `Object.keys()`
inside a `$where` clause — to ask the database to describe its own schema back to us, one field
name and then one character at a time.

## The Target

The login endpoint again takes JSON:

```
POST /login
{"username":"carlos","password":"..."}
```

but this time the goal is full account takeover of `carlos` via a password-reset token that lives
somewhere in his own document — a field name we don't know until we go looking for it.

## The Investigation

We first re-confirmed operator injection was live here independently of the previous lab, since
each lab instance is a fresh target: sending `{"username":"carlos","password":{"$ne":""}}` returned
"Account locked: please reset your password" rather than the generic "Invalid username or
password," which told us two things at once — the `$ne` operator was accepted, and carlos's account
exists and responds differently once matched.

Next we confirmed the application evaluates a `$where` clause as JavaScript rather than ignoring
it, by sending the same request with `"$where": "0"` and then `"$where": "1"` appended. The `"1"`
version reproduced the locked-account message; `"0"` did not. That's the same true/false oracle from
the previous lab, just reached through an extra top-level operator instead of a syntax injection
inside a string value.

Before hunting for the token field, we deliberately triggered `/forgot-password` for `carlos` first.
Password reset tokens in this kind of schema are commonly ephemeral — the field doesn't get created
until a reset flow needs somewhere to store it — so probing for it before triggering that flow would
have searched for a field that didn't exist yet. This turned out to matter: the field we were after
only appeared in the document after this step.

With the oracle and the trigger both in place, we swept the object's own key list using
`Object.keys()` indexed per position, with a regex anchor per character:

```
"$where": "Object.keys(this)[0].match('^.{0}a.*')"
```

extended across key index and character position the same way the password extraction worked in the
previous lab — grow a known prefix, test each candidate character in parallel, keep the one that
reproduces the "Account locked" response. Sweeping through key indices recovered the known fields
first (`_id`, `username`, `password`, `email`) and then one more that hadn't existed before we
triggered the reset flow: `changePwd`. One detail we had to correct for mid-run — our first charset
for field names was lowercase-plus-digits, and it stalled partway through `changePwd`, because the
field uses camelCase. MongoDB schemas built by JavaScript developers lean on camelCase by default,
so the extraction charset needed uppercase letters included, not just lowercase and underscores.

## The Exploit

With the field name known, we pointed the same `$where` regex-extraction loop at its value instead
of its name:

```
"$where": "this.changePwd.match('^<known-prefix><candidate-char>.*')"
```

which recovered the reset token as a 16-character hex string, one character at a time, using the
same "Account locked" oracle as every prior step. With the token in hand, we requested the
password-reset page directly:

```
GET /forgot-password?changePwd=<token>
```

which returned the reset form (carrying its own CSRF token), and submitted a new password through
it:

```
POST /forgot-password
csrf=<csrf>&changePwd=<token>&new-password-1=hacked123&new-password-2=hacked123
```

which came back as a `302`, confirming the reset succeeded. Logging in as `carlos` with the new
password `hacked123` via the same JSON `/login` endpoint returned a redirect to
`/my-account?id=carlos`, and the lab's completion banner confirmed the takeover.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows an identical arc: confirm `{"$ne": "invalid"}` on the password
triggers the locked-account message, confirm `"$where": "0"` versus `"$where": "1"` toggles the same
message to establish JavaScript evaluation, then extract the object's field names with
`Object.keys(this)[1].match('^.{§§}§§.*')` swept via Intruder's Cluster bomb attack across position
and character. Where our runs diverge slightly is in how the token field's *existence* gets
confirmed: PortSwigger's solution calls out testing `GET /forgot-password?foo=invalid` against
`GET /forgot-password?<discovered-field-name>=invalid` as a sanity check that the extracted name is
really the parameter the reset endpoint expects, before extracting its value with
`"$where": "this.<field>.match('^.{§§}§§.*')"` and finally requesting
`GET /forgot-password?<field>=<token>` to complete the reset.

The core technique — reflection via `Object.keys()`, then value extraction via the same `$where`
regex oracle — is exactly what we did. The one point our record is explicit about that's easy to
miss without hitting it directly: PortSwigger's walkthrough doesn't flag the need to trigger
`/forgot-password` *before* the `Object.keys()` sweep, but without that step the field simply isn't
part of the document yet and the sweep won't find it — which we only discovered because our first
extraction attempt found nothing until we added that trigger. As with the earlier labs, the other
difference is tooling: Intruder's Cluster bomb versus our own parallelized async loop over
positions and candidate characters.

## What This Teaches Us

This lab pushes the `$where` weakness one step further than "leak a value I already know the name
of" — it shows that `Object.keys()` turns the same injection point into a live schema browser, which
matters because "the field name is unknown to the attacker" is not a real security boundary once
arbitrary JavaScript can run against the document. It's also a reminder that ephemeral, workflow-
created fields (a reset token that only exists mid-flow) are not safer by virtue of not always being
present — an attacker willing to trigger the workflow themselves controls exactly when that field
comes into existence. The fix is the same as every other lab in this series: never let user input
be evaluated as executable query logic, whether it's shaping a string comparison or, as here,
reflecting over the object's own keys.
