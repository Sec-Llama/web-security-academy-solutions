# Lab: User role can be modified in user profile

**Category:** Access Control
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile

Profile update endpoints tend to be treated as low-risk by developers — what harm could changing
your own email address do? But if the same request that updates your email also happens to echo
back (and accept) fields that were never meant to be user-editable, "update my profile" quietly
becomes "update my privileges."

## The Target

Logged-in users can change the email address on their account via a JSON request to
`/my-account/change-email`. The response to that request includes the account's `roleid`, which
told us the field exists in the same data model the update endpoint writes to — the only open
question was whether the endpoint was actually validating which fields it accepted.

## The Investigation

Once we saw `roleid` reflected in a routine email-change response, the natural next step was to try
sending it back on the request instead of just reading it. If the server was pulling the entire
JSON body into an update against the user record without an allow-list of editable fields, adding
`roleid` ourselves should update it right alongside the email.

## The Exploit

Logged in as `wiener`, we sent the change-email request with an extra field injected into the JSON
body:

```
{"email":"x@x.com","roleid": 2}    -- Inject roleid in change-email JSON request
```

```python
resp = client.post(f"{base}/my-account/change-email", json={
    "email": "pwned@exploit.com",
    "roleid": 2
})
```

The update succeeded, and with `roleid` now set to the administrative value, `/admin` was reachable.
We located `carlos`'s delete link in the returned panel and followed it, which solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches this through the same discovery: change the email address normally,
notice the response contains the account's `roleid`, then send the change-email request to Burp
Repeater with `"roleid":2` added into the JSON body, and confirm the response shows the updated
role before browsing to `/admin` to delete `carlos`. This is the exact technique we used — same
injected field, same value, same underlying mass-assignment flaw.

The only difference is tooling: PortSwigger edits and resends the captured request by hand in
Repeater, while our script sent the modified JSON directly through `httpx`. For a single crafted
request like this one, that's a difference in workflow, not in the exploit itself.

## What This Teaches Us

This is a textbook mass-assignment problem: the update handler bound the entire request body to the
user record instead of an explicit list of fields a user is actually allowed to change. Reflecting
`roleid` back in the response was the tell — anything the server is willing to *show* you about your
own record in a write-path response is worth testing as something it might also be willing to
*accept*. The fix is narrow and mechanical: the email-change endpoint should only ever touch the
email field, with role changes handled by a completely separate, properly access-controlled code
path.
