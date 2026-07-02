# SSRF via OpenID dynamic client registration

**Category:** OAuth authentication
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/oauth/openid/lab-oauth-ssrf-via-openid-dynamic-client-registration

OpenID Connect layers identity on top of OAuth, and one of the features it standardizes is dynamic
client registration — letting a new client application register itself with the provider
programmatically instead of through a manual admin console. That convenience assumes the
registration endpoint is either authenticated or treats everything a registering client submits as
untrusted input. This lab's provider does neither, and one of the fields a client gets to supply
during registration is a URL the provider will fetch on the server side — which is SSRF with extra
steps.

## The Target

The OAuth provider publishes its configuration at `/.well-known/openid-configuration`, which
includes a `registration_endpoint` — here, `/reg` — that accepts unauthenticated `POST` requests to
register a new OAuth client. Registered clients can supply a `logo_uri`, and the provider fetches
that URL server-side whenever a user is shown the client's logo on the "Authorize" consent screen,
served from `/client/CLIENT-ID/logo`.

## The Investigation

We started at the discovery document and confirmed `registration_endpoint` pointed at `/reg` with no
authentication requirement mentioned or enforced — a plain unauthenticated `POST` with a minimal
JSON body succeeded and returned a fresh `client_id`. That alone is worth noting (open registration
lets anyone mint OAuth clients against this provider) but it isn't a vulnerability by itself; the
interesting part is what optional metadata a registered client can supply, and whether any of it
results in the provider making requests on the client's behalf.

`logo_uri` is exactly that kind of field by design — the whole point of OpenID Connect's dynamic
registration is to let a client describe itself, including branding, without an administrator typing
it in by hand. The provider has to fetch that logo from somewhere to display it, and fetching a
client-supplied URL server-side is the textbook SSRF primitive: the request is made by the
provider's own infrastructure, from wherever that infrastructure sits on the network, with whatever
network access that grants.

## The Exploit

We registered a client with `logo_uri` pointed directly at the AWS instance metadata service, at the
path that returns temporary IAM credentials for the role this lab's OAuth provider assumes:

```
POST /reg  {"redirect_uris":["https://example.com"],"logo_uri":"http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"}
```

The registration succeeded and returned a new `client_id`. Fetching that client's logo endpoint
triggered the provider to make the SSRF request on our behalf and return the result directly in the
HTTP response:

```
GET /client/{client_id}/logo  → OAuth provider fetches logo_uri internally → SSRF response returned
```

The response body contained the full IAM credential set for the metadata service's `admin` role —
`AccessKeyId`, `SecretAccessKey`, and a session `Token`. We extracted `SecretAccessKey` and submitted
it to solve the lab. Notably, this SSRF isn't blind: the logo endpoint reflects whatever the fetch
actually returned straight back in its own response body, rather than just confirming success or
failure. That meant no out-of-band callback infrastructure was needed at any point — the metadata
response came back in-band, in the same request that triggered the fetch.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same endpoint chain — `/.well-known/openid-configuration` to find
`/reg`, register a client with a `logo_uri`, then hit `/client/CLIENT-ID/logo` to trigger the fetch —
but takes a more cautious middle step before firing at the real target. Their twelve-step walkthrough
has the reader first register a client with `logo_uri` set to a Burp Collaborator payload URL, fetch
the logo endpoint, and confirm an interaction actually arrives in the Collaborator tab. Only after
that blind-SSRF confirmation do they re-register with the real metadata URL and read the credentials
out of the logo response.

We skipped that intermediate confirmation step and registered directly with the AWS metadata URL on
the first attempt. That's a genuine difference in approach, not just tooling, and it's defensible for
a specific reason: PortSwigger's Collaborator step exists to *prove* the SSRF fires at all before
risking a wasted attempt against a sensitive target, which matters when the fetch result is blind and
you have no other way to know if it worked. Here it isn't blind — the logo endpoint echoes the fetch
result straight back in its response — so the metadata request and its confirmation are the same
HTTP round trip. Their approach is the right instinct for SSRF in general, where responses often
*are* blind; it just wasn't strictly necessary against this particular endpoint, where the fetched
content comes back in-band regardless of what URL you point it at.

## What This Teaches Us

Dynamic client registration multiplies the usual SSRF risk of "a server fetches a URL you gave it"
by removing the step where a human normally reviews what's being registered. Any field that results
in a server-side fetch — logos, JWKS URIs, webhook callbacks, anything OpenID Connect or a custom
extension defines as client-supplied metadata — needs the same treatment as user input anywhere
else: validated against a strict scheme and destination allowlist, and ideally resolved and checked
against private IP ranges before the fetch happens, not after. Pairing that with unauthenticated
registration turns a single misconfigured field into a pre-authentication path to a cloud provider's
metadata service, which is about as direct a route to full account compromise as SSRF gets.
