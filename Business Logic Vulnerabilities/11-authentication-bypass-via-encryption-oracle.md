# Authentication bypass via encryption oracle

**Category:** Business Logic Vulnerabilities
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-encryption-oracle

An encryption oracle is what you get when an application will encrypt attacker-controlled data and
hand the ciphertext back, using the same key it trusts elsewhere for something security-critical.
The encryption algorithm itself doesn't need a flaw for this to be dangerous — CBC mode, done
correctly, is not "broken" in the cryptographic sense. The flaw is architectural: reusing one key
across a low-stakes feature that echoes attacker input back as ciphertext, and a high-stakes feature
that trusts ciphertext as an authentication token.

## The Target

The blog application sets a `stay-logged-in` cookie when a user logs in with that option enabled,
containing an encrypted `username:timestamp` string. Separately, commenting on a blog post with an
invalid email address triggers a `notification` cookie containing an encrypted error message that
gets displayed back to the user, reflecting the submitted email inside a fixed prefix string.

## The Investigation

Two cookies, encrypted with (as it turns out) the same CBC key, each exposing one half of an
attack: the `notification` cookie can be *set* to arbitrary ciphertext, and the resulting decrypted
text is displayed on the page — a decryption oracle. The comment form's invalid-email path
*generates* a fresh `notification` cookie by encrypting attacker-controlled input (the email
field) — an encryption oracle. Having both halves of the same cipher available under the same key is
the entire vulnerability.

We used the decryption half first: setting the `notification` cookie to the value of our own
`stay-logged-in` cookie and loading a page that reflects it revealed the plaintext format directly —
`wiener:<timestamp>`. That confirmed both the cookie's structure and that the two cookies really do
share a key.

Then the encryption half: submitting an invalid email of our choosing to the comment form returns a
`notification` cookie encrypting `"Invalid email address: " + our_input`. That fixed 23-character
prefix is the obstacle — we can't directly encrypt an arbitrary plaintext, only that prefix
concatenated with whatever we submit. But CBC ciphertext is a chain of 16-byte blocks, each one
derived from the plaintext block XORed with the *previous* ciphertext block (or the IV, for the
first block) before encryption. Removing complete leading blocks from a CBC ciphertext — including the
IV, which is prepended as the first 16 bytes — doesn't corrupt the blocks that come after; it just
makes the block that used to be third the new first block, decrypting correctly on its own using the
now-preceding block as its IV. Padding the fixed 23-character prefix out to exactly 32 bytes (two full
blocks) with 9 filler characters means the entire prefix occupies whole blocks that can be stripped
cleanly, leaving only our own payload as valid, correctly-decrypting ciphertext.

## The Exploit

1. **Recover the timestamp.** Login with `stay-logged-in` enabled, then set the `notification`
   cookie to the resulting `stay-logged-in` value and read the decrypted `wiener:<timestamp>` string
   back from the page.
2. **Encrypt the forged payload.** Submit a blog comment with the email field set to
   `"x" * 9 + "administrator:" + timestamp` — 9 padding characters bring the fixed
   `"Invalid email address: "` prefix (23 bytes) up to exactly 32 bytes, two full AES blocks. The
   resulting `notification` cookie now encrypts:
   `["Invalid email address: " + "xxxxxxxxx"] || ["administrator:" + timestamp]` across its first
   two ciphertext blocks, with our intended forged cookie value occupying the blocks after that.
3. **Strip the IV and the first ciphertext block.** Base64-decode the cookie, remove the first 32
   bytes (`IV || C1`), and re-encode what's left. In CBC, dropping those bytes makes the former `C2`
   the new leading ciphertext block, decrypting correctly as if it were `C1` with the removed `C2`
   value acting as its IV — the padding was sized specifically so this boundary falls on a clean
   16-byte block edge.
4. **Set the forged cookie and authenticate.** Send the trimmed, re-encoded value as the
   `stay-logged-in` cookie, with no session cookie present at all:

   ```
   Set-Cookie: stay-logged-in={forged}
   ```

   Requesting `/admin` with only that cookie returned the admin panel. Deleting `carlos` solved the
   lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution walks the identical logic: log in with "stay logged in," submit an invalid
comment email to observe the reflected `"Invalid email address: "` prefix, deduce that the
`notification` cookie must decrypt to that reflected text, and use the comment-submission request and
a subsequent GET (each renamed "encrypt" and "decrypt" in Repeater) as the two oracle halves. It
decrypts the `stay-logged-in` cookie to recover `username:timestamp`, encrypts
`administrator:timestamp`, and — after discovering through a block-size error message that exactly
16-byte multiples must be removed — pads the payload with 9 characters specifically so that removing
32 bytes (the full `Invalid email address: ` prefix plus IV) leaves a cleanly decrypting
`administrator:timestamp` ciphertext, which is set as the `stay-logged-in` cookie with the session
cookie deleted.

This is a byte-for-byte match with our approach: the same 23-character prefix, the same 9-character
padding to reach a 32-byte, two-block boundary, and the same "remove IV plus first block" CBC
mechanic. There's essentially no technique divergence in this lab — the encryption oracle admits
exactly one clean solution given the fixed prefix length, and both paths arrive at it through the
same block-arithmetic reasoning. The difference is purely mechanical: PortSwigger discovers the
32-byte requirement through an error message returned by Burp Repeater's Hex-tab byte deletion,
while our script computed the padding and offset directly from the known 23-byte prefix length and
16-byte block size rather than discovering the constraint through trial and error against a live
error response.

## What This Teaches Us

Encryption is not, by itself, an access control — trusting a piece of ciphertext as an authentication
token is only as strong as the guarantee that only the server could have produced that ciphertext for
that plaintext. The moment any other feature on the same domain will encrypt attacker-chosen data
under the same key, that guarantee is gone, because the attacker can now produce arbitrary valid
ciphertexts by construction rather than needing to break the cipher. The fix isn't a stronger
algorithm — CBC with a sound key is fine here — it's never sharing a key between a feature that
echoes user input as ciphertext and a feature that trusts ciphertext as a credential.
