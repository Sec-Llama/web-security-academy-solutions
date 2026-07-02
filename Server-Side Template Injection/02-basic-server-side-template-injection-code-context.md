# Basic server-side template injection (code context)

**Category:** Server-Side Template Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic-code-context

The previous lab's injection point was a full, unrestricted template string — our input became
the entire expression. Most real templates don't work that way; user input usually lands *inside*
an expression the developer already wrote, surrounded by their own template syntax. That's a
meaningfully different injection shape, because the payload has to close what's already open
before it can introduce anything new, and this lab is built around exactly that constraint.

## The Target

The blog lets a logged-in user choose how their name displays above their comments — full name,
first name, or nickname. Picking an option sends:

```
POST /my-account/change-blog-post-author-display
blog-post-author-display=user.name
```

and the value of that parameter (`user.name`, `user.first_name`, or `user.nickname`) is later
used inside a template expression when the blog post renders, presumably something shaped like
`{{ <chosen value> }}`. We don't see the surrounding `{{ }}` — we only control what goes between
them.

## The Investigation

Because the injection point sits inside an existing expression rather than being the whole
template, our approach had to account for context explicitly. We built the injection as an
`SSTIPoint` with a `context_prefix` of `user.name` — the legitimate value the parameter already
expects — and treated everything after it as attacker-controlled. Closing the surrounding braces
and reopening a fresh expression turns "one value inside `{{ }}`" back into "arbitrary template
syntax":

```
user.name}}{{7*7}}
```

Setting `blog-post-author-display` to this value and then reloading the blog post that carries
our comment rendered the author name as `Peter Wiener49}}` — the `}}` closed the original
expression, `{{7*7}}` evaluated as a new one, and the trailing `}}` from that new expression
leaked through as literal text. The `49` confirmed both the injection and math-eval syntax
consistent with Tornado (Python's templating engine), which the lab's stack made the leading
candidate.

## The Exploit

Tornado supports statement blocks with `{% %}`, distinct from expression blocks with `{{ }}`,
which meant the RCE payload needed both: a statement to import `os`, and an expression to invoke
it. Our tool's code-context RCE table for Tornado is:

```
}}{% import os %}{{ os.popen('{CMD}').read()
```

prepended with the same `user.name` context prefix used for detection. Substituting the delete
command against Carlos's file gives the full parameter value:

```
blog-post-author-display=user.name}}{% import os %}{{ os.popen('rm /home/carlos/morale.txt').read()
```

We POSTed that to `/my-account/change-blog-post-author-display`, then requested the blog post
page again to force the template to actually render (setting the preference alone doesn't trigger
rendering — that only happens when the page containing the comment is loaded). The lab's
"Congratulations" banner confirmed the solve on that second request.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger reaches the same injection point and the same break-out payload — `user.name}}{{7*7}}`
to confirm the vulnerability, then Tornado's `{% import os %}` statement block to reach `os`. The
one real divergence is the RCE call itself: PortSwigger's solution uses
`{{os.system('rm /home/carlos/morale.txt')` (note: deliberately left with an unbalanced final
brace, since Tornado still executes it), while ours used `os.popen('{CMD}').read()`.

Both work, and the difference is a legitimate engineering trade-off documented in our own
payload notes: `os.system()` is fire-and-forget — it runs the command and returns only an exit
code, which is all PortSwigger's solution needs since the goal is just deleting a file. `os.popen()
.read()` runs the command *and* captures its stdout into the rendered page, which our tool defaults
to because a generic exploitation engine needs to work for read-oriented commands too (`cat`,
`id`, directory listings), not just fire-and-forget deletes. For this specific lab the extra
capability was unnecessary, but it's the same reasoning that made `os.popen().read()` the right
default for the verification step afterward.

## What This Teaches Us

Code-context SSTI is a sharper version of the same underlying flaw: the developer never intended
`blog-post-author-display` to be arbitrary template syntax, only one of three whitelisted-looking
values. But because the value is concatenated into the template source rather than passed as a
bound variable, "whitelisted-looking" was never actually enforced anywhere — nothing on the server
checked that the value was one of the three expected strings before it reached the template
engine. The fix is the same as always: bind the value as data (look up the corresponding display
string server-side from an enum, rather than trusting the client to send template-safe text) so
that closing a brace in user input is just two meaningless characters instead of an escape hatch
out of the developer's intended expression.
