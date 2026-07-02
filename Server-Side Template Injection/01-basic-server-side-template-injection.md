# Basic server-side template injection

**Category:** Server-Side Template Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic

Server-side template injection turns a templating engine — the thing meant to safely render
`Hello {{name}}` — into a code execution primitive, because most template languages let you do
far more than substitute variables: import modules, call methods, read the filesystem. The gap
between "renders user input" and "executes user input" is usually just one string concatenation
away from disaster, and this lab is the cleanest possible demonstration of that gap.

## The Target

The lab is a storefront where viewing a product that's out of stock renders a message on the
home page:

```
GET /?message=Unfortunately+this+product+is+out+of+stock
```

The `message` value comes back reflected on the page, which is unremarkable on its own — plenty
of applications echo a query parameter into a status banner without any vulnerability at all. The
question is whether that value is being concatenated into a template string before rendering, or
handed to the template engine purely as inert data.

## The Investigation

We ran our SSTI capability tool's detection routine against the `message` parameter. It works
through a table of math-eval probes, one per major template engine, and checks whether the raw
expression syntax gets evaluated rather than reflected verbatim:

```
${{<%[%'"}}%\        -- shotgun fuzz, triggers errors revealing the engine
{{7*7}}              -- Jinja2 / Twig / Tornado -> 49
${7*7}                -- Freemarker / Velocity / Mako -> 49
<%= 7*7 %>           -- ERB (Ruby) -> 49
#{7*7}                -- Pug / Jade -> 49
```

Sending `<%= 7*7 %>` as the `message` value returned `49` on the page instead of the literal
string — confirmation that the parameter is being evaluated as a template expression, and that
the engine's expression syntax is ERB's `<%= ... %>`. ERB is Ruby's built-in templating language,
consistent with the lab's Ruby/Sinatra-style stack, and its `<%= %>` construct doesn't just
evaluate expressions — it evaluates arbitrary Ruby, including calls to Ruby's `Kernel#system`.

## The Exploit

With ERB confirmed, our tool's exploiter selects from a small set of ERB RCE payload templates
and substitutes the target command:

```
<%= system('{CMD}') %>
```

Substituting the lab's actual goal — deleting Carlos's file — produced:

```
GET /?message=<%25+system('rm+%2Fhome%2Fcarlos%2Fmorale.txt')+%25>
```

(the raw payload is `<%= system('rm /home/carlos/morale.txt') %>`, URL-encoded so `%` and `/`
survive transport as the query string). The tool followed up by requesting the same endpoint with
a `cat`-style verification payload; the response no longer showed the file's contents, and the
lab's own "Congratulations" banner confirmed the solve.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution reaches the identical conclusion by the same path: confirm the
`message` parameter renders on the home page, consult the ERB documentation to learn the
`<%= someExpression %>` syntax, send `<%= 7*7 %>` and observe `49` come back, then consult Ruby's
documentation for `system()` and send `<%= system("rm /home/carlos/morale.txt") %>` URL-encoded
as the `message` value.

The technique is exactly the same — same detection probe, same `system()` call, same target file.
The only real difference is mechanism: PortSwigger's walkthrough is a manual Burp Repeater
exercise (send the request, read the documentation, edit the parameter, resend). Our tool ran the
same probe-then-exploit sequence as two scripted HTTP requests through a generic detector that
tries every major template engine's math probe before settling on the one that fires — which
matters more once you're testing an unknown target rather than a lab that tells you which engine
to expect.

## What This Teaches Us

The vulnerability is structural, not a missing filter: the application built its template string
by concatenating `message` directly into ERB source before calling `render`, rather than passing
it in as a bound variable. ERB has no concept of "this substitution is just data" once the string
reaches the engine — everything inside `<%= %>` is Ruby, full stop. The fix isn't sanitizing the
`message` value; it's never letting user input become part of the template *source* in the first
place. Passing `message` as a template variable (`render("out_of_stock", message: user_input)`)
closes this off completely, because the engine then treats it as a value to substitute, not code
to evaluate.
