# Lab: Developing a custom gadget chain for Java deserialization

**Category:** Insecure Deserialization
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-developing-a-custom-gadget-chain-for-java-deserialization

Every Java lab up to this point relied on a chain someone else already built — ysoserial did the
hard work, we just picked the right entry from its catalog. This lab removes that crutch
entirely: there's no library-wide gadget chain to reach for, because the vulnerability lives in
the application's own code. Building the exploit means reading leaked source, finding where a
deserialized field flows into something dangerous, and constructing a payload object by hand.

## The Target

The same session-cookie deserialization point as the Apache Commons lab, but this application also
exposes a `/backup/` directory containing leaked `.java` source files — `AccessTokenUser.java` and
`ProductTemplate.java`. `ProductTemplate` is the class actually deserialized from the session
cookie.

## The Investigation

Reading `ProductTemplate.java` showed its `readObject()` method — the Java equivalent of a magic
method, invoked automatically during deserialization — executing a SQL query built directly from
one of the object's own fields: `SELECT * FROM products WHERE id = '{id}' LIMIT 1`, with `id`
interpolated straight from the deserialized object with no parameterization. That's a SQL
injection vulnerability, but a distinctive one: the injection point isn't a request parameter at
all, it's a field inside a Java object we construct and serialize ourselves. Building the exploit
meant compiling a minimal local `ProductTemplate` class — matching the target's package
(`data.productcatalog`), `serialVersionUID` (`1L`), and the single `private final String id` field
— purely so Java's own `ObjectOutputStream` could produce a wire-compatible serialized instance
with our chosen `id` value baked in.

With that harness in place, a single quote in the `id` field confirmed the injection fired on
deserialization and broke the underlying query. From there, the database was PostgreSQL, and
rather than automating a purely blind extraction we used the response's own error text: casting a
subquery result to an incompatible type makes PostgreSQL echo the value it failed to cast, right
in the error message.

## The Exploit

We serialized a `ProductTemplate` with its `id` field set to an error-based extraction payload:

```
' AND 1=CAST((SELECT password FROM users WHERE username='administrator') AS int)--
```

Injected via the deserialized object rather than a URL parameter, this forces PostgreSQL to
attempt casting the administrator's password string to an integer — which fails, and the resulting
error surfaces the offending value directly:

```
ERROR: invalid input syntax for type integer: "the_password_here"
```

Base64-encoding the serialized object and sending it as the session cookie on a request to
`/my-account` returned that error in the response body; a regex against the
`invalid input syntax for (?:type )?integer: "([^"]+)"` pattern (matching against the
HTML-decoded response, since `&quot;` needed unescaping first) pulled the administrator's password
straight out. Logging in with the recovered credentials and deleting `carlos` from the admin panel
solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's official solution reaches the same starting point — the same `/backup/` source leak,
the same discovery that `ProductTemplate.readObject()` interpolates `id` into a SQL query, the same
single-quote confirmation of the injection — but extracts the password differently. Their
walkthrough enumerates the query's column count (eight) and uses a UNION-based extraction,
`' UNION SELECT NULL, NULL, NULL, CAST(password AS numeric), NULL, NULL, NULL, NULL FROM users--`,
substituting the password into whichever column position renders visibly in the application's
response.

We used error-based extraction instead — casting the password directly to `int` and reading it out
of the exception message — which works because PostgreSQL's error output includes the exact value
it couldn't cast. Both techniques are standard SQL injection extraction methods and both are valid
against this same injection point; which one is preferable depends entirely on what the
application's response actually surfaces. UNION-based extraction needs a response that echoes back
query results in a visible position, which requires first mapping out the column count and finding
which columns render; error-based extraction needs a response that surfaces database error text at
all, which is often present in permissive debug configurations. Here, both signals happened to be
available, and we reached for the one that avoided the column-counting step.

## What This Teaches Us

This lab is where deserialization vulnerabilities and classic web vulnerabilities actually merge:
the interesting bug isn't in the deserialization mechanism at all, it's a SQL injection that would
be completely unremarkable from a URL parameter — the only unusual part is that the injection point
happens to be a field inside a serialized object instead. That distinction matters practically: a
source code review looking only for obvious request-parameter-to-SQL flows would miss this, because
`id` never appears as a query string parameter anywhere in the application's routes. It's populated
exclusively from deserialized session state. The fix is the same as any SQL injection — parameterize
the query — but the discovery method is deserialization-specific: leaked source review, identifying
which object fields the deserializer trusts, and recognizing that "arbitrary object I get to build
myself" is just as much an injection point as any HTTP parameter, arguably more dangerous because
it's less likely to be on anyone's SAST scanner's radar for this exact data flow.
