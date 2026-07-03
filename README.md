# PortSwigger Web Security Academy — Complete Solutions

> Full **writeups** *and* runnable **solution scripts** for the PortSwigger Web Security Academy labs — every lab solved, explained, and automated.
>
> By **Michael Dahan** — ranked **#38 in the world** on the [PortSwigger Hall of Fame](https://portswigger.net/web-security/hall-of-fame) — founder of **[Sec-Llama Academy](https://academy.sec-llama.com)**.

**270 writeups · 269 scripts · 32 vulnerability categories.**

---

## What's inside

Every lab has two files in its category folder:

- **`NN-slug.md`** — a full writeup: the target, the investigation, the working exploit, a comparison to PortSwigger's own official solution, and what the lab actually teaches about the vulnerability class.
- **`NN-slug.py`** — a real, runnable script that solves the lab against *your own* instance. No hardcoded per-instance values — everything is discovered at runtime, the same way the original solve did.

These aren't simplified teaching toys — they're the actual technique from each writeup, packaged so you can point them at your own lab and watch them solve.

## Quick start

```bash
pip install -r requirements.txt
# a few scripts drive a headless browser:
playwright install chromium

# then point any script at YOUR lab instance URL:
python "SQL Injection/01-retrieve-hidden-data.py" https://YOUR-LAB-ID.web-security-academy.net
```

## Categories

| Category | Labs |
|----------|-----:|
| [XXE Injection](<XXE Injection>) | 9 |
| [WebSockets](<WebSockets>) | 3 |
| [Web LLM Attacks](<Web LLM Attacks>) | 4 |
| [Web Cache Poisoning](<Web Cache Poisoning>) | 13 |
| [Web Cache Deception](<Web Cache Deception>) | 5 |
| [Server-Side Template Injection](<Server-Side Template Injection>) | 7 |
| [Server-Side Prototype Pollution](<Server-Side Prototype Pollution>) | 5 |
| [SSRF](<SSRF>) | 7 |
| [SQL Injection](<SQL Injection>) | 18 |
| [Race Conditions](<Race Conditions>) | 6 |
| [OS Command Injection](<OS Command Injection>) | 5 |
| [OAuth](<OAuth>) | 6 |
| [NoSQL Injection](<NoSQL Injection>) | 4 |
| [JWT](<JWT>) | 8 |
| [Insecure Deserialization](<Insecure Deserialization>) | 10 |
| [Information Disclosure](<Information Disclosure>) | 5 |
| [HTTP Request Smuggling](<HTTP Request Smuggling>) | 22 |
| [HTTP Host Header Attacks](<HTTP Host Header Attacks>) | 7 |
| [GraphQL](<GraphQL>) | 5 |
| [File Upload](<File Upload>) | 7 |
| [Essential Skills](<Essential Skills>) | 2 |
| [Directory Traversal](<Directory Traversal>) | 6 |
| [DOM-Based Vulnerabilities](<DOM-Based Vulnerabilities>) | 7 |
| [Cross-Site Scripting (XSS)](<Cross-Site Scripting (XSS)>) | 30 |
| [Client-Side Prototype Pollution](<Client-Side Prototype Pollution>) | 5 |
| [Clickjacking](<Clickjacking>) | 5 |
| [CSRF](<CSRF>) | 12 |
| [CORS](<CORS>) | 3 |
| [Business Logic Vulnerabilities](<Business Logic Vulnerabilities>) | 12 |
| [Authentication](<Authentication>) | 14 |
| [Access Control](<Access Control>) | 13 |
| [API Testing](<API Testing>) | 5 |


## About

These solutions are written and maintained by **Michael Dahan**, an active red teamer and founder of **[Sec-Llama Academy](https://academy.sec-llama.com)**. Every writeup is written to the standard of a serious research blog — the reasoning, not just the payload.

If you're working through these to break into offensive security, Sec-Llama Academy runs a live, hands-on **"zero to junior penetration tester"** program in small cohorts. It starts with a **free live webinar** → **[academy.sec-llama.com](https://academy.sec-llama.com/#webinar)**. More free walkthroughs: **[academy.sec-llama.com/learn](https://academy.sec-llama.com/learn/)**.

## Disclaimer

For **education and authorized security testing only.** The scripts target *your own* PortSwigger Web Security Academy lab instances. Do not use these techniques against any system you do not own or are not explicitly authorized to test. Unauthorized access is illegal.

## License

[MIT](LICENSE) © 2026 Michael Dahan / Sec-Llama S.A.C.
