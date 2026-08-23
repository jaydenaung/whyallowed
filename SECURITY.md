# Security policy

WhyAllowed asks people to paste production IAM policies into it, so it is held to a higher standard than a normal static page. Reports are welcome.

## Before you report: never paste real policies

**Do not put real policy documents, account IDs, ARNs, bucket names, role names or CloudTrail output in a GitHub issue.** Issues are public and permanent.

Reproduce the problem with placeholder values instead. The AWS documentation account IDs are `111122223333`, `111122224444` and `999988887777`, and every example shipped in this repo uses them.

## What counts as a vulnerability here

This is a single static HTML file with no server, no backend and no user accounts, so the interesting attack surface is narrow and specific:

- **Script injection through pasted JSON.** Any policy document, Context field or CloudTrail record that causes script to execute in the page. This is the highest severity issue possible in this project, because it could read every other tab of pasted policy. Report it privately, see below.
- **Any outbound network request.** The page must never make one. `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, an external script, stylesheet, font or image, anything at all. If you observe a request leaving the page, that is a critical bug.
- **Data persistence.** `localStorage`, `sessionStorage`, cookies, IndexedDB or anything else that survives a tab close.
- **A wrong verdict.** An action reported as allowed when AWS would deny it, or denied when AWS would allow it. This is not a memory-safety bug, but for this tool a wrong "allowed" is the most damaging thing it can do, so it is treated as a security issue rather than a feature request.

## How to report

- **Injection or data leakage:** use [GitHub private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository. Please do not open a public issue first.
- **Wrong verdicts and everything else:** a normal public issue is fine. Include the placeholder policy set, the action, the verdict you got, and the verdict you expected.

This is a personal project maintained in spare time. There is no SLA. Realistically expect a few days for a first response, and please do not treat a slow reply as an invitation to disclose publicly without talking to me first.

## Verifying your copy

Everything runs locally, so you can and should check that the file you loaded is the file that was published:

```bash
shasum -a 256 index.html
```

Compare against the hash on the corresponding release. The whole file is human readable, has no build step and no dependencies, so you can also just read it.

## Defences currently in place

- One HTML sink (`$('#results').innerHTML`) and one escaper (`esc()`), applied to every user-controlled string
- A Content Security Policy shipped as both a meta tag and a real HTTP header, including `default-src 'none'` and `connect-src 'none'`, so the browser blocks exfiltration even if injection were achieved
- Objects keyed by pasted strings use `Object.create(null)` so a key such as `__proto__` cannot reach `Object.prototype`
- No dependencies, so no supply chain to compromise

See `HANDOFF.md` for the invariants any contributor is expected to preserve.
