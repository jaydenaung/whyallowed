# WhyAllowed

A free AWS IAM policy analyser that answers one question AWS itself makes hard to answer: **why is this allowed?**

Paste your policies and it traces every action through the same five checks AWS actually runs, then tells you in plain English what this identity can do, why it can do it, and what breaks if the credential is stolen.

It is a single HTML file with no build step and no dependencies. Everything runs in your browser. There are no network calls anywhere in the file, and the served page sends `connect-src 'none'`, so nothing you paste can leave the tab even if the page were compromised.

Open it in a browser, paste policy JSON, read the verdict instead of the JSON.

---

## The problem it solves

An AWS permission is never decided by one document. A single `s3:GetObject` call is the outcome of up to six separate policies, written by different teams, living in different consoles:

| Layer | Who usually owns it | Where it lives |
|---|---|---|
| Service control policy | Cloud platform or governance | AWS Organizations |
| Permissions boundary | Security engineering | IAM |
| Identity policy | Application team | IAM |
| Resource policy | Data or platform owner | S3, SQS, and so on |
| Trust policy | Whoever created the role | IAM |
| KMS key policy | Key administrator | KMS |

Nobody reads all six together. So the common failures are all correlation failures:

- A bucket policy grants access that the IAM policy never mentions, so an IAM review shows nothing.
- A GitHub Actions role trusts `repo:org/*:*`, which means every repository in the organisation, including the one an intern created yesterday.
- A role has `s3:*` and `iam:PassRole` on `*`, which is not "storage access", it is administrator two steps away.
- An IAM policy allows `kms:Decrypt`, the key policy never names the principal, and the pipeline fails in production with a confusing error.
- A permissions boundary is set to `Allow *` on `*`, which passes every review and constrains nothing.

This tool reads them together, applies the real AWS evaluation order, and states the final answer in plain English.

---

## What it produces

**Risk score and headline.** A single number and one sentence naming the worst thing that is true.

**Blast radius diagram.** The principal at the centre. Each service it can reach is placed on a ring by how far the damage travels: read, change, data, destroy or escalate. Bubble size is the number of actions. An outer red ring appears when an unauthenticated caller can reach the bucket.

**Trust and role chaining graph.** Entry points on the left, roles in the middle, the reach of each role on its right edge. Solid edges work today. Dashed edges also need `sts:AssumeRole` on the caller side. Paths are ranked by what the last role can do, not by hop count.

**Privilege escalation paths.** Only shown when the identity holds every action a known chain needs, evaluated against final permissions rather than raw grants. Covers the IAM classics plus EKS access entries, ECS task roles, CloudFormation, SageMaker, Glue and SSM.

**Final effective permissions.** A table of actions with the verdict and what decided it. Click any row to trace it through the same gates AWS runs: explicit deny, SCP ceiling, permissions boundary, identity policy, resource policy, KMS key policy, and a preceding gate showing how the credential was obtained.

**Findings.** Each one has three parts: what this means, why it matters in attacker terms, and how to fix it with a copy-ready JSON snippet. Good practices are reported too, so a customer sees what they got right.

**Least privilege from evidence.** When CloudTrail events are supplied, a generated policy scoped to observed resources, the list of granted-but-never-used permissions sorted with escalation first, and any denied attempts.

Everything runs in the browser. There are no network calls anywhere in the file. You can hand it to a customer who will paste production policies into it.

---

## Quick start

1. Open `index.html` in Chrome, Edge, Firefox or Safari. No install, no server, no build.
2. Choose an example from the picker at the top right. Start with **Overly permissive IAM and public S3**.
3. Click a row in the effective permissions table to see the evaluation chain for that action.
4. Load **CloudTrail: right-size an over-permissive role**, scroll to the generated policy, and press **Apply to IAM tab and re-analyse**. The score falls from 100 Severe to 0 Contained.

The six examples are each built to show one thing:

| Example | What it demonstrates |
|---|---|
| Overly permissive IAM and public S3 | Wildcards, `NotAction`, public bucket, boundary and SCP catching the fall |
| Hardened least privilege | What a good policy set scores, and conditioned public principals |
| CI/CD chain: GitHub OIDC to admin | `repo:org/*:*` reaching a role with `PassRole` and `RunInstances` |
| Enterprise SSO and human access | Cognito guest role with data access, SAML with no audience condition |
| SSE-KMS: allowed by S3, denied at the key | The correctness case that IAM review alone gets wrong |
| CloudTrail: right-size an over-permissive role | 18 unused permissions and a generated replacement policy |

---

## Running it against your own environment

### Step 1: collect the policies

Replace the placeholder names. All of these are read-only calls.

**Identity policy** for the role you are reviewing:

```bash
# managed policies attached to the role
aws iam list-attached-role-policies --role-name MyRole

# the document for one of them
aws iam get-policy-version \
  --policy-arn arn:aws:iam::111122223333:policy/MyPolicy \
  --version-id v3 \
  --query 'PolicyVersion.Document'

# any inline policy
aws iam list-role-policies --role-name MyRole
aws iam get-role-policy --role-name MyRole --policy-name Inline1 --query 'PolicyDocument'
```

**Trust policy and permissions boundary:**

```bash
aws iam get-role --role-name MyRole --query 'Role.AssumeRolePolicyDocument'
aws iam get-role --role-name MyRole --query 'Role.PermissionsBoundary'
# if a boundary is set, fetch its document with get-policy-version as above
```

**Resource policy.** The same correlation failure that hides behind an S3 bucket policy hides behind any resource-based policy. Paste the one that applies:

```bash
# S3 bucket
aws s3api get-bucket-policy --bucket my-bucket --query Policy --output text

# SQS queue
aws sqs get-queue-attributes --queue-url https://sqs.ap-southeast-1.amazonaws.com/111122223333/my-queue \
  --attribute-names Policy --query 'Attributes.Policy' --output text

# SNS topic
aws sns get-topic-attributes --topic-arn arn:aws:sns:ap-southeast-1:111122223333:my-topic \
  --query 'Attributes.Policy' --output text

# Secrets Manager secret
aws secretsmanager get-resource-policy --secret-id my-secret --query ResourcePolicy --output text

# Lambda function
aws lambda get-policy --function-name my-function --query Policy --output text

# ECR repository
aws ecr get-repository-policy --repository-name my-repo --query policyText --output text
```

**KMS key policy and grants:**

```bash
aws kms get-key-policy --key-id 1234abcd-... --policy-name default --query Policy --output text
aws kms list-grants --key-id 1234abcd-...
```

**Service control policy:**

```bash
aws organizations list-policies-for-target \
  --target-id ou-abcd-12345678 --filter SERVICE_CONTROL_POLICY
aws organizations describe-policy --policy-id p-abcd1234 --query 'Policy.Content'
```

**CloudTrail evidence** for the role:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=MyRole \
  --start-time 2026-05-01 --end-time 2026-08-01 \
  --max-results 200
```

Paste the whole `lookup-events` response. The tool understands that shape, an S3 trail file with a `Records` array, a plain array of events, and CSV rows of `eventSource,eventName`.

For a serious sample, query CloudTrail in Athena and export two columns:

```sql
SELECT eventsource, eventname
FROM cloudtrail_logs
WHERE useridentity.sessioncontext.sessionissuer.arn LIKE '%MyRole%'
  AND eventtime > '2026-05-01'
GROUP BY 1, 2;
```

### Step 2: paste and set context

Tabs, left panel: **IAM**, **Resource policy**, **SCP**, **Boundary**, **Trust**, **KMS key**, **CloudTrail**. Every tab is optional and each analyser works on its own.

The Resource policy tab accepts any resource-based policy: S3 bucket, SQS queue, SNS topic, Secrets Manager secret, Lambda function or ECR repository. The service is detected from the actions named inside the pasted JSON, so there is nothing to select. Findings, the effective permissions table and the correlation checks (grants that come only from the resource side, duplicate grants, confused deputy, public exposure) all apply to whichever one you paste.

For chaining, paste a list of roles into the Trust tab:

```json
[
  { "role": "arn:aws:iam::111122223333:role/GitHubDeployRole",
    "trustPolicy": { },
    "identityPolicy": { } },
  { "role": "arn:aws:iam::111122223333:role/AppDeployRole",
    "trustPolicy": { },
    "identityPolicy": { } }
]
```

For KMS, paste the key policy on its own, or with grants:

```json
{ "keyArn": "arn:aws:kms:ap-southeast-1:111122223333:key/1234abcd",
  "keyPolicy": { },
  "grants": [ { "name": "backup", "granteePrincipal": "arn:...", "operations": ["Decrypt"] } ] }
```

Fill the Context panel where it applies. It changes the answer, not just the labels:

- **Principal ARN**: who you are asking about. Its account decides same-account versus cross-account evaluation.
- **Resource owner account**: set this when the resource lives in a different account from the principal.
- **Organisation ID** and **Your account IDs**: how the tool tells an internal account from a third party.
- **Bucket encryption key**: pasting a KMS policy or filling this field makes S3 object actions resolve as S3 plus the matching KMS operation.

### Step 3: read the results in this order

1. **Headline.** The worst true statement.
2. **Blast radius.** Anything on the outer ring is what an attacker uses first.
3. **Escalation paths and trust graph.** These turn "one role" into "the whole account".
4. **Effective permissions.** Click the highest-risk allowed action and read the gate chain. This is the row to screenshot for a report.
5. **Findings.** Work top down. Critical and high first, and note the good practice entries, since they tell you which control is currently doing the work.

### Step 4: fix and re-run

Every finding carries a hardened JSON snippet. Apply it, re-paste, and watch the score. With CloudTrail supplied, use **Apply to IAM tab and re-analyse** to see the generated least privilege policy scored against the same rules.

---

## How the verdict is reached

Evaluation follows AWS order:

1. **Explicit deny** anywhere wins, always.
2. **SCP ceiling.** If an SCP is supplied and does not allow the action, nothing below can grant it.
3. **Permissions boundary.** Caps identity-based grants.
4. **Identity policy** and **resource policy** are combined. Same account needs an allow on only one side. Cross account needs both.
5. **KMS key policy**, when the data is encrypted with SSE-KMS.

Two documented exceptions are implemented, because both routinely surprise people:

- **Role trust policies.** Inside one account, an explicit principal ARN in the trust policy is enough on its own. An account root principal, or any cross-account principal, also needs `sts:AssumeRole` in the caller's identity policy. Those edges are drawn dashed in the graph.
- **KMS key policies.** The key policy must name the principal itself. An IAM policy only works when the key policy delegates to the account root, which is what the standard `Enable IAM User Permissions` statement does.

**Scoring:** critical 30, high 14, medium 6, low 2, capped at 100. Bands are Contained under 20, Elevated under 45, High under 75, Severe above that. It is a communication device for prioritising a session, not a compliance rating.

---

## Limits, stated plainly

- **Conditions are reported, not simulated.** There is no request context in a browser, so a conditioned grant shows as "Allow if" with the condition printed. It never guesses whether the condition would be met.
- **Effective permissions come from a probe list**, not the full AWS action set. The list is the high-signal actions across every service, plus every action your policies name or cover with a wildcard. The header states how many actions were probed. Treat the counts as a floor.
- **Only what you paste is considered.** Other attached policies, session policies, S3 Block Public Access, object ACLs, resource control policies and VPC endpoint policies can all change the real answer.
- **CloudTrail proves what was used, never what is needed.** A short window misses monthly and quarterly jobs, and S3 data events are off by default on most trails. Send generated policies to a staging role first.
- **This is an analysis and explanation tool.** Confirm any change with the IAM policy simulator and IAM Access Analyzer before applying it to production.

---

## Suggested workshop flow, about ten minutes

1. Load the risky example. Point at the headline, not the JSON. *"This is the same policy set you sent us, in one sentence."*
2. Open the blast radius. *"If this credential leaks, these five services are reachable and three of these actions are not reversible."*
3. Load the CI/CD example. Trace `repo:org/*:*` to a role with `PassRole`. *"Any repository in your org, including new ones, reaches this."*
4. Load the SSE-KMS example. Show `s3:GetObject` denied at the key. *"An IAM-only review would have told you this works."*
5. Load the CloudTrail example. Press apply. *"Same role, evidence-based policy, score 100 to 0."*

The strongest moment is usually step 4 or 5, because both are things the customer's current tooling did not tell them.

---

## Privacy and security

This tool asks you to paste production IAM policies, so it should be held to a higher standard than a normal web page. Here is exactly what protects you.

**Nothing leaves your browser.** There is no `fetch`, no `XMLHttpRequest`, no `WebSocket`, no `sendBeacon`, no analytics, no external script, stylesheet, font or image anywhere in the file. There is no `localStorage`, no `sessionStorage` and no cookie. Nothing is read from the URL. Close the tab and the data is gone.

**That claim is enforced, not just promised.** The page ships a Content Security Policy as both a meta tag and a real HTTP header via `_headers`:

```
default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline';
img-src data:; connect-src 'none'; form-action 'none'; base-uri 'none';
frame-ancestors 'none'
```

`connect-src 'none'` means the browser itself blocks every outbound request. Even if someone found a way to inject script into the page, there is no network path to send your policies anywhere. `script-src 'unsafe-inline'` is required because this is a single file with one inline `<script>`, so the CSP does not prevent injection, it prevents exfiltration. That is the honest description.

**Verify what you loaded.** Print the hash of your copy and compare it against the release:

```bash
shasum -a 256 index.html
```

**Reporting an issue.** Open a GitHub issue. Do not paste real policies, account IDs or ARNs into it.

---

## Run it yourself

It is one file. Any of these work:

```bash
# just open it
open index.html

# or serve it locally
python3 -m http.server 8000
```

**Deploying your own copy** to Cloudflare Pages, which is free with unlimited bandwidth and allows commercial use:

1. Push this repo to GitHub.
2. Cloudflare dashboard, Workers and Pages, Create, Pages, Connect to Git.
3. Pick the repo. Framework preset **None**, build command **empty**, output directory **`/`**.
4. Deploy. The `_headers` file is picked up automatically, so you get the CSP and HSTS headers with no extra config.

There is no build step, so there is nothing to break.

---

## Reporting a bug or a wrong verdict

See [SECURITY.md](SECURITY.md). One rule above all others: **never paste real policies, account IDs or ARNs into a GitHub issue.** Reproduce with the placeholder account IDs used throughout this repo.

A wrong verdict is treated as a security issue here, not a feature request. If this tool says "allowed" when AWS would say "denied", that is the worst thing it can do, and I want to know.

---

## Disclaimer

**Independent project.** WhyAllowed is a personal project. It is not affiliated with, sponsored by, or endorsed by Amazon Web Services or any other organisation. Amazon Web Services, AWS, IAM, S3, KMS, CloudTrail and related marks are trademarks of Amazon.com, Inc. or its affiliates. They are used here only to describe truthfully what this tool analyses.

**Not an audit, and no warranty.** This is an analysis and teaching tool, provided as is, without warranty of any kind. Its output is not a security audit, a compliance assessment, or professional advice, and no liability is accepted for any decision made using it.

It sees only what you paste. Other attached policies, session policies, S3 Block Public Access, object ACLs, resource control policies and VPC endpoint policies can all change the real answer. Conditions are reported, not simulated. The effective permissions table comes from a probe list, not the full AWS action set, so treat the counts as a floor. Confirm every finding with the AWS IAM policy simulator and IAM Access Analyzer before changing anything in production.

**Privacy.** This tool collects nothing. No analytics, no cookies, no storage, and nothing you paste is transmitted anywhere. Everything is computed in your browser and is gone when you close the tab. The hosted copy is served by Cloudflare Pages, which logs standard request metadata such as IP address and user agent in order to serve the page, as any web host does. If that matters to you, download `index.html` and open it locally. It works identically with no network connection at all.

---

## Licence

MIT. See [LICENSE](LICENSE).

Built by a cloud security architect, for cloud security architects.

By [Jayden Aung](https://x.com/jaydenaung).
