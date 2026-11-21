# Exercise C3: the public "partner export" bucket

**Where:** local AWS emulator only (MiniStack), in a separate sandbox account `111111111111`.
**Data:** synthetic, three invented users at `example.com`.
**Reproduce:** `sh terraform/exercises/public-bucket/run.sh`. CI runs the same script on every
push and fails if any expectation below stops holding.

## Scenario

A developer has to hand a CSV export to a partner. Instead of issuing a presigned URL, they
switch off the bucket's Block Public Access and add a bucket policy that lets anyone read it:

```hcl
Statement = [{ Sid = "PublicRead", Effect = "Allow", Principal = "*",
               Action = "s3:GetObject", Resource = "arn:aws:s3:::<bucket>/*" }]
```

This is the classic cloud data-exposure pattern. The export holds emails and home coordinates,
exactly the location data GeoVault exists to protect.

## Results

| Phase | What ran | Outcome |
|---|---|---|
| 0. Before deploy | Checkov on the **resolved Terraform plan** | Vulnerable plan: 12 failed checks, including **CKV_AWS_70** (allows any principal) and CKV_AWS_53/54/55/56 (Block Public Access off). Fixed plan: no exposure findings. |
| 1. Vulnerable | `terraform apply`, then the account scanner (`verify/scan_public.py`) | **2 critical**: a public bucket policy, and an **anonymous download that succeeded** (HTTP 200; the first bytes were the CSV header and the first user's email). Plus 3 medium and 2 low findings. |
| 2. Fixed | Private bucket, SSE-KMS, versioning, TLS-only policy, **account-level Block Public Access** | Anonymous download **403**. 0 findings. |
| 3. Prevention | The same mistake again, with the account guardrail still on | S3 **rejected** the public policy: `AccessDenied: public policies are prevented by the BlockPublicPolicy setting in S3 Block Public Access`. The data stayed private. |

Scanner output, vulnerable phase:

```
Account 111111111111: account-level Block Public Access OFF
CRITICAL  geovault-exercise-partner-export  s3_bucket_policy_public_access        Allow to Principal * (Sid PublicRead)
CRITICAL  geovault-exercise-partner-export  anonymous_object_read                 GET exports/partner-2026-11.csv without credentials -> 200, first bytes: 'user_id,email,display_name,home_lat,home_lon ...'
MEDIUM    (account)                         s3_account_level_public_access_blocks account-wide guardrail is off
MEDIUM    geovault-exercise-partner-export  s3_bucket_level_public_access_block   {"BlockPublicAcls": false, ...}
MEDIUM    geovault-exercise-partner-export  s3_bucket_secure_transport_policy     no deny for non-TLS requests
LOW       geovault-exercise-partner-export  s3_bucket_kms_encryption              default encryption: AES256
LOW       geovault-exercise-partner-export  s3_bucket_object_versioning           versioning off
7 finding(s), 2 critical
```

The fixed plan's 5 remaining Checkov items are hygiene, not exposure: cross-region
replication, an explicit KMS key policy, access logging, lifecycle rules and event
notifications. The main stack has them, or skips them with documented reasons.

## What I learned (and changed)

1. **Scan the plan, not only the source.**
   - Checkov on the `.tf` source could not resolve the `phase` conditional. It reported the
     same 10 failures for both phases, so the fixed version looked broken.
   - More importantly, it **never flagged the `Principal: "*"` policy** at all.
   - Scanning `terraform show -json` of the plan gives the resolved values. It catches the
     public policy and is clean for the fix.
2. **Values unknown at plan time are invisible to plan scanners.** The first version built the
   policy from `aws_s3_bucket.export.arn`. That value is unknown until apply, so the plan held
   `policy = null` and Checkov missed the public statement again. The policy now uses an ARN
   built from the known bucket name.
3. **A plan of a change embeds the old state.** Scanning the "fixed" plan made over the
   vulnerable deployment still reported CKV_AWS_70, because the plan JSON's `prior_state`
   contains the old public policy. The exercise scans plans built against an empty state.
4. **Detection must include the effect, not only the settings.** The scanner's decisive check
   is an anonymous `GET` with no credentials. It proves the exposure (200), and later proves
   the fix (403).
5. **Prevention beats detection: the account-level guardrail.** With account-level S3 Block
   Public Access on, the identical mistake is rejected by S3 itself. **The main stack lacked
   this guardrail.** C3 added `aws_s3_account_public_access_block` to the bootstrap, so the
   real account gets it in C4, and the verifier checks it.

## Mapping

| Framework | Item |
|---|---|
| CIS AWS Foundations | 2.1.4: S3 Block Public Access (account and bucket level) |
| AWS FSBP | S3.1 (account BPA), S3.2/S3.3 (no public read/write), S3.5 (TLS only), S3.8 (bucket BPA) |
| OWASP Top 10 (2021) | A05 Security Misconfiguration |
| Privacy | APP 11 (AU) / DPDP Act s.8(5) (IN): reasonable security safeguards for personal data |

## Limits

- **Emulator fidelity:** the emulator enforces anonymous access and account-level Block
  Public Access, as shown above. It is still not AWS. Real AWS confirms these results in C4,
  where Prowler runs against the real account.
- **Scope:** only S3 bucket policies and Block Public Access are exercised. Public ACLs are
  covered by the scanner and the guardrail, but are not staged here, because ACLs are
  disabled by default on new buckets.
