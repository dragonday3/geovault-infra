# Changelog

## [Unreleased]

### Milestone C3: public-bucket misconfiguration exercise (2026-11-21)

- `terraform/exercises/public-bucket`: a deliberately public "partner export" bucket in a
  sandbox emulator account (111111111111) with synthetic data. Three phases:
  - `phase=vulnerable`: the mistake.
  - `phase=fixed`: private, SSE-KMS, versioned, TLS only.
  - `guardrail=true`: account-level Block Public Access.
  The local-emulator-only guard is the same as `envs/local`.
- `verify/scan_public.py` (compose service `scan`): an account-wide, Prowler-style S3 exposure
  scan. It checks account and bucket Block Public Access, public policies and ACLs, TLS-only,
  KMS and versioning, and makes an anonymous `GET` to prove real exposure.
- `run.sh` runs every phase and asserts each outcome:
  - a static Checkov scan of the resolved plans;
  - detection, including a successful anonymous download;
  - the fix (403);
  - prevention: S3 rejects the repeated mistake under the account guardrail.
  CI job `exercise` runs it on every push.
- **Stack gap found and fixed:** `aws_s3_account_public_access_block` is added to the bootstrap,
  and the verifier checks it (68 checks).
- Lessons recorded in `docs/exercises/c3-public-bucket.md`:
  - Source scanning missed the public policy and gave false positives on the fix.
  - Values computed at apply are invisible to plan scans.
  - Plans of a change embed the old state.
- The main Checkov gate skips `exercises/`, which is insecure on purpose and has its own CI
  assertions.

### Milestone C2: CI bootstrap with GitHub OIDC (2026-11-21)

- `modules/bootstrap`:
  - Terraform state bucket: versioned, SSE, all Block Public Access settings, ACLs disabled,
    TLS-only policy, old versions expire after 90 days.
  - GitHub Actions OIDC provider.
  - Two CI roles whose trust uses `StringEquals` on audience and subject:
    - `geovault-ci-plan` (main only): `ReadOnlyAccess`, writes only `*.tflock`, KMS decrypt only
      through the `geovault-prod` alias and only via SSM.
    - `geovault-ci-apply` (only the `production` environment, which has a required reviewer):
      `PowerUserAccess`, plus IAM limited to `geovault-prod-*` and PassRole only to EC2 and VPC
      flow logs.
- `envs/aws-bootstrap`: a one-time root for the real account. Validated, not applied.
- CI: `plan-aws`, `plan-for-apply` and `apply-aws` jobs. They are skipped until repository
  variables exist. They use OIDC with `id-token: write` granted per job and a pinned
  `configure-aws-credentials`. The `terraform-aws` compose service passes the OIDC
  session through. Nothing is stored.
- Verifier: new checks cover the OIDC audience and subject, the read-only plan role,
  lock-only writes, and the exact inline policy set on every role.
- Mutation-tested:
  - A widened trust (`repo:dragonday3/*`), `AdministratorAccess` on the plan role and a
    backdoor inline policy are each detected.
  - Fixed: IAM policies are now owned exclusively (`aws_iam_role_policy_attachments_exclusive`,
    `aws_iam_role_policies_exclusive`), so `apply` removes anything attached by hand. A plain
    attachment let `AdministratorAccess` survive.
  - Fixed: the verifier first missed an extra inline policy. It now compares the full list.
- **Fresh-eyes review (critical finding, fixed before shipping):** `CreateRole`, `PutRolePolicy`
  and `PowerUserAccess`'s `sts:AssumeRole` together let the apply role escalate to admin.
  Fixes:
  - `geovault-<env>-boundary` permissions boundary on every stack role. The apply role's
    role-raising IAM writes now require it.
  - Explicit denies: state-bucket tampering, `cloudtrail:StopLogging`, and edits to its own
    roles, the boundary or the OIDC provider.
- Other review fixes:
  - Pull requests no longer get AWS credentials.
  - The plan role's decrypt is limited to SSM, so it cannot read the photos.
  - Deploying is split into plan-for-apply (published for review) and apply-aws (approval,
    re-plan, then apply only if the changes hash matches).
  - Pushes cannot cancel a running apply, and state access is serialized.
  - Missing IAM actions added.
- Verifier: 67 checks. New checks cover the boundary on stack roles, guarded role writes, the
  deny statements, the state bucket TLS policy and the apply role's exact managed policies.
  All were mutation-tested.
- Checkov: 0 failed. actionlint: clean.

### Milestone C1: hardened stack, local emulator, verification (2026-11-21)

- Terraform modules `kms`, `network`, `storage`, `iam`, `secrets`, `compute` and `audit`,
  composed by `terraform/stack`. Environments: `envs/local` (MiniStack) and `envs/aws`
  (ap-south-1, S3 backend with `use_lockfile`; validated, never applied).
- `compose.yml` adds MiniStack 1.5.43, Terraform 1.17.2, Checkov 3.4.6 and the verifier, all
  pinned by digest. Terraform and the verifier run on an internal network with no internet
  route. The local provider is pinned to account `000000000000` through STS.
- `verify/verify.py` runs 45 read-only checks covering KMS rotation, S3 public access,
  encryption, versioning and TLS-only policy, network rules, flow logs, IMDSv2, EBS encryption,
  IAM least privilege, SecureString secrets, CloudTrail and budget alerts.
- Mutation-tested: Block Public Access removal, KMS rotation off and an SSH 0.0.0.0/0 rule are
  each detected, then repaired by `terraform apply`.
- Fixed during C1:
  - The security group now uses inline, exclusive rules. Separate rule resources let a
    hand-added SSH rule survive `apply`.
  - The missing `s3control` endpoint let one call reach real AWS. It was rejected with dummy
    credentials (403). The network isolation above now prevents this class of leak.
  - Flow-log retention raised to 400 days.
- Checkov: 0 failed checks. Each accepted finding is skipped inline with its reason (public IP
  without NAT/ALB, no cross-region replication, SSE-S3 on the log bucket, and others).
- CI: fmt, validate (both environments), Checkov and Gitleaks, then a job that applies the
  stack to the emulator, runs the verifier and destroys it. No AWS credentials exist in CI.
