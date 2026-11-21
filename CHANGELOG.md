# Changelog

## [Unreleased]

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
