# One-time account bootstrap: everything CI needs before the stack itself can be planned.
#   - Terraform state bucket (versioned, encrypted, private, TLS only)
#   - GitHub Actions OIDC identity provider: CI gets short-lived credentials, no stored keys
#   - plan role:  read-only + state lock; trusted ONLY from this repo's main branch
#                 (pull requests never get AWS credentials: they run on the emulator)
#   - apply role: change rights; trusted ONLY from the GitHub "production" environment,
#                 which requires a human reviewer before the job starts
#   - permissions boundary: every role the apply role creates or edits must carry it, which
#                 caps those roles at S3 / KMS / SSM / logs. Without it, CreateRole +
#                 PutRolePolicy + sts:AssumeRole (in PowerUserAccess) is a path to full admin.

variable "account_id" { type = string }
variable "region" { type = string }
variable "github_repo" {
  type        = string
  description = "owner/name of the only repository allowed to assume the CI roles."
  validation {
    condition     = can(regex("^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$", var.github_repo))
    error_message = "Use owner/name, no wildcards."
  }
}
variable "env" {
  type        = string
  description = "Stack environment the roles manage (names geovault-<env>-*)."
}
variable "force_destroy" {
  type    = bool
  default = false
}

locals {
  oidc_host   = "token.actions.githubusercontent.com"
  state_name  = "geovault-tfstate-${var.account_id}"
  stack_names = "geovault-${var.env}"
}

# --- state bucket ---------------------------------------------------------------------------

resource "aws_s3_bucket" "state" {
  # checkov:skip=CKV_AWS_144: single-region project; replication doubles cost
  # checkov:skip=CKV2_AWS_62: no consumer for event notifications
  # checkov:skip=CKV_AWS_18: one operator; CloudTrail data events cover state access if needed
  # checkov:skip=CKV_AWS_145: SSE-S3 keeps the bootstrap free of a chicken-and-egg KMS key
  bucket        = local.state_name
  force_destroy = var.force_destroy
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled" # every state version is recoverable
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    id     = "old-state-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration { noncurrent_days = 90 }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}

data "aws_iam_policy_document" "state" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "state" {
  bucket     = aws_s3_bucket.state.id
  policy     = data.aws_iam_policy_document.state.json
  depends_on = [aws_s3_bucket_public_access_block.state]
}

# --- account-wide S3 Block Public Access ---------------------------------------------------
# Guardrail from exercise C3: even if a bucket's own settings are switched off by mistake, no
# bucket in this account can be made public (S3 rejects public policies and ignores public ACLs).
resource "aws_s3_account_public_access_block" "this" {
  account_id              = var.account_id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- GitHub OIDC ----------------------------------------------------------------------------

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
  # AWS validates GitHub's certificate through its own trusted CAs; no thumbprint needed.
}

# Trust: the token must be for AWS STS AND come from this repo in the given context.
# StringEquals (not StringLike) so no wildcard can widen it.
data "aws_iam_policy_document" "trust" {
  for_each = {
    plan  = ["repo:${var.github_repo}:ref:refs/heads/main"]
    apply = ["repo:${var.github_repo}:environment:production"]
  }
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = each.value
    }
  }
}

resource "aws_iam_role" "ci" {
  for_each             = data.aws_iam_policy_document.trust
  name                 = "geovault-ci-${each.key}"
  assume_role_policy   = each.value.json
  max_session_duration = 3600
}

# --- plan role: read everything, write only the state lock ----------------------------------


data "aws_iam_policy_document" "plan_extra" {
  statement {
    sid       = "StateRead"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
  }
  statement {
    sid       = "StateLockOnly"
    actions   = ["s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.state.arn}/*.tflock"]
  }
  statement {
    # Refreshing SecureString parameters needs decrypt on the stack's key, nothing else.
    sid       = "DecryptStackParameters"
    actions   = ["kms:Decrypt"]
    resources = ["arn:aws:kms:${var.region}:${var.account_id}:key/*"]
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "kms:ResourceAliases"
      values   = ["alias/${local.stack_names}"]
    }
    condition {
      # Parameters only: this cannot decrypt the KMS-encrypted user photos in S3.
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ssm.${var.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "plan_extra" {
  name   = "state-and-decrypt"
  role   = aws_iam_role.ci["plan"].id
  policy = data.aws_iam_policy_document.plan_extra.json
}

# --- apply role: PowerUser (no IAM) + IAM limited to the stack's own names ------------------


# --- permissions boundary for every stack role -------------------------------------------
# The most any stack role (instance role, flow-logs role) can ever do, whatever policy is put
# on it. No IAM, no STS, no other services: a role created through the apply role cannot be
# turned into an administrator.
data "aws_iam_policy_document" "boundary" {
  # checkov:skip=CKV_AWS_356: a boundary is a ceiling, intersected with each role's own scoped policy
  # checkov:skip=CKV_AWS_111: a boundary is a ceiling, intersected with each role's own scoped policy
  # checkov:skip=CKV_AWS_108: a boundary is a ceiling, intersected with each role's own scoped policy
  statement {
    sid       = "AppData"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "s3:GetEncryptionConfiguration"]
    resources = ["arn:aws:s3:::${local.stack_names}-*", "arn:aws:s3:::${local.stack_names}-*/*"]
  }
  statement {
    sid       = "UseKeys"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = ["arn:aws:kms:${var.region}:${var.account_id}:key/*"]
  }
  statement {
    sid = "SessionManagerAndParameters" # what AmazonSSMManagedInstanceCore needs, plus reads
    actions = [
      "ssm:Describe*", "ssm:Get*", "ssm:List*", "ssm:PutInventory", "ssm:PutComplianceItems",
      "ssm:PutConfigurePackageResult", "ssm:UpdateAssociationStatus",
      "ssm:UpdateInstanceAssociationStatus", "ssm:UpdateInstanceInformation",
      "ssmmessages:*", "ec2messages:*",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "WriteLogs" # VPC flow logs
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams", "logs:DescribeLogGroups"]
    resources = ["arn:aws:logs:${var.region}:${var.account_id}:log-group:/geovault/*"]
  }
}

resource "aws_iam_policy" "boundary" {
  name        = "${local.stack_names}-boundary"
  description = "Ceiling for every GeoVault ${var.env} stack role"
  policy      = data.aws_iam_policy_document.boundary.json
}

# --- apply role: PowerUser (no IAM) + IAM limited to bounded stack roles ---------------------

data "aws_iam_policy_document" "apply_iam" {
  statement {
    # Every write that could raise a role's power requires the boundary to be on that role.
    sid = "BoundedRoleWrites"
    actions = [
      "iam:CreateRole", "iam:PutRolePolicy", "iam:AttachRolePolicy", "iam:PutRolePermissionsBoundary",
    ]
    resources = ["arn:aws:iam::${var.account_id}:role/${local.stack_names}-*"]
    condition {
      test     = "StringEquals"
      variable = "iam:PermissionsBoundary"
      values   = [aws_iam_policy.boundary.arn]
    }
  }
  statement {
    # Reads, removals and metadata cannot raise power (trust edits stay capped by the boundary).
    sid = "ManageStackIam"
    actions = [
      "iam:DeleteRole", "iam:GetRole", "iam:TagRole", "iam:UntagRole", "iam:UpdateRole",
      "iam:UpdateRoleDescription", "iam:UpdateAssumeRolePolicy", "iam:DeleteRolePolicy",
      "iam:GetRolePolicy", "iam:DetachRolePolicy", "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies", "iam:ListInstanceProfilesForRole",
      "iam:CreateInstanceProfile", "iam:DeleteInstanceProfile", "iam:GetInstanceProfile",
      "iam:AddRoleToInstanceProfile", "iam:RemoveRoleFromInstanceProfile",
      "iam:TagInstanceProfile", "iam:UntagInstanceProfile",
    ]
    resources = [
      "arn:aws:iam::${var.account_id}:role/${local.stack_names}-*",
      "arn:aws:iam::${var.account_id}:instance-profile/${local.stack_names}-*",
    ]
  }
  statement {
    sid       = "ReadBoundaryAndManagedPolicies"
    actions   = ["iam:GetPolicy", "iam:GetPolicyVersion"]
    resources = [aws_iam_policy.boundary.arn, "arn:aws:iam::aws:policy/*"]
  }
  statement {
    sid       = "PassStackRolesToServices"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${var.account_id}:role/${local.stack_names}-*"]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ec2.amazonaws.com", "vpc-flow-logs.amazonaws.com"]
    }
  }
  statement {
    sid       = "StateReadWrite"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
  }
  statement {
    # PowerUserAccess includes s3:* - make sure no apply can weaken the state bucket or erase
    # state history, and no apply can silence the audit trail.
    sid    = "ProtectStateAndAudit"
    effect = "Deny"
    actions = [
      "s3:DeleteBucket", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketVersioning",
      "s3:PutLifecycleConfiguration", "s3:PutEncryptionConfiguration", "s3:PutBucketPublicAccessBlock",
      "s3:PutBucketOwnershipControls", "s3:PutBucketAcl", "s3:DeleteObjectVersion",
    ]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
  }
  statement {
    sid       = "KeepAuditOn"
    effect    = "Deny"
    actions   = ["cloudtrail:StopLogging"]
    resources = ["*"]
  }
  statement {
    # The apply role must not edit its own guard rails.
    sid       = "NoSelfEdit"
    effect    = "Deny"
    actions   = ["iam:*"]
    resources = [aws_iam_policy.boundary.arn, "arn:aws:iam::${var.account_id}:role/geovault-ci-*", aws_iam_openid_connect_provider.github.arn]
  }
}

resource "aws_iam_role_policy" "apply_iam" {
  name   = "stack-iam-and-state"
  role   = aws_iam_role.ci["apply"].id
  policy = data.aws_iam_policy_document.apply_iam.json
}

# --- exclusive ownership --------------------------------------------------------------------
# Terraform owns the COMPLETE set of policies on each CI role: anything attached or added
# outside Terraform is removed on the next apply. (A plain policy_attachment manages only
# itself; a mutation test showed a hand-attached AdministratorAccess surviving apply.)

locals {
  ci_managed = {
    plan  = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
    apply = ["arn:aws:iam::aws:policy/PowerUserAccess"]
  }
}

resource "aws_iam_role_policy_attachments_exclusive" "ci" {
  for_each    = local.ci_managed
  role_name   = aws_iam_role.ci[each.key].name
  policy_arns = each.value
}

resource "aws_iam_role_policies_exclusive" "ci" {
  for_each = {
    plan  = [aws_iam_role_policy.plan_extra.name]
    apply = [aws_iam_role_policy.apply_iam.name]
  }
  role_name    = aws_iam_role.ci[each.key].name
  policy_names = each.value
}

output "state_bucket" { value = aws_s3_bucket.state.id }
output "plan_role_arn" { value = aws_iam_role.ci["plan"].arn }
output "apply_role_arn" { value = aws_iam_role.ci["apply"].arn }
output "boundary_arn" { value = aws_iam_policy.boundary.arn }
