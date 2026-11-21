# Two private buckets:
#   photos - user photos (already EXIF-stripped by the app): SSE-KMS, versioned, TLS only.
#   logs   - S3 access logs and CloudTrail. Server access logging only supports SSE-S3
#            targets; CloudTrail objects are still KMS-encrypted by the trail itself.

variable "name" { type = string }
variable "account_id" { type = string }
variable "kms_key_arn" { type = string }
variable "log_retention_days" { type = number }
variable "force_destroy" {
  type        = bool
  default     = false
  description = "Only true for the throwaway local emulator."
}

locals {
  buckets = {
    photos = "${var.name}-photos-${var.account_id}"
    logs   = "${var.name}-logs-${var.account_id}"
  }
}

resource "aws_s3_bucket" "this" {
  # Accepted for cost / by design:
  # checkov:skip=CKV_AWS_144: single-region project; cross-region replication doubles storage cost
  # checkov:skip=CKV2_AWS_62: no consumer for S3 event notifications
  # checkov:skip=CKV_AWS_145: the logs bucket must use SSE-S3 (S3 access-log targets do not support KMS); photos use SSE-KMS
  # checkov:skip=CKV_AWS_18: the logs bucket is the access-log target; logging it to itself would recurse
  # Checkov cannot follow for_each into the companion resources below; verify/verify.py checks
  # these on the deployed buckets instead:
  # checkov:skip=CKV2_AWS_61: lifecycle rules exist for both buckets
  # checkov:skip=CKV_AWS_21: versioning is enabled for both buckets
  # checkov:skip=CKV2_AWS_6: Block Public Access is on for both buckets
  for_each      = local.buckets
  bucket        = each.value
  force_destroy = var.force_destroy
}

resource "aws_s3_bucket_public_access_block" "this" {
  for_each                = aws_s3_bucket.this
  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  for_each = aws_s3_bucket.this
  bucket   = each.value.id
  rule {
    object_ownership = "BucketOwnerEnforced" # ACLs disabled
  }
}

resource "aws_s3_bucket_versioning" "this" {
  for_each = aws_s3_bucket.this
  bucket   = each.value.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "photos" {
  bucket = aws_s3_bucket.this["photos"].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.this["logs"].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # required for S3 server access log targets
    }
  }
}

resource "aws_s3_bucket_logging" "photos" {
  bucket        = aws_s3_bucket.this["photos"].id
  target_bucket = aws_s3_bucket.this["logs"].id
  target_prefix = "s3-access/photos/"
}

resource "aws_s3_bucket_lifecycle_configuration" "photos" {
  bucket = aws_s3_bucket.this["photos"].id
  rule {
    id     = "expire-old-versions"
    status = "Enabled"
    filter {}
    # A deleted or replaced photo must really go: privacy erasure (APP 11.2 / DPDP s.8(7)).
    noncurrent_version_expiration { noncurrent_days = 7 }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.this["logs"].id
  rule {
    id     = "retain-then-expire"
    status = "Enabled"
    filter {}
    expiration { days = var.log_retention_days }
    noncurrent_version_expiration { noncurrent_days = 30 }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}

# --- Bucket policies: TLS only everywhere; the logs bucket also admits the log writers. ----

data "aws_iam_policy_document" "tls_only" {
  for_each = aws_s3_bucket.this
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [each.value.arn, "${each.value.arn}/*"]
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

  dynamic "statement" {
    for_each = each.key == "logs" ? [1] : []
    content {
      sid       = "S3AccessLogs"
      actions   = ["s3:PutObject"]
      resources = ["${each.value.arn}/s3-access/*"]
      principals {
        type        = "Service"
        identifiers = ["logging.s3.amazonaws.com"]
      }
      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [var.account_id]
      }
    }
  }

  dynamic "statement" {
    for_each = each.key == "logs" ? [1] : []
    content {
      sid       = "CloudTrailAclCheck"
      actions   = ["s3:GetBucketAcl"]
      resources = [each.value.arn]
      principals {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }
      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [var.account_id]
      }
    }
  }

  dynamic "statement" {
    for_each = each.key == "logs" ? [1] : []
    content {
      sid       = "CloudTrailWrite"
      actions   = ["s3:PutObject"]
      resources = ["${each.value.arn}/cloudtrail/AWSLogs/${var.account_id}/*"]
      principals {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }
      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [var.account_id]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  for_each   = aws_s3_bucket.this
  bucket     = each.value.id
  policy     = data.aws_iam_policy_document.tls_only[each.key].json
  depends_on = [aws_s3_bucket_public_access_block.this]
}

output "photos_bucket" { value = aws_s3_bucket.this["photos"].id }
output "photos_bucket_arn" { value = aws_s3_bucket.this["photos"].arn }
output "logs_bucket" { value = aws_s3_bucket.this["logs"].id }
