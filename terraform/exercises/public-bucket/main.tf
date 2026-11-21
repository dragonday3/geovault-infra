# EXERCISE C3 - a publicly readable S3 bucket. EMULATOR ONLY.
#
# Scenario: a developer needs to hand a CSV export to a partner and "just makes the bucket
# public". This root reproduces that mistake, then fixes it, then adds the account guardrail
# that would have prevented it.
#
#   phase = "vulnerable"  public bucket policy, Block Public Access off, no encryption
#   phase = "fixed"       private, encrypted, versioned, TLS only; partner gets a presigned URL
#   guardrail = true      account-level S3 Block Public Access (prevents recurrence)
#
# Safety: runs only against the local emulator, in a separate sandbox account
# (111111111111), with synthetic data. The provider config below cannot reach real AWS, and
# the compose network has no internet route. NEVER point this at a real account.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
  backend "local" {}
}

variable "endpoint" {
  type    = string
  default = "http://localhost:4566"
  validation {
    condition     = can(regex("^http://(localhost|127\\.0\\.0\\.1|ministack):[0-9]+$", var.endpoint))
    error_message = "This exercise may only run against a local emulator."
  }
}

variable "phase" {
  type = string
  validation {
    condition     = contains(["vulnerable", "fixed"], var.phase)
    error_message = "phase must be vulnerable or fixed."
  }
}

variable "guardrail" {
  type    = bool
  default = false
}

locals {
  account_id = "111111111111" # sandbox account, separate from the stack's 000000000000
  bucket     = "geovault-exercise-partner-export"
  vulnerable = var.phase == "vulnerable"
  # Built from the known name (not local.bucket_arn) so the policy is fully known at
  # plan time - otherwise a plan scanner sees `policy = null` and misses Principal "*".
  bucket_arn = "arn:aws:s3:::${local.bucket}"
}

provider "aws" {
  region                      = "ap-south-1"
  access_key                  = local.account_id # MiniStack: a 12-digit key selects the account
  secret_key                  = "test"
  allowed_account_ids         = [local.account_id]
  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = false
  max_retries                 = 2
  endpoints {
    s3        = var.endpoint
    s3control = var.endpoint
    sts       = var.endpoint
    kms       = var.endpoint
  }
}

resource "aws_s3_bucket" "export" {
  bucket        = local.bucket
  force_destroy = true
}

# Synthetic stand-in for an export: invented users at example.com, no real data.
resource "aws_s3_object" "export" {
  bucket       = aws_s3_bucket.export.id
  key          = "exports/partner-2026-11.csv"
  content_type = "text/csv"
  content      = <<-CSV
    user_id,email,display_name,home_lat,home_lon
    1001,asha.k@example.com,Asha,23.0225,72.5714
    1002,rohan.m@example.com,Rohan,12.9716,77.5946
    1003,lena.w@example.com,Lena,-37.8136,144.9631
  CSV
}

# --- the mistake ---------------------------------------------------------------------------

resource "aws_s3_bucket_public_access_block" "export" {
  bucket                  = aws_s3_bucket.export.id
  block_public_acls       = !local.vulnerable
  block_public_policy     = !local.vulnerable
  ignore_public_acls      = !local.vulnerable
  restrict_public_buckets = !local.vulnerable
}

resource "aws_s3_bucket_policy" "export" {
  bucket = aws_s3_bucket.export.id
  policy = local.vulnerable ? jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead" # the mistake: anyone on the internet can read every object
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${local.bucket_arn}/*"
    }]
    }) : jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [local.bucket_arn, "${local.bucket_arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.export]
}

# --- the fix -------------------------------------------------------------------------------

resource "aws_kms_key" "export" {
  count               = local.vulnerable ? 0 : 1
  description         = "exercise export bucket"
  enable_key_rotation = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "export" {
  count  = local.vulnerable ? 0 : 1
  bucket = aws_s3_bucket.export.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.export[0].arn
    }
  }
}

resource "aws_s3_bucket_versioning" "export" {
  count  = local.vulnerable ? 0 : 1
  bucket = aws_s3_bucket.export.id
  versioning_configuration {
    status = "Enabled"
  }
}

# --- the guardrail -------------------------------------------------------------------------

resource "aws_s3_account_public_access_block" "this" {
  count                   = var.guardrail ? 1 : 0
  account_id              = local.account_id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

output "object_url" {
  value = "${var.endpoint}/${local.bucket}/${aws_s3_object.export.key}"
}
