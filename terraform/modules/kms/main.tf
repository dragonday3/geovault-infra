# One customer-managed key for GeoVault data at rest: photos bucket, EBS root volume,
# SSM SecureString parameters, CloudTrail logs and VPC flow logs.
# ponytail: one key for everything; split per data class if access patterns ever diverge.

variable "name" { type = string }
variable "account_id" { type = string }
variable "region" { type = string }

data "aws_iam_policy_document" "key" {
  # In a KMS key policy, Resource "*" means "this key" - it cannot reach other resources.
  # checkov:skip=CKV_AWS_356: key-policy resource "*" is the key itself
  # checkov:skip=CKV_AWS_111: key-policy resource "*" is the key itself
  # checkov:skip=CKV_AWS_109: key-policy resource "*" is the key itself; admin is the account root only
  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"] # in a key policy "*" means this key
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
  }

  statement {
    sid       = "CloudTrailEncrypt"
    actions   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${var.account_id}:trail/*"]
    }
  }

  statement {
    sid       = "CloudWatchLogsEncrypt"
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.region}:${var.account_id}:log-group:*"]
    }
  }
}

resource "aws_kms_key" "this" {
  description             = "${var.name} data at rest"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.key.json
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.this.key_id
}

output "key_arn" { value = aws_kms_key.this.arn }
output "key_id" { value = aws_kms_key.this.key_id }
