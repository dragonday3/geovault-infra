# Audit and cost guard rails.
#   - CloudTrail: all regions, management events, log-file validation, KMS-encrypted.
#   - Budget: monthly cost alerts at 50 % and 100 % of the limit.

variable "name" { type = string }
variable "logs_bucket" { type = string }
variable "kms_key_arn" { type = string }
variable "budget_limit_usd" { type = number }
variable "alert_email" {
  type      = string
  sensitive = true # personal address: kept in an untracked tfvars file
}

resource "aws_cloudtrail" "this" {
  name                          = var.name
  s3_bucket_name                = var.logs_bucket
  s3_key_prefix                 = "cloudtrail"
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = var.kms_key_arn
  # checkov:skip=CKV_AWS_252: SNS delivery notifications are not needed for a single-operator project
  # checkov:skip=CKV2_AWS_10: CloudWatch Logs delivery costs extra; S3 + Athena is enough here
}

resource "aws_budgets_budget" "monthly" {
  name         = "${var.name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = [50, 100]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = [var.alert_email]
    }
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.alert_email]
  }
}

output "trail_name" { value = aws_cloudtrail.this.name }
output "budget_name" { value = aws_budgets_budget.monthly.name }
