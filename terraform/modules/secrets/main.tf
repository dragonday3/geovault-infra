# App secrets as SSM SecureString parameters (standard tier: free; Secrets Manager would be
# US$0.40 per secret per month). Values are generated here, never typed or committed.
# They do live in Terraform state, which is why the state bucket is encrypted and private.

terraform {
  required_providers {
    random = { source = "hashicorp/random" }
  }
}

variable "param_path" { type = string }
variable "kms_key_arn" { type = string }

resource "random_password" "this" {
  for_each = toset(["postgres-password", "db-password", "jwt-secret", "geoserver-admin-password"])
  length   = 48
  special  = false # used inside connection URLs
}

resource "aws_ssm_parameter" "this" {
  for_each = random_password.this
  name     = "${var.param_path}/${each.key}"
  type     = "SecureString"
  key_id   = var.kms_key_arn
  value    = each.value.result
}

output "parameter_names" { value = [for p in aws_ssm_parameter.this : p.name] }
