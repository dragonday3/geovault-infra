# Real AWS, ap-south-1 (Mumbai). NOT APPLIED YET.
# Applying this creates billable resources. It needs, first: a cost estimate reviewed and
# approved, the state bucket created, and an untracked terraform.tfvars (see the example).
#
#   terraform -chdir=envs/aws init -backend-config=backend.hcl
#   terraform -chdir=envs/aws plan -out=plan.tfplan

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 6.0" }
    random = { source = "hashicorp/random", version = "~> 3.7" }
  }
  # Partial config: bucket/key come from an untracked backend.hcl.
  # use_lockfile = native S3 state locking (no DynamoDB table needed).
  backend "s3" {
    region       = "ap-south-1"
    encrypt      = true
    use_lockfile = true
  }
}

variable "aws_account_id" {
  type        = string
  description = "The only account this configuration may touch."
  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id)) && var.aws_account_id != "000000000000"
    error_message = "Set the real 12-digit account id."
  }
}
variable "alert_email" {
  type      = string
  sensitive = true
}
variable "budget_limit_usd" {
  type    = number
  default = 20
}

locals {
  region = "ap-south-1"
}

provider "aws" {
  region              = local.region
  allowed_account_ids = [var.aws_account_id]
  default_tags {
    tags = { Project = "geovault", Environment = "prod", ManagedBy = "terraform" }
  }
}

# Latest Amazon Linux 2023 for ARM (Graviton), resolved at plan time.
data "aws_ssm_parameter" "al2023_arm64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

module "stack" {
  source           = "../../stack"
  env              = "prod"
  account_id       = var.aws_account_id
  region           = local.region
  az               = "${local.region}a"
  ami_id           = nonsensitive(data.aws_ssm_parameter.al2023_arm64.value)
  budget_limit_usd = var.budget_limit_usd
  alert_email      = var.alert_email
}

output "summary" { value = module.stack.summary }
