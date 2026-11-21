# One-time bootstrap of the real account: state bucket + GitHub OIDC + CI roles.
# NOT APPLIED YET. Run by hand, once, with an administrator session (SSO), in milestone C4:
#
#   terraform -chdir=envs/aws-bootstrap init
#   terraform -chdir=envs/aws-bootstrap apply -var aws_account_id=<id>
#
# Its own state stays local (it creates the bucket every other state lives in); keep
# terraform.tfstate from this directory somewhere safe, or migrate it into the bucket after.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
  backend "local" {}
}

variable "aws_account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id)) && var.aws_account_id != "000000000000"
    error_message = "Set the real 12-digit account id."
  }
}

provider "aws" {
  region              = "ap-south-1"
  allowed_account_ids = [var.aws_account_id]
  default_tags {
    tags = { Project = "geovault", Environment = "bootstrap", ManagedBy = "terraform" }
  }
}

module "bootstrap" {
  source      = "../../modules/bootstrap"
  account_id  = var.aws_account_id
  region      = "ap-south-1"
  github_repo = "dragonday3/geovault-infra"
  env         = "prod"
}

output "state_bucket" { value = module.bootstrap.state_bucket }
output "plan_role_arn" { value = module.bootstrap.plan_role_arn }
output "apply_role_arn" { value = module.bootstrap.apply_role_arn }
