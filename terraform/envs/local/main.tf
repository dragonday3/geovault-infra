# Local environment: the full stack applied to the MiniStack emulator. Free, offline from
# AWS, and safe to destroy. Three independent guards keep it off real AWS:
#   1. every service endpoint is the emulator URL (validated below),
#   2. the credentials are the dummy pair "test"/"test",
#   3. allowed_account_ids only admits 000000000000, which no real AWS account has.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 6.0" }
    random = { source = "hashicorp/random", version = "~> 3.7" }
  }
  backend "local" {}
}

variable "endpoint" {
  type        = string
  default     = "http://localhost:4566"
  description = "MiniStack gateway. compose.yml sets http://ministack:4566."
  validation {
    condition     = can(regex("^http://(localhost|127\\.0\\.0\\.1|ministack):[0-9]+$", var.endpoint))
    error_message = "The local environment may only talk to a local emulator."
  }
}

locals {
  account_id = "000000000000"
  region     = "ap-south-1"
}

provider "aws" {
  region                      = local.region
  access_key                  = "test"
  secret_key                  = "test"
  allowed_account_ids         = [local.account_id]
  s3_use_path_style           = true
  max_retries                 = 2 # fail fast: a missing endpoint must not hang
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = false # STS (emulated) must say 000000000000

  endpoints {
    budgets    = var.endpoint
    cloudtrail = var.endpoint
    ec2        = var.endpoint
    iam        = var.endpoint
    kms        = var.endpoint
    logs       = var.endpoint
    s3         = var.endpoint
    s3control  = var.endpoint
    ssm        = var.endpoint
    sts        = var.endpoint
  }

  default_tags {
    tags = { Project = "geovault", Environment = "local", ManagedBy = "terraform" }
  }
}

module "stack" {
  source                = "../../stack"
  env                   = "local"
  account_id            = local.account_id
  region                = local.region
  az                    = "${local.region}a"
  ami_id                = "ami-0123456789abcdef0" # the emulator accepts any AMI id
  budget_limit_usd      = 20
  alert_email           = "alerts@example.com"
  force_destroy_buckets = true
  depends_on            = [module.bootstrap] # creates the permissions boundary
}

module "bootstrap" {
  source        = "../../modules/bootstrap"
  account_id    = local.account_id
  region        = local.region
  github_repo   = "dragonday3/geovault-infra"
  env           = "local"
  force_destroy = true
}

output "summary" { value = module.stack.summary }
output "bootstrap" {
  value = {
    state_bucket   = module.bootstrap.state_bucket
    plan_role_arn  = module.bootstrap.plan_role_arn
    apply_role_arn = module.bootstrap.apply_role_arn
  }
}
