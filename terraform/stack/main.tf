# The whole GeoVault deployment, composed from the modules. Both environments call this
# with different inputs: envs/local (MiniStack emulator) and envs/aws (ap-south-1).

terraform {
  required_version = ">= 1.10" # S3 backend native locking (use_lockfile)
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 6.0" }
    random = { source = "hashicorp/random", version = "~> 3.7" }
  }
}

variable "env" {
  type = string
  validation {
    condition     = contains(["local", "prod"], var.env)
    error_message = "env must be local or prod."
  }
}
variable "account_id" { type = string }
variable "region" { type = string }
variable "az" { type = string }
variable "ami_id" { type = string }
variable "instance_type" {
  type    = string
  default = "t4g.small"
}
variable "budget_limit_usd" { type = number }
variable "alert_email" {
  type      = string
  sensitive = true
}
variable "force_destroy_buckets" {
  type    = bool
  default = false
}

locals {
  name = "geovault-${var.env}"
  # Created by the bootstrap (modules/bootstrap); every stack role must carry it.
  permissions_boundary = "arn:aws:iam::${var.account_id}:policy/geovault-${var.env}-boundary"
  param_path           = "/geovault/${var.env}"
  # CERT-In directions: keep logs for at least 180 days, inside India (ap-south-1).
  log_days = 400
}

module "kms" {
  source     = "../modules/kms"
  name       = local.name
  account_id = var.account_id
  region     = var.region
}

module "network" {
  source                  = "../modules/network"
  name                    = local.name
  cidr                    = "10.20.0.0/16"
  az                      = var.az
  kms_key_arn             = module.kms.key_arn
  flow_log_retention_days = local.log_days
  permissions_boundary    = local.permissions_boundary
}

module "storage" {
  source             = "../modules/storage"
  name               = local.name
  account_id         = var.account_id
  kms_key_arn        = module.kms.key_arn
  log_retention_days = local.log_days
  force_destroy      = var.force_destroy_buckets
}

module "iam" {
  source               = "../modules/iam"
  name                 = local.name
  region               = var.region
  account_id           = var.account_id
  photos_bucket_arn    = module.storage.photos_bucket_arn
  kms_key_arn          = module.kms.key_arn
  param_path           = local.param_path
  permissions_boundary = local.permissions_boundary
}

module "secrets" {
  source      = "../modules/secrets"
  param_path  = local.param_path
  kms_key_arn = module.kms.key_arn
}

module "compute" {
  source             = "../modules/compute"
  name               = local.name
  ami_id             = var.ami_id
  instance_type      = var.instance_type
  subnet_id          = module.network.subnet_id
  security_group_ids = [module.network.web_sg_id]
  instance_profile   = module.iam.instance_profile
  kms_key_arn        = module.kms.key_arn
  root_volume_gb     = 20
}

module "audit" {
  source           = "../modules/audit"
  name             = local.name
  logs_bucket      = module.storage.logs_bucket
  kms_key_arn      = module.kms.key_arn
  budget_limit_usd = var.budget_limit_usd
  alert_email      = var.alert_email
  depends_on       = [module.storage] # the trail needs the bucket policy first
}

output "summary" {
  value = {
    vpc_id        = module.network.vpc_id
    instance_id   = module.compute.instance_id
    public_ip     = module.compute.public_ip
    photos_bucket = module.storage.photos_bucket
    logs_bucket   = module.storage.logs_bucket
    kms_key       = module.kms.key_arn
    parameters    = module.secrets.parameter_names
    trail         = module.audit.trail_name
    budget        = module.audit.budget_name
  }
}
