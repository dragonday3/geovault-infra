# A single small ARM instance runs the GeoVault containers (api + PostGIS) behind Caddy.
# Hardening: IMDSv2 only, encrypted root volume, no key pair (Session Manager instead of
# SSH), termination protection off so `terraform destroy` stays one command.

variable "name" { type = string }
variable "ami_id" { type = string }
variable "instance_type" { type = string }
variable "subnet_id" { type = string }
variable "security_group_ids" { type = list(string) }
variable "instance_profile" { type = string }
variable "kms_key_arn" { type = string }
variable "root_volume_gb" { type = number }

resource "aws_instance" "app" {
  # checkov:skip=CKV_AWS_88: public IP by design - no NAT gateway or load balancer (cost); SG admits 80/443 only
  ami                         = var.ami_id
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = var.security_group_ids
  iam_instance_profile        = var.instance_profile
  associate_public_ip_address = true
  ebs_optimized               = true
  # checkov:skip=CKV_AWS_126: detailed monitoring costs extra; basic 5-minute metrics suffice
  monitoring = false

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only: blocks SSRF-style credential theft
    http_put_response_hop_limit = 1          # containers cannot reach IMDS through the host
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_gb
    encrypted             = true
    kms_key_id            = var.kms_key_arn
    delete_on_termination = true
  }

  tags = { Name = var.name }
}

output "instance_id" { value = aws_instance.app.id }
output "public_ip" { value = aws_instance.app.public_ip }
