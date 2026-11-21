# One VPC, one public subnet, no NAT gateway (~US$45/month saved). The instance sits in the
# public subnet behind a security group that admits only HTTP/HTTPS. There is no SSH:
# administration goes through SSM Session Manager.

variable "name" { type = string }
variable "cidr" { type = string }
variable "az" { type = string }
variable "kms_key_arn" { type = string }
variable "flow_log_retention_days" {
  type        = number
  description = "At least 180 days (CERT-In directions, India)."
  validation {
    condition     = var.flow_log_retention_days >= 180
    error_message = "CERT-In requires at least 180 days."
  }
}

resource "aws_vpc" "this" {
  cidr_block           = var.cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = var.name }
}

# Strip every rule from the default security group so nothing lands in it by accident.
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = var.name }
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(var.cidr, 8, 1)
  availability_zone = var.az
  # Public IPs are attached per instance instead of by default.
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name}-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = { Name = "${var.name}-public" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Rules are inline on purpose: Terraform then treats them as the EXCLUSIVE rule set and
# deletes any rule added outside Terraform on the next apply. (Separate
# aws_vpc_security_group_*_rule resources only manage themselves: a mutation test showed a
# hand-added SSH rule surviving `terraform apply` that way.)
locals {
  ingress = { https = 443, http = 80 }
  egress = {
    https = { proto = "tcp", port = 443 } # AWS APIs, image pulls, ACME
    http  = { proto = "tcp", port = 80 }  # OS package mirrors
    ntp   = { proto = "udp", port = 123 } # time sync (CERT-In)
  }
}

resource "aws_security_group" "web" {
  name        = "${var.name}-web"
  description = "GeoVault web: HTTPS and HTTP (redirect / ACME) in; HTTPS, HTTP, NTP out"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.name}-web" }
  # checkov:skip=CKV2_AWS_5: attached to the instance through the compute module input

  dynamic "ingress" {
    for_each = local.ingress
    content {
      description = "${upper(ingress.key)} from the internet"
      protocol    = "tcp"
      from_port   = ingress.value
      to_port     = ingress.value
      cidr_blocks = ["0.0.0.0/0"] # public web app
    }
  }

  dynamic "egress" {
    for_each = local.egress
    content {
      description = "${upper(egress.key)} out"
      protocol    = egress.value.proto
      from_port   = egress.value.port
      to_port     = egress.value.port
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}

# --- VPC flow logs -> CloudWatch Logs (encrypted) -----------------------------------------

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/geovault/${var.name}/vpc-flow"
  retention_in_days = var.flow_log_retention_days
  kms_key_id        = var.kms_key_arn
}

data "aws_iam_policy_document" "flow_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow" {
  name               = "${var.name}-vpc-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_assume.json
}

data "aws_iam_policy_document" "flow" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.flow.arn}:*"]
  }
}

resource "aws_iam_role_policy" "flow" {
  name   = "write-flow-logs"
  role   = aws_iam_role.flow.id
  policy = data.aws_iam_policy_document.flow.json
}

resource "aws_flow_log" "this" {
  vpc_id          = aws_vpc.this.id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow.arn
  iam_role_arn    = aws_iam_role.flow.arn
}

output "vpc_id" { value = aws_vpc.this.id }
output "subnet_id" { value = aws_subnet.public.id }
output "web_sg_id" { value = aws_security_group.web.id }
