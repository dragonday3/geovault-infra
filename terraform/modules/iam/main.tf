# The instance role: exactly what the GeoVault host needs, nothing account-wide.
#   - photos bucket: object read/write/delete under photos/ and list of that prefix
#   - KMS: use the data key, only through S3 or SSM in this region
#   - SSM parameters: read /geovault/<env>/* only
#   - Session Manager (no SSH): the AWS-managed core policy

variable "name" { type = string }
variable "region" { type = string }
variable "account_id" { type = string }
variable "photos_bucket_arn" { type = string }
variable "kms_key_arn" { type = string }
variable "param_path" { type = string }

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance" {
  name               = "${var.name}-instance"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "app" {
  statement {
    sid       = "PhotoObjects"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${var.photos_bucket_arn}/photos/*"]
  }
  statement {
    sid       = "PhotoList"
    actions   = ["s3:ListBucket"]
    resources = [var.photos_bucket_arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["photos/*"]
    }
  }
  statement {
    sid       = "UseDataKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com", "ssm.${var.region}.amazonaws.com"]
    }
  }
  statement {
    sid       = "ReadOwnParameters"
    actions   = ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"]
    resources = ["arn:aws:ssm:${var.region}:${var.account_id}:parameter${var.param_path}/*"]
  }
}

resource "aws_iam_role_policy" "app" {
  name   = "geovault-app"
  role   = aws_iam_role.instance.id
  policy = data.aws_iam_policy_document.app.json
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.name}-instance"
  role = aws_iam_role.instance.name
}

output "instance_profile" { value = aws_iam_instance_profile.instance.name }
output "role_name" { value = aws_iam_role.instance.name }
