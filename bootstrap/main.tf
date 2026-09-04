# One-time bootstrap — run locally with admin credentials BEFORE the pipeline can work.
# Creates: remote state backend, GitHub OIDC provider, and the IAM roles the
# workflows assume. Nothing else should ever be applied from a laptop.
#
#   cd bootstrap
#   terraform init && terraform apply -var="github_repo=<owner>/<repo>"

terraform {
  required_version = ">= 1.9.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "Region for the state backend and IAM resources"
  type        = string
  default     = "us-east-1"
}

variable "github_repo" {
  description = "GitHub repository allowed to assume the CI roles, as owner/repo"
  type        = string
}

variable "project" {
  description = "Project slug used to name bootstrap resources"
  type        = string
  default     = "secres"
}

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# Remote state
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "tf_state" {
  bucket = "${var.project}-tf-state-${data.aws_caller_identity.current.account_id}"

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "tf_state" {
  bucket = aws_s3_bucket.tf_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tf_state" {
  bucket = aws_s3_bucket.tf_state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "tf_state" {
  bucket                  = aws_s3_bucket.tf_state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_dynamodb_table" "tf_lock" {
  name         = "${var.project}-tf-lock"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }
}

# ---------------------------------------------------------------------------
# GitHub OIDC — no long-lived AWS keys in GitHub secrets
# ---------------------------------------------------------------------------

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

locals {
  oidc_sub_pr   = "repo:${var.github_repo}:pull_request"
  oidc_sub_main = "repo:${var.github_repo}:ref:refs/heads/main"
}

data "aws_iam_policy_document" "assume_plan" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [local.oidc_sub_pr, local.oidc_sub_main]
    }
  }
}

data "aws_iam_policy_document" "assume_apply" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    # Apply role only from main — a PR can never assume it.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [local.oidc_sub_main]
    }
  }
}

# Read-only role for `terraform plan` on PRs (plus state read/write lock access).
resource "aws_iam_role" "tf_plan" {
  name               = "${var.project}-github-tf-plan"
  assume_role_policy = data.aws_iam_policy_document.assume_plan.json
}

resource "aws_iam_role_policy_attachment" "plan_readonly" {
  role       = aws_iam_role.tf_plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Full deploy role for `terraform apply` on main. Scope this down to the
# services your root module actually manages once it stabilizes.
resource "aws_iam_role" "tf_apply" {
  name               = "${var.project}-github-tf-apply"
  assume_role_policy = data.aws_iam_policy_document.assume_apply.json
}

resource "aws_iam_role_policy_attachment" "apply_power" {
  role       = aws_iam_role.tf_apply.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

# Prowler needs SecurityAudit + ViewOnly per Prowler docs.
resource "aws_iam_role" "prowler" {
  name               = "${var.project}-github-prowler"
  assume_role_policy = data.aws_iam_policy_document.assume_plan.json
}

resource "aws_iam_role_policy_attachment" "prowler_secaudit" {
  role       = aws_iam_role.prowler.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "prowler_viewonly" {
  role       = aws_iam_role.prowler.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

# State access shared by plan/apply roles.
data "aws_iam_policy_document" "state_access" {
  statement {
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.tf_state.arn]
  }
  statement {
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.tf_state.arn}/*"]
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
    resources = [aws_dynamodb_table.tf_lock.arn]
  }
}

resource "aws_iam_policy" "state_access" {
  name   = "${var.project}-tf-state-access"
  policy = data.aws_iam_policy_document.state_access.json
}

resource "aws_iam_role_policy_attachment" "plan_state" {
  role       = aws_iam_role.tf_plan.name
  policy_arn = aws_iam_policy.state_access.arn
}

resource "aws_iam_role_policy_attachment" "apply_state" {
  role       = aws_iam_role.tf_apply.name
  policy_arn = aws_iam_policy.state_access.arn
}

# ---------------------------------------------------------------------------
# Outputs — paste these into GitHub repo settings
# ---------------------------------------------------------------------------

output "state_bucket" {
  value       = aws_s3_bucket.tf_state.bucket
  description = "Set as backend bucket in terraform/backend.tf"
}

output "lock_table" {
  value       = aws_dynamodb_table.tf_lock.name
  description = "Set as backend dynamodb_table in terraform/backend.tf"
}

output "plan_role_arn" {
  value       = aws_iam_role.tf_plan.arn
  description = "GitHub secret AWS_PLAN_ROLE_ARN"
}

output "apply_role_arn" {
  value       = aws_iam_role.tf_apply.arn
  description = "GitHub secret AWS_APPLY_ROLE_ARN"
}

output "prowler_role_arn" {
  value       = aws_iam_role.prowler.arn
  description = "GitHub secret AWS_PROWLER_ROLE_ARN"
}
