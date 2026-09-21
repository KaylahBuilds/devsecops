# ECR repository hardened for the pipeline, plus the IAM role GitHub Actions
# assumes through OIDC to push. Apply with the bootstrap OIDC provider ARN:
#   terraform apply -var="github_oidc_provider_arn=arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"

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
  description = "Region for the registry and the hosts"
  type        = string
  default     = "us-east-1"
}

variable "repository_name" {
  description = "ECR repository name, e.g. acme/api"
  type        = string
  default     = "acme/api"
}

variable "github_repo" {
  description = "owner/repo allowed to push, e.g. acme/api"
  type        = string
  default     = "acme/api"
}

variable "github_oidc_provider_arn" {
  description = "ARN of the GitHub OIDC provider created by ../../../bootstrap"
  type        = string
}

# --- registry ---------------------------------------------------------------

resource "aws_kms_key" "ecr" {
  description         = "ECR image encryption for ${var.repository_name}"
  enable_key_rotation = true
}

resource "aws_ecr_repository" "app" {
  name                 = var.repository_name
  image_tag_mutability = "IMMUTABLE" # a tag, once pushed, cannot be re-pointed
  force_delete         = false

  image_scanning_configuration {
    scan_on_push = true # basic scanning; enable enhanced (Inspector) registry-wide below
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }
}

# Enhanced scanning (Amazon Inspector) for every repository in the registry:
# continuous rescans as new CVEs are published, not only on push.
resource "aws_ecr_registry_scanning_configuration" "enhanced" {
  scan_type = "ENHANCED"

  rule {
    scan_frequency = "CONTINUOUS_SCAN"
    repository_filter {
      filter      = "*"
      filter_type = "WILDCARD"
    }
  }
}

# Keep the last 30 tagged images, drop untagged layers after 7 days.
# Signatures and attestations are untagged referrers: the 7-day rule would
# delete them, so the first rule keeps anything whose tag starts with "sha256-"
# (cosign's tag scheme) alongside the image.
resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "keep cosign signatures and attestations"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["sha256-"]
          countType     = "imageCountMoreThan"
          countNumber   = 1000
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "keep the last 30 release images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["sha-"]
          countType     = "imageCountMoreThan"
          countNumber   = 30
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 3
        description  = "drop untagged layers after 7 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 7
        }
        action = { type = "expire" }
      },
    ]
  })
}

# Only the account's own principals may pull; no cross-account, no public.
data "aws_caller_identity" "current" {}

resource "aws_ecr_repository_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AccountPullOnly"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      }
      Action = [
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchCheckLayerAvailability",
      ]
    }]
  })
}

# --- GitHub OIDC push role: only main of the named repo may assume it --------

data "aws_iam_policy_document" "assume_push" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.github_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role" "push" {
  name               = "github-ecr-push-${replace(var.repository_name, "/", "-")}"
  assume_role_policy = data.aws_iam_policy_document.assume_push.json
}

data "aws_iam_policy_document" "push" {
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
      "ecr:DescribeImages",
    ]
    resources = [aws_ecr_repository.app.arn]
  }
}

resource "aws_iam_role_policy" "push" {
  role   = aws_iam_role.push.id
  policy = data.aws_iam_policy_document.push.json
}

# --- GitHub OIDC deploy role: may only run the deploy document on tagged hosts --

resource "aws_iam_role" "deploy" {
  name               = "github-docker-deploy-${replace(var.repository_name, "/", "-")}"
  assume_role_policy = data.aws_iam_policy_document.assume_push.json # same trust: main branch only
}

data "aws_iam_policy_document" "deploy" {
  statement {
    actions   = ["ssm:SendCommand"]
    resources = ["arn:aws:ssm:${var.aws_region}::document/AWS-RunShellScript"]
  }
  statement {
    actions   = ["ssm:SendCommand"]
    resources = ["arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:instance/*"]
    condition {
      test     = "StringEquals"
      variable = "ssm:resourceTag/role"
      values   = ["docker"]
    }
  }
  statement {
    actions   = ["ssm:GetCommandInvocation", "ssm:ListCommandInvocations"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "deploy" {
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy.json
}

# --- outputs ----------------------------------------------------------------

output "repository_url" {
  value       = aws_ecr_repository.app.repository_url
  description = "IMAGE value for the workflow"
}

output "push_role_arn" {
  value       = aws_iam_role.push.arn
  description = "GitHub secret AWS_ECR_PUSH_ROLE_ARN"
}

output "deploy_role_arn" {
  value       = aws_iam_role.deploy.arn
  description = "GitHub secret AWS_DEPLOY_ROLE_ARN"
}
