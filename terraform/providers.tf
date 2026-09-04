provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(
      {
        Project     = var.project
        Environment = var.environment
        ManagedBy   = "terraform"
        Repository  = "secres-infra"
      },
      var.extra_tags
    )
  }
}
