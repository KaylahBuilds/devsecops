# Partial backend config: `key` is injected per-environment at init time —
#   terraform init -backend-config="key=<env>/terraform.tfstate"
# Fill bucket/table with the outputs from bootstrap/ after its one-time apply.
terraform {
  backend "s3" {
    bucket         = "REPLACE_WITH_bootstrap_state_bucket_output"
    region         = "us-east-1"
    dynamodb_table = "secres-tf-lock"
    encrypt        = true
  }
}
