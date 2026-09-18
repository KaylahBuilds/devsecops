# Partial backend config, same bucket/table as ../terraform. The state key is
# injected at init time so one tenant == one state file:
#   terraform init -backend-config="key=stepsecurity/terraform.tfstate"
# Fill bucket/table with the outputs from ../bootstrap after its one-time apply.
terraform {
  backend "s3" {
    bucket         = "REPLACE_WITH_bootstrap_state_bucket_output"
    region         = "us-east-1"
    dynamodb_table = "secres-tf-lock"
    encrypt        = true
  }
}
