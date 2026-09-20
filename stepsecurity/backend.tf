# ===========================================================================
# backend.tf — where Terraform keeps the state file for this tenant.
#
# State maps every map key in terraform.tfvars to the StepSecurity object it
# created (ids, policy_id, rule_id, ...). It must be shared and locked, so it
# lives in the S3 bucket + DynamoDB lock table that ../bootstrap created
# (`terraform -chdir=../bootstrap output state_bucket` / `lock_table`) — the
# same pair ../terraform/backend.tf uses; only the `key` differs.
#
# This is a PARTIAL configuration: `key` (the object path inside the bucket)
# is deliberately missing and injected at init, so one tenant == one state
# file and a second tenant only needs a different key (README → "Multiple
# tenants"):
#   terraform init -backend-config="key=stepsecurity/terraform.tfstate"                        # first tenant; CI passes $TF_STATE_KEY the same way
#   terraform init -reconfigure -backend-config="key=stepsecurity/<other>/terraform.tfstate"    # point at another tenant's state, copy nothing
#   terraform init -migrate-state                                                              # after CHANGING the block below: copies the existing state to the new backend
#   terraform init -backend-config=backend.hcl                                                 # or keep key/bucket in a separate HCL file containing  key = "stepsecurity/terraform.tfstate"
# AWS credentials are not part of the block: locally they come from your AWS
# profile/env (AWS_PROFILE, AWS_REGION, ...), in CI from OIDC via
# aws-actions/configure-aws-credentials (plan role reads state, apply role
# writes it). The StepSecurity API key is NOT stored in state, but every
# resource attribute is — treat the bucket as confidential.
# ===========================================================================

# ===== S3 state backend (live) ===============================================
# Fill bucket/table with the outputs from ../bootstrap after its one-time apply.
terraform {                                                       # second terraform {} block of the module (versions.tf has the other); Terraform merges them, but a configuration may hold only ONE backend block
  backend "s3" {                                                  # state stored as one object in an S3 bucket; alternatives further down (local, S3 without DynamoDB, HCP Terraform, other clouds)
    bucket         = "REPLACE_WITH_bootstrap_state_bucket_output" # bucket name = `terraform -chdir=../bootstrap output -raw state_bucket`; must already exist — backends never create it
    region         = "us-east-1"                                  # AWS region of the bucket and lock table (nothing StepSecurity manages lives in AWS); alt: AWS_REGION env var
    dynamodb_table = "secres-tf-lock"                             # DynamoDB table for state locking = `terraform -chdir=../bootstrap output -raw lock_table`; stops two applies running at once; deprecated from Terraform 1.11 in favour of use_lockfile
    encrypt        = true                                         # server-side encrypt the state object (SSE-S3); false = plaintext at rest (default: false)
    # key                  = "stepsecurity/terraform.tfstate"                 # optional: hard-code the object path instead of -backend-config (default: none — the S3 backend requires it, so init prompts for it when missing)
    # use_lockfile         = true                                             # optional (Terraform >= 1.10): lock with a <key>.tflock object in the bucket, no DynamoDB; keep both during migration, then drop dynamodb_table (default: false)
    # kms_key_id           = "arn:aws:kms:us-east-1:123456789012:key/<uuid>"  # optional: SSE-KMS with your own key instead of SSE-S3; the plan/apply roles need kms:Encrypt/Decrypt/GenerateDataKey on it (default: none)
    # profile              = "secres-admin"                                   # optional: named AWS CLI profile used for backend calls only (default: the ambient AWS credential chain)
    # assume_role {                                                           # optional: assume an IAM role for state access (replaces the pre-1.6 top-level role_arn)
    #   role_arn     = "arn:aws:iam::123456789012:role/tf-state"              # role to assume
    #   session_name = "stepsecurity-terraform"                               # shows up in CloudTrail
    # }
    # workspace_key_prefix = "env"                                            # optional: object prefix for non-default workspaces, <prefix>/<workspace>/<key> (default: "env:")
    # endpoints            = { s3 = "https://s3.example.internal" }           # optional: S3-compatible store (MinIO, Ceph); pair with use_path_style = true and skip_credentials_validation / skip_requesting_account_id = true (default: AWS endpoints)
  }
}

# ===== alternative 1: local state (laptop trial, no AWS) =====================
# Only one backend block is allowed, so either replace the block above or put
# this in backend_override.tf (git-ignored via *_override.tf): Terraform loads
# override files last and a backend block there replaces the S3 one, which is
# exactly how the verification harness plans this module offline.
# terraform {
#   backend "local" {
#     path = "terraform.tfstate" # state file next to the code (git-ignored via *.tfstate); no locking or sharing across machines (default: "terraform.tfstate")
#   }
# }

# ===== alternative 2: S3 without DynamoDB (Terraform >= 1.10) ================
# Native S3 locking: the same bucket, one lock object per state key, no table.
# terraform {
#   backend "s3" {
#     bucket       = "REPLACE_WITH_bootstrap_state_bucket_output" # same bucket as above
#     key          = "stepsecurity/terraform.tfstate"             # may stay partial (-backend-config) exactly like the live block
#     region       = "us-east-1"                                  # bucket region
#     use_lockfile = true                                         # lock object <key>.tflock; the plan/apply roles need s3:PutObject + s3:DeleteObject on it
#     encrypt      = true                                         # SSE-S3
#   }
# }

# ===== alternative 3: HCP Terraform / Terraform Enterprise ===================
# State, locking and remote runs hosted for you (`terraform login` first). A
# cloud {} block replaces the backend block; put STEP_SECURITY_CUSTOMER and
# STEP_SECURITY_API_KEY in the workspace as sensitive environment variables.
# terraform {
#   cloud {
#     organization = "acme" # your HCP Terraform organization
#     workspaces {
#       name = "stepsecurity" # one workspace == one tenant; or tags = ["stepsecurity"] to pick the workspace at init
#     }
#   }
# }

# ===== alternative 4: another cloud's object store ===========================
# Same idea, different block:
#   backend "gcs"     { bucket = "acme-tf-state"  prefix = "stepsecurity" }                                                   # Google Cloud Storage: locking built in
#   backend "azurerm" { storage_account_name = "acmetfstate"  container_name = "tfstate"  key = "stepsecurity.tfstate" }      # Azure Blob: blob leases for locking
