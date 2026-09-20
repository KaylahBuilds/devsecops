# ===========================================================================
# versions.tf — which Terraform CLI and which provider build this module needs.
#
# Terraform refuses to run when the CLI version is outside required_version,
# and `terraform init` downloads the newest provider release that satisfies
# `version`, then records the exact choice plus checksums in
# .terraform.lock.hcl. Commit that lock file: laptops and CI then use the same
# build even though the constraint below allows newer ones. CI pins
# TF_VERSION: "1.9.8" in .github/workflows/stepsecurity.yml — keep it inside
# required_version when you raise the minimum.
#
# How to run (from this directory):
#   terraform init -backend-config="key=stepsecurity/terraform.tfstate"     # first time, and after editing this file
#   terraform init -upgrade                                                 # move to the newest provider allowed by `version`, rewrite the lock file
#   terraform providers lock -platform=linux_amd64 -platform=darwin_arm64   # add lock-file checksums for every OS/arch your team runs
#   terraform version                                                       # prints the CLI version and the provider version in use
#
# Constraint syntax (same for required_version and provider version):
#   "= 0.0.44"            exactly this release
#   ">= 0.0.44"           this or anything newer, including breaking releases
#   ">= 0.0.44, < 0.1.0"  explicit range; identical to "~> 0.0.44"
#   "~> 0.0.44"           pessimistic: only the LAST listed component may grow (0.0.45 ok, 0.1.0 not)
#   "~> 0.0"              >= 0.0.0, < 1.0.0 — any pre-1.0 release
#
# Optional: install providers from a mirror instead of the public registry
# (air-gapped CI) — CLI config, not this file (~/.terraformrc or $TF_CLI_CONFIG_FILE):
#   provider_installation {
#     filesystem_mirror { path = "/opt/tf-mirror"  include = ["step-security/*"] }   # or network_mirror { url = "https://mirror.example.com/" }
#     direct            { exclude = ["step-security/*"] }
#   }
# ===========================================================================

# ===== Terraform settings ====================================================
terraform {                     # Terraform's own settings block; backend.tf holds a second terraform {} block with the state backend — Terraform merges them
  required_version = ">= 1.9.0" # oldest CLI allowed (CI runs 1.9.8); raise it — never lower it — when you adopt a newer feature: >= 1.10.0 for `ephemeral` variables (variables.tf) or S3 `use_lockfile` (backend.tf). Alternative: "~> 1.9" = >= 1.9.0, < 2.0.0

  # Every provider this module uses, keyed by its local name; one entry per provider.
  required_providers {
    stepsecurity = {                         # local name referenced by provider "stepsecurity" {} in providers.tf and implied by the stepsecurity_* resource types
      source  = "step-security/stepsecurity" # registry address, short for registry.terraform.io/step-security/stepsecurity — the official StepSecurity provider; a mirror can serve the same address
      version = "~> 0.0.44"                  # >= 0.0.44, < 0.1.0: `init -upgrade` may take 0.0.x patch releases but never 0.1.0; 0.0.44 is the release this module was written against. Alternatives: "= 0.0.44" (exact pin), ">= 0.0.44" (accept anything newer)
    }
    # aws = {                     # optional: add another provider the same way, e.g. hashicorp/aws if you manage the state bucket from here (this module itself needs none)
    #   source  = "hashicorp/aws" # registry address
    #   version = "~> 5.0"        # >= 5.0.0, < 6.0.0
    # }
  }
}
