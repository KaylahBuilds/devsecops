# ===========================================================================
# providers.tf — how this module talks to StepSecurity.
#
# StepSecurity is a SaaS that hardens GitHub Actions (Harden-Runner egress
# control, run policies, PR checks, remediation PRs, ...). Its Terraform
# provider is a thin client for the StepSecurity REST API: every resource in
# this module becomes one API object inside ONE tenant (StepSecurity calls the
# tenant a "customer"). This file configures that single connection. The three
# values come from the provider-auth variables in variables.tf and, when those
# are null (the default), from environment variables.
#
# Precedence per argument: non-null variable > STEP_SECURITY_* env var >
# provider built-in default (only api_base_url has one). customer and api_key
# have no default: when neither is set, `terraform plan` stops with a provider
# configuration error before any API call is made.
#
#   argument      variable          env var fallback             built-in default
#   customer      var.customer      STEP_SECURITY_CUSTOMER       (none — required)
#   api_key       var.api_key       STEP_SECURITY_API_KEY        (none — required)
#   api_base_url  var.api_base_url  STEP_SECURITY_API_BASE_URL   https://agent.api.stepsecurity.io
#
# How to run (from this directory):
#   export STEP_SECURITY_CUSTOMER=<tenant> STEP_SECURITY_API_KEY=<api key>   # key: dashboard → Settings → API keys
#   terraform init -backend-config="key=stepsecurity/terraform.tfstate"      # see backend.tf
#   terraform plan                                                           # or: terraform plan -var-file=examples/01-minimal.tfvars
# In CI (.github/workflows/stepsecurity.yml) the same two env vars come from
# repository secrets, so nothing about auth is ever written to disk.
#
# Optional ways to pass the same values without editing this file:
#   export TF_VAR_customer=acme                  # any variable can be set as TF_VAR_<name>; TF_VAR_api_key works too
#   terraform plan -var customer=acme            # one-off on the command line (never do this with api_key: it lands in shell history)
#   secrets.auto.tfvars: api_key = "<key>"       # git-ignored (*.auto.tfvars); still prefer the env var — nothing on disk
#   export STEP_SECURITY_API_BASE_URL=https://<host>   # only when StepSecurity gives you a dedicated/regional API host
# ===========================================================================

# ===== the tenant connection =================================================
# One provider block == one tenant. Version constraints do NOT go here (a
# `version` argument in a provider block is deprecated); they live in
# versions.tf under required_providers.
provider "stepsecurity" {         # local name "stepsecurity" must match the key in versions.tf required_providers; every stepsecurity_* resource uses this block implicitly
  customer     = var.customer     # tenant (customer) name exactly as shown in the StepSecurity dashboard; null → $STEP_SECURITY_CUSTOMER; no built-in default
  api_key      = var.api_key      # API key that authenticates every call; sensitive (plan prints "(sensitive value)"); null → $STEP_SECURITY_API_KEY; no built-in default
  api_base_url = var.api_base_url # API endpoint incl. scheme; null → $STEP_SECURITY_API_BASE_URL → built-in https://agent.api.stepsecurity.io; set only for a dedicated/regional host
  # alias = "labs" # optional: name this configuration so a resource can select it with `provider = stepsecurity.labs`; an aliased block is never used implicitly, so keep exactly one block WITHOUT alias (default: no alias)
}

# ===== optional: a second tenant in the SAME configuration ===================
# Not recommended. README → "Multiple tenants" keeps one tenant per state file
# by swapping -backend-config key + STEP_SECURITY_CUSTOMER + -var-file, because
# every resource in this layout is one for_each over one map and cannot switch
# provider per entry — you would have to duplicate the resource blocks with
# `provider = stepsecurity.labs`. Shown here only so the shape is known:
# provider "stepsecurity" {
#   alias        = "labs"           # required on any second block of the same provider
#   customer     = "acme-labs"      # or a new variable in variables.tf, e.g. var.labs_customer
#   api_key      = var.labs_api_key # add it to variables.tf with sensitive = true; MUST be set explicitly — the env var fallback would silently reuse the first tenant's key
#   api_base_url = null             # null → same env var / built-in default as the main block
# }
