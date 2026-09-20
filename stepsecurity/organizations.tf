# ---------------------------------------------------------------------------
# Onboarding: apply the standard controls to every repo of every org.
#
#   var.defaults                      the standard (this file; do not set it in tfvars)
#   var.tenant_settings               tenant-wide overrides of any default key (tfvars)
#   organizations[org].settings       org-wide overrides of any default key
#   organizations[org].repo_settings  per-repo overrides of the repo-level keys
#
# Adding an org  = one entry in `organizations`.
# Adding a repo  = one name in that org's `repos` list.
# Repo specifics = one entry in that org's `repo_settings`.
# ---------------------------------------------------------------------------

variable "defaults" {
  description = "The full standard. Override keys through tenant_settings, not by setting this in tfvars (a tfvars value replaces the whole map)."
  type        = any
  default = {
    # --- Harden-Runner (per repo) ---
    egress_policy         = "audit" # audit | block
    allowed_endpoints     = []      # extra host:port on top of var.base_allowed_endpoints
    lockdown              = false   # stop the job on runtime detections
    workflows             = null    # null = attach to the whole repo; or ["ci.yml", ...]
    require_harden_runner = true    # every job must run harden-runner with a policy-store policy

    # --- Pinning guard (per repo) ---
    require_pinned_actions          = true
    allowed_actions                 = { "*/*" = "allow" }
    actions_to_exempt_while_pinning = []

    dry_run = true # report only; flip per repo/org once clean

    # --- Org-level ---
    compromised_actions_policy = true
    check_controls             = null # null → var.default_check_controls
    checks_omit_repos          = []
    remediation_prs            = true
    dependabot = [
      { package = "github-actions", interval = "weekly" },
      { package = "npm", interval = "weekly" },
    ]
    notification_email = null # null = no org notification settings
  }
}

# Tenant-wide overrides of any var.defaults key, e.g. { egress_policy = "block", notification_email = "sec@example.com" }
variable "tenant_settings" {
  type    = any
  default = {}
}

# Every org to onboard:
#   "acme-platform" = {
#     repos         = ["api", "web"]
#     settings      = { notification_email = "sec@example.com", dry_run = false }   # any var.defaults key
#     repo_settings = { "api" = { egress_policy = "block" } }                       # any per-repo key
#   }
variable "organizations" {
  type    = any
  default = {}
}

module "org" {
  source   = "./modules/org"
  for_each = var.organizations

  org           = each.key
  repos         = each.value.repos
  repo_settings = try(each.value.repo_settings, {})
  settings      = merge(var.defaults, var.tenant_settings, try(each.value.settings, {}))

  base_allowed_endpoints = var.base_allowed_endpoints
  default_check_controls = var.default_check_controls
  notification_events    = var.default_notification_events
  webhooks               = try(var.notification_webhooks[each.key], {})
}

output "onboarded" {
  description = "Org → repos under the standard controls"
  value       = module.org
}
