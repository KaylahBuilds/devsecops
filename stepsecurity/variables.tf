# ---------------------------------------------------------------------------
# Tenant-wide settings and defaults.
#
# Everything here applies to EVERY organization unless an org overrides it in
# var.organizations (see inputs.tf). Keep this file to true cross-cutting
# knobs; per-org/per-repo shape belongs in inputs.tf, values in *.tfvars.
# ---------------------------------------------------------------------------

# --- provider auth ----------------------------------------------------------

variable "customer" {
  description = "StepSecurity tenant (customer) name. null → STEP_SECURITY_CUSTOMER env var."
  type        = string
  default     = null
}

variable "api_key" {
  description = "StepSecurity API key. null → STEP_SECURITY_API_KEY env var (preferred; never commit this)."
  type        = string
  default     = null
  sensitive   = true
}

variable "api_base_url" {
  description = "Override the StepSecurity API base URL (only for non-default tenancy). null → provider default."
  type        = string
  default     = null
}

# --- Harden-Runner egress defaults -----------------------------------------

variable "default_egress_policy" {
  description = "Egress mode for policy-store policies that don't set one: audit (log only) or block."
  type        = string
  default     = "audit"

  validation {
    condition     = contains(["audit", "block"], var.default_egress_policy)
    error_message = "default_egress_policy must be audit or block."
  }
}

variable "base_allowed_endpoints" {
  description = <<-EOT
    host:port endpoints every GitHub-hosted job needs (checkout, artifacts, GHCR).
    Prepended to each egress policy's allowed_endpoints unless the policy sets
    include_base_endpoints = false. Ignored for deny-list policies.
  EOT
  type        = list(string)
  default = [
    "github.com:443",
    "api.github.com:443",
    "codeload.github.com:443",
    "objects.githubusercontent.com:443",
    "*.actions.githubusercontent.com:443",
    "results-receiver.actions.githubusercontent.com:443",
    "ghcr.io:443",
    "pkg-containers.githubusercontent.com:443",
  ]

  validation {
    condition     = alltrue([for e in var.base_allowed_endpoints : can(regex("^[A-Za-z0-9*.-]+:[0-9]{1,5}$", e))])
    error_message = "Every base_allowed_endpoints entry must look like host:port (wildcards allowed in host)."
  }
}

# --- Run-policy defaults ----------------------------------------------------

variable "default_secrets_exempted_users" {
  description = "Users/bots exempt from the secrets run policy when an org policy doesn't list its own."
  type        = set(string)
  default     = ["dependabot[bot]", "renovate[bot]"]
}

# --- PR checks defaults -----------------------------------------------------

variable "default_check_controls" {
  description = <<-EOT
    StepSecurity PR-check controls applied to an org that enables `checks`
    without listing its own controls. Control names as StepSecurity spells them:
    "NPM Package Cooldown", "PyPI Package Cooldown", "Maven Package Cooldown",
    "NuGet Package Cooldown", "Compromised Updates", "PWN Request", "Script Injection".
  EOT
  type = list(object({
    control = string
    enable  = optional(bool, true)
    type    = optional(string, "required") # required | optional
    settings = optional(object({
      cool_down_period                     = optional(number)
      packages_to_exempt_in_cooldown_check = optional(list(string))
    }))
  }))
  default = [
    { control = "NPM Package Cooldown", settings = { cool_down_period = 3 } },
    { control = "PyPI Package Cooldown", settings = { cool_down_period = 3 } },
    { control = "PWN Request" },
    { control = "Script Injection", type = "optional" },
  ]

  validation {
    condition     = alltrue([for c in var.default_check_controls : contains(["required", "optional"], c.type)])
    error_message = "Each default_check_controls[*].type must be required or optional."
  }
}

# --- Notification defaults --------------------------------------------------

variable "default_notification_email" {
  description = "Fallback email for org notifications when an org sets `notifications` without an email."
  type        = string
  default     = null
}

variable "default_notification_events" {
  description = "Event → on/off baseline for every org; an org's notifications.events map is merged over this."
  type        = map(bool)
  default = {
    domain_blocked                        = true
    file_overwrite                        = true
    new_endpoint_discovered               = false
    https_detections                      = true
    secrets_detected                      = true
    artifacts_secrets_detected            = true
    imposter_commits_detected             = true
    suspicious_network_call_detected      = true
    suspicious_process_events_detected    = true
    harden_runner_config_changes_detected = true
    non_compliant_artifact_detected       = false
    run_blocked_by_policy                 = true
    baseline_check_failures               = false
    required_check_failures               = true
    optional_check_failures               = false
  }

  validation {
    condition     = length(setsubtract(keys(var.default_notification_events), local.notification_event_names)) == 0
    error_message = "default_notification_events contains an unknown event name."
  }
}

# --- Secrets that must not live in terraform.tfvars ------------------------

variable "notification_webhooks" {
  description = <<-EOT
    Per-org Slack/Teams webhook URLs, keyed by org name. Sensitive — supply via
    a git-ignored secrets.auto.tfvars or TF_VAR_notification_webhooks, never in
    terraform.tfvars.
  EOT
  type = map(object({
    slack_webhook_url = optional(string)
    teams_webhook_url = optional(string)
  }))
  default   = {}
  sensitive = true
}
