# ---------------------------------------------------------------------------
# Tenant-wide settings and defaults. Applies to every org unless an entry in
# inputs.tf overrides it. Values live in terraform.tfvars.
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
  description = "Override the StepSecurity API base URL. null → provider default."
  type        = string
  default     = null
}

# --- Harden-Runner egress defaults -----------------------------------------

variable "default_egress_policy" {
  description = "Egress mode for policies that don't set one: audit (log only) or block."
  type        = string
  default     = "audit"

  validation {
    condition     = contains(["audit", "block"], var.default_egress_policy)
    error_message = "default_egress_policy must be audit or block."
  }
}

variable "base_allowed_endpoints" {
  description = "host:port endpoints every GitHub-hosted job needs. Prepended to each egress policy's allowed_endpoints."
  type        = any
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
}

# --- PR checks defaults -----------------------------------------------------

variable "default_check_controls" {
  description = <<-EOT
    Controls used by any `checks` entry that doesn't list its own. Names as
    StepSecurity spells them: "NPM Package Cooldown", "PyPI Package Cooldown",
    "Maven Package Cooldown", "NuGet Package Cooldown",
    "NPM|PyPI|Maven|NuGet Package Compromised Updates", "PWN Request", "Script Injection".
    Every control needs control, enable and type (required | optional); the cooldown
    controls also take settings = { cool_down_period, packages_to_exempt_in_cooldown_check }.
  EOT
  type        = any
  default = [
    { control = "NPM Package Cooldown", enable = true, type = "required", settings = { cool_down_period = 3 } },
    { control = "PyPI Package Cooldown", enable = true, type = "required", settings = { cool_down_period = 3 } },
    { control = "PWN Request", enable = true, type = "required" },
    { control = "Script Injection", enable = true, type = "optional" },
  ]
}

# --- Notification defaults --------------------------------------------------

variable "default_notification_email" {
  description = "Email used by any `notifications` entry that doesn't set one."
  type        = string
  default     = null
}

variable "default_notification_events" {
  description = "Event → on/off baseline; a notifications entry's `events` map is merged over this."
  type        = any
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
}

# --- Secrets that must not live in terraform.tfvars ------------------------

variable "notification_webhooks" {
  description = "Per-org Slack/Teams webhook URLs, keyed by org. Supply via git-ignored secrets.auto.tfvars or TF_VAR_notification_webhooks."
  type        = any
  default     = {}
  sensitive   = true
}
