# One GitHub org: the standard controls stamped onto every repo in `repos`,
# with per-repo overrides in `repo_settings` and org-wide values in `settings`.

variable "org" {
  description = "GitHub organization name"
  type        = string
}

variable "repos" {
  description = "Repos that get the default controls, e.g. [\"api\", \"web\"]"
  type        = any
  default     = []
}

# Per-repo overrides, keyed by repo name. Every key is optional:
#   "payments-api" = {
#     egress_policy                   = "block"                   # audit | block
#     allowed_endpoints               = ["sts.amazonaws.com:443"] # extra endpoints for this repo only
#     lockdown                        = true                      # stop the job on runtime detections
#     workflows                       = ["deploy.yml"]            # attach only to these workflows (default: whole repo)
#     require_harden_runner           = true
#     require_pinned_actions          = true
#     allowed_actions                 = { "*/*" = "allow" }
#     actions_to_exempt_while_pinning = ["acme/*"]
#     dry_run                         = false                     # enforce instead of report
#   }
variable "repo_settings" {
  type    = any
  default = {}
}

# Org-wide values, already merged with the tenant defaults by the root module.
# Same keys as var.defaults in ../../organizations.tf.
variable "settings" {
  type = any
}

variable "base_allowed_endpoints" {
  description = "Endpoints every job needs; prepended to every repo policy"
  type        = any
}

variable "default_check_controls" {
  description = "PR-check controls used when settings.check_controls is null"
  type        = any
}

variable "notification_events" {
  description = "Event => on/off map for the org notification settings"
  type        = any
}

variable "webhooks" {
  description = "{ slack_webhook_url, teams_webhook_url } for this org, or {}"
  type        = any
  default     = {}
  sensitive   = true
}
