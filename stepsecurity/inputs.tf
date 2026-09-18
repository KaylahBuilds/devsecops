# ---------------------------------------------------------------------------
# Per-org / per-repo inputs. One flat map per StepSecurity resource type.
# Every entry names the GitHub org it belongs to (`owner`), so one tfvars
# file covers any number of orgs. Values live in terraform.tfvars.
#
#   egress_policies            → stepsecurity_github_policy_store
#   egress_policy_attachments  → stepsecurity_github_policy_store_attachment
#   run_policies               → stepsecurity_github_run_policy
#   checks                     → stepsecurity_github_checks
#   notifications              → stepsecurity_github_org_notification_settings
#   policy_driven_prs          → stepsecurity_policy_driven_pr
#   pr_templates               → stepsecurity_github_pr_template
#   suppression_rules          → stepsecurity_github_supression_rule
# ---------------------------------------------------------------------------

# --- Harden-Runner egress policies (policy store), keyed by policy name ------
variable "egress_policies" {
  description = "Harden-Runner egress policies. Key = policy name (set `name` to override)."
  type = map(object({
    owner                   = string
    name                    = optional(string)           # defaults to the map key
    egress_policy           = optional(string)           # audit | block; null → var.default_egress_policy
    allowed_endpoints       = optional(list(string), []) # host:port, appended to var.base_allowed_endpoints
    include_base_endpoints  = optional(bool, true)
    denied_endpoints        = optional(set(string)) # hostnames only; use instead of allowed_endpoints
    disable_sudo            = optional(bool)
    disable_file_monitoring = optional(bool)
    disable_telemetry       = optional(bool)
    lockdown = optional(object({ # stop the job on these detections
      enabled                   = optional(bool, true)
      privileged_container      = optional(bool, true)
      reverse_shell             = optional(bool, true)
      runner_worker_memory_read = optional(bool, true)
    }))
  }))
  default = {}
}

# --- Where each egress policy applies, keyed by the egress_policies key ------
variable "egress_policy_attachments" {
  description = "Attach an egress policy to the org, to repos/workflows, or to clusters. Key must match an egress_policies key."
  type = map(object({
    org_wide = optional(bool, false) # every repo and workflow in the org
    repositories = optional(list(object({
      name      = string                 # repo name, or a pattern like "svc-*" (patterns must list workflows)
      workflows = optional(list(string)) # workflow files; omit for the whole repo
    })))
    clusters = optional(list(string)) # Harden-Runner for Kubernetes
  }))
  default = {}
}

# --- Run policies, keyed by policy name --------------------------------------
# `policy` mirrors the provider's policy_config block 1:1, so the examples in
# the StepSecurity provider docs paste straight in.
variable "run_policies" {
  description = "Run policies (allowed actions, pinning, runner labels, harden-runner, secrets, compromised actions)."
  type = map(object({
    owner        = string
    name         = optional(string)       # defaults to the map key
    repositories = optional(list(string)) # null → all repos in the org
    policy = object({
      is_dry_run = optional(bool, false)

      enable_action_policy            = optional(bool)
      allowed_actions                 = optional(map(string)) # "owner/repo" | "owner/*" | "*/*" → "allow"
      require_pinned_actions          = optional(bool)
      actions_to_exempt_while_pinning = optional(set(string))

      enable_runs_on_policy         = optional(bool)
      runs_on_mode                  = optional(string) # disallowed | allowed
      disallowed_runner_labels      = optional(set(string))
      allowed_runner_labels         = optional(set(string))
      allowed_runner_constraints    = optional(map(set(string)))
      enable_standard_runner_labels = optional(bool)

      enable_harden_runner_policy  = optional(bool)
      harden_runner_target_labels  = optional(set(string)) # [] = every job
      harden_runner_custom_actions = optional(set(string))
      require_policy_store         = optional(bool)
      block_job_container          = optional(bool)

      enable_secrets_policy          = optional(bool)
      exempted_users                 = optional(set(string))
      bulk_secrets_only_mode         = optional(bool)
      secrets_analyze_default_branch = optional(bool)

      enable_compromised_actions_policy = optional(bool)

      pr_comment_template = optional(string)
    })
  }))
  default = {}
}

# --- PR checks, keyed by org ---------------------------------------------------
variable "checks" {
  description = "StepSecurity PR checks per org. Key = org name."
  type = map(object({
    custom_description = optional(string)
    controls = optional(list(object({ # null → var.default_check_controls
      control = string
      enable  = optional(bool, true)
      type    = optional(string, "required")
      settings = optional(object({
        cool_down_period                     = optional(number)
        packages_to_exempt_in_cooldown_check = optional(list(string))
      }))
    })))
    required_checks = optional(object({
      repos      = list(string)
      omit_repos = optional(list(string))
    }))
    optional_checks = optional(object({
      repos      = list(string)
      omit_repos = optional(list(string))
    }))
    baseline_check = optional(object({
      repos      = list(string)
      omit_repos = optional(list(string))
    }))
  }))
  default = {}
}

# --- Notifications, keyed by org -------------------------------------------------
# Webhook URLs come from var.notification_webhooks[<org>] (sensitive), not here.
variable "notifications" {
  description = "Org notification channels and events. Key = org name."
  type = map(object({
    email            = optional(string)        # null → var.default_notification_email
    slack_channel_id = optional(string)        # set for Slack OAuth delivery instead of a webhook
    events           = optional(map(bool), {}) # merged over var.default_notification_events
    threat_intel = optional(object({
      enabled = optional(bool, true)
      level   = optional(string, "all") # all | name | version
    }))
  }))
  default = {}
}

# --- Policy-driven PRs, keyed by org -----------------------------------------------
# `auto_remediation_options` mirrors the provider block 1:1.
variable "policy_driven_prs" {
  description = "StepSecurity remediation PRs per org. Key = org name."
  type = map(object({
    selected_repos = optional(list(string), ["*"])
    excluded_repos = optional(list(string))
    selected_repos_filter = optional(object({
      include_repos_only_with_topics = optional(set(string))
    }))
    auto_remediation_options = object({
      create_pr                             = optional(bool, true)
      create_issue                          = optional(bool, false)
      create_github_advanced_security_alert = optional(bool, false)
      harden_github_hosted_runner           = optional(bool, true)
      pin_actions_to_sha                    = optional(bool, true)
      restrict_github_token_permissions     = optional(bool, true)
      secure_docker_file                    = optional(bool, false)
      replace_action_on_major_tag_match     = optional(bool)
      update_existing_configuration         = optional(bool)

      actions_to_exempt_while_pinning               = optional(list(string))
      images_to_exempt_while_pinning                = optional(list(string))
      actions_to_replace_with_step_security_actions = optional(list(string))
      actions_exempted_from_replacement             = optional(list(string))

      harden_runner_config = optional(object({
        config                        = optional(string)
        target_runner_labels          = optional(list(string))
        exempt_runner_labels          = optional(set(string))
        update_existing_configuration = optional(bool)
      }))
      package_ecosystem = optional(list(object({
        package       = string
        interval      = string
        cooldown_yaml = optional(string)
        groups_yaml   = optional(string)
      })))
    })
  }))
  default = {}
}

# --- Template used for those PRs, keyed by org ------------------------------------
variable "pr_templates" {
  description = "PR template for policy-driven PRs. Key = org name."
  type = map(object({
    title          = string
    summary        = string
    commit_message = string
    labels         = optional(list(string))
    branch_name    = optional(string) # must contain {time}
  }))
  default = {}
}

# --- Suppression rules, keyed by rule name --------------------------------------
variable "suppression_rules" {
  description = "Ignore reviewed detections. Key = rule name. Scope with repo/workflow/job; \"*\" = any."
  type = map(object({
    owner         = string # org name, or "*" for every org in the tenant
    type          = string # secret_in_build_log | secret_in_artifact | anomalous_outbound_network_call | ...
    description   = optional(string)
    repo          = optional(string, "*")
    workflow      = optional(string, "*")
    job           = optional(string, "*")
    process       = optional(string) # required for network-call / process detection types
    secret_type   = optional(string)
    artifact_name = optional(string)
    endpoint      = optional(string)
    host          = optional(string)
    file          = optional(string)
    file_path     = optional(string)
    github_action = optional(string)
    destination = optional(object({
      domain = optional(string)
      ip     = optional(string)
    }))
  }))
  default = {}
}
