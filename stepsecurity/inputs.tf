# ---------------------------------------------------------------------------
# Per-organization / per-repository inputs.
#
# ONE variable describes every GitHub org this tenant manages. Every section
# is optional, so an org entry can be as small as `"my-org" = {}`. Values
# live in terraform.tfvars; tenant-wide defaults live in variables.tf.
#
# Sections (each maps 1:1 onto a StepSecurity resource):
#   egress_policies    → stepsecurity_github_policy_store (+ _attachment)
#   run_policies       → stepsecurity_github_run_policy
#   checks             → stepsecurity_github_checks
#   notifications      → stepsecurity_github_org_notification_settings
#   policy_driven_prs  → stepsecurity_policy_driven_pr
#   pr_template        → stepsecurity_github_pr_template
#   suppression_rules  → stepsecurity_github_supression_rule
# ---------------------------------------------------------------------------

variable "organizations" {
  description = "GitHub organizations to manage, keyed by org name. See inputs.tf for the shape."

  type = map(object({

    # --- Harden-Runner egress policies (policy store) and where they attach --
    egress_policies = optional(map(object({
      egress_policy           = optional(string)           # audit | block; null → var.default_egress_policy
      allowed_endpoints       = optional(list(string), []) # host:port, appended to the base list
      include_base_endpoints  = optional(bool, true)       # prepend var.base_allowed_endpoints
      denied_endpoints        = optional(set(string))      # hostnames only; replaces the allow-list entirely
      disable_sudo            = optional(bool)
      disable_file_monitoring = optional(bool)
      disable_telemetry       = optional(bool)
      lockdown = optional(object({ # stop the job on these detections
        enabled                   = optional(bool, true)
        privileged_container      = optional(bool, true)
        reverse_shell             = optional(bool, true)
        runner_worker_memory_read = optional(bool, true)
      }))
      attach = optional(object({
        org_wide     = optional(bool, false)           # every repo/workflow in the org
        repositories = optional(map(list(string)), {}) # repo (or glob like "svc-*") → workflow files; [] = whole repo
        clusters     = optional(list(string), [])      # Harden-Runner for Kubernetes clusters
      }), {})
    })), {})

    # --- Run policies: what a workflow run is allowed to do --------------------
    # Each policy type switches on when you set its fields; leave a group unset
    # to leave that policy type off in this policy.
    run_policies = optional(map(object({
      repositories = optional(list(string)) # null → all repos in the org
      dry_run      = optional(bool, false)  # evaluate and report, never block

      # allowed-actions policy
      allowed_actions                 = optional(map(string)) # "owner/repo" or "owner/*" or "*/*" → "allow"
      require_pinned_actions          = optional(bool)
      actions_to_exempt_while_pinning = optional(set(string))

      # runs-on (runner label) policy
      disallowed_runner_labels      = optional(set(string))
      allowed_runner_labels         = optional(set(string)) # setting this switches runs_on_mode to "allowed"
      allowed_runner_constraints    = optional(map(set(string)))
      enable_standard_runner_labels = optional(bool)

      # harden-runner presence policy
      harden_runner_target_labels  = optional(set(string)) # [] = every job must run harden-runner
      harden_runner_custom_actions = optional(set(string))
      require_policy_store         = optional(bool)
      block_job_container          = optional(bool)

      # secrets policy
      secrets_policy                 = optional(bool, false)
      exempted_users                 = optional(set(string)) # null → var.default_secrets_exempted_users
      bulk_secrets_only_mode         = optional(bool)
      secrets_analyze_default_branch = optional(bool)

      # compromised-actions policy
      compromised_actions_policy = optional(bool, false)

      pr_comment_template = optional(string)
    })), {})

    # --- PR checks (StepSecurity GitHub App checks on pull requests) ----------
    checks = optional(object({
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
        repos      = optional(list(string), ["*"])
        omit_repos = optional(list(string), [])
      }), {})
      optional_checks = optional(object({
        repos      = optional(list(string), [])
        omit_repos = optional(list(string), [])
      }), {})
      baseline_check = optional(object({
        repos      = optional(list(string), ["*"])
        omit_repos = optional(list(string), [])
      }), {})
    }))

    # --- Notifications ---------------------------------------------------------
    # Webhook URLs come from var.notification_webhooks[<org>] (sensitive), not here.
    notifications = optional(object({
      email            = optional(string)        # null → var.default_notification_email
      slack_channel_id = optional(string)        # set for Slack OAuth delivery instead of a webhook
      events           = optional(map(bool), {}) # merged over var.default_notification_events
      threat_intel = optional(object({
        enabled = optional(bool, true)
        level   = optional(string, "all") # all | name | version
      }))
    }))

    # --- Policy-driven PRs (StepSecurity opens remediation PRs) ---------------
    policy_driven_prs = optional(object({
      selected_repos         = optional(list(string), ["*"])
      excluded_repos         = optional(list(string), [])
      only_repos_with_topics = optional(set(string)) # filter when selected_repos = ["*"]

      create_pr                                     = optional(bool, true)
      create_issue                                  = optional(bool, false)
      create_github_advanced_security_alert         = optional(bool, false)
      harden_github_hosted_runner                   = optional(bool, true)
      pin_actions_to_sha                            = optional(bool, true)
      restrict_github_token_permissions             = optional(bool, true)
      secure_docker_file                            = optional(bool, false)
      replace_action_on_major_tag_match             = optional(bool)
      update_existing_configuration                 = optional(bool)
      actions_to_exempt_while_pinning               = optional(list(string), [])
      images_to_exempt_while_pinning                = optional(list(string), [])
      actions_to_replace_with_step_security_actions = optional(list(string))
      actions_exempted_from_replacement             = optional(list(string))

      harden_runner_config = optional(object({
        config                        = optional(string)
        target_runner_labels          = optional(list(string))
        exempt_runner_labels          = optional(set(string))
        update_existing_configuration = optional(bool)
      }))
      package_ecosystem = optional(list(object({ # dependabot config the PRs add
        package       = string
        interval      = string
        cooldown_yaml = optional(string)
        groups_yaml   = optional(string)
      })))
    }))

    # --- Template used for those PRs -----------------------------------------
    pr_template = optional(object({
      title          = string
      summary        = string
      commit_message = string
      labels         = optional(list(string))
      branch_name    = optional(string) # must contain {time}
    }))

    # --- Suppression rules (ignore known-good detections) --------------------
    suppression_rules = optional(map(object({
      type          = string # see local.suppression_rule_types
      description   = optional(string)
      repo          = optional(string, "*")
      workflow      = optional(string, "*")
      job           = optional(string, "*")
      secret_type   = optional(string)
      artifact_name = optional(string)
      endpoint      = optional(string)
      host          = optional(string)
      file          = optional(string)
      file_path     = optional(string)
      github_action = optional(string)
      process       = optional(string)
      destination = optional(object({
        domain = optional(string)
        ip     = optional(string)
      }))
    })), {})
  }))

  default = {}

  # --- guard rails: fail at plan time with a readable message ---------------

  validation {
    condition = alltrue(flatten([
      for org, cfg in var.organizations : [
        for name, p in cfg.egress_policies : contains(["audit", "block"], coalesce(p.egress_policy, var.default_egress_policy))
      ]
    ]))
    error_message = "egress_policies[*].egress_policy must be audit or block."
  }

  validation {
    condition = alltrue(flatten([
      for org, cfg in var.organizations : [
        for name, p in cfg.egress_policies : !(p.denied_endpoints != null && length(p.allowed_endpoints) > 0)
      ]
    ]))
    error_message = "An egress policy cannot set both denied_endpoints and allowed_endpoints."
  }

  validation {
    condition = alltrue(flatten([
      for org, cfg in var.organizations : [
        for name, p in cfg.egress_policies : !(length(p.attach.clusters) > 0 && (p.attach.org_wide || length(p.attach.repositories) > 0))
      ]
    ]))
    error_message = "An egress policy attaches to clusters OR to the org/repos, not both."
  }

  validation {
    condition = alltrue(flatten([
      for org, cfg in var.organizations : [
        for name, p in cfg.egress_policies : [
          for repo, workflows in p.attach.repositories : !(can(regex("\\*", repo)) && length(workflows) == 0)
        ]
      ]
    ]))
    error_message = "Wildcard repository patterns (e.g. \"svc-*\") must list workflow files; StepSecurity cannot attach a pattern to whole repositories."
  }

  validation {
    condition = alltrue(flatten([
      for org, cfg in var.organizations : [
        for name, p in cfg.run_policies : anytrue([
          p.allowed_actions != null,
          coalesce(p.require_pinned_actions, false),
          p.disallowed_runner_labels != null,
          p.allowed_runner_labels != null,
          p.harden_runner_target_labels != null,
          p.secrets_policy,
          p.compromised_actions_policy,
        ])
      ]
    ]))
    error_message = "Every run policy must enable at least one policy type (actions, runs-on, harden-runner, secrets, compromised-actions)."
  }

  validation {
    condition = alltrue(flatten([
      for org, cfg in var.organizations : [
        for name, p in cfg.run_policies : !(p.disallowed_runner_labels != null && p.allowed_runner_labels != null)
      ]
    ]))
    error_message = "A run policy uses disallowed_runner_labels OR allowed_runner_labels, not both."
  }

  validation {
    condition = alltrue(flatten([
      for org, cfg in var.organizations : [
        for name, p in cfg.run_policies : p.repositories == null ? true : length(p.repositories) > 0
      ]
    ]))
    error_message = "run_policies[*].repositories must be null (all repos) or a non-empty list."
  }

  validation {
    condition = alltrue(flatten([
      for org, cfg in var.organizations : try(cfg.checks.controls, null) == null ? [true] : [
        for c in cfg.checks.controls : contains(["required", "optional"], c.type)
      ]
    ]))
    error_message = "checks.controls[*].type must be required or optional."
  }

  validation {
    condition = alltrue([
      for org, cfg in var.organizations :
      cfg.notifications == null ? true : length(setsubtract(keys(cfg.notifications.events), local.notification_event_names)) == 0
    ])
    error_message = "notifications.events contains an unknown event name (see local.notification_event_names)."
  }

  validation {
    condition = alltrue([
      for org, cfg in var.organizations :
      try(cfg.notifications.threat_intel.level, null) == null ? true : contains(["all", "name", "version"], cfg.notifications.threat_intel.level)
    ])
    error_message = "notifications.threat_intel.level must be all, name, or version."
  }

  validation {
    condition = alltrue([
      for org, cfg in var.organizations :
      try(cfg.pr_template.branch_name, null) == null ? true : can(regex("\\{time\\}", cfg.pr_template.branch_name))
    ])
    error_message = "pr_template.branch_name must contain the {time} placeholder."
  }

  validation {
    condition = alltrue(flatten([
      for org, cfg in var.organizations : [
        for name, r in cfg.suppression_rules : contains(local.suppression_rule_types, r.type)
      ]
    ]))
    error_message = "suppression_rules[*].type is not a known StepSecurity detection type (see local.suppression_rule_types)."
  }

  validation {
    condition = alltrue(flatten([
      for org, cfg in var.organizations : [
        for name, r in cfg.suppression_rules :
        contains(["anomalous_outbound_network_call", "runner_worker_memory_read", "privileged_container", "reverse_shell"], r.type) ? r.process != null : true
      ]
    ]))
    error_message = "suppression_rules of type anomalous_outbound_network_call, runner_worker_memory_read, privileged_container or reverse_shell must set process (\"*\" for any)."
  }

  validation {
    condition = alltrue(flatten([
      for org, cfg in var.organizations : [
        for name, r in cfg.suppression_rules : r.destination == null ? true : !(r.destination.domain != null && r.destination.ip != null)
      ]
    ]))
    error_message = "suppression_rules[*].destination sets domain OR ip, not both."
  }
}
