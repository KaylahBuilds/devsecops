# ---------------------------------------------------------------------------
# Flatten var.organizations into for_each-ready maps, one per resource type,
# and apply tenant-wide defaults. Keys are "<org>/<name>" so state addresses
# read naturally: stepsecurity_github_run_policy.this["acme/pin-actions"].
# ---------------------------------------------------------------------------

locals {
  # Reference lists used by validations in variables.tf / inputs.tf.
  notification_event_names = [
    "domain_blocked",
    "file_overwrite",
    "new_endpoint_discovered",
    "https_detections",
    "secrets_detected",
    "artifacts_secrets_detected",
    "imposter_commits_detected",
    "suspicious_network_call_detected",
    "suspicious_process_events_detected",
    "harden_runner_config_changes_detected",
    "non_compliant_artifact_detected",
    "run_blocked_by_policy",
    "baseline_check_failures",
    "required_check_failures",
    "optional_check_failures",
  ]

  suppression_rule_types = [
    "secret_in_build_log",
    "secret_in_artifact",
    "anomalous_outbound_network_call",
    "suspicious_network_call",
    "https_outbound_network_call",
    "source_code_overwritten",
    "action_uses_imposter_commit",
    "runner_worker_memory_read",
    "privileged_container",
    "reverse_shell",
  ]

  # --- egress policies ------------------------------------------------------
  egress_policies = merge([
    for org, cfg in var.organizations : {
      for name, p in cfg.egress_policies : "${org}/${name}" => {
        owner         = org
        policy_name   = name
        egress_policy = coalesce(p.egress_policy, var.default_egress_policy)

        # deny-list policies carry no allow-list; otherwise base + policy-specific
        allowed_endpoints = p.denied_endpoints != null ? null : distinct(concat(
          p.include_base_endpoints ? var.base_allowed_endpoints : [],
          p.allowed_endpoints,
        ))
        denied_endpoints        = p.denied_endpoints
        disable_sudo            = p.disable_sudo
        disable_file_monitoring = p.disable_file_monitoring
        disable_telemetry       = p.disable_telemetry
        lockdown                = p.lockdown
        attach                  = p.attach
      }
    }
  ]...)

  # Only policies that actually target something get an attachment resource.
  egress_policy_attachments = {
    for key, p in local.egress_policies : key => p
    if p.attach.org_wide || length(p.attach.repositories) > 0 || length(p.attach.clusters) > 0
  }

  # --- run policies ---------------------------------------------------------
  run_policies = merge([
    for org, cfg in var.organizations : {
      for name, p in cfg.run_policies : "${org}/${name}" => merge(p, {
        owner = org
        name  = name

        all_repos = p.repositories == null ? true : null

        enable_action_policy              = p.allowed_actions != null || coalesce(p.require_pinned_actions, false)
        enable_runs_on_policy             = p.disallowed_runner_labels != null || p.allowed_runner_labels != null
        runs_on_mode                      = p.allowed_runner_labels != null ? "allowed" : (p.disallowed_runner_labels != null ? "disallowed" : null)
        enable_harden_runner_policy       = p.harden_runner_target_labels != null
        enable_secrets_policy             = p.secrets_policy
        enable_compromised_actions_policy = p.compromised_actions_policy

        exempted_users = p.secrets_policy ? (p.exempted_users != null ? p.exempted_users : var.default_secrets_exempted_users) : null
      })
    }
  ]...)

  # --- org-level singletons (one resource per org) --------------------------
  checks            = { for org, cfg in var.organizations : org => cfg.checks if cfg.checks != null }
  notifications     = { for org, cfg in var.organizations : org => cfg.notifications if cfg.notifications != null }
  policy_driven_prs = { for org, cfg in var.organizations : org => cfg.policy_driven_prs if cfg.policy_driven_prs != null }
  pr_templates      = { for org, cfg in var.organizations : org => cfg.pr_template if cfg.pr_template != null }

  # --- suppression rules ----------------------------------------------------
  suppression_rules = merge([
    for org, cfg in var.organizations : {
      for name, r in cfg.suppression_rules : "${org}/${name}" => merge(r, { owner = org, name = name })
    }
  ]...)
}
