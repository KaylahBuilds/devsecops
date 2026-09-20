# ===========================================================================
# outputs.tf — what this module reports back after apply.
#
# Each output is the WHOLE resource map, keyed exactly like the input map in
# terraform.tfvars, so every attribute the provider returns — including the
# server-generated IDs you need for `import` blocks — is one jq path away.
# Outputs are stored in state and printed after `terraform apply`; they are
# the supported way to read state without parsing it.
#
# How to read them (after apply, from this directory):
#   terraform output                                                       # every output, HCL style — long maps are easier as JSON:
#   terraform output -json | jq 'keys'                                     # the output names
#   terraform output -json run_policies | jq -r '.["pin-actions"].policy_id'   # one attribute (-raw only works on plain strings, so use jq -r)
#   terraform output -json run_policies | jq -r 'to_entries[] | "\(.key)  \(.value.owner)/\(.value.policy_id)"'   # map key → import ID for every run policy
#   terraform output -json egress_policies | jq '.["acme-baseline"].allowed_endpoints'   # confirm var.base_allowed_endpoints was prepended
#   terraform output -json suppression_rules | jq -r '.[] | [.name, .owner, .type, .rule_id] | @tsv'   # rule IDs as a table
#   terraform show -json | jq '.values.outputs'                            # same data straight from state (or from a saved plan file)
# jq is optional — `terraform output -json run_policies` alone prints the JSON.
#
# Optional arguments every `output` block accepts (shown commented out below
# where they matter):
#   sensitive   = true          # print "(sensitive value)" instead of the value; REQUIRED when the value derives from a sensitive variable (default: false)
#   depends_on  = [<resource>]  # only for hidden dependencies; never needed here, the value already references the resource (default: none)
#   precondition {              # Terraform >= 1.2: fail with a clear message when the value is not what you expect
#     condition     = <bool expression>
#     error_message = "<what is wrong>"
#   }
# The layout rule (no for-expressions, no locals) is why the outputs are raw
# maps: reshape them with jq, not in HCL.
# ===========================================================================

# ===== egress_policies (policy_store.tf) =====================================
# Attributes per entry: id ("<org>:::<policy name>" — the import ID), owner,
# policy_name, egress_policy, allowed_endpoints (base list + the entry's own,
# or null for a deny-list policy), denied_endpoints, disable_sudo,
# disable_file_monitoring, disable_telemetry, lockdown { enabled, ... }.
output "egress_policies" {                                                       # read with: terraform output -json egress_policies
  description = "Managed policy-store policies, keyed as in var.egress_policies" # free text shown by `terraform output` tooling and terraform-docs
  value       = stepsecurity_github_policy_store.this                            # the whole for_each map of stepsecurity_github_policy_store resources → map(key => object of every attribute)
  # sensitive = true # optional: hide the endpoint lists and flags from CI logs; nothing here is secret, so it is off (default: false)
}

# ===== run_policies (run_policies.tf) ========================================
# Attributes per entry: policy_id (server-generated; import ID is
# "<org>/<policy_id>"), owner, name, all_repos, all_orgs, repositories,
# policy_config { ... } (the whole policy block as applied), created_at,
# created_by, last_updated_at, last_updated_by.
output "run_policies" {                                                                                # read with: terraform output -json run_policies
  description = "Managed run policies (policy_id is needed for imports), keyed as in var.run_policies" # free text
  value       = stepsecurity_github_run_policy.this                                                    # map(key => stepsecurity_github_run_policy attributes); policy_id exists only after apply (plan shows "known after apply")
  # precondition {                                                                # optional: guard rail — refuse to apply a tfvars that dropped a mandatory baseline policy
  #   condition     = can(stepsecurity_github_run_policy.this["pin-actions"])     # true when the map has that key (examples without it would then fail on purpose)
  #   error_message = "run_policies must keep the tenant-wide \"pin-actions\" policy."
  # }
}

# ===== suppression_rules (suppressions.tf) ===================================
# Attributes per entry: rule_id (server-generated), name (= the map key),
# owner ("*" = every org), type, action ("ignore"), description, repo,
# workflow, job (each "*" by default), plus the type-specific fields (process,
# destination { domain | ip }, endpoint, host, file, file_path, github_action,
# secret_type, artifact_name) — null unless that rule type uses them.
output "suppression_rules" {                                                             # read with: terraform output -json suppression_rules
  description = "Managed suppression rules (rule_id), keyed as in var.suppression_rules" # free text
  value       = stepsecurity_github_supression_rule.this                                 # map(key => stepsecurity_github_supression_rule attributes); the provider spells the type "supression" (one p) — keep it
}

# ===== optional: the five maps not exported ==================================
# Left out because their import ID is just the org name you already know
# (checks, notifications, policy_driven_prs, pr_templates → "<org>") or the
# same "<org>:::<policy name>" as the policy (attachments). Copy any block
# above and point `value` at the resource; shapes shown as comments:
# output "egress_policy_attachments" { # optional: where each egress policy applies
#   description = "Managed policy-store attachments, keyed as in var.egress_policy_attachments"
#   value       = stepsecurity_github_policy_store_attachment.this # id, owner, policy_name, clusters, org { apply_to_org, repositories [ { name, apply_to_repo, workflows } ] }
# }
# output "checks" { # optional: PR-check configuration per org
#   description = "Managed PR checks, keyed by org as in var.checks"
#   value       = stepsecurity_github_checks.this # owner, controls [ { control, type, enable, settings } ], required_checks / optional_checks / baseline_check { repos, omit_repos }, custom_description
# }
# output "notifications" { # optional: notification channels + events per org
#   description = "Managed org notification settings, keyed by org as in var.notifications"
#   value       = stepsecurity_github_org_notification_settings.this # id, owner, notification_channels { email, slack_*, teams_webhook_url }, notification_events { 15 bools }, threat_intel { enabled, level }
#   sensitive   = true # REQUIRED here: notification_channels carries the Slack/Teams webhook URLs fed from the sensitive var.notification_webhooks — Terraform refuses to export a sensitive value from a non-sensitive output
# }
# output "policy_driven_prs" { # optional: remediation-PR settings per org
#   description = "Managed policy-driven PR settings, keyed by org as in var.policy_driven_prs"
#   value       = stepsecurity_policy_driven_pr.this # id, owner, selected_repos, excluded_repos, selected_repos_filter, auto_remediation_options { ... }
# }
# output "pr_templates" { # optional: PR title/body/branch templates per org
#   description = "Managed PR templates, keyed by org as in var.pr_templates"
#   value       = stepsecurity_github_pr_template.this # id, owner, title, summary, commit_message, branch_name, labels
# }
