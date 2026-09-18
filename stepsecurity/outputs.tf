output "organizations" {
  description = "Orgs under management"
  value       = sort(keys(var.organizations))
}

output "egress_policies" {
  description = "Policy-store policies by <org>/<name> → { id, egress_policy, attached }"
  value = {
    for key, p in stepsecurity_github_policy_store.this : key => {
      id            = p.id
      egress_policy = p.egress_policy
      attached      = contains(keys(local.egress_policy_attachments), key)
    }
  }
}

output "run_policies" {
  description = "Run policies by <org>/<name> → StepSecurity policy_id (needed for imports)"
  value       = { for key, p in stepsecurity_github_run_policy.this : key => p.policy_id }
}

output "suppression_rules" {
  description = "Suppression rules by <org>/<name> → rule_id"
  value       = { for key, r in stepsecurity_github_supression_rule.this : key => r.rule_id }
}

output "orgs_with_checks" {
  description = "Orgs with PR checks configured"
  value       = sort(keys(stepsecurity_github_checks.this))
}

output "orgs_with_notifications" {
  description = "Orgs with notification settings configured"
  value       = sort(keys(stepsecurity_github_org_notification_settings.this))
}

output "orgs_with_policy_driven_prs" {
  description = "Orgs where StepSecurity opens remediation PRs"
  value       = sort(keys(stepsecurity_policy_driven_pr.this))
}
