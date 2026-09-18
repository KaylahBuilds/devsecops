# Plain maps of the managed resources; read e.g.
#   terraform output -json run_policies | jq '.["pin-actions"].policy_id'

output "egress_policies" {
  description = "Managed policy-store policies, keyed as in var.egress_policies"
  value       = stepsecurity_github_policy_store.this
}

output "run_policies" {
  description = "Managed run policies (policy_id is needed for imports), keyed as in var.run_policies"
  value       = stepsecurity_github_run_policy.this
}

output "suppression_rules" {
  description = "Managed suppression rules (rule_id), keyed as in var.suppression_rules"
  value       = stepsecurity_github_supression_rule.this
}
