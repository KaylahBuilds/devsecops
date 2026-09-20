output "repos" {
  description = "Repos under default controls in this org"
  value       = var.repos
}

output "run_policy_ids" {
  description = "Per-repo run policies (policy_id needed for imports)"
  value = {
    harden_runner  = stepsecurity_github_run_policy.harden_runner
    pinned_actions = stepsecurity_github_run_policy.pinned_actions
  }
}
