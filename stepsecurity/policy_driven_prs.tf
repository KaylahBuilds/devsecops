# Policy-driven PRs: StepSecurity opens remediation PRs in the selected repos,
# using the org's PR template when one is defined.

resource "stepsecurity_policy_driven_pr" "this" {
  for_each = var.policy_driven_prs

  owner                 = each.key
  selected_repos        = try(each.value.selected_repos, ["*"])
  excluded_repos        = try(each.value.excluded_repos, null)
  selected_repos_filter = try(each.value.selected_repos_filter, null)

  # Sensible defaults; anything set in tfvars overrides them.
  auto_remediation_options = merge({
    create_pr                             = true
    create_issue                          = false
    create_github_advanced_security_alert = false
    harden_github_hosted_runner           = true
    pin_actions_to_sha                    = true
    restrict_github_token_permissions     = true
    secure_docker_file                    = false
  }, try(each.value.auto_remediation_options, {}))
}

resource "stepsecurity_github_pr_template" "this" {
  for_each = var.pr_templates

  owner          = each.key
  title          = each.value.title
  summary        = each.value.summary
  commit_message = each.value.commit_message
  labels         = try(each.value.labels, null)
  branch_name    = try(each.value.branch_name, null)
}
