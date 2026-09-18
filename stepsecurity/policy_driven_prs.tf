# Policy-driven PRs: StepSecurity opens remediation PRs in the selected repos,
# using the org's PR template when one is defined.

resource "stepsecurity_policy_driven_pr" "this" {
  for_each = var.policy_driven_prs

  owner                    = each.key
  selected_repos           = each.value.selected_repos
  excluded_repos           = each.value.excluded_repos
  selected_repos_filter    = each.value.selected_repos_filter
  auto_remediation_options = each.value.auto_remediation_options
}

resource "stepsecurity_github_pr_template" "this" {
  for_each = var.pr_templates

  owner          = each.key
  title          = each.value.title
  summary        = each.value.summary
  commit_message = each.value.commit_message
  labels         = each.value.labels
  branch_name    = each.value.branch_name
}
