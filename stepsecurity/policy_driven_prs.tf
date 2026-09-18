# Policy-driven PRs: StepSecurity opens remediation PRs (pin actions, add
# harden-runner, restrict GITHUB_TOKEN, ...) in the selected repos, using the
# org's PR template when one is defined.

resource "stepsecurity_policy_driven_pr" "this" {
  for_each = local.policy_driven_prs

  owner          = each.key
  selected_repos = each.value.selected_repos
  excluded_repos = length(each.value.excluded_repos) > 0 ? each.value.excluded_repos : null

  selected_repos_filter = each.value.only_repos_with_topics == null ? null : {
    include_repos_only_with_topics = each.value.only_repos_with_topics
  }

  auto_remediation_options = {
    create_pr                             = each.value.create_pr
    create_issue                          = each.value.create_issue
    create_github_advanced_security_alert = each.value.create_github_advanced_security_alert
    harden_github_hosted_runner           = each.value.harden_github_hosted_runner
    pin_actions_to_sha                    = each.value.pin_actions_to_sha
    restrict_github_token_permissions     = each.value.restrict_github_token_permissions
    secure_docker_file                    = each.value.secure_docker_file
    replace_action_on_major_tag_match     = each.value.replace_action_on_major_tag_match
    update_existing_configuration         = each.value.update_existing_configuration

    actions_to_exempt_while_pinning               = each.value.actions_to_exempt_while_pinning
    images_to_exempt_while_pinning                = each.value.images_to_exempt_while_pinning
    actions_to_replace_with_step_security_actions = each.value.actions_to_replace_with_step_security_actions
    actions_exempted_from_replacement             = each.value.actions_exempted_from_replacement

    harden_runner_config = each.value.harden_runner_config
    package_ecosystem    = each.value.package_ecosystem
  }
}

resource "stepsecurity_github_pr_template" "this" {
  for_each = local.pr_templates

  owner          = each.key
  title          = each.value.title
  summary        = each.value.summary
  commit_message = each.value.commit_message
  labels         = each.value.labels
  branch_name    = each.value.branch_name
}
