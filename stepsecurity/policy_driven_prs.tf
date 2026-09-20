# Policy-driven PRs: StepSecurity opens remediation PRs in the selected repos,
# using the org's PR template when one is defined. Import ID for both: "<org>".
# Provider auto_remediation_options attributes not exposed by this layout (add
# them to the merge below if needed): action_commit_map, custom_actions_to_replace,
# labels_to_replace, add_workflows, update_precommit_file, custom_precommit_config.

resource "stepsecurity_policy_driven_pr" "this" { # one per org in var.policy_driven_prs
  for_each = var.policy_driven_prs                # map key = org name

  owner                 = each.key                                    # the org
  selected_repos        = try(each.value.selected_repos, ["*"])       # repos that get PRs; "*" = all
  excluded_repos        = try(each.value.excluded_repos, null)        # carve-outs from "*"
  selected_repos_filter = try(each.value.selected_repos_filter, null) # { include_repos_only_with_topics = [...] }

  # Sensible defaults; anything set in tfvars overrides them.
  auto_remediation_options = merge({               # what the PRs fix
    create_pr                             = true   # open a PR (cannot be combined with create_issue)
    create_issue                          = false  # open an issue instead
    create_github_advanced_security_alert = false  # raise a GHAS alert; needs create_issue = true
    harden_github_hosted_runner           = true   # add the harden-runner step
    pin_actions_to_sha                    = true   # pin actions to commit SHAs
    restrict_github_token_permissions     = true   # minimal GITHUB_TOKEN permissions
    secure_docker_file                    = false  # pin Docker base images by digest
  }, try(each.value.auto_remediation_options, {})) # the entry's own options win
}

resource "stepsecurity_github_pr_template" "this" { # one per org in var.pr_templates
  for_each = var.pr_templates                       # map key = org name

  owner          = each.key                          # the org
  title          = each.value.title                  # PR title (required)
  summary        = each.value.summary                # PR body; {{STEPSECURITY_SECURITY_FIXES}} is replaced (required)
  commit_message = each.value.commit_message         # commit message (required)
  labels         = try(each.value.labels, null)      # labels added to the PR
  branch_name    = try(each.value.branch_name, null) # must contain {time}
}
