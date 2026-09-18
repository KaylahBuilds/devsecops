# Run policies: gate what a workflow run may do (which actions, which runners,
# harden-runner presence, secrets exposure, compromised actions). One resource
# per entry in organizations[*].run_policies; enable_* flags are derived in
# locals.tf from which fields the entry sets.

resource "stepsecurity_github_run_policy" "this" {
  for_each = local.run_policies

  owner        = each.value.owner
  name         = each.value.name
  all_repos    = each.value.all_repos
  repositories = each.value.repositories

  policy_config = {
    owner      = each.value.owner
    name       = each.value.name
    is_dry_run = each.value.dry_run

    # allowed-actions
    enable_action_policy            = each.value.enable_action_policy
    allowed_actions                 = each.value.allowed_actions
    require_pinned_actions          = each.value.require_pinned_actions
    actions_to_exempt_while_pinning = each.value.actions_to_exempt_while_pinning

    # runs-on
    enable_runs_on_policy         = each.value.enable_runs_on_policy
    runs_on_mode                  = each.value.runs_on_mode
    disallowed_runner_labels      = each.value.disallowed_runner_labels
    allowed_runner_labels         = each.value.allowed_runner_labels
    allowed_runner_constraints    = each.value.allowed_runner_constraints
    enable_standard_runner_labels = each.value.enable_standard_runner_labels

    # harden-runner
    enable_harden_runner_policy  = each.value.enable_harden_runner_policy
    harden_runner_target_labels  = each.value.harden_runner_target_labels
    harden_runner_custom_actions = each.value.harden_runner_custom_actions
    require_policy_store         = each.value.require_policy_store
    block_job_container          = each.value.block_job_container

    # secrets
    enable_secrets_policy          = each.value.enable_secrets_policy
    exempted_users                 = each.value.exempted_users
    bulk_secrets_only_mode         = each.value.bulk_secrets_only_mode
    secrets_analyze_default_branch = each.value.secrets_analyze_default_branch

    # compromised actions
    enable_compromised_actions_policy = each.value.enable_compromised_actions_policy

    pr_comment_template = each.value.pr_comment_template
  }
}
