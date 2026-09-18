# Run policies: gate what a workflow run may do.

resource "stepsecurity_github_run_policy" "this" {
  for_each = var.run_policies

  owner        = each.value.owner
  name         = coalesce(each.value.name, each.key)
  all_repos    = each.value.repositories == null ? true : null
  repositories = each.value.repositories

  policy_config = merge(each.value.policy, {
    owner = each.value.owner
    name  = coalesce(each.value.name, each.key)
  })
}
