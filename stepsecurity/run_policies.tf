# Run policies: gate what a workflow run may do.

resource "stepsecurity_github_run_policy" "this" {
  for_each = var.run_policies

  owner        = each.value.owner
  name         = try(each.value.name, each.key)
  all_repos    = try(each.value.repositories, null) == null ? true : null
  repositories = try(each.value.repositories, null)

  policy_config = merge(each.value.policy, {
    owner = each.value.owner
    name  = try(each.value.name, each.key)
  })
}
