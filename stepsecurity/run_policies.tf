# Run policies: gate what a workflow run may do.
# Import ID: "<org>/<policy_id>" (policy_id from the dashboard or the output).
# Provider attributes not exposed by this layout: all_orgs (apply one policy to every org in the tenant).

resource "stepsecurity_github_run_policy" "this" { # one run policy per var.run_policies entry
  for_each = var.run_policies                      # map key = policy name (unless `name` overrides it)

  owner        = each.value.owner                                         # GitHub org (required)
  name         = try(each.value.name, each.key)                           # dashboard name
  all_repos    = try(each.value.repositories, null) == null ? true : null # every repo in the org unless a list is given
  repositories = try(each.value.repositories, null)                       # explicit repo list scopes the policy

  policy_config = merge(each.value.policy, { # the entry's `policy` block is the provider's policy_config, passed through
    owner = each.value.owner                 # the provider wants owner/name repeated inside policy_config
    name  = try(each.value.name, each.key)   # keep it equal to the top-level name
  })
}
