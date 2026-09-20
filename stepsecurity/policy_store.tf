# Harden-Runner egress policies (policy store) and their attachments.

resource "stepsecurity_github_policy_store" "this" {
  for_each = var.egress_policies

  owner         = each.value.owner
  policy_name   = try(each.value.name, each.key)
  egress_policy = try(each.value.egress_policy, var.default_egress_policy)

  # A deny-list policy carries no allow-list; otherwise base endpoints + policy-specific ones.
  allowed_endpoints = try(each.value.denied_endpoints, null) != null ? null : distinct(concat(
    try(each.value.include_base_endpoints, true) ? var.base_allowed_endpoints : [],
    try(each.value.allowed_endpoints, []),
  ))
  denied_endpoints = try(each.value.denied_endpoints, null)

  disable_sudo            = try(each.value.disable_sudo, null)
  disable_file_monitoring = try(each.value.disable_file_monitoring, null)
  disable_telemetry       = try(each.value.disable_telemetry, null)

  # lockdown = {} means every detection on; each key can be switched off individually.
  lockdown = try(each.value.lockdown, null) == null ? null : merge({
    enabled                   = true
    privileged_container      = true
    reverse_shell             = true
    runner_worker_memory_read = true
  }, each.value.lockdown)
}

resource "stepsecurity_github_policy_store_attachment" "this" {
  for_each = var.egress_policy_attachments

  owner       = stepsecurity_github_policy_store.this[each.key].owner
  policy_name = stepsecurity_github_policy_store.this[each.key].policy_name

  clusters = try(each.value.clusters, null)

  org = try(each.value.clusters, null) != null ? null : {
    apply_to_org = try(each.value.org_wide, false)
    repositories = try(each.value.org_wide, false) ? null : try(each.value.repositories, null)
  }
}
