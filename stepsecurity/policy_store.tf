# Harden-Runner egress policies (policy store) and their attachments.

resource "stepsecurity_github_policy_store" "this" {
  for_each = var.egress_policies

  owner         = each.value.owner
  policy_name   = coalesce(each.value.name, each.key)
  egress_policy = coalesce(each.value.egress_policy, var.default_egress_policy)

  # A deny-list policy carries no allow-list; otherwise base endpoints + policy-specific ones.
  allowed_endpoints = each.value.denied_endpoints != null ? null : distinct(concat(
    each.value.include_base_endpoints ? var.base_allowed_endpoints : [],
    each.value.allowed_endpoints,
  ))
  denied_endpoints = each.value.denied_endpoints

  disable_sudo            = each.value.disable_sudo
  disable_file_monitoring = each.value.disable_file_monitoring
  disable_telemetry       = each.value.disable_telemetry
  lockdown                = each.value.lockdown
}

resource "stepsecurity_github_policy_store_attachment" "this" {
  for_each = var.egress_policy_attachments

  owner       = stepsecurity_github_policy_store.this[each.key].owner
  policy_name = stepsecurity_github_policy_store.this[each.key].policy_name

  clusters = each.value.clusters

  org = each.value.clusters != null ? null : {
    apply_to_org = each.value.org_wide
    repositories = each.value.org_wide ? null : each.value.repositories
  }
}
