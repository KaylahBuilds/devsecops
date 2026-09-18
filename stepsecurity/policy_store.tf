# Harden-Runner egress policies (policy store) and their attachments.
# Attaching to org/repo/workflow makes harden-runner pull the policy at run
# time, so tightening egress never needs a workflow edit.

resource "stepsecurity_github_policy_store" "this" {
  for_each = local.egress_policies

  owner         = each.value.owner
  policy_name   = each.value.policy_name
  egress_policy = each.value.egress_policy

  allowed_endpoints = each.value.allowed_endpoints
  denied_endpoints  = each.value.denied_endpoints

  disable_sudo            = each.value.disable_sudo
  disable_file_monitoring = each.value.disable_file_monitoring
  disable_telemetry       = each.value.disable_telemetry

  lockdown = each.value.lockdown
}

resource "stepsecurity_github_policy_store_attachment" "this" {
  for_each = local.egress_policy_attachments

  owner       = each.value.owner
  policy_name = stepsecurity_github_policy_store.this[each.key].policy_name

  clusters = length(each.value.attach.clusters) > 0 ? each.value.attach.clusters : null

  org = length(each.value.attach.clusters) > 0 ? null : {
    apply_to_org = each.value.attach.org_wide
    repositories = each.value.attach.org_wide ? null : [
      for repo, workflows in each.value.attach.repositories : {
        name      = repo
        workflows = length(workflows) > 0 ? workflows : null
      }
    ]
  }
}
