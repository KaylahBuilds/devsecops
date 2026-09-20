# Harden-Runner egress policies (policy store) and their attachments.
# Import IDs: both resources use "<org>:::<policy name>".
# Provider attributes not exposed by this layout: none for the policy store;
# attachment repositories[*].apply_to_repo (the provider derives it from `workflows`).

resource "stepsecurity_github_policy_store" "this" { # one policy-store entry per var.egress_policies entry
  for_each = var.egress_policies                     # map key = policy name (unless `name` overrides it)

  owner         = each.value.owner                                         # GitHub org that owns the policy (required)
  policy_name   = try(each.value.name, each.key)                           # dashboard name; `name` field wins over the map key
  egress_policy = try(each.value.egress_policy, var.default_egress_policy) # audit | block; tenant default when omitted

  # A deny-list policy carries no allow-list; otherwise base endpoints + policy-specific ones.
  allowed_endpoints = try(each.value.denied_endpoints, null) != null ? null : distinct(concat( # null when denied_endpoints is used
    try(each.value.include_base_endpoints, true) ? var.base_allowed_endpoints : [],            # include_base_endpoints = false drops the GitHub base list
    try(each.value.allowed_endpoints, []),                                                     # the policy's own host:port entries
  ))
  denied_endpoints = try(each.value.denied_endpoints, null) # hostnames only; mutually exclusive with allowed_endpoints

  disable_sudo            = try(each.value.disable_sudo, null)            # true removes sudo inside the job (provider default false)
  disable_file_monitoring = try(each.value.disable_file_monitoring, null) # true stops source-overwrite monitoring (provider default false)
  disable_telemetry       = try(each.value.disable_telemetry, null)       # true sends no process/network telemetry (provider default false)

  # lockdown = {} means every detection on; each key can be switched off individually.
  lockdown = try(each.value.lockdown, null) == null ? null : merge({ # omitted → no lockdown block at all
    enabled                   = true                                 # master switch
    privileged_container      = true                                 # stop the job when a privileged container starts
    reverse_shell             = true                                 # stop the job on a reverse-shell pattern
    runner_worker_memory_read = true                                 # stop the job when a process reads the runner worker's memory (token theft)
  }, each.value.lockdown)                                            # the entry's own keys override the defaults above
}

resource "stepsecurity_github_policy_store_attachment" "this" { # where each policy applies
  for_each = var.egress_policy_attachments                      # key must match an egress_policies key

  owner       = stepsecurity_github_policy_store.this[each.key].owner       # taken from the policy, so it cannot drift
  policy_name = stepsecurity_github_policy_store.this[each.key].policy_name # same; also orders creation after the policy

  clusters = try(each.value.clusters, null) # Harden-Runner for Kubernetes clusters; null when attaching to GitHub

  org = try(each.value.clusters, null) != null ? null : {                                      # a cluster attachment has no org block
    apply_to_org = try(each.value.org_wide, false)                                             # true = every repo and workflow in the org
    repositories = try(each.value.org_wide, false) ? null : try(each.value.repositories, null) # [{ name, workflows }] when not org-wide
  }
}
