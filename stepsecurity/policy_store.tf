# =============================================================================
# policy_store.tf — Harden-Runner egress policies ("policy store") and where
# they are attached.
# =============================================================================
# What this file manages
#   Harden-Runner is the StepSecurity agent that runs inside a GitHub Actions
#   job (or a Kubernetes runner pod) and watches its outbound network traffic
#   and runtime behaviour. An EGRESS POLICY says which endpoints a job may
#   reach and which runtime detections stop it; an ATTACHMENT says where that
#   policy applies (a whole org, named repos / workflow files, or clusters).
#
#   var.egress_policies           -> stepsecurity_github_policy_store            one instance per map entry
#   var.egress_policy_attachments -> stepsecurity_github_policy_store_attachment one instance per map entry, SAME key
#
# Where the values come from
#   Entries live in terraform.tfvars (or examples/*.tfvars); their object
#   types are declared in inputs.tf; the tenant-wide defaults this file applies
#   (default_egress_policy, base_allowed_endpoints) live in variables.tf.
#   Adding an org, a policy or an attachment never touches this file.
#
# How to run (from stepsecurity/; credentials come from the environment)
#   export STEP_SECURITY_CUSTOMER=<tenant> STEP_SECURITY_API_KEY=<key>
#   terraform init -backend-config="key=stepsecurity/terraform.tfstate"
#   terraform plan            # uses terraform.tfvars, or -var-file=examples/02-egress-policies.tfvars
#
# Adopting policies that already exist in the dashboard (README, "Adopting
# existing config"): both resources import with the ID  <org>:::<policy name>
#   import { to = stepsecurity_github_policy_store.this["baseline"],            id = "acme-platform:::baseline" }
#   import { to = stepsecurity_github_policy_store_attachment.this["baseline"], id = "acme-platform:::baseline" }
# =============================================================================

# ===== egress_policies -> stepsecurity_github_policy_store ===================
# One policy-store policy per entry. The map key is the policy's name in the
# StepSecurity dashboard unless the entry sets `name`. Minimal tfvars entry:
#   egress_policies = { "baseline" = { owner = "acme-platform" } }   # audit mode (var.default_egress_policy) + base endpoints only
resource "stepsecurity_github_policy_store" "this" { # address: stepsecurity_github_policy_store.this["<map key>"]
  for_each = var.egress_policies                     # one instance per entry of the map; each.key = map key, each.value = the entry object typed in inputs.tf

  owner         = each.value.owner                                              # (required) GitHub org that owns the policy, e.g. "acme-platform"; tfvars: owner = "<org>"
  policy_name   = coalesce(each.value.name, each.key)                           # (required) dashboard name: the entry's `name` when set, otherwise the map key; tfvars: name = "..." (optional, default: the key)
  egress_policy = coalesce(each.value.egress_policy, var.default_egress_policy) # (required) audit = log egress only | block = drop anything not in allowed_endpoints; entry value, else var.default_egress_policy (module default: audit)

  # Allow-list of "host:port" endpoints, enforced only in block mode. A policy
  # that sets denied_endpoints is a DENY-list policy and must not carry an
  # allow-list (the provider rejects the two together), so it sends null.
  # Otherwise the list is var.base_allowed_endpoints (what every GitHub-hosted
  # job needs to reach GitHub itself) followed by the entry's own endpoints,
  # de-duplicated with distinct(). tfvars knobs on the entry:
  #   allowed_endpoints      = ["registry.npmjs.org:443", "*.amazonaws.com:443"] # host:port, wildcards ok (default: [] = base list only)
  #   include_base_endpoints = false                                            # optional: skip the base list and list every endpoint yourself (default: true)
  #   denied_endpoints       = ["evil.example.com"]                             # optional: switch to a deny-list; hostnames only, no port (default: null)
  allowed_endpoints = each.value.denied_endpoints != null ? null : distinct(concat( # null for a deny-list policy; else base + own, duplicates removed
    each.value.include_base_endpoints ? var.base_allowed_endpoints : [],            # base list first (empty when include_base_endpoints = false)
    each.value.allowed_endpoints,                                                   # then the entry's own host:port endpoints (default [])
  ))
  denied_endpoints = each.value.denied_endpoints # (optional) set of hostnames blocked in block mode; null (default) = allow-list policy. Never combined with allowed_endpoints

  disable_sudo            = each.value.disable_sudo            # (optional) true = remove sudo inside the job so a compromised step cannot escalate; null (default) = provider default (false)
  disable_file_monitoring = each.value.disable_file_monitoring # (optional) true = stop watching for source-file overwrites during the build; null (default) = provider default (false)
  disable_telemetry       = each.value.disable_telemetry       # (optional) true = stop the agent sending run telemetry to StepSecurity; null (default) = provider default (false)
  # Lockdown stops the job the moment one of the selected runtime detections
  # fires. Passed as the whole object; null (default) = no lockdown block.
  # tfvars: lockdown = { enabled = true }                        # all three detections on (inputs.tf defaults every flag to true)
  #         lockdown = { enabled = true, reverse_shell = false }  # opt one detection out
  #   enabled                   = true | false (default true)  master switch
  #   privileged_container      = true | false (default true)  stop on a Privileged-Container detection
  #   reverse_shell             = true | false (default true)  stop on a Reverse-Shell detection
  #   runner_worker_memory_read = true | false (default true)  stop on a Runner-Worker-Memory-Read detection
  lockdown = each.value.lockdown # (optional) lockdown { enabled, privileged_container, reverse_shell, runner_worker_memory_read }; null = off
}
# ---- Provider attributes NOT exposed by this layout (stepsecurity v0.0.44) ---
#   none — every argument of stepsecurity_github_policy_store is passed through
#   (owner, policy_name, egress_policy, allowed_endpoints, denied_endpoints,
#   disable_sudo, disable_file_monitoring, disable_telemetry, lockdown{...}).
#   Computed (read-only): id = owner + policy name, the same string used as the
#   import ID  <org>:::<policy name>.
#   Layout-only knob with no provider attribute: include_base_endpoints (it only
#   steers the concat() above).
# -----------------------------------------------------------------------------

# ===== egress_policy_attachments -> stepsecurity_github_policy_store_attachment
# One attachment per entry. The map KEY MUST equal an egress_policies key:
# owner and policy_name are read from that policy's resource, which also makes
# Terraform create the policy first and fail at plan time on a typo. An entry
# picks exactly ONE scope (tfvars):
#   "<key>" = { org_wide = true }                                              # every repo and workflow in the org
#   "<key>" = { repositories = [{ name = "web" }, { name = "svc-*", workflows = ["ci.yml"] }] } # whole repo | workflow files in matching repos
#   "<key>" = { clusters = ["prod-eks"] }                                      # Harden-Runner for Kubernetes clusters instead of an org scope
resource "stepsecurity_github_policy_store_attachment" "this" { # address: stepsecurity_github_policy_store_attachment.this["<map key>"]
  for_each = var.egress_policy_attachments                      # one instance per entry of the map; each.key must also be a key of var.egress_policies

  owner       = stepsecurity_github_policy_store.this[each.key].owner       # (required) same org as the policy being attached, looked up by key so it is never typed twice
  policy_name = stepsecurity_github_policy_store.this[each.key].policy_name # (required) the policy's dashboard name (map key, or its `name` override)

  clusters = each.value.clusters # (optional) list of Harden-Runner for Kubernetes cluster names; null (default) = not a cluster attachment; tfvars: clusters = ["prod-eks"]

  # Org-level scope. Sent only when `clusters` is null — an attachment is
  # either org/repo-scoped or cluster-scoped, never both. Inside it:
  #   apply_to_org = true            the whole org; repositories is then dropped
  #   apply_to_org = false           only the listed repositories
  # tfvars per repositories[] item:
  #   name      = "payments-api"            # (required) exact repo name, or a pattern "svc-*" / "*" — a pattern MUST also list workflows
  #   workflows = ["ci.yml", "deploy.yml"]  # optional: workflow file names (no wildcards); omit for the whole repo (default: null)
  org = each.value.clusters != null ? null : {                          # null for a cluster attachment, otherwise the org block below
    apply_to_org = each.value.org_wide                                  # true = every repo and workflow in the org; false (default) = only `repositories`; tfvars: org_wide = true
    repositories = each.value.org_wide ? null : each.value.repositories # repo list is dropped when org_wide (redundant); otherwise the entry's list (default null = none)
  }
}
# ---- Provider attributes NOT exposed by this layout (stepsecurity v0.0.44) ---
#   org.repositories[].apply_to_repo   the provider derives it: false when the item lists
#                                      workflows, true otherwise. To set it by hand add
#                                      `apply_to_repo = optional(bool)` to the repositories
#                                      object type in inputs.tf (it then passes through).
#   owner, policy_name                 always taken from the matching egress_policies entry.
#   Computed (read-only): id = owner + policy name; import ID  <org>:::<policy name>.
# -----------------------------------------------------------------------------
