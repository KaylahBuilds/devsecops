# ===========================================================================
# inputs.tf — the SHAPE of a StepSecurity tenant's configuration.
#
# One flat map variable per StepSecurity resource type. Every map entry names
# the GitHub org it belongs to (`owner`), or the map is keyed by org for
# per-org settings, so one tfvars file covers any number of orgs. Design rule
# of the layout: no loops, no for-expressions, no locals — every resource file
# is a single for_each over exactly one of these maps.
#
# You normally never edit this file. Values go in terraform.tfvars (or
# examples/*.tfvars), tenant-wide defaults go in variables.tf. Edit this file
# only to expose a provider attribute the layout does not pass through yet
# (each block below ends with the list of attributes it leaves out).
#
#   variable                   → resource (one instance per map entry)          file
#   egress_policies            → stepsecurity_github_policy_store                 policy_store.tf
#   egress_policy_attachments  → stepsecurity_github_policy_store_attachment      policy_store.tf
#   run_policies               → stepsecurity_github_run_policy                   run_policies.tf
#   checks                     → stepsecurity_github_checks                       checks.tf
#   notifications              → stepsecurity_github_org_notification_settings    notifications.tf
#   policy_driven_prs          → stepsecurity_policy_driven_pr                    policy_driven_prs.tf
#   pr_templates               → stepsecurity_github_pr_template                  policy_driven_prs.tf
#   suppression_rules          → stepsecurity_github_supression_rule              suppressions.tf
#
# How to run (from this directory, with STEP_SECURITY_API_KEY and
# STEP_SECURITY_CUSTOMER exported — never put them in a tfvars file):
#   terraform init -backend-config="key=stepsecurity/terraform.tfstate"
#   terraform plan                                             # uses terraform.tfvars
#   terraform plan -var-file=examples/02-egress-policies.tfvars # try one of the examples
#   terraform apply
#
# Reading the type definitions below:
#   attr = string                required — Terraform rejects the entry without it
#   attr = optional(string)      optional; null when omitted, so the provider default applies
#   attr = optional(bool, true)  optional; the layout fills in `true` when omitted
#   "→ resource.attr" in a trailing comment names the provider attribute the value ends up in
#
# Optional arguments a `variable` block accepts but none of these use:
#   sensitive  = true   # redact the values from plan/apply output (default: false)
#   nullable   = false  # forbid passing null for the whole map (default: true)
#   ephemeral  = true   # keep the values out of state/plan files; Terraform >= 1.10 (default: false)
#   validation { condition = <expr> error_message = "..." } # extra plan-time checks;
#                       the provider already validates every value at plan time
# ===========================================================================

# ===========================================================================
# egress_policies → stepsecurity_github_policy_store   (policy_store.tf)
# ===========================================================================
# A Harden-Runner egress policy: which network destinations a job may reach
# and which runtime detections stop it. Harden-Runner is StepSecurity's agent
# that runs as the first step of a job and watches its outbound traffic,
# processes and files. A policy stored here is used by every job whose
# harden-runner step sets `use-policy-store: true` and that is covered by an
# egress_policy_attachments entry with the same key.
#
# Example entry (terraform.tfvars):
#   egress_policies = {
#     "platform-node-build" = {                          # map key = policy name
#       owner             = "acme-platform"              # required
#       egress_policy     = "block"                      # audit | block
#       allowed_endpoints = ["registry.npmjs.org:443"]   # on top of var.base_allowed_endpoints
#       disable_sudo      = true
#     }
#   }
# Required: owner.
# Optional: name, egress_policy, allowed_endpoints, include_base_endpoints,
#   denied_endpoints, disable_sudo, disable_file_monitoring, disable_telemetry,
#   lockdown { enabled, privileged_container, reverse_shell, runner_worker_memory_read }.
# Layout-only (no provider attribute): include_base_endpoints.
# Provider attributes not exposed: none (`id` is computed by the provider).
variable "egress_policies" {
  # One-line help shown by `terraform-docs` and in variable errors.
  description = "Harden-Runner egress policies. Key = policy name (set `name` to override)."
  type = map(object({                                    # map key = policy name (→ policy_name unless `name` is set) and the key egress_policy_attachments must reuse
    owner                   = string                     # GitHub org that owns the policy, e.g. "acme-platform" → policy_store.owner (required)
    name                    = optional(string)           # policy name shown in the dashboard → policy_store.policy_name; default: the map key
    egress_policy           = optional(string)           # audit = log outbound calls only | block = drop calls not in allowed_endpoints → policy_store.egress_policy; default: var.default_egress_policy ("audit")
    allowed_endpoints       = optional(list(string), []) # host:port entries, wildcards ok ("registry.npmjs.org:443", "*.amazonaws.com:443"), appended after var.base_allowed_endpoints → policy_store.allowed_endpoints; default: [] (base endpoints only)
    include_base_endpoints  = optional(bool, true)       # layout-only: true = prepend var.base_allowed_endpoints | false = send only this entry's allowed_endpoints; default: true
    denied_endpoints        = optional(set(string))      # deny-list of hostnames WITHOUT port ("evil.example.com", "*.pastebin.com") → policy_store.denied_endpoints; when set the resource sends NO allowed_endpoints (provider forbids both); default: null (allow-list mode)
    disable_sudo            = optional(bool)             # true = remove sudo inside the job → policy_store.disable_sudo; default: null (provider default: sudo stays available)
    disable_file_monitoring = optional(bool)             # true = stop watching for source-file overwrites → policy_store.disable_file_monitoring; default: null (provider default: monitoring on)
    disable_telemetry       = optional(bool)             # true = send no process/network telemetry to StepSecurity → policy_store.disable_telemetry; default: null (provider default: telemetry on)
    lockdown = optional(object({                         # stop the job when a selected detection fires → policy_store.lockdown; default: null (no lockdown block sent, job keeps running on detections)
      enabled                   = optional(bool, true)   # master switch; false = keep the sub-settings but do not stop jobs → lockdown.enabled; default: true when the block is given
      privileged_container      = optional(bool, true)   # stop the job on a Privileged-Container detection (container started with --privileged) → lockdown.privileged_container; default: true
      reverse_shell             = optional(bool, true)   # stop the job on a Reverse-Shell detection (shell bound to a remote socket) → lockdown.reverse_shell; default: true
      runner_worker_memory_read = optional(bool, true)   # stop the job on a Runner-Worker-Memory-Read detection (process reading secrets from the runner's memory) → lockdown.runner_worker_memory_read; default: true
    }))
  }))
  default = {} # no policies unless the tfvars adds entries; an empty map plans cleanly
  # Optional variable-block arguments (see file header): sensitive, nullable, ephemeral, validation {}.
}

# ===========================================================================
# egress_policy_attachments → stepsecurity_github_policy_store_attachment   (policy_store.tf)
# ===========================================================================
# WHERE an egress policy applies. The map key MUST equal a key of
# egress_policies: the resource reads owner and policy_name from that policy,
# so a policy and its attachment share one name. Pick exactly one scope:
#   org_wide     = true          every repo and workflow in the org
#   repositories = [ ... ]       named repos / repo patterns, optionally per workflow file
#   clusters     = [ ... ]       Harden-Runner for Kubernetes cluster names (no org block is sent)
#
# Example entry (terraform.tfvars):
#   egress_policy_attachments = {
#     "platform-node-build" = {                          # same key as the policy above
#       repositories = [
#         { name = "web-frontend" },                     # whole repo
#         { name = "svc-*", workflows = ["ci.yml"] },    # a pattern MUST list workflows
#       ]
#     }
#   }
# Required: nothing at the top level (but set one of the three scopes);
#   repositories[].name inside each repo object.
# Optional: org_wide, repositories, repositories[].workflows, clusters.
# Provider attributes not exposed: org.repositories[].apply_to_repo (the provider
#   derives it: false when workflows are listed, true otherwise); owner and
#   policy_name (taken from the matching egress_policies entry); `id` (computed).
variable "egress_policy_attachments" {
  # One-line help; the key lookup fails at plan time when no policy matches.
  description = "Attach an egress policy to the org, to repos/workflows, or to clusters. Key must match an egress_policies key."
  type = map(object({                     # map key = the egress_policies key this attachment belongs to → attachment.owner / attachment.policy_name come from that policy
    org_wide = optional(bool, false)      # true = every repo and workflow in the org (repositories is then ignored) → attachment.org.apply_to_org; default: false
    repositories = optional(list(object({ # repo-level scope, used when org_wide = false → attachment.org.repositories; default: null (nothing attached unless org_wide or clusters)
      name      = string                  # repo name ("web-frontend") or a '*' pattern ("svc-*", "*"); a pattern MUST list workflows and may not contain consecutive stars → repositories[].name (required)
      workflows = optional(list(string))  # workflow file names ("ci.yml"; no wildcards) → repositories[].workflows; default: null = the whole repo (apply_to_repo = true)
    })))
    clusters = optional(list(string)) # Harden-Runner for Kubernetes cluster names; when set the org block is NOT sent (cluster-level attachment) → attachment.clusters; default: null
  }))
  default = {} # no attachments unless the tfvars adds entries; a policy without one applies only where referenced explicitly
  # Optional variable-block arguments (see file header): sensitive, nullable, ephemeral, validation {}.
}

# ===========================================================================
# run_policies → stepsecurity_github_run_policy   (run_policies.tf)
# ===========================================================================
# A run policy gates what a workflow run may do BEFORE it runs: which actions
# it may use and how they are pinned, which runner labels it may target,
# whether Harden-Runner must be present, whether it may touch secrets, and
# whether it uses a known-compromised action. `policy` is the provider's
# policy_config block passed through verbatim (run_policies.tf merges in
# owner and name), so examples from the provider docs paste straight in.
# At least one enable_* must be true or the provider rejects the policy.
#
# Example entry (terraform.tfvars):
#   run_policies = {
#     "platform-pin-actions" = {                         # map key = policy name
#       owner        = "acme-platform"                   # required
#       repositories = ["payments-api"]                  # omit = every repo in the org
#       policy = {                                       # required (provider policy_config)
#         enable_action_policy   = true
#         require_pinned_actions = true
#         allowed_actions        = { "*/*" = "allow" }
#         is_dry_run             = true                  # report only while rolling out
#       }
#     }
#   }
# Required: owner, policy (an object; every attribute inside it is optional).
# Optional: name, repositories, policy.{is_dry_run, enable_action_policy,
#   allowed_actions, require_pinned_actions, actions_to_exempt_while_pinning,
#   enable_runs_on_policy, runs_on_mode, disallowed_runner_labels,
#   allowed_runner_labels, allowed_runner_constraints,
#   enable_standard_runner_labels, enable_harden_runner_policy,
#   harden_runner_target_labels, harden_runner_custom_actions,
#   require_policy_store, block_job_container, enable_secrets_policy,
#   exempted_users, bulk_secrets_only_mode, secrets_analyze_default_branch,
#   enable_compromised_actions_policy, pr_comment_template}.
# Provider attributes not exposed: all_orgs (tenant-wide policy; this layout is
#   per-org), all_repos (derived: true when repositories is omitted),
#   policy_config.owner / policy_config.name (merged in from owner / key);
#   computed: policy_id, created_at, created_by, last_updated_at, last_updated_by.
variable "run_policies" {
  # One-line help listing the five sub-policies.
  description = "Run policies (allowed actions, pinning, runner labels, harden-runner, secrets, compromised actions)."
  type = map(object({                     # map key = policy name → run_policy.name and policy_config.name unless `name` is set
    owner        = string                 # GitHub org the policy belongs to, e.g. "acme-platform" → run_policy.owner and policy_config.owner (required)
    name         = optional(string)       # policy name shown in the dashboard → run_policy.name; default: the map key
    repositories = optional(list(string)) # repo names the policy is limited to, e.g. ["payments-api"] → run_policy.repositories; default: null = every repo (the resource then sends all_repos = true)
    policy = object({                     # the provider's policy_config block verbatim; at least one enable_* = true is required (required object, all attributes optional)
      is_dry_run = optional(bool, false)  # true = evaluate and report violations but never block a run → policy_config.is_dry_run; default: false (enforce)

      # -- action policy: which actions a workflow may use and how they must be referenced
      enable_action_policy            = optional(bool)        # true = turn on the allowed-actions policy → policy_config.enable_action_policy; default: null (off)
      allowed_actions                 = optional(map(string)) # action → "allow"; keys: "actions/checkout@v4" (exact) | "actions/checkout" (any ref) | "my-org/*" (owner) | "*/*" (every action) → policy_config.allowed_actions; default: null
      require_pinned_actions          = optional(bool)        # true = every action must be pinned to a full-length commit SHA (needs enable_action_policy = true) → policy_config.require_pinned_actions; default: null (off)
      actions_to_exempt_while_pinning = optional(set(string)) # actions that may stay on a tag/branch: "actions/checkout@v4" | "actions/checkout" | "my-org/*" ("*/*" is rejected by the API) → policy_config.actions_to_exempt_while_pinning; default: null

      # -- runs-on policy: which runner labels a job may target
      enable_runs_on_policy         = optional(bool)             # true = turn on the runner-label policy → policy_config.enable_runs_on_policy; default: null (off)
      runs_on_mode                  = optional(string)           # disallowed = block jobs whose runs-on is in disallowed_runner_labels | allowed = permit ONLY allowed_runner_labels / allowed_runner_constraints → policy_config.runs_on_mode; default: null (the provider plans "" = disallowed)
      disallowed_runner_labels      = optional(set(string))      # labels to block in disallowed mode, e.g. ["self-hosted"] → policy_config.disallowed_runner_labels; default: null
      allowed_runner_labels         = optional(set(string))      # plain labels permitted in allowed mode, matched verbatim, e.g. ["ubuntu-latest"] (required when runs_on_mode = "allowed") → policy_config.allowed_runner_labels; default: null
      allowed_runner_constraints    = optional(map(set(string))) # runs-on.com key=value constraints permitted in allowed mode, e.g. { family = ["m7a"], cpu = ["4", "8"] } (lowercase keys, at least one value each) → policy_config.allowed_runner_constraints; default: null
      enable_standard_runner_labels = optional(bool)             # true = add GitHub's hosted labels (ubuntu-latest, windows-latest, macos-*, arm variants) to disallowed_runner_labels and harden_runner_target_labels at evaluation time → policy_config.enable_standard_runner_labels; default: null (off)

      # -- harden-runner policy: targeted jobs must run the step-security/harden-runner step
      enable_harden_runner_policy  = optional(bool)        # true = require the Harden-Runner step in every targeted job → policy_config.enable_harden_runner_policy; default: null (off)
      harden_runner_target_labels  = optional(set(string)) # runner labels the requirement applies to: [] = every job | ["ubuntu-latest"] = only jobs with that runs-on | omitted = leave the backend value untouched → policy_config.harden_runner_target_labels; default: null
      harden_runner_custom_actions = optional(set(string)) # extra actions accepted as Harden-Runner equivalents, e.g. ["acme-platform/harden-wrapper"] → policy_config.harden_runner_custom_actions; default: null
      require_policy_store         = optional(bool)        # true = the Harden-Runner step must set `use-policy-store: true` (the legacy `policy:` input does not count) → policy_config.require_policy_store; default: null (off)
      block_job_container          = optional(bool)        # true = block targeted jobs that run entirely inside a job-level `container:` (Harden-Runner cannot monitor them; step containers are fine) → policy_config.block_job_container; default: null (off)

      # -- secrets policy: stop workflow runs from exfiltrating secrets
      enable_secrets_policy          = optional(bool)        # true = turn on the secrets exfiltration policy → policy_config.enable_secrets_policy; default: null (off)
      exempted_users                 = optional(set(string)) # users/bots the secrets policy never blocks, e.g. ["dependabot[bot]", "renovate[bot]"] → policy_config.exempted_users; default: null
      bulk_secrets_only_mode         = optional(bool)        # true = only block high-risk BULK secret exposure, not every secret reference → policy_config.bulk_secrets_only_mode; default: null (all references)
      secrets_analyze_default_branch = optional(bool)        # true = also evaluate runs on the repo's default branch (by default only other branches are) → policy_config.secrets_analyze_default_branch; default: null (off)

      # -- compromised actions policy: block action versions StepSecurity has flagged as compromised
      enable_compromised_actions_policy = optional(bool) # true = block runs that use a known-compromised action version → policy_config.enable_compromised_actions_policy; default: null (off)

      pr_comment_template = optional(string) # custom text for the PR comment posted when this policy blocks a run (supports placeholder substitution) → policy_config.pr_comment_template; default: null (StepSecurity's default comment)
    })
  }))
  default = {} # no run policies unless the tfvars adds entries
  # Optional variable-block arguments (see file header): sensitive, nullable, ephemeral, validation {}.
}

# ===========================================================================
# checks → stepsecurity_github_checks   (checks.tf)
# ===========================================================================
# StepSecurity PR checks for one org: status checks StepSecurity posts on pull
# requests (package cooldown, compromised updates, PWN request, script
# injection). `controls` says which checks run and whether each is blocking;
# required_checks / optional_checks / baseline_check say in which repos each
# kind runs. One entry per org, keyed by org.
#
# Example entry (terraform.tfvars):
#   checks = {
#     "acme-platform" = {                                # map key = org
#       custom_description = "Questions: #security on Slack."
#       # controls omitted → var.default_check_controls
#       required_checks = { repos = ["*"] }              # blocking checks everywhere
#       baseline_check  = { repos = ["*"], omit_repos = ["sandbox"] }
#     }
#   }
# Required: nothing (an empty entry only adopts the org with default controls).
# Optional: custom_description, controls[].{control (required inside), enable,
#   type, settings{cool_down_period, packages_to_exempt_in_cooldown_check}},
#   required_checks{repos (required inside), omit_repos},
#   optional_checks{repos, omit_repos}, baseline_check{repos, omit_repos}.
# Control names, exactly as the provider spells them: "NPM Package Cooldown",
#   "PyPI Package Cooldown", "Maven Package Cooldown", "NuGet Package Cooldown",
#   "NPM Package Compromised Updates", "PyPI Package Compromised Updates",
#   "Maven Package Compromised Updates", "NuGet Package Compromised Updates",
#   "PWN Request", "Script Injection".
# Provider attributes not exposed: none (owner is the map key).
variable "checks" {
  # One-line help.
  description = "StepSecurity PR checks per org. Key = org name."
  type = map(object({                                                 # map key = GitHub org name → checks.owner
    custom_description = optional(string)                             # free text appended to every check summary, e.g. a contact channel → checks.custom_description; default: null (none)
    controls = optional(list(object({                                 # which checks run and whether they block → checks.controls; default: null → var.default_check_controls
      control = string                                                # control name exactly as listed above, e.g. "NPM Package Cooldown" → controls[].control (required)
      enable  = optional(bool, true)                                  # false = keep the control listed but switched off → controls[].enable; default: true
      type    = optional(string, "required")                          # required = the check blocks merging | optional = advisory only → controls[].type; default: "required"
      settings = optional(object({                                    # per-control tuning; only the "* Package Cooldown" controls read it → controls[].settings; default: null
        cool_down_period                     = optional(number)       # days a newly published package version must age before the check accepts it → settings.cool_down_period; default: null (provider default: 2)
        packages_to_exempt_in_cooldown_check = optional(list(string)) # package names never held back by the cooldown, e.g. ["@acme/internal-sdk"] → settings.packages_to_exempt_in_cooldown_check; default: null
      }))
    })))
    required_checks = optional(object({   # where the blocking (type = "required") checks run → checks.required_checks; default: null (no required checks)
      repos      = list(string)           # repo names, or ["*"] for every repo in the org → required_checks.repos (required)
      omit_repos = optional(list(string)) # repos skipped; only valid together with repos = ["*"] → required_checks.omit_repos; default: null
    }))
    optional_checks = optional(object({   # where the advisory (type = "optional") checks run → checks.optional_checks; default: null (no optional checks)
      repos      = list(string)           # repo names, or ["*"] for every repo in the org → optional_checks.repos (required)
      omit_repos = optional(list(string)) # repos skipped; only valid together with repos = ["*"] → optional_checks.omit_repos; default: null
    }))
    baseline_check = optional(object({    # where StepSecurity's baseline PR check runs → checks.baseline_check; default: null (no baseline check)
      repos      = list(string)           # repo names, or ["*"] for every repo in the org → baseline_check.repos (required)
      omit_repos = optional(list(string)) # repos skipped; only valid together with repos = ["*"] → baseline_check.omit_repos; default: null
    }))
  }))
  default = {} # no checks configured unless the tfvars adds an org
  # Optional variable-block arguments (see file header): sensitive, nullable, ephemeral, validation {}.
}

# ===========================================================================
# notifications → stepsecurity_github_org_notification_settings   (notifications.tf)
# ===========================================================================
# Where one org's alerts go (email, Slack, Teams) and which events raise one.
# Webhook URLs are secrets: notifications.tf reads them from the sensitive
# var.notification_webhooks[<org>] (git-ignored secrets.auto.tfvars or
# TF_VAR_notification_webhooks), never from this map. Setting slack_channel_id
# switches Slack delivery to the StepSecurity Slack app (OAuth) instead.
#
# Example entry (terraform.tfvars):
#   notifications = {
#     "acme-platform" = {                                # map key = org
#       email            = "sec@example.com"             # omit → var.default_notification_email
#       slack_channel_id = "C0123456789"                 # OAuth delivery to this channel
#       events           = { new_endpoint_discovered = true }
#       threat_intel     = { enabled = true, level = "version" }
#     }
#   }
# Required: nothing (an empty entry sends to var.default_notification_email
#   with var.default_notification_events).
# Optional: email, slack_channel_id, events, threat_intel{enabled, level}.
# Event names accepted in `events` (true/false; var.default_notification_events
#   value in parentheses):
#   domain_blocked (true)                         outbound call to a domain was blocked
#   file_overwrite (true)                         a source file was overwritten during a run
#   new_endpoint_discovered (false)               anomalous outbound call to a new endpoint
#   https_detections (true)                       anomalous HTTPS outbound call
#   secrets_detected (true)                       secret found in a build log
#   artifacts_secrets_detected (true)             secret found in an uploaded artifact
#   imposter_commits_detected (true)              action pinned to a commit that is not in its repo
#   suspicious_network_call_detected (true)       suspicious network call
#   suspicious_process_events_detected (true)     suspicious process event (reverse shell, ...)
#   harden_runner_config_changes_detected (true)  harden-runner config changed in a workflow
#   non_compliant_artifact_detected (false)       non-compliant artifact detected
#   run_blocked_by_policy (true)                  a run policy blocked a run
#   baseline_check_failures (false)               baseline PR check failed
#   required_check_failures (true)                required PR check failed
#   optional_check_failures (false)               optional PR check failed
# Provider attributes not exposed: notification_channels.slack_webhook_url and
#   teams_webhook_url (read from var.notification_webhooks),
#   slack_notification_method (derived: "oauth" when slack_channel_id is set,
#   otherwise the provider default "webhook"); `id` (computed).
variable "notifications" {
  # One-line help.
  description = "Org notification channels and events. Key = org name."
  type = map(object({                          # map key = GitHub org name → notification_settings.owner
    email            = optional(string)        # inbox for alerts, e.g. "sec@example.com" → notification_channels.email; default: null → var.default_notification_email
    slack_channel_id = optional(string)        # Slack channel ID ("C0123456789") for delivery through the StepSecurity Slack app; the resource then sets slack_notification_method = "oauth" → notification_channels.slack_channel_id; default: null (webhook delivery, if var.notification_webhooks has a URL)
    events           = optional(map(bool), {}) # event name → true/false, merged OVER var.default_notification_events; keys are exactly the 15 names listed above → notification_events.<name>; default: {} (defaults only)
    threat_intel = optional(object({           # Threat Intel alerts about compromised packages/actions in this org's PRs and workflows → notification_settings.threat_intel; default: null (block omitted; the org's current setting is kept and adopted into state)
      enabled = optional(bool, true)           # false = never send Threat Intel alerts to this org → threat_intel.enabled; default: true
      level   = optional(string, "all")        # all = every incident | name = only when this org uses the affected package at any version | version = only when it uses the exact compromised version → threat_intel.level; default: "all"
    }))
  }))
  default = {} # no notification settings managed unless the tfvars adds an org
  # Optional variable-block arguments (see file header): sensitive, nullable, ephemeral, validation {}.
}

# ===========================================================================
# policy_driven_prs → stepsecurity_policy_driven_pr   (policy_driven_prs.tf)
# ===========================================================================
# Policy-driven PRs: StepSecurity opens remediation pull requests (or issues)
# in the selected repos of one org — adding Harden-Runner, pinning actions to
# SHAs, restricting GITHUB_TOKEN permissions, pinning Dockerfile images,
# configuring Dependabot. `auto_remediation_options` is the provider block
# passed through verbatim. Turn this on last: it opens PRs in every selected
# repo. The PR text comes from pr_templates[<same org>] when one exists.
#
# Example entry (terraform.tfvars):
#   policy_driven_prs = {
#     "acme-platform" = {                                # map key = org
#       selected_repos = ["*"]                           # default; or a list of repo names
#       excluded_repos = ["sandbox"]
#       auto_remediation_options = {                     # required; {} = every default below
#         actions_to_exempt_while_pinning = ["acme-platform/*"]
#         harden_runner_config            = { target_runner_labels = ["ubuntu-latest"] }
#       }
#     }
#   }
# Required: auto_remediation_options (an object; every attribute inside it is optional).
# Optional: selected_repos, excluded_repos,
#   selected_repos_filter{include_repos_only_with_topics},
#   auto_remediation_options.{create_pr, create_issue,
#   create_github_advanced_security_alert, harden_github_hosted_runner,
#   pin_actions_to_sha, restrict_github_token_permissions, secure_docker_file,
#   replace_action_on_major_tag_match, update_existing_configuration,
#   actions_to_exempt_while_pinning, images_to_exempt_while_pinning,
#   actions_to_replace_with_step_security_actions,
#   actions_exempted_from_replacement, harden_runner_config{config,
#   target_runner_labels, exempt_runner_labels, update_existing_configuration},
#   package_ecosystem[]{package (required inside), interval (required inside),
#   cooldown_yaml, groups_yaml}}.
# Provider attributes not exposed (add them to the object type and they pass
#   through unchanged): auto_remediation_options.action_commit_map (map action →
#   commit SHA to use instead of resolving the pin), add_workflows (extra
#   workflow YAML to add), custom_actions_to_replace (map original action →
#   replacement action), labels_to_replace (map disallowed runner label →
#   allowed label), update_precommit_file (list of pre-commit config paths to
#   update); `id` (computed).
variable "policy_driven_prs" {
  # One-line help.
  description = "StepSecurity remediation PRs per org. Key = org name."
  type = map(object({                                        # map key = GitHub org name → policy_driven_pr.owner
    selected_repos = optional(list(string), ["*"])           # repos that receive remediation PRs: ["*"] = every repo | ["payments-api", "web-frontend"] = only these → policy_driven_pr.selected_repos; default: ["*"]
    excluded_repos = optional(list(string))                  # repos skipped when selected_repos = ["*"]; their previous config is restored or removed → policy_driven_pr.excluded_repos; default: null
    selected_repos_filter = optional(object({                # narrows selected_repos = ["*"] further → policy_driven_pr.selected_repos_filter; default: null (no filter)
      include_repos_only_with_topics = optional(set(string)) # only repos carrying one of these GitHub topics, e.g. ["production"] → selected_repos_filter.include_repos_only_with_topics; default: null
    }))
    auto_remediation_options = object({                             # the provider's auto_remediation_options block verbatim: what the PR/issue fixes (required object; {} takes every default below)
      create_pr                             = optional(bool, true)  # open a pull request with the fixes → auto_remediation_options.create_pr; default: true
      create_issue                          = optional(bool, false) # open a GitHub issue describing the findings → auto_remediation_options.create_issue; default: false
      create_github_advanced_security_alert = optional(bool, false) # also raise a GitHub Advanced Security alert (only acts when create_issue = true) → auto_remediation_options.create_github_advanced_security_alert; default: false
      harden_github_hosted_runner           = optional(bool, true)  # add the Harden-Runner step to jobs on GitHub-hosted runners → auto_remediation_options.harden_github_hosted_runner; default: true
      pin_actions_to_sha                    = optional(bool, true)  # replace action tags with full-length commit SHAs → auto_remediation_options.pin_actions_to_sha; default: true
      restrict_github_token_permissions     = optional(bool, true)  # add a least-privilege `permissions:` block for GITHUB_TOKEN → auto_remediation_options.restrict_github_token_permissions; default: true
      secure_docker_file                    = optional(bool, false) # pin Dockerfile base images to a SHA digest → auto_remediation_options.secure_docker_file; default: false
      replace_action_on_major_tag_match     = optional(bool)        # true = swap actions from actions_to_replace_with_step_security_actions only when the major tag matches (needs that list non-empty) → auto_remediation_options.replace_action_on_major_tag_match; default: null (off)
      update_existing_configuration         = optional(bool)        # true = Dependabot config drops ecosystems that are not in package_ecosystem → auto_remediation_options.update_existing_configuration; default: null (off)

      actions_to_exempt_while_pinning               = optional(list(string)) # actions left unpinned by pin_actions_to_sha, e.g. ["acme-platform/*"] → auto_remediation_options.actions_to_exempt_while_pinning; default: null
      images_to_exempt_while_pinning                = optional(list(string)) # Docker images left unpinned by secure_docker_file, e.g. ["alpine"] → auto_remediation_options.images_to_exempt_while_pinning; default: null
      actions_to_replace_with_step_security_actions = optional(list(string)) # third-party actions to swap for StepSecurity-maintained forks, e.g. ["actions/checkout"]; mutually exclusive with the next attribute → auto_remediation_options.actions_to_replace_with_step_security_actions; default: null
      actions_exempted_from_replacement             = optional(list(string)) # replace ALL maintained actions EXCEPT these; mutually exclusive with the previous attribute → auto_remediation_options.actions_exempted_from_replacement; default: null

      harden_runner_config = optional(object({                 # how the Harden-Runner step is written into workflows → auto_remediation_options.harden_runner_config; default: null (StepSecurity's default config)
        config                        = optional(string)       # YAML string configuring the Harden-Runner step, e.g. "egress-policy: audit" → harden_runner_config.config; default: null
        target_runner_labels          = optional(list(string)) # only jobs whose runs-on matches one of these get the step, e.g. ["ubuntu-latest"] → harden_runner_config.target_runner_labels; default: null (all jobs)
        exempt_runner_labels          = optional(set(string))  # glob patterns of runner labels to skip regardless of target_runner_labels, e.g. ["gpu-*"] → harden_runner_config.exempt_runner_labels; default: null
        update_existing_configuration = optional(bool)         # true = strip existing Harden-Runner settings that are not in `config` → harden_runner_config.update_existing_configuration; default: null (leave them)
      }))
      package_ecosystem = optional(list(object({ # Dependabot ecosystems written to .github/dependabot.yml → auto_remediation_options.package_ecosystem; default: null (no Dependabot changes)
        package       = string                   # Dependabot ecosystem name: npm | pip | docker | github-actions | maven | nuget | ... → package_ecosystem[].package (required)
        interval      = string                   # update schedule: daily | weekly | monthly → package_ecosystem[].interval (required)
        cooldown_yaml = optional(string)         # YAML for the ecosystem's `cooldown:` block, e.g. "default-days: 7" → package_ecosystem[].cooldown_yaml; default: null
        groups_yaml   = optional(string)         # YAML for the ecosystem's `groups:` block (batch updates into one PR) → package_ecosystem[].groups_yaml; default: null
      })))
    })
  }))
  default = {} # no remediation PRs unless the tfvars adds an org
  # Optional variable-block arguments (see file header): sensitive, nullable, ephemeral, validation {}.
}

# ===========================================================================
# pr_templates → stepsecurity_github_pr_template   (policy_driven_prs.tf)
# ===========================================================================
# The title, body, commit message, labels and branch name StepSecurity uses
# for the policy-driven PRs of one org. Keyed by org; only meaningful for an
# org that also has a policy_driven_prs entry. Multi-line values work with a
# heredoc (summary = <<-EOT ... EOT) in terraform.tfvars.
#
# Example entry (terraform.tfvars):
#   pr_templates = {
#     "acme-platform" = {                                # map key = org
#       title          = "[StepSecurity] Apply security best practices"
#       summary        = "Automated hardening from StepSecurity — review and merge."
#       commit_message = "[StepSecurity] Apply security best practices"
#       labels         = ["security", "automated"]
#       branch_name    = "chore/stepsecurity-{time}"     # {time} is mandatory
#     }
#   }
# Required: title, summary, commit_message.
# Optional: labels, branch_name.
# Provider attributes not exposed: none (owner is the map key; `id` is computed).
variable "pr_templates" {
  # One-line help.
  description = "PR template for policy-driven PRs. Key = org name."
  type = map(object({                       # map key = GitHub org name → pr_template.owner
    title          = string                 # PR title, e.g. "[StepSecurity] Apply security best practices" → pr_template.title (required)
    summary        = string                 # PR body template (Markdown; heredocs work, see terraform.tfvars) → pr_template.summary (required)
    commit_message = string                 # commit message for the remediation commit → pr_template.commit_message (required)
    labels         = optional(list(string)) # labels applied to each PR, e.g. ["security", "automated"] → pr_template.labels; default: null (no labels)
    branch_name    = optional(string)       # branch name template; MUST contain {time} (replaced by a DDHHMM timestamp so each PR gets a unique branch), e.g. "chore/stepsecurity-{time}" → pr_template.branch_name; default: null (StepSecurity's default branch name)
  }))
  default = {} # no templates unless the tfvars adds an org; StepSecurity then uses its default PR text
  # Optional variable-block arguments (see file header): sensitive, nullable, ephemeral, validation {}.
}

# ===========================================================================
# suppression_rules → stepsecurity_github_supression_rule   (suppressions.tf)
# ===========================================================================
# Silence a detection you have reviewed and accepted, so it stops raising
# alerts. Keyed by rule name. Every rule is scoped by owner (org or "*" for
# the whole tenant) and optionally repo / workflow / job ("*" = any), plus the
# detail fields the rule type needs. The action is always "ignore" (set by
# suppressions.tf; the provider supports nothing else yet).
#
# Example entry (terraform.tfvars):
#   suppression_rules = {
#     "platform-codecov-upload" = {                      # map key = rule name
#       owner       = "acme-platform"                    # required; "*" = every org
#       type        = "anomalous_outbound_network_call"  # required
#       repo        = "payments-api"                     # omit → "*"
#       process     = "*"                                # required for this type
#       destination = { domain = "*.codecov.io" }        # required for this type: domain OR ip
#     }
#   }
# Required: owner, type. Extra fields REQUIRED per type:
#   anomalous_outbound_network_call → process + destination { domain | ip } (one of the two)
#   suspicious_network_call         → endpoint
#   https_outbound_network_call     → host + file_path (path of the calling program, "*" = any)
#   secret_in_build_log             → secret_type
#   secret_in_artifact              → secret_type + artifact_name
#   source_code_overwritten         → file (+ optional file_path)
#   action_uses_imposter_commit     → github_action
#   runner_worker_memory_read | privileged_container | reverse_shell → process
# Optional: description, repo, workflow, job, and whichever detail fields the
#   type does not need (leave them out; they must not be set for other types).
# Provider attributes not exposed: action (always "ignore"); rule_id (computed).
variable "suppression_rules" {
  # One-line help.
  description = "Ignore reviewed detections. Key = rule name. Scope with repo/workflow/job; \"*\" = any."
  type = map(object({                     # map key = rule name → supression_rule.name (the resource always sends action = "ignore")
    owner         = string                # GitHub org the rule applies to, or "*" for every org in the tenant → supression_rule.owner (required)
    type          = string                # detection type: anomalous_outbound_network_call | suspicious_network_call | https_outbound_network_call | secret_in_build_log | secret_in_artifact | source_code_overwritten | action_uses_imposter_commit | runner_worker_memory_read | privileged_container | reverse_shell → supression_rule.type (required)
    description   = optional(string)      # why this detection is accepted; shown in the dashboard → supression_rule.description; default: null
    repo          = optional(string, "*") # repo the rule is limited to; "*" = any repo → supression_rule.repo; default: "*"
    workflow      = optional(string, "*") # workflow name the rule is limited to; "*" = any workflow → supression_rule.workflow; default: "*"
    job           = optional(string, "*") # job name the rule is limited to; "*" = any job → supression_rule.job; default: "*"
    process       = optional(string)      # process that made the call / showed the behaviour: exact name or wildcards ("curl", "*node", "*"); REQUIRED for anomalous_outbound_network_call, runner_worker_memory_read, privileged_container, reverse_shell → supression_rule.process; default: null
    secret_type   = optional(string)      # category of the detected secret; REQUIRED for secret_in_build_log and secret_in_artifact → supression_rule.secret_type; default: null
    artifact_name = optional(string)      # name of the uploaded artifact; REQUIRED for secret_in_artifact → supression_rule.artifact_name; default: null
    endpoint      = optional(string)      # endpoint of the flagged call; REQUIRED for suspicious_network_call → supression_rule.endpoint; default: null
    host          = optional(string)      # host of the flagged HTTPS call; REQUIRED for https_outbound_network_call → supression_rule.host; default: null
    file          = optional(string)      # name of the overwritten file; REQUIRED for source_code_overwritten → supression_rule.file; default: null
    file_path     = optional(string)      # REQUIRED for https_outbound_network_call (calling program path, "*" = any); optional refinement of `file` for source_code_overwritten → supression_rule.file_path; default: null
    github_action = optional(string)      # action name, e.g. "actions/checkout"; REQUIRED for action_uses_imposter_commit → supression_rule.github_action; default: null
    destination = optional(object({       # where the traffic went; REQUIRED for anomalous_outbound_network_call; set domain OR ip, never both → supression_rule.destination; default: null
      domain = optional(string)           # destination domain, wildcards ok ("*.codecov.io", "*.amazonaws.com:443") → destination.domain; default: null
      ip     = optional(string)           # destination IP, wildcards ok ("192.168.*.1:443") → destination.ip; default: null
    }))
  }))
  default = {} # no suppression rules unless the tfvars adds entries
  # Optional variable-block arguments (see file header): sensitive, nullable, ephemeral, validation {}.
}
