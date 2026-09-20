# ---------------------------------------------------------------------------
# Per-org / per-repo inputs. One map per StepSecurity resource type.
# Every entry names its GitHub org (`owner`), or the map is keyed by org.
# Values live in terraform.tfvars. Each comment below shows one full entry
# with every field it accepts; anything not listed as required can be left out.
# ---------------------------------------------------------------------------

# Harden-Runner egress policies, keyed by policy name.
#
#   "my-policy" = {
#     owner                   = "my-org"                              # required
#     egress_policy           = "block"                               # audit | block   (default: var.default_egress_policy)
#     allowed_endpoints       = ["registry.npmjs.org:443"]            # host:port, added to var.base_allowed_endpoints
#     include_base_endpoints  = false                                 # default true
#     denied_endpoints        = ["evil.example.com"]                  # hostnames only; use instead of allowed_endpoints
#     disable_sudo            = true                                  # default false
#     disable_file_monitoring = true                                  # default false
#     disable_telemetry       = true                                  # default false
#     lockdown                = { reverse_shell = true }              # stop the job on detections; {} = all four on
#     name                    = "Dashboard name"                      # default: the map key
#   }
variable "egress_policies" { # map of entries, keyed as described above; one resource per entry
  type    = any              # no type declaration: the example above is the contract; the provider validates values at plan time
  default = {}               # nothing managed until terraform.tfvars adds entries
}

# Where each egress policy applies. Key must match an egress_policies key.
#
#   "my-policy" = {
#     org_wide     = true                                             # every repo and workflow in the org
#     repositories = [                                                # or pick repos / workflows:
#       { name = "api" },                                             #   whole repo
#       { name = "svc-*", workflows = ["ci.yml"] },                   #   pattern + workflow files (patterns need workflows)
#     ]
#     clusters     = ["prod-k8s"]                                     # or Harden-Runner for Kubernetes clusters
#   }
variable "egress_policy_attachments" { # map of entries, keyed as described above; one resource per entry
  type    = any                        # no type declaration: the example above is the contract; the provider validates values at plan time
  default = {}                         # nothing managed until terraform.tfvars adds entries
}

# Run policies, keyed by policy name. `policy` is the provider's policy_config
# block verbatim, so the StepSecurity docs examples paste straight in.
#
#   "pin-actions" = {
#     owner        = "my-org"                                         # required
#     repositories = ["payments", "billing"]                          # default: all repos in the org
#     name         = "Dashboard name"                                 # default: the map key
#     policy = {                                                      # set at least one enable_* = true
#       is_dry_run                        = true                      # report only, never block
#       enable_action_policy              = true
#       require_pinned_actions            = true
#       allowed_actions                   = { "*/*" = "allow" }       # "owner/repo" | "owner/*" | "*/*"
#       actions_to_exempt_while_pinning   = ["my-org/*"]
#       enable_runs_on_policy             = true
#       runs_on_mode                      = "disallowed"              # disallowed | allowed
#       disallowed_runner_labels          = ["self-hosted"]
#       allowed_runner_labels             = ["ubuntu-latest"]         # with runs_on_mode = "allowed"
#       allowed_runner_constraints        = { cpu = ["2", "4"] }
#       enable_standard_runner_labels     = true
#       enable_harden_runner_policy       = true
#       harden_runner_target_labels       = []                        # [] = every job
#       harden_runner_custom_actions      = ["my-org/harden-runner"]
#       require_policy_store              = true
#       block_job_container               = true
#       enable_secrets_policy             = true
#       exempted_users                    = ["dependabot[bot]"]
#       bulk_secrets_only_mode            = true
#       secrets_analyze_default_branch    = true
#       enable_compromised_actions_policy = true
#       pr_comment_template               = "..."
#     }
#   }
variable "run_policies" { # map of entries, keyed as described above; one resource per entry
  type    = any           # no type declaration: the example above is the contract; the provider validates values at plan time
  default = {}            # nothing managed until terraform.tfvars adds entries
}

# PR checks, keyed by org.
#
#   "my-org" = {
#     custom_description = "Questions? #security on Slack"
#     controls = [                                                    # default: var.default_check_controls
#       { control = "NPM Package Cooldown", enable = true, type = "required", settings = { cool_down_period = 3 } },
#       { control = "Script Injection", enable = true, type = "optional" },   # control, enable, type are all needed
#     ]
#     required_checks = { repos = ["*"], omit_repos = ["sandbox"] }   # merge-blocking
#     optional_checks = { repos = ["docs"] }                          # informational
#     baseline_check  = { repos = ["*"] }                             # existing violations, non-blocking
#   }
variable "checks" { # map of entries, keyed as described above; one resource per entry
  type    = any     # no type declaration: the example above is the contract; the provider validates values at plan time
  default = {}      # nothing managed until terraform.tfvars adds entries
}

# Notifications, keyed by org. Webhook URLs come from var.notification_webhooks.
#
#   "my-org" = {
#     email            = "sec@example.com"                            # default: var.default_notification_email
#     slack_channel_id = "C0123456789"                                # Slack OAuth delivery instead of a webhook
#     events           = { new_endpoint_discovered = true }           # merged over var.default_notification_events
#     threat_intel     = { enabled = true, level = "version" }        # level: all | name | version
#   }
variable "notifications" { # map of entries, keyed as described above; one resource per entry
  type    = any            # no type declaration: the example above is the contract; the provider validates values at plan time
  default = {}             # nothing managed until terraform.tfvars adds entries
}

# Policy-driven remediation PRs, keyed by org. `auto_remediation_options` is
# the provider block verbatim.
#
#   "my-org" = {
#     selected_repos        = ["*"]                                   # default ["*"]
#     excluded_repos        = ["sandbox"]
#     selected_repos_filter = { include_repos_only_with_topics = ["prod"] }
#     auto_remediation_options = {
#       create_pr                             = true                  # default true (not with create_issue)
#       create_issue                          = false
#       create_github_advanced_security_alert = false                 # needs create_issue = true
#       harden_github_hosted_runner           = true                  # default true
#       pin_actions_to_sha                    = true                  # default true
#       restrict_github_token_permissions     = true                  # default true
#       secure_docker_file                    = false
#       replace_action_on_major_tag_match     = true
#       update_existing_configuration         = true
#       actions_to_exempt_while_pinning       = ["my-org/*"]
#       images_to_exempt_while_pinning        = ["amazon*"]
#       actions_to_replace_with_step_security_actions = ["actions/setup-go"]
#       actions_exempted_from_replacement     = ["actions/checkout"]
#       harden_runner_config = { target_runner_labels = ["ubuntu-latest"], exempt_runner_labels = [], update_existing_configuration = true, config = "..." }
#       package_ecosystem    = [{ package = "npm", interval = "weekly", cooldown_yaml = "...", groups_yaml = "..." }]
#     }
#   }
variable "policy_driven_prs" { # map of entries, keyed as described above; one resource per entry
  type    = any                # no type declaration: the example above is the contract; the provider validates values at plan time
  default = {}                 # nothing managed until terraform.tfvars adds entries
}

# PR template for those PRs, keyed by org.
#
#   "my-org" = {
#     title          = "[StepSecurity] Apply security best practices"  # required
#     summary        = "..."                                            # required; {{STEPSECURITY_SECURITY_FIXES}} placeholder
#     commit_message = "..."                                            # required
#     labels         = ["security"]
#     branch_name    = "chore/stepsecurity-{time}"                      # must contain {time}
#   }
variable "pr_templates" { # map of entries, keyed as described above; one resource per entry
  type    = any           # no type declaration: the example above is the contract; the provider validates values at plan time
  default = {}            # nothing managed until terraform.tfvars adds entries
}

# Suppression rules, keyed by rule name. Scope with repo / workflow / job ("*" = any).
#
#   "codecov-upload" = {
#     owner         = "my-org"                                        # required; "*" = every org
#     type          = "anomalous_outbound_network_call"               # required; see suppressions.tf for the types
#     description   = "Coverage upload is expected"
#     repo          = "api"                                           # default "*"
#     workflow      = "ci.yml"                                        # default "*"
#     job           = "test"                                          # default "*"
#     process       = "*"                                             # network-call / process types
#     destination   = { domain = "*.codecov.io" }                     # or { ip = "..." }
#     endpoint      = "https://..."                                   # suspicious_network_call
#     host          = "api.github.com*"                               # https_outbound_network_call (+ file_path)
#     file          = "Dockerfile"                                    # source_code_overwritten (+ file_path)
#     file_path     = "*"
#     secret_type   = "github-pat"                                    # secret_in_build_log / secret_in_artifact
#     artifact_name = "build"                                         # secret_in_artifact
#     github_action = "owner/action"                                  # action_uses_imposter_commit
#   }
variable "suppression_rules" { # map of entries, keyed as described above; one resource per entry
  type    = any                # no type declaration: the example above is the contract; the provider validates values at plan time
  default = {}                 # nothing managed until terraform.tfvars adds entries
}
