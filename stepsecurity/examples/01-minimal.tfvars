# =============================================================================
# Example 01 - Minimal: one org, observe only
# =============================================================================
# What it demonstrates:
#   - onboarding a single GitHub org ("acme-corp") with nothing that can fail a build
#   - one Harden-Runner egress policy in "audit" mode (logs every outbound call, blocks none), attached org-wide
#   - StepSecurity PR checks marked "required" on every repo, using the tenant-default controls
#   - notifications to one email address with the tenant-default event set
#   - every optional attribute of the three live entries, commented out with meaning / allowed values / default
#   - the four input maps this scenario does not need (run_policies, policy_driven_prs, pr_templates, suppression_rules), set to {} so this file fully replaces terraform.tfvars
#
# Run (from the repo root):
#   cd stepsecurity && terraform plan -var-file=examples/01-minimal.tfvars
#
# Credentials never live in a tfvars file - export them first:
#   export STEP_SECURITY_CUSTOMER=<tenant name> STEP_SECURITY_API_KEY=<api key>
#
# Expected plan: 4 resources to add
#   stepsecurity_github_policy_store.this["acme-baseline"]             the egress policy
#   stepsecurity_github_policy_store_attachment.this["acme-baseline"]  its org-wide attachment
#   stepsecurity_github_checks.this["acme-corp"]                       PR checks
#   stepsecurity_github_org_notification_settings.this["acme-corp"]    email notifications
# =============================================================================

# ===== Tenant-wide settings (variables.tf) ===================================
# Provider auth - keep these commented out; the provider reads the env vars.
# customer     = "acme"                        # optional: StepSecurity tenant name (default: null -> STEP_SECURITY_CUSTOMER env var)
# api_key      = "<never put a real key here>" # optional: API key (default: null -> STEP_SECURITY_API_KEY env var); sensitive, must never be committed
# api_base_url = "https://<host StepSecurity gave you>" # optional: dedicated/regional API host incl. scheme (default: null -> STEP_SECURITY_API_BASE_URL env var -> built-in https://agent.api.stepsecurity.io)

default_egress_policy = "audit" # mode for egress policies that omit egress_policy: audit = log only | block = drop unlisted endpoints (default: audit)

# base_allowed_endpoints = [                              # optional: host:port endpoints every GitHub-hosted job needs; prepended to each egress policy's allowed_endpoints (default below)
#   "github.com:443",                                     #   git clone / push over HTTPS
#   "api.github.com:443",                                 #   GitHub REST API
#   "codeload.github.com:443",                            #   tarball downloads (actions/checkout, gh release)
#   "objects.githubusercontent.com:443",                  #   release assets and LFS objects
#   "*.actions.githubusercontent.com:443",                #   action downloads, cache, artifacts
#   "results-receiver.actions.githubusercontent.com:443", #   job result upload
#   "ghcr.io:443",                                        #   GitHub container registry
#   "pkg-containers.githubusercontent.com:443",           #   container layer downloads
# ]

# default_check_controls = [                                                   # optional: controls for any `checks` entry without its own `controls` list (default below)
#   { enable = true, type = "required", control = "NPM Package Cooldown", settings = { cool_down_period = 3 } },  #   required: fail when an npm package was published less than 3 days ago
#   { enable = true, type = "required", control = "PyPI Package Cooldown", settings = { cool_down_period = 3 } }, #   required: same for PyPI
#   { enable = true, type = "required", control = "PWN Request" },                                                #   required: pull_request_target misuse
#   { enable = true, control = "Script Injection", type = "optional" },                        #   optional (non-blocking): untrusted input interpolated into run: scripts
# ]

# default_notification_email = "sec@example.com" # optional: email for `notifications` entries that omit `email` (default: null = no email)

# default_notification_events = {                # optional: baseline on/off per event; a notifications entry's `events` map is merged over it (default below)
#   domain_blocked                        = true  #   outbound call to a domain was blocked (block mode only)
#   file_overwrite                        = true  #   a source file was overwritten during the job
#   new_endpoint_discovered               = false #   a call to an endpoint not seen before (noisy: every new dependency triggers it; off by default)
#   https_detections                      = true  #   anomalous HTTPS outbound call
#   secrets_detected                      = true  #   a secret showed up in the build log
#   artifacts_secrets_detected            = true  #   a secret showed up in a build artifact
#   imposter_commits_detected             = true  #   an action is pinned to a commit that is not in its repo
#   suspicious_network_call_detected      = true  #   suspicious network call
#   suspicious_process_events_detected    = true  #   suspicious process (reverse shell, privileged container, ...)
#   harden_runner_config_changes_detected = true  #   someone changed a harden-runner step in a workflow
#   non_compliant_artifact_detected       = false #   artifact failed compliance checks
#   run_blocked_by_policy                 = true  #   a run policy blocked a workflow run
#   baseline_check_failures               = false #   baseline PR check failed
#   required_check_failures               = true  #   required PR check failed
#   optional_check_failures               = false #   optional PR check failed
# }

# notification_webhooks = { "acme-corp" = { slack_webhook_url = "...", teams_webhook_url = "..." } } # SECRET, never here: copy examples/secrets.auto.tfvars.example to stepsecurity/secrets.auto.tfvars (git-ignored) or set TF_VAR_notification_webhooks (default: {})

# ===== Harden-Runner egress policies (policy_store.tf) =======================
# Key = policy name in the StepSecurity dashboard. Each entry names its org via `owner`.
egress_policies = {
  # One org-wide audit policy: harden-runner records every outbound call, blocks nothing.
  "acme-baseline" = {
    owner         = "acme-corp" # GitHub org this policy belongs to (required)
    egress_policy = "audit"     # audit = log egress only | block = drop anything not in allowed_endpoints; omitted -> var.default_egress_policy
    # name                    = "acme-baseline"            # optional: dashboard policy name (default: the map key)
    # allowed_endpoints       = ["registry.npmjs.org:443"] # optional: extra host:port endpoints appended after var.base_allowed_endpoints; wildcards like "*.amazonaws.com:443" ok; only enforced in block mode (default: [])
    # include_base_endpoints  = false                      # optional: false leaves var.base_allowed_endpoints out of this policy (default: true)
    # denied_endpoints        = ["evil.example.com"]       # optional: hostnames only, no port; deny-list mode - the allow-list is dropped when this is set (default: null)
    # disable_sudo            = true                       # optional: remove sudo inside the job (default: false)
    # disable_file_monitoring = true                       # optional: stop watching for source-file overwrites (default: false)
    # disable_telemetry       = true                       # optional: stop sending harden-runner telemetry to StepSecurity (default: false)
    # lockdown = {                                         # optional: stop the job when one of these detections fires (default: null = no lockdown)
    #   enabled                   = true                   #   optional: master switch (default: true once the block is present)
    #   privileged_container      = true                   #   optional: stop on Privileged-Container detection (default: true)
    #   reverse_shell             = true                   #   optional: stop on Reverse-Shell detection (default: true)
    #   runner_worker_memory_read = true                   #   optional: stop on Runner-Worker-Memory-Read detection (default: true)
    # }
  }
}

# ===== Where each egress policy applies (policy_store.tf) ====================
# Key MUST equal an egress_policies key. Use org_wide OR repositories OR clusters.
egress_policy_attachments = {
  # Attach the audit policy to every repo and workflow in acme-corp.
  "acme-baseline" = {
    org_wide = true # true = every repo and workflow in the org (default: false)
    # repositories = [                              # optional: instead of org_wide, pick repos / workflows (default: null); ignored when org_wide = true
    #   { name = "web-frontend" },                  #   whole repo: name only, workflows omitted
    #   { name = "svc-*", workflows = ["ci.yml"] }, #   a "*" pattern MUST list workflow files; no wildcards inside workflow names
    # ]
    # clusters = ["prod-eks"]                       # optional: Harden-Runner for Kubernetes cluster names; replaces the org attachment when set (default: null)
  }
}

# ===== Run policies (run_policies.tf) ========================================
run_policies = {} # what a workflow run may do (allowed / SHA-pinned actions, runner labels, harden-runner presence, secrets, compromised actions) - not used here; see example 03 (examples/03-run-policies.tfvars)

# ===== PR checks (checks.tf), keyed by org ===================================
checks = {
  # Required (merge-blocking) checks on every repo, with the tenant-default controls.
  "acme-corp" = {
    required_checks = { repos = ["*"] } # run the "required" check on these repos; "*" = every repo in the org
    # custom_description = "Questions? Ask #security on Slack."                       # optional: text appended to every check summary (default: null)
    # controls = [                                                                     # optional: which controls run and in which check type (default: null -> var.default_check_controls)
    #   { enable = true, type = "required", control = "NPM Package Cooldown", settings = { cool_down_period = 5, packages_to_exempt_in_cooldown_check = ["lodash"] } }, # settings only apply to the cooldown controls; cool_down_period in days (provider default: 2)
    #   { enable = true, type = "required", control = "PyPI Package Cooldown", settings = { cool_down_period = 5 } },      # enable defaults to true, type to "required"
    #   { enable = true, type = "required", control = "Maven Package Cooldown" },                                          # other names: "NuGet Package Cooldown", "NPM|PyPI|Maven|NuGet Package Compromised Updates", "PWN Request", "Script Injection"
    #   { control = "Script Injection", enable = true, type = "optional" },              # type = required (blocks merge) | optional (informational); enable = false keeps the entry but turns it off
    # ]
    # required_checks = { repos = ["*"], omit_repos = ["sandbox"] }                    # omit_repos is only valid when repos = ["*"]
    # optional_checks = { repos = ["*"] }                                              # optional: non-blocking check on these repos (default: null); omit_repos allowed as above
    # baseline_check  = { repos = ["*"], omit_repos = ["sandbox"] }                    # optional: baseline check on these repos (default: null); omit_repos allowed as above
  }
}

# ===== Notifications (notifications.tf), keyed by org ========================
notifications = {
  # Email only; the events fired are var.default_notification_events unchanged.
  "acme-corp" = {
    email = "sec@example.com" # address that receives alerts; omitted -> var.default_notification_email
    # slack_channel_id = "C0123456789"                                              # optional: Slack channel ID; setting it switches Slack delivery to the OAuth app instead of a webhook (default: null)
    # events = { new_endpoint_discovered = true, optional_check_failures = true }   # optional: per-event overrides merged over var.default_notification_events; keys = the 15 event names listed above (default: {})
    # threat_intel = {                                                              # optional: Threat Intel (compromised package) alerts for this org; omitted -> the org's current setting is kept (default: null)
    #   enabled = true                                                              #   optional: receive Threat Intel notifications at all (default: true once the block is present)
    #   level   = "all"                                                             #   optional: all = every incident | name = only packages this org uses, any version | version = only the exact compromised version (default: all)
    # }
    # Slack / Teams webhook URLs are NOT set here: put notification_webhooks["acme-corp"] in the git-ignored secrets.auto.tfvars (see examples/secrets.auto.tfvars.example)
  }
}

# ===== Policy-driven PRs (policy_driven_prs.tf), keyed by org ================
policy_driven_prs = {} # StepSecurity remediation PRs (pin actions to SHA, add harden-runner, restrict GITHUB_TOKEN, ...) - not used here; see example 06 (examples/06-remediation-prs.tfvars)

# ===== PR template for those PRs (policy_driven_prs.tf), keyed by org ========
pr_templates = {} # title / summary / commit message / labels / branch name of the remediation PRs - not used here; see example 06 (examples/06-remediation-prs.tfvars)

# ===== Suppression rules (suppressions.tf), keyed by rule name ===============
suppression_rules = {} # silence reviewed detections (expected network calls, known secrets in logs, ...) - not used here; see example 07 (examples/07-notifications-and-suppressions.tfvars)
