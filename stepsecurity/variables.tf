# ===========================================================================
# variables.tf — tenant-wide settings and defaults for the StepSecurity module.
#
# Everything here applies to EVERY GitHub org in the tenant unless an entry in
# inputs.tf overrides it. The resource files do the merging; each variable
# below says how (coalesce / concat / merge) and which file reads it. Values
# come from terraform.tfvars — you normally never edit this file.
#
#   variable                     read by            how the default is applied
#   customer, api_key,
#     api_base_url               providers.tf       passed to provider "stepsecurity"; null → STEP_SECURITY_* env var
#   default_egress_policy        policy_store.tf    coalesce(entry.egress_policy, var.default_egress_policy)
#   base_allowed_endpoints       policy_store.tf    concat(var.base_allowed_endpoints, entry.allowed_endpoints) unless include_base_endpoints = false
#   default_check_controls       checks.tf          coalesce(entry.controls, var.default_check_controls)
#   default_notification_email   notifications.tf   entry.email != null ? entry.email : var.default_notification_email
#   default_notification_events  notifications.tf   merge(var.default_notification_events, entry.events)
#   notification_webhooks        notifications.tf   try(var.notification_webhooks[<org>].<slack|teams>_webhook_url, null)
#
# How to override any default (Terraform applies these in order, last wins):
#   1. environment      export TF_VAR_default_egress_policy=block        # lists/maps in HCL syntax: TF_VAR_x='["a","b"]'
#   2. terraform.tfvars default_egress_policy = "block"                  # auto-loaded from this directory
#   3. *.auto.tfvars    secrets.auto.tfvars (git-ignored) — webhook URLs   # auto-loaded, alphabetical order
#   4. command line     -var-file=examples/02-egress-policies.tfvars, -var 'default_egress_policy=block'
#   A list or map default is REPLACED wholesale by an override, never merged:
#   repeat the entries you want to keep.
#
# How to run (from this directory):
#   export STEP_SECURITY_CUSTOMER=<tenant> STEP_SECURITY_API_KEY=<api key>   # never in a tfvars file
#   terraform init -backend-config="key=stepsecurity/terraform.tfstate"
#   terraform plan                                                           # terraform.tfvars + *.auto.tfvars
#   terraform plan -var-file=examples/01-minimal.tfvars                      # or one of the examples
#
# Optional arguments every `variable` block accepts (shown commented out below
# where they make sense for that variable):
#   sensitive = true    # redact the value from plan/apply output; still stored in state (default: false)
#   nullable  = false   # forbid null; an explicit null then falls back to `default` (default: true)
#   ephemeral = true    # keep the value out of state and plan files, Terraform >= 1.10; only for
#                       # values that feed provider config or write-only arguments (default: false)
#   validation {        # extra plan-time check; several blocks allowed
#     condition     = <bool expression over var.<name>>
#     error_message = "<what the reader must fix>"
#   }
# ===========================================================================

# ===== provider auth (providers.tf) ==========================================
# All three go straight into provider "stepsecurity" {}. Leave them null and
# the provider reads the matching STEP_SECURITY_* environment variable — that
# is how CI (.github/workflows/stepsecurity.yml) supplies them from repository
# secrets. A non-null variable wins over its environment variable.

# The StepSecurity tenant this module manages: the "customer" name shown in
# the dashboard. Not a secret, but keep it out of committed files if the same
# module should target more than one tenant (README → "Multiple tenants").
variable "customer" {
  description = "StepSecurity tenant (customer) name. null → STEP_SECURITY_CUSTOMER env var." # help text shown by terraform-docs and in variable errors
  type        = string                                                                        # one plain string, e.g. "acme"
  default     = null                                                                          # null = not set here → provider uses $STEP_SECURITY_CUSTOMER; alternatives: terraform.tfvars `customer = "acme"`, export TF_VAR_customer=acme, or -var customer=acme
  # nullable  = false # optional: forbid null; Terraform then also requires a non-null default, which removes the env-var fallback (default: true)
  # ephemeral = true  # optional (Terraform >= 1.10): keep the value out of plan files; allowed here because it only feeds the provider block (default: false)
}

# The API key that authenticates this module against the StepSecurity API
# (dashboard → Settings → API keys). Treat it like a password.
variable "api_key" {
  description = "StepSecurity API key. null → STEP_SECURITY_API_KEY env var (preferred; never commit this)." # help text
  type        = string                                                                                       # the raw key string
  default     = null                                                                                         # null = not set here → provider uses $STEP_SECURITY_API_KEY (preferred: nothing on disk); alternatives that never touch git: export TF_VAR_api_key=<key>, or git-ignored secrets.auto.tfvars `api_key = "<key>"`
  sensitive   = true                                                                                         # plan/apply print "(sensitive value)"; a saved plan file (-out) still contains it, so do not commit plan files either
  # ephemeral = true # optional (Terraform >= 1.10, bump versions.tf): also keep the key out of plan files; valid here because the value only feeds provider config (default: false)
  # nullable  = false # optional: forbid null — needs a non-null default too, which defeats the env-var fallback; not recommended (default: true)
}

# Where the provider sends API calls. Only needed when StepSecurity gives you a
# dedicated or regional API host; otherwise the provider's built-in URL is used.
variable "api_base_url" {
  description = "Override the StepSecurity API base URL. null → provider default." # help text
  type        = string                                                             # full URL including scheme, e.g. "https://<host StepSecurity gave you>"
  default     = null                                                               # null = provider default, or $STEP_SECURITY_API_BASE_URL when that is exported; alternatives: terraform.tfvars `api_base_url = "https://..."`, export TF_VAR_api_base_url=https://...
  # validation { # optional: catch a pasted host without scheme before the provider fails to connect
  #   condition     = var.api_base_url == null ? true : startswith(var.api_base_url, "https://")
  #   error_message = "api_base_url must start with https://."
  # }
}

# ===== Harden-Runner egress defaults (policy_store.tf) =======================
# Harden-Runner is StepSecurity's agent that runs as the first step of a GitHub
# Actions job and watches its outbound network calls. An egress policy
# (var.egress_policies in inputs.tf) tells it which endpoints a job may reach;
# the two variables below are the tenant-wide pieces every policy starts from.

# Egress mode for any egress_policies entry that omits `egress_policy`.
# policy_store.tf: egress_policy = coalesce(entry.egress_policy, var.default_egress_policy)
variable "default_egress_policy" {
  description = "Egress mode for policies that don't set one: audit (log only) or block." # help text
  type        = string                                                                    # one of the two mode names
  default     = "audit"                                                                   # audit = every outbound call is logged in the dashboard, nothing is blocked (safe starting point) | block = calls to endpoints outside the policy's allow-list are dropped; override: terraform.tfvars `default_egress_policy = "block"` or export TF_VAR_default_egress_policy=block

  # Rejects any other spelling at plan/validate time, before the API is called.
  validation {
    condition     = contains(["audit", "block"], var.default_egress_policy) # true only for the two modes the provider accepts (a per-entry egress_policy is checked by the provider itself)
    error_message = "default_egress_policy must be audit or block."         # message terraform prints when the condition is false
  }
}

# Endpoints prepended to EVERY egress policy's allow-list, so a tfvars entry
# lists only what its own build tools need. In "audit" mode this decides what
# is reported as unexpected; in "block" mode it is what keeps the runner itself
# working — remove an entry and every block-mode job in the tenant may fail.
# policy_store.tf:
#   allowed_endpoints = distinct(concat(entry.include_base_endpoints ? var.base_allowed_endpoints : [], entry.allowed_endpoints))
# Per-policy opt-out: include_base_endpoints = false. Deny-list policies
# (denied_endpoints set) carry no allow-list at all, so this list is ignored there.
# Format: "host:port"; "*" wildcards are allowed in the host part.
variable "base_allowed_endpoints" {
  description = "host:port endpoints every GitHub-hosted job needs. Prepended to each egress policy's allowed_endpoints." # help text
  type        = any                                                                                                       # a plain list of "host:port" strings
  # One entry per line; the trailing comment says which build step needs it.
  default = [                                             # the GitHub endpoints a hosted job needs to check out code, fetch actions and report results
    "github.com:443",                                     # git clone/fetch/push (actions/checkout), the gh CLI, downloads from release pages
    "api.github.com:443",                                 # GitHub REST/GraphQL API: actions/checkout ref lookups, actions/github-script, setup-* actions listing releases, anything using GITHUB_TOKEN
    "codeload.github.com:443",                            # tarball/zipball downloads: action sources, `go get` / pip installs straight from GitHub archives
    "objects.githubusercontent.com:443",                  # GitHub release assets and Git LFS objects (setup-node/-go/-java toolchain downloads, curl of a release binary)
    "*.actions.githubusercontent.com:443",                # GitHub Actions service hosts (pipelines, job orchestration, tool cache, artifact/cache front doors); a job cannot start or finish without them
    "results-receiver.actions.githubusercontent.com:443", # where the runner streams step logs and job results; blocked = the job's logs never reach the Actions UI
    "ghcr.io:443",                                        # GitHub Container Registry: docker pull of container actions and of `container:` / `services:` images, docker/login-action
    "pkg-containers.githubusercontent.com:443",           # blob storage behind ghcr.io; every ghcr.io pull is redirected here for the image layers
    # "*.blob.core.windows.net:443",                   # optional: Azure blob storage used by actions/cache and actions/upload-artifact — add here only if every job uses them, else per policy
    # "registry.npmjs.org:443",                        # optional: a package registry belongs here only when EVERY job needs it; otherwise egress_policies["<policy>"].allowed_endpoints
  ]
  # Override in terraform.tfvars — replaces the whole list, so copy the entries you keep:
  #   base_allowed_endpoints = ["github.com:443", "api.github.com:443", ...]
  # or: export TF_VAR_base_allowed_endpoints='["github.com:443","api.github.com:443"]'
  # validation { # optional: refuse an entry that forgot its port
  #   condition     = length(var.base_allowed_endpoints) == length(regexall("(?m):[0-9]+$", join("\n", var.base_allowed_endpoints)))
  #   error_message = "Every base_allowed_endpoints entry must be host:port."
  # }
}

# ===== PR checks defaults (checks.tf) =========================================
# StepSecurity PR checks are GitHub status checks that StepSecurity posts on
# every pull request of the selected repos (var.checks in inputs.tf picks the
# repos and whether the check is "required" — can block merging via branch
# protection — or "optional", i.e. advisory). Each check runs a list of
# *controls*; this variable is the control list for any checks entry that has
# no `controls` of its own.
# checks.tf: controls = coalesce(entry.controls, var.default_check_controls)
#
# Control names the provider accepts (exact spelling, checked at plan time):
#   "NPM Package Cooldown"    "PyPI Package Cooldown"    "Maven Package Cooldown"    "NuGet Package Cooldown"
#   "NPM Package Compromised Updates"    "PyPI Package Compromised Updates"
#   "Maven Package Compromised Updates"  "NuGet Package Compromised Updates"
#   "PWN Request"    "Script Injection"
# (the description below shortens the four "... Compromised Updates" controls
# to "Compromised Updates"; the provider wants the per-ecosystem name.)
variable "default_check_controls" {
  # Help text; a heredoc so it can span several lines (<<- strips the indentation).
  description = <<-EOT
    Controls used by any `checks` entry that doesn't list its own. Names as
    StepSecurity spells them: "NPM Package Cooldown", "PyPI Package Cooldown",
    "Maven Package Cooldown", "NuGet Package Cooldown",
    "NPM|PyPI|Maven|NuGet Package Compromised Updates", "PWN Request", "Script Injection".
    Every control needs control, enable and type (required | optional); the cooldown
    controls also take settings = { cool_down_period, packages_to_exempt_in_cooldown_check }.
  EOT
  type        = any                                                                                               # a plain list; each item is { control, enable, type, settings = {...} } (see the default below)
  default = [                                                                                                     # conservative baseline: cooldowns + PWN request block merging, script injection only warns
    { control = "NPM Package Cooldown", enable = true, type = "required", settings = { cool_down_period = 3 } },  # fail the PR when it adds or bumps an npm package to a version published < 3 days ago (malicious versions are usually pulled within days); enable = true and type = "required" by default
    { control = "PyPI Package Cooldown", enable = true, type = "required", settings = { cool_down_period = 3 } }, # the same 3-day cooldown for Python packages from PyPI
    { control = "PWN Request", enable = true, type = "required" },                                                # fail when a workflow lets untrusted pull-request code run with write permissions (pull_request_target + checkout of the PR head)
    { control = "Script Injection", enable = true, type = "optional" },                                           # warn (advisory check only) when a workflow pastes untrusted input (issue titles, branch names, PR bodies, ...) straight into a run: script
    # { control = "Maven Package Cooldown", enable = true, type = "required", settings = { cool_down_period = 2, packages_to_exempt_in_cooldown_check = ["com.acme:sdk"] } }, # optional: Java/Maven cooldown with an exempt package
    # { control = "NuGet Package Cooldown", enable = true, type = "required" },                                  # optional: .NET/NuGet cooldown (cool_down_period falls back to the provider's 2 days)
    # { control = "NPM Package Compromised Updates", enable = true, type = "required" },                         # optional: fail when an npm update pulls a version StepSecurity flagged as compromised (PyPI/Maven/NuGet variants exist)
    # { control = "Script Injection", enable = false, type = "optional" },                        # optional: keep an entry in the list but switch the control off
  ]
  # Override in terraform.tfvars (replaces the whole list); for one org only, set checks["<org>"].controls instead.
}

# ===== Notification defaults (notifications.tf) ==============================
# StepSecurity raises a *detection* when Harden-Runner or a PR check sees
# something unusual in an org. var.notifications (inputs.tf) says per org who
# is told (email / Slack / Teams); the two variables below are the tenant-wide
# baseline every org starts from.

# Email used by any notifications entry that omits `email`.
# notifications.tf: email = entry.email != null ? entry.email : var.default_notification_email
variable "default_notification_email" {
  description = "Email used by any `notifications` entry that doesn't set one." # help text
  type        = string                                                          # one address; the provider takes a single string, so use a group alias for several recipients
  default     = null                                                            # null = an org that sets no email gets no email delivery (Slack/Teams only, if configured); override: terraform.tfvars `default_notification_email = "security@example.com"` or export TF_VAR_default_notification_email=security@example.com
}

# On/off baseline for the 15 event types StepSecurity can notify about. Each
# notifications entry's `events` map is merged OVER this, so an org lists only
# the events it flips.
# notifications.tf: notification_events = merge(var.default_notification_events, entry.events)
# Keys must be exactly these 15 provider attribute names; an unknown key is
# rejected by the provider at plan time.
variable "default_notification_events" {
  description = "Event → on/off baseline; a notifications entry's `events` map is merged over this." # help text
  type        = any                                                                                  # a plain map of event name => true/false
  # One line per event; the trailing comment says what triggers it.
  default = {                                     # security-relevant events on, per-run noise off
    domain_blocked                        = true  # Harden-Runner dropped an outbound call under a "block" egress policy: a job tried to reach an endpoint outside its allow-list (usually the first sign a build tool needs a new endpoint)
    file_overwrite                        = true  # a job step overwrote a checked-out source file — code or config tampered with mid-build (suppress with type source_code_overwritten)
    new_endpoint_discovered               = false # a job called an endpoint it had never called before (anomalous outbound call); off because every new dependency triggers it — turn on per org once egress is stable (suppress with type anomalous_outbound_network_call)
    https_detections                      = true  # an anomalous HTTPS outbound call was detected, i.e. a TLS destination unusual for this workflow (suppress with type https_outbound_network_call)
    secrets_detected                      = true  # a secret (token, key, password) was printed in the build log (suppress with type secret_in_build_log)
    artifacts_secrets_detected            = true  # a secret was found inside an uploaded build artifact (suppress with type secret_in_artifact)
    imposter_commits_detected             = true  # a workflow uses an action pinned to a commit SHA that does not belong to that action's repository (suppress with type action_uses_imposter_commit)
    suspicious_network_call_detected      = true  # an outbound call to a known-bad or otherwise suspicious endpoint (suppress with type suspicious_network_call)
    suspicious_process_events_detected    = true  # suspicious process behaviour on the runner: privileged container, reverse shell, reading the runner worker's memory — the same three detections egress_policies[*].lockdown can stop the job on
    harden_runner_config_changes_detected = true  # a commit changed a workflow's harden-runner step configuration (e.g. block → audit, extra allowed endpoints)
    non_compliant_artifact_detected       = false # a build artifact was flagged as non-compliant with the org's artifact rules; off — turn on for orgs that publish artifacts
    run_blocked_by_policy                 = true  # a run policy (var.run_policies) blocked a workflow run
    baseline_check_failures               = false # the baseline PR check failed (pre-existing findings in a repo); off — informational
    required_check_failures               = true  # the required PR check failed, so a pull request is blocked from merging
    optional_check_failures               = false # the optional (advisory) PR check failed; off — it never blocks anything
  }
  # Override in terraform.tfvars — replaces the whole map, so list all 15 keys
  # (a missing key leaves that event at the provider's own default):
  #   default_notification_events = { domain_blocked = true, file_overwrite = true, ... }
  # For one org only, flip single events in notifications["<org>"].events = { new_endpoint_discovered = true }.
  # validation { # optional: catch a misspelled event name before the provider does
  #   condition     = length(setsubtract(keys(var.default_notification_events), ["domain_blocked", "file_overwrite", "new_endpoint_discovered", "https_detections", "secrets_detected", "artifacts_secrets_detected", "imposter_commits_detected", "suspicious_network_call_detected", "suspicious_process_events_detected", "harden_runner_config_changes_detected", "non_compliant_artifact_detected", "run_blocked_by_policy", "baseline_check_failures", "required_check_failures", "optional_check_failures"])) == 0
  #   error_message = "default_notification_events contains a key that is not one of the 15 StepSecurity event names."
  # }
}

# ===== Secrets that must not live in terraform.tfvars (notifications.tf) =====
# Slack / Microsoft Teams incoming-webhook URLs are credentials (anyone holding
# one can post into the channel), so they are a separate sensitive variable
# instead of an attribute of var.notifications. notifications.tf looks up each
# org by its `notifications` key:
#   slack_webhook_url = try(var.notification_webhooks[<org>].slack_webhook_url, null)
#   teams_webhook_url = try(var.notification_webhooks[<org>].teams_webhook_url, null)
# An org without an entry gets no webhook delivery; an entry for an org that
# has no `notifications` entry is ignored. Slack via the StepSecurity Slack app
# (OAuth) needs no webhook: set notifications["<org>"].slack_channel_id instead.
variable "notification_webhooks" {
  description = "Per-org Slack/Teams webhook URLs, keyed by org. Supply via git-ignored secrets.auto.tfvars or TF_VAR_notification_webhooks." # help text
  type        = any                                                                                                                           # a plain map: org name => { slack_webhook_url = "...", teams_webhook_url = "..." }, either URL may be left out
  default     = {}                                                                                                                            # no webhooks anywhere; fill it from examples/secrets.auto.tfvars.example (copy to stepsecurity/secrets.auto.tfvars, which .gitignore excludes) or in CI: export TF_VAR_notification_webhooks='{"acme-corp":{"slack_webhook_url":"https://..."}}'
  sensitive   = true                                                                                                                          # plan/apply print "(sensitive value)" instead of the URLs; they are still written to the state file, so protect the state bucket
  # nullable  = false # optional: reject `notification_webhooks = null` so notifications.tf's try() always sees a map (default: true; null is already handled by try())
  # ephemeral = true  # NOT usable here: the URLs feed a regular resource attribute, and ephemeral values may only feed provider config or write-only arguments
}
