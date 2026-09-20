# =============================================================================
# Example 04 - Multi-org: three orgs, three postures, one tenant
# =============================================================================
# One StepSecurity tenant usually fronts several GitHub orgs that deserve
# different treatment. This scenario manages three of them from one file:
#
#   acme-prod     block-mode egress, ENFORCED run policies, required PR checks,
#                 remediation PRs opened in every repo
#   acme-staging  block-mode egress, the same run policies in DRY-RUN mode
#                 (violations are reported, nothing is blocked), required PR
#                 checks with its own control list, remediation findings as
#                 issues (not PRs) in repos tagged for the pilot
#   acme-sandbox  audit-mode egress (log only), optional PR checks, no run
#                 policies, no remediation PRs, a quiet notification profile
#
# What it demonstrates:
#   - all five tenant-wide defaults set live with custom values; for each of
#     default_egress_policy, default_check_controls, default_notification_email
#     and default_notification_events one org inherits it and another overrides
#     it; base_allowed_endpoints is inherited by all three orgs (the per-policy
#     opt-out, include_base_endpoints = false, is shown commented out)
#   - every one of the eight input maps with entries for two or three orgs
#   - the "<org>-<thing>" key convention for the maps whose entries carry `owner`
#   - promoting a posture from staging to prod = copying an entry and flipping
#     is_dry_run; a tenant-wide suppression rule (owner = "*") next to per-org ones
#   - every optional attribute of every object type, commented out in place
#     with its meaning, allowed values and default
#
# Run (from the repo root):
#   cd stepsecurity && terraform plan -var-file=examples/04-multi-org.tfvars
#
# Credentials never live in a tfvars file - export them first:
#   export STEP_SECURITY_CUSTOMER=<tenant name> STEP_SECURITY_API_KEY=<api key>
#
# Expected plan: 24 resources to add
#   3 x stepsecurity_github_policy_store               one egress policy per org
#   3 x stepsecurity_github_policy_store_attachment    each attached org-wide
#   4 x stepsecurity_github_run_policy                 2 enforced (prod), 2 dry-run (staging)
#   3 x stepsecurity_github_checks                     required / required / optional
#   3 x stepsecurity_github_org_notification_settings  default email + Slack / own email / own email
#   2 x stepsecurity_policy_driven_pr                  prod (PRs), staging (issues)
#   2 x stepsecurity_github_pr_template                prod, staging
#   4 x stepsecurity_github_supression_rule            one per org + one tenant-wide
#
# KEY CONVENTION. Maps whose entries name their org via `owner` (egress_policies,
# run_policies, suppression_rules) are keyed "<org>-<thing>", e.g.
# "acme-prod-egress". Terraform map keys must be unique across the whole
# tenant, while StepSecurity scopes names per org - two orgs may both want a
# policy called "egress". The prefix keeps keys unique, groups
# `terraform state list` by org, and carries through to
# egress_policy_attachments (whose key must equal the policy key). The name
# shown in the dashboard can still drop the prefix via `name` (see
# "acme-staging-egress"). Maps keyed BY org (checks, notifications,
# policy_driven_prs, pr_templates) use the bare org name as the key. A rule
# that applies to every org uses the "all-orgs-<thing>" prefix.
# =============================================================================

# ===== Provider auth (variables.tf) - never in a committed file ==============
# customer     = "acme"                        # optional: StepSecurity tenant name (default: null -> STEP_SECURITY_CUSTOMER env var)
# api_key      = "<never put a real key here>" # optional: API key (default: null -> STEP_SECURITY_API_KEY env var); sensitive, must never be committed
# api_base_url = "https://api.stepsecurity.io" # optional: override the API base URL for a dedicated deployment (default: null -> provider default)

# ===== Tenant-wide defaults (variables.tf) - ALL five set live here ==========

# (1) Egress mode for every egress policy that omits egress_policy. "block"
#     because two of the three orgs block: acme-prod inherits it, acme-staging
#     repeats it explicitly, acme-sandbox overrides it with "audit".
default_egress_policy = "block" # audit = log egress only | block = drop anything not in allowed_endpoints (module default: audit)

# (2) Endpoints every GitHub-hosted job needs to run at all. policy_store.tf
#     PREPENDS this list to each egress policy's own allowed_endpoints unless
#     the policy sets include_base_endpoints = false. The first 8 entries are
#     the module default; the last 2 are this tenant's additions.
base_allowed_endpoints = [
  "github.com:443",                                     # git clone / push and HTTPS downloads from github.com
  "api.github.com:443",                                 # GitHub REST + GraphQL API (gh CLI, actions/github-script, most actions)
  "codeload.github.com:443",                            # tarball / zip downloads of repositories and actions
  "objects.githubusercontent.com:443",                  # release assets and Git LFS objects
  "*.actions.githubusercontent.com:443",                # runner <-> GitHub Actions control plane (pipelines, vstoken, ...)
  "results-receiver.actions.githubusercontent.com:443", # step results and job log upload
  "ghcr.io:443",                                        # GitHub Container Registry manifests
  "pkg-containers.githubusercontent.com:443",           # GitHub Container Registry image layers
  "*.blob.core.windows.net:443",                        # ADDED: actions/cache and upload-artifact / download-artifact storage
  "release-assets.githubusercontent.com:443",           # ADDED: release asset downloads via `gh release download`
]

# (3) PR-check controls for any `checks` entry that omits `controls`.
#     acme-prod inherits this list; acme-staging and acme-sandbox list their own.
#     Custom set: longer cooldowns, Maven + NuGet added, compromised-update
#     detection on, Script Injection required instead of optional. Names must
#     be spelled exactly as the provider accepts them: "NPM Package Cooldown",
#     "PyPI Package Cooldown", "Maven Package Cooldown", "NuGet Package Cooldown",
#     "NPM Package Compromised Updates", "PyPI Package Compromised Updates",
#     "Maven Package Compromised Updates", "NuGet Package Compromised Updates",
#     "PWN Request", "Script Injection". Per control: enable (default: true),
#     type = required (blocks merge) | optional (informational) (default: required),
#     settings only for the cooldown controls.
default_check_controls = [
  { control = "NPM Package Cooldown", settings = { cool_down_period = 5 } },   # fail when an npm package version was published < 5 days ago (provider default period: 2 days)
  { control = "PyPI Package Cooldown", settings = { cool_down_period = 5 } },  # same for PyPI
  { control = "Maven Package Cooldown", settings = { cool_down_period = 7 } }, # same for Maven Central (Java); not in the module default
  { control = "NuGet Package Cooldown", settings = { cool_down_period = 7 } }, # same for NuGet (.NET); not in the module default
  { control = "NPM Package Compromised Updates" },                             # fail when an npm update pulls a version StepSecurity flagged as compromised
  { control = "PyPI Package Compromised Updates" },                            # same for PyPI ("Maven Package Compromised Updates" / "NuGet Package Compromised Updates" exist too)
  { control = "PWN Request" },                                                 # pull_request_target that checks out untrusted PR code
  { control = "Script Injection", type = "required" },                         # untrusted input interpolated into run: scripts; required here (module default: optional)
  # { control = "Maven Package Compromised Updates", enable = false },                                                    # optional: enable = false keeps the entry but turns the control off (default: true)
  # { control = "NPM Package Cooldown", settings = { cool_down_period = 5, packages_to_exempt_in_cooldown_check = ["lodash"] } }, # optional: exempt named packages from the cooldown (default: none)
]

# (4) Email for any `notifications` entry that omits `email`. acme-prod
#     inherits it; acme-staging and acme-sandbox set their own.
default_notification_email = "secops@example.com" # module default: null = no email

# (5) Baseline on/off per event; each org's `events` map is merged over it.
#     acme-prod turns two more on, acme-staging adjusts three, acme-sandbox
#     turns most off. All 15 event names, as the provider spells them:
default_notification_events = {
  domain_blocked                        = true  # an outbound call to a domain was dropped by a block-mode egress policy
  file_overwrite                        = true  # a source file in the checkout was overwritten during the job
  new_endpoint_discovered               = false # a job called an endpoint it had never called before (noisy in audit mode; module default: false)
  https_detections                      = true  # an anomalous HTTPS outbound call was detected
  secrets_detected                      = true  # a secret showed up in the build log
  artifacts_secrets_detected            = true  # a secret showed up in a build artifact
  imposter_commits_detected             = true  # an action is pinned to a commit that does not belong to its repository
  suspicious_network_call_detected      = true  # a network call to a known-bad destination
  suspicious_process_events_detected    = true  # a suspicious process: reverse shell, privileged container, runner-worker memory read
  harden_runner_config_changes_detected = true  # someone changed a harden-runner step in a workflow file
  non_compliant_artifact_detected       = true  # a build artifact failed compliance checks (module default: false)
  run_blocked_by_policy                 = true  # a run policy blocked a workflow run
  baseline_check_failures               = true  # the baseline PR check failed (module default: false)
  required_check_failures               = true  # a required (merge-blocking) PR check failed
  optional_check_failures               = false # an optional (informational) PR check failed
}

# ===== Secrets (variables.tf) - never here ===================================
# notification_webhooks = {                                                        # SENSITIVE: Slack/Teams webhook URLs keyed by org (default: {})
#   "acme-prod"    = { slack_webhook_url = "<see examples/secrets.auto.tfvars.example>" } # copy that file to stepsecurity/secrets.auto.tfvars (git-ignored) ...
#   "acme-staging" = { teams_webhook_url = "<see examples/secrets.auto.tfvars.example>" } # ... or set TF_VAR_notification_webhooks in CI
# }

# =============================================================================
# egress_policies -> stepsecurity_github_policy_store        key: "<org>-<thing>"
# =============================================================================
# Harden-Runner is the agent StepSecurity runs inside a job to watch its
# outbound traffic; an egress policy says which host:port endpoints the job
# may reach. One policy per org here, attached org-wide below. The three
# entries show the three ways egress_policy relates to the tenant default:
# inherit it (prod), repeat it (staging), override it (sandbox).
egress_policies = {

  # acme-prod: block mode INHERITED from default_egress_policy (egress_policy
  # omitted). Allowed = the 10 base endpoints prepended by the module + the
  # registries prod builds use. Lockdown stops the job on every runtime
  # detection and sudo is removed.
  "acme-prod-egress" = {
    owner = "acme-prod"             # GitHub org this policy belongs to (required)
    allowed_endpoints = [           # extra host:port endpoints appended after var.base_allowed_endpoints; wildcards like "*.amazonaws.com:443" ok (default: [])
      "registry.npmjs.org:443",     # npm ci / npm install
      "pypi.org:443",               # pip index lookups
      "files.pythonhosted.org:443", # pip package downloads
      "sts.amazonaws.com:443",      # AWS STS - OIDC role assumption for deploys
      "*.amazonaws.com:443",        # ECR image pulls and S3 caches in every AWS region
    ]
    disable_sudo = true                # remove sudo inside the job so a compromised step cannot escalate (default: false)
    lockdown = {                       # stop the job as soon as an enabled detection fires (default: null = no lockdown)
      enabled                   = true # master switch (default: true once the block is present)
      privileged_container      = true # stop when a step starts a privileged container (default: true)
      reverse_shell             = true # stop when a process opens a reverse shell (default: true)
      runner_worker_memory_read = true # stop when a process reads the runner worker's memory, i.e. tries to dump secrets (default: true)
    }
    # name                    = "acme-prod-egress" # optional: dashboard policy name (default: the map key)
    # egress_policy           = "block"            # optional: audit | block; omitted ON PURPOSE -> var.default_egress_policy ("block" here)
    # include_base_endpoints  = true               # optional: false leaves var.base_allowed_endpoints out of this policy (default: true)
    # denied_endpoints        = ["pastebin.com"]   # optional: hostnames only, no port; deny-list mode - the allow-list is dropped when this is set (default: null)
    # disable_file_monitoring = true               # optional: stop watching for source-file overwrites (default: false)
    # disable_telemetry       = true               # optional: stop sending harden-runner telemetry to StepSecurity (default: false)
  }

  # acme-staging: same mode, stated explicitly. `name` drops the org prefix, so
  # the dashboard lists this policy as "egress-baseline" under acme-staging
  # while its Terraform key stays unique tenant-wide.
  "acme-staging-egress" = {
    owner         = "acme-staging"    # GitHub org (required)
    name          = "egress-baseline" # dashboard policy name; the org is already implied by owner (default: the map key "acme-staging-egress")
    egress_policy = "block"           # audit = log only | block = drop calls to anything not allowed; set explicitly, same value as the default
    allowed_endpoints = [             # appended after var.base_allowed_endpoints
      "registry.npmjs.org:443",       # npm ci / npm install
      "pypi.org:443",                 # pip index lookups
      "files.pythonhosted.org:443",   # pip package downloads
      "staging-api.acme.example:443", # the staging environment the integration tests call
    ]
    lockdown = {} # empty block = lockdown on with all four detections enabled (each attribute defaults to true)
    # disable_sudo            = true  # optional: remove sudo (default: false); left on because staging images still apt-get at job start
    # disable_file_monitoring = true  # optional: (default: false)
    # disable_telemetry       = true  # optional: (default: false)
    # include_base_endpoints  = false # optional: (default: true)
    # denied_endpoints        = [...] # optional: deny-list instead of allow-list (default: null)
  }

  # acme-sandbox: audit only - OVERRIDES the tenant default. Harden-Runner logs
  # every outbound call and blocks none. allowed_endpoints is omitted, so the
  # plan renders exactly the 10 base_allowed_endpoints entries.
  "acme-sandbox-egress" = {
    owner         = "acme-sandbox" # GitHub org (required)
    egress_policy = "audit"        # overrides var.default_egress_policy ("block") for this org: audit = log egress only, never drop
    # name              = "sandbox-audit"  # optional: dashboard name (default: the map key)
    # allowed_endpoints = ["pypi.org:443"] # optional: in audit mode the list only changes what is reported as a new endpoint (default: [])
    # lockdown          = {}               # optional: stop the job on runtime detections even in audit mode (default: null = off)
    # disable_sudo      = true             # optional: (default: false)
  }
}

# =============================================================================
# egress_policy_attachments -> stepsecurity_github_policy_store_attachment
# =============================================================================
# Key MUST equal an egress_policies key - the org prefix carries through.
# Exactly one shape per entry: org_wide = true | repositories = [...] | clusters = [...].
egress_policy_attachments = {

  # acme-prod: every repo and workflow in the org.
  "acme-prod-egress" = {
    org_wide = true # true = every repo and workflow in acme-prod (default: false); `repositories` is ignored when true
    # repositories = [                                        # optional: instead of org_wide, pick repos / workflows (default: null)
    #   { name = "payments-api" },                            #   whole repo: name only, workflows omitted
    #   { name = "svc-*", workflows = ["ci.yml", "cd.yml"] }, #   a "*" pattern MUST list workflow files; no wildcards inside workflow names
    # ]
    # clusters = ["prod-eks"]                                 # optional: Harden-Runner for Kubernetes cluster names; replaces the org attachment when set (default: null)
  }

  # acme-staging: every repo and workflow in the org.
  "acme-staging-egress" = {
    org_wide = true # every repo and workflow in acme-staging (default: false)
    # repositories = [{ name = "web-app", workflows = ["ci.yml"] }] # optional: repo / workflow scope instead of org_wide (default: null)
    # clusters     = ["staging-eks"]                                # optional: attach to clusters instead (default: null)
  }

  # acme-sandbox: every repo and workflow in the org.
  "acme-sandbox-egress" = {
    org_wide = true # every repo and workflow in acme-sandbox (default: false)
    # repositories = [{ name = "playground" }] # optional: repo scope instead of org_wide (default: null)
    # clusters     = ["sandbox-kind"]          # optional: attach to clusters instead (default: null)
  }
}

# =============================================================================
# run_policies -> stepsecurity_github_run_policy              key: "<org>-<thing>"
# =============================================================================
# A run policy gates what a workflow run may do. `policy` is the provider's
# policy_config block verbatim and must switch on at least one enable_*.
# acme-prod has two ENFORCED policies; acme-staging has the same two in
# DRY-RUN mode (reported, never blocked); acme-sandbox has none.
run_policies = {

  # acme-prod (ENFORCED): supply-chain policy - only SHA-pinned actions, block
  # actions StepSecurity flagged as compromised, block secret exfiltration.
  "acme-prod-supply-chain" = {
    owner = "acme-prod"  # GitHub org (required)
    policy = {           # the provider's policy_config block; at least one enable_* must be true
      is_dry_run = false # false = violations BLOCK the run | true = report only (default: false) - compare acme-staging-supply-chain

      enable_action_policy            = true                # switch on the allowed-actions / pinning policy
      allowed_actions                 = { "*/*" = "allow" } # keys: "owner/repo" | "owner/repo@ref" | "owner/*" | "*/*" (every action) -> "allow" (default: null)
      require_pinned_actions          = true                # every action must be pinned to a full commit SHA; sub-feature of enable_action_policy (default: false)
      actions_to_exempt_while_pinning = ["acme-prod/*"]     # org-owned actions may keep using tags; "*/*" is rejected here because it would exempt everything (default: null)

      enable_compromised_actions_policy = true # block runs that use an action version StepSecurity flagged as compromised (default: false)

      enable_secrets_policy          = true                                 # block runs that read secrets in ways that look like exfiltration (default: false)
      exempted_users                 = ["dependabot[bot]", "renovate[bot]"] # PRs by these users / bots are not subject to the secrets policy (default: null)
      bulk_secrets_only_mode         = false                                # true = only flag bulk reads such as toJSON(secrets) | false = every suspicious reference (default: false)
      secrets_analyze_default_branch = true                                 # also evaluate runs on the default branch (default: false = only non-default branches)

      # pr_comment_template = "Blocked by the acme-prod supply-chain policy. See https://wiki.example.com/stepsecurity" # optional: custom PR comment when this policy blocks a run (default: null = StepSecurity's comment)
      # enable_runs_on_policy / enable_harden_runner_policy and their sub-settings live in "acme-prod-runners" below; several enable_* may also share one policy
    }
    # name         = "acme-prod-supply-chain" # optional: dashboard name (default: the map key)
    # repositories = ["payments-api"]         # optional: scope to these repos (default: null = every repo in the org; the module then sets all_repos = true)
  }

  # acme-prod (ENFORCED): runner policy - every job must run harden-runner with
  # a policy-store policy, only the listed GitHub-hosted labels may be used.
  "acme-prod-runners" = {
    owner = "acme-prod"  # GitHub org (required)
    policy = {           # provider policy_config block
      is_dry_run = false # enforced (default: false)

      enable_harden_runner_policy = true # every targeted job must contain a step-security/harden-runner step (default: false)
      harden_runner_target_labels = []   # [] = every job whatever its runs-on | non-empty set = only jobs on those labels | omitted = leave the backend value untouched
      require_policy_store        = true # the harden-runner step must set use-policy-store: true, so the egress policies above actually apply (default: false)
      block_job_container         = true # block targeted jobs that run entirely inside a job-level container:, which harden-runner cannot monitor (default: false)
      # harden_runner_custom_actions = ["acme-prod/harden-runner-wrapper"] # optional: extra actions accepted as harden-runner equivalents (default: null)

      enable_runs_on_policy = true                              # switch on the runs-on label policy (default: false)
      runs_on_mode          = "allowed"                         # disallowed = block labels in disallowed_runner_labels (default) | allowed = only labels in allowed_runner_labels / allowed_runner_constraints pass
      allowed_runner_labels = ["ubuntu-latest", "ubuntu-24.04"] # required in allowed mode: exact runs-on labels a job may use (default: null)
      # allowed_runner_constraints    = { family = ["m7a", "c7a"], image = ["ubuntu24-full-x64"] } # optional: runs-on.com key=value constraints permitted in allowed mode; lowercase keys (default: null)
      # disallowed_runner_labels      = ["self-hosted"]                                            # optional: only read in disallowed mode - see acme-staging-runners (default: null)
      # enable_standard_runner_labels = true                                                       # optional: add GitHub's standard labels to disallowed_runner_labels and harden_runner_target_labels at evaluation time (default: false)
    }
    # name         = "acme-prod-runners" # optional: dashboard name (default: the map key)
    # repositories = ["payments-api"]    # optional: scope to these repos (default: null = every repo)
  }

  # acme-staging (DRY RUN): the same supply-chain policy as prod with
  # is_dry_run = true. Violations show up in the dashboard and as PR comments,
  # nothing is blocked. Promote to prod = copy the entry, flip is_dry_run.
  "acme-staging-supply-chain" = {
    owner = "acme-staging"       # GitHub org (required)
    name  = "supply-chain-trial" # dashboard name without the org prefix (default: the map key)
    policy = {                   # provider policy_config block
      is_dry_run = true          # report only - the one line that differs from acme-prod-supply-chain (default: false)

      enable_action_policy            = true                # allowed-actions / pinning policy on
      allowed_actions                 = { "*/*" = "allow" } # every action allowed ...
      require_pinned_actions          = true                # ... as long as it is pinned to a full commit SHA
      actions_to_exempt_while_pinning = ["acme-staging/*"]  # org-owned actions may use tags

      enable_compromised_actions_policy = true # report runs that use a compromised action version

      enable_secrets_policy          = true                                 # report secret-exfiltration patterns
      exempted_users                 = ["dependabot[bot]", "renovate[bot]"] # bot PRs exempt
      secrets_analyze_default_branch = true                                 # include default-branch runs
      # bulk_secrets_only_mode = false # optional: (default: false)
    }
    # repositories = ["web-app"] # optional: scope to these repos (default: null = every repo in the org)
  }

  # acme-staging (DRY RUN, scoped to two repos): runner policy in the default
  # "disallowed" mode, harden-runner required only on ubuntu-latest jobs.
  "acme-staging-runners" = {
    owner        = "acme-staging"             # GitHub org (required)
    repositories = ["web-app", "api-gateway"] # only these repos (default: null = every repo); the module sets all_repos = true only when this is null
    policy = {                                # provider policy_config block
      is_dry_run = true                       # report only (default: false)

      enable_harden_runner_policy = true              # harden-runner step required ...
      harden_runner_target_labels = ["ubuntu-latest"] # ... only in jobs whose runs-on matches this label ([] would mean every job)
      require_policy_store        = false             # not yet: staging workflows are still being migrated to use-policy-store (default: false)
      # block_job_container          = true      # optional: block fully containerised jobs (default: false)
      # harden_runner_custom_actions = ["..."]   # optional: extra harden-runner equivalents (default: null)

      enable_runs_on_policy    = true                            # runs-on label policy on
      runs_on_mode             = "disallowed"                    # default mode: block jobs whose runs-on matches disallowed_runner_labels (allowed mode is shown in acme-prod-runners)
      disallowed_runner_labels = ["self-hosted", "macos-latest"] # labels that may not be used; ignored in allowed mode (default: null)
      # enable_standard_runner_labels = true # optional: also disallow every GitHub-hosted standard label, i.e. force self-hosted runners (default: false)
      # allowed_runner_labels         = [...] # optional: only read in allowed mode (default: null)
    }
  }
}

# =============================================================================
# checks -> stepsecurity_github_checks                              key: org
# =============================================================================
# StepSecurity PR checks run on pull requests and flag supply-chain risks.
# `required` checks block the merge, `optional` ones only report, `baseline`
# reports the repo's overall posture. Controls default to
# var.default_check_controls (acme-prod); staging and sandbox list their own.
checks = {

  # acme-prod: required (merge-blocking) checks on every repo except the
  # archive, plus the baseline check. controls omitted -> the custom
  # default_check_controls above (8 controls, all required).
  "acme-prod" = {
    custom_description = "Required by the acme-prod security policy. Questions: #prod-security on Slack." # text appended to every check summary (default: null)
    required_checks    = { repos = ["*"], omit_repos = ["prod-archive"] }                                 # merge-blocking check on every repo ("*") except the listed ones; omit_repos is only valid with repos = ["*"]
    baseline_check     = { repos = ["*"] }                                                                # posture baseline on every repo (default: null); omit_repos allowed as above
    # controls        = [...]              # optional: omitted ON PURPOSE -> var.default_check_controls; see acme-staging for the shape
    # optional_checks = { repos = ["*"] }  # optional: non-blocking check on these repos (default: null)
  }

  # acme-staging: required checks too, but with its OWN control list - shorter
  # cooldowns so fresher packages can be tested, the in-house UI kit exempt,
  # Script Injection informational only.
  "acme-staging" = {
    controls = [                                                                                                                          # overrides var.default_check_controls for this org
      { control = "NPM Package Cooldown", settings = { cool_down_period = 2, packages_to_exempt_in_cooldown_check = ["@acme/ui-kit"] } }, # 2-day cooldown; the in-house package is released to staging the same day
      { control = "PyPI Package Cooldown", settings = { cool_down_period = 2 } },                                                         # 2-day cooldown for PyPI
      { control = "NPM Package Compromised Updates" },                                                                                    # enable defaults to true, type to "required"
      { control = "PyPI Package Compromised Updates" },                                                                                   # same for PyPI
      { control = "PWN Request" },                                                                                                        # pull_request_target misuse
      { control = "Script Injection", type = "optional" },                                                                                # type = required (blocks merge) | optional (informational)
    ]
    required_checks = { repos = ["*"] } # merge-blocking check on every repo
    # custom_description = "..."                       # optional: (default: null)
    # optional_checks    = { repos = ["*"] }           # optional: (default: null)
    # baseline_check     = { repos = ["*"], omit_repos = ["scratch"] } # optional: (default: null)
  }

  # acme-sandbox: informational only. The controls all carry type = "optional"
  # so they run inside the optional check; nothing here can block a merge.
  "acme-sandbox" = {
    custom_description = "Informational only - nothing in acme-sandbox blocks a merge."              # appended to every check summary
    controls = [                                                                                     # overrides var.default_check_controls; every control is optional here
      { control = "NPM Package Cooldown", type = "optional", settings = { cool_down_period = 1 } },  # 1-day cooldown, report only
      { control = "PyPI Package Cooldown", type = "optional", settings = { cool_down_period = 1 } }, # same for PyPI
      { control = "PWN Request", type = "optional" },                                                # report only
      { control = "Script Injection", type = "optional" },                                           # report only
      { control = "Maven Package Cooldown", enable = false, type = "optional" },                     # enable = false keeps the entry but turns the control off (default: true)
    ]
    optional_checks = { repos = ["*"] } # non-blocking check on every repo
    # required_checks = { repos = ["*"] } # optional: none in the sandbox (default: null)
    # baseline_check  = { repos = ["*"] } # optional: (default: null)
  }
}

# =============================================================================
# notifications -> stepsecurity_github_org_notification_settings    key: org
# =============================================================================
# Where each org's alerts go and which events fire. email falls back to
# var.default_notification_email, events are merged over
# var.default_notification_events. Slack / Teams WEBHOOK URLs are never set
# here - they come from var.notification_webhooks[<org>] in the git-ignored
# secrets.auto.tfvars; only the Slack OAuth channel ID is a plain value.
notifications = {

  # acme-prod: email INHERITED (secops@example.com), Slack via the OAuth app,
  # two extra events switched on, Threat Intel only for exact compromised
  # versions this org actually uses.
  "acme-prod" = {
    slack_channel_id = "C04PRODSEC01" # Slack channel ID; setting it switches Slack delivery to the OAuth app instead of a webhook (default: null)
    events = {                        # per-event overrides merged over var.default_notification_events; keys = the 15 event names above (default: {})
      new_endpoint_discovered = true  # prod is in block mode, so a new endpoint means a dropped call worth a look (tenant default: false)
      optional_check_failures = true  # prod wants to hear about informational findings too (tenant default: false)
    }
    threat_intel = {      # Threat Intel (compromised component) alerts for this org (default: null = keep the org's current setting)
      enabled = true      # receive Threat Intel notifications at all (default: true once the block is present)
      level   = "version" # all = every incident | name = only packages this org uses, any version | version = only the exact compromised version in use (default: all)
    }
    # email = "prod-security@example.com" # optional: omitted ON PURPOSE -> var.default_notification_email
    # Slack / Teams webhook URLs: notification_webhooks["acme-prod"] in secrets.auto.tfvars (see examples/secrets.auto.tfvars.example)
  }

  # acme-staging: its OWN email, a small events subset, Threat Intel by
  # package name.
  "acme-staging" = {
    email = "staging-alerts@example.com" # overrides var.default_notification_email for this org
    events = {                           # merged over var.default_notification_events
      run_blocked_by_policy   = false    # every staging run policy is a dry run, so this never fires anyway (tenant default: true)
      baseline_check_failures = false    # baseline noise is not wanted in staging (tenant default: true)
      optional_check_failures = true     # but optional findings are - Script Injection is optional here (tenant default: false)
    }
    threat_intel = {   # Threat Intel alerts
      enabled = true   # on
      level   = "name" # only when a compromised package this org uses is involved, at any version
    }
    # slack_channel_id = "C04STAGING01" # optional: Slack OAuth channel (default: null)
  }

  # acme-sandbox: its OWN email and a quiet profile - most events off,
  # Threat Intel off entirely.
  "acme-sandbox" = {
    email = "sandbox-owners@example.com"            # overrides var.default_notification_email
    events = {                                      # merged over var.default_notification_events
      domain_blocked                        = false # audit mode never blocks (tenant default: true)
      run_blocked_by_policy                 = false # no run policies in the sandbox (tenant default: true)
      required_check_failures               = false # no required checks in the sandbox (tenant default: true)
      baseline_check_failures               = false # no baseline check either (tenant default: true)
      non_compliant_artifact_detected       = false # sandbox artifacts are throwaway (tenant default: true)
      harden_runner_config_changes_detected = false # people edit workflows here all day (tenant default: true)
    }
    threat_intel = {  # Threat Intel alerts
      enabled = false # off for this org; level is ignored when enabled = false
      # level = "all" # optional: ignored while enabled = false (default: all)
    }
    # slack_channel_id = "C04SANDBOX01" # optional: Slack OAuth channel (default: null)
  }
}

# =============================================================================
# policy_driven_prs -> stepsecurity_policy_driven_pr                key: org
# =============================================================================
# StepSecurity opens remediation PRs - or issues, never both - in the selected
# repos: pin actions to SHAs, add harden-runner, restrict GITHUB_TOKEN
# permissions, ... `auto_remediation_options` is the provider block verbatim.
# The PR text comes from pr_templates[<org>] below. acme-sandbox gets none.
policy_driven_prs = {

  # acme-prod: every repo except the archive, PRs only, full remediation set,
  # Dependabot config for actions and npm.
  "acme-prod" = {
    selected_repos = ["*"]                                       # repos to remediate; ["*"] = every repo in the org (default: ["*"])
    excluded_repos = ["prod-archive"]                            # skipped when selected_repos = ["*"]; their existing config is restored (default: null)
    auto_remediation_options = {                                 # the provider's auto_remediation_options block (required)
      create_pr                             = true               # open a pull request per finding (default: true); create_pr and create_issue cannot both be true
      create_issue                          = false              # open an issue INSTEAD of a PR (default: false) - see acme-staging
      create_github_advanced_security_alert = false              # also raise a GHAS alert; only fires when create_issue = true (default: false)
      harden_github_hosted_runner           = true               # add the harden-runner step to every job on GitHub-hosted runners (default: true)
      pin_actions_to_sha                    = true               # replace tag references with full commit SHAs (default: true)
      restrict_github_token_permissions     = true               # add a least-privilege permissions: block to workflows (default: true)
      secure_docker_file                    = true               # pin Dockerfile base images to their digest (default: false)
      actions_to_exempt_while_pinning       = ["acme-prod/*"]    # these actions keep their tag references (default: null)
      harden_runner_config = {                                   # how the harden-runner step is written (default: null = StepSecurity's default step)
        target_runner_labels = ["ubuntu-latest", "ubuntu-24.04"] # only jobs on these labels get the step (default: null = every GitHub-hosted job)
        exempt_runner_labels = ["gpu-*"]                         # glob patterns of labels to skip regardless of target_runner_labels (default: null)
        # config                        = "egress-policy: block" # optional: YAML for the step's `with:` block (default: null = StepSecurity's default config)
        # update_existing_configuration = true                   # optional: rewrite harden-runner steps that already exist (default: null)
      }
      package_ecosystem = [                                  # Dependabot ecosystems StepSecurity keeps configured (default: null = leave dependabot.yml alone)
        { package = "github-actions", interval = "weekly" }, # package = npm | pip | docker | github-actions | ...; interval = daily | weekly | monthly
        { package = "npm", interval = "weekly" },            # a second ecosystem; docker and pip work the same way
        # { package = "pip", interval = "daily", cooldown_yaml = "default-days: 3", groups_yaml = "dev-deps:\n  dependency-type: development" }, # optional per entry: Dependabot cooldown / groups config as YAML strings (default: null)
      ]
      # replace_action_on_major_tag_match             = true             # optional: only replace listed actions when the major tag matches; needs actions_to_replace_with_step_security_actions (default: null)
      # update_existing_configuration                 = true             # optional: Dependabot removes entries that are not in package_ecosystem (default: null)
      # images_to_exempt_while_pinning                = ["ubuntu:24.04"] # optional: Docker images that keep their tag when secure_docker_file = true (default: null)
      # actions_to_replace_with_step_security_actions = ["actions/checkout"] # optional: swap these for StepSecurity-maintained forks (default: null)
      # actions_exempted_from_replacement             = ["actions/cache"]    # optional: replace EVERY maintained action except these; mutually exclusive with the line above (default: null)
    }
    # selected_repos_filter = { include_repos_only_with_topics = ["tier-1"] } # optional: with selected_repos = ["*"], only repos carrying these GitHub topics (default: null)
  }

  # acme-staging: only repos tagged for the pilot (GitHub topic). Findings
  # arrive as ISSUES + GHAS alerts instead of PRs (create_pr and create_issue
  # are mutually exclusive - the provider rejects both = true); token-permission
  # and Dockerfile fixes still off.
  "acme-staging" = {
    selected_repos = ["*"]                                    # every repo ...
    selected_repos_filter = {                                 # ... narrowed by topic (default: null = no filter)
      include_repos_only_with_topics = ["stepsecurity-pilot"] # only repos that carry this GitHub topic take part
    }
    auto_remediation_options = {                    # provider block (required)
      create_pr                             = false # no PRs during the pilot; exactly one of create_pr / create_issue may be true (default: true)
      create_issue                          = true  # open an issue per finding instead (default: false)
      create_github_advanced_security_alert = true  # and a GHAS alert - only fires when create_issue = true (default: false)
      harden_github_hosted_runner           = true  # add harden-runner (default: true)
      pin_actions_to_sha                    = true  # pin actions (default: true)
      restrict_github_token_permissions     = false # not yet in staging - some workflows still need broad tokens (default: true)
      secure_docker_file                    = false # Dockerfile pinning off (default: false)
      # actions_to_exempt_while_pinning = ["acme-staging/*"]                     # optional: (default: null)
      # harden_runner_config            = { target_runner_labels = ["ubuntu-latest"] } # optional: (default: null)
      # package_ecosystem               = [{ package = "pip", interval = "daily" }]   # optional: (default: null)
    }
    # excluded_repos = ["scratch"] # optional: skipped repos when selected_repos = ["*"] (default: null)
  }
}

# =============================================================================
# pr_templates -> stepsecurity_github_pr_template                   key: org
# =============================================================================
# Title, body, commit message, labels and branch name of the remediation PRs
# above. {{STEPSECURITY_SECURITY_FIXES}} in the summary is replaced with the
# list of fixes in that PR. One template per org that has policy_driven_prs.
pr_templates = {

  # acme-prod: labelled, custom branch name, heredoc body.
  "acme-prod" = {
    title          = "[StepSecurity] Apply the acme-prod security baseline" # PR title (required)
    commit_message = "chore(security): apply StepSecurity remediation"      # commit message of the remediation commit (required)
    labels         = ["security", "stepsecurity", "prod"]                   # GitHub labels added to each PR (default: null)
    branch_name    = "chore/stepsecurity-{time}"                            # branch name; MUST contain {time}, replaced with a DDHHMM stamp so every PR gets a unique branch (default: null = StepSecurity's default)
    # PR body (required); a heredoc keeps the Markdown readable
    summary = <<-EOT
      ## Summary
      Automated hardening from StepSecurity, opened by the acme-prod remediation policy.
      Review the diff, run the CI, merge when green.

      ## Security fixes
      {{STEPSECURITY_SECURITY_FIXES}}

      ## Questions
      #prod-security on Slack.
    EOT
  }

  # acme-staging: minimal template - one-line summary, heredoc commit
  # message, default labels and branch name.
  "acme-staging" = {
    title   = "[StepSecurity][staging pilot] Security remediation"                         # PR title (required)
    summary = "Pilot remediation PR from StepSecurity.\n\n{{STEPSECURITY_SECURITY_FIXES}}" # PR body (required); a plain string with \n works too
    # commit message (required) as a heredoc
    commit_message = <<-EOT
      chore(security): StepSecurity pilot remediation

      Opened automatically in repos tagged stepsecurity-pilot.
    EOT
    # labels      = ["security"]                 # optional: GitHub labels (default: null = none)
    # branch_name = "stepsecurity/pilot-{time}"  # optional: must contain {time} (default: null = StepSecurity's default branch name)
  }
}

# =============================================================================
# suppression_rules -> stepsecurity_github_supression_rule   key: "<org>-<thing>"
# =============================================================================
# Silence detections you have reviewed and accepted. action is always
# "ignore" (set by suppressions.tf). repo / workflow / job default to "*" (any).
# Fields required per type: anomalous_outbound_network_call -> process +
# destination { domain | ip }; https_outbound_network_call -> host + file_path;
# suspicious_network_call -> endpoint; secret_in_build_log -> secret_type;
# secret_in_artifact -> secret_type + artifact_name; source_code_overwritten ->
# file (+ file_path); action_uses_imposter_commit -> github_action;
# runner_worker_memory_read | privileged_container | reverse_shell -> process.
suppression_rules = {

  # Tenant-wide: owner = "*" applies the rule to every org in the tenant.
  # Coverage upload to Codecov is expected everywhere.
  "all-orgs-codecov-upload" = {
    owner       = "*"                                                   # "*" = every org in the tenant (or one org name)
    type        = "anomalous_outbound_network_call"                     # detection type this rule silences
    description = "Coverage upload to Codecov is expected in every org" # free text shown in the dashboard (default: null)
    process     = "*"                                                   # process name that makes the call; "*" = any; wildcards like "*node" ok (required for this type)
    destination = { domain = "*.codecov.io" }                           # destination to ignore: { domain = "..." } OR { ip = "..." }, never both (required for this type)
    # repo     = "*" # optional: repo name (default: "*" = any)
    # workflow = "*" # optional: workflow file name (default: "*" = any)
    # job      = "*" # optional: job name (default: "*" = any)
  }

  # acme-prod: the Datadog CI agent ships test metrics from one job of one
  # repo - scoped as tightly as possible.
  "acme-prod-datadog-ci" = {
    owner       = "acme-prod"                                                      # org the rule belongs to
    type        = "anomalous_outbound_network_call"                                # detection type
    description = "datadog-ci uploads test metrics from the payments-api test job" # why it is ignored
    repo        = "payments-api"                                                   # only this repo (default: "*")
    workflow    = "ci.yml"                                                         # only this workflow file (default: "*")
    job         = "test"                                                           # only this job (default: "*")
    process     = "datadog-ci"                                                     # exact process name (required for this type)
    destination = { domain = "*.datadoghq.com" }                                   # domain to ignore; alternatively { ip = "10.20.*.*" } (required for this type)
  }

  # acme-staging: the integration workflow calls the staging API over HTTPS;
  # that is the point of the workflow. This type needs host AND file_path.
  "acme-staging-integration-api" = {
    owner       = "acme-staging"                                      # org the rule belongs to
    type        = "https_outbound_network_call"                       # detection type: anomalous HTTPS call (the https_detections event)
    description = "Integration tests call the staging API on purpose" # why it is ignored
    workflow    = "integration.yml"                                   # only this workflow file (default: "*")
    host        = "staging-api.acme.example"                          # HTTPS host to ignore (required for this type)
    file_path   = "/api/v1/*"                                         # request path to ignore, as shown in the detection (required for this type)
    # repo = "web-app" # optional: only this repo (default: "*")
    # job  = "e2e"     # optional: only this job (default: "*")
  }

  # acme-sandbox: npm install rewrites the lock file in the checkout; that is
  # expected in the sandbox, not an attack.
  "acme-sandbox-lockfile-rewrite" = {
    owner       = "acme-sandbox"                                            # org the rule belongs to
    type        = "source_code_overwritten"                                 # detection type: a file in the checkout was modified (the file_overwrite event)
    description = "npm install rewrites package-lock.json in sandbox repos" # why it is ignored
    file        = "package-lock.json"                                       # file name to ignore (required for this type)
    file_path   = "web/"                                                    # directory the file lives in, narrows the rule (default: null = any path)
    # repo     = "playground" # optional: (default: "*")
    # workflow = "try.yml"    # optional: (default: "*")
    # job      = "build"      # optional: (default: "*")
  }

  # Other types, for reference (one commented entry each):
  # "acme-prod-known-test-key" = { owner = "acme-prod", type = "secret_in_build_log", secret_type = "AWS Access Key", repo = "payments-api", description = "Fixture key printed by the test suite" }
  # "acme-prod-sbom-token"     = { owner = "acme-prod", type = "secret_in_artifact", secret_type = "Generic API Key", artifact_name = "sbom.json" }
  # "acme-staging-canary"      = { owner = "acme-staging", type = "suspicious_network_call", endpoint = "canary.acme.example:443" }
  # "acme-prod-forked-action"  = { owner = "acme-prod", type = "action_uses_imposter_commit", github_action = "acme-prod/forked-setup-node" }
  # "acme-sandbox-dind"        = { owner = "acme-sandbox", type = "privileged_container", process = "dockerd" }
  # "acme-sandbox-debug-shell" = { owner = "acme-sandbox", type = "reverse_shell", process = "*tmate*" }
  # "acme-prod-profiler"       = { owner = "acme-prod", type = "runner_worker_memory_read", process = "perf" }
}
