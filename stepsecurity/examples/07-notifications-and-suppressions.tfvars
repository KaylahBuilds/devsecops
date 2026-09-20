# =============================================================================
# Example 07 - Alert routing and suppressing known-good detections
# =============================================================================
# Harden-Runner (StepSecurity's agent inside a GitHub Actions job) and the
# StepSecurity PR checks raise a *detection* whenever they see something
# unusual: an outbound call to a host the job never used before, a secret
# printed in the build log, a container started with --privileged, an action
# pinned to a commit that is not in its repo, ... Two settings decide what
# happens to a detection:
#   notifications      per org: who is told (email, Slack, Teams) and for
#                      which of the 15 event types
#   suppression_rules  detections a human has reviewed and accepted; a
#                      matching detection is ignored and never notifies
#
# What it demonstrates (two orgs: "acme-corp" and "acme-labs"):
#   - acme-corp: email + Slack delivery through the StepSecurity Slack app (OAuth,
#     addressed by channel ID), all 15 notification events set explicitly, and
#     Threat Intel alerts narrowed to packages the org actually uses
#   - acme-labs: email only - its events and Threat Intel setting fall back to the
#     tenant-wide defaults, which this file sets live (default_notification_*)
#   - one suppression rule per detection type (all 10 types), each carrying exactly
#     the extra fields that type needs and scoped to one repo / workflow / job
#   - one tenant-wide suppression rule (owner = "*") that applies to every org
#   - where Slack / Teams webhook URLs go instead of this file:
#     examples/secrets.auto.tfvars.example (copy to stepsecurity/secrets.auto.tfvars)
#
# Run (from the repo root):
#   cd stepsecurity && terraform plan -var-file=examples/07-notifications-and-suppressions.tfvars
#
# Credentials never live in a tfvars file - export them first:
#   export STEP_SECURITY_CUSTOMER=<tenant name> STEP_SECURITY_API_KEY=<api key>
#
# Expected plan: 17 resources to add
#   stepsecurity_github_policy_store.this["corp-baseline" | "labs-baseline"]             one audit egress policy per org (detections need Harden-Runner running)
#   stepsecurity_github_policy_store_attachment.this["corp-baseline" | "labs-baseline"]  their org-wide attachments
#   stepsecurity_github_org_notification_settings.this["acme-corp" | "acme-labs"]        channels + events per org
#   stepsecurity_github_supression_rule.this[<11 rule names>]                            ten per-type rules + one tenant-wide rule
# =============================================================================

# ===== Tenant-wide settings (variables.tf) ===================================
# Provider auth - keep these commented out; the provider reads the env vars.
# customer     = "acme"                        # optional: StepSecurity tenant name (default: null -> STEP_SECURITY_CUSTOMER env var)
# api_key      = "<never put a real key here>" # optional: API key (default: null -> STEP_SECURITY_API_KEY env var); sensitive, must never be committed
# api_base_url = "https://api.stepsecurity.io" # optional: override the API base URL (default: null -> provider default)

# default_egress_policy = "audit" # optional: mode for egress policies that omit egress_policy: audit = log only | block = drop unlisted endpoints (default: audit)

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
#   { control = "NPM Package Cooldown", settings = { cool_down_period = 3 } },  #   required: fail when an npm package was published less than 3 days ago
#   { control = "PyPI Package Cooldown", settings = { cool_down_period = 3 } }, #   required: same for PyPI
#   { control = "PWN Request" },                                                #   required: pull_request_target misuse
#   { control = "Script Injection", type = "optional" },                        #   optional (non-blocking): untrusted input interpolated into run: scripts
# ]

# Notification defaults - the two tenant-wide knobs this scenario is about. Both
# orgs below set their own email, so default_notification_email is only the
# safety net for an org added later with a bare `{}` entry.
default_notification_email = "security@example.com" # email for any `notifications` entry that omits `email` (default: null = that org gets no email)

# Tenant baseline of which events notify. Each org's `events` map is merged OVER
# this (org wins per key), so acme-labs below, which sets no events, gets
# exactly this list. Same as the variable default except baseline_check_failures.
default_notification_events = {                 # on/off per event; keys are the 15 event names below and nothing else (default: the same map with baseline_check_failures = false)
  domain_blocked                        = true  # Harden-Runner in block mode dropped an outbound call to a domain not in the allow-list
  file_overwrite                        = true  # a checked-out source file was overwritten during the job
  new_endpoint_discovered               = false # an outbound call to an endpoint not in the job's baseline - noisy while workflows change, keep off
  https_detections                      = true  # anomalous HTTPS outbound call (URL-level, not just the host)
  secrets_detected                      = true  # a secret-shaped string was printed in the build log
  artifacts_secrets_detected            = true  # a secret-shaped string was found inside an uploaded artifact
  imposter_commits_detected             = true  # an action is pinned to a commit that is not in the action's repo
  suspicious_network_call_detected      = true  # a call to an endpoint on StepSecurity's suspicious list (tunnels, paste sites, miners, ...)
  suspicious_process_events_detected    = true  # reverse shell, privileged container or runner-worker memory read
  harden_runner_config_changes_detected = true  # a harden-runner step was edited in a workflow file
  non_compliant_artifact_detected       = false # an uploaded artifact failed the artifact compliance checks
  run_blocked_by_policy                 = true  # a run policy (03-run-policies.tfvars) blocked a workflow run
  baseline_check_failures               = true  # the baseline PR check failed - ON for this tenant (variable default: false)
  required_check_failures               = true  # a required (merge-blocking) PR check failed
  optional_check_failures               = false # an optional (informational) PR check failed
}

# notification_webhooks = { "acme-corp" = { teams_webhook_url = "..." }, "acme-labs" = { slack_webhook_url = "..." } } # SECRET, never here: copy examples/secrets.auto.tfvars.example to stepsecurity/secrets.auto.tfvars (git-ignored via *.auto.tfvars) or set TF_VAR_notification_webhooks in CI (default: {})

# ===== Harden-Runner egress policies (policy_store.tf) =======================
# Suppression rules only matter for detections Harden-Runner actually raises, so
# each org gets one org-wide "audit" policy: every outbound call is logged and
# analysed, nothing is blocked. Key = policy name shown in the dashboard.
egress_policies = {
  # acme-corp: observe every repo.
  "corp-baseline" = {
    owner         = "acme-corp" # GitHub org this policy belongs to (required)
    egress_policy = "audit"     # audit = log egress only | block = drop anything not in allowed_endpoints; omitted -> var.default_egress_policy (audit)
    # name                    = "corp-baseline"            # optional: dashboard policy name (default: the map key)
    # allowed_endpoints       = ["registry.npmjs.org:443"] # optional: host:port list appended to var.base_allowed_endpoints; only enforced in block mode (default: [])
    # include_base_endpoints  = true                       # optional: prepend var.base_allowed_endpoints (GitHub itself, ghcr.io, ...) to allowed_endpoints (default: true)
    # denied_endpoints        = ["evil.example.com"]       # optional: hostnames (no port) to block instead of an allow-list; cannot be combined with allowed_endpoints (default: null)
    # disable_sudo            = true                       # optional: remove sudo inside the job (default: false)
    # disable_file_monitoring = true                       # optional: stop watching for source files overwritten during the job (default: false)
    # disable_telemetry       = true                       # optional: stop sending Harden-Runner telemetry to StepSecurity (default: false)
    # lockdown = {                                         # optional: stop the job when one of these detections fires (default: null = no lockdown)
    #   enabled                   = true                   #   optional: master switch (default: true once the block is present)
    #   privileged_container      = true                   #   optional: stop on a --privileged container (default: true)
    #   reverse_shell             = true                   #   optional: stop on a reverse shell (default: true)
    #   runner_worker_memory_read = true                   #   optional: stop when a process reads the runner worker's memory (default: true)
    # }
  }

  # acme-labs: same for the lab org; egress_policy omitted -> var.default_egress_policy (audit).
  "labs-baseline" = {
    owner = "acme-labs" # GitHub org this policy belongs to (required); every other attribute is optional, see corp-baseline
  }
}

# ===== Where each egress policy applies (policy_store.tf) ====================
# Key must equal an egress_policies key.
egress_policy_attachments = {
  # Every repo and workflow in acme-corp.
  "corp-baseline" = {
    org_wide = true # true = the whole org | false (default) = only the repositories listed
    # repositories = [                                        # optional: instead of org_wide (default: null)
    #   { name = "payments-api" },                            #   whole repo: workflows omitted
    #   { name = "svc-*", workflows = ["ci.yml", "cd.yml"] }, #   a "*" pattern MUST list workflow files (no wildcards in workflow names)
    # ]
    # clusters = ["prod-eks"]                                 # optional: Harden-Runner for Kubernetes clusters instead of GitHub repos - use org_wide/repositories OR clusters, not both (default: null)
  }

  # Every repo and workflow in acme-labs.
  "labs-baseline" = {
    org_wide = true # whole org (see corp-baseline for the repositories / clusters alternatives)
  }
}

# ===== Run policies (run_policies.tf) ========================================
run_policies = {} # what a workflow run may do (allowed / SHA-pinned actions, runner labels, harden-runner presence, secrets, compromised actions) - not used here; see 03-run-policies.tfvars

# ===== PR checks (checks.tf), keyed by org ===================================
checks = {} # StepSecurity PR checks per org (controls + required/optional/baseline repos) - not used here; see 04-multi-org.tfvars and 05-repo-and-workflow-scoped.tfvars

# ===== Notifications (notifications.tf), keyed by org ========================
# One entry per org. notifications.tf fills the provider resource from it:
#   email            -> notification_channels.email (or var.default_notification_email)
#   slack_channel_id -> notification_channels.slack_channel_id + slack_notification_method = "oauth"
#   events           -> merge(var.default_notification_events, events)
#   threat_intel     -> threat_intel block, passed through
#   webhook URLs     -> from var.notification_webhooks[<org>] (secrets.auto.tfvars), never from here
notifications = {
  # acme-corp: email + Slack through the StepSecurity Slack app (install it from
  # the dashboard, then paste the channel ID). Every event is listed so the org's
  # alert set is fully explicit - nothing is inherited from the tenant baseline.
  "acme-corp" = {
    email            = "sec@example.com"            # address that receives alerts; omitted -> var.default_notification_email
    slack_channel_id = "C0123456789"                # Slack channel ID (channel details -> "Copy channel ID"); setting it makes notifications.tf send slack_notification_method = "oauth", so the Slack app posts here and no webhook is needed (default: null = Slack only via a webhook URL, if one is in notification_webhooks)
    events = {                                      # per-event on/off merged over var.default_notification_events; all 15 keys listed, each with its meaning (default: {} = tenant baseline unchanged)
      domain_blocked                        = true  # Harden-Runner in block mode dropped an outbound call (tenant baseline: true)
      file_overwrite                        = true  # a source file was overwritten during the job - see suppression rule 6/10 (tenant baseline: true)
      new_endpoint_discovered               = false # first call to an endpoint outside the job's baseline - too noisy for Slack (tenant baseline: false)
      https_detections                      = true  # anomalous HTTPS outbound call - see rule 5/10 (tenant baseline: true)
      secrets_detected                      = true  # secret in the build log - see rule 1/10 (tenant baseline: true)
      artifacts_secrets_detected            = true  # secret inside an uploaded artifact - see rule 2/10 (tenant baseline: true)
      imposter_commits_detected             = true  # action pinned to a commit that is not in its repo - see rule 7/10 (tenant baseline: true)
      suspicious_network_call_detected      = true  # call to a known-suspicious endpoint - see rule 4/10 (tenant baseline: true)
      suspicious_process_events_detected    = true  # reverse shell / privileged container / runner-worker memory read - see rules 8-10 (tenant baseline: true)
      harden_runner_config_changes_detected = true  # a harden-runner step was edited in a workflow file (tenant baseline: true)
      non_compliant_artifact_detected       = true  # an artifact failed compliance checks - ON here, acme-corp signs its release artifacts (tenant baseline: false)
      run_blocked_by_policy                 = true  # a run policy blocked a workflow run (tenant baseline: true)
      baseline_check_failures               = false # baseline PR check failed - OFF here, acme-corp has no baseline check (tenant baseline: true)
      required_check_failures               = true  # a required (merge-blocking) PR check failed (tenant baseline: true)
      optional_check_failures               = false # an optional (informational) PR check failed (tenant baseline: false)
    }
    threat_intel = {   # Threat Intel = StepSecurity's feed of compromised packages / actions found in this org's PRs and workflows (default when omitted: null = the org's current dashboard setting is kept)
      enabled = true   # false = no Threat Intel alerts for this org at all (default: true once the block is present)
      level   = "name" # all = every incident | name = only when this org uses the compromised package, any version | version = only when it uses the exact compromised version (default: all)
    }
    # Slack / Teams webhook URLs are NOT set here: put notification_webhooks["acme-corp"] in the git-ignored secrets.auto.tfvars (see examples/secrets.auto.tfvars.example)
  }

  # acme-labs: email only. events = var.default_notification_events as set above;
  # threat_intel omitted = the org's existing Threat Intel setting is left as is;
  # Slack/Teams only if notification_webhooks["acme-labs"] exists in secrets.auto.tfvars.
  "acme-labs" = {
    email = "labs-security@example.com" # address that receives alerts; omitted -> var.default_notification_email (security@example.com above)
    # slack_channel_id = "C0987654321"                                     # optional: Slack channel ID; switches Slack delivery to the OAuth app instead of a webhook (default: null)
    # events = { new_endpoint_discovered = true, secrets_detected = false } # optional: per-event overrides merged over var.default_notification_events; keys = the 15 event names above (default: {})
    # threat_intel = {                                                     # optional: Threat Intel alerts for this org; omitted -> current setting kept (default: null)
    #   enabled = false                                                    #   optional: false = opt this org out of Threat Intel alerts (default: true once the block is present)
    #   level   = "version"                                                #   optional: all | name | version, ignored when enabled = false (default: all)
    # }
  }
}

# ===== Policy-driven PRs (policy_driven_prs.tf), keyed by org ================
policy_driven_prs = {} # StepSecurity remediation PRs (pin actions to SHA, add harden-runner, restrict GITHUB_TOKEN, ...) - not used here; see 06-remediation-prs.tfvars

# ===== PR template for those PRs (policy_driven_prs.tf), keyed by org ========
pr_templates = {} # title / summary / commit message / labels / branch name of the remediation PRs - not used here; see 06-remediation-prs.tfvars

# ===== Suppression rules (suppressions.tf), keyed by rule name ===============
# A rule ignores every detection that matches ALL of its fields. Every rule has:
#   owner                  org name, or "*" for every org in the tenant
#   type                   the detection type it silences (10 types, one rule each below)
#   repo / workflow / job  scope; each defaults to "*" (any) - narrow them whenever you can
#   description            free text shown in the dashboard (optional)
#   action                 always "ignore" - set by suppressions.tf, the only action StepSecurity supports
# plus exactly the fields its `type` needs (set nothing else):
#   secret_in_build_log              secret_type
#   secret_in_artifact               secret_type + artifact_name
#   anomalous_outbound_network_call  process + destination { domain } or { ip } (one, not both)
#   suspicious_network_call          endpoint
#   https_outbound_network_call      host + file_path
#   source_code_overwritten          file (+ optional file_path)
#   action_uses_imposter_commit      github_action
#   runner_worker_memory_read        process
#   privileged_container             process
#   reverse_shell                    process
# Key = rule name in the dashboard. A missing required field fails at plan time.
suppression_rules = {

  # ---- secrets ---------------------------------------------------------------
  # 1/10 secret_in_build_log: a secret-shaped string was printed in the job log.
  # Playwright logs the throwaway JWT it mints against the mock identity provider.
  "corp-e2e-mock-jwt-in-log" = {
    owner       = "acme-corp"                                                    # org the rule belongs to (or "*" = every org in the tenant)
    type        = "secret_in_build_log"                                          # detection type this rule silences
    description = "Playwright prints the short-lived JWT minted by the mock IdP" # why it was accepted, shown in the dashboard (default: null)
    repo        = "web-frontend"                                                 # only this repo (default: "*" = any repo)
    workflow    = "e2e.yml"                                                      # only this workflow file (default: "*" = any workflow)
    job         = "playwright"                                                   # only this job name (default: "*" = any job)
    secret_type = "JSON Web Token"                                               # secret type exactly as the detection names it, e.g. "AWS Access Key", "GitHub Token", "JSON Web Token" (required for this type)
  }

  # 2/10 secret_in_artifact: a secret-shaped string was found inside an uploaded artifact.
  # The test-fixtures bundle contains the self-signed TLS key the unit tests use.
  "corp-fixture-tls-key-in-artifact" = {
    owner         = "acme-corp"                                                            # org
    type          = "secret_in_artifact"                                                   # detection type
    description   = "test-fixtures carries the self-signed TLS key used by the unit tests" # why it was accepted
    repo          = "auth-service"                                                         # only this repo
    workflow      = "ci.yml"                                                               # only this workflow
    job           = "unit-tests"                                                           # only this job
    secret_type   = "Private Key"                                                          # secret type as the detection names it (required for this type)
    artifact_name = "test-fixtures"                                                        # artifact name as given to actions/upload-artifact (required for this type)
  }

  # ---- network ---------------------------------------------------------------
  # 3/10 anomalous_outbound_network_call: a process called a host outside the job's baseline.
  # terraform plan talks to AWS from the infra repo.
  "corp-terraform-to-aws" = {
    owner       = "acme-corp"                               # org
    type        = "anomalous_outbound_network_call"         # detection type
    description = "terraform plan reads AWS APIs and state" # why it was accepted
    repo        = "secres-infra"                            # only this repo
    workflow    = "terraform.yml"                           # only this workflow
    job         = "plan"                                    # only this job
    process     = "terraform"                               # process making the call: exact name, or wildcards like "*node", "*.exe", "*" (required for this type)
    destination = { domain = "*.amazonaws.com" }            # where it called: { domain = "..." } OR { ip = "..." }, never both; "*" wildcards allowed (required for this type)
    # destination = { ip = "10.42.*.*" }                     # the IP form of the same field, e.g. for a fixed-address collector
  }

  # 4/10 suspicious_network_call: a call to an endpoint on StepSecurity's suspicious list
  # (tunnels, paste sites, miners, ...). The integration job opens an ngrok tunnel so
  # the vendor sandbox can deliver test webhooks back into the job.
  "corp-webhook-callback-tunnel" = {
    owner       = "acme-corp"                                                               # org
    type        = "suspicious_network_call"                                                 # detection type
    description = "ngrok tunnel lets the vendor sandbox deliver test webhooks into the job" # why it was accepted
    repo        = "webhooks-service"                                                        # only this repo
    workflow    = "integration.yml"                                                         # only this workflow
    job         = "callback-test"                                                           # only this job
    endpoint    = "*.ngrok-free.app:443"                                                    # endpoint as the detection shows it, host:port, "*" wildcards allowed (required for this type)
  }

  # 5/10 https_outbound_network_call: an anomalous HTTPS call (the full request was
  # unexpected, not just the host). The publish job uploads the release bundle to S3.
  "corp-release-bundle-to-s3" = {
    owner       = "acme-corp"                              # org
    type        = "https_outbound_network_call"            # detection type
    description = "aws s3 sync uploads the release bundle" # why it was accepted
    repo        = "web-frontend"                           # only this repo
    workflow    = "release.yml"                            # only this workflow
    job         = "publish"                                # only this job
    host        = "*.s3.amazonaws.com"                     # host as the detection shows it, "*" wildcards allowed (required for this type)
    file_path   = "/usr/local/bin/aws"                     # path of the program that made the call, as the detection shows it; "*" = any caller (required for this type - the provider rejects the rule without it)
  }

  # ---- files and actions -----------------------------------------------------
  # 6/10 source_code_overwritten: a checked-out source file was modified during the job.
  # npm install rewrites the lockfile in the build job (a real supply-chain signal anywhere else).
  "corp-lockfile-rewritten-by-npm" = {
    owner       = "acme-corp"                                             # org
    type        = "source_code_overwritten"                               # detection type
    description = "npm install regenerates the lockfile in the build job" # why it was accepted
    repo        = "web-frontend"                                          # only this repo
    workflow    = "ci.yml"                                                # only this workflow
    job         = "build"                                                 # only this job
    file        = "package-lock.json"                                     # file name as the detection shows it (required for this type)
    file_path   = "web/package-lock.json"                                 # optional: path of that file inside the checkout, so only this copy is ignored (default: null = any path with that name)
  }

  # 7/10 action_uses_imposter_commit: an action is pinned to a SHA that does not exist in the
  # action's own repo (typically a fork). acme-corp pins actions/setup-node to a commit on its
  # security-reviewed fork in EVERY repo, so this rule deliberately stays org-wide.
  "corp-setup-node-vetted-fork" = {
    owner         = "acme-corp"                                                                          # org
    type          = "action_uses_imposter_commit"                                                        # detection type
    description   = "actions/setup-node is pinned to a commit on our reviewed fork acme-corp/setup-node" # why it was accepted
    github_action = "actions/setup-node"                                                                 # action as written after `uses:` (owner/repo, no ref) (required for this type)
    # repo     = "*" # optional: repo name (default: "*" = any) - left at "*" on purpose here
    # workflow = "*" # optional: workflow file name (default: "*" = any)
    # job      = "*" # optional: job name (default: "*" = any)
  }

  # ---- process detections ----------------------------------------------------
  # 8/10 privileged_container: a container was started with --privileged.
  # docker/setup-qemu-action registers binfmt handlers for multi-arch builds, which needs --privileged.
  "corp-binfmt-privileged-container" = {
    owner       = "acme-corp"                                                                   # org
    type        = "privileged_container"                                                        # detection type
    description = "setup-qemu-action runs tonistiigi/binfmt with --privileged for arm64 builds" # why it was accepted
    repo        = "svc-images"                                                                  # only this repo
    workflow    = "release.yml"                                                                 # only this workflow
    job         = "multi-arch-build"                                                            # only this job
    process     = "docker"                                                                      # process that started the container, exact or wildcard (required for this type)
  }

  # 9/10 runner_worker_memory_read: a process read the memory of the GitHub runner worker
  # (where job secrets live). The nightly crash-dump job attaches gdb to the native test harness.
  "labs-crash-dump-gdb" = {
    owner       = "acme-labs"                                                      # org - the lab org this time
    type        = "runner_worker_memory_read"                                      # detection type
    description = "gdb attaches to the native test harness to collect a core dump" # why it was accepted
    repo        = "native-sdk"                                                     # only this repo
    workflow    = "nightly.yml"                                                    # only this workflow
    job         = "crash-dump"                                                     # only this job
    process     = "gdb"                                                            # process doing the read, exact or wildcard (required for this type)
  }

  # 10/10 reverse_shell: a shell whose input/output is wired to a network socket.
  # mxschmitt/action-tmate opens an interactive SSH session on demand for lab debugging.
  "labs-tmate-debug-shell" = {
    owner       = "acme-labs"                                                              # org
    type        = "reverse_shell"                                                          # detection type
    description = "action-tmate opens an on-demand SSH shell for debugging in the lab org" # why it was accepted
    repo        = "sandbox"                                                                # only this repo
    workflow    = "debug.yml"                                                              # only this workflow
    job         = "tmate-session"                                                          # only this job
    process     = "tmate"                                                                  # process that opened the shell, exact or wildcard (required for this type)
  }

  # ---- tenant-wide -----------------------------------------------------------
  # owner = "*" applies one rule to every org in the tenant (acme-corp, acme-labs and
  # any org added later). Coverage upload to Codecov is expected everywhere.
  "all-orgs-codecov-upload" = {
    owner       = "*"                                                   # "*" = every org in the tenant
    type        = "anomalous_outbound_network_call"                     # detection type
    description = "Coverage upload to Codecov is expected in every org" # why it was accepted
    process     = "codecov"                                             # the codecov uploader binary (required for this type)
    destination = { domain = "*.codecov.io" }                           # every Codecov host (required for this type)
    # repo     = "*" # optional: repo name (default: "*" = any) - a tenant-wide rule usually keeps all three scopes at "*"
    # workflow = "*" # optional: workflow file name (default: "*" = any)
    # job      = "*" # optional: job name (default: "*" = any)
  }
}
