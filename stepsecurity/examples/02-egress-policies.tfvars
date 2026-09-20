# =============================================================================
# Example 02 — Harden-Runner egress policies and attachments
# =============================================================================
# Harden-Runner is StepSecurity's agent that runs inside a GitHub Actions job
# (or a Kubernetes runner pod) and watches its outbound network traffic. An
# egress policy tells it which endpoints a job may reach; an attachment says
# which org / repos / workflows / clusters the policy applies to.
#
# This scenario (one org: acme-corp) demonstrates:
#   * an org-wide audit baseline that inherits its mode from default_egress_policy
#   * a block-mode build policy: base endpoints + npm + Docker Hub, lockdown on all
#     four detections, no sudo - attached to a "svc-*" pattern and a named repo
#   * a deny-list policy (denied_endpoints, hostnames only) attached to a whole repo
#   * a policy that opts out of the base list (include_base_endpoints = false),
#     lists every endpoint itself, and turns file monitoring and telemetry off
#   * a policy attached to Harden-Runner for Kubernetes clusters (clusters = [...])
#   * a customised base_allowed_endpoints list + default_egress_policy, so the
#     plan shows how the tenant-wide defaults and each policy are merged
#
# Run it (credentials come from the environment - see README.md):
#   export STEP_SECURITY_CUSTOMER=<tenant> STEP_SECURITY_API_KEY=<key>
#   cd stepsecurity && terraform plan -var-file=examples/02-egress-policies.tfvars
#
# Every module variable is covered here: the maps this scenario uses are set
# live, the others are set to {} so that this file fully overrides the
# auto-loaded terraform.tfvars, and the remaining tenant-wide variables are
# listed as comments with their defaults.
# =============================================================================

# ===== Provider auth - never in a committed file =============================
# customer     = "acme"                  # StepSecurity tenant name; omit it and export STEP_SECURITY_CUSTOMER instead (default: null -> env var)
# api_key      = "<from-the-dashboard>"  # StepSecurity API key; NEVER commit it - export STEP_SECURITY_API_KEY instead (default: null -> env var, sensitive)
# api_base_url = "https://api.example"   # optional: override the StepSecurity API URL for a dedicated deployment (default: null -> provider default)

# ===== Tenant-wide Harden-Runner defaults (both set live in this example) ===
# Mode used by every egress policy below that does NOT set egress_policy
# itself. Policy (a) omits egress_policy, so its plan renders this value.
default_egress_policy = "audit" # audit = log egress only | block = drop anything not in allowed_endpoints (module default: audit)

# Endpoints every GitHub-hosted job needs to run at all. policy_store.tf
# PREPENDS this list to each policy's own allowed_endpoints
# (distinct(concat(base, policy))) unless the policy sets
# include_base_endpoints = false, and removes duplicates. Policies (b) and (e)
# therefore render 10 base entries followed by their own; policy (d) opts out.
# The first 8 entries are the module default (variables.tf); the last 2 are
# this tenant's additions.
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
  "raw.githubusercontent.com:443",                      # ADDED: install scripts fetched straight from raw.githubusercontent.com
]

# ===== Other tenant-wide defaults - not used here, shown with module defaults
# default_check_controls = [                                        # PR-check controls for any `checks` entry without its own list (see the checks example)
#   { control = "NPM Package Cooldown", settings = { cool_down_period = 3 } },  # block npm versions younger than 3 days
#   { control = "PyPI Package Cooldown", settings = { cool_down_period = 3 } }, # same for PyPI
#   { control = "PWN Request" },                                                # required check (type default: required)
#   { control = "Script Injection", type = "optional" },                        # optional = reports but does not block
# ]
# default_notification_email = null                                 # email for any `notifications` entry without its own (default: null = no email)
# default_notification_events = {                                   # event -> on/off baseline; a notifications entry's `events` map is merged over it
#   domain_blocked = true, file_overwrite = true, new_endpoint_discovered = false, https_detections = true,
#   secrets_detected = true, artifacts_secrets_detected = true, imposter_commits_detected = true,
#   suspicious_network_call_detected = true, suspicious_process_events_detected = true,
#   harden_runner_config_changes_detected = true, non_compliant_artifact_detected = false,
#   run_blocked_by_policy = true, baseline_check_failures = false, required_check_failures = true,
#   optional_check_failures = false,
# }
# notification_webhooks = { "acme-corp" = { slack_webhook_url = "..." } } # SENSITIVE: Slack/Teams webhook URLs, keyed by org - keep them in the
#                                                                          # git-ignored secrets.auto.tfvars; see examples/secrets.auto.tfvars.example

# =============================================================================
# egress_policies -> stepsecurity_github_policy_store
# =============================================================================
# Key = policy name shown in the StepSecurity dashboard (override with `name`).
# A policy only takes effect where it is attached (egress_policy_attachments
# below) AND the workflow's harden-runner step runs with `use-policy-store: true`.
# Attribute reference (all optional except owner):
#   egress_policy            audit | block; omitted -> var.default_egress_policy
#   allowed_endpoints        list of host:port ("registry.npmjs.org:443", "*.amazonaws.com:443")
#   include_base_endpoints   prepend var.base_allowed_endpoints (default: true)
#   denied_endpoints         set of hostnames (no port); replaces the allow-list
#   disable_sudo             remove sudo inside the job (default: false)
#   disable_file_monitoring  stop watching for source-file overwrites (default: false)
#   disable_telemetry        stop the agent's telemetry upload (default: false)
#   lockdown                 { enabled, privileged_container, reverse_shell, runner_worker_memory_read } all default true
egress_policies = {

  # (a) Org-wide baseline: observe every workflow in acme-corp, block nothing.
  #     egress_policy is omitted on purpose so the plan shows the fallback to
  #     var.default_egress_policy ("audit"). allowed_endpoints is omitted too,
  #     so the plan renders exactly the 10 base_allowed_endpoints entries.
  "org-baseline" = {
    owner = "acme-corp" # GitHub org (owner) this policy belongs to (required)
    # name                    = "acme-corp-baseline" # optional: dashboard name; default = the map key ("org-baseline")
    # egress_policy           = "audit"              # optional: audit | block; omitted -> var.default_egress_policy ("audit" here)
    # allowed_endpoints       = ["pypi.org:443"]     # optional: extra host:port entries after the base list (default: []); in audit mode calls outside the list are only logged
    # include_base_endpoints  = true                 # optional: prepend var.base_allowed_endpoints (default: true) - see (d) for false
    # denied_endpoints        = ["pastebin.com"]     # optional: hostnames to block instead of an allow-list (default: null) - see (c)
    # disable_sudo            = true                 # optional: remove sudo inside the job (default: false) - see (b)
    # disable_file_monitoring = true                 # optional: stop watching for source-file overwrites (default: false) - see (d)
    # disable_telemetry       = true                 # optional: stop the agent's telemetry upload (default: false) - see (d)
    # lockdown                = { enabled = true }   # optional: stop the job on selected detections (default: null = off) - see (b)
  }

  # (b) Build workflows: block mode. Allowed = the 10 base entries (prepended by
  #     the module) + npm + Docker Hub. Lockdown kills the job on any of the four
  #     runtime detections, and sudo is removed so a compromised step cannot
  #     escalate. Attached below to every svc-* repo's ci.yml / release.yml and
  #     to web-frontend's build.yml.
  "build-block" = {
    owner         = "acme-corp"               # GitHub org (required)
    egress_policy = "block"                   # audit = log only | block = drop calls to anything not allowed; omitted -> var.default_egress_policy
    allowed_endpoints = [                     # host:port entries, merged AFTER var.base_allowed_endpoints (include_base_endpoints defaults to true)
      "registry.npmjs.org:443",               # npm install / npm ci
      "registry-1.docker.io:443",             # Docker Hub manifests (docker pull, Dockerfile FROM)
      "auth.docker.io:443",                   # Docker Hub token exchange
      "production.cloudflare.docker.com:443", # Docker Hub image layers (CDN)
    ]
    disable_sudo = true                # remove sudo inside the job (default: false); omit or set false when a step needs apt-get etc.
    lockdown = {                       # stop the job as soon as an enabled detection fires (default: null = no lockdown; {} = all four on)
      enabled                   = true # master switch (default: true once the block is present)
      privileged_container      = true # stop the job when a step starts a privileged container (default: true)
      reverse_shell             = true # stop the job when a process opens a reverse shell (default: true)
      runner_worker_memory_read = true # stop the job when a process reads the runner worker's memory, i.e. tries to dump secrets (default: true)
    }
    # name                    = "build-block" # optional: dashboard name (default: the map key)
    # include_base_endpoints  = true          # optional: keep prepending var.base_allowed_endpoints (default: true)
    # disable_file_monitoring = true          # optional: stop watching for source-file overwrites during the job (default: false)
    # disable_telemetry       = true          # optional: send no process/network telemetry to StepSecurity (default: false)
  }

  # (c) Deny-list: block a short list of known exfiltration hosts and allow
  #     everything else. denied_endpoints takes HOSTNAMES ONLY (no port) and
  #     cannot be combined with an allow-list, so policy_store.tf sends no
  #     allowed_endpoints for this policy at all (the plan renders
  #     allowed_endpoints = [] because the provider normalises the missing list).
  "docs-denylist" = {
    owner         = "acme-corp" # GitHub org (required)
    egress_policy = "block"     # deny-lists only drop traffic in block mode; in audit mode hits are only logged
    denied_endpoints = [        # set of hostnames to drop (no ports - a port here is ignored by the provider)
      "pastebin.com",           # paste site, classic exfiltration target
      "transfer.sh",            # anonymous file upload service
      "file.io",                # anonymous file upload service
    ]
    # allowed_endpoints      = ["pypi.org:443"] # NOT allowed together with denied_endpoints - the module drops the allow-list when denied_endpoints is set
    # include_base_endpoints = true             # no effect here: no allow-list is sent for a deny-list policy
    # disable_sudo           = true             # optional (default: false); the other switches work exactly as in (a)
  }

  # (d) Self-hosted runners in the acme-corp data centre: they reach GitHub
  #     through an internal proxy, so the GitHub-hosted base list does not fit.
  #     include_base_endpoints = false makes the module send ONLY this list -
  #     you own every entry, including any GitHub host the job still needs.
  "onprem-runners" = {
    owner                  = "acme-corp"        # GitHub org (required)
    egress_policy          = "block"            # audit | block; omitted -> var.default_egress_policy
    include_base_endpoints = false              # do NOT prepend var.base_allowed_endpoints (default: true)
    allowed_endpoints = [                       # the complete allow-list for these jobs - nothing else is added
      "proxy.corp.acme-corp.example:3128",      # outbound HTTP(S) proxy that fronts github.com for the data centre
      "artifactory.corp.acme-corp.example:443", # internal package / artifact mirror
      "vault.corp.acme-corp.example:8200",      # HashiCorp Vault for build-time secrets
    ]
    disable_file_monitoring = true # the build writes generated code back into the checkout on purpose - stop "source file overwritten" noise (default: false)
    disable_telemetry       = true # data-centre policy forbids the agent's usage telemetry (default: false)
    # disable_sudo = true # optional: remove sudo (default: false); left on here because the on-prem image installs packages at job start
    # lockdown     = {}   # optional: {} turns lockdown on with all four detections enabled (see (b) for the long form)
  }

  # (e) Harden-Runner for Kubernetes: same policy shape, but attached to
  #     clusters instead of repos (see egress_policy_attachments["k8s-ci-runners"]).
  #     The base list still applies - runner pods talk to GitHub too.
  "k8s-ci-runners" = {
    owner         = "acme-corp" # GitHub org (required)
    egress_policy = "block"     # audit | block; omitted -> var.default_egress_policy
    allowed_endpoints = [       # merged after var.base_allowed_endpoints
      "*.amazonaws.com:443",    # ECR image pulls, S3 caches and STS in every AWS region
      "registry.k8s.io:443",    # Kubernetes community images (pause, metrics-server, ...)
    ]
    lockdown = {} # empty block = lockdown enabled with all four detections on (each attribute defaults to true)
    # disable_sudo            = true # optional: remove sudo inside the job (default: false)
    # disable_file_monitoring = true # optional: stop watching for source-file overwrites (default: false)
    # disable_telemetry       = true # optional: send no process/network telemetry to StepSecurity (default: false)
  }
}

# =============================================================================
# egress_policy_attachments -> stepsecurity_github_policy_store_attachment
# =============================================================================
# Key MUST equal an egress_policies key (the module looks the policy up by it).
# Exactly one shape per entry:
#   org_wide = true                            every repo and workflow in the org
#   repositories = [{ name }]                  one whole repo (workflows omitted)
#   repositories = [{ name, workflows }]       named workflow files in one repo
#   repositories = [{ "svc-*", workflows }]    a repo-name pattern - MUST list workflows
#   clusters = [...]                           Harden-Runner for Kubernetes; replaces the org/repo attachment
egress_policy_attachments = {

  # (a) whole org
  "org-baseline" = {
    org_wide = true # every repo and workflow in acme-corp (default: false); the module ignores `repositories` when true
    # repositories = [{ name = "docs-site" }] # optional: repo-level scope instead of org_wide (default: null)
    # clusters     = ["ci-prod-eks"]          # optional: attach to clusters instead - the org/repo attachment is then not sent at all
  }

  # (b) a repo-name pattern + workflows, and a named repo + workflows
  "build-block" = {
    repositories = [                                             # list of repo-level attachments (org_wide stays at its default, false)
      { name = "svc-*", workflows = ["ci.yml", "release.yml"] }, # every repo named svc-*, only these workflow files; a pattern MUST list workflows and cannot cover a whole repo
      { name = "web-frontend", workflows = ["build.yml"] },      # one repo, one workflow file (file name under .github/workflows/, no wildcards)
    ]
    # clusters = [...] # optional: use INSTEAD of repositories, never together
  }

  # (c) one whole repo
  "docs-denylist" = {
    repositories = [          # workflows omitted -> the whole repo (the provider sets apply_to_repo = true)
      { name = "docs-site" }, # every workflow in acme-corp/docs-site
    ]
  }

  # (d) a named repo + specific workflows
  "onprem-runners" = {
    repositories = [                                                                  # only the listed workflow files; any other workflow in the repo is untouched
      { name = "mainframe-bridge", workflows = ["nightly-build.yml", "deploy.yml"] }, # the two jobs that run on the data-centre runners
    ]
  }

  # (e) Kubernetes clusters
  "k8s-ci-runners" = {
    clusters = ["ci-prod-eks", "ci-staging-eks"] # cluster names as registered with Harden-Runner for Kubernetes; org_wide/repositories are not sent when this is set
  }
}

# =============================================================================
# Maps this scenario does not use - set to {} so the auto-loaded
# terraform.tfvars is fully overridden when this file is passed via -var-file
# =============================================================================
run_policies      = {} # allowed actions, SHA pinning, runner labels, harden-runner presence - see the run-policies example (03-run-policies.tfvars)
checks            = {} # PR checks per org - see 04-multi-org.tfvars or 05-repo-and-workflow-scoped.tfvars
notifications     = {} # email / Slack / Teams channels + events per org - see 07-notifications-and-suppressions.tfvars (also 04-multi-org.tfvars)
policy_driven_prs = {} # StepSecurity remediation PRs per org - see 06-remediation-prs.tfvars
pr_templates      = {} # title / body / branch template for those PRs - see 06-remediation-prs.tfvars
suppression_rules = {} # reviewed detections to ignore - see 07-notifications-and-suppressions.tfvars
