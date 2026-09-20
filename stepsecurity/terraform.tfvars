# =============================================================================
# terraform.tfvars — the reference configuration for this StepSecurity tenant
# =============================================================================
# This is the file you edit day to day. `terraform plan` loads it automatically
# (a file named terraform.tfvars needs no -var-file). It fills the eight input
# maps declared in inputs.tf — one map per StepSecurity resource type — and
# overrides two of the tenant-wide defaults declared in variables.tf. Every map
# entry names its GitHub org via `owner`, or the map is keyed by org. Two orgs
# are configured:
#
#   acme-platform  production: block-mode egress on the deploy and Node
#                  pipelines, run policies that require Harden-Runner and
#                  SHA-pinned actions, merge-blocking PR checks, Slack alerts,
#                  automated remediation PRs and one suppression rule
#   acme-labs      experiments: audit-only egress, a dry-run pinning policy,
#                  advisory PR checks and email alerts — nothing can fail a build
#
# Every attribute an entry can carry is shown: live when this tenant uses it,
# otherwise commented out with its meaning, allowed values and default. To use
# one, copy the line, drop the leading "# " and change the value.
#
# Run (from stepsecurity/; credentials come from the environment, never from
# a tfvars file):
#   export STEP_SECURITY_CUSTOMER=<tenant> STEP_SECURITY_API_KEY=<key>
#   terraform init -backend-config="key=stepsecurity/terraform.tfstate"
#   terraform plan                        # expect "Plan: 20 to add" on a fresh tenant
#   terraform apply
#
# Expected plan: 20 resources, addressed as <type>.this["<map key>"]
#   4 stepsecurity_github_policy_store               ← egress_policies
#   4 stepsecurity_github_policy_store_attachment    ← egress_policy_attachments
#   5 stepsecurity_github_run_policy                 ← run_policies
#   2 stepsecurity_github_checks                     ← checks
#   2 stepsecurity_github_org_notification_settings  ← notifications
#   1 stepsecurity_policy_driven_pr                  ← policy_driven_prs
#   1 stepsecurity_github_pr_template                ← pr_templates
#   1 stepsecurity_github_supression_rule            ← suppression_rules
#
# Secrets (API key, Slack/Teams webhook URLs) are NOT here — see README.md and
# examples/secrets.auto.tfvars.example. Add an org by adding entries; remove an
# org by deleting them. No .tf file changes either way.
# =============================================================================

# ===== Tenant-wide settings (variables.tf) ===================================
# Provider auth — keep these commented out; the provider reads the STEP_SECURITY_* environment variables.
# customer     = "acme"                                # optional: StepSecurity tenant (customer) name as shown in the dashboard (default: null → STEP_SECURITY_CUSTOMER env var)
# api_key      = "<never put a real key here>"         # optional, SENSITIVE: API key from dashboard → Settings → API keys (default: null → STEP_SECURITY_API_KEY env var); never commit it
# api_base_url = "https://<host StepSecurity gave you>" # optional: override the API base URL for a dedicated or regional deployment (default: null → provider default)

default_egress_policy      = "audit"                # egress mode for every egress_policies entry that omits egress_policy: audit = log outbound calls only | block = drop calls not in allowed_endpoints (module default: audit); "labs-audit" below inherits it
default_notification_email = "security@example.com" # inbox for every notifications entry that omits email (module default: null = no email delivery); "acme-platform" below inherits it, "acme-labs" overrides it

# base_allowed_endpoints = [                              # optional: host:port endpoints every GitHub-hosted job needs; policy_store.tf prepends them to each policy's allowed_endpoints unless include_base_endpoints = false (default below; an override REPLACES the whole list, so repeat the entries you keep)
#   "github.com:443",                                     #   git clone / fetch / push, release page downloads
#   "api.github.com:443",                                 #   GitHub REST/GraphQL API (actions/checkout ref lookups, setup-* actions, GITHUB_TOKEN calls)
#   "codeload.github.com:443",                            #   tarball / zip downloads of repos and actions
#   "objects.githubusercontent.com:443",                  #   release assets and Git LFS objects
#   "*.actions.githubusercontent.com:443",                #   GitHub Actions control plane (pipelines, tool cache, artifact and cache front doors)
#   "results-receiver.actions.githubusercontent.com:443", #   step logs and job results upload
#   "ghcr.io:443",                                        #   GitHub Container Registry manifests
#   "pkg-containers.githubusercontent.com:443",           #   GitHub Container Registry image layers
# ]

# default_check_controls = [                                                   # optional: PR-check controls for any `checks` entry without its own `controls` list (default below; an override replaces the whole list)
#   { enable = true, type = "required", control = "NPM Package Cooldown", settings = { cool_down_period = 3 } },  #   required: fail when the PR adds or bumps an npm package to a version published < 3 days ago (enable = true, type = "required" by default)
#   { enable = true, type = "required", control = "PyPI Package Cooldown", settings = { cool_down_period = 3 } }, #   required: the same 3-day cooldown for PyPI packages
#   { enable = true, type = "required", control = "PWN Request" },                                                #   required: a workflow lets untrusted PR code run with write permissions (pull_request_target + checkout of the PR head)
#   { enable = true, control = "Script Injection", type = "optional" },                        #   optional (advisory): untrusted input (issue titles, branch names, ...) pasted into a run: script
# ]

# default_notification_events = {                # optional: on/off baseline for the 15 event types; a notifications entry's `events` map is merged over it (default below; an override replaces the whole map)
#   domain_blocked                        = true  #   Harden-Runner dropped an outbound call under a block-mode egress policy
#   file_overwrite                        = true  #   a source file was overwritten during a job
#   new_endpoint_discovered               = false #   anomalous outbound call to an endpoint not seen before (noisy while egress is still changing)
#   https_detections                      = true  #   anomalous HTTPS outbound call
#   secrets_detected                      = true  #   a secret was printed in the build log
#   artifacts_secrets_detected            = true  #   a secret was found inside an uploaded artifact
#   imposter_commits_detected             = true  #   an action is pinned to a commit that is not in its repo
#   suspicious_network_call_detected      = true  #   call to a known-suspicious endpoint (tunnels, paste sites, miners, ...)
#   suspicious_process_events_detected    = true  #   privileged container, reverse shell, runner-worker memory read
#   harden_runner_config_changes_detected = true  #   a harden-runner step's configuration changed in a workflow
#   non_compliant_artifact_detected       = false #   a build artifact failed the org's artifact rules
#   run_blocked_by_policy                 = true  #   a run policy blocked a workflow run
#   baseline_check_failures               = false #   the baseline PR check failed
#   required_check_failures               = true  #   the required PR check failed (merge blocked)
#   optional_check_failures               = false #   the advisory PR check failed
# }

# notification_webhooks = { "acme-platform" = { slack_webhook_url = "...", teams_webhook_url = "..." } } # SECRET, never here: copy examples/secrets.auto.tfvars.example to stepsecurity/secrets.auto.tfvars (git-ignored) or export TF_VAR_notification_webhooks (default: {} = no webhook delivery)

# ===== Harden-Runner egress policies (policy_store.tf) =======================
# Harden-Runner is the StepSecurity agent that runs as the first step of a job
# and watches its outbound traffic. An egress policy is the list of endpoints a
# job may reach (block mode) or a request to just log them (audit mode). It
# applies to every job whose harden-runner step sets `use-policy-store: true`
# and that is covered by the egress_policy_attachments entry with the SAME key.
# Key = policy name in the dashboard; each entry names its org via `owner`.
# Resource: stepsecurity_github_policy_store.this["<key>"].
egress_policies = {
  # acme-platform: org-wide audit baseline until the egress reports are clean,
  # then flip egress_policy to "block". The plan renders the 8 base endpoints only.
  "platform-baseline" = {
    owner         = "acme-platform" # GitHub org that owns the policy (required)
    egress_policy = "audit"         # audit = log egress only | block = drop anything not in allowed_endpoints; omitted → var.default_egress_policy ("audit")
    # name                    = "platform-baseline"        # optional: policy name shown in the dashboard (default: the map key)
    # allowed_endpoints       = ["registry.npmjs.org:443"] # optional: extra host:port endpoints appended after var.base_allowed_endpoints; "*" wildcards in the host part ok ("*.amazonaws.com:443"); only enforced in block mode (default: [])
    # include_base_endpoints  = false                      # optional: false = send only this entry's allowed_endpoints, without var.base_allowed_endpoints (default: true)
    # denied_endpoints        = ["evil.example.com"]       # optional: deny-list of hostnames WITHOUT port; when set the allow-list is dropped entirely because the provider refuses both (default: null = allow-list mode)
    # disable_sudo            = true                       # optional: remove sudo inside the job (default: false)
    # disable_file_monitoring = true                       # optional: stop watching for source-file overwrites (default: false)
    # disable_telemetry       = true                       # optional: send no process/network telemetry to StepSecurity (default: false)
    # lockdown = {                                         # optional: stop the job when a selected runtime detection fires (default: null = no lockdown, detections only alert)
    #   enabled                   = true                   #   optional: master switch; false keeps the sub-settings but never stops a job (default: true once the block is present)
    #   privileged_container      = true                   #   optional: stop on a Privileged-Container detection — a container started with --privileged (default: true)
    #   reverse_shell             = true                   #   optional: stop on a Reverse-Shell detection — a shell bound to a remote socket (default: true)
    #   runner_worker_memory_read = true                   #   optional: stop on a Runner-Worker-Memory-Read detection — a process reading secrets from the runner's memory (default: true)
    # }
  }

  # acme-platform: deploy pipelines — block mode, AWS + Terraform endpoints on
  # top of the base list, lockdown on every runtime detection. The plan renders
  # 12 allowed_endpoints: the 8 base entries followed by the 4 below.
  "platform-terraform-deploy" = {
    owner         = "acme-platform" # GitHub org that owns the policy (required)
    egress_policy = "block"         # block = drop any outbound call not in allowed_endpoints | audit = log only (default: var.default_egress_policy)
    allowed_endpoints = [           # host:port endpoints this pipeline needs, appended after var.base_allowed_endpoints (default: [] = base endpoints only)
      "sts.amazonaws.com:443",      # aws-actions/configure-aws-credentials: OIDC token exchange (AssumeRoleWithWebIdentity)
      "*.amazonaws.com:443",        # every other AWS API plus the S3 state bucket and DynamoDB lock table; "*" wildcard in the host part
      "registry.terraform.io:443",  # provider index used by terraform init
      "releases.hashicorp.com:443", # provider binaries and the terraform CLI (hashicorp/setup-terraform)
    ]
    lockdown = { enabled = true } # stop the job when a runtime detection fires; the three detection switches default to true, so this is "lockdown on everything"
    # lockdown = {                       # the same block written out — set a switch to false to keep that detection alert-only
    #   enabled                   = true #   master switch (default: true once the block is present)
    #   privileged_container      = true #   stop on a Privileged-Container detection (default: true)
    #   reverse_shell             = true #   stop on a Reverse-Shell detection (default: true)
    #   runner_worker_memory_read = true #   stop on a Runner-Worker-Memory-Read detection (default: true)
    # }
    # name                    = "platform-terraform-deploy" # optional: dashboard name (default: the map key)
    # include_base_endpoints  = false                       # optional: false = leave the 8 base endpoints out and list everything yourself (default: true)
    # denied_endpoints        = ["evil.example.com"]        # optional: hostnames only, no port; switches to deny-list mode and drops the allow-list (default: null)
    # disable_sudo            = true                        # optional: remove sudo inside the job (default: false)
    # disable_file_monitoring = true                        # optional: stop watching for source-file overwrites (default: false)
    # disable_telemetry       = true                        # optional: send no telemetry to StepSecurity (default: false)
  }

  # acme-platform: Node services — block mode, npm registry on top of the base
  # list, no sudo. Attached below to ci.yml in every svc-* repo and to web-frontend.
  "platform-node-build" = {
    owner             = "acme-platform"            # GitHub org that owns the policy (required)
    egress_policy     = "block"                    # block = drop anything not in allowed_endpoints | audit = log only (default: var.default_egress_policy)
    allowed_endpoints = ["registry.npmjs.org:443"] # npm installs; appended after the 8 base endpoints (default: [])
    disable_sudo      = true                       # remove sudo inside the job so a compromised dependency cannot escalate (default: false)
    # name                    = "platform-node-build"  # optional: dashboard name (default: the map key)
    # include_base_endpoints  = false                  # optional: false = send only this entry's allowed_endpoints (default: true)
    # denied_endpoints        = ["*.pastebin.com"]     # optional: hostnames only, no port; deny-list mode, the allow-list is dropped (default: null)
    # disable_file_monitoring = true                   # optional: stop watching for source-file overwrites (default: false)
    # disable_telemetry       = true                   # optional: send no telemetry to StepSecurity (default: false)
    # lockdown = { enabled = true, reverse_shell = true, privileged_container = false, runner_worker_memory_read = true } # optional: stop the job on the selected detections (default: null = alert only; each switch defaults to true)
  }

  # acme-labs: observe only — no egress_policy, so var.default_egress_policy
  # ("audit") applies and the plan renders only the 8 base endpoints.
  "labs-audit" = {
    owner = "acme-labs" # GitHub org that owns the policy (required); every other attribute is left at its default
    # name                    = "labs-audit"               # optional: dashboard name (default: the map key)
    # egress_policy           = "block"                    # optional: audit | block (default: var.default_egress_policy = "audit")
    # allowed_endpoints       = ["pypi.org:443"]           # optional: host:port endpoints appended after var.base_allowed_endpoints (default: [])
    # include_base_endpoints  = false                      # optional: false = leave the base endpoints out (default: true)
    # denied_endpoints        = ["evil.example.com"]       # optional: hostnames only; deny-list mode, the allow-list is dropped (default: null)
    # disable_sudo            = true                       # optional: remove sudo inside the job (default: false)
    # disable_file_monitoring = true                       # optional: stop watching for source-file overwrites (default: false)
    # disable_telemetry       = true                       # optional: send no telemetry to StepSecurity (default: false)
    # lockdown = {                                         # optional: stop the job on a runtime detection (default: null = alert only)
    #   enabled                   = true                   #   optional: master switch (default: true once the block is present)
    #   privileged_container      = true                   #   optional: stop on Privileged-Container (default: true)
    #   reverse_shell             = true                   #   optional: stop on Reverse-Shell (default: true)
    #   runner_worker_memory_read = true                   #   optional: stop on Runner-Worker-Memory-Read (default: true)
    # }
  }
}

# ===== Where each egress policy applies (policy_store.tf) ====================
# Key MUST equal an egress_policies key: the attachment reads owner and policy
# name from that policy. Pick exactly one scope per entry:
#   org_wide = true        every repo and workflow in the org
#   repositories = [...]   named repos or "*" patterns, optionally per workflow file
#   clusters = [...]       Harden-Runner for Kubernetes cluster names (the org block is then not sent)
# Resource: stepsecurity_github_policy_store_attachment.this["<key>"].
egress_policy_attachments = {
  # Every repo and workflow in acme-platform. The two other scopes, for reference:
  #   "platform-baseline" = { repositories = [{ name = "web-frontend" }] } # named repos / patterns instead of org_wide (default: null)
  #   "platform-baseline" = { clusters = ["ci-prod-eks"] }                 # Harden-Runner for Kubernetes cluster names; org_wide/repositories are then not sent (default: null)
  "platform-baseline" = { org_wide = true } # true = apply_to_org: every repo and workflow in the org; repositories is ignored (default: false)

  # Only the two deploy workflows of the infra repo.
  "platform-terraform-deploy" = {
    repositories = [                                                                # repo-level scope; org_wide stays at its default, false (default: null)
      { name = "secres-infra", workflows = ["terraform.yml", "stepsecurity.yml"] }, # one repo, two workflow FILE names under .github/workflows/ (no wildcards in workflow names); the plan shows apply_to_repo = false
      # { name = "secres-infra" },                                                  # optional: omit workflows → the whole repo (apply_to_repo = true)
    ]
    # org_wide = true            # optional: the whole org instead; repositories is then ignored (default: false)
    # clusters = ["ci-prod-eks"] # optional: cluster-level attachment instead of the org block; never together with org_wide/repositories (default: null)
  }

  # ci.yml in every svc-* repo, plus the whole web-frontend repo.
  "platform-node-build" = {
    repositories = [                              # repo-level scope (default: null)
      { name = "svc-*", workflows = ["ci.yml"] }, # a "*" pattern MUST list workflows and may not contain consecutive stars ("*" alone = every repo); the plan shows apply_to_repo = false
      { name = "web-frontend" },                  # whole repo: name only, workflows omitted; the plan shows apply_to_repo = true
    ]
    # org_wide = true            # optional: the whole org instead (default: false)
    # clusters = ["ci-prod-eks"] # optional: cluster-level attachment instead (default: null)
  }

  # Every repo and workflow in acme-labs.
  "labs-audit" = { org_wide = true } # true = apply_to_org (default: false); alternatives: repositories = [{ name = "...", workflows = [...] }] or clusters = ["..."]
}

# ===== Run policies (run_policies.tf) ========================================
# A run policy gates a workflow run BEFORE it runs: which actions it may use
# and how they are pinned, which runner labels it may target, whether the
# Harden-Runner step is present, whether it may touch secrets, and whether it
# uses a known-compromised action. `policy` is the provider's policy_config
# block verbatim (run_policies.tf merges in owner and name), so examples from
# the provider docs paste straight in; at least one enable_* must be true.
# Key = policy name in the dashboard. Resource: stepsecurity_github_run_policy.this["<key>"].
run_policies = {
  # Every job in acme-platform must run step-security/harden-runner with
  # `use-policy-store: true`, so the egress policies above apply. This first
  # entry lists the COMPLETE policy_config menu; the entries below repeat only
  # what is relevant to them.
  "platform-require-harden-runner" = {
    owner = "acme-platform" # GitHub org the policy belongs to (required)
    # name         = "Require Harden-Runner"          # optional: name shown in the dashboard (default: the map key)
    # repositories = ["payments-api", "web-frontend"] # optional: limit the policy to these repos (default: null = every repo in the org; the plan then shows all_repos = true)
    policy = {                           # the provider's policy_config block (required); every attribute inside is optional, but one enable_* must be true
      enable_harden_runner_policy = true # require the Harden-Runner step in every targeted job (default: false)
      harden_runner_target_labels = []   # [] = every job | ["ubuntu-latest"] = only jobs whose runs-on matches one of the labels | omitted = leave the current backend value untouched
      require_policy_store        = true # the step must set `use-policy-store: true`; the legacy `policy:` input does not count (default: false)
      # is_dry_run = true # optional: evaluate and report violations but never block a run (default: false = enforce)
      # -- rest of the harden-runner policy
      # harden_runner_custom_actions  = ["acme-platform/harden-wrapper"] # optional: extra actions accepted as Harden-Runner equivalents (default: null = only step-security/harden-runner)
      # block_job_container           = true                             # optional: block targeted jobs that run entirely inside a job-level `container:` — Harden-Runner cannot monitor them; step containers are fine (default: false)
      # enable_standard_runner_labels = true                             # optional: add GitHub's hosted labels (ubuntu-latest, windows-latest, macos-*, arm variants) to harden_runner_target_labels and disallowed_runner_labels at evaluation time (default: false)
      # -- action policy (live in "platform-pin-actions")
      # enable_action_policy            = true                # optional: turn on the allowed-actions policy (default: false)
      # allowed_actions                 = { "*/*" = "allow" } # optional: action pattern → "allow"; keys: "actions/checkout@v4" (exact ref) | "actions/checkout" (any ref) | "my-org/*" (one owner) | "*/*" (every action) (default: null)
      # require_pinned_actions          = true                # optional: every action must be pinned to a full-length commit SHA; needs enable_action_policy = true (default: false)
      # actions_to_exempt_while_pinning = ["acme-platform/*"] # optional: actions that may stay on a tag/branch: "my-org/*" | "actions/checkout" | "actions/checkout@v4"; "*/*" is rejected by the API (default: null)
      # -- runs-on policy (live in "platform-no-self-hosted")
      # enable_runs_on_policy      = true                                # optional: turn on the runner-label policy (default: false)
      # runs_on_mode               = "disallowed"                        # optional: disallowed = block jobs whose runs-on is in disallowed_runner_labels (default; the plan shows "") | allowed = permit ONLY allowed_runner_labels / allowed_runner_constraints
      # disallowed_runner_labels   = ["self-hosted"]                     # optional: labels blocked in disallowed mode (default: null)
      # allowed_runner_labels      = ["ubuntu-latest"]                   # optional: plain labels permitted in allowed mode, matched verbatim; required when runs_on_mode = "allowed" (default: null)
      # allowed_runner_constraints = { family = ["m7a"], cpu = ["4", "8"] } # optional: runs-on.com key=value constraints permitted in allowed mode; lowercase keys, at least one value each (default: null)
      # -- secrets policy (live in "platform-secrets-and-compromised-actions")
      # enable_secrets_policy          = true                                 # optional: stop workflow runs from exfiltrating secrets (default: false)
      # exempted_users                 = ["dependabot[bot]", "renovate[bot]"] # optional: users/bots the secrets policy never blocks (default: null)
      # bulk_secrets_only_mode         = true                                 # optional: only block high-risk BULK exposure such as toJSON(secrets), not every secret reference (default: false)
      # secrets_analyze_default_branch = true                                 # optional: also evaluate runs on the repo's default branch; by default only other branches are (default: false)
      # -- compromised-actions policy (live in "platform-secrets-and-compromised-actions")
      # enable_compromised_actions_policy = true # optional: block runs that use an action version StepSecurity flagged as compromised (default: false)
      # -- PR comment
      # pr_comment_template = "Blocked by StepSecurity — ask #security on Slack." # optional: custom Markdown for the PR comment posted when this policy blocks a run; supports placeholder substitution, heredocs work (default: null = StepSecurity's standard comment)
    }
  }

  # Only SHA-pinned actions may run: any action is allowed ("*/*") as long as
  # it is pinned to a commit SHA, and acme-platform's own actions may stay on a tag.
  "platform-pin-actions" = {
    owner = "acme-platform" # GitHub org the policy belongs to (required)
    # name         = "Pin actions to SHA" # optional: dashboard name (default: the map key)
    # repositories = ["payments-api"]     # optional: limit to these repos (default: null = every repo in the org)
    policy = {                                              # provider policy_config block (required)
      enable_action_policy            = true                # turn on the allowed-actions policy (default: false); the three lines below only matter when this is true
      require_pinned_actions          = true                # every `uses:` must reference a full 40-character commit SHA; tags and branches are blocked (default: false)
      allowed_actions                 = { "*/*" = "allow" } # action pattern → "allow": "*/*" = every action | "my-org/*" = one owner | "actions/checkout" = any ref | "actions/checkout@v4" = one ref; an action matching no key blocks the run (default: null)
      actions_to_exempt_while_pinning = ["acme-platform/*"] # actions that may stay unpinned: "my-org/*" | "actions/checkout" | "actions/checkout@v4"; "*/*" is rejected by the API (default: null)
      # is_dry_run          = true                             # optional: report violations without blocking (default: false)
      # pr_comment_template = "Pin your actions to a commit SHA." # optional: custom PR comment when a run is blocked (default: null = StepSecurity's standard comment)
      # other sub-policies (runs-on, harden-runner, secrets, compromised actions): see the complete menu in "platform-require-harden-runner" above
    }
  }

  # No self-hosted runners on the money paths — scoped to two repos, dry-run
  # first so violations are reported but nothing is blocked yet.
  "platform-no-self-hosted" = {
    owner        = "acme-platform"                    # GitHub org the policy belongs to (required)
    repositories = ["payments-api", "billing-worker"] # only these repos (default: null = every repo in the org); the plan shows all_repos = false
    # name = "No self-hosted runners" # optional: dashboard name (default: the map key)
    policy = {                                   # provider policy_config block (required)
      enable_runs_on_policy    = true            # turn on the runner-label (runs-on) policy (default: false)
      disallowed_runner_labels = ["self-hosted"] # jobs whose runs-on contains one of these labels are blocked — the "disallowed" mode (default: null)
      is_dry_run               = true            # evaluate and report violations, never block (default: false); drop it once the reports are clean
      # runs_on_mode                  = "disallowed"                          # optional: disallowed = block the listed labels (default; the plan shows "") | allowed = permit only allowed_runner_labels / allowed_runner_constraints
      # allowed_runner_labels         = ["ubuntu-latest", "acme-8core"]       # optional: labels permitted in allowed mode, matched verbatim; required when runs_on_mode = "allowed" (default: null)
      # allowed_runner_constraints    = { family = ["m7a"], cpu = ["4", "8"] } # optional: runs-on.com key=value constraints permitted in allowed mode; lowercase keys, at least one value each (default: null)
      # enable_standard_runner_labels = true                                  # optional: also add GitHub's hosted labels (ubuntu-latest, windows-latest, macos-*, ...) to disallowed_runner_labels — forces the org's own runners (default: false)
      # pr_comment_template           = "Use a GitHub-hosted runner."         # optional: custom PR comment when a run is blocked (default: null)
      # other sub-policies (action, harden-runner, secrets, compromised actions): see the complete menu in "platform-require-harden-runner" above
    }
  }

  # Two policies in one entry: block runs that would exfiltrate secrets (the
  # dependency bots are exempt) and block runs that use a known-compromised action version.
  "platform-secrets-and-compromised-actions" = {
    owner = "acme-platform" # GitHub org the policy belongs to (required)
    # name         = "Secrets + compromised actions" # optional: dashboard name (default: the map key)
    # repositories = ["payments-api"]                # optional: limit to these repos (default: null = every repo in the org)
    policy = {                                                                 # provider policy_config block (required)
      enable_secrets_policy             = true                                 # stop workflow runs from exfiltrating secrets (default: false)
      exempted_users                    = ["dependabot[bot]", "renovate[bot]"] # users/bots whose runs the secrets policy never blocks (default: null = nobody)
      enable_compromised_actions_policy = true                                 # block runs that use an action version StepSecurity's threat intel flagged as compromised; it has no further settings (default: false)
      # bulk_secrets_only_mode         = true                                  # optional: only block high-risk BULK exposure such as toJSON(secrets), not every secret reference (default: false)
      # secrets_analyze_default_branch = true                                  # optional: also evaluate runs on the repo's default branch; by default only other branches are (default: false)
      # is_dry_run                     = true                                  # optional: report violations without blocking (default: false)
      # pr_comment_template            = "Blocked: this run would expose secrets." # optional: custom PR comment when a run is blocked (default: null)
      # other sub-policies (action, runs-on, harden-runner): see the complete menu in "platform-require-harden-runner" above
    }
  }

  # acme-labs: the same pinning rule as acme-platform, but dry-run — violations
  # show up in the dashboard and PR comments, nothing is blocked.
  "labs-pin-actions-dry-run" = {
    owner = "acme-labs" # GitHub org the policy belongs to (required)
    # name         = "Pin actions (dry run)" # optional: dashboard name (default: the map key)
    # repositories = ["ml-sandbox"]          # optional: limit to these repos (default: null = every repo in the org)
    policy = {                                     # provider policy_config block (required)
      enable_action_policy   = true                # turn on the allowed-actions policy (default: false)
      require_pinned_actions = true                # every action must be pinned to a full-length commit SHA (default: false)
      allowed_actions        = { "*/*" = "allow" } # every action is allowed, so only pinning is enforced; narrower keys: "my-org/*" | "actions/checkout" | "actions/checkout@v4" (default: null)
      is_dry_run             = true                # report only, never block (default: false)
      # actions_to_exempt_while_pinning = ["acme-labs/*"]                   # optional: actions that may stay on a tag/branch; "*/*" is rejected by the API (default: null)
      # pr_comment_template             = "Pin your actions to a commit SHA." # optional: custom PR comment when a run is blocked (default: null)
      # other sub-policies (runs-on, harden-runner, secrets, compromised actions): see the complete menu in "platform-require-harden-runner" above
    }
  }
}

# ===== PR checks (checks.tf), keyed by org ===================================
# StepSecurity posts status checks on pull requests: package cooldown (a new
# package version must age N days before the PR may pull it in), compromised
# updates, PWN Request (pull_request_target misuse) and Script Injection.
# `controls` says which run and whether each blocks merging; required_checks /
# optional_checks / baseline_check say in which repos each kind runs.
# Resource: stepsecurity_github_checks.this["<org>"].
checks = {
  # acme-platform: merge-blocking checks on every repo, the baseline check
  # everywhere except sandbox, tenant-default controls.
  "acme-platform" = {
    custom_description = "Checks by StepSecurity. Contact: #security on Slack." # free text appended to every check summary — tell developers where to ask (default: null)
    # controls omitted → var.default_check_controls (NPM + PyPI cooldown 3 days, PWN Request required, Script Injection optional). To override for this org only:
    # controls = [                                                                                                                       # optional: which controls run and in which check (default: null → var.default_check_controls)
    #   { enable = true, type = "required", control = "NPM Package Cooldown", settings = { cool_down_period = 5, packages_to_exempt_in_cooldown_check = ["@acme/sdk"] } }, #   cooldown controls take settings: days a new version must age (provider default: 2) and packages never held back
    #   { enable = true, type = "required", control = "PyPI Package Cooldown", settings = { cool_down_period = 5 } },                                                      #   enable defaults to true, type to "required"
    #   { enable = true, type = "required", control = "Maven Package Cooldown" },                                                                                          #   other names: "NuGet Package Cooldown", "NPM Package Compromised Updates" (also PyPI / Maven / NuGet), "PWN Request", "Script Injection"
    #   { control = "Script Injection", enable = true, type = "optional" },                                                              #   type = required (blocks merging) | optional (advisory); enable = false keeps the entry but switches it off
    # ]
    required_checks = { repos = ["*"] }                           # where the merge-blocking (type = "required") controls run; ["*"] = every repo in the org (repos is required inside)
    baseline_check  = { repos = ["*"], omit_repos = ["sandbox"] } # where the baseline check runs: everywhere except sandbox; omit_repos is only valid with repos = ["*"] (default: null)
    # required_checks = { repos = ["*"], omit_repos = ["sandbox"] } # optional: the same omit_repos escape hatch works for required checks
    # optional_checks = { repos = ["*"] }                           # optional: where the advisory (type = "optional") controls run (default: null = nowhere)
  }

  # acme-labs: advisory checks only — nothing in the lab blocks a merge.
  "acme-labs" = {
    optional_checks = { repos = ["*"] } # where the advisory (type = "optional") controls run; ["*"] = every repo (repos is required inside; omit_repos = [...] is allowed with "*")
    # custom_description = "Lab checks are advisory. Contact: #labs on Slack." # optional: text appended to every check summary (default: null)
    # controls           = [{ enable = true, control = "Script Injection", type = "optional" }] # optional: this org's own control list (default: null → var.default_check_controls)
    # required_checks    = { repos = ["*"], omit_repos = ["scratch"] }         # optional: where the merge-blocking controls run (default: null = nowhere)
    # baseline_check     = { repos = ["*"] }                                   # optional: where the baseline check runs (default: null = nowhere)
  }
}

# ===== Notifications (notifications.tf), keyed by org ========================
# Where an org's alerts go and which events raise one. Webhook URLs are secrets
# and come ONLY from var.notification_webhooks[<org>] (git-ignored
# secrets.auto.tfvars); slack_channel_id switches Slack to the StepSecurity
# Slack app (OAuth) instead. With no webhook the plan renders
# slack_webhook_url / teams_webhook_url as " ". Resource: stepsecurity_github_org_notification_settings.this["<org>"].
notifications = {
  # acme-platform: Slack via the StepSecurity app + the tenant default email;
  # new-endpoint alerts switched on; Threat Intel only for exact compromised versions.
  "acme-platform" = {
    slack_channel_id = "C0123456789"                         # Slack channel ID (not the name) for OAuth delivery through the StepSecurity Slack app; the plan renders slack_notification_method = "oauth" (default: null = webhook delivery, if var.notification_webhooks has a URL)
    events           = { new_endpoint_discovered = true }    # per-event overrides merged OVER var.default_notification_events; here anomalous new-endpoint calls alert too (default: {} = baseline only)
    threat_intel     = { enabled = true, level = "version" } # Threat Intel alerts about compromised packages/actions in this org's PRs and workflows: enabled = receive them at all (default: true) | level = all (every incident) | name (only packages this org uses, any version) | version (only the exact compromised version) (default: all); omit the block to keep the org's current setting
    # email = "platform-security@example.com" # optional: alert inbox (default: null → var.default_notification_email = "security@example.com", which is what the plan renders)
    # events = {                                    # the 15 event names accepted, each with the var.default_notification_events baseline it starts from
    #   domain_blocked                        = true  #   Harden-Runner dropped an outbound call under a block-mode egress policy
    #   file_overwrite                        = true  #   a source file was overwritten during a job
    #   new_endpoint_discovered               = false #   anomalous outbound call to an endpoint not seen before (this org turns it on above)
    #   https_detections                      = true  #   anomalous HTTPS outbound call
    #   secrets_detected                      = true  #   a secret was printed in the build log
    #   artifacts_secrets_detected            = true  #   a secret was found inside an uploaded artifact
    #   imposter_commits_detected             = true  #   an action is pinned to a commit that is not in its repo
    #   suspicious_network_call_detected      = true  #   call to a known-suspicious endpoint (tunnels, paste sites, miners, ...)
    #   suspicious_process_events_detected    = true  #   privileged container, reverse shell, runner-worker memory read
    #   harden_runner_config_changes_detected = true  #   a harden-runner step's configuration changed in a workflow
    #   non_compliant_artifact_detected       = false #   a build artifact failed the org's artifact rules
    #   run_blocked_by_policy                 = true  #   a run policy blocked a workflow run
    #   baseline_check_failures               = false #   the baseline PR check failed
    #   required_check_failures               = true  #   the required PR check failed (merge blocked)
    #   optional_check_failures               = false #   the advisory PR check failed
    # }
  }

  # acme-labs: email only; the events fired are var.default_notification_events unchanged.
  "acme-labs" = {
    email = "labs-security@example.com" # alert inbox for this org, overriding var.default_notification_email (default: null → the tenant default)
    # slack_channel_id = "C0123456789"                      # optional: Slack channel ID → OAuth delivery through the StepSecurity Slack app (default: null)
    # events           = { new_endpoint_discovered = true } # optional: per-event overrides merged over the baseline; keys = the 15 event names listed above (default: {})
    # threat_intel     = { enabled = false }                # optional: switch Threat Intel alerts off for this org; level = all | name | version when enabled (default: null = keep the org's current setting)
  }
}

# ===== Policy-driven remediation PRs (policy_driven_prs.tf), keyed by org ====
# StepSecurity opens pull requests (or issues) in the selected repos that add
# the Harden-Runner step, pin actions to SHAs, restrict GITHUB_TOKEN
# permissions, pin Dockerfile images and configure Dependabot.
# `auto_remediation_options` is the provider block verbatim. Turn this on
# last: it opens PRs in every selected repo. The PR text comes from
# pr_templates["acme-platform"] below. Resource: stepsecurity_policy_driven_pr.this["<org>"].
policy_driven_prs = {
  # acme-platform: every repo except sandbox; keep org-owned actions unpinned;
  # only add Harden-Runner to ubuntu-latest jobs. Everything else is the default.
  "acme-platform" = {
    selected_repos = ["*"]       # repos that receive PRs: ["*"] = every repo | ["payments-api", "web-frontend"] = only these (default: ["*"])
    excluded_repos = ["sandbox"] # repos skipped when selected_repos = ["*"]; a repo removed from this list later gets its original config restored (default: null)
    # selected_repos_filter = {                         # optional: narrow ["*"] further by GitHub topic (default: null = no filter)
    #   include_repos_only_with_topics = ["production"] #   only repos carrying one of these topics take part (default: null)
    # }
    auto_remediation_options = {                            # what the PRs fix — the provider's auto_remediation_options block verbatim (required; {} = every default below)
      actions_to_exempt_while_pinning = ["acme-platform/*"] # actions left on their tag when pinning: "owner/*" or "owner/action" (default: null = pin everything)
      harden_runner_config = {                              # how the Harden-Runner step is written into workflows (default: null = StepSecurity's default step)
        target_runner_labels = ["ubuntu-latest"]            # only jobs whose runs-on matches one of these labels get the step (default: null = every GitHub-hosted job)
        # config                        = "egress-policy: audit" # optional: YAML for the step's `with:` inputs (default: null = StepSecurity's default config)
        # exempt_runner_labels          = ["gpu-*"]              # optional: glob patterns of runs-on labels to skip regardless of target_runner_labels (default: null)
        # update_existing_configuration = true                   # optional: strip existing Harden-Runner settings that are not in `config` (default: false)
      }
      # -- delivery (the plan renders these defaults)
      # create_pr                             = true  # optional: open a pull request with the fixes (default: true)
      # create_issue                          = false # optional: open a GitHub issue describing the findings instead (default: false)
      # create_github_advanced_security_alert = false # optional: also raise a GitHub Advanced Security alert; only acts when create_issue = true (default: false)
      # -- which fixes go into the PR
      # harden_github_hosted_runner       = true  # optional: add the Harden-Runner step to jobs on GitHub-hosted runners (default: true)
      # pin_actions_to_sha                = true  # optional: replace action tags with full-length commit SHAs (default: true)
      # restrict_github_token_permissions = true  # optional: add a least-privilege `permissions:` block for GITHUB_TOKEN (default: true)
      # secure_docker_file                = false # optional: pin Dockerfile base images to a sha256 digest (default: false)
      # replace_action_on_major_tag_match = false # optional: swap actions from actions_to_replace_with_step_security_actions only when the major tag matches; needs that list non-empty (default: false)
      # update_existing_configuration     = false # optional: Dependabot drops ecosystems that are not listed in package_ecosystem (default: false)
      # -- exemptions and replacements
      # images_to_exempt_while_pinning                = ["alpine"]           # optional: Docker images left unpinned by secure_docker_file (default: null)
      # actions_to_replace_with_step_security_actions = ["actions/checkout"] # optional: third-party actions to swap for StepSecurity-maintained forks; mutually exclusive with the next line (default: null)
      # actions_exempted_from_replacement             = ["actions/checkout"] # optional: replace ALL maintained actions EXCEPT these; mutually exclusive with the previous line (default: null)
      # -- Dependabot
      # package_ecosystem = [                                                                                 # optional: ecosystems written to .github/dependabot.yml (default: null = leave it alone)
      #   { package = "npm", interval = "weekly" },                                                            #   package: npm | pip | docker | github-actions | maven | nuget | ... (required); interval: daily | weekly | monthly (required)
      #   { package = "github-actions", interval = "monthly", cooldown_yaml = "default-days: 3", groups_yaml = "all:\n  patterns: [\"*\"]" }, # cooldown_yaml / groups_yaml: YAML for the ecosystem's `cooldown:` / `groups:` blocks; heredocs work (default: null)
      # ]
      # Not exposed by inputs.tf (extend the object type to use them): action_commit_map, add_workflows, custom_actions_to_replace, labels_to_replace, update_precommit_file.
    }
  }
}

# ===== PR template for the remediation PRs (policy_driven_prs.tf), keyed by org
# Title, body, commit message, labels and branch name of the PRs that
# policy_driven_prs opens. Only meaningful for an org that also has a
# policy_driven_prs entry. Resource: stepsecurity_github_pr_template.this["<org>"].
pr_templates = {
  # acme-platform: every attribute set — labels and branch_name are the optional ones.
  "acme-platform" = {
    title          = "[StepSecurity] Apply security best practices" # PR title (required)
    labels         = ["security", "automated"]                      # GitHub labels added to every PR (default: null = none)
    branch_name    = "chore/stepsecurity-{time}"                    # branch name template; MUST contain {time}, replaced by a DDHHMM timestamp so each PR gets a unique branch (default: null = StepSecurity's default name)
    commit_message = "[StepSecurity] Apply security best practices" # commit message of the remediation commit (required); a heredoc (<<-EOT ... EOT) works for a multi-line message
    # summary: PR body in Markdown (required). {{STEPSECURITY_SECURITY_FIXES}} is replaced with the list of fixes in that PR; <<-EOT strips the common indentation. No "#" comments inside the heredoc — they would end up in the PR text.
    summary = <<-EOT
      ## Summary
      Automated hardening from StepSecurity — review and merge.

      ## Security fixes
      {{STEPSECURITY_SECURITY_FIXES}}
    EOT
  }
}

# ===== Suppression rules (suppressions.tf), keyed by rule name ===============
# Silence a detection you have reviewed and accepted, so it stops raising
# alerts. Scope with owner ("*" = every org in the tenant), repo / workflow /
# job ("*" = any), plus the detail fields the rule type needs. The action is
# always "ignore" (set by suppressions.tf; the provider supports nothing else).
# Resource: stepsecurity_github_supression_rule.this["<key>"].
suppression_rules = {
  # anomalous_outbound_network_call: payments-api's ci.yml uploads coverage to
  # Codecov from any process; that call is expected, do not alert on it.
  "platform-codecov-upload" = {
    owner       = "acme-platform"                   # org the rule applies to; "*" = every org in the tenant (required)
    type        = "anomalous_outbound_network_call" # detection type: anomalous_outbound_network_call | suspicious_network_call | https_outbound_network_call | secret_in_build_log | secret_in_artifact | source_code_overwritten | action_uses_imposter_commit | runner_worker_memory_read | privileged_container | reverse_shell (required)
    description = "Coverage upload is expected"     # why the detection is accepted; shown in the dashboard (default: null)
    repo        = "payments-api"                    # only this repo (default: "*" = any repo)
    workflow    = "ci.yml"                          # only this workflow file (default: "*" = any workflow)
    process     = "*"                               # process that made the call: exact name or wildcards ("curl", "*node", "*") — REQUIRED for this type
    destination = { domain = "*.codecov.io" }       # where it went — REQUIRED for this type: { domain = "..." } OR { ip = "..." }, never both; "*" wildcards ok
    # job         = "coverage"                 # optional: only this job name (default: "*" = any job)
    # destination = { ip = "192.168.*.1:443" } # the IP form of destination, e.g. for a fixed-address collector
    # -- detail fields the other rule types require (leave them out for this type; they must not be set for other types)
    # endpoint      = "*.ngrok-free.app:443" # suspicious_network_call: the flagged endpoint
    # host          = "s3.amazonaws.com"     # https_outbound_network_call: the flagged HTTPS host
    # secret_type   = "AWS Access Key"       # secret_in_build_log and secret_in_artifact: category of the detected secret
    # artifact_name = "test-fixtures"        # secret_in_artifact: name of the uploaded artifact
    # file          = "package.json"         # source_code_overwritten: name of the overwritten file
    # file_path     = "web/package.json"     # source_code_overwritten: optional path refinement of `file`
    # github_action = "actions/checkout"     # action_uses_imposter_commit: the action pinned to a commit that is not in its repo
    # process       = "python3"              # runner_worker_memory_read | privileged_container | reverse_shell also require process (already set above for this type)
  }
}
