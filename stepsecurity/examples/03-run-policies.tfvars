# =============================================================================
# Example 03 - Run policies: one policy per policy type
# =============================================================================
# A run policy is evaluated by StepSecurity every time a GitHub Actions
# workflow run starts in the org. It can block the run (or, in dry-run mode,
# only report what it would have blocked) and posts a PR comment explaining
# why. One policy = one entry in `run_policies`; its `policy` object is the
# provider's policy_config block passed through verbatim by run_policies.tf,
# so examples from the StepSecurity provider docs paste straight in.
#
# What it demonstrates (one org "acme-corp", nine policies, one per type):
#   - action policy with SHA pinning: allow-list keys of every shape (exact "owner/repo",
#     owner wildcard "owner/*", global "*/*") plus actions exempt from pinning
#   - action policy as a plain allow-list, no pinning requirement
#   - runs-on policy in "disallowed" mode (listed labels + GitHub's standard hosted labels)
#   - runs-on policy in "allowed" mode (plain labels + structured runs-on.com constraints)
#   - Harden-Runner policy on every job (target labels = []) with policy-store and
#     job-container checks, and a targeted variant (specific labels + custom actions)
#   - secrets policy with exempted bots, bulk-only mode, default-branch analysis and a
#     custom PR comment template using every placeholder
#   - compromised-actions policy
#   - a repo-scoped dry-run policy with a dashboard `name` override (the rollout
#     pattern from README.md: trial a stricter setting on a few repos first)
#
# Run (from the repo root):
#   cd stepsecurity && terraform plan -var-file=examples/03-run-policies.tfvars
#
# Credentials never live in a tfvars file - export them first:
#   export STEP_SECURITY_CUSTOMER=<tenant name> STEP_SECURITY_API_KEY=<api key>
#
# Expected plan: 9 resources to add, all of them stepsecurity_github_run_policy.this["<key>"]:
#   pin-actions, actions-allow-list, runner-disallowed, runner-allowed,
#   harden-runner-all-jobs, harden-runner-targeted, secrets, compromised-actions,
#   secrets-strict-dry-run
#
# Entries (c)/(d) and (e)/(f) overlap on purpose so the plan renders both
# runs-on modes and both Harden-Runner shapes; a real org keeps one of each
# pair. Every attribute of the policy object is set live in at least one entry
# and shown commented out, with meaning / allowed values / default, where an
# entry does not use it. The seven other input maps are set to {} so this file
# fully overrides the auto-loaded terraform.tfvars.
# =============================================================================

# ===== Tenant-wide settings (variables.tf) ===================================
# Run policies use none of the tenant-wide defaults, so everything in this
# section stays commented out and shows the module default.
# Provider auth - keep these commented out; the provider reads the env vars.
# customer     = "acme"                        # optional: StepSecurity tenant name (default: null -> STEP_SECURITY_CUSTOMER env var)
# api_key      = "<never put a real key here>" # optional: API key (default: null -> STEP_SECURITY_API_KEY env var); sensitive, must never be committed
# api_base_url = "https://api.stepsecurity.io" # optional: override the API base URL (default: null -> provider default)

# default_egress_policy = "audit" # optional: mode for egress policies that omit egress_policy: audit = log only | block = drop unlisted endpoints (default: audit) - see 02-egress-policies.tfvars

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

# default_check_controls = [                                                   # optional: controls for any `checks` entry without its own `controls` list (default below) - see 04-multi-org.tfvars
#   { control = "NPM Package Cooldown", settings = { cool_down_period = 3 } },  #   required: fail when an npm package was published less than 3 days ago
#   { control = "PyPI Package Cooldown", settings = { cool_down_period = 3 } }, #   required: same for PyPI
#   { control = "PWN Request" },                                                #   required: pull_request_target misuse
#   { control = "Script Injection", type = "optional" },                        #   optional (non-blocking): untrusted input interpolated into run: scripts
# ]

# default_notification_email = "sec@example.com" # optional: email for `notifications` entries that omit `email` (default: null = no email) - see 07-notifications-and-suppressions.tfvars

# default_notification_events = {                # optional: baseline on/off per event; a notifications entry's `events` map is merged over it (default below)
#   domain_blocked                        = true  #   outbound call to a domain was blocked (block mode only)
#   file_overwrite                        = true  #   a source file was overwritten during the job
#   new_endpoint_discovered               = false #   a call to an endpoint not seen before (noisy while in audit mode)
#   https_detections                      = true  #   anomalous HTTPS outbound call
#   secrets_detected                      = true  #   a secret showed up in the build log
#   artifacts_secrets_detected            = true  #   a secret showed up in a build artifact
#   imposter_commits_detected             = true  #   an action is pinned to a commit that is not in its repo
#   suspicious_network_call_detected      = true  #   suspicious network call
#   suspicious_process_events_detected    = true  #   suspicious process (reverse shell, privileged container, ...)
#   harden_runner_config_changes_detected = true  #   someone changed a harden-runner step in a workflow
#   non_compliant_artifact_detected       = false #   artifact failed compliance checks
#   run_blocked_by_policy                 = true  #   a run policy from THIS file blocked a workflow run
#   baseline_check_failures               = false #   baseline PR check failed
#   required_check_failures               = true  #   required PR check failed
#   optional_check_failures               = false #   optional PR check failed
# }

# notification_webhooks = { "acme-corp" = { slack_webhook_url = "...", teams_webhook_url = "..." } } # SECRET, never here: copy examples/secrets.auto.tfvars.example to stepsecurity/secrets.auto.tfvars (git-ignored) or set TF_VAR_notification_webhooks (default: {})

# ===== Harden-Runner egress policies (policy_store.tf) =======================
egress_policies = {} # Harden-Runner egress policies (audit/block, allowed or denied endpoints, lockdown) - not used here; see 02-egress-policies.tfvars

# ===== Where each egress policy applies (policy_store.tf) ====================
egress_policy_attachments = {} # org-wide / repo / workflow / cluster attachments of the egress policies above - not used here; see 02-egress-policies.tfvars

# ===== Run policies (run_policies.tf), keyed by policy name ==================
# Key = state address this["<key>"] and, unless `name` is set, the dashboard name.
# Entry shape (inputs.tf):
#   owner         GitHub org the policy belongs to (required)
#   name          dashboard name (default: the map key)
#   repositories  list of repo names the policy is limited to (default: null = every repo in the org; the resource then sets all_repos = true)
#   policy        the provider's policy_config block - one entry can enable several policy types at once, but one type per entry is easier to reason about
# policy attributes by policy type (all optional; an enable_* that is omitted is off):
#   is_dry_run                        report instead of block (default: false)
#   enable_action_policy              allowed_actions, require_pinned_actions, actions_to_exempt_while_pinning
#   enable_runs_on_policy             runs_on_mode, disallowed_runner_labels, allowed_runner_labels, allowed_runner_constraints, enable_standard_runner_labels
#   enable_harden_runner_policy       harden_runner_target_labels, harden_runner_custom_actions, require_policy_store, block_job_container
#   enable_secrets_policy             exempted_users, bulk_secrets_only_mode, secrets_analyze_default_branch
#   enable_compromised_actions_policy (no further settings)
#   pr_comment_template               custom PR comment for any policy type
run_policies = {

  # (a) Action policy + SHA pinning: every `uses:` must reference a full-length
  #     commit SHA. The "*/*" key allows every action, so this entry is about
  #     pinning; the narrower keys show the other two key shapes.
  "pin-actions" = {
    owner = "acme-corp" # GitHub org this policy belongs to (required)
    # name         = "Pin actions to SHA"               # optional: name shown in the StepSecurity dashboard (default: the map key "pin-actions") - see (i)
    # repositories = ["payments-api", "billing-worker"] # optional: limit the policy to these repos (default: null = all repos in the org) - see (i)
    policy = {                       # the provider's policy_config block, passed through verbatim by run_policies.tf
      enable_action_policy   = true  # turn the allowed-actions policy on (default: omitted = off); the three attributes below only matter when this is true
      require_pinned_actions = true  # every action must be pinned to a full 40-character commit SHA; tags and branches are blocked (default: omitted = false)
      allowed_actions = {            # map of action pattern -> "allow"; a run using an action that matches no key is blocked
        "actions/checkout" = "allow" # name-only "owner/repo": actions/checkout at any ref (append "@v4" for an exact-ref match)
        "acme-corp/*"      = "allow" # owner wildcard "owner/*": every action published by the acme-corp org
        "*/*"              = "allow" # global wildcard: every action - it makes the two keys above redundant, so only pinning is enforced here
      }
      actions_to_exempt_while_pinning = [ # actions that may stay on a tag/branch although pinning is required (default: omitted = none); "*/*" is REJECTED here
        "acme-corp/*",                    # owner wildcard: internal actions live in the same org, their tags are trusted
        "github/codeql-action",           # name-only: GitHub's own CodeQL action at any ref
        "actions/checkout@v4",            # exact ref: only this tag of actions/checkout is exempt
      ]
      # is_dry_run          = true  # optional: report violations in the dashboard and PR comment without blocking the run (default: false) - see (i)
      # pr_comment_template = "..." # optional: custom PR comment posted when this policy blocks a run (default: null = StepSecurity's standard comment) - see (g)
    }
  }

  # (b) Action policy as a plain allow-list: runs may use nothing but these
  #     actions, and they are not required to be SHA-pinned.
  "actions-allow-list" = {
    owner = "acme-corp"                                   # GitHub org this policy belongs to (required)
    policy = {                                            # provider policy_config block
      enable_action_policy = true                         # allowed-actions policy on (default: omitted = off)
      allowed_actions = {                                 # any action that matches no key blocks the run; value is always "allow"
        "actions/*"                             = "allow" # every action published by GitHub's "actions" org (checkout, setup-node, cache, ...)
        "github/*"                              = "allow" # GitHub's own security actions (codeql-action, dependency-review-action, ...)
        "acme-corp/*"                           = "allow" # internal actions
        "step-security/harden-runner"           = "allow" # the StepSecurity agent, any ref
        "aws-actions/configure-aws-credentials" = "allow" # one third-party action by name, any ref
        "docker/build-push-action@v6"           = "allow" # one third-party action at exactly this ref
      }
      # require_pinned_actions          = true          # optional: also require full-SHA pins (default: omitted = false) - see (a)
      # actions_to_exempt_while_pinning = ["acme-corp/*"] # optional: only meaningful with require_pinned_actions = true (default: omitted = none) - see (a)
      # is_dry_run                      = true          # optional: report instead of block (default: false) - see (i)
    }
  }

  # (c) runs-on policy in "disallowed" mode (the default): block jobs whose
  #     `runs-on` matches a listed label. With enable_standard_runner_labels
  #     GitHub's standard hosted labels (ubuntu-latest, windows-latest,
  #     macos-*, arm variants, ...) are added to the list, so acme-corp jobs
  #     must use the org's own larger runners - exactly what (d) allows.
  "runner-disallowed" = {
    owner = "acme-corp"                                              # GitHub org this policy belongs to (required)
    policy = {                                                       # provider policy_config block
      enable_runs_on_policy         = true                           # turn the runs-on (runner label) policy on (default: omitted = off)
      disallowed_runner_labels      = ["self-hosted", "legacy-pool"] # jobs whose runs-on contains any of these labels are blocked (default: omitted = none); here the retired self-hosted pool
      enable_standard_runner_labels = true                           # also add GitHub's standard hosted label set, kept current by StepSecurity, to disallowed_runner_labels (default: omitted = false)
      # runs_on_mode               = "disallowed"                  # optional: disallowed = block listed labels (default; "" means the same) | allowed = permit only listed labels/constraints - see (d)
      # allowed_runner_labels      = ["acme-ubuntu-8core"]         # optional: ignored in disallowed mode (default: omitted) - see (d)
      # allowed_runner_constraints = { family = ["m7a"] }          # optional: ignored in disallowed mode (default: omitted) - see (d)
      # is_dry_run                 = true                          # optional: report instead of block (default: false) - see (i)
    }
  }

  # (d) runs-on policy in "allowed" mode: a job may run only if its `runs-on`
  #     matches an allowed label verbatim, or if every runs-on.com
  #     "key=value" token it carries satisfies the constraints below.
  #     Everything else is blocked.
  "runner-allowed" = {
    owner = "acme-corp"                                                                    # GitHub org this policy belongs to (required)
    policy = {                                                                             # provider policy_config block
      enable_runs_on_policy = true                                                         # runs-on policy on (default: omitted = off)
      runs_on_mode          = "allowed"                                                    # allowed = permit only what is listed below | disallowed = block listed labels (default: disallowed); "allowed" requires allowed_runner_labels
      allowed_runner_labels = ["acme-ubuntu-8core", "acme-ubuntu-16core", "acme-macos-m2"] # plain labels matched verbatim (GitHub larger runners / runner groups); ignored in disallowed mode
      allowed_runner_constraints = {                                                       # runs-on.com constraints keyed by dimension (lowercase keys, each with at least one value); a key=value token passes when its key is not listed here or its value is in the set
        "runs-on" = ["$${{ github.run_id }}"]                                              # the routing key pinned to the conventional expression; "$$" escapes "${" in HCL, the plan shows ${{ github.run_id }}
        family    = ["m7a", "c7a"]                                                         # allowed EC2 instance families
        cpu       = ["4", "8", "16"]                                                       # allowed vCPU counts
        image     = ["ubuntu24-full-x64"]                                                  # allowed runner images
      }
      # disallowed_runner_labels      = ["self-hosted"] # optional: ignored in allowed mode (default: omitted) - see (c)
      # enable_standard_runner_labels = true            # optional: extends disallowed_runner_labels, which allowed mode ignores, so it has no effect here (default: omitted = false) - see (c)
      # is_dry_run                    = true            # optional: report instead of block (default: false) - see (i)
    }
  }

  # (e) Harden-Runner policy on every job: each job must run
  #     step-security/harden-runner with `use-policy-store: true` (so the
  #     egress policies from 02-egress-policies.tfvars apply), and jobs that
  #     run entirely inside a job-level `container:` are blocked because the
  #     agent cannot monitor them there.
  "harden-runner-all-jobs" = {
    owner = "acme-corp"                  # GitHub org this policy belongs to (required)
    policy = {                           # provider policy_config block
      enable_harden_runner_policy = true # require a Harden-Runner step in every targeted job (default: omitted = off)
      harden_runner_target_labels = []   # [] = every job | non-empty set = only jobs whose runs-on matches one of the labels | omitted = leave the current backend value untouched
      require_policy_store        = true # the harden-runner step must set `use-policy-store: true`; the legacy `policy:` input does not count (default: omitted = false)
      block_job_container         = true # block targeted jobs that run entirely inside a job-level container:; step-level containers are fine (default: omitted = false)
      # harden_runner_custom_actions  = ["acme-corp/harden-runner-wrapper"] # optional: extra actions accepted as Harden-Runner equivalents (default: omitted = only step-security/harden-runner) - see (f)
      # enable_standard_runner_labels = true                                # optional: add GitHub's standard hosted labels to harden_runner_target_labels (default: omitted = false); pointless with [] = every job
      # is_dry_run                    = true                                # optional: report instead of block (default: false) - see (i)
    }
  }

  # (f) Targeted variant of (e): only Ubuntu jobs (Harden-Runner runs on
  #     Linux runners) are checked, and the org's composite wrapper actions
  #     count as Harden-Runner because they call it internally.
  "harden-runner-targeted" = {
    owner = "acme-corp"                                                                                           # GitHub org this policy belongs to (required)
    policy = {                                                                                                    # provider policy_config block
      enable_harden_runner_policy  = true                                                                         # Harden-Runner policy on (default: omitted = off)
      harden_runner_target_labels  = ["ubuntu-latest", "ubuntu-24.04", "acme-ubuntu-8core", "acme-ubuntu-16core"] # only jobs whose runs-on matches one of these labels must run the agent
      harden_runner_custom_actions = ["acme-corp/harden-runner-wrapper", "acme-corp/ci-bootstrap"]                # actions accepted in place of step-security/harden-runner (default: omitted = none)
      # require_policy_store          = true # optional: require `use-policy-store: true` on the step (default: omitted = false) - see (e)
      # block_job_container           = true # optional: block fully containerised jobs (default: omitted = false) - see (e)
      # enable_standard_runner_labels = true # optional: add GitHub's standard hosted labels to the target set instead of listing ubuntu-latest etc. by hand (default: omitted = false)
      # is_dry_run                    = true # optional: report instead of block (default: false) - see (i)
    }
  }

  # (g) Secrets policy: block runs that would expose repository/org secrets
  #     to untrusted code, with a custom PR comment.
  "secrets" = {
    owner = "acme-corp"                                                                         # GitHub org this policy belongs to (required)
    policy = {                                                                                  # provider policy_config block
      enable_secrets_policy          = true                                                     # turn the secrets (exfiltration) policy on (default: omitted = off)
      exempted_users                 = ["dependabot[bot]", "renovate[bot]", "acme-release-bot"] # GitHub users / bots whose runs skip this policy (default: omitted = nobody)
      bulk_secrets_only_mode         = true                                                     # true = enforce only high-risk bulk exposure such as toJSON(secrets) | false = every secret reference (default: omitted = false)
      secrets_analyze_default_branch = true                                                     # also evaluate runs on the default branch; by default only non-default-branch runs are checked (default: omitted = false)
      # pr_comment_template: Markdown of the PR comment posted when this policy blocks a run (default: omitted = StepSecurity's standard comment).
      # Placeholders: {{policy_type}} {{policy_name}} {{policy_details}} {{workflow_run_url}} {{remediation}} {{docs_url}}
      pr_comment_template = <<-EOT
        ### Blocked by StepSecurity run policy **{{policy_name}}** ({{policy_type}})

        Workflow run: {{workflow_run_url}}

        {{policy_details}}

        **How to fix:** {{remediation}}

        Questions? Ask #security on Slack or read {{docs_url}}.
      EOT
      # is_dry_run = true # optional: report instead of block (default: false) - see (i)
    }
  }

  # (h) Compromised-actions policy: block a run that uses an action release
  #     StepSecurity's threat intel has flagged as compromised (for example
  #     the tj-actions/changed-files incident). It has no further settings.
  "compromised-actions" = {
    owner = "acme-corp"                        # GitHub org this policy belongs to (required)
    policy = {                                 # provider policy_config block
      enable_compromised_actions_policy = true # block runs that use a known-compromised action version (default: omitted = off)
      # is_dry_run          = true  # optional: report instead of block (default: false) - see (i)
      # pr_comment_template = "..." # optional: custom PR comment (default: omitted = StepSecurity's standard comment) - see (g)
    }
  }

  # (i) Rollout pattern from README.md: trial a stricter setting on a few
  #     repos first, in dry-run mode, under a descriptive dashboard name.
  #     Here the full secrets policy (bulk-only mode off, every secret
  #     reference evaluated) is tried on the two money repos while (g) keeps
  #     enforcing bulk-only mode org-wide.
  "secrets-strict-dry-run" = {
    owner        = "acme-corp"                                   # GitHub org this policy belongs to (required)
    name         = "Secrets policy - strict (dry run, payments)" # dashboard name; overrides the map key, while the state address stays this["secrets-strict-dry-run"]
    repositories = ["payments-api", "billing-worker"]            # only these repos; the plan then renders all_repos = false (omitted -> all_repos = true, every repo in the org)
    policy = {                                                   # provider policy_config block
      is_dry_run            = true                               # report what would be blocked (dashboard + PR comment) without blocking the run (default: false)
      enable_secrets_policy = true                               # secrets policy on (default: omitted = off)
      exempted_users        = ["dependabot[bot]"]                # only Dependabot is exempt in the trial (default: omitted = nobody)
      # bulk_secrets_only_mode         = false # optional: deliberately left off here so every secret reference is evaluated (default: omitted = false) - see (g)
      # secrets_analyze_default_branch = true  # optional: also check default-branch runs (default: omitted = false) - see (g)
      # pr_comment_template            = "..." # optional: custom PR comment (default: omitted = StepSecurity's standard comment) - see (g)
    }
  }
}

# ===== PR checks (checks.tf), keyed by org ===================================
checks = {} # StepSecurity PR checks per org (controls + required/optional/baseline repos) - not used here; see 04-multi-org.tfvars and 05-repo-and-workflow-scoped.tfvars

# ===== Notifications (notifications.tf), keyed by org ========================
notifications = {} # email / Slack / Teams channels and which events fire per org - not used here; see 07-notifications-and-suppressions.tfvars (04-multi-org.tfvars also has one)

# ===== Policy-driven PRs (policy_driven_prs.tf), keyed by org ================
policy_driven_prs = {} # StepSecurity remediation PRs (pin actions to SHA, add harden-runner, restrict GITHUB_TOKEN, ...) - not used here; see 06-remediation-prs.tfvars

# ===== PR template for those PRs (policy_driven_prs.tf), keyed by org ========
pr_templates = {} # title / summary / commit message / labels / branch name of the remediation PRs - not used here; see 06-remediation-prs.tfvars

# ===== Suppression rules (suppressions.tf), keyed by rule name ===============
suppression_rules = {} # silence reviewed detections (expected network calls, known secrets in logs, ...) - not used here; see 07-notifications-and-suppressions.tfvars
