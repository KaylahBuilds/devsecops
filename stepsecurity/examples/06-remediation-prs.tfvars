# =============================================================================
# Example 06 - Policy-driven remediation PRs and PR template
# =============================================================================
# What it demonstrates:
#   - StepSecurity opening one remediation PR per repo in "acme-corp": every repo tagged with a GitHub topic, minus two exclusions
#   - EVERY auto_remediation_options attribute this layout exposes, live or commented: PR vs issue delivery, pin actions to SHA,
#     add harden-runner, restrict GITHUB_TOKEN, pin Dockerfile base images, replace actions with StepSecurity forks, exemptions
#   - a custom harden_runner_config (step YAML heredoc, target / exempt runner labels, rewrite of existing steps)
#   - two package_ecosystem entries (npm weekly, github-actions monthly) with Dependabot cooldown_yaml and groups_yaml heredocs
#   - a pr_templates entry with every field: title, summary with {{STEPSECURITY_SECURITY_FIXES}}, commit message, labels, branch_name with {time}
#   - one org-wide egress policy in "audit" mode so the harden-runner steps the PRs add report into an existing policy (see egress_policies)
#   - the provider attributes this layout does NOT expose and what it takes to add them (comment block above policy_driven_prs)
#
# Run (from the repo root):
#   cd stepsecurity && terraform plan -var-file=examples/06-remediation-prs.tfvars
#
# Credentials never live in a tfvars file - export them first:
#   export STEP_SECURITY_CUSTOMER=<tenant name> STEP_SECURITY_API_KEY=<api key>
#
# Rollout advice: turn policy_driven_prs on LAST - it opens PRs in every selected
# repo at once. Start with a short selected_repos list or a topic filter (below),
# widen to ["*"] once the first PRs merged cleanly.
#
# Expected plan: 4 resources to add
#   stepsecurity_github_policy_store.this["acme-baseline"]             org-wide audit egress policy
#   stepsecurity_github_policy_store_attachment.this["acme-baseline"]  its org-wide attachment
#   stepsecurity_policy_driven_pr.this["acme-corp"]                    which repos get PRs and what the PRs fix
#   stepsecurity_github_pr_template.this["acme-corp"]                  how those PRs look
# =============================================================================

# ===== Tenant-wide settings (variables.tf) ===================================
# Provider auth - keep these commented out; the provider reads the env vars.
# customer     = "acme"                        # optional: StepSecurity tenant name (default: null -> STEP_SECURITY_CUSTOMER env var)
# api_key      = "<never put a real key here>" # optional: API key (default: null -> STEP_SECURITY_API_KEY env var); sensitive, must never be committed
# api_base_url = "https://api.stepsecurity.io" # optional: override the API base URL (default: null -> provider default)

default_egress_policy = "audit" # mode for egress policies that omit egress_policy: audit = log only | block = drop unlisted endpoints (default: audit); the policy below relies on it

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

# default_check_controls = [                                                   # optional: controls for any `checks` entry without its own `controls` list (default below); unused here, checks = {}
#   { control = "NPM Package Cooldown", settings = { cool_down_period = 3 } },  #   required: fail when an npm package was published less than 3 days ago
#   { control = "PyPI Package Cooldown", settings = { cool_down_period = 3 } }, #   required: same for PyPI
#   { control = "PWN Request" },                                                #   required: pull_request_target misuse
#   { control = "Script Injection", type = "optional" },                        #   optional (non-blocking): untrusted input interpolated into run: scripts
# ]

# default_notification_email = "sec@example.com" # optional: email for `notifications` entries that omit `email` (default: null = no email); unused here, notifications = {}

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
#   harden_runner_config_changes_detected = true  #   someone changed a harden-runner step in a workflow - fires on the PRs this example opens once they merge
#   non_compliant_artifact_detected       = false #   artifact failed compliance checks
#   run_blocked_by_policy                 = true  #   a run policy blocked a workflow run
#   baseline_check_failures               = false #   baseline PR check failed
#   required_check_failures               = true  #   required PR check failed
#   optional_check_failures               = false #   optional PR check failed
# }

# notification_webhooks = { "acme-corp" = { slack_webhook_url = "...", teams_webhook_url = "..." } } # SECRET, never here: copy examples/secrets.auto.tfvars.example to stepsecurity/secrets.auto.tfvars (git-ignored) or set TF_VAR_notification_webhooks (default: {})

# ===== Harden-Runner egress policies (policy_store.tf) =======================
# Why an egress policy in a PR example: harden_github_hosted_runner = true (below)
# inserts a `step-security/harden-runner` step into every job. That step reports
# the job's outbound traffic to the org's policy in the StepSecurity policy store.
# With this org-wide audit policy in place the new runner steps have a policy to
# report into from their first run, nothing is blocked, and the dashboard's egress
# reports fill up - the input you need before switching to "block"
# (02-egress-policies.tfvars shows the block-mode allow-lists).
# Key = policy name in the StepSecurity dashboard. Each entry names its org via `owner`.
egress_policies = {
  # One org-wide audit policy: harden-runner records every outbound call, blocks nothing.
  "acme-baseline" = {
    owner = "acme-corp" # GitHub org this policy belongs to (required)
    # egress_policy           = "audit"                    # optional: audit = log egress only | block = drop anything not in allowed_endpoints (default: null -> var.default_egress_policy, "audit" above)
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
  # Attach the audit policy to every repo and workflow in acme-corp - the same scope the PRs cover.
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
run_policies = {} # what a workflow run may do (allowed / SHA-pinned actions, runner labels, harden-runner presence, secrets) - not used here; see 03-run-policies.tfvars. Natural companion: a run policy with enable_harden_runner_policy + require_pinned_actions ENFORCES what these PRs add

# ===== PR checks (checks.tf), keyed by org ===================================
checks = {} # StepSecurity PR checks per org (package cooldown, PWN request, script injection controls + required/optional/baseline repos) - not used here; see the checks example in this directory (04-multi-org.tfvars also has one)

# ===== Notifications (notifications.tf), keyed by org ========================
notifications = {} # email / Slack / Teams channels and which events fire per org - not used here; see the notifications example in this directory (04-multi-org.tfvars also has one)

# ===== Policy-driven PRs (policy_driven_prs.tf), keyed by org ================
# StepSecurity scans the selected repos and opens one PR (or issue) per repo
# carrying every fix enabled in auto_remediation_options. That object is the
# provider's auto_remediation_options block passed through verbatim (inputs.tf),
# so the examples in the provider docs paste straight in.
#
# NOT exposed by this layout - present in the provider schema (v0.0.44) but
# absent from the auto_remediation_options object type in inputs.tf. Terraform
# rejects unknown attributes in a typed object, so using one of these means
# adding it as an optional(...) attribute to that object type in inputs.tf; the
# resource in policy_driven_prs.tf passes the whole object through, so nothing
# else changes:
#   action_commit_map         = { "actions/checkout" = "<40-char sha>" } # map(string): pin an action to THIS commit instead of resolving its tag
#   custom_actions_to_replace = { "actions/cache" = "acme-corp/cache" }  # map(string): original action -> your own replacement action
#   labels_to_replace         = { "self-hosted" = "ubuntu-latest" }     # map(string): disallowed runs-on label -> allowed label; opens a PR/issue swapping them
#   add_workflows             = "<workflow yaml>"                        # string: extra workflow file(s) to add as part of the PR
#   update_precommit_file     = [".pre-commit-config.yaml"]              # list(string): pre-commit config files the PR updates (shows as [] in the plan: the provider computes it when unset)
#   custom_precommit_config   = "<pre-commit yaml>"                      # string: custom pre-commit config (documented for newer provider releases; not in the v0.0.44 schema dump - check `terraform providers schema -json` before adding it)
policy_driven_prs = {
  # acme-corp: every repo carrying the "production" topic, except the two listed, one PR per repo.
  "acme-corp" = {
    selected_repos = ["*"]                            # repos to remediate: ["*"] = every repo in the org (default: ["*"]); an explicit list like ["payments-api"] works too, but then excluded_repos / selected_repos_filter are not allowed
    excluded_repos = ["sandbox", "archived-docs"]     # never open PRs here; only valid with selected_repos = ["*"]; a repo removed from this list later gets its original config restored (default: null = nothing excluded)
    selected_repos_filter = {                         # narrows ["*"] by GitHub topic (default: null = no filter); only valid with selected_repos = ["*"]
      include_repos_only_with_topics = ["production"] # set of repository topics; a repo takes part only when it carries them (default: null)
    }
    auto_remediation_options = { # what the PRs fix - the provider's auto_remediation_options block verbatim (required)
      # --- delivery: how findings reach the repo; exactly one of create_pr / create_issue may be true ---
      create_pr                             = true  # open a pull request with the fixes (default: true); the provider rejects create_pr and create_issue both true
      create_issue                          = false # open a GitHub issue describing the finding instead of a PR (default: false)
      create_github_advanced_security_alert = false # also raise a GitHub Advanced Security (code scanning) alert; only fires when create_issue = true (default: false)
      # --- which fixes go into the PR ---
      harden_github_hosted_runner       = true # add a step-security/harden-runner step to every job on GitHub-hosted runners, shaped by harden_runner_config below (default: true)
      pin_actions_to_sha                = true # replace `uses: owner/action@v4` with the full 40-char commit SHA plus a `# v4` comment (default: true)
      restrict_github_token_permissions = true # add a least-privilege `permissions:` block (e.g. contents: read) to every workflow / job (default: true)
      secure_docker_file                = true # pin Dockerfile `FROM` base images to their sha256 digest (default: false)
      replace_action_on_major_tag_match = true # swap the actions in actions_to_replace_with_step_security_actions only when the StepSecurity fork has the same major tag (v4 -> v4); requires that list to be non-empty (default: null = provider default)
      update_existing_configuration     = true # Dependabot: remove ecosystems from .github/dependabot.yml that are not in package_ecosystem below (default: null = keep them)
      # --- exemptions and replacements ---
      actions_to_exempt_while_pinning               = ["acme-corp/*", "actions/checkout"]          # actions that keep their tag reference when pinning: "owner/*" or "owner/action" (default: null = pin everything)
      images_to_exempt_while_pinning                = ["ghcr.io/acme-corp/*", "scratch"]           # Docker base images left on their tag when secure_docker_file = true (default: null = pin every base image)
      actions_to_replace_with_step_security_actions = ["actions/cache", "actions/upload-artifact"] # swap these for the StepSecurity-maintained forks (step-security/<name>) (default: null = no replacement)
      # actions_exempted_from_replacement           = ["actions/checkout"]                        # optional: the inverse - replace EVERY StepSecurity-maintained action except these; mutually exclusive with actions_to_replace_with_step_security_actions, so pick one (default: null)
      # --- how the harden-runner step is written ---
      harden_runner_config = { # shape of the harden-runner step the PR inserts (default: null = StepSecurity's default step)
        # config: YAML for the step's `with:` inputs. egress-policy: audit = log outbound calls | block = drop calls not on the allow-list; keep audit until the allow-lists exist (02-egress-policies.tfvars)
        config                        = <<-EOT
          egress-policy: audit
          disable-sudo: false
          disable-file-monitoring: false
        EOT
        target_runner_labels          = ["ubuntu-latest", "ubuntu-24.04"] # only jobs whose runs-on matches one of these labels get the step (default: null = every GitHub-hosted job)
        exempt_runner_labels          = ["gpu-*", "self-hosted"]          # glob patterns of runs-on labels to skip regardless of target_runner_labels (default: null = skip none)
        update_existing_configuration = true                              # rewrite harden-runner steps that already exist so they match `config` (default: null = leave existing steps alone)
      }
      # --- Dependabot ---
      package_ecosystem = [   # Dependabot ecosystems the PR configures in .github/dependabot.yml (default: null = leave dependabot.yml alone)
        {                     # npm: weekly updates, minimum package age before an update is proposed, grouped PRs
          package  = "npm"    # ecosystem name as Dependabot spells it: npm | pip | docker | github-actions | gomod | maven | nuget | ... (required)
          interval = "weekly" # how often Dependabot looks for updates: daily | weekly | monthly (required)
          # cooldown_yaml: Dependabot `cooldown:` block - days a new version must be public before it is proposed, a supply-chain guard (default: null = no cooldown)
          cooldown_yaml = <<-EOT
            default-days: 7
            semver-major-days: 30
            semver-minor-days: 7
            semver-patch-days: 3
            exclude:
              - "@acme-corp/*"
          EOT
          # groups_yaml: Dependabot `groups:` block - bundle related updates into one PR (default: null = one PR per dependency)
          groups_yaml = <<-EOT
            dev-dependencies:
              dependency-type: "development"
              update-types: ["minor", "patch"]
            production-minor-patch:
              dependency-type: "production"
              update-types: ["minor", "patch"]
          EOT
        },
        {                             # github-actions: monthly, 3-day cooldown, every action bump in one PR
          package  = "github-actions" # keeps `uses:` references current; SHA-pinned actions get their pin bumped (required)
          interval = "monthly"        # daily | weekly | monthly (required)
          # cooldown_yaml: three days for every action, no per-semver split
          cooldown_yaml = <<-EOT
            default-days: 3
          EOT
          # groups_yaml: one group whose pattern matches every action
          groups_yaml = <<-EOT
            github-actions:
              patterns: ["*"]
          EOT
        },
      ]
    }
  }
}

# ===== PR template for those PRs (policy_driven_prs.tf), keyed by org ========
# Title, body, commit message, labels and branch name of the PRs opened above.
# One template per org that has a policy_driven_prs entry; an org without one
# gets StepSecurity's default template.
pr_templates = {
  # acme-corp: every field set - two heredocs keep the Markdown and the commit body readable.
  "acme-corp" = {
    title       = "[StepSecurity] Apply security best practices" # PR title (required)
    labels      = ["security", "stepsecurity", "automated"]      # GitHub labels added to every PR (default: null = none)
    branch_name = "chore/stepsecurity-{time}"                    # branch name; MUST contain {time}, replaced with a DDHHMM stamp so every PR gets a unique branch (default: null = StepSecurity's default name)
    # summary: PR body (required). {{STEPSECURITY_SECURITY_FIXES}} is replaced with the list of fixes in that PR; the rest is plain Markdown
    summary = <<-EOT
      ## Summary
      Automated hardening from StepSecurity for acme-corp. Review the diff, let CI run, merge when green.

      ## Security fixes
      {{STEPSECURITY_SECURITY_FIXES}}

      ## Reviewer checklist
      - [ ] each pinned SHA matches the tag in its trailing comment
      - [ ] the `permissions:` block still covers everything the workflow does
      - [ ] the harden-runner step is present in every job (audit mode - nothing is blocked)

      Questions: #security on Slack or sec@example.com
    EOT
    # commit_message: message of the commit that carries the changes (required); heredoc = subject line + blank line + body
    commit_message = <<-EOT
      chore(security): apply StepSecurity best practices

      Pins actions to commit SHAs, adds harden-runner, restricts GITHUB_TOKEN
      permissions, pins Dockerfile base images and configures Dependabot.
      Opened automatically by StepSecurity policy-driven PRs.
    EOT
  }
}

# ===== Suppression rules (suppressions.tf), keyed by rule name ===============
suppression_rules = {} # silence reviewed detections (expected network calls, known secrets in logs, ...) - not used here; see the suppression-rules example in this directory
