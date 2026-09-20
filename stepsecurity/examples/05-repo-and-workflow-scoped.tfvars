# =============================================================================
# Example 05 - Precision targeting: repos, workflows, patterns
# =============================================================================
# Every resource this module manages can be aimed at a slice of a GitHub org
# instead of the whole org, but each resource type has its own scoping fields
# and its own rules (exact names here, "*" patterns there, omit-lists only
# together with "*", ...). This scenario (one org: acme-corp) puts every
# scoping shape side by side so one plan shows how each of them renders, and
# the comments spell out the scope and precedence semantics of every field.
#
# What it demonstrates:
#   - egress_policy_attachments aimed at: one workflow file in one repo, several
#     workflows in one repo, one workflow in every repo matching "svc-*", and the
#     whole of one named repo - four attachment shapes, one minimal policy each
#   - run_policies limited by a `repositories` list: a strict policy on the two
#     money repos and a dry-run trial on the three service repos, next to an
#     org-wide policy so the plan shows all_repos = true against an explicit list
#   - checks with an explicit `repos` list for the required check and ["*"] +
#     omit_repos for the optional and baseline checks
#   - policy_driven_prs with an explicit selected_repos list, and the ["*"] +
#     excluded_repos + selected_repos_filter (topics) variant commented out beside it
#   - suppression_rules narrowed to repo + workflow + job, and one that stops at the
#     workflow so the job wildcard "*" is visible in the plan
#
# Run (from the repo root):
#   cd stepsecurity && terraform plan -var-file=examples/05-repo-and-workflow-scoped.tfvars
#
# Credentials never live in a tfvars file - export them first:
#   export STEP_SECURITY_CUSTOMER=<tenant name> STEP_SECURITY_API_KEY=<api key>
#
# Expected plan: 15 resources to add
#   stepsecurity_github_policy_store.this["<key>"]             x4  deploy-prod, release-pipeline, svc-ci, web-frontend
#   stepsecurity_github_policy_store_attachment.this["<key>"]  x4  the same four keys
#   stepsecurity_github_run_policy.this["<key>"]               x3  critical-repos-strict, svc-runners-dry-run, org-secrets-baseline
#   stepsecurity_github_checks.this["acme-corp"]               x1  required / optional / baseline scopes
#   stepsecurity_policy_driven_pr.this["acme-corp"]            x1  explicit selected_repos
#   stepsecurity_github_supression_rule.this["<key>"]          x2  payments-ci-codecov-upload, infra-deploy-terraform-registry
#
# All eight input maps are set (notifications and pr_templates to {}), so this
# file fully overrides the auto-loaded terraform.tfvars. Repos used throughout:
# payments-api, billing-worker, infra-live (critical), svc-orders, svc-inventory,
# svc-search (services), web-frontend, sandbox, docs-site.
# =============================================================================

# ===== Tenant-wide settings (variables.tf) ===================================
# Scoping is decided per entry, so this scenario changes none of the tenant-wide
# defaults; everything in this section stays commented out and shows the module
# default. Policy (d) below and the `checks` entry rely on two of them.
# Provider auth - keep these commented out; the provider reads the env vars.
# customer     = "acme"                        # optional: StepSecurity tenant name (default: null -> STEP_SECURITY_CUSTOMER env var)
# api_key      = "<never put a real key here>" # optional: API key (default: null -> STEP_SECURITY_API_KEY env var); sensitive, must never be committed
# api_base_url = "https://api.stepsecurity.io" # optional: override the API base URL (default: null -> provider default)

# default_egress_policy = "audit" # optional: mode for egress policies that omit egress_policy: audit = log only | block = drop unlisted endpoints (default: audit) - policy (d) below falls back to it

# base_allowed_endpoints = [                              # optional: host:port endpoints every GitHub-hosted job needs; prepended to each egress policy's allowed_endpoints (default below) - see 02-egress-policies.tfvars
#   "github.com:443",                                     #   git clone / push over HTTPS
#   "api.github.com:443",                                 #   GitHub REST API
#   "codeload.github.com:443",                            #   tarball downloads (actions/checkout, gh release)
#   "objects.githubusercontent.com:443",                  #   release assets and LFS objects
#   "*.actions.githubusercontent.com:443",                #   action downloads, cache, artifacts
#   "results-receiver.actions.githubusercontent.com:443", #   job result upload
#   "ghcr.io:443",                                        #   GitHub container registry
#   "pkg-containers.githubusercontent.com:443",           #   container layer downloads
# ]

# default_check_controls = [                                                   # optional: controls for any `checks` entry without its own `controls` list (default below) - the checks entry below uses it; see the checks example for custom lists
#   { control = "NPM Package Cooldown", settings = { cool_down_period = 3 } },  #   required: fail when an npm package was published less than 3 days ago
#   { control = "PyPI Package Cooldown", settings = { cool_down_period = 3 } }, #   required: same for PyPI
#   { control = "PWN Request" },                                                #   required: pull_request_target misuse
#   { control = "Script Injection", type = "optional" },                        #   optional (non-blocking): untrusted input interpolated into run: scripts
# ]

# default_notification_email = "sec@example.com" # optional: email for `notifications` entries that omit `email` (default: null = no email) - see the notifications example

# default_notification_events = {                # optional: baseline on/off per event; a notifications entry's `events` map is merged over it (default below) - see the notifications example
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
#   run_blocked_by_policy                 = true  #   a run policy blocked a workflow run
#   baseline_check_failures               = false #   baseline PR check failed
#   required_check_failures               = true  #   required PR check failed
#   optional_check_failures               = false #   optional PR check failed
# }

# notification_webhooks = { "acme-corp" = { slack_webhook_url = "...", teams_webhook_url = "..." } } # SECRET, never here: copy examples/secrets.auto.tfvars.example to stepsecurity/secrets.auto.tfvars (git-ignored) or set TF_VAR_notification_webhooks (default: {})

# ===== Harden-Runner egress policies (policy_store.tf), keyed by policy name =
# One minimal policy per attachment shape below - the attachment map key MUST
# equal the policy key, so the scope of a policy is read off the entry with the
# same name in egress_policy_attachments. What each policy allows is not the
# point of this example (02-egress-policies.tfvars covers every attribute);
# each entry sets only its org, its mode and the endpoints its workflows need.
egress_policies = {

  # (a) Production deploys from infra-live: block mode, AWS + Terraform registry
  #     on top of var.base_allowed_endpoints. Attached to ONE workflow file.
  "deploy-prod" = {
    owner         = "acme-corp"     # GitHub org this policy belongs to (required)
    egress_policy = "block"         # audit = log egress only | block = drop anything not in allowed_endpoints; omitted -> var.default_egress_policy
    allowed_endpoints = [           # host:port entries appended after var.base_allowed_endpoints (include_base_endpoints defaults to true); wildcards like "*.amazonaws.com:443" ok
      "sts.amazonaws.com:443",      # AWS STS - OIDC role assumption
      "*.amazonaws.com:443",        # every other AWS API, incl. the S3 state bucket
      "registry.terraform.io:443",  # Terraform provider index
      "releases.hashicorp.com:443", # Terraform provider binaries
    ]
    # name                    = "deploy-prod"       # optional: dashboard policy name (default: the map key)
    # include_base_endpoints  = false               # optional: false leaves var.base_allowed_endpoints out of this policy (default: true)
    # denied_endpoints        = ["pastebin.com"]    # optional: hostnames only, no port; deny-list mode - the allow-list is dropped when this is set (default: null)
    # disable_sudo            = true                # optional: remove sudo inside the job (default: false)
    # disable_file_monitoring = true                # optional: stop watching for source-file overwrites (default: false)
    # disable_telemetry       = true                # optional: stop sending harden-runner telemetry to StepSecurity (default: false)
    # lockdown                = { enabled = true }  # optional: stop the job on privileged_container / reverse_shell / runner_worker_memory_read detections, each default true (default: null = no lockdown)
  }

  # (b) Release pipeline of payments-api: block mode, npm + Docker Hub on top of
  #     the base list. Attached to TWO workflow files of one repo.
  "release-pipeline" = {
    owner         = "acme-corp"               # GitHub org this policy belongs to (required)
    egress_policy = "block"                   # block = drop anything not in allowed_endpoints (audit = log only)
    allowed_endpoints = [                     # appended after var.base_allowed_endpoints
      "registry.npmjs.org:443",               # npm ci
      "registry-1.docker.io:443",             # Docker Hub manifests
      "auth.docker.io:443",                   # Docker Hub token exchange
      "production.cloudflare.docker.com:443", # Docker Hub image layers
    ]
    # every other attribute is optional and shown commented out in (a)
  }

  # (c) CI of every service repo: audit mode (log only, nothing blocked), so a
  #     new svc-* repo is observed from its first run. Attached to ONE workflow
  #     file across every repo matching the "svc-*" pattern.
  "svc-ci" = {
    owner         = "acme-corp" # GitHub org this policy belongs to (required)
    egress_policy = "audit"     # audit = log egress only; allowed_endpoints is left at [] because nothing is enforced yet
    # every other attribute is optional and shown commented out in (a)
  }

  # (d) The web-frontend repo, every workflow in it. egress_policy is omitted on
  #     purpose: the plan renders var.default_egress_policy ("audit"). Attached
  #     to the WHOLE repo.
  "web-frontend" = {
    owner = "acme-corp" # GitHub org this policy belongs to (required)
    # egress_policy = "block" # optional: audit | block (default: omitted -> var.default_egress_policy = audit)
    # every other attribute is optional and shown commented out in (a)
  }
}

# ===== Where each egress policy applies (policy_store.tf) ====================
# Key MUST equal an egress_policies key. Pick exactly ONE of the three shapes per entry:
#   org_wide = true        every repo and workflow in the org; policy_store.tf then ignores `repositories`
#   repositories = [...]   a list of { name, workflows } entries - the four shapes shown below (the default, org_wide = false)
#   clusters = [...]       Harden-Runner for Kubernetes cluster names; policy_store.tf then sends no org attachment at all
# Scope rules for one { name, workflows } entry:
#   name       an exact repo name, or a pattern with "*" ("svc-*", "*-api", "*" = every repo); consecutive stars ("**") are rejected
#   workflows  omitted -> the whole repo, every workflow, now and later (the provider sets apply_to_repo = true); only allowed with an exact name
#              [...]   -> only these workflow FILE names as in .github/workflows/ (ci.yml); no wildcards inside a name; apply_to_repo becomes false
#   a pattern MUST list workflows: it means "this workflow file in every matching repo", never "every workflow of every matching repo"
# Precedence: when a job is covered by more than one attachment the most specific one
# wins - a workflow-level attachment beats a whole-repo attachment, which beats org_wide.
# Nothing here takes effect until the job's harden-runner step runs with `use-policy-store: true`.
egress_policy_attachments = {

  # (a) One workflow file in one repo: only infra-live's deploy-prod.yml runs
  #     under the block-mode deploy policy; the repo's other workflows keep
  #     whatever policy is attached at repo or org level (none in this file).
  "deploy-prod" = {
    repositories = [                                            # repo / workflow attachments (org_wide stays false)
      { name = "infra-live", workflows = ["deploy-prod.yml"] }, # exact repo name + one workflow file; add more { name, workflows } entries to attach the same policy elsewhere
    ]
    # org_wide = true         # optional: every repo and workflow in the org instead of the list above (default: false)
    # clusters = ["prod-eks"] # optional: Harden-Runner for Kubernetes cluster names; replaces the org attachment when set (default: null)
  }

  # (b) Several workflows in one repo: payments-api's release and image-publish
  #     workflows share the release policy; its ci.yml is NOT covered.
  "release-pipeline" = {
    repositories = [                                                               # repo / workflow attachments
      { name = "payments-api", workflows = ["release.yml", "publish-image.yml"] }, # one repo, two workflow files; each name must be a plain file name (no "*")
    ]
  }

  # (c) A pattern: ci.yml in every repo whose name starts with "svc-" - today
  #     svc-orders, svc-inventory and svc-search, and any svc-* repo created
  #     later. Because the name is a pattern, `workflows` is mandatory.
  "svc-ci" = {
    repositories = [                              # repo / workflow attachments
      { name = "svc-*", workflows = ["ci.yml"] }, # "*" pattern + the workflow file it applies to; { name = "svc-*" } alone would be rejected at plan time
    ]
  }

  # (d) A whole repo: every workflow in web-frontend, present and future. Only
  #     an exact name may omit `workflows`.
  "web-frontend" = {
    repositories = [             # repo / workflow attachments
      { name = "web-frontend" }, # exact repo name, workflows omitted = the entire repo (apply_to_repo = true)
    ]
  }
}

# ===== Run policies (run_policies.tf), keyed by policy name ==================
# Scope field: `repositories`.
#   omitted / null   every repo in the org, now and in the future; run_policies.tf sets all_repos = true - see (c)
#   ["a", "b"]       only these repos, by exact name (this field has no "*" patterns, unlike the attachments above); the plan then renders all_repos = false - see (a), (b)
# Precedence: run policies never override each other. Every policy whose scope
# covers the repo is evaluated on each run and the run must pass ALL of them,
# so a repo-scoped policy ADDS rules on top of an org-wide one. To relax a
# rule for some repos, take them out of the wider policy's scope instead.
# 03-run-policies.tfvars explains every policy_config attribute.
run_policies = {

  # (a) Strict, on the two money repos only: SHA-pinned actions, Harden-Runner
  #     with a policy-store policy on every job, and no compromised actions.
  #     Every other repo in acme-corp is untouched by this entry.
  "critical-repos-strict" = {
    owner        = "acme-corp"                                # GitHub org this policy belongs to (required)
    repositories = ["payments-api", "billing-worker"]         # exact repo names, so the plan renders all_repos = false; every other repo in the org is ignored (omitted -> all repos)
    policy = {                                                # the provider's policy_config block, passed through verbatim by run_policies.tf
      enable_action_policy              = true                # allowed-actions policy on (default: omitted = off)
      require_pinned_actions            = true                # every `uses:` must reference a full-length commit SHA (default: omitted = false)
      allowed_actions                   = { "*/*" = "allow" } # every action is allowed, so this entry enforces pinning only; narrower keys: "owner/repo", "owner/*", "owner/repo@ref"
      enable_harden_runner_policy       = true                # every targeted job must run step-security/harden-runner (default: omitted = off)
      harden_runner_target_labels       = []                  # [] = every job | ["ubuntu-latest"] = only jobs whose runs-on matches | omitted = leave the backend value untouched
      require_policy_store              = true                # the harden-runner step must set `use-policy-store: true`, so the egress policies above actually apply (default: omitted = false)
      enable_compromised_actions_policy = true                # block runs that use an action version StepSecurity flagged as compromised (default: omitted = off)
      # is_dry_run                      = true                        # optional: report instead of block (default: false) - see (b)
      # actions_to_exempt_while_pinning = ["acme-corp/*"]             # optional: actions that may stay on a tag although pinning is required; "*/*" is rejected here (default: omitted = none)
      # harden_runner_custom_actions    = ["acme-corp/ci-bootstrap"]  # optional: extra actions accepted as Harden-Runner equivalents (default: omitted = only step-security/harden-runner)
      # block_job_container             = true                        # optional: block targeted jobs that run entirely inside a job-level container: (default: omitted = false)
      # pr_comment_template             = "..."                       # optional: custom Markdown for the PR comment posted when this policy blocks a run (default: omitted = StepSecurity's standard comment)
    }
    # name = "Critical repos - strict" # optional: name shown in the StepSecurity dashboard (default: the map key "critical-repos-strict")
  }

  # (b) Dry-run trial on the three service repos: the same set the "svc-*"
  #     attachment matches, spelled out by hand because this field has no
  #     patterns. Nothing is blocked yet; violations show up in the dashboard
  #     and as PR comments until is_dry_run is dropped.
  "svc-runners-dry-run" = {
    owner        = "acme-corp"                                   # GitHub org this policy belongs to (required)
    repositories = ["svc-orders", "svc-inventory", "svc-search"] # exact repo names; a new svc-* repo must be added here by hand
    policy = {                                                   # provider policy_config block
      is_dry_run               = true                            # report what would be blocked without blocking the run (default: false)
      enable_runs_on_policy    = true                            # runs-on (runner label) policy on (default: omitted = off)
      disallowed_runner_labels = ["self-hosted"]                 # jobs whose runs-on contains this label are flagged (default: omitted = none)
      # runs_on_mode                  = "disallowed"            # optional: disallowed = block listed labels (default) | allowed = permit only allowed_runner_labels / allowed_runner_constraints
      # allowed_runner_labels         = ["acme-ubuntu-8core"]   # optional: plain labels permitted in allowed mode; ignored in disallowed mode (default: omitted)
      # allowed_runner_constraints    = { family = ["m7a"] }    # optional: runs-on.com key=value constraints permitted in allowed mode (default: omitted)
      # enable_standard_runner_labels = true                    # optional: also add GitHub's standard hosted labels to disallowed_runner_labels (default: omitted = false)
    }
  }

  # (c) Org-wide contrast: `repositories` is omitted, so the plan renders
  #     all_repos = true and the policy covers every repo, including (a)'s and
  #     (b)'s - their runs must satisfy this entry AND their own.
  "org-secrets-baseline" = {
    owner = "acme-corp" # GitHub org this policy belongs to (required)
    # repositories = ["payments-api"]              # optional: limit to these repos (default: null = every repo in the org, all_repos = true)
    policy = {                                     # provider policy_config block
      enable_secrets_policy  = true                # secrets (exfiltration) policy on (default: omitted = off)
      bulk_secrets_only_mode = true                # true = enforce only high-risk bulk exposure such as toJSON(secrets) | false = every secret reference (default: omitted = false)
      exempted_users         = ["dependabot[bot]"] # GitHub users / bots whose runs skip this policy (default: omitted = nobody)
      # secrets_analyze_default_branch = true # optional: also evaluate default-branch runs; by default only non-default-branch runs are checked (default: omitted = false)
      # is_dry_run                     = true # optional: report instead of block (default: false) - see (b)
    }
  }
}

# ===== PR checks (checks.tf), keyed by org ===================================
# StepSecurity posts up to three GitHub checks on a pull request, each with its
# own repo scope inside the org's single `checks` entry:
#   required_checks   the required check: controls with type = "required" run here; make it a required status check in branch protection to block merges
#   optional_checks   the optional check: controls with type = "optional" run here; informational, never blocks
#   baseline_check    the baseline check, reported separately from the two above (see the checks example for what it evaluates)
# Scope rules, identical for all three:
#   repos = ["a", "b"]                   exact repo names; omit_repos is NOT allowed with an explicit list
#   repos = ["*"]                        every repo in the org, including repos created later
#   repos = ["*"], omit_repos = [...]    every repo except these; omit_repos is only valid together with ["*"]
#   block omitted                        that check is not installed anywhere in the org
# The three scopes are independent: a repo may sit in all of them or in none.
checks = {

  # Merge-blocking checks on the three critical repos only; informational and
  # baseline checks everywhere except the sandboxes. Controls come from
  # var.default_check_controls because `controls` is omitted.
  "acme-corp" = {
    required_checks = { repos = ["payments-api", "billing-worker", "infra-live"] } # explicit list: only these repos get the merge-blocking check; a new repo must be added here by hand; adding omit_repos here would be rejected
    optional_checks = { repos = ["*"], omit_repos = ["sandbox", "docs-site"] }     # every repo, present and future, except the two listed; omit_repos is only valid next to "*"
    baseline_check  = { repos = ["*"], omit_repos = ["sandbox"] }                  # every repo except sandbox
    # custom_description = "Questions? Ask #security on Slack."                                                                # optional: text appended to every check summary (default: null)
    # controls = [                                                                                                              # optional: which controls run and in which check type (default: null -> var.default_check_controls)
    #   { control = "NPM Package Cooldown", settings = { cool_down_period = 5, packages_to_exempt_in_cooldown_check = ["lodash"] } }, # settings only apply to the cooldown controls; cool_down_period in days (provider default: 2)
    #   { control = "PyPI Package Cooldown", settings = { cool_down_period = 5 } },                                             # enable defaults to true, type to "required"
    #   { control = "Maven Package Cooldown" },                                                                                 # other names: "NuGet Package Cooldown", "Compromised Updates", "PWN Request", "Script Injection"
    #   { control = "Script Injection", enable = true, type = "optional" },                                                     # type = required (runs in the required check) | optional (runs in the optional check); enable = false keeps the entry but turns it off
    # ]
  }
}

# ===== Notifications (notifications.tf), keyed by org ========================
notifications = {} # email / Slack / Teams channels and which events fire per org - not used here; see the notifications example in this directory

# ===== Policy-driven PRs (policy_driven_prs.tf), keyed by org ================
# Scope fields:
#   selected_repos = ["a", "b"]   explicit list - exactly these repos get remediation PRs; excluded_repos and selected_repos_filter must not be set with it
#   selected_repos = ["*"]        every repo in the org, now and later (the module default), narrowed by:
#     selected_repos_filter.include_repos_only_with_topics   keep only repos carrying these GitHub topics (valid only with ["*"])
#     excluded_repos                                          drop these repos; StepSecurity restores or deletes their config (valid only with ["*"])
#   a repo under ["*"] gets PRs only if it passes the topic filter AND is not excluded
# Turning this on opens PRs in every selected repo, so start with an explicit
# list (README "Rollout advice"). See the policy-driven-PRs example for every
# auto_remediation_options attribute.
policy_driven_prs = {

  # Variant A (live): only the three critical repos get remediation PRs.
  "acme-corp" = {
    selected_repos = ["payments-api", "billing-worker", "infra-live"] # exact repo names (default: ["*"] = every repo); with a list, excluded_repos / selected_repos_filter are not allowed
    # Variant B (commented): every repo, filtered by topic, minus exclusions - swap the line above for these three
    # selected_repos        = ["*"]                                                        # every repo in the org, including repos created later
    # selected_repos_filter = { include_repos_only_with_topics = ["production", "tier-1"] } # optional: only repos tagged with these GitHub topics; valid only with ["*"] (default: null = no topic filter)
    # excluded_repos        = ["sandbox", "docs-site"]                                     # optional: never open PRs in these; valid only with ["*"] (default: null = nothing excluded)
    auto_remediation_options = {               # what the PRs fix - the provider block, passed through verbatim
      create_pr                         = true # open a pull request per finding (default: true); set false and create_issue = true to open issues instead
      pin_actions_to_sha                = true # replace `uses: owner/action@v4` with the full commit SHA (default: true)
      harden_github_hosted_runner       = true # add a step-security/harden-runner step to every job (default: true)
      restrict_github_token_permissions = true # add a least-privilege `permissions:` block (default: true)
      # create_issue                                  = false                     # optional: open a GitHub issue per finding (default: false)
      # create_github_advanced_security_alert         = false                     # optional: also raise a GHAS alert; only fires when create_issue is true (default: false)
      # secure_docker_file                            = false                     # optional: pin Dockerfile base images to a digest (default: false)
      # replace_action_on_major_tag_match             = true                      # optional: replace listed actions only when the major tag matches; needs actions_to_replace_with_step_security_actions (default: null)
      # update_existing_configuration                 = true                      # optional: let dependabot drop entries not in package_ecosystem (default: null)
      # actions_to_exempt_while_pinning               = ["acme-corp/*"]           # optional: actions left on their tag when pinning (default: null)
      # images_to_exempt_while_pinning                = ["ubuntu"]                # optional: Docker images left unpinned (default: null)
      # actions_to_replace_with_step_security_actions = ["actions/cache"]         # optional: swap these for StepSecurity-maintained forks (default: null)
      # actions_exempted_from_replacement             = ["actions/checkout"]      # optional: replace ALL maintained actions except these; mutually exclusive with the line above (default: null)
      # harden_runner_config = {                                                  # optional: how the harden-runner step is written (default: null = StepSecurity's default step)
      #   config                        = "egress-policy: audit"                  #   optional: YAML for the step's `with:` block
      #   target_runner_labels          = ["ubuntu-latest"]                       #   optional: only add the step to jobs with these runs-on labels
      #   exempt_runner_labels          = ["gpu-*"]                               #   optional: glob patterns of runs-on labels to skip
      #   update_existing_configuration = true                                    #   optional: rewrite harden-runner steps that already exist
      # }
      # package_ecosystem = [                                                     # optional: dependabot ecosystems the PR configures (default: null)
      #   { package = "npm", interval = "weekly", cooldown_yaml = "default-days: 3", groups_yaml = "dev-deps:\n  dependency-type: development" }, # package = npm | pip | docker | ...; interval = daily | weekly | monthly
      # ]
    }
  }
}

# ===== PR template for those PRs (policy_driven_prs.tf), keyed by org ========
pr_templates = {} # title / summary / commit message / labels / branch name of the remediation PRs - not used here (StepSecurity's default template is used); see the policy-driven-PRs example in this directory

# ===== Suppression rules (suppressions.tf), keyed by rule name ===============
# Scope fields - a detection is ignored only when EVERY field matches:
#   owner      org name, or "*" for every org in the tenant (required)
#   repo       repo name, or "*" for any repo of that org (default: "*")
#   workflow   workflow file name as in .github/workflows/ (ci.yml), or "*" for any workflow (default: "*")
#   job        job name as shown in the Actions run, or "*" for any job (default: "*")
# Each field narrows the previous one; leaving all three at "*" silences the
# detection everywhere in the org, so scope a rule as tightly as the finding
# allows. The remaining fields depend on `type`: anomalous_outbound_network_call
# needs process + destination { domain | ip }, https_outbound_network_call needs
# host + file_path; see the suppression-rules example for the other types.
suppression_rules = {

  # (a) Fully scoped - repo + workflow + job: the coverage upload made by the
  #     unit-tests job of payments-api's ci.yml. The same call from any other
  #     job, workflow or repo is still reported.
  "payments-ci-codecov-upload" = {
    owner       = "acme-corp"                                           # org the rule applies to; "*" = every org in the tenant (required)
    type        = "anomalous_outbound_network_call"                     # detection type this rule silences
    description = "Coverage upload from the unit-tests job is expected" # free text shown in the dashboard (optional)
    repo        = "payments-api"                                        # only this repo (default: "*" = any repo)
    workflow    = "ci.yml"                                              # only this workflow file (default: "*" = any workflow)
    job         = "unit-tests"                                          # only this job (default: "*" = any job)
    process     = "codecov"                                             # process that makes the call; exact name or wildcard such as "*" (required for this type)
    destination = { domain = "*.codecov.io" }                           # where it calls; set domain OR ip, not both (required for this type)
    # destination = { ip = "192.168.*.1" } # alternative: IP with wildcards instead of a domain
  }

  # (b) Repo + workflow only: terraform init in infra-live's deploy workflow
  #     fetches the provider index; job is set to "*" explicitly, which is the
  #     same as omitting it - every job of that workflow is covered.
  "infra-deploy-terraform-registry" = {
    owner     = "acme-corp"                   # org the rule applies to (required)
    type      = "https_outbound_network_call" # anomalous-HTTPS-call detection
    repo      = "infra-live"                  # only this repo
    workflow  = "deploy-prod.yml"             # only this workflow file
    job       = "*"                           # every job in that workflow - the default, written out to show the wildcard in the plan
    host      = "registry.terraform.io"       # host of the HTTPS call to ignore (required for this type)
    file_path = "/.well-known/terraform.json" # path part of the HTTPS request URL; the provider requires it for this type (a rule without it is rejected at plan time)
    # description   = "..."                     # optional: free text (default: null)
    # file_path     = "infra/"                  # for source_code_overwritten: directory of the overwritten file (default: null); for https_outbound_network_call it is the URL path and is required (set live above)
    # secret_type   = "GitHub Token"            # only for secret_in_build_log / secret_in_artifact
    # artifact_name = "build-logs"              # only for secret_in_artifact
    # endpoint      = "203.0.113.10:4444"       # only for suspicious_network_call
    # file          = "package-lock.json"       # only for source_code_overwritten
    # github_action = "acme-corp/ci-bootstrap"  # only for action_uses_imposter_commit
    # process       = "*"                       # only for anomalous_outbound_network_call, runner_worker_memory_read, privileged_container, reverse_shell
  }
}
