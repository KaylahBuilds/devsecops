# ---------------------------------------------------------------------------
# Per-repo controls: one egress policy + attachment and two run policies for
# every repo in var.repos. A value is taken from repo_settings[<repo>] when
# set, otherwise from the org/tenant settings.
# ---------------------------------------------------------------------------

# --- Harden-Runner egress policy per repo ----------------------------------
resource "stepsecurity_github_policy_store" "repo" {
  for_each = toset(var.repos)

  owner         = var.org
  policy_name   = "repo-${each.key}"
  egress_policy = try(var.repo_settings[each.key].egress_policy, var.settings.egress_policy)

  allowed_endpoints = distinct(concat(
    var.base_allowed_endpoints,
    var.settings.allowed_endpoints,
    try(var.repo_settings[each.key].allowed_endpoints, []),
  ))

  lockdown = try(var.repo_settings[each.key].lockdown, var.settings.lockdown) ? {
    enabled                   = true
    privileged_container      = true
    reverse_shell             = true
    runner_worker_memory_read = true
  } : null
}

resource "stepsecurity_github_policy_store_attachment" "repo" {
  for_each = toset(var.repos)

  owner       = var.org
  policy_name = stepsecurity_github_policy_store.repo[each.key].policy_name

  org = {
    apply_to_org = false
    repositories = [{
      name      = each.key
      workflows = try(var.repo_settings[each.key].workflows, var.settings.workflows)
    }]
  }
}

# --- Harden-Runner must run in every job of the repo -----------------------
resource "stepsecurity_github_run_policy" "harden_runner" {
  for_each = toset(var.repos)

  owner        = var.org
  name         = "repo-${each.key}-harden-runner"
  repositories = [each.key]

  policy_config = {
    owner                       = var.org
    name                        = "repo-${each.key}-harden-runner"
    enable_harden_runner_policy = try(var.repo_settings[each.key].require_harden_runner, var.settings.require_harden_runner)
    harden_runner_target_labels = []
    require_policy_store        = true
    is_dry_run                  = try(var.repo_settings[each.key].dry_run, var.settings.dry_run)
  }
}

# --- Pinning guard: only SHA-pinned, allowed actions -----------------------
resource "stepsecurity_github_run_policy" "pinned_actions" {
  for_each = toset(var.repos)

  owner        = var.org
  name         = "repo-${each.key}-pinned-actions"
  repositories = [each.key]

  policy_config = {
    owner                           = var.org
    name                            = "repo-${each.key}-pinned-actions"
    enable_action_policy            = try(var.repo_settings[each.key].require_pinned_actions, var.settings.require_pinned_actions)
    require_pinned_actions          = try(var.repo_settings[each.key].require_pinned_actions, var.settings.require_pinned_actions)
    allowed_actions                 = try(var.repo_settings[each.key].allowed_actions, var.settings.allowed_actions)
    actions_to_exempt_while_pinning = try(var.repo_settings[each.key].actions_to_exempt_while_pinning, var.settings.actions_to_exempt_while_pinning)
    is_dry_run                      = try(var.repo_settings[each.key].dry_run, var.settings.dry_run)
  }
}

# ---------------------------------------------------------------------------
# Org-level controls: one of each per org, covering the same repo list.
# ---------------------------------------------------------------------------

# --- Block runs that use a known-compromised action, org-wide --------------
resource "stepsecurity_github_run_policy" "compromised_actions" {
  count = var.settings.compromised_actions_policy ? 1 : 0

  owner     = var.org
  name      = "org-compromised-actions"
  all_repos = true

  policy_config = {
    owner                             = var.org
    name                              = "org-compromised-actions"
    enable_compromised_actions_policy = true
    is_dry_run                        = var.settings.dry_run
  }
}

# --- PR checks (package cooldown, PWN request, script injection) -----------
resource "stepsecurity_github_checks" "org" {
  owner    = var.org
  controls = var.settings.check_controls == null ? var.default_check_controls : var.settings.check_controls

  required_checks = {
    repos      = var.repos
    omit_repos = length(var.settings.checks_omit_repos) > 0 ? var.settings.checks_omit_repos : null
  }
}

# --- Remediation PRs: harden-runner, pinned SHAs, Dependabot ---------------
resource "stepsecurity_policy_driven_pr" "org" {
  count = var.settings.remediation_prs ? 1 : 0

  owner          = var.org
  selected_repos = var.repos

  auto_remediation_options = {
    create_pr                         = true
    harden_github_hosted_runner       = true
    pin_actions_to_sha                = true
    restrict_github_token_permissions = true
    actions_to_exempt_while_pinning   = var.settings.actions_to_exempt_while_pinning
    package_ecosystem                 = var.settings.dependabot
  }
}

# --- Notifications -----------------------------------------------------------
resource "stepsecurity_github_org_notification_settings" "org" {
  count = var.settings.notification_email == null ? 0 : 1

  owner = var.org

  notification_channels = {
    email             = var.settings.notification_email
    slack_webhook_url = try(var.webhooks.slack_webhook_url, null)
    teams_webhook_url = try(var.webhooks.teams_webhook_url, null)
  }

  notification_events = var.notification_events
}
