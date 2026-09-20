# =============================================================================
# notifications.tf — where one org's StepSecurity alerts go, and which events
# raise one.
# =============================================================================
# What this file manages
#   StepSecurity raises a DETECTION when Harden-Runner (its agent inside a
#   GitHub Actions job) or a PR check sees something unusual: an outbound call
#   to a host the job never used before, a secret printed in the build log, a
#   run blocked by a policy, ... Per org, this resource decides
#     channels      email address; Slack, either through an incoming webhook or
#                   through the StepSecurity Slack app (OAuth, addressed by
#                   channel ID); Microsoft Teams through an incoming webhook
#     events        which of the 15 event types send a notification
#     threat_intel  whether the org hears about compromised packages/actions
#                   that StepSecurity threat intel finds in its PRs and workflows
#
#   var.notifications -> stepsecurity_github_org_notification_settings   one instance per map entry, keyed by org
#
# Where the values come from
#   Entries live in terraform.tfvars (or examples/*.tfvars); the object type is
#   in inputs.tf. Two tenant-wide defaults from variables.tf fill the gaps:
#   default_notification_email (used when an entry sets no email) and
#   default_notification_events (the on/off baseline an entry's `events` map
#   is merged over). Webhook URLs are credentials, so they are NOT part of the
#   entry: this file reads them from the sensitive var.notification_webhooks
#   (git-ignored secrets.auto.tfvars — copy examples/secrets.auto.tfvars.example —
#   or TF_VAR_notification_webhooks in CI), keyed by the same org name.
#
# How to run (from stepsecurity/; credentials come from the environment)
#   export STEP_SECURITY_CUSTOMER=<tenant> STEP_SECURITY_API_KEY=<key>
#   terraform init -backend-config="key=stepsecurity/terraform.tfstate"
#   terraform plan            # uses terraform.tfvars + secrets.auto.tfvars, or -var-file=examples/07-notifications-and-suppressions.tfvars
#
# Adopting an org's existing notification settings: import ID  <org>
#   import { to = stepsecurity_github_org_notification_settings.this["acme-platform"], id = "acme-platform" }
# =============================================================================

# ===== notifications -> stepsecurity_github_org_notification_settings ========
# Minimal tfvars entry (email from var.default_notification_email, events from var.default_notification_events):
#   notifications = { "acme-platform" = {} }
resource "stepsecurity_github_org_notification_settings" "this" { # address: stepsecurity_github_org_notification_settings.this["<org>"]
  for_each = var.notifications                                    # one instance per entry of the map; each.key = GitHub org name, each.value = the entry object typed in inputs.tf

  owner = each.key # (required) GitHub org these settings belong to — the map key itself, so it is never typed twice

  # Delivery channels (provider block notification_channels, required). Every
  # attribute inside is optional; null means "no delivery that way".
  notification_channels = {                                                                                  # who receives the alerts
    email                     = each.value.email != null ? each.value.email : var.default_notification_email # inbox: the entry's `email` when set, else var.default_notification_email (variables.tf); null when both are null = no email delivery (a conditional rather than coalesce(), which would error on two nulls)
    slack_webhook_url         = try(var.notification_webhooks[each.key].slack_webhook_url, null)             # SECRET: Slack incoming-webhook URL looked up in var.notification_webhooks["<this org>"]; try() turns a missing org key or a missing attribute into null = no Slack webhook delivery
    teams_webhook_url         = try(var.notification_webhooks[each.key].teams_webhook_url, null)             # SECRET: Microsoft Teams incoming-webhook URL, same lookup; null = no Teams delivery
    slack_channel_id          = each.value.slack_channel_id                                                  # (optional) Slack channel ID ("C0123456789") for delivery through the StepSecurity Slack app; null (default) = not used
    slack_notification_method = each.value.slack_channel_id != null ? "oauth" : null                         # oauth = post through the Slack app into slack_channel_id | webhook = post to slack_webhook_url; derived: "oauth" whenever a channel ID is set, otherwise null so the provider applies its default "webhook"
  }

  # Which events notify: the tenant-wide baseline overlaid with the entry's
  # flips. merge() keeps every key of the first map and lets the second map
  # override, so the provider always receives all 15 event names.
  notification_events = merge(var.default_notification_events, each.value.events) # event name -> true/false; the entry's `events` (default {}) wins over var.default_notification_events (variables.tf)
  threat_intel        = each.value.threat_intel                                   # (optional) { enabled = true|false, level = all|name|version }; null (default) = block omitted: the org's current setting is left alone and adopted into state
  # ---- What tfvars can set on a notifications entry (all optional; the org key is the only required part)
  #   email            = "sec@example.com"   # inbox for alerts; omit -> var.default_notification_email (null = no email delivery)
  #   slack_channel_id = "C0123456789"       # Slack channel ID -> delivery through the StepSecurity Slack app (OAuth; install the app in the workspace first); omit -> webhook delivery, if var.notification_webhooks has a slack_webhook_url for the org
  #   events = {                             # event name -> true | false, merged OVER var.default_notification_events (default {} = baseline only); the 15 names, with the baseline value in parentheses:
  #     domain_blocked                        = true # (true)  Harden-Runner dropped an outbound call under a "block" egress policy
  #     file_overwrite                        = true # (true)  a job overwrote a checked-out source file
  #     new_endpoint_discovered               = true # (false) anomalous outbound call to a never-seen endpoint
  #     https_detections                      = true # (true)  anomalous HTTPS outbound call
  #     secrets_detected                      = true # (true)  secret printed in a build log
  #     artifacts_secrets_detected            = true # (true)  secret found in an uploaded artifact
  #     imposter_commits_detected             = true # (true)  action pinned to a commit that is not in its repo
  #     suspicious_network_call_detected      = true # (true)  call to a known-bad or otherwise suspicious endpoint
  #     suspicious_process_events_detected    = true # (true)  privileged container, reverse shell, runner-worker memory read
  #     harden_runner_config_changes_detected = true # (true)  a workflow's harden-runner step configuration changed
  #     non_compliant_artifact_detected       = true # (false) build artifact flagged as non-compliant
  #     run_blocked_by_policy                 = true # (true)  a run policy blocked a workflow run
  #     baseline_check_failures               = true # (false) baseline PR check failed
  #     required_check_failures               = true # (true)  required PR check failed, so the PR cannot merge
  #     optional_check_failures               = true # (false) optional (advisory) PR check failed
  #   }
  #   threat_intel = { enabled = true, level = "version" } # enabled: false = no Threat Intel alerts for this org (default true); level: all (default) = every incident | name = only packages this org uses, any version | version = only the exact compromised version; omit the block -> org's current setting kept
  # ---- Secrets: NOT in the entry. Git-ignored secrets.auto.tfvars (copy examples/secrets.auto.tfvars.example) or TF_VAR_notification_webhooks in CI:
  #   notification_webhooks = { "acme-platform" = { slack_webhook_url = "<Slack incoming-webhook URL>", teams_webhook_url = "<Teams incoming-webhook URL>" } } # key = this entry's org; each URL optional (default: none)
}
# ---- Provider attributes NOT exposed by this layout (stepsecurity v0.0.44) ---
#   none are left out of the resource: owner (map key), all five
#   notification_channels attributes, all 15 notification_events and
#   threat_intel{enabled, level} are sent. Three of them are simply not
#   settable from the `notifications` entry itself:
#   notification_channels.slack_webhook_url          read from var.notification_webhooks[<org>].slack_webhook_url (sensitive, variables.tf)
#   notification_channels.teams_webhook_url          read from var.notification_webhooks[<org>].teams_webhook_url
#   notification_channels.slack_notification_method  derived above: "oauth" when slack_channel_id is set, else null -> provider default "webhook"
#   Computed (read-only): id — equals the org name, which is also the import ID.
# -----------------------------------------------------------------------------
