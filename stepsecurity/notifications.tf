# Org notification settings. Import ID: "<org>". Webhook URLs come from the
# sensitive var.notification_webhooks map so they never appear in terraform.tfvars.
# Provider attributes not exposed by this layout: none.

resource "stepsecurity_github_org_notification_settings" "this" { # one per org in var.notifications
  for_each = var.notifications                                    # map key = org name

  owner = each.key # the org

  notification_channels = {                                                                      # where alerts go
    email                     = try(each.value.email, var.default_notification_email)            # the entry's email, else the tenant default
    slack_webhook_url         = try(var.notification_webhooks[each.key].slack_webhook_url, null) # from the secrets map; null if absent
    teams_webhook_url         = try(var.notification_webhooks[each.key].teams_webhook_url, null) # same for Teams
    slack_channel_id          = try(each.value.slack_channel_id, null)                           # Slack OAuth channel
    slack_notification_method = try(each.value.slack_channel_id, null) != null ? "oauth" : null  # oauth when a channel id is set, else webhook
  }

  notification_events = merge(var.default_notification_events, try(each.value.events, {})) # tenant baseline, overridden by the entry's events
  threat_intel        = try(each.value.threat_intel, null)                                 # { enabled, level }; omitted → provider default
}
