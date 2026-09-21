# Org notification settings. Webhook URLs come from the sensitive
# var.notification_webhooks map so they never appear in terraform.tfvars.

resource "stepsecurity_github_org_notification_settings" "this" {
  for_each = var.notifications

  owner = each.key

  notification_channels = {
    email                     = try(each.value.email, var.default_notification_email)
    slack_webhook_url         = try(var.notification_webhooks[each.key].slack_webhook_url, null)
    teams_webhook_url         = try(var.notification_webhooks[each.key].teams_webhook_url, null)
    slack_channel_id          = try(each.value.slack_channel_id, null)
    slack_notification_method = try(each.value.slack_channel_id, null) != null ? "oauth" : null
  }

  notification_events = merge(var.default_notification_events, try(each.value.events, {}))
  threat_intel        = try(each.value.threat_intel, null)
}
