# Org notification settings: where alerts go and which events fire.
# Webhook URLs are read from the sensitive var.notification_webhooks map so
# they never appear in terraform.tfvars.

resource "stepsecurity_github_org_notification_settings" "this" {
  for_each = local.notifications

  owner = each.key

  notification_channels = {
    email                     = each.value.email != null ? each.value.email : var.default_notification_email
    slack_webhook_url         = try(var.notification_webhooks[each.key].slack_webhook_url, null)
    teams_webhook_url         = try(var.notification_webhooks[each.key].teams_webhook_url, null)
    slack_channel_id          = each.value.slack_channel_id
    slack_notification_method = each.value.slack_channel_id != null ? "oauth" : null
  }

  notification_events = merge(var.default_notification_events, each.value.events)

  threat_intel = each.value.threat_intel
}
