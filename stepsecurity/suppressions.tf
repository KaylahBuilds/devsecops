# Suppression rules: silence detections you have reviewed and accepted.

resource "stepsecurity_github_supression_rule" "this" {
  for_each = var.suppression_rules

  name        = each.key
  owner       = each.value.owner
  type        = each.value.type
  action      = "ignore" # the only action StepSecurity supports today
  description = each.value.description

  repo     = each.value.repo
  workflow = each.value.workflow
  job      = each.value.job

  process       = each.value.process
  secret_type   = each.value.secret_type
  artifact_name = each.value.artifact_name
  endpoint      = each.value.endpoint
  host          = each.value.host
  file          = each.value.file
  file_path     = each.value.file_path
  github_action = each.value.github_action
  destination   = each.value.destination
}
