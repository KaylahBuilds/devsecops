# Suppression rules: silence detections you have reviewed and accepted.
# Types: secret_in_build_log, secret_in_artifact, anomalous_outbound_network_call,
# suspicious_network_call, https_outbound_network_call, source_code_overwritten,
# action_uses_imposter_commit, runner_worker_memory_read, privileged_container, reverse_shell.

resource "stepsecurity_github_supression_rule" "this" {
  for_each = var.suppression_rules

  name        = each.key
  owner       = each.value.owner
  type        = each.value.type
  action      = "ignore" # the only action StepSecurity supports today
  description = try(each.value.description, null)

  repo     = try(each.value.repo, "*")
  workflow = try(each.value.workflow, "*")
  job      = try(each.value.job, "*")

  process       = try(each.value.process, null)
  secret_type   = try(each.value.secret_type, null)
  artifact_name = try(each.value.artifact_name, null)
  endpoint      = try(each.value.endpoint, null)
  host          = try(each.value.host, null)
  file          = try(each.value.file, null)
  file_path     = try(each.value.file_path, null)
  github_action = try(each.value.github_action, null)
  destination   = try(each.value.destination, null)
}
