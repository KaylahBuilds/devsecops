# Suppression rules: silence detections you have reviewed and accepted.
# Types: secret_in_build_log, secret_in_artifact, anomalous_outbound_network_call,
# suspicious_network_call, https_outbound_network_call, source_code_overwritten,
# action_uses_imposter_commit, runner_worker_memory_read, privileged_container, reverse_shell.
# The provider does not document an import ID for this resource.

resource "stepsecurity_github_supression_rule" "this" { # one per var.suppression_rules entry
  for_each = var.suppression_rules                      # map key = rule name

  name        = each.key                          # rule name shown in the dashboard
  owner       = each.value.owner                  # org, or "*" for every org (required)
  type        = each.value.type                   # detection type, see the list above (required)
  action      = "ignore"                          # the only action StepSecurity supports today
  description = try(each.value.description, null) # why this is acceptable and who reviewed it

  repo     = try(each.value.repo, "*")     # scope: repo name or "*"
  workflow = try(each.value.workflow, "*") # scope: workflow file or "*"
  job      = try(each.value.job, "*")      # scope: job name or "*"

  process       = try(each.value.process, null)       # REQUIRED for anomalous_outbound_network_call, runner_worker_memory_read, privileged_container, reverse_shell
  secret_type   = try(each.value.secret_type, null)   # REQUIRED for secret_in_build_log and secret_in_artifact
  artifact_name = try(each.value.artifact_name, null) # REQUIRED for secret_in_artifact
  endpoint      = try(each.value.endpoint, null)      # REQUIRED for suspicious_network_call
  host          = try(each.value.host, null)          # REQUIRED for https_outbound_network_call
  file          = try(each.value.file, null)          # REQUIRED for source_code_overwritten
  file_path     = try(each.value.file_path, null)     # REQUIRED for https_outbound_network_call (calling program, "*" = any); optional for source_code_overwritten
  github_action = try(each.value.github_action, null) # REQUIRED for action_uses_imposter_commit
  destination   = try(each.value.destination, null)   # REQUIRED for anomalous_outbound_network_call: { domain } or { ip }
}
