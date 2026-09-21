# StepSecurity PR checks per org.

resource "stepsecurity_github_checks" "this" {
  for_each = var.checks

  owner              = each.key
  custom_description = try(each.value.custom_description, null)
  controls           = try(each.value.controls, var.default_check_controls)
  required_checks    = try(each.value.required_checks, null)
  optional_checks    = try(each.value.optional_checks, null)
  baseline_check     = try(each.value.baseline_check, null)
}
