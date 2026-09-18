# StepSecurity PR checks per org.

resource "stepsecurity_github_checks" "this" {
  for_each = var.checks

  owner              = each.key
  custom_description = each.value.custom_description
  controls           = coalesce(each.value.controls, var.default_check_controls)
  required_checks    = each.value.required_checks
  optional_checks    = each.value.optional_checks
  baseline_check     = each.value.baseline_check
}
