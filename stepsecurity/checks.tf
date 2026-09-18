# StepSecurity PR checks: which controls run on pull requests and in which
# repos they are required, optional, or baseline-only.

resource "stepsecurity_github_checks" "this" {
  for_each = local.checks

  owner              = each.key
  custom_description = each.value.custom_description

  controls = [
    for c in coalesce(each.value.controls, var.default_check_controls) : {
      control  = c.control
      enable   = c.enable
      type     = c.type
      settings = c.settings
    }
  ]

  required_checks = length(each.value.required_checks.repos) == 0 ? null : {
    repos      = each.value.required_checks.repos
    omit_repos = length(each.value.required_checks.omit_repos) > 0 ? each.value.required_checks.omit_repos : null
  }

  optional_checks = length(each.value.optional_checks.repos) == 0 ? null : {
    repos      = each.value.optional_checks.repos
    omit_repos = length(each.value.optional_checks.omit_repos) > 0 ? each.value.optional_checks.omit_repos : null
  }

  baseline_check = length(each.value.baseline_check.repos) == 0 ? null : {
    repos      = each.value.baseline_check.repos
    omit_repos = length(each.value.baseline_check.omit_repos) > 0 ? each.value.baseline_check.omit_repos : null
  }
}
