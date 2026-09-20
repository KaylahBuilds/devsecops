# StepSecurity PR checks per org. Import ID: "<org>".
# Provider attributes not exposed by this layout: none.

resource "stepsecurity_github_checks" "this" { # one per org in var.checks
  for_each = var.checks                        # map key = org name

  owner              = each.key                                             # the org
  custom_description = try(each.value.custom_description, null)             # text appended to every check summary
  controls           = try(each.value.controls, var.default_check_controls) # the org's own control list, else the tenant default
  required_checks    = try(each.value.required_checks, null)                # { repos, omit_repos }: merge-blocking check
  optional_checks    = try(each.value.optional_checks, null)                # { repos, omit_repos }: informational check
  baseline_check     = try(each.value.baseline_check, null)                 # { repos, omit_repos }: existing violations, non-blocking
}
