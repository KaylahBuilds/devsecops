# =============================================================================
# checks.tf — StepSecurity pull-request checks, one configuration per org.
# =============================================================================
# What this file manages
#   StepSecurity can post GitHub checks on every pull request that inspect
#   what the PR changes. Each CONTROL is one kind of finding:
#     "* Package Cooldown"            a dependency bumped to a version younger than N days (fresh, possibly malicious release)
#     "* Package Compromised Updates" a dependency bumped to a version StepSecurity threat intel flags as compromised
#     "PWN Request"                   workflow changes that let a fork PR run with write tokens (pull_request_target misuse)
#     "Script Injection"              untrusted event data (PR title, branch name, ...) interpolated into run: scripts
#   Controls are posted in one of two separate check runs — the REQUIRED
#   check (branch protection normally requires it, so it blocks merging) or
#   the OPTIONAL check (advisory) — chosen per control with `type`. A third,
#   BASELINE check can be enabled per repo as well. Which repos get each
#   check is set per org with required_checks / optional_checks /
#   baseline_check.
#
#   var.checks -> stepsecurity_github_checks   one instance per map entry, keyed by org
#
# Where the values come from
#   Entries live in terraform.tfvars (or examples/*.tfvars); the object type is
#   in inputs.tf; the control list used when an entry has none
#   (default_check_controls) is in variables.tf.
#
# How to run (from stepsecurity/; credentials come from the environment)
#   export STEP_SECURITY_CUSTOMER=<tenant> STEP_SECURITY_API_KEY=<key>
#   terraform init -backend-config="key=stepsecurity/terraform.tfstate"
#   terraform plan            # uses terraform.tfvars, or -var-file=examples/04-multi-org.tfvars
#
# Adopting an org's existing check configuration: import ID  <org>
#   import { to = stepsecurity_github_checks.this["acme-platform"], id = "acme-platform" }
# =============================================================================

# ===== checks -> stepsecurity_github_checks ==================================
# Minimal tfvars entry (default controls, required check on every repo):
#   checks = { "acme-platform" = { required_checks = { repos = ["*"] } } }
resource "stepsecurity_github_checks" "this" { # address: stepsecurity_github_checks.this["<org>"]
  for_each = var.checks                        # one instance per entry of the map; each.key = GitHub org name, each.value = the entry object typed in inputs.tf

  owner              = each.key                                                  # (required) GitHub org — the map key itself, so it is never typed twice
  custom_description = each.value.custom_description                             # (optional) text appended to every check summary on the PR, e.g. who to contact; null (default) = none
  controls           = coalesce(each.value.controls, var.default_check_controls) # list of controls: the entry's own `controls` when set (even []), otherwise var.default_check_controls from variables.tf
  required_checks    = each.value.required_checks                                # (optional) { repos, omit_repos } — where the REQUIRED (blocking) check runs; null (default) = nowhere
  optional_checks    = each.value.optional_checks                                # (optional) same shape — where the OPTIONAL (advisory) check runs; null (default) = nowhere
  baseline_check     = each.value.baseline_check                                 # (optional) same shape — where the BASELINE check runs; null (default) = nowhere
  # ---- What tfvars can set on a checks entry (all optional; the org key is the only required part)
  #   custom_description = "Checks by StepSecurity. Questions: #security on Slack."
  #   controls = [                                                   # omit -> var.default_check_controls; [] = no controls at all
  #     { control = "NPM Package Cooldown",                          # (required) exact provider name: "NPM Package Cooldown" | "PyPI Package Cooldown" | "Maven Package Cooldown" | "NuGet Package Cooldown"
  #                                                                  #   | "NPM Package Compromised Updates" | "PyPI Package Compromised Updates" | "Maven Package Compromised Updates" | "NuGet Package Compromised Updates"
  #                                                                  #   | "PWN Request" | "Script Injection"
  #       enable = true,                                             # optional: false keeps the control listed but switched off (default true)
  #       type   = "required",                                       # optional: required (default) = posted in the required check | optional = posted in the optional check
  #       settings = {                                               # optional; cooldown controls only
  #         cool_down_period                     = 3,                # days a new version must exist before it may be used (provider default 2)
  #         packages_to_exempt_in_cooldown_check = ["@acme/tools"],  # package names allowed to bypass the cooldown
  #       } },
  #   ]
  #   required_checks = { repos = ["*"], omit_repos = ["sandbox"] }  # repos: repo names, or ["*"] for all; omit_repos is only valid together with repos = ["*"]
  #   optional_checks = { repos = ["docs-site"] }                    # same shape
  #   baseline_check  = { repos = ["*"] }                            # same shape
}
# ---- Provider attributes NOT exposed by this layout (stepsecurity v0.0.44) ---
#   none — every argument of stepsecurity_github_checks is passed through
#   (owner from the map key, custom_description, controls[]{control, enable,
#   type, settings{cool_down_period, packages_to_exempt_in_cooldown_check}},
#   required_checks, optional_checks, baseline_check — each {repos, omit_repos}).
#   The resource has no computed id attribute; import with the org name  <org>.
# -----------------------------------------------------------------------------
