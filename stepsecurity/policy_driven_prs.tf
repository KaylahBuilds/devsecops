# =============================================================================
# policy_driven_prs.tf — remediation pull requests StepSecurity opens for you,
# and the PR template they use.
# =============================================================================
# What this file manages
#   Policy-driven PRs: StepSecurity scans the selected repos of an org and
#   opens ONE pull request (or issue) per repo that applies the fixes chosen in
#   auto_remediation_options — add the Harden-Runner step, pin actions to
#   commit SHAs, add a least-privilege GITHUB_TOKEN `permissions:` block, pin
#   Dockerfile base images, write a Dependabot config, swap third-party
#   actions for StepSecurity-maintained forks. Two resources:
#
#   var.policy_driven_prs -> stepsecurity_policy_driven_pr    one per org: which repos, which fixes
#   var.pr_templates      -> stepsecurity_github_pr_template  one per org: title / body / commit message / labels / branch of those PRs
#
#   Both are keyed by org. A pr_templates entry only matters for an org that
#   also has a policy_driven_prs entry; without one StepSecurity uses its
#   default PR text. Turn policy_driven_prs on LAST: it opens PRs in every
#   selected repo as soon as it is applied.
#
# Where the values come from
#   Entries live in terraform.tfvars (or examples/*.tfvars); the object types
#   are in inputs.tf. The entry's `auto_remediation_options` object IS the
#   provider block of the same name, mirrored attribute by attribute, so
#   examples from the provider docs paste in unchanged. No tenant-wide
#   defaults are involved; per-attribute defaults live in the object type.
#
# How to run (from stepsecurity/; credentials come from the environment)
#   export STEP_SECURITY_CUSTOMER=<tenant> STEP_SECURITY_API_KEY=<key>
#   terraform init -backend-config="key=stepsecurity/terraform.tfstate"
#   terraform plan            # uses terraform.tfvars, or -var-file=examples/06-remediation-prs.tfvars
#
# Adopting an org's existing configuration: import ID  <org>  for both resources
#   import { to = stepsecurity_policy_driven_pr.this["acme-platform"],   id = "acme-platform" }
#   import { to = stepsecurity_github_pr_template.this["acme-platform"], id = "acme-platform" }
# =============================================================================

# ===== policy_driven_prs -> stepsecurity_policy_driven_pr ====================
# Minimal tfvars entry (every repo; the default fixes: a PR that adds harden-runner, pins actions, restricts the token):
#   policy_driven_prs = { "acme-platform" = { auto_remediation_options = {} } }
resource "stepsecurity_policy_driven_pr" "this" { # address: stepsecurity_policy_driven_pr.this["<org>"]
  for_each = var.policy_driven_prs                # one instance per entry of the map; each.key = GitHub org name, each.value = the entry object typed in inputs.tf

  owner                    = each.key                            # (required) GitHub org that receives the PRs — the map key itself, so it is never typed twice
  selected_repos           = each.value.selected_repos           # (required by the provider) repo names that get a PR; ["*"] (layout default) = every repo in the org; tfvars: selected_repos = ["payments-api", "web-frontend"]
  excluded_repos           = each.value.excluded_repos           # (optional) repos skipped when selected_repos = ["*"]; their previous config is restored or deleted; null (default) = none; tfvars: excluded_repos = ["sandbox"]
  selected_repos_filter    = each.value.selected_repos_filter    # (optional) { include_repos_only_with_topics = ["production"] } narrows selected_repos = ["*"] to repos carrying one of these GitHub topics (only valid with ["*"]); null (default) = no filter
  auto_remediation_options = each.value.auto_remediation_options # (required) the provider block verbatim — what each PR/issue fixes; {} in tfvars = every default listed below; attributes the entry leaves unset arrive as null = "not configured"
  # ---- What tfvars can set under auto_remediation_options = { ... } (all optional)
  #   -- delivery --
  #   create_pr                             = true  # open a pull request with the fixes (default true)
  #   create_issue                          = false # open a GitHub issue describing the findings, instead of or as well as a PR (default false)
  #   create_github_advanced_security_alert = false # also raise a GitHub Advanced Security alert; only acts when create_issue = true (default false)
  #   -- fixes --
  #   harden_github_hosted_runner       = true                # add the step-security/harden-runner step to jobs on GitHub-hosted runners (default true)
  #   pin_actions_to_sha                = true                # replace action tags/branches with full-length commit SHAs (default true)
  #   restrict_github_token_permissions = true                # add a least-privilege `permissions:` block for GITHUB_TOKEN (default true)
  #   secure_docker_file                = false               # pin Dockerfile base images to a SHA digest (default false)
  #   actions_to_exempt_while_pinning   = ["acme-platform/*"] # actions pin_actions_to_sha leaves on their tag (default null = pin everything)
  #   images_to_exempt_while_pinning    = ["alpine"]          # images secure_docker_file leaves unpinned (default null = pin everything)
  #   -- replacing third-party actions with StepSecurity-maintained forks (use ONE of the two lists) --
  #   actions_to_replace_with_step_security_actions = ["actions/checkout"] # only these actions are swapped (default null = no swaps)
  #   actions_exempted_from_replacement             = ["actions/cache"]    # swap ALL maintained actions EXCEPT these; mutually exclusive with the list above (default null)
  #   replace_action_on_major_tag_match             = true                 # swap only when the major tag matches; needs actions_to_replace_with_step_security_actions non-empty (default null = off)
  #   -- how the harden-runner step is written (omit the whole block for StepSecurity's default step) --
  #   harden_runner_config = {
  #     config                        = "egress-policy: audit" # YAML configuring the harden-runner step; a heredoc works in tfvars (default null = StepSecurity's default config)
  #     target_runner_labels          = ["ubuntu-latest"]      # only jobs whose runs-on matches one of these get the step (default null = every job)
  #     exempt_runner_labels          = ["gpu-*"]              # glob patterns of runner labels never touched, regardless of target_runner_labels (default null)
  #     update_existing_configuration = true                   # rewrite existing harden-runner steps to match `config`, dropping settings not in it (default null = leave them)
  #   }
  #   -- Dependabot config (.github/dependabot.yml); omit the list for no Dependabot changes --
  #   package_ecosystem = [
  #     { package = "npm", interval = "weekly",                            # package (required): npm | pip | docker | github-actions | maven | nuget | ...; interval (required): daily | weekly | monthly
  #       cooldown_yaml = "default-days: 7",                               # YAML for the ecosystem's `cooldown:` block (default null)
  #       groups_yaml   = "dev-deps:\n  dependency-type: development" },   # YAML for the ecosystem's `groups:` block, batching updates into one PR (default null)
  #   ]
  #   update_existing_configuration = true # Dependabot config drops ecosystems that are not in package_ecosystem (default null = keep them)
}
# ---- Provider attributes NOT exposed by this layout (stepsecurity v0.0.44) ---
#   All five live inside auto_remediation_options. The block is passed through
#   verbatim, so exposing one is a change to inputs.tf ONLY: add the attribute
#   to the auto_remediation_options object type and it reaches the provider.
#   action_commit_map          map action -> commit SHA to pin to instead of resolving it, e.g. { "actions/checkout@v4" = "<40-char sha>" }
#                              inputs.tf: action_commit_map = optional(map(string))
#   add_workflows              string of extra workflow YAML the PR adds to the repo
#                              inputs.tf: add_workflows = optional(string)
#   custom_actions_to_replace  map original action -> replacement action of your own choice (instead of StepSecurity forks)
#                              inputs.tf: custom_actions_to_replace = optional(map(string))
#   labels_to_replace          map disallowed runner label -> allowed label; the PR rewrites runs-on accordingly
#                              inputs.tf: labels_to_replace = optional(map(string))
#   update_precommit_file      list of pre-commit config paths to update, e.g. [".pre-commit-config.yaml"]
#                              inputs.tf: update_precommit_file = optional(list(string))
#   Top level: nothing left out (owner, selected_repos, excluded_repos,
#   selected_repos_filter, auto_remediation_options are all sent).
#   Computed (read-only): id — equals the org name, which is also the import ID.
# -----------------------------------------------------------------------------

# ===== pr_templates -> stepsecurity_github_pr_template =======================
# Minimal tfvars entry (the three required fields; StepSecurity's default labels and branch name):
#   pr_templates = { "acme-platform" = { title = "[StepSecurity] Apply security best practices", summary = "Automated hardening — review and merge.", commit_message = "[StepSecurity] Apply security best practices" } }
resource "stepsecurity_github_pr_template" "this" { # address: stepsecurity_github_pr_template.this["<org>"]
  for_each = var.pr_templates                       # one instance per entry of the map; each.key = GitHub org name, each.value = the entry object typed in inputs.tf

  owner          = each.key                  # (required) GitHub org whose policy-driven PRs use this template — the map key, so it lines up with the policy_driven_prs key
  title          = each.value.title          # (required) PR title, e.g. "[StepSecurity] Apply security best practices"
  summary        = each.value.summary        # (required) PR body in Markdown; {{STEPSECURITY_SECURITY_FIXES}} is replaced by the list of applied fixes; multi-line via a heredoc in tfvars
  commit_message = each.value.commit_message # (required) message of the remediation commit
  labels         = each.value.labels         # (optional) labels applied to every PR, e.g. ["security", "automated"]; null (default) = none
  branch_name    = each.value.branch_name    # (optional) branch-name template that MUST contain {time} (replaced by a DDHHMM timestamp so each PR gets a unique branch), e.g. "chore/stepsecurity-{time}"; null (default) = StepSecurity's default branch name
  # ---- What tfvars can set on a pr_templates entry
  #   title          = "[StepSecurity] Apply security best practices" # required
  #   summary        = <<-EOT                                          # required; a heredoc for a multi-line Markdown body
  #     ## Summary
  #     Automated hardening from StepSecurity — review and merge.
  #     {{STEPSECURITY_SECURITY_FIXES}}
  #   EOT
  #   commit_message = "[StepSecurity] Apply security best practices" # required
  #   labels         = ["security", "automated"]                       # optional (default: no labels)
  #   branch_name    = "chore/stepsecurity-{time}"                     # optional; {time} is mandatory when set (default: StepSecurity's own branch name)
}
# ---- Provider attributes NOT exposed by this layout (stepsecurity v0.0.44) ---
#   none — every argument of stepsecurity_github_pr_template is passed through
#   (owner from the map key, title, summary, commit_message, labels, branch_name).
#   Computed (read-only): id — equals the org name, which is also the import ID.
# -----------------------------------------------------------------------------
