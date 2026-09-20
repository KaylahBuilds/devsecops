# stepsecurity — StepSecurity configuration as code

Terraform root module that manages a whole StepSecurity tenant — every GitHub
org, repo and policy — from one `terraform.tfvars`. Uses the official
[`step-security/stepsecurity`](https://github.com/step-security/terraform-provider-stepsecurity)
provider.

Design rule: **no loops, no locals, no type declarations.** Each resource
type is one flat map variable (`type = any`) and one `for_each`; the fields an
entry accepts are shown as a plain example above each variable in `inputs.tf`.
Every entry names its org (`owner`), or is keyed by org for per-org settings.
Reading a `.tf` file is reading the provider docs.

Operating procedures, SAST/DAST positioning, GitHub Advanced Security and
Woodpecker CI notes are in [RUNBOOK.md](RUNBOOK.md).

## Onboarding orgs and repos with shared defaults

`organizations.tf` plus `modules/org/` stamp one standard set of controls onto
every repo you list, per org:

| Control | Resource created | Scope |
|---|---|---|
| Harden-Runner egress policy + attachment | `stepsecurity_github_policy_store` / `_attachment` | one per repo |
| Harden-Runner required in every job | `stepsecurity_github_run_policy` | one per repo |
| Pinning guard: SHA-pinned, allowed actions only | `stepsecurity_github_run_policy` | one per repo |
| Compromised-actions block | `stepsecurity_github_run_policy` | one per org, all repos |
| PR checks (package cooldown, PWN request, script injection) | `stepsecurity_github_checks` | one per org, `required` on the repo list |
| Remediation PRs: harden-runner, pinned SHAs, Dependabot | `stepsecurity_policy_driven_pr` | one per org, on the repo list |
| Notifications | `stepsecurity_github_org_notification_settings` | one per org when an email is set |

Four layers, each a plain map, later wins:

1. `var.defaults` in `organizations.tf`: the full standard. Leave it alone.
2. `tenant_settings` in `terraform.tfvars`: any default key, for the whole tenant.
3. `organizations["<org>"].settings`: any default key, for that org.
4. `organizations["<org>"].repo_settings["<repo>"]`: the repo-level keys
   (`egress_policy`, `allowed_endpoints`, `lockdown`, `workflows`,
   `require_harden_runner`, `require_pinned_actions`, `allowed_actions`,
   `actions_to_exempt_while_pinning`, `dry_run`) for that repo.

**Add an org**: one entry.

```hcl
"acme-payments" = { repos = ["payments-api", "ledger"] }
```

**Add a repo**: one name in the org's `repos` list. It gets the org's
settings and the tenant defaults.

**Give a repo specifics**: one entry in `repo_settings`.

```hcl
repo_settings = {
  "payments-api" = { egress_policy = "block", allowed_endpoints = ["api.stripe.com:443"] }
}
```

`terraform.tfvars` shows four orgs and ten repos on the defaults, then a fifth
org and three more repos being added. Nothing else changes: no new `.tf`,
no new resource blocks.

The flat maps (`egress_policies`, `run_policies`, `checks`, ...) still work
for one-off resources outside the standard. Do not define an org-level
singleton (`checks`, `notifications`, `policy_driven_prs`) through a flat map
for an org that `organizations` already manages; StepSecurity keeps one per
org and the two definitions would fight.

## Layout

```
variables.tf      Tenant-wide settings + defaults (auth, base egress endpoints,
                  default check controls, default notification events, webhooks)
inputs.tf         One map variable per resource type, with a full example entry in the comment
terraform.tfvars  Your orgs and policies — the only file you edit day to day
organizations.tf  Shared-defaults onboarding: tenant defaults + module call per org
modules/org/      The standard controls stamped onto each repo of one org

policy_store.tf   egress_policies, egress_policy_attachments
run_policies.tf   run_policies
checks.tf         checks
notifications.tf  notifications
policy_driven_prs.tf  policy_driven_prs, pr_templates
suppressions.tf   suppression_rules
outputs.tf        Managed resources (IDs for imports)
```

**Values go in `terraform.tfvars`, shape goes in `inputs.tf`, tenant-wide
defaults go in `variables.tf`.** Onboarding an org or repo never touches a
`.tf` file.

## The inputs

| Variable | Key | One entry manages |
|---|---|---|
| `egress_policies` | policy name | a Harden-Runner egress policy (audit/block, allowed or denied endpoints, lockdown) |
| `egress_policy_attachments` | same key as the policy | where it applies: org-wide, repos/workflows, or clusters |
| `run_policies` | policy name | allowed actions, SHA pinning, runner labels, harden-runner presence, secrets, compromised actions |
| `checks` | org | PR checks: controls + required/optional/baseline repos |
| `notifications` | org | email / Slack / Teams channels and which events fire |
| `policy_driven_prs` | org | which repos get StepSecurity remediation PRs and what they fix |
| `pr_templates` | org | title / body / branch used for those PRs |
| `suppression_rules` | rule name | detections to ignore, scoped by org/repo/workflow/job |

`run_policies[*].policy` and `policy_driven_prs[*].auto_remediation_options`
are the provider's own blocks passed through unchanged, so examples from the
provider docs paste straight in.

Tenant-wide defaults applied by the resources:

- `base_allowed_endpoints` is prepended to every egress policy's `allowed_endpoints`
  (set `include_base_endpoints = false` to opt out).
- `default_egress_policy` fills in `egress_policy` when an entry omits it.
- `default_check_controls` is used when a `checks` entry has no `controls`.
- `default_notification_events` is merged under each `notifications.events`.
- `default_notification_email` fills in a missing `notifications.email`.

## Minimal example

```hcl
egress_policies = {
  "baseline" = { owner = "my-org" }                       # audit mode, base endpoints
}
egress_policy_attachments = {
  "baseline" = { org_wide = true }
}
run_policies = {
  "pin-actions" = {
    owner  = "my-org"
    policy = { enable_action_policy = true, require_pinned_actions = true, allowed_actions = { "*/*" = "allow" } }
  }
}
checks        = { "my-org" = { required_checks = { repos = ["*"] } } }
notifications = { "my-org" = { email = "sec@example.com" } }
```

`terraform.tfvars` holds a fuller two-org example: a locked-down
`acme-platform` and an audit-only `acme-labs`.

## Setup

### 1. Credentials — never in tfvars

| Env var | Where it comes from |
|---|---|
| `STEP_SECURITY_API_KEY` | StepSecurity dashboard → Settings → API keys |
| `STEP_SECURITY_CUSTOMER` | Your tenant name in the dashboard |

Locally: `export` them. In CI: repo secrets of the same names (see
`.github/workflows/stepsecurity.yml`).

Slack/Teams webhook URLs are secrets too. They go in the sensitive
`notification_webhooks` variable, keyed by org, in a **git-ignored**
`secrets.auto.tfvars`:

```hcl
notification_webhooks = {
  "acme-platform" = { slack_webhook_url = "https://hooks.slack.com/services/..." }
}
```

or in CI as the `TF_VAR_notification_webhooks` env var.

### 2. State

`backend.tf` reuses the S3 bucket / lock table from `../bootstrap`. The key is
injected at init (CI uses `stepsecurity/terraform.tfstate`):

```bash
terraform init -backend-config="key=stepsecurity/terraform.tfstate"
```

### 3. Run it

```bash
terraform fmt -check -recursive
terraform validate
terraform plan
terraform apply
```

Input mistakes (an egress mode that isn't audit/block, a wildcard repo pattern
without workflows, a network-call suppression without `process`, a control
without `enable`/`type`, ...) are rejected by the provider at `plan` time with
a message naming the entry. A misspelled optional field is silently ignored,
so compare new entries against the example in `inputs.tf`.

## Multiple tenants

The provider talks to exactly one StepSecurity tenant, so one tenant == one
state file == one tfvars. For a second tenant, keep this module and swap
inputs:

```bash
terraform init -reconfigure -backend-config="key=stepsecurity/<other>/terraform.tfstate"
STEP_SECURITY_CUSTOMER=<other> terraform plan -var-file=tenants/<other>.tfvars
```

(Move `terraform.tfvars` into `tenants/` if you go this way — Terraform
auto-loads `terraform.tfvars`, which you don't want with more than one.)

## Adopting existing config

Resource addresses are `<type>.this["<key>"]` with the same keys as tfvars.
Import IDs:

| Resource | Import ID |
|---|---|
| `stepsecurity_github_policy_store.this["baseline"]` | `<org>:::<policy name>` |
| `stepsecurity_github_policy_store_attachment.this["baseline"]` | `<org>:::<policy name>` |
| `stepsecurity_github_run_policy.this["pin-actions"]` | `<org>/<policy_id>` (dashboard, or the `stepsecurity_github_run_policies` data source) |
| `stepsecurity_github_checks.this["my-org"]` | `<org>` |
| `stepsecurity_github_org_notification_settings.this["my-org"]` | `<org>` |
| `stepsecurity_policy_driven_pr.this["my-org"]` | `<org>` |
| `stepsecurity_github_pr_template.this["my-org"]` | `<org>` |

Put `import` blocks in a temporary `imports.tf`, run `terraform plan` until it
shows no changes, apply, then delete the file.

## Rollout advice

1. Start each org with one org-wide egress policy in `audit` mode and
   `is_dry_run = true` on run policies. Nothing blocks.
2. After a week, read the egress reports in the dashboard, add endpoints to
   `allowed_endpoints`, flip `egress_policy = "block"`.
3. Drop `is_dry_run`, starting with run policies that target a short
   `repositories` list.
4. Turn on `policy_driven_prs` last — it opens PRs in every selected repo.

## Not covered

Tenant users/roles, tenant-level notifications, Secure Registry policies and
developer MDM profiles are tenant-wide rather than per-org. Add them as plain
resources in a new `tenant.tf` if you adopt them.
