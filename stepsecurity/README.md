# stepsecurity — StepSecurity configuration as code

Terraform root module that manages a whole StepSecurity tenant — every GitHub
org, repo and policy — from one `terraform.tfvars`. Uses the official
[`step-security/stepsecurity`](https://github.com/step-security/terraform-provider-stepsecurity)
provider.

Design rule: **no loops, no locals.** Each resource type is one flat map
variable and one `for_each`. Every entry names its org (`owner`), or is keyed
by org for per-org settings. Reading a `.tf` file is reading the provider docs.

## Layout

```
variables.tf      Tenant-wide settings + defaults (auth, base egress endpoints,
                  default check controls, default notification events, webhooks)
inputs.tf         One typed map variable per resource type — the shape of your config
terraform.tfvars  Your orgs and policies — the only file you edit day to day

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
without workflows, a network-call suppression without `process`, ...) are
rejected by the provider at `plan` time with a message naming the entry.

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
