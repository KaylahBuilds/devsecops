# stepsecurity — StepSecurity configuration as code

Terraform root module that manages a whole StepSecurity tenant — every GitHub
org, every repo, every policy — from **one typed variable** and **one
`terraform.tfvars`**. Uses the official
[`step-security/stepsecurity`](https://github.com/step-security/terraform-provider-stepsecurity)
provider.

## Layout

```
variables.tf      Tenant-wide settings + defaults (auth, base egress endpoints,
                  default check controls, default notification events, ...)
inputs.tf         The `organizations` variable: per-org / per-repo shape,
                  with plan-time validations
terraform.tfvars  Your actual orgs and policies — the only file you edit day to day
locals.tf         Flattens `organizations` into for_each maps, applies defaults
policy_store.tf   Harden-Runner egress policies + where they attach
run_policies.tf   Allowed actions / pinning / runner labels / secrets / compromised actions
checks.tf         StepSecurity PR checks
notifications.tf  Org notification channels + events
policy_driven_prs.tf  Remediation PRs + the PR template they use
suppressions.tf   Suppression rules
outputs.tf        IDs you need for imports and cross-referencing
```

The rule of thumb: **values go in `terraform.tfvars`, shape goes in
`inputs.tf`, tenant-wide defaults go in `variables.tf`.** You should rarely
need to touch a `*.tf` file to onboard a new org or repo.

## What one org looks like

Every section is optional — `"my-org" = {}` is a valid entry.

```hcl
organizations = {
  "my-org" = {
    egress_policies = {                       # → policy store + attachment
      "baseline" = {
        egress_policy = "block"               # audit | block (default: var.default_egress_policy)
        allowed_endpoints = ["registry.npmjs.org:443"]   # appended to var.base_allowed_endpoints
        attach = {
          org_wide     = false
          repositories = {
            "svc-*"    = ["ci.yml"]           # wildcard repos must name workflows
            "api"      = []                   # [] = whole repo
          }
        }
      }
    }
    run_policies = {                          # → run policy; set a group's fields to switch it on
      "pin-actions" = { require_pinned_actions = true, allowed_actions = { "*/*" = "allow" } }
      "harden"      = { harden_runner_target_labels = [] }        # [] = every job
      "no-self-hosted" = { repositories = ["payments"], disallowed_runner_labels = ["self-hosted"], dry_run = true }
      "secrets"     = { secrets_policy = true, compromised_actions_policy = true }
    }
    checks            = { required_checks = { repos = ["*"] } }   # controls default to var.default_check_controls
    notifications     = { email = "sec@example.com", events = { new_endpoint_discovered = true } }
    policy_driven_prs = { selected_repos = ["*"], excluded_repos = ["sandbox"] }
    pr_template       = { title = "...", summary = "...", commit_message = "...", branch_name = "sec/{time}" }
    suppression_rules = {
      "codecov" = { type = "anomalous_outbound_network_call", repo = "api", process = "*",
                    destination = { domain = "*.codecov.io" } }
    }
  }
}
```

See `terraform.tfvars` for a full two-org example (a locked-down prod org and
an audit-only lab org) and `inputs.tf` for every field with its default.

## Setup

### 1. Credentials — never in tfvars

| Env var | Where it comes from |
|---|---|
| `STEP_SECURITY_API_KEY` | StepSecurity dashboard → Settings → API keys |
| `STEP_SECURITY_CUSTOMER` | Your tenant name in the dashboard |

Locally: `export` them. In CI: repo secrets `STEP_SECURITY_API_KEY` and
`STEP_SECURITY_CUSTOMER` (see `.github/workflows/stepsecurity.yml`).

Slack/Teams webhook URLs are also secrets. They live in the sensitive
`notification_webhooks` variable, keyed by org, in a **git-ignored**
`secrets.auto.tfvars`:

```hcl
notification_webhooks = {
  "acme-platform" = { slack_webhook_url = "https://hooks.slack.com/services/..." }
}
```

or in CI as `TF_VAR_notification_webhooks` (HCL/JSON string).

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

## Multiple tenants

The provider authenticates to exactly one StepSecurity tenant, so one tenant
== one state file == one set of tfvars. For a second tenant, keep this module
and swap the inputs:

```bash
terraform init -reconfigure -backend-config="key=stepsecurity/<other-customer>/terraform.tfstate"
STEP_SECURITY_CUSTOMER=<other-customer> terraform plan -var-file=tenants/<other-customer>.tfvars
```

(Rename `terraform.tfvars` into `tenants/` if you go this way — Terraform
auto-loads `terraform.tfvars`, which you don't want with more than one.)

## Adopting existing config

Everything is `for_each`-keyed as `"<org>/<name>"` (or just `"<org>"` for
per-org singletons), so imports are predictable. Import IDs per resource:

| Resource | Import ID |
|---|---|
| `stepsecurity_github_policy_store.this["org/pol"]` | `org:::pol` |
| `stepsecurity_github_policy_store_attachment.this["org/pol"]` | `org:::pol` |
| `stepsecurity_github_run_policy.this["org/name"]` | `org/<policy_id>` (dashboard, or `stepsecurity_github_run_policies` data source) |
| `stepsecurity_github_checks.this["org"]` | `org` |
| `stepsecurity_github_org_notification_settings.this["org"]` | `org` |
| `stepsecurity_policy_driven_pr.this["org"]` | `org` |
| `stepsecurity_github_pr_template.this["org"]` | `org` |

Put `import` blocks in a temporary `imports.tf`, run `terraform plan` until it
shows no changes, apply, then delete the file.

## Rollout advice

1. Start every org with one org-wide egress policy in `audit` mode and
   `dry_run = true` on run policies. Nothing blocks.
2. After a week, read the egress reports in the StepSecurity dashboard, add
   the endpoints to `allowed_endpoints`, flip `egress_policy = "block"`.
3. Drop `dry_run`, starting with the run policies that target a short
   `repositories` list.
4. Turn on `policy_driven_prs` last — it opens PRs in every selected repo.

## Not covered (add a file if you need it)

The provider also manages tenant users/roles, tenant-level notifications,
Secure Registry policies and the developer MDM profiles. They are tenant-wide
rather than per-org, so they don't fit the `organizations` map; add them as
plain resources in a new `tenant.tf` if you adopt them.
