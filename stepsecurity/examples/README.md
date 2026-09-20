# Examples

Working, fully commented `.tfvars` scenarios for the `stepsecurity/` module.
Every example is a complete input set: it sets all eight input maps (unused
ones as `{}`) plus the tenant-wide variables it cares about, so passing it
with `-var-file` fully replaces the auto-loaded `terraform.tfvars`.

On this branch every module file (`*.tf`, `terraform.tfvars`) is also
commented line by line, with the optional settings shown as commented-out
lines next to the live ones.

## The scenarios

| File | Scenario | What it demonstrates | Plan |
|---|---|---|---|
| `01-minimal.tfvars` | One org, observe only | one audit egress policy org-wide, required PR checks with default controls, email notifications; every optional attribute of the live entries shown commented out | 4 resources |
| `02-egress-policies.tfvars` | Harden-Runner egress policies | audit vs block, allowed vs denied endpoints, base-endpoint merging and opt-out, lockdown, sudo/file-monitoring/telemetry switches; every attachment shape: org-wide, whole repo, repo + workflows, wildcard pattern + workflows, Kubernetes clusters | 10 resources |
| `03-run-policies.tfvars` | Run policies, one per type | allowed actions and SHA pinning, runner labels in disallowed and allowed mode, Harden-Runner presence (all jobs, targeted, custom actions), secrets policy with a PR comment template, compromised actions, repo-scoped dry run, `name` override | 9 resources |
| `04-multi-org.tfvars` | Three orgs, three postures | prod / staging / sandbox with different enforcement; every tenant-wide default set live and overridden per org; the `<org>-<thing>` key convention | 24 resources |
| `05-repo-and-workflow-scoped.tfvars` | Precision targeting | attachments per workflow, per repo, per pattern; run policies with `repositories`; checks with explicit repo lists and `omit_repos`; remediation PRs with selected / excluded repos and topic filters; suppression rules scoped to repo + workflow + job | 15 resources |
| `06-remediation-prs.tfvars` | Policy-driven remediation PRs | every `auto_remediation_options` field the layout exposes (live or commented), Harden-Runner config and dependabot ecosystems, the PR template; which provider options need `inputs.tf` extended | 4 resources |
| `07-notifications-and-suppressions.tfvars` | Alert routing and suppressions | all 15 notification events explained, Slack OAuth, threat intel; one suppression rule per detection type (all 10) with the fields each type requires, plus a tenant-wide `owner = "*"` rule | 17 resources |
| `secrets.auto.tfvars.example` | Webhook secrets | the `notification_webhooks` map that must never go in a committed tfvars | n/a |
| `imports.tf.example` | Adopting existing config | commented `import` blocks with the ID format for every resource type | n/a |

## Running one

```bash
cd stepsecurity
export STEP_SECURITY_API_KEY=...      # from the StepSecurity dashboard
export STEP_SECURITY_CUSTOMER=...     # your tenant name
terraform init -backend-config="key=stepsecurity/terraform.tfstate"
terraform plan -var-file=examples/03-run-policies.tfvars
```

Because each example sets every input variable, the `-var-file` values win
over `terraform.tfvars` for all of them. To apply an example for real:

```bash
terraform apply -var-file=examples/03-run-policies.tfvars
```

To adopt an example as your configuration, copy it over `terraform.tfvars`
and edit the org, repo and endpoint names:

```bash
cp examples/04-multi-org.tfvars terraform.tfvars
```

Mixing two examples in one plan does not work as you might hope: Terraform
takes the last value given for each variable, so the second file's maps
replace the first file's rather than merge with them.

## Secrets

Slack and Teams webhook URLs belong in the sensitive `notification_webhooks`
variable, never in an example or in `terraform.tfvars`:

```bash
cp examples/secrets.auto.tfvars.example secrets.auto.tfvars   # git-ignored by *.auto.tfvars
```

In CI, set the same map through the `TF_VAR_notification_webhooks`
environment variable from a repository secret.

## Reading order for newcomers

1. `01-minimal.tfvars` to see the shape of every input map and its options.
2. `02-egress-policies.tfvars` and `03-run-policies.tfvars` for the two
   resource types that do the actual blocking.
3. `04-multi-org.tfvars` once you manage more than one org.
4. `05`, `06`, `07` when you need to scope, remediate, or tune noise.
5. `imports.tf.example` when adopting policies that already exist in the
   StepSecurity dashboard.

## Commenting convention

- Every code line carries a trailing comment or a comment line directly above it.
- Inputs have no type declarations; `inputs.tf` documents each field with an example entry, and the provider validates values at plan time. PR-check controls always state `enable` and `type`.
- Comments say what the line does and, for any field with choices, the allowed values and the default.
- Optional settings the example does not use appear as commented-out lines in the place they would go, so uncommenting them is the whole change.
- Each file's header says what it demonstrates and how to run it.
