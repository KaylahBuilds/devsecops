# secres-infra

Terraform-managed AWS core infrastructure with a security-gated GitHub Actions
pipeline: **StepSecurity harden-runner** on every job, **Prowler** CSPM scans,
and **Horizon3.ai NodeZero** pentest triggering. PRs must pass `terraform plan`
before merging to `main`; merge deploys.

## Layout

```
bootstrap/            One-time local apply: state backend + GitHub OIDC + CI roles
terraform/            Root module — core VPC/network, all variables-driven
  envs/dev.tfvars     Per-environment inputs
  envs/prod.tfvars
stepsecurity/         Root module — StepSecurity tenant config (egress policies,
                      RUNBOOK.md: operating procedures, SAST/DAST, GHAS, Woodpecker
                      run policies, PR checks, notifications, remediation PRs)
                      for every GitHub org/repo, driven by one terraform.tfvars
.github/workflows/
  terraform.yml       PR → fmt/validate/plan (dev+prod, commented on PR); main → apply
  stepsecurity.yml    Same gate for stepsecurity/; apply behind the `stepsecurity` environment
  security-scan.yml   Weekly Prowler scan; manual NodeZero trigger
```

## Pipeline flow

1. **PR opened** → `Terraform Plan (dev)` and `Terraform Plan (prod)` run:
   `fmt -check`, `validate`, `plan` against real state via a **read-only** OIDC
   role. The rendered plan is posted (and updated in place) as a PR comment.
2. **Branch protection** blocks merge until both plan checks pass.
3. **Merge to main** → auto-applies **dev** with the apply role (only
   assumable from `main` — a PR can never reach it).
4. **Prod** applies only via manual `workflow_dispatch`, behind the `prod`
   GitHub environment (add required reviewers there).
5. **Weekly** (or on demand) Prowler scans the account with
   SecurityAudit/ViewOnly and uploads CSV/OCSF/HTML reports as artifacts.
6. **NodeZero** pentests are triggered manually via `workflow_dispatch` with
   the `run_nodezero` input.

## Setup

### 1. Bootstrap (once, locally, with admin creds)

```bash
cd bootstrap
terraform init
terraform apply -var="github_repo=<owner>/<repo>"
```

Then copy the outputs:

- `state_bucket` / `lock_table` → into `terraform/backend.tf`
- role ARNs → GitHub repo **Settings → Secrets and variables → Actions**:

| Secret | Value |
|---|---|
| `AWS_PLAN_ROLE_ARN` | `plan_role_arn` output |
| `AWS_APPLY_ROLE_ARN` | `apply_role_arn` output |
| `AWS_PROWLER_ROLE_ARN` | `prowler_role_arn` output |
| `H3_API_KEY` | NodeZero API key from the Horizon3.ai portal (optional until you use it) |
| `STEP_SECURITY_API_KEY` | StepSecurity API key (dashboard → Settings → API keys) — for `stepsecurity/` |
| `STEP_SECURITY_CUSTOMER` | StepSecurity tenant name — for `stepsecurity/` |
| `STEPSECURITY_NOTIFICATION_WEBHOOKS` | Optional HCL map of per-org Slack/Teams webhooks (see `stepsecurity/README.md`) |

### 2. Branch protection

Settings → Branches → protect `main`, require status checks:
`Terraform Plan (dev)` and `Terraform Plan (prod)`. Or via CLI:

```bash
gh api -X PUT "repos/<owner>/<repo>/branches/main/protection" --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["Terraform Plan (dev)", "Terraform Plan (prod)"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": { "required_approving_review_count": 1 },
  "restrictions": null
}
EOF
```

### 3. Prod environment gate

Settings → Environments → create `prod` → add yourself as a required reviewer.
Dispatch the **Terraform** workflow with `environment: prod` to deploy prod.

### 4. NodeZero prerequisites

- A Horizon3.ai account with an op template configured in the portal.
- `H3_API_KEY` secret set.
- Internal pentests need a NodeZero runner **inside the target network** —
  the GitHub job only *triggers* the op via h3-cli.
- Verify the `h3 run_pentest` invocation against the current
  [h3-cli docs](https://github.com/horizon3ai/h3-cli) — CLI syntax evolves.
- Only pentest environments you own or have written authorization to test.

## Security posture notes

- **No static AWS keys** — all three roles are assumed via GitHub OIDC, with
  the apply role restricted to `refs/heads/main`.
- **StepSecurity harden-runner** runs first in every job in `audit` mode.
  After a few runs, review the egress reports at app.stepsecurity.io and
  switch to `egress-policy: block` with an `allowed-endpoints` list.
- **Pin actions to commit SHAs** before this gets serious — the workflows use
  version tags for readability; StepSecurity's [secure-repo](https://app.stepsecurity.io/securerepo)
  app will pin them for you in one PR.
- The apply role ships as `PowerUserAccess` to get you moving — scope it down
  to the services the root module manages once it stabilizes.
- Prowler runs with `-z` so findings don't fail the job; drop the flag when
  you want findings to break the build.

## Everyday commands

```bash
terraform -chdir=terraform init -backend-config="key=dev/terraform.tfstate"
```

```bash
terraform -chdir=terraform plan -var-file=envs/dev.tfvars
```

```bash
terraform -chdir=terraform fmt -recursive
```
