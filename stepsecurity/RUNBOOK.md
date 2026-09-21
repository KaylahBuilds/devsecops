# StepSecurity runbook

Operating guide for the StepSecurity tenant managed from `stepsecurity/`.
Audience: platform / security engineers who run it, and developers who hit
its checks. Everything here is driven by `terraform.tfvars`; the procedures
say which key to change.

Sources of truth: the [provider docs](https://github.com/step-security/terraform-provider-stepsecurity),
[Harden-Runner](https://github.com/step-security/harden-runner) and
[secure-repo](https://github.com/step-security/secure-repo). Where this
runbook says a capability does **not** exist, that is deliberate: do not
promise it to a team.

---

## 1. What StepSecurity is, and is not

StepSecurity is **CI/CD supply-chain and runtime security for GitHub
Actions**. It is not a code scanner. The table maps what people ask for to
what actually delivers it here.

| Need | Delivered by | Managed in this repo via |
|---|---|---|
| Stop a compromised build step exfiltrating secrets | Harden-Runner egress policy (audit → block) | `egress_policies`, `egress_policy_attachments` |
| Detect tampering during a job (source overwrite, reverse shell, privileged container, runner memory read) | Harden-Runner runtime detections + lockdown | `egress_policies[*].lockdown`, `notifications` |
| Only allow vetted / SHA-pinned actions and runner types | Run policies | `run_policies` |
| Block PRs that add just-published or compromised packages, `pull_request_target` misuse, script injection | StepSecurity PR checks | `checks` |
| Secrets leaking into build logs or artifacts | Secrets detection (run policy + notifications) | `run_policies[*].policy.enable_secrets_policy`, events `secrets_detected`, `artifacts_secrets_detected` |
| Automatic hardening PRs (pin SHAs, minimal `GITHUB_TOKEN`, add Harden-Runner, Dependabot, **CodeQL**, dependency review, Scorecard, Dockerfile digests) | Policy-driven PRs (secure-repo) | `policy_driven_prs`, `pr_templates` |
| **SAST** (static analysis of your code) | **CodeQL / GitHub Advanced Security**, which StepSecurity installs and protects but does not perform | `policy_driven_prs` adds the workflow; GHAS licence runs it (see §5) |
| **DAST** (probing a running app) | **Not a StepSecurity feature.** Use OWASP ZAP in a hardened job | see §6 |
| Runtime security in **Woodpecker CI** or any non-GitHub CI | **Not available.** Harden-Runner runs only on GitHub Actions runners (hosted, self-hosted, ARC) | see §7 |

---

## 2. How it is wired in this repo

```
stepsecurity/terraform.tfvars        every org, policy, check and rule (the only file you edit)
stepsecurity/*.tf                    provider resources, one flat map each; no loops
stepsecurity/examples/               worked scenarios (examples branch)
.github/workflows/stepsecurity.yml   PR → plan commented on the PR; merge → apply
.github/workflows/terraform.yml      AWS infra; every job starts with harden-runner (audit)
```

Secrets: `STEP_SECURITY_API_KEY`, `STEP_SECURITY_CUSTOMER` and the optional
`STEPSECURITY_NOTIFICATION_WEBHOOKS` live in GitHub repo secrets. Nothing
sensitive is in tfvars.

Apply path: open a PR touching `stepsecurity/`, read the plan comment, merge.
The `stepsecurity` GitHub environment gates the apply; add required reviewers
there.

---

## 3. Standard operating procedures

Each procedure names the tfvars key, the check that proves it worked, and the
rollback. Plans are cheap: run `terraform plan` locally before opening the PR.

### 3.1 Onboard a new GitHub org

1. Install the StepSecurity GitHub App on the org (dashboard → Add
   organization). Terraform cannot do this step.
2. Add entries to `terraform.tfvars`, minimum viable set:
   ```hcl
   egress_policies           = { "<org>-baseline" = { owner = "<org>" } }        # audit mode
   egress_policy_attachments = { "<org>-baseline" = { org_wide = true } }
   checks                    = { "<org>" = { required_checks = { repos = ["*"] } } }
   notifications             = { "<org>" = { email = "<team alias>" } }
   ```
3. PR → plan shows 4 new resources → merge.
4. Verify: dashboard shows the org with the baseline policy; open any PR in
   the org and confirm the StepSecurity check appears.
5. Rollback: delete the entries and merge. Terraform destroys them.

### 3.2 Take a workflow from audit to block

Do this per workflow, never org-wide on day one.

1. Confirm the workflow has run with Harden-Runner in audit for at least a
   week (dashboard → Runtime Security → the repo → egress report).
2. Copy the observed endpoints into a dedicated policy:
   ```hcl
   egress_policies = {
     "<org>-<repo>-<workflow>" = {
       owner             = "<org>"
       egress_policy     = "block"
       allowed_endpoints = ["registry.npmjs.org:443", "..."]   # base GitHub endpoints are prepended
       lockdown          = {}                                 # stop the job on runtime detections
     }
   }
   egress_policy_attachments = {
     "<org>-<repo>-<workflow>" = {
       repositories = [{ name = "<repo>", workflows = ["<file>.yml"] }]
     }
   }
   ```
3. Merge, then re-run the workflow. Check the run summary: a blocked call
   shows in the Harden-Runner step summary with the destination.
4. If a legitimate call was blocked: add the endpoint, merge, re-run. Do
   **not** flip back to audit for one endpoint.
5. Rollback: `egress_policy = "audit"`. The attachment stays, so re-blocking
   later is one word.

Notes. Because the policy store is attached, the workflow file never changes.
A repo that hard-codes `allowed-endpoints:` in its `harden-runner` step is
managing its own list outside Terraform; a run policy with
`require_policy_store = true` fails such jobs, so enable it once the org is
mostly on the store.

### 3.3 Roll out a run policy

Every run policy starts in dry run.

1. Add the policy with `is_dry_run = true` and, if scoping, `repositories`.
2. Merge. Watch the dashboard → Run Policies → violations for a few days.
   Nothing is blocked yet; violations are reported.
3. Fix the violators (or exempt them: `actions_to_exempt_while_pinning`,
   `exempted_users`), then set `is_dry_run = false`.
4. Rollback: `is_dry_run = true`. Takes effect on the next run.

Order that works: pinned actions first (`require_pinned_actions`), then
`enable_harden_runner_policy` with `harden_runner_target_labels = []`, then
runner-label restrictions, then secrets and compromised-actions policies.

### 3.4 Enable or tune PR checks

- Required (merge-blocking): `checks["<org>"].required_checks.repos`.
- Optional (informational): `optional_checks`.
- Baseline (existing violations, non-blocking): `baseline_check`.
- Controls default to `var.default_check_controls`. To change the cooldown
  window for one org, set `controls` on that org.
- Then add the check name to branch protection as a required status check.
  Terraform does not manage branch protection.

### 3.5 Respond to an alert

Alerts arrive on the channels in `notifications`. Triage by event:

| Event | First look | Usual outcome |
|---|---|---|
| `domain_blocked` | Run summary → which step, which destination | Legitimate: add to `allowed_endpoints`. Unknown: treat as incident, keep blocked |
| `secrets_detected` / `artifacts_secrets_detected` | The job log / artifact named in the alert | Rotate the secret first, then fix the step that printed it. Never suppress without rotating |
| `imposter_commits_detected` | The action reference in the alert | The action's SHA is not on its upstream branch. Replace the reference; consider `enable_compromised_actions_policy` |
| `file_overwrite` | Which file, which step | Build steps that generate code are normal; anything touching `.github/` or lockfiles outside a known step is not |
| `suspicious_process_events_detected` (reverse shell, privileged container, memory read) | Stop the runner if self-hosted; read the process tree in the dashboard | Incident until proven otherwise |
| `run_blocked_by_policy` | PR comment from the run policy | Developer fixes the workflow; see §8 |
| `harden_runner_config_changes_detected` | The PR that edited the harden-runner step | Someone loosened `egress-policy` in a workflow; move that repo to the policy store |

Suppressing a known-good detection: add a `suppression_rules` entry scoped to
the repo, workflow and job, with a `description` saying why and who reviewed
it. Example 07 on the examples branch has one rule per detection type.

### 3.6 A developer's build is blocked

See §8 for the developer-facing version. Operator side: the PR comment
names the policy and the violation. Check the policy is not in dry run by
mistake, then either help fix the workflow or, if the policy is wrong,
change the policy, not the workflow.

### 3.7 Rotate the API key

1. Dashboard → Settings → API keys → create a new key.
2. Update the `STEP_SECURITY_API_KEY` repo secret.
3. Run the StepSecurity workflow via `workflow_dispatch`; a clean plan proves
   the key works.
4. Revoke the old key.

### 3.8 Adopt policies created in the dashboard

Use `import` blocks; the ID formats are in `stepsecurity/README.md` and
`examples/imports.tf.example` on the examples branch. Plan until it shows no
changes, apply, delete the import file.

### 3.9 Emergency loosen

When enforcement is blocking a release and the fix is not obvious:

1. Set `egress_policy = "audit"` on the specific policy, or
   `is_dry_run = true` on the specific run policy. Never touch org-wide
   entries for a one-repo problem.
2. Merge with the `stepsecurity` environment reviewers; the apply takes
   about a minute.
3. Open a ticket to re-enable within 48 hours. Audit mode still records
   everything, so the evidence for the fix is in the dashboard.

---

## 4. SAST

StepSecurity does not run static analysis. It gets SAST in place and keeps
the job that runs it honest.

**What it does**

- Policy-driven PRs add a **CodeQL** workflow, a **dependency review**
  workflow and an **OpenSSF Scorecard** workflow to every selected repo
  (`policy_driven_prs`). CodeQL is the SAST engine; results land in GitHub
  code scanning and need a GHAS licence on private repos.
- PR checks catch two workflow-level SAST classes that CodeQL does not:
  **script injection** (untrusted `${{ }}` input in `run:`) and **PWN
  request** (`pull_request_target` misuse). Both are in
  `default_check_controls`.
- Harden-Runner runs first in the CodeQL job, so the scanner itself cannot
  be turned into an exfiltration path. Allow-list only
  `api.github.com:443`, `uploads.github.com:443` and the GitHub base set.

**What it does not do**

- No language SAST rules of its own, no SARIF output, no IaC scanning.
- For Terraform in this repo, add a scanner yourself (Checkov, tfsec or
  Trivy config) in a Harden-Runner job; upload SARIF to code scanning with
  `github/codeql-action/upload-sarif`.

**Reference job** (add to any repo; pin the SHAs before merging):

```yaml
sast:
  runs-on: ubuntu-latest
  permissions:
    contents: read
    security-events: write
  steps:
    - uses: step-security/harden-runner@v2
      with:
        egress-policy: block            # or omit and let the policy store attach
        allowed-endpoints: >
          api.github.com:443
          github.com:443
          objects.githubusercontent.com:443
          uploads.github.com:443
    - uses: actions/checkout@v4
    - uses: github/codeql-action/init@v3
      with:
        languages: go
    - uses: github/codeql-action/analyze@v3
```

---

## 5. GitHub Advanced Security

StepSecurity and GHAS overlap in name only. Use both; the table says which
covers what and where the two touch.

| Concern | GHAS | StepSecurity | Where they meet |
|---|---|---|---|
| Code vulnerabilities | CodeQL code scanning | installs the workflow via policy-driven PRs | `policy_driven_prs` |
| Secrets in the repo | Secret scanning + push protection | secrets in **build logs and artifacts** at run time | events `secrets_detected`, `artifacts_secrets_detected` |
| Vulnerable dependencies | Dependabot alerts, dependency review | cooldown checks block *just-published* versions before a CVE exists; compromised-updates checks use StepSecurity threat intel | `checks` controls |
| Dependabot config | Dependabot | policy-driven PRs write `dependabot.yml`, including package cooldown | `policy_driven_prs[*].auto_remediation_options.package_ecosystem` |
| Workflow security | none | run policies, PR checks, Harden-Runner | `run_policies`, `checks` |
| Findings in the GHAS UI | Security tab | remediation findings can be raised as **GHAS alerts** | `create_github_advanced_security_alert = true` |

Raising StepSecurity findings as GHAS alerts:

```hcl
policy_driven_prs = {
  "<org>" = {
    auto_remediation_options = {
      create_pr                             = false   # the provider rejects create_pr and create_issue both true
      create_issue                          = true    # required by the alert option
      create_github_advanced_security_alert = true
    }
  }
}
```

Branch protection should require the CodeQL check **and** the StepSecurity
required check. GHAS licensing is per active committer on private repos;
StepSecurity is per tenant, so enabling StepSecurity on an org does not
change the GHAS bill.

---

## 6. DAST

StepSecurity has no dynamic testing. The pattern below runs a scanner in a
job that StepSecurity hardens.

**OWASP ZAP baseline** for a deployed web app, run from GitHub Actions:

```yaml
dast:
  runs-on: ubuntu-latest
  steps:
    - uses: step-security/harden-runner@v2
      with:
        egress-policy: block
        allowed-endpoints: >
          github.com:443
          ghcr.io:443
          pkg-containers.githubusercontent.com:443
          staging.example.com:443          # the ONLY non-GitHub destination
    - uses: zaproxy/action-baseline@v0.12.0
      with:
        target: https://staging.example.com
        fail_action: false
```

What StepSecurity adds to a DAST job: the egress allow-list proves the
scanner talked only to the intended target; secrets detection catches an
auth token echoed into the scan log; the artifact scan checks the uploaded
report. Scan only environments you own or have authorization to test.

---

## 7. Woodpecker CI

**No native integration exists.** Harden-Runner installs only on GitHub
Actions runners, and the StepSecurity backend consumes GitHub webhooks and
Actions run data. A Woodpecker agent gets no runtime protection, no run
policies and no dashboard entry, and StepSecurity has said other CI
platforms are by request only (interest@stepsecurity.io).

What still applies when Woodpecker builds a repo hosted on GitHub:

- **PR checks** run on the GitHub side regardless of which CI builds the
  code: package cooldown, compromised updates, script injection and PWN
  request checks on `.github/workflows` still fire.
- **Policy-driven PRs** still open (pin SHAs, Dependabot, CodeQL). CodeQL
  needs Actions to run, so a Woodpecker-only org either accepts that one
  Actions workflow or runs CodeQL CLI in Woodpecker and uploads SARIF.
- **Branch protection** can require both the Woodpecker status and the
  StepSecurity required check.

Getting equivalent controls inside Woodpecker is your own work. The
patterns below are Woodpecker features, not StepSecurity:

- Pin step images by digest (`image: golang:1.23@sha256:...`), the analogue
  of pinning actions.
- Keep secrets out of logs: `from_secret` plus `secrets: [...]` on the step;
  Woodpecker masks them, but scan logs with a `gitleaks` step anyway.
- Egress control: on the Kubernetes backend, a NetworkPolicy on the agent
  namespace; on the Docker backend, a dedicated network with an egress
  proxy. This replaces the Harden-Runner allow-list.
- SAST and DAST as ordinary steps (Semgrep, Trivy, ZAP) in
  `.woodpecker/security.yaml`:

```yaml
when:
  - event: [push, pull_request]

steps:
  - name: sast
    image: semgrep/semgrep@sha256:<digest>
    commands:
      - semgrep ci --config p/ci
    environment:
      SEMGREP_APP_TOKEN:
        from_secret: semgrep_token

  - name: deps
    image: aquasec/trivy@sha256:<digest>
    commands:
      - trivy fs --scanners vuln,secret,misconfig --exit-code 1 .

  - name: dast
    image: ghcr.io/zaproxy/zaproxy:stable@sha256:<digest>
    commands:
      - zap-baseline.py -t https://staging.example.com -r zap.html || true
    when:
      - branch: main
```

Route Woodpecker findings to the same Slack channel as the StepSecurity
notifications so on-call sees one stream.

---

## 8. What developers get

Written for the PR author who just saw a StepSecurity comment.

- **A comment that says what to change.** A blocked run gets a PR comment
  with the policy name, the violation and the remediation
  (`pr_comment_template` if the org customised it). No dashboard trip needed.
- **PRs that do the boring hardening for you.** SHA-pinning every action,
  trimming `GITHUB_TOKEN` to what the workflow uses, adding Harden-Runner,
  writing `dependabot.yml`, pinning Docker base images by digest. Review and
  merge; nothing to write.
- **Fewer supply-chain surprises.** The cooldown check stops a PR that pulls
  a package version published in the last few days, which is when
  hijacked-maintainer releases do their damage. Compromised-updates checks
  use StepSecurity's threat intel for known-bad versions.
- **A per-job network map.** The Harden-Runner step summary shows every
  outbound call a job made, by step. It is the fastest way to find out why
  a build is slow or what a new dependency talks to.
- **Maintained forks of popular actions.** StepSecurity keeps hardened,
  maintained copies of dozens of community actions (`step-security/*`) for
  when upstream goes stale.
- **Dev-machine checks.** `step-security/dev-machine-guard` scans a laptop
  for suspicious packages, IDE extensions and MCP servers; the same tenant
  can enforce IDE-extension and package policies through developer MDM
  (not managed by this module).
- **Nothing to configure in the workflow.** With the policy store attached,
  the only line a developer ever adds is the Harden-Runner step, and
  policy-driven PRs add that too.

How to get unblocked, in order: read the PR comment; if the policy is
wrong, open a PR against `stepsecurity/terraform.tfvars` (the plan is posted
on the PR, so a reviewer sees exactly what changes); if it is urgent, ask
the on-call to use §3.9.

---

## 9. Quick reference

| Task | Where |
|---|---|
| Change any policy | `stepsecurity/terraform.tfvars` → PR → merge |
| See the plan before merge | the `StepSecurity plan` comment on the PR |
| Apply manually | Actions → StepSecurity Config → Run workflow |
| Egress reports, violations, detections | app.stepsecurity.io → the org |
| Import IDs | `stepsecurity/README.md`, examples branch `examples/imports.tf.example` |
| Worked configs | examples branch `stepsecurity/examples/` |
| Provider version | `stepsecurity/versions.tf` (`~> 0.0.44`) |

Contacts to fill in: StepSecurity tenant owner, security on-call alias,
Slack channel for alerts.
