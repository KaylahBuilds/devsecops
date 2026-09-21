# Container security programme: timeline for sizing

Assumptions: about 10 services, 3 build pipelines (Node, Python, Go),
one Kubernetes cluster per environment, images in one registry, GitHub
Actions with StepSecurity already in place. Adjust the "per pipeline" and
"per cluster" lines for your numbers.

## Phase 0: baseline (1 week, one engineer)

Know what you have before changing it.

| Task | Effort | Output |
|---|---|---|
| Inventory images in production: registry listing joined with running pods | S | spreadsheet of image, tag, digest, base image, owner |
| Scan everything once with Trivy, no gates | S | count of critical/high per image; the top 10 base images |
| Lint every Dockerfile with hadolint, no gates | S | list of `:latest`, root users, `curl \| sh`, secrets in `ARG` |
| Record cluster posture: PSA level per namespace, any privileged pods, network policies present | S | one page |

Exit: a ranked list of images by risk, and agreement on which 3 go first.

## Phase 1: build-time hardening (3 to 5 weeks)

| Task | Effort | Notes |
|---|---|---|
| Hardened Dockerfile template per language | M per pipeline | multi-stage, distroless or slim base, non-root, `COPY --chown`, pinned digests. First one is M, the rest are S once the pattern exists |
| Migrate the 3 pilot services | M | expect one surprise per service: a native module that needs glibc, a shell in an entrypoint, a healthcheck that used `curl` |
| hadolint in CI, warn only | S | `.hadolint.yaml` in this folder |
| Trivy in CI, warn only, SARIF to code scanning | S | `container-security.yml` |
| Digest pinning via StepSecurity remediation PRs | S | `secure_docker_file = true` in the org's `policy_driven_prs`; one PR per repo |
| Flip lint and scan to blocking on the pilots | S | after two clean weeks |

Exit: pilots build from the template, CI blocks new criticals, base images
are pinned by digest and bumped by bot PRs.

## Phase 2: supply chain proof (2 to 4 weeks)

| Task | Effort | Notes |
|---|---|---|
| SBOM generation and attestation on every build | S per pipeline | Syft or the BuildKit `--sbom` flag; attach with cosign |
| Keyless signing with cosign via GitHub OIDC | M | one-time trust setup, then a step per pipeline. Decide identity: the workflow file or the repo |
| SLSA provenance attestation | S | `actions/attest-build-provenance` or slsa-github-generator |
| Registry hygiene: immutable tags, retention, no anonymous pull | S | provider-specific |
| Private base image mirror or Chainguard/Distroless subscription decision | M | this is a procurement conversation, start it in week 1 |

Exit: every image the pipeline pushes carries an SBOM, provenance and a
verifiable signature.

## Phase 3: admission control (3 to 6 weeks, the risky one)

| Task | Effort | Notes |
|---|---|---|
| Install Kyverno (or OPA Gatekeeper) in audit mode | S per cluster | |
| Policies: signed images only, no `:latest`, non-root, no privileged, no hostPath, resource limits set | M | `kyverno-policies.yaml`; audit mode first |
| Work the audit report with every team that owns a violating workload | L | this is where the calendar goes. Third-party charts (ingress, monitoring) are the usual blockers; carve namespace exceptions with an expiry |
| Pod Security Admission `restricted` on app namespaces | M | label namespaces one at a time |
| Enforce mode, one namespace per day | M | keep a rollback that is one label change |

Exit: an unsigned or root image cannot be scheduled in an app namespace.

## Phase 4: runtime least privilege and detection (3 to 5 weeks, parallelisable with phase 3)

| Task | Effort | Notes |
|---|---|---|
| securityContext template: read-only root, drop ALL caps, seccomp RuntimeDefault, no privilege escalation | M | `pod-hardened.yaml`; apps that write to disk need an `emptyDir` |
| Default-deny NetworkPolicy per namespace plus explicit egress | M per cluster | `network-policy.yaml`; DNS and the metrics scraper are the two everyone forgets |
| Runtime detection (Falco or a commercial agent) in one cluster, alerts to the security channel | M | tune for two weeks before paging anyone |
| Node hardening: no SSH, minimal OS image, kernel unprivileged-userns setting reviewed | M | often owned by the platform team already |

Exit: pods run with the profile in `pod-hardened.yaml` or a documented
exception; a shell spawned in a production container pages someone.

## Phase 5: steady state (ongoing, about 10 percent of one engineer)

- Base image bumps arrive as bot PRs; merge weekly.
- Scan gates stay on; triage new criticals within the SLA (suggest 7 days for critical, 30 for high).
- Quarterly: re-run the phase 0 inventory and compare.

## Roll-up

| Phase | Elapsed | Engineer effort | Can overlap with |
|---|---|---|---|
| 0 baseline | 1 week | 1 | nothing, do it first |
| 1 build-time | 3 to 5 weeks | 1 to 1.5 | phase 2 after week 2 |
| 2 supply chain | 2 to 4 weeks | 1 | phase 1 |
| 3 admission | 3 to 6 weeks | 1 plus owner time from every team | phase 4 |
| 4 runtime | 3 to 5 weeks | 1 | phase 3 |
| 5 steady state | ongoing | 0.1 | |

Realistic total for the assumed scope: **one engineer for one quarter to
reach phase 2, two engineers for a second quarter to land phases 3 and 4.**
The build-time work is predictable. The admission and runtime phases are
gated by other teams' calendars, not by engineering effort; that is the
line to defend when the timeline is questioned.

## Where estimates go wrong

- **"Just switch to distroless."** Any service that shells out, uses a
  native module linked against glibc, or has a `curl`-based healthcheck
  needs code changes. Budget one surprise per service.
- **Third-party Helm charts** ship as root with `:latest` more often than
  not. Exceptions with an expiry date beat waiting for upstream.
- **Signing identity decisions** stall on who is allowed to sign. Decide
  early: signature identity = the workflow file on the default branch.
- **Network policies** break things silently (DNS, sidecars, webhooks).
  Audit-log first with a policy engine that supports it, or roll out per
  namespace with a fast rollback.
- **Scanner noise.** A first Trivy run on an old image reports hundreds of
  findings, most in the base image. Fix the base image first; the count
  drops by an order of magnitude and morale survives.

## Definition of done for the programme

- Every production image: pinned base digest, non-root, no critical CVEs
  older than the SLA, SBOM and signature verifiable with one command.
- Every app namespace: PSA `restricted` or Kyverno equivalent enforcing,
  default-deny network policy, documented exceptions with expiry.
- Every build pipeline: Harden-Runner in block mode, lint and scan gates
  blocking, provenance attested.
- One runbook entry per alert type the runtime agent can raise.
