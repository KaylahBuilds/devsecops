# Container security programme (Docker hosts): timeline for sizing

Assumptions: about 10 services, 3 build pipelines (Node, Python, Go),
deployed with Docker Compose onto a handful of Linux hosts per environment,
images in one registry, GitHub Actions with StepSecurity already in place.
Adjust the "per pipeline" and "per host" lines for your numbers.

## Phase 0: baseline (1 week, one engineer)

Know what you have before changing it.

| Task | Effort | Output |
|---|---|---|
| Inventory images in production: `docker ps` across hosts joined with the registry | S | spreadsheet of image, tag, digest, base image, owner, host |
| Scan everything once with Trivy, no gates | S | count of critical/high per image; the top 10 base images |
| Lint every Dockerfile with hadolint, no gates | S | list of `:latest`, root users, `curl \| sh`, secrets in `ARG` |
| Run Docker Bench for Security on one host per environment | S | CIS Docker Benchmark pass/fail list; expect 20 to 40 warnings on an untouched host |
| Record who can reach the Docker socket (group `docker`, mounted sockets, TCP listeners) | S | one page; this is usually the worst finding |

Exit: a ranked list of images by risk, the Bench report, and agreement on
which 3 services go first.

## Phase 1: build-time hardening (3 to 5 weeks)

| Task | Effort | Notes |
|---|---|---|
| Hardened Dockerfile template per language | M per pipeline | multi-stage, distroless or slim base, non-root, `COPY --chown`, pinned digests. First one is M, the rest are S once the pattern exists |
| Migrate the 3 pilot services | M | expect one surprise per service: a native module that needs glibc, a shell in an entrypoint, a `curl`-based healthcheck |
| hadolint in CI, warn only | S | `.hadolint.yaml` in this folder |
| Trivy in CI, warn only, SARIF to code scanning | S | `container-security.yml` |
| Digest pinning via StepSecurity remediation PRs | S | `secure_docker_file = true` in the org's `policy_driven_prs`; one PR per repo |
| Flip lint and scan to blocking on the pilots | S | after two clean weeks |

Exit: pilots build from the template, CI blocks new criticals, base images
are pinned by digest and bumped by bot PRs.

## Phase 2: supply chain proof (2 to 4 weeks)

| Task | Effort | Notes |
|---|---|---|
| SBOM generation and attestation on every build | S per pipeline | BuildKit `sbom: true` or Syft; attach with cosign |
| Keyless signing with cosign via GitHub OIDC | M | one-time trust setup, then a step per pipeline. Decide identity: the workflow file on the default branch |
| SLSA provenance attestation | S | `actions/attest-build-provenance` |
| Registry hygiene: immutable tags, retention, no anonymous pull | S | `examples/aws/ecr.tf` or `examples/azure/acr.tf`; ACR tags stay mutable, so lock release tags in the workflow |
| Cloud identity for push and deploy (OIDC, no static credentials) | S | same Terraform files; the deploy role/identity is scoped to tagged hosts only |
| Private base image mirror or Chainguard/Distroless subscription decision | M | a procurement conversation; start it in week 1 |

Exit: every image the pipeline pushes carries an SBOM, provenance and a
verifiable signature.

## Phase 3: deploy-time verification and host hardening (2 to 4 weeks)

Docker has no admission controller, so the gate is the deploy script and
the daemon.

| Task | Effort | Notes |
|---|---|---|
| Deploy wrapper: cosign verify, pull by digest, compose up | S | `verify-and-deploy.sh`; the only path allowed to start production containers |
| Remote execution without SSH: SSM Run Command (AWS) or VM Run Command (Azure), hosts selected by tag | S per host group | `examples/aws/deploy-ssm.sh`, `examples/azure/deploy-run-command.sh`; needs the agent and an instance/VM identity with registry pull and secret read |
| Secrets delivered as files at deploy time from Secrets Manager / Key Vault | S per service | the deploy scripts do it; rotation is the M-sized follow-up |
| Compose files reference digests, never tags | S per service | bot PRs bump them |
| Hardened `daemon.json` rolled out with config management | M per host group | `daemon.json`; `userns-remap` is the one that breaks things (volume ownership), do it last |
| Docker socket lockdown: no TCP listener, `docker` group emptied, no socket mounts into containers | M | every CI agent and monitoring tool that mounts the socket needs a replacement (socket proxy or API token) |
| Docker Bench in CI against a staging host, warn then block | S | |
| Rootless Docker on hosts that can take it | L | changes networking, ports below 1024, and storage; pilot on one host group |

Exit: nothing runs in production that was not verified and pulled by
digest; Bench is clean on the checks you chose to enforce.

## Phase 4: runtime least privilege and detection (3 to 5 weeks, overlaps phase 3)

| Task | Effort | Notes |
|---|---|---|
| Compose template: `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, `user`, `pids_limit`, memory limits, `tmpfs` | M | `docker-compose.hardened.yml`; apps that write to disk need a `tmpfs` or named volume |
| Migrate services to the template | S per service | one surprise per three services (a process that needs one capability back) |
| Networks: user-defined bridges per app, `internal: true` for backends, `icc=false` on the daemon | M per host group | the two everyone forgets: DNS for containers on internal networks, and the metrics scraper |
| Secrets via Compose `secrets:` (files), not environment variables | S per service | |
| Runtime detection (Falco or a commercial agent) on one host group, alerts to the security channel | M | tune for two weeks before paging anyone |
| Host: minimal OS, unattended security updates, auditd rules for Docker files (CIS section 1) | M | often owned by the platform team already |

Exit: services run with the profile in `docker-compose.hardened.yml` or a
documented exception; a shell spawned in a production container pages someone.

## Phase 5: steady state (ongoing, about 10 percent of one engineer)

- Base image and Compose digest bumps arrive as bot PRs; merge weekly.
- Scan gates stay on; triage new criticals within the SLA (suggest 7 days for critical, 30 for high).
- Quarterly: re-run the phase 0 inventory and Bench, compare.

## Roll-up

| Phase | Elapsed | Engineer effort | Can overlap with |
|---|---|---|---|
| 0 baseline | 1 week | 1 | nothing, do it first |
| 1 build-time | 3 to 5 weeks | 1 to 1.5 | phase 2 after week 2 |
| 2 supply chain | 2 to 4 weeks | 1 | phase 1 |
| 3 deploy-time and host | 2 to 4 weeks (+ rootless pilot) | 1 | phase 4 |
| 4 runtime | 3 to 5 weeks | 1 | phase 3 |
| 5 steady state | ongoing | 0.1 | |

Realistic total for the assumed scope: **one engineer for one quarter to
reach phase 2, one to two engineers for a second quarter to land phases 3
and 4.** Docker hosts make phases 3 and 4 cheaper than a Kubernetes rollout
would be (no cluster-wide admission to negotiate), but each host group is
its own change window, and the socket lockdown touches every tool that
talks to Docker. Those two items are the ones to defend when the timeline
is questioned.

## Where estimates go wrong

- **"Just switch to distroless."** Any service that shells out, uses a
  native module linked against glibc, or has a `curl`-based healthcheck
  needs code changes. Budget one surprise per service.
- **The Docker socket.** CI runners, log shippers, reverse proxies with
  auto-discovery and monitoring agents all want `/var/run/docker.sock`.
  Mounting it is root on the host. Each one needs a socket proxy with a
  read-only allow-list or a different integration.
- **`userns-remap`** changes the uid every volume is owned by. Existing
  named volumes need a one-time chown; bind mounts need thought. Do it per
  host group with a rollback.
- **Signing identity decisions** stall on who is allowed to sign. Decide
  early: signature identity = the workflow file on the default branch.
- **`icc=false` and internal networks** break things silently (DNS,
  sidecars, a service that talked to another over the default bridge).
  Roll out per host group with a fast rollback.
- **Scanner noise.** A first Trivy run on an old image reports hundreds of
  findings, most in the base image. Fix the base image first; the count
  drops by an order of magnitude.

## Definition of done for the programme

- Every production image: pinned base digest, non-root, no critical CVEs
  older than the SLA, SBOM and signature verifiable with one command.
- Every host: hardened `daemon.json`, no socket exposure, Bench clean on
  the enforced checks, security updates unattended.
- Every service: started only through the verify-and-deploy path, by
  digest, with the Compose least-privilege profile or a documented
  exception with expiry.
- Every build pipeline: Harden-Runner in block mode, lint and scan gates
  blocking, provenance attested.
- One runbook entry per alert type the runtime agent can raise.
