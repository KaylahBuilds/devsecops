# containers — image hardening and container security

Knowledge base and working examples for hardening container images and
running them safely, written so a staff engineer can size the work. Every
control carries an effort rating; `TIMELINE.md` rolls them up into phases.

```
TIMELINE.md                      phased plan, effort per phase, dependencies, risks, definition of done
knowledge/
  image-hardening.md             build-time: base images, layers, users, secrets, pinning, SBOM, signing
  supply-chain.md                provenance, registries, admission, policy-as-code
  runtime-security.md            Kubernetes pod hardening, capabilities, seccomp, network, detection
  scanning-and-gates.md          scanners, what they catch, where to gate, noise control
examples/
  Dockerfile.before              a typical "works on my machine" image, annotated with what is wrong
  Dockerfile.hardened            the same service, hardened: multi-stage, distroless, non-root, pinned
  .hadolint.yaml                 Dockerfile linter config
  container-security.yml         GitHub Actions: build, scan, SBOM, sign, push, behind Harden-Runner
  pod-hardened.yaml              Kubernetes Deployment with a locked-down securityContext
  network-policy.yaml            default-deny plus explicit egress
  kyverno-policies.yaml          admission rules: signed images only, no :latest, non-root, no privileged
  trivy.yaml                     scanner config with severity gates and ignore file conventions
```

## Effort scale used throughout

| Rating | Meaning | Typical elapsed time |
|---|---|---|
| S | one engineer, well-understood, mostly config | up to 2 days |
| M | one engineer, some discovery, touches several repos or a cluster | 3 to 8 days |
| L | cross-team, migrations, or changes that can break production | 2 to 5 weeks |

Elapsed time assumes one engineer with platform access and a security
reviewer available. Multiply by the number of independent build pipelines
where the note says "per pipeline".

## How the pieces fit

1. **Build** a small, pinned, non-root image (`Dockerfile.hardened`).
2. **Prove** what is in it: SBOM, vulnerability scan, provenance, signature
   (`container-security.yml`).
3. **Admit** only images that carry that proof (`kyverno-policies.yaml`).
4. **Run** them with the least privilege the workload tolerates
   (`pod-hardened.yaml`, `network-policy.yaml`).
5. **Watch** for the things the above cannot prevent (runtime detection,
   `runtime-security.md`).

Each step is useful on its own; the order is the order of cheapest wins.

## Relation to the rest of this repo

The build workflow starts with StepSecurity Harden-Runner in block mode and
the policy-driven PRs in `stepsecurity/` can pin Docker base images to
digests for you (`secure_docker_file = true`). Nothing here depends on the
AWS module.
