# Image hardening (build time)

What goes into the image decides most of what an attacker can do with it
later. These controls are ordered by payoff per effort. Effort ratings use
the scale in `../README.md`.

## 1. Base image choice (M first time, S after)

| Option | Size | Shell / package manager | CVE surface | When |
|---|---|---|---|---|
| `ubuntu` / `debian` full | 70 to 120 MB | yes | large | never for production services |
| `debian:*-slim`, `python:*-slim` | 40 to 80 MB | yes | medium | services that need apt at build time; use as the **builder** stage |
| `alpine` | 5 to 10 MB | yes (busybox) | small | fine for Go; musl breaks some Python/Node native modules |
| `gcr.io/distroless/*` | 2 to 30 MB | no shell | small | default for the **runtime** stage |
| Chainguard / Wolfi images | small | optional | smallest, patched daily | when you can pay for the SLA, or use the free `latest` tags |
| `scratch` | 0 | nothing | none | statically linked Go/Rust only |

Rule: build in a full image, run in a distroless one. The runtime stage
must not contain a package manager, a shell, or compilers. If you need a
shell for debugging use `docker debug` (Docker Desktop / Scout) or start a
sidecar that shares the PID namespace: `docker run --pid container:<id> ...`.

## 2. Multi-stage builds (S)

Compile, install and test in stage one; copy only the artefacts into stage
two. Side effects: build tools, `.git`, test fixtures and credentials used
during the build never reach the runtime layer. See `Dockerfile.hardened`.

## 3. Pin everything by digest (S, then automated)

`FROM python:3.12-slim` moves every time upstream rebuilds. Pin to
`python:3.12-slim@sha256:...` and let a bot bump it. Two ways in this repo:

- Dependabot with `package-ecosystem: docker` (Dependabot understands digests).
- StepSecurity remediation PRs with `secure_docker_file = true`, which
  rewrites tags to digests across the org.

The same applies to `apt`, `pip`, `npm`: lockfiles committed, installs with
`--require-hashes`, `npm ci`, `pip install --no-deps -r requirements.txt`.

## 4. Run as a non-root user (S per image, M if the app writes to disk)

```dockerfile
COPY --chown=nonroot:nonroot --from=build /app /app
USER nonroot:nonroot
```

Distroless images ship a `nonroot` user (uid 65532). Consequences you will
hit: cannot bind ports below 1024 (use 8080 and publish `-p 80:8080`),
cannot write to `/` (use a `tmpfs` mount for scratch space), file ownership
must be set at `COPY` time.

## 5. No secrets in the image (S)

Never `ARG` or `ENV` a token: both persist in image history. Use BuildKit
secret mounts for build-time credentials and inject runtime secrets from
the orchestrator:

```dockerfile
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci
```

Scan for leaks anyway (`trivy image --scanners secret`).

## 6. Minimal surface (S)

- One process per container, `ENTRYPOINT` in exec form, no `sh -c`.
- No `curl | sh` installs; download, verify checksum, then install.
- `rm -rf /var/lib/apt/lists/*` in the same `RUN` layer as `apt-get`.
- `.dockerignore` with `.git`, `node_modules`, `*.env`, test data.
- No `EXPOSE` of ports the process does not listen on; `HEALTHCHECK`
  without `curl` (distroless has none): use the runtime you already ship,
  e.g. `node -e` with `fetch`, or a tiny static health binary.

## 7. Labels and metadata (S)

OCI labels (`org.opencontainers.image.source`, `.revision`, `.created`)
make an image traceable back to a commit without the registry's help.
The Docker `metadata-action` in the workflow example sets them.

## 8. SBOM at build time (S)

Generate a CycloneDX or SPDX SBOM per image and attach it as an attestation
so it travels with the image. `docker buildx build --sbom=true` or Syft.
An SBOM without a way to query it across images is a checkbox; pair it
with a place to search ("which images contain log4j 2.14?").

## 9. Reproducibility (M, optional)

`SOURCE_DATE_EPOCH`, sorted file lists and pinned everything give
bit-for-bit rebuildable images. Worth it for regulated environments;
otherwise provenance attestation (see `supply-chain.md`) gives most of the
assurance for less work.

## Quick checklist for a code review

- [ ] Runtime stage is distroless/slim/scratch, no shell or package manager
- [ ] `FROM` lines pinned by digest
- [ ] `USER` is non-root and files are `--chown`ed
- [ ] No `ARG`/`ENV` secrets; BuildKit secret mounts for build creds
- [ ] Lockfiles used; no `curl | sh`
- [ ] `.dockerignore` present
- [ ] `ENTRYPOINT` exec form; one process
- [ ] hadolint clean; Trivy shows no critical/high in the final stage
