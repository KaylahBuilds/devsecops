# Supply chain: proving where an image came from

Hardening the image is half the job; the other half is making sure the
image that runs is the image you built. Effort ratings per `../README.md`.

## 1. Signing with cosign, keyless (M once, S per pipeline)

Keyless signing uses the GitHub Actions OIDC token as identity, so there is
no private key to manage. The signature is stored in the registry next to
the image and recorded in the public Rekor transparency log (or a private
Sigstore instance for regulated environments).

```bash
cosign sign --yes "$IMAGE@$DIGEST"
cosign verify \
  --certificate-identity-regexp '^https://github.com/acme/.+/\.github/workflows/container-security\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$IMAGE@$DIGEST"
```

Decide the identity early: **the workflow file on the default branch**.
Signing from PR branches lets anyone with a PR mint a valid signature.

## 2. Provenance (S)

SLSA provenance is a signed statement of "this artefact was built by this
workflow from this commit with these inputs". `actions/attest-build-provenance`
produces it in one step and admission controllers can require it. Aim for
SLSA level 3: hosted, isolated builders (GitHub-hosted runners with
Harden-Runner qualify) and provenance the builder generates, not the job.

## 3. SBOM attestation (S)

Attach the SBOM as an in-toto attestation (`cosign attest --type cyclonedx`)
so a consumer can fetch it from the registry by digest. Store a copy in a
searchable place (Dependency-Track, GitHub's dependency submission API, or
even a bucket plus a script).

## 4. Registry hygiene (S per registry)

- Immutable tags on production repositories.
- No anonymous pull; pull-through cache for public images so builds do not
  depend on Docker Hub rate limits or availability.
- Retention: untagged manifests deleted after 30 days, tagged after 180
  unless referenced by a deployment.
- Registry scanning on push as a second opinion to CI scanning.

## 5. Admission: only admit what is proven (M policies, L rollout)

An admission controller (Kyverno, OPA Gatekeeper, or the cloud provider's
Binary Authorization) checks every pod before scheduling:

- image is signed by the expected identity;
- image carries provenance from an allowed builder;
- image is from an allowed registry;
- no `:latest`, digest present.

`../examples/kyverno-policies.yaml` covers these. Run in **Audit** mode
first; the audit report is the to-do list for the rollout.

## 6. Base image supply (M, mostly a decision)

Someone has to patch the base images you build on. Options in rising cost
and assurance: upstream official images (patched on their schedule),
Google Distroless (free, rebuilt often), Chainguard/Wolfi (patched daily,
paid SLA), your own golden images (full control, full cost). The decision
gates phase 2 of the timeline; start it in week one.

## 7. Verifying in the deployment pipeline too (S)

Admission control catches the cluster; verify in the CD step as well so
a policy engine outage does not become a bypass:

```bash
cosign verify ... "$IMAGE@$DIGEST" && kubectl set image ...
```

## Threats this addresses

| Threat | Control |
|---|---|
| Registry compromise swaps an image | signature + digest pinning |
| Malicious PR builds and pushes an image | identity restricted to the default-branch workflow; Harden-Runner egress block on the build job |
| Upstream base image compromised | pinned digests, SBOM diff on bump PRs, scanning |
| Dependency confusion during build | lockfiles with hashes, private registry mirror, egress allow-list |
| "Who is affected by CVE X?" takes days | SBOMs in a searchable store |
