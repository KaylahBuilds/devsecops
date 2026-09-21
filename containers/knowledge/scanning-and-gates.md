# Scanning and where to gate

Scanners find known problems in known places. The value comes from where
you run them and what you do with the output. Effort ratings per `../README.md`.

## What each layer catches

| Tool (examples) | Layer | Finds | Misses |
|---|---|---|---|
| hadolint | Dockerfile | `:latest`, root user, `apt` without cleanup, `curl \| sh`, secrets in `ARG` | anything about the resulting image |
| Trivy / Grype | image | OS package CVEs, language dependency CVEs, secrets in layers, misconfig | zero-days, custom code bugs, runtime behaviour |
| Trivy config / Checkov / kube-linter | manifests, Helm | privileged pods, missing limits, hostPath, missing probes | cluster-side reality (what is actually running) |
| Syft + Grype | SBOM | the same CVEs, but queryable across the fleet later | same as image scan |
| Kyverno / Gatekeeper | admission | anything the manifest scanners find, at the last moment, plus signature and provenance | runtime |
| Falco / agent | runtime | behaviour: shells, unexpected network, file writes | vulnerabilities that are not exploited |

## Where to gate (S each, once the tool runs)

1. **PR**: hadolint and manifest lint block. Fast, deterministic, no noise.
2. **Build**: image scan. Block on **critical with a fix available**, warn on
   high, ignore unfixed. Blocking on unfixed CVEs teaches teams to disable
   the gate.
3. **Registry**: scan on push as a second opinion; surfaces images built
   outside CI.
4. **Admission**: signature, provenance, registry allow-list, no `:latest`.
5. **Cluster, continuously**: rescan running images nightly; new CVEs
   appear in old images.

## Noise control (S, revisit monthly)

- Fix the base image first; it usually owns 80 percent of findings.
- `.trivyignore` with a reason and an expiry per entry; review expired
  entries in the weekly bump PR.
- Severity from the vendor feed (Debian, Alpine, GitHub Advisory) beats NVD
  alone: Trivy already prefers vendor data.
- VEX statements for "not affected" when the vulnerable function is not
  reachable; supported by Trivy and Grype.
- SLA: critical fixed in 7 days, high in 30, tracked per image owner.

## SARIF to GitHub code scanning (S)

Both Trivy and Grype emit SARIF; upload with `github/codeql-action/upload-sarif`
and findings appear in the Security tab with the rest of GHAS. Requires
`security-events: write` on the job.

## Sizing note

Getting a scanner to run: hours. Getting a team to keep it green: weeks,
because it changes who patches what. Put the gate on warn for two weeks,
publish the counts, then block. The timeline in `../TIMELINE.md` assumes
that sequence.
