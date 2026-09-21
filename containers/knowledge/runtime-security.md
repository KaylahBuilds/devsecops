# Runtime security (Kubernetes)

A hardened image still runs as whatever the pod spec allows. These controls
shrink what a compromised process can do. Effort ratings per `../README.md`.

## 1. Pod Security Admission (S per namespace, M to get every workload compliant)

Kubernetes' built-in admission enforces three profiles per namespace via
labels: `privileged`, `baseline`, `restricted`. Target `restricted` on app
namespaces:

```bash
kubectl label ns payments pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted
```

`restricted` requires: non-root, no privilege escalation, all capabilities
dropped (NET_BIND_SERVICE may be added back), seccomp profile set, no
hostPath/hostNetwork/hostPID, volume types limited. `../examples/pod-hardened.yaml`
passes it.

## 2. securityContext, the six lines that matter (S per workload)

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities: { drop: ["ALL"] }
  seccompProfile: { type: RuntimeDefault }
```

`readOnlyRootFilesystem` is the one that needs application knowledge:
anything that writes to `/tmp` or a cache dir needs an `emptyDir` mount.

## 3. Resource limits (S)

CPU and memory limits are a security control: a compromised pod without
limits can starve its neighbours. Memory limits also make crypto-miners
obvious.

## 4. Network policy (M per cluster)

Default-deny ingress and egress per namespace, then allow explicitly. The
two everyone forgets: DNS egress to kube-dns, and ingress from the metrics
scraper. `../examples/network-policy.yaml` shows both. Egress allow-lists
by FQDN need a CNI that supports it (Cilium) or an egress gateway.

## 5. Service accounts and the API (S)

- `automountServiceAccountToken: false` unless the pod talks to the API.
- One service account per workload, RBAC scoped to what it uses.
- No workload gets `cluster-admin`; audit with `kubectl auth can-i --list`.

## 6. Secrets (S to M)

Secrets from the orchestrator, not the image. Prefer a CSI secrets driver
or external-secrets with a cloud secret manager over plain Kubernetes
Secrets, and encrypt etcd at rest either way. Mount as files, not env
vars, where the app allows it: env vars leak into crash dumps and child
processes.

## 7. Node and kernel (M, usually the platform team)

- Minimal, immutable node OS (Bottlerocket, Flatcar, COS).
- No SSH; break-glass via the cloud console session tooling.
- `kernel.unprivileged_userns_clone` reviewed; user namespaces in
  Kubernetes (`hostUsers: false`) once the cluster version supports it.
- Container runtime with seccomp and AppArmor/SELinux enabled by default.
- gVisor or Kata for workloads that run untrusted code.

## 8. Runtime detection (M install, ongoing tuning)

Falco (open source) or a commercial agent watches syscalls and flags:
shell spawned in a container, outbound connection from an unexpected
process, write to `/etc`, privilege escalation, crypto-miner patterns.
Route to the same channel as StepSecurity CI alerts. Budget two weeks of
tuning before anything pages.

## 9. Things admission cannot catch

- A legitimate image with a vulnerable dependency exploited at runtime:
  scanning plus detection.
- A leaked service account token used from outside: short-lived projected
  tokens, audience binding, API audit logs.
- Lateral movement through allowed network paths: network policy is only
  as tight as the allow rules; review them with the app teams.

## Checklist for a namespace to be "done"

- [ ] PSA `restricted` enforced (or Kyverno equivalent)
- [ ] Every Deployment has the six securityContext lines and limits
- [ ] Default-deny NetworkPolicy plus explicit allows
- [ ] Service account token not automounted unless needed
- [ ] Secrets from a secret manager, mounted as files
- [ ] Runtime detection rules enabled and routed
