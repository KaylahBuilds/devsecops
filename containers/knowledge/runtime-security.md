# Runtime security (Docker Engine and Compose)

A hardened image still runs with whatever the daemon and the `docker run`
or Compose options allow. These controls shrink what a compromised process
can do. Effort ratings per `../README.md`.

## 1. The Docker socket is root (S to find, M to fix)

Anyone who can talk to `/var/run/docker.sock` can start a privileged
container with the host filesystem mounted. Treat socket access as root
access:

- Empty the `docker` group; use `sudo` with logging for humans.
- Never expose the daemon on TCP without mutual TLS (`tlsverify` in
  `daemon.json`); prefer not at all.
- Never mount the socket into a container. Tools that need it (reverse
  proxies with auto-discovery, log shippers, CI agents) get a socket proxy
  such as `tecnativa/docker-socket-proxy` with a read-only allow-list.

## 2. Daemon hardening (M per host group)

`../examples/daemon.json` sets:

| Option | Effect |
|---|---|
| `no-new-privileges: true` | default for every container; setuid binaries gain nothing |
| `icc: false` | containers on the default bridge cannot talk to each other unless linked by a user-defined network |
| `userns-remap: default` | root inside a container maps to an unprivileged uid on the host; the strongest single setting and the one that breaks volume ownership, roll out last |
| `live-restore: true` | containers survive a daemon restart, so patching the daemon is not an outage |
| `log-driver` with `max-size` | a chatty container cannot fill the disk |
| `default-ulimits` | fd and process limits |
| `userland-proxy: false` | fewer host processes per published port |
| `seccomp-profile` (optional) | a stricter profile than the default |

Roll out with configuration management; Docker Bench checks most of these.

## 3. Per-container least privilege: the eight options (S per service)

In `docker run` or Compose form (`../examples/docker-run.sh`,
`../examples/docker-compose.hardened.yml`):

| Option | Compose key | Why |
|---|---|---|
| `--user 65532:65532` | `user:` | run as the image's non-root user even if the image forgot `USER` |
| `--read-only` | `read_only: true` | root filesystem immutable; writes go to `tmpfs` or a volume |
| `--tmpfs /tmp:rw,noexec,nosuid,size=64m` | `tmpfs:` | scratch space without a writable image layer |
| `--cap-drop ALL` (+ `--cap-add NET_BIND_SERVICE` only if binding < 1024) | `cap_drop: [ALL]` | the kernel capabilities a process gets by default are far more than a web service needs |
| `--security-opt no-new-privileges` | `security_opt:` | belt and braces with the daemon default |
| `--pids-limit 256` | `pids_limit:` | stops fork bombs |
| `--memory 256m --cpus 0.5` | `mem_limit:`, `cpus:` | a compromised container cannot starve the host; miners become obvious |
| `--restart unless-stopped` and a `HEALTHCHECK` | `restart:`, `healthcheck:` | availability, not security, but it is what lets you kill a bad container without a page |

Never: `--privileged`, `--pid host`, `--net host` (except for a monitoring
agent that documents why), `-v /:/host`, `-v /var/run/docker.sock`.

## 4. Networks (M per host group)

- One user-defined bridge network per application stack; the default
  bridge gets nothing.
- `internal: true` for networks that only backends use (database, cache):
  no route to the outside.
- Publish ports on `127.0.0.1:` when a reverse proxy on the host fronts
  the service; `-p 8080:8080` binds on every interface and bypasses host
  firewalls that only filter INPUT (Docker writes its own iptables rules).
- Egress filtering per container needs a proxy or host firewall on the
  `DOCKER-USER` chain; plan it if the service handles secrets.

## 5. Secrets (S per service)

Compose `secrets:` mounts a file at `/run/secrets/<name>` (tmpfs in Swarm,
bind-mounted file in plain Compose). Prefer that over `environment:`, which
leaks into `docker inspect`, crash dumps and child processes. Never put
secrets in the image or in `docker-compose.yml` itself; use `.env` files
kept out of git, or a secret manager that writes the files at deploy time.

## 6. Rootless Docker (L to pilot)

The daemon itself runs as an unprivileged user, so a container escape
lands as that user, not root. Costs: ports below 1024 need `sysctl` or a
proxy, overlay networking is slower, some storage drivers are unavailable,
and every tool that assumed `/var/run/docker.sock` moves to a per-user
socket. Pilot on one host group after the rest of this list is in place.

## 7. Host (M, usually the platform team)

- Minimal OS, unattended security updates, no SSH password auth.
- auditd rules for `/var/lib/docker`, `/etc/docker`, the socket and the
  service files (CIS Docker Benchmark section 1).
- Separate partition for `/var/lib/docker`.
- Kernel: AppArmor or SELinux enabled; Docker applies `docker-default`
  automatically when available.
- Keep the engine current; container escapes are usually runc or kernel
  bugs fixed in the next release.

## 8. Runtime detection (M install, ongoing tuning)

Falco runs on plain Docker hosts and flags: shell spawned in a container,
outbound connection from an unexpected process, write below `/etc`,
privilege escalation, crypto-miner patterns. Route to the same channel as
StepSecurity CI alerts. Budget two weeks of tuning before anything pages.

## 9. Docker Bench for Security (S)

`docker/docker-bench-security` scores a host against the CIS Docker
Benchmark: daemon config, files and permissions, image and runtime
options for every running container. Run it in phase 0 for the baseline,
then in CI against a staging host. It is a checklist, not a scanner: it
tells you a container runs without `no-new-privileges`, not that the
process inside is malicious.

## Checklist for a host to be "done"

- [ ] No TCP daemon listener; `docker` group empty; no socket mounts
- [ ] `daemon.json` from `../examples/daemon.json` applied
- [ ] Every service uses the Compose least-privilege profile or has a documented exception
- [ ] Backend networks `internal: true`; ports published on loopback behind a proxy
- [ ] Secrets as files, not environment
- [ ] Bench clean on the enforced checks; runtime detection rules routed
