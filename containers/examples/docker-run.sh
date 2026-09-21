#!/usr/bin/env bash
# The api service from docker-compose.hardened.yml as a single docker run,
# for hosts without Compose. One flag per line so a review can see each control.
set -euo pipefail

IMAGE="ghcr.io/acme/api@sha256:0000000000000000000000000000000000000000000000000000000000000000"

docker network inspect api-frontend >/dev/null 2>&1 || docker network create api-frontend

exec docker run \
  --name api \
  --detach \
  --restart unless-stopped \
  --user 65532:65532 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 256 \
  --memory 256m \
  --cpus 0.5 \
  --network api-frontend \
  --publish 127.0.0.1:8080:8080 \
  --env NODE_ENV=production \
  --env PORT=8080 \
  --mount type=bind,source=/etc/acme/api/db_password,target=/run/secrets/db_password,readonly \
  --log-driver json-file \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  --health-cmd "/nodejs/bin/node -e \"fetch('http://127.0.0.1:8080/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))\"" \
  --health-interval 30s \
  --health-timeout 3s \
  --health-retries 3 \
  "$IMAGE"
