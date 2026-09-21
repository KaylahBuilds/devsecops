#!/usr/bin/env bash
# The only path that starts production containers:
#   1. resolve the tag to a digest (or accept a digest),
#   2. verify the cosign signature against the expected build identity,
#   3. verify SLSA provenance,
#   4. pull by digest,
#   5. rewrite the Compose file to that digest and bring the stack up.
# Usage: verify-and-deploy.sh ghcr.io/acme/api:sha-<commit>  [compose-file]
set -euo pipefail

REF="${1:?image reference (tag or digest)}"
COMPOSE="${2:-docker-compose.yml}"
REPO="${REF%%[:@]*}"
IDENTITY_RE='^https://github.com/acme/[^/]+/\.github/workflows/container-security\.yml@refs/heads/main$'
ISSUER='https://token.actions.githubusercontent.com'

# 1. digest
if [[ "$REF" == *@sha256:* ]]; then
  DIGEST="${REF#*@}"
else
  DIGEST="$(crane digest "$REF")"          # crane: go install github.com/google/go-containerregistry/cmd/crane@latest
fi
IMAGE="${REPO}@${DIGEST}"
echo "resolved ${REF} -> ${IMAGE}"

# 2. signature: keyless, identity pinned to the default-branch workflow
cosign verify \
  --certificate-identity-regexp "$IDENTITY_RE" \
  --certificate-oidc-issuer "$ISSUER" \
  "$IMAGE" > /dev/null
echo "signature ok"

# 3. provenance: built by GitHub Actions from the expected repo
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp "$IDENTITY_RE" \
  --certificate-oidc-issuer "$ISSUER" \
  "$IMAGE" > /dev/null
echo "provenance ok"

# 4. pull by digest only
docker pull "$IMAGE" > /dev/null

# 5. pin the compose file to this digest and deploy
sed -i.bak -E "s#(image: ${REPO})[@:][^[:space:]]+#\1@${DIGEST}#" "$COMPOSE"
if grep -Eq 'image: [^[:space:]]+:[^@[:space:]]+$' "$COMPOSE"; then
  echo "refusing: ${COMPOSE} still references an image by tag" >&2
  exit 1
fi
docker compose -f "$COMPOSE" up -d --remove-orphans
docker compose -f "$COMPOSE" ps
