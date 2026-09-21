#!/usr/bin/env bash
# Runs ON the EC2 Docker host (installed at /opt/acme/deploy-ssm.sh by config
# management, invoked through SSM by the workflow). Fetches secrets, then hands
# off to the generic verify-and-deploy.sh.
set -euo pipefail

IMAGE="${1:?image@digest}"
APP_DIR=/opt/acme/api
SECRET_ID=prod/acme/api          # Secrets Manager entry, JSON with one key per secret

cd "$APP_DIR"

# Registry login with the instance role (no credentials on disk)
aws ecr get-login-password | docker login --username AWS --password-stdin "${IMAGE%%/*}"

# Secrets to files under ./secrets, readable by the container user only
umask 077
mkdir -p secrets
aws secretsmanager get-secret-value --secret-id "$SECRET_ID" --query SecretString --output text \
  | python3 -c 'import json,sys; [open(f"secrets/{k}","w").write(v) for k,v in json.load(sys.stdin).items()]'
chown -R 65532:65532 secrets

# Verify signature + provenance, pull by digest, compose up
/opt/acme/verify-and-deploy.sh "$IMAGE" docker-compose.aws.yml
