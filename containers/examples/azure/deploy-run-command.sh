#!/usr/bin/env bash
# Runs ON the Azure VM (installed at /opt/acme/deploy-run-command.sh by config
# management, invoked through Run Command by the workflow). Fetches secrets with
# the VM's managed identity, then hands off to the generic verify-and-deploy.sh.
set -euo pipefail

IMAGE="${1:?image@digest}"
APP_DIR=/opt/acme/api
REGISTRY="${IMAGE%%/*}"
VAULT=kv-acme-api               # Key Vault; VM identity has "Key Vault Secrets User"

cd "$APP_DIR"

# Managed identity login, then registry login with a short-lived token
az login --identity --allow-no-subscriptions > /dev/null
az acr login --name "${REGISTRY%%.*}" > /dev/null

# Secrets to files under ./secrets, readable by the container user only
umask 077
mkdir -p secrets
for NAME in db-password; do
  az keyvault secret show --vault-name "$VAULT" --name "$NAME" --query value -o tsv > "secrets/${NAME//-/_}"
done
chown -R 65532:65532 secrets

# Verify signature + provenance, pull by digest, compose up
/opt/acme/verify-and-deploy.sh "$IMAGE" docker-compose.azure.yml
echo "DEPLOY OK"
