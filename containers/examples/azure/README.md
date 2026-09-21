# Azure: ACR + Docker hosts on Azure VMs

The generic pipeline in `../container-security.yml` with Azure pieces
swapped in. No client secrets anywhere: GitHub OIDC gets a token through a
federated credential on a user-assigned managed identity, and the VMs pull
with their own managed identity.

```
acr.tf                          ACR (admin user off, no anonymous pull, retention, private by default)
                                + managed identity with a GitHub federated credential and AcrPush
container-security-azure.yml    build, scan, sign, push to ACR, then deploy to VMs with Run Command (no SSH)
docker-compose.azure.yml        the service with secrets from Key Vault and logs shipped by the Azure Monitor agent
deploy-run-command.sh           what runs on each VM: fetch secrets, verify, compose up
```

## How it fits

| Step | Azure piece | Why |
|---|---|---|
| Push | `azure/login` with `client-id` + `tenant-id` + `subscription-id` (OIDC), identity has `AcrPush` on the registry only | no client secret in GitHub |
| Registry | ACR Premium: admin user disabled, anonymous pull off, public network off with a private endpoint (or allow-listed CI egress), retention policy for untagged manifests | tags are mutable in ACR by default: lock releases with `az acr repository update --write-enabled false` or deploy by digest only (we do the latter) |
| Scan | Microsoft Defender for Containers scans on push and continuously | second opinion to Trivy, findings in Defender for Cloud |
| Sign | cosign keyless; ACR supports OCI referrers | `cosign verify` works against ACR directly |
| Deploy | `az vm run-command invoke` on VMs tagged `role=docker` | no inbound SSH; output in the activity log |
| Secrets | `az keyvault secret show` on the VM with its managed identity, written to `/run/secrets/*` | never in Compose, image, or environment |
| Logs | Azure Monitor agent on the VM collecting the Docker json-file logs | keep the `json-file` driver with size limits; the agent ships them |
| Pull on VM | VM system-assigned identity with `AcrPull` | no registry credentials on disk |

## Apply order

1. `terraform apply` in this folder.
2. Put the outputs `client_id`, `tenant_id`, `subscription_id` in repo
   secrets `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`.
3. Give the Docker VMs a system-assigned identity with `AcrPull` on the
   registry and `Key Vault Secrets User` on the vault; tag them `role=docker`.
4. Merge to `main`; the workflow pushes and deploys.

## Effort

| Task | Effort |
|---|---|
| ACR + identity + federated credential (this Terraform) | S |
| Private endpoint for ACR (if CI egress cannot be allow-listed) | M |
| Workflow adaptation | S |
| VM identities, Run Command extension, Azure Monitor agent | S per host group |
| Key Vault entries + rotation | S, M with rotation |
