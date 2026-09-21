# AWS: ECR + Docker hosts on EC2

The generic pipeline in `../container-security.yml` with AWS pieces swapped
in. No static keys anywhere: GitHub OIDC assumes an IAM role to push, and
the hosts pull with their instance role.

```
ecr.tf                        ECR repository (immutable tags, scan on push, KMS, lifecycle) + the GitHub OIDC push role
container-security-aws.yml    build, scan, sign, push to ECR, then deploy to hosts through SSM (no SSH)
docker-compose.aws.yml        the service with secrets from Secrets Manager and logs to CloudWatch
deploy-ssm.sh                 what the workflow runs on each host: fetch secrets, verify, compose up
```

## How it fits

| Step | AWS piece | Why |
|---|---|---|
| Push | `aws-actions/configure-aws-credentials` with `role-to-assume` (OIDC) | no long-lived keys in GitHub |
| Registry | ECR with `image_tag_mutability = IMMUTABLE`, `scan_on_push`, KMS | tags cannot be re-pointed; every push is scanned by Inspector as a second opinion to Trivy |
| Sign | cosign keyless, signature stored in ECR next to the image | ECR supports OCI referrers, so `cosign verify` needs no extra bucket |
| Deploy | SSM `send-command` runs `deploy-ssm.sh` on hosts tagged `role=docker` | no inbound SSH; the command and its output are in CloudTrail and SSM history |
| Secrets | `aws secretsmanager get-secret-value` written to `/run/secrets/*` files at deploy time | never in the Compose file, the image, or environment variables |
| Logs | `awslogs` log driver | log volume off the host disk; retention set on the log group |
| Pull on host | instance role with `AmazonEC2ContainerRegistryReadOnly` | hosts never hold registry credentials |

## Apply order

1. `terraform apply` in this folder (needs the GitHub OIDC provider from
   `../../../bootstrap`; pass its ARN as `github_oidc_provider_arn`).
2. Put the `push_role_arn` output in the repo secret `AWS_ECR_PUSH_ROLE_ARN`,
   and the `deploy_role_arn` output in `AWS_DEPLOY_ROLE_ARN`.
3. Tag the Docker hosts `role=docker` and give their instance profile
   `AmazonSSMManagedInstanceCore`, ECR read, and `secretsmanager:GetSecretValue`
   on the app's secrets.
4. Merge to `main`; the workflow pushes and deploys.

## Effort

| Task | Effort |
|---|---|
| ECR repo + push role (this Terraform) | S |
| Workflow adaptation | S |
| Host instance profile + SSM agent | S per host group |
| Secrets Manager entries + rotation | S, M with rotation lambdas |
