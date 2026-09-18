# Auth comes from variables when set, otherwise from the environment:
#   STEP_SECURITY_API_KEY, STEP_SECURITY_CUSTOMER, STEP_SECURITY_API_BASE_URL
# Never put the API key in a committed .tfvars — leave var.api_key null in CI
# and export the env var from a secret instead.
provider "stepsecurity" {
  customer     = var.customer
  api_key      = var.api_key
  api_base_url = var.api_base_url
}
