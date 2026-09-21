terraform {
  required_version = ">= 1.9.0"

  required_providers {
    stepsecurity = {
      source  = "step-security/stepsecurity"
      version = "~> 0.0.44"
    }
  }
}
