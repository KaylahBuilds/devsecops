# ---------------------------------------------------------------------------
# Onboarding scenario: 4 orgs / 10 repos on the shared defaults, then a 5th
# org and 3 more repos are added (marked NEW). Everything not listed here
# comes from var.defaults in organizations.tf.
# ---------------------------------------------------------------------------

# Tenant-wide overrides of the standard in organizations.tf (var.defaults).
tenant_settings = {
  egress_policy      = "audit"
  notification_email = "security@example.com"
  dependabot = [
    { package = "github-actions", interval = "weekly" },
    { package = "npm", interval = "weekly" },
    { package = "pip", interval = "weekly" },
  ]
}

organizations = {

  # --- existing: 4 orgs, 10 repos ------------------------------------------
  "acme-platform" = {
    repos = ["api", "web", "worker", "billing"] # NEW: billing
    settings = {
      dry_run = false # this org is past the audit phase: enforce
    }
    repo_settings = {
      "api" = {
        egress_policy     = "block"
        allowed_endpoints = ["sts.amazonaws.com:443", "*.amazonaws.com:443"]
        lockdown          = true
      }
    }
  }

  "acme-data" = {
    repos = ["pipelines", "warehouse", "notebooks", "feature-store"] # NEW: feature-store
    repo_settings = {
      "notebooks" = {
        require_pinned_actions = false # research repo, tags are fine for now
      }
    }
  }

  "acme-mobile" = {
    repos = ["ios-app", "android-app"]
    settings = {
      actions_to_exempt_while_pinning = ["acme-mobile/*"] # org-owned actions may use tags
    }
  }

  "acme-labs" = {
    repos = ["sandbox", "experiments"]
    settings = {
      remediation_prs            = false # no bot PRs in the lab
      compromised_actions_policy = false
      notification_email         = null # no alerts for the lab
    }
  }

  # --- NEW: a 5th org -------------------------------------------------------
  "acme-payments" = {
    repos = ["payments-api", "ledger", "reconciliation"]
    settings = {
      egress_policy = "block" # strict from day one, org-wide
      lockdown      = true
      dry_run       = false
    }
    repo_settings = {
      "payments-api" = {
        allowed_endpoints = ["api.stripe.com:443"]
        workflows         = ["ci.yml", "deploy.yml"] # only these workflows, not the whole repo
      }
    }
  }
}
