# ---------------------------------------------------------------------------
# One tenant, many orgs. Every entry names its org via `owner` (or is keyed by
# org for per-org settings). Add an org by adding entries; remove an org by
# deleting them. Secrets (API key, webhooks) are NOT here — see README.
# ---------------------------------------------------------------------------

# --- tenant-wide ------------------------------------------------------------
default_egress_policy      = "audit"
default_notification_email = "security@example.com"

# ===========================================================================
# Harden-Runner egress policies
# ===========================================================================
egress_policies = {
  # acme-platform: org-wide audit baseline until the egress reports are clean,
  # then flip to "block".
  "platform-baseline" = {
    owner         = "acme-platform"
    egress_policy = "audit"
  }

  # acme-platform: deploy pipelines — block mode, AWS + Terraform on top of base.
  "platform-terraform-deploy" = {
    owner         = "acme-platform"
    egress_policy = "block"
    allowed_endpoints = [
      "sts.amazonaws.com:443",
      "*.amazonaws.com:443",
      "registry.terraform.io:443",
      "releases.hashicorp.com:443",
    ]
    lockdown = { enabled = true }
  }

  # acme-platform: Node services.
  "platform-node-build" = {
    owner             = "acme-platform"
    egress_policy     = "block"
    allowed_endpoints = ["registry.npmjs.org:443"]
    disable_sudo      = true
  }

  # acme-labs: observe only.
  "labs-audit" = {
    owner = "acme-labs"
  }
}

egress_policy_attachments = {
  "platform-baseline" = { org_wide = true }

  "platform-terraform-deploy" = {
    repositories = [
      { name = "secres-infra", workflows = ["terraform.yml", "stepsecurity.yml"] },
    ]
  }

  "platform-node-build" = {
    repositories = [
      { name = "svc-*", workflows = ["ci.yml"] }, # patterns must list workflows
      { name = "web-frontend" },                  # whole repo
    ]
  }

  "labs-audit" = { org_wide = true }
}

# ===========================================================================
# Run policies — `policy` is the provider's policy_config block verbatim
# ===========================================================================
run_policies = {
  # Every job must run harden-runner with a policy-store policy.
  "platform-require-harden-runner" = {
    owner = "acme-platform"
    policy = {
      enable_harden_runner_policy = true
      harden_runner_target_labels = [] # every job
      require_policy_store        = true
    }
  }

  # Only SHA-pinned actions; org-owned actions exempt.
  "platform-pin-actions" = {
    owner = "acme-platform"
    policy = {
      enable_action_policy            = true
      require_pinned_actions          = true
      allowed_actions                 = { "*/*" = "allow" }
      actions_to_exempt_while_pinning = ["acme-platform/*"]
    }
  }

  # No self-hosted runners on the money paths; dry-run first.
  "platform-no-self-hosted" = {
    owner        = "acme-platform"
    repositories = ["payments-api", "billing-worker"]
    policy = {
      enable_runs_on_policy    = true
      disallowed_runner_labels = ["self-hosted"]
      is_dry_run               = true
    }
  }

  "platform-secrets-and-compromised-actions" = {
    owner = "acme-platform"
    policy = {
      enable_secrets_policy             = true
      exempted_users                    = ["dependabot[bot]", "renovate[bot]"]
      enable_compromised_actions_policy = true
    }
  }

  "labs-pin-actions-dry-run" = {
    owner = "acme-labs"
    policy = {
      enable_action_policy   = true
      require_pinned_actions = true
      allowed_actions        = { "*/*" = "allow" }
      is_dry_run             = true
    }
  }
}

# ===========================================================================
# Per-org settings (keyed by org)
# ===========================================================================
checks = {
  "acme-platform" = {
    custom_description = "Checks by StepSecurity. Contact: #security on Slack."
    # controls omitted → var.default_check_controls
    required_checks = { repos = ["*"] }
    baseline_check  = { repos = ["*"], omit_repos = ["sandbox"] }
  }
  "acme-labs" = {
    optional_checks = { repos = ["*"] } # nothing blocking in the lab
  }
}

notifications = {
  "acme-platform" = {
    slack_channel_id = "C0123456789" # OAuth delivery; webhook URLs come from notification_webhooks
    events           = { new_endpoint_discovered = true }
    threat_intel     = { enabled = true, level = "version" }
  }
  "acme-labs" = {
    email = "labs-security@example.com"
  }
}

policy_driven_prs = {
  "acme-platform" = {
    selected_repos = ["*"]
    excluded_repos = ["sandbox"]
    auto_remediation_options = {
      actions_to_exempt_while_pinning = ["acme-platform/*"]
      harden_runner_config = {
        target_runner_labels = ["ubuntu-latest"]
      }
    }
  }
}

pr_templates = {
  "acme-platform" = {
    title          = "[StepSecurity] Apply security best practices"
    labels         = ["security", "automated"]
    branch_name    = "chore/stepsecurity-{time}"
    commit_message = "[StepSecurity] Apply security best practices"
    summary        = <<-EOT
      ## Summary
      Automated hardening from StepSecurity — review and merge.

      ## Security fixes
      {{STEPSECURITY_SECURITY_FIXES}}
    EOT
  }
}

# ===========================================================================
# Suppression rules
# ===========================================================================
suppression_rules = {
  "platform-codecov-upload" = {
    owner       = "acme-platform"
    type        = "anomalous_outbound_network_call"
    description = "Coverage upload is expected"
    repo        = "payments-api"
    workflow    = "ci.yml"
    process     = "*"
    destination = { domain = "*.codecov.io" }
  }
}
