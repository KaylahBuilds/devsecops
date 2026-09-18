# ---------------------------------------------------------------------------
# One tenant, many orgs. Add an org by adding a key under `organizations`;
# every section inside an org is optional. Secrets (API key, webhooks) are
# NOT here — see README.
# ---------------------------------------------------------------------------

# --- tenant-wide ------------------------------------------------------------
default_egress_policy      = "audit"
default_notification_email = "security@example.com"

# --- organizations ----------------------------------------------------------
organizations = {

  # Production org: everything on, egress blocked, remediation PRs enabled.
  "acme-platform" = {

    egress_policies = {
      # Baseline for the whole org: GitHub endpoints only, audit mode until the
      # egress reports are clean, then flip to "block".
      "org-baseline" = {
        egress_policy = "audit"
        attach        = { org_wide = true }
      }

      # Deploy pipelines: block mode, AWS + Terraform registry on top of base.
      "terraform-deploy" = {
        egress_policy = "block"
        allowed_endpoints = [
          "sts.amazonaws.com:443",
          "*.amazonaws.com:443",
          "registry.terraform.io:443",
          "releases.hashicorp.com:443",
        ]
        lockdown = { enabled = true }
        attach = {
          repositories = {
            "secres-infra" = ["terraform.yml", "stepsecurity.yml"]
          }
        }
      }

      # Node services: the CI workflow of every repo matching svc-*, plus the
      # whole of one named repo (wildcard patterns must name workflows).
      "node-build" = {
        egress_policy     = "block"
        allowed_endpoints = ["registry.npmjs.org:443"]
        disable_sudo      = true
        attach = {
          repositories = {
            "svc-*"        = ["ci.yml"]
            "web-frontend" = []
          }
        }
      }
    }

    run_policies = {
      # Every job must run harden-runner, and must use a policy-store policy.
      "require-harden-runner" = {
        harden_runner_target_labels = []
        require_policy_store        = true
      }

      # Only SHA-pinned actions, org-owned actions exempt from pinning.
      "pin-actions" = {
        require_pinned_actions          = true
        allowed_actions                 = { "*/*" = "allow" }
        actions_to_exempt_while_pinning = ["acme-platform/*"]
      }

      # No self-hosted runners for the money paths, dry-run first.
      "no-self-hosted" = {
        repositories             = ["payments-api", "billing-worker"]
        disallowed_runner_labels = ["self-hosted"]
        dry_run                  = true
      }

      "secrets-and-compromised-actions" = {
        secrets_policy             = true
        compromised_actions_policy = true
      }
    }

    checks = {
      custom_description = "Checks by StepSecurity. Contact: #security on Slack."
      # controls omitted → var.default_check_controls
      required_checks = { repos = ["*"] }
      baseline_check  = { repos = ["*"], omit_repos = ["sandbox"] }
    }

    notifications = {
      slack_channel_id = "C0123456789" # OAuth delivery; webhook URLs come from notification_webhooks
      events           = { new_endpoint_discovered = true }
      threat_intel     = { enabled = true, level = "version" }
    }

    policy_driven_prs = {
      selected_repos                  = ["*"]
      excluded_repos                  = ["sandbox"]
      actions_to_exempt_while_pinning = ["acme-platform/*"]
      harden_runner_config = {
        target_runner_labels = ["ubuntu-latest"]
      }
    }

    pr_template = {
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

    suppression_rules = {
      "codecov-upload" = {
        type        = "anomalous_outbound_network_call"
        description = "Coverage upload is expected"
        repo        = "payments-api"
        workflow    = "ci.yml"
        process     = "*"
        destination = { domain = "*.codecov.io" }
      }
    }
  }

  # Lab org: observe only. One audit policy org-wide plus PR checks.
  "acme-labs" = {
    egress_policies = {
      "audit-everything" = {
        attach = { org_wide = true }
      }
    }
    run_policies = {
      "pin-actions-dry-run" = {
        require_pinned_actions = true
        allowed_actions        = { "*/*" = "allow" }
        dry_run                = true
      }
    }
    checks = {
      required_checks = { repos = [] } # nothing blocking in the lab
      optional_checks = { repos = ["*"] }
    }
    notifications = {
      email = "labs-security@example.com"
    }
  }
}
