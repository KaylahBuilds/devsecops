# ---------------------------------------------------------------------------
# Identity / naming
# ---------------------------------------------------------------------------

variable "project" {
  description = "Project slug, prefixed onto every resource name"
  type        = string
  default     = "secres"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,20}$", var.project))
    error_message = "project must be lowercase alphanumeric/hyphen, 2-21 chars."
  }
}

variable "environment" {
  description = "Deployment environment"
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging, or prod."
  }
}

variable "aws_region" {
  description = "AWS region to deploy core infrastructure into"
  type        = string
  default     = "us-east-1"
}

variable "extra_tags" {
  description = "Additional tags merged onto every resource"
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------------------------
# Network topology
# ---------------------------------------------------------------------------

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.20.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "vpc_cidr must be a valid IPv4 CIDR block."
  }
}

variable "az_count" {
  description = "Number of availability zones to spread subnets across"
  type        = number
  default     = 2

  validation {
    condition     = var.az_count >= 2 && var.az_count <= 4
    error_message = "az_count must be between 2 and 4."
  }
}

variable "subnet_newbits" {
  description = "Bits added to vpc_cidr when carving subnets (e.g. /16 VPC + 4 = /20 subnets)"
  type        = number
  default     = 4

  validation {
    condition     = var.subnet_newbits >= 2 && var.subnet_newbits <= 12
    error_message = "subnet_newbits must be between 2 and 12."
  }

  validation {
    condition     = pow(2, var.subnet_newbits) >= 2 * var.az_count
    error_message = "subnet_newbits must yield at least 2 * az_count subnets."
  }
}

variable "enable_dns_support" {
  description = "Enable DNS resolution inside the VPC"
  type        = bool
  default     = true
}

variable "enable_dns_hostnames" {
  description = "Assign DNS hostnames to instances in the VPC"
  type        = bool
  default     = true
}

variable "map_public_ip_on_launch" {
  description = "Auto-assign public IPs in public subnets (keep false; Prowler flags it on)"
  type        = bool
  default     = false
}

variable "internet_egress_cidr" {
  description = "Destination CIDR for default routes to the IGW/NAT"
  type        = string
  default     = "0.0.0.0/0"
}

# ---------------------------------------------------------------------------
# NAT
# ---------------------------------------------------------------------------

variable "enable_nat_gateway" {
  description = "Provision NAT for private-subnet egress (costs ~$32/mo per gateway)"
  type        = bool
  default     = false
}

variable "one_nat_gateway_per_az" {
  description = "true = one NAT per AZ (HA, prod); false = single shared NAT (cheap, dev)"
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------
# VPC flow logs
# ---------------------------------------------------------------------------

variable "enable_flow_logs" {
  description = "Enable VPC flow logs to CloudWatch (recommended — Prowler will flag it off)"
  type        = bool
  default     = true
}

variable "flow_log_traffic_type" {
  description = "Which traffic to capture in flow logs"
  type        = string
  default     = "ALL"

  validation {
    condition     = contains(["ALL", "ACCEPT", "REJECT"], var.flow_log_traffic_type)
    error_message = "flow_log_traffic_type must be ALL, ACCEPT, or REJECT."
  }
}

variable "flow_log_retention_days" {
  description = "CloudWatch retention for VPC flow logs"
  type        = number
  default     = 90

  validation {
    condition = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.flow_log_retention_days)
    error_message = "flow_log_retention_days must be a valid CloudWatch retention value."
  }
}

variable "flow_log_aggregation_interval" {
  description = "Max interval (seconds) for aggregating flow log records"
  type        = number
  default     = 60

  validation {
    condition     = contains([60, 600], var.flow_log_aggregation_interval)
    error_message = "flow_log_aggregation_interval must be 60 or 600."
  }
}
