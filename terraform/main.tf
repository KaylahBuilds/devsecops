# =============================================================================
# main.tf — shared data sources and derived values ONLY. No resources here.
#
# Resources live in:
#   network.tf    — VPC, subnets, routing, NAT
#   flow-logs.tf  — VPC flow logs + the IAM role they require
#
# Everything an environment may tune comes from variables.tf (fed by
# envs/<env>.tfvars). Values that are deliberate security/posture decisions
# are pinned as locals below, so changing them requires a reviewed code
# change — a tfvars file cannot weaken them.
# =============================================================================

# All AZs currently accepting new resources in the target region;
# local.azs slices this down to the number the environment asked for.
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  # Canonical name prefix stamped onto every resource, e.g. "secres-dev".
  name = "${var.project}-${var.environment}"

  # First az_count usable AZs, e.g. ["us-east-1a", "us-east-1b"].
  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  # Deterministic subnet carving from the VPC CIDR:
  #   public subnets take indexes 0..az_count-1 (the low range),
  #   private subnets take the next az_count indexes above them.
  # With defaults (/16 VPC, newbits=4) each subnet is a /20.
  public_subnet_cidrs  = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, var.subnet_newbits, i)]
  private_subnet_cidrs = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, var.subnet_newbits, i + var.az_count)]

  # How many NAT gateways to build:
  #   NAT disabled            → 0 (dev default — no idle spend)
  #   NAT on, shared          → 1 (cheap, single-AZ blast radius)
  #   NAT on, one per AZ      → az_count (prod HA)
  nat_gateway_count = var.enable_nat_gateway ? (var.one_nat_gateway_per_az ? var.az_count : 1) : 0

  # --- Fixed posture choices — intentionally NOT variables -----------------
  internet_egress_cidr    = "0.0.0.0/0" # the only default-route destination we ever program
  flow_log_traffic_type   = "ALL"       # capture accepts AND rejects; rejects are the interesting half
  flow_log_agg_interval   = 60          # tightest aggregation window AWS offers (seconds)
  map_public_ip_on_launch = false       # instances never get public IPs implicitly (Prowler check)
}
