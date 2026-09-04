# Shared data sources and derived values. Resources live in:
#   network.tf    — VPC, subnets, routing, NAT
#   flow-logs.tf  — VPC flow logs + IAM
# All tunables come from variables.tf; fixed posture choices are locals here.

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  name = "${var.project}-${var.environment}"
  azs  = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  # Public subnets in the low range, private offset above them.
  public_subnet_cidrs  = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, var.subnet_newbits, i)]
  private_subnet_cidrs = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, var.subnet_newbits, i + var.az_count)]

  nat_gateway_count = var.enable_nat_gateway ? (var.one_nat_gateway_per_az ? var.az_count : 1) : 0

  # Fixed posture choices — deliberate, not per-environment knobs.
  internet_egress_cidr    = "0.0.0.0/0"
  flow_log_traffic_type   = "ALL"
  flow_log_agg_interval   = 60
  map_public_ip_on_launch = false
}
