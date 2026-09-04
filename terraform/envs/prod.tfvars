# --- identity ---
environment = "prod"
aws_region  = "us-east-1"

# --- topology ---
vpc_cidr                = "10.40.0.0/16"
az_count                = 3
subnet_newbits          = 4 # /16 + 4 = /20 subnets
enable_dns_support      = true
enable_dns_hostnames    = true
map_public_ip_on_launch = false
internet_egress_cidr    = "0.0.0.0/0"

# --- nat (HA: one gateway per AZ) ---
enable_nat_gateway     = true
one_nat_gateway_per_az = true

# --- flow logs ---
enable_flow_logs              = true
flow_log_traffic_type         = "ALL"
flow_log_retention_days       = 365
flow_log_aggregation_interval = 60

# --- tags ---
extra_tags = {
  CostCenter = "core"
}
