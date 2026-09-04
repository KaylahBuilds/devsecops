environment = "prod"
aws_region  = "us-east-1"

vpc_cidr       = "10.40.0.0/16"
az_count       = 3
subnet_newbits = 4 # /16 + 4 = /20 subnets

enable_nat_gateway     = true # HA: one gateway per AZ
one_nat_gateway_per_az = true

enable_flow_logs        = true
flow_log_retention_days = 365

extra_tags = {
  CostCenter = "core"
}
