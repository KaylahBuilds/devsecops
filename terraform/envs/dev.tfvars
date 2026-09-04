environment = "dev"
aws_region  = "us-east-1"

vpc_cidr       = "10.20.0.0/16"
az_count       = 2
subnet_newbits = 4 # /16 + 4 = /20 subnets

enable_nat_gateway     = false
one_nat_gateway_per_az = false

enable_flow_logs        = true
flow_log_retention_days = 90

extra_tags = {
  CostCenter = "lab"
}
