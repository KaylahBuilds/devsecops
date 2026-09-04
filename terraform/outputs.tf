output "vpc_id" {
  description = "ID of the core VPC"
  value       = aws_vpc.core.id
}

output "vpc_cidr" {
  description = "CIDR block of the core VPC"
  value       = aws_vpc.core.cidr_block
}

output "public_subnet_ids" {
  description = "Public subnet IDs across AZs"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "Private subnet IDs across AZs"
  value       = aws_subnet.private[*].id
}

output "availability_zones" {
  description = "AZs in use"
  value       = local.azs
}

output "nat_gateway_ids" {
  description = "NAT gateway IDs (empty when NAT is disabled)"
  value       = aws_nat_gateway.core[*].id
}

output "private_route_table_ids" {
  description = "Per-AZ private route table IDs"
  value       = aws_route_table.private[*].id
}

output "flow_log_group" {
  description = "CloudWatch log group receiving VPC flow logs (null if disabled)"
  value       = var.enable_flow_logs ? aws_cloudwatch_log_group.flow_logs[0].name : null
}
