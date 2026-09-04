# Core network: VPC, subnets, routing, NAT.

resource "aws_vpc" "core" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${local.name}-vpc" }
}

# Prowler flags permissive default SGs — strip all rules from ours.
resource "aws_default_security_group" "core" {
  vpc_id = aws_vpc.core.id
  tags   = { Name = "${local.name}-default-sg-locked" }
}

resource "aws_internet_gateway" "core" {
  vpc_id = aws_vpc.core.id
  tags   = { Name = "${local.name}-igw" }
}

# ---------------------------------------------------------------------------
# Subnets
# ---------------------------------------------------------------------------

resource "aws_subnet" "public" {
  count = var.az_count

  vpc_id                  = aws_vpc.core.id
  cidr_block              = local.public_subnet_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = local.map_public_ip_on_launch

  tags = {
    Name = "${local.name}-public-${local.azs[count.index]}"
    Tier = "public"
  }
}

resource "aws_subnet" "private" {
  count = var.az_count

  vpc_id            = aws_vpc.core.id
  cidr_block        = local.private_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = {
    Name = "${local.name}-private-${local.azs[count.index]}"
    Tier = "private"
  }
}

# ---------------------------------------------------------------------------
# Public routing
# ---------------------------------------------------------------------------

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.core.id

  route {
    cidr_block = local.internet_egress_cidr
    gateway_id = aws_internet_gateway.core.id
  }

  tags = { Name = "${local.name}-public-rt" }
}

resource "aws_route_table_association" "public" {
  count = var.az_count

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------------
# NAT — single shared gateway, or one per AZ when one_nat_gateway_per_az
# ---------------------------------------------------------------------------

resource "aws_eip" "nat" {
  count = local.nat_gateway_count

  domain = "vpc"
  tags   = { Name = "${local.name}-nat-eip-${local.azs[count.index]}" }
}

resource "aws_nat_gateway" "core" {
  count = local.nat_gateway_count

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  tags          = { Name = "${local.name}-nat-${local.azs[count.index]}" }

  depends_on = [aws_internet_gateway.core]
}

# ---------------------------------------------------------------------------
# Private routing — one route table per AZ so per-AZ NAT stays zonal
# ---------------------------------------------------------------------------

resource "aws_route_table" "private" {
  count = var.az_count

  vpc_id = aws_vpc.core.id

  dynamic "route" {
    for_each = var.enable_nat_gateway ? [1] : []
    content {
      cidr_block     = local.internet_egress_cidr
      nat_gateway_id = aws_nat_gateway.core[var.one_nat_gateway_per_az ? count.index : 0].id
    }
  }

  tags = { Name = "${local.name}-private-rt-${local.azs[count.index]}" }
}

resource "aws_route_table_association" "private" {
  count = var.az_count

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}
