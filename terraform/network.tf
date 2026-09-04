# =============================================================================
# network.tf — core network: VPC, subnets, routing, NAT.
# Extracted from main.tf; resource addresses unchanged (aws_vpc.core etc.),
# so against existing state this file plans as a no-op.
# =============================================================================

resource "aws_vpc" "core" {
  cidr_block           = var.vpc_cidr # per-env: dev 10.20/16, prod 10.40/16 (non-overlapping for future peering)
  enable_dns_support   = true         # required for AWS-provided DNS + VPC endpoints
  enable_dns_hostnames = true         # required for private-zone Route53 and endpoint DNS names

  tags = { Name = "${local.name}-vpc" }
}

# Adopting the VPC's default security group with NO ingress/egress blocks
# strips every rule from it. Nothing should ever attach to the default SG;
# this makes it inert. (Prowler check: ec2_securitygroup_default_restrict_traffic)
resource "aws_default_security_group" "core" {
  vpc_id = aws_vpc.core.id
  tags   = { Name = "${local.name}-default-sg-locked" }
}

# Single IGW per VPC — the only ingress/egress edge for the public tier.
resource "aws_internet_gateway" "core" {
  vpc_id = aws_vpc.core.id
  tags   = { Name = "${local.name}-igw" }
}

# ---------------------------------------------------------------------------
# Subnets — one public + one private per AZ, CIDRs derived in main.tf locals
# ---------------------------------------------------------------------------

resource "aws_subnet" "public" {
  count = var.az_count # one per AZ

  vpc_id                  = aws_vpc.core.id
  cidr_block              = local.public_subnet_cidrs[count.index]  # low range of the VPC CIDR
  availability_zone       = local.azs[count.index]                  # pinned so count.index ↔ AZ stays stable
  map_public_ip_on_launch = local.map_public_ip_on_launch           # false — public IPs must be explicit

  tags = {
    Name = "${local.name}-public-${local.azs[count.index]}"
    Tier = "public" # lets downstream stacks select subnets by tag filter
  }
}

resource "aws_subnet" "private" {
  count = var.az_count # one per AZ, offset range above the public CIDRs

  vpc_id            = aws_vpc.core.id
  cidr_block        = local.private_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]
  # no map_public_ip_on_launch: defaults to false, and nothing here routes to the IGW anyway

  tags = {
    Name = "${local.name}-private-${local.azs[count.index]}"
    Tier = "private"
  }
}

# ---------------------------------------------------------------------------
# Public routing — one shared table: identical routes in every AZ
# ---------------------------------------------------------------------------

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.core.id

  route {
    cidr_block = local.internet_egress_cidr        # 0.0.0.0/0
    gateway_id = aws_internet_gateway.core.id      # default route straight to the IGW
  }

  tags = { Name = "${local.name}-public-rt" }
}

# Every public subnet uses the shared public table.
resource "aws_route_table_association" "public" {
  count = var.az_count

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------------
# NAT — count derives from two flags (see local.nat_gateway_count):
#   0 = disabled, 1 = shared (dev), az_count = one per AZ (prod HA)
# ---------------------------------------------------------------------------

# Each NAT gateway needs its own static public IP.
resource "aws_eip" "nat" {
  count = local.nat_gateway_count

  domain = "vpc"
  tags   = { Name = "${local.name}-nat-eip-${local.azs[count.index]}" }
}

resource "aws_nat_gateway" "core" {
  count = local.nat_gateway_count

  allocation_id = aws_eip.nat[count.index].id          # 1:1 EIP per gateway
  subnet_id     = aws_subnet.public[count.index].id    # NAT lives in the public subnet of its AZ
  tags          = { Name = "${local.name}-nat-${local.azs[count.index]}" }

  # NAT can't pass traffic until the VPC has an IGW; make ordering explicit
  # so destroys also sequence correctly.
  depends_on = [aws_internet_gateway.core]
}

# ---------------------------------------------------------------------------
# Private routing — one table PER AZ (unlike public) so that with per-AZ NAT
# each AZ egresses through its own gateway and an AZ outage stays zonal
# ---------------------------------------------------------------------------

resource "aws_route_table" "private" {
  count = var.az_count

  vpc_id = aws_vpc.core.id

  # Default route exists only when NAT is enabled; with NAT off the private
  # tier has no internet path at all (local VPC routes only).
  dynamic "route" {
    for_each = var.enable_nat_gateway ? [1] : []
    content {
      cidr_block = local.internet_egress_cidr
      # per-AZ NAT → this AZ's gateway; shared NAT → everyone uses gateway [0]
      nat_gateway_id = aws_nat_gateway.core[var.one_nat_gateway_per_az ? count.index : 0].id
    }
  }

  tags = { Name = "${local.name}-private-rt-${local.azs[count.index]}" }
}

# Private subnet N attaches to private route table N (same AZ).
resource "aws_route_table_association" "private" {
  count = var.az_count

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}
