# =============================================================================
# flow-logs.tf — VPC flow logs to CloudWatch, plus the IAM role the
# vpc-flow-logs service assumes to write them.
#
# Every resource is gated on var.enable_flow_logs via count (0 or 1), so an
# environment that disables flow logs creates none of this. Default is ON —
# Prowler flags VPCs without flow logs (vpc_flow_logs_enabled).
# =============================================================================

resource "aws_cloudwatch_log_group" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name              = "/vpc/${local.name}/flow-logs"    # predictable path for queries/alerts
  retention_in_days = var.flow_log_retention_days       # per-env: dev 90d, prod 365d
}

# Trust policy: only the VPC flow-logs service may assume the writer role.
data "aws_iam_policy_document" "flow_logs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name               = "${local.name}-vpc-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
}

# Permissions policy: write access scoped to THIS log group only (":*" covers
# the log streams under it) — not logs:* on the account.
data "aws_iam_policy_document" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0 # data source must be gated too, or its [0] reference breaks when disabled

  statement {
    actions = [
      "logs:CreateLogStream",     # streams are created per ENI
      "logs:PutLogEvents",        # the actual record writes
      "logs:DescribeLogGroups",   # service sanity checks
      "logs:DescribeLogStreams",
    ]
    resources = ["${aws_cloudwatch_log_group.flow_logs[0].arn}:*"]
  }
}

# Attach the scoped policy inline on the role.
resource "aws_iam_role_policy" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name   = "${local.name}-vpc-flow-logs"
  role   = aws_iam_role.flow_logs[0].id
  policy = data.aws_iam_policy_document.flow_logs[0].json
}

# The flow log itself, attached at VPC scope (covers every ENI in the VPC).
resource "aws_flow_log" "core" {
  count = var.enable_flow_logs ? 1 : 0

  vpc_id                   = aws_vpc.core.id
  traffic_type             = local.flow_log_traffic_type       # "ALL" — pinned in main.tf locals
  log_destination_type     = "cloud-watch-logs"                # (vs s3/kinesis — CW keeps queries simple here)
  log_destination          = aws_cloudwatch_log_group.flow_logs[0].arn
  iam_role_arn             = aws_iam_role.flow_logs[0].arn     # role defined above
  max_aggregation_interval = local.flow_log_agg_interval       # 60s — pinned in main.tf locals
}
