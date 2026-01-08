resource "aws_dynamodb_table" "audit_table" {
  name         = "${var.stage_name}-aegis-audit"
  hash_key     = "Sub"
  range_key    = "SignedAt"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "Sub"
    type = "S"
  }

  attribute {
    name = "SignedAt"
    type = "S"
  }
}
