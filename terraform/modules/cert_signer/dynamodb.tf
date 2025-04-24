resource "aws_dynamodb_table" "audit_table" {
  name         = "aegis-audit"
  hash_key     = "sub"
  range_key    = "signed_at"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "sub"
    type = "S"
  }

  attribute {
    name = "signed_at"
    type = "S"
  }
}
