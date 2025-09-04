data "aws_secretsmanager_secret" "user_ca_secret_id" {
  name = var.user_ca_secret_name
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_iam_role" "lambda_role" {
  name = "lambda-ssh-cert-signing-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_secrets_policy" {
  name = "lambda-ssh-cert-signing-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "secretsmanager:GetSecretValue"
        Effect   = "Allow"
        Resource = data.aws_secretsmanager_secret.user_ca_secret_id.arn
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_write_audit_event" {
  name = "lambda-ssh-cert-allow-db-write"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "dynamodb:PutItem"
        Resource = aws_dynamodb_table.audit_table.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_permission" "allow_apigw_to_invoke" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ssh_cert_signer.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "arn:aws:execute-api:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:${aws_apigatewayv2_stage.prod.api_id}/*/*/*"
}


resource "aws_lambda_function" "ssh_cert_signer" {
  function_name = "aeige_lambda"
  role          = aws_iam_role.lambda_role.arn
  package_type  = "Zip"
  s3_bucket     = var.lambda_s3_bucket
  s3_key        = var.lambda_s3_key
  source_code_hash = var.lambda_zip_sha256 != "" ? var.lambda_zip_sha256 : null
  handler       = "bootstrap"
  runtime       = var.lambda_runtime
  architectures = ["x86_64"]

  environment {
    variables = {
      USER_CA_KEY_NAME     = var.user_ca_secret_name
      JSME_PATH_EXPRESSION = var.jsme_expression
      DYNAMO_DB_TABLE      = aws_dynamodb_table.audit_table.name
    }
  }
}


